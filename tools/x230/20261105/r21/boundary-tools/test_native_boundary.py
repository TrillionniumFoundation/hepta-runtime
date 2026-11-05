#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Fake-MCP only: exact error classification and full bounded recovery evidence."""
import argparse
import ast
from collections import Counter
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
import run_native_boundary as launcher
import audit_native_boundary as auditor

HARNESS = launcher.HERE.parent / "measurement-tools"


class BoundaryTests(unittest.TestCase):
    audited_fake_calls = 0
    audited_fake_frames = 0

    @classmethod
    def setUpClass(cls):
        cls.bench = launcher.load_frozen(HARNESS)
        from test_native_harness import FAKE
        cls.fake = FAKE
        cls.policy_raw = (launcher.HERE / "capacity-policy.json").read_bytes()
        cls.policy = launcher.load_policy(cls.policy_raw)

    def test_exact_error_whitelist_and_unknown_fail(self):
        verified = {"rendering_verified": True, "accepted_error_envelopes": [
            {"kind": "native_single_text", "text": launcher.CAPACITY_TEXT}]}
        native = {"result": {"isError": True, "content": [{"type": "text", "text": launcher.CAPACITY_TEXT}]}}
        self.assertEqual(launcher.envelope_kind(native, verified), "capacity_rejection")
        self.assertEqual(auditor.error_class(native, verified), "capacity_rejection")
        cases = [
            {"error": {"code": -32603, "message": launcher.CAPACITY_TEXT}},
            {"result": {"isError": True, "content": [{"type": "text", "text": "wrapper: " + launcher.CAPACITY_TEXT}]}},
            {"result": {"isError": True, "content": [{"type": "text", "text": launcher.CAPACITY_TEXT + "!"}]}},
            {"result": {"isError": True, "content": [{"type": "text", "text": launcher.CAPACITY_TEXT}, {"type": "text", "text": "extra"}]}},
            {"result": {"isError": False, "content": [{"type": "text", "text": launcher.CAPACITY_TEXT}]}}]
        for value in cases:
            self.assertNotEqual(launcher.envelope_kind(value, verified), "capacity_rejection")
            self.assertEqual(auditor.error_class(value, verified), "other_error")
        unverified = {"rendering_verified": False, "accepted_error_envelopes": []}
        self.assertEqual(launcher.envelope_kind(native, unverified), "other_error")
        self.assertEqual(auditor.error_class(native, unverified), "other_error")

    def test_fake_bursts_raw_audit_draining_restart_and_all_success_case(self):
        for mixed in (True, False):
            with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": "/selftest-unused-agent"}):
                root = Path(temporary)
                policy = self.policy
                fake = self.fake.replace("import json,sys", "import json,sys,os")
                injection = '''    if request["method"]=="tools/call" and os.path.basename(os.getcwd())=="first" and (32<=request["id"]<=63 or 112<=request["id"]<=143):
        message = CAPACITY if request["id"]%4==0 else "wrapper: "+CAPACITY if request["id"]%7==0 else None
        if message is not None:
            reply={"jsonrpc":"2.0","id":request["id"],"result":{"isError":True,"content":[{"type":"text","text":message}]}}
            sys.stdout.write(json.dumps(reply,separators=(", ",": "))+"\\n");sys.stdout.flush()
            continue
'''.replace("CAPACITY", repr(launcher.CAPACITY_TEXT))
                if mixed:
                    fake = fake.replace('    if "id" not in request: continue\n', '    if "id" not in request: continue\n' + injection)
                ast.parse(fake, filename="fake-mcp-selftest")
                executable = root / "fake-mcp"
                executable.write_text(fake)
                executable.chmod(0o700)
                binary_hash = launcher.sha(executable.read_bytes())
                hosts = sorted(self.bench.HOSTS)
                template_hash = launcher.sha(b"fake-profile-template\n")
                manifest = {"schema": "hepta-x230-benchmark-topology/v1", "profile_template_sha256": template_hash,
                            "hosts": {host: {"platform": "macos" if host == "mac" else "linux", "machine_group": host} for host in hosts}}
                topology_raw = launcher.canonical(manifest)
                (root / "topology.json").write_bytes(topology_raw)
                topology = {"file": "topology.json", "bytes": len(topology_raw), "sha256": launcher.sha(topology_raw),
                            "profile_template_sha256": template_hash, "hosts": manifest["hosts"], "alias_count": 6, "physical_machine_groups": 6}
                (root / "capacity-policy.json").write_bytes(self.policy_raw)
                jobs = []
                for host in hosts:
                    record = {"ssh_target": "unused-" + host, "remote_job_dir": "/unused/jobs/job-" + host}
                    data = launcher.canonical(record)
                    jobs.append({"host": host, "id": "job-" + host, "record": record, "record_bytes": data,
                                 "record_sha256": launcher.sha(data), "expected": ("SELFTEST-" + host + "\n").encode()})
                config = self.bench.fixture(root / "controller", jobs, topology)
                report = {"schema": "hepta-x230-native-boundary-diagnostic/v1", "candidate_sha256": binary_hash,
                    "tokio_workers": 2, "arena_max": 1, "bursts_planned": 2, "attempts_per_burst": 32,
                    "warmup_calls": 24, "post_drain_concurrency": [1, 8], "post_drain_calls_per_cell": 24,
                    "automatic_rpc_retries": 0, "effect_starts": 0, "remote_mutation_tool_calls": 0,
                    "profile": {"template_sha256": template_hash}, "topology": topology,
                    "source_sha256": launcher.source_hashes(), "frozen_harness_sha256": launcher.freeze(HARNESS),
                    "classification_policy": {"file": "capacity-policy.json", "bytes": len(self.policy_raw),
                                              "sha256": launcher.sha(self.policy_raw), "rendering_verified": policy["rendering_verified"]},
                    "allocator_configuration": self.bench.allocator.run_metadata({"candidate": {"MALLOC_ARENA_MAX": "1"}}, {"candidate": binary_hash}),
                    "six_originals": [{"host": job["host"], "job_id": job["id"], "record_sha256": job["record_sha256"],
                                       "stdout_bytes": len(job["expected"]), "stdout_sha256": launcher.sha(job["expected"])} for job in jobs],
                    "bursts": [], "limitations": ["Synthetic fake-MCP selftest; no SSH or HeptaRuntime binary."]}
                controller_type = launcher.make_controller(self.bench, policy)
                for phase in ("first", "restart"):
                    folder = root / "controller" / phase
                    folder.mkdir()
                    try:
                        controller = controller_type(executable, config, root / "unused-profile", folder, 2,
                                                     allocator_values={"MALLOC_ARENA_MAX": "1"})
                    except PermissionError as error:
                        if error.errno == 13 and str(error.filename).endswith("/environ"):
                            self.skipTest("this executor denies child /proc/environ; run unchanged test on X230")
                        raise
                    try:
                        if phase == "first":
                            report["startup"] = controller.startup
                            controller.boundary_phase = "preflight"
                            report["initial_complete_outputs"] = [controller.call("process_read", job, "preflight_complete_output") for job in jobs]
                            controller.boundary_phase = "initial-warmup"
                            report["initial_warmup"] = self.bench.cell(controller, jobs, 8, 24)
                            for number in range(2):
                                burst = launcher.run_burst(self.bench, controller, jobs, number)
                                entry = {"index": number, "burst": burst, "drain": launcher.drain(controller, burst["rows"]), "post_drain_cells": []}
                                self.assertTrue(entry["drain"]["complete"])
                                report["bursts"].append(entry)
                                for concurrency in (1, 8):
                                    controller.boundary_phase = f"post-drain-{number}-C{concurrency}"
                                    entry["post_drain_cells"].append(self.bench.cell(controller, jobs, concurrency, 24))
                        else:
                            report["restart_startup"] = controller.startup
                            controller.boundary_phase = "normal-restart"
                            report["restart_checks"] = [controller.call(tool, job, "restart_same_original") for job in jobs for tool in ("process_status", "process_read")]
                    finally:
                        report["shutdown" if phase == "first" else "restart_shutdown"] = controller.close()
                for key in ("sources_unchanged", "source_originals_unchanged", "copied_originals_unchanged", "binary_hashes_unchanged",
                            "topology_manifest_unchanged", "profile_template_unchanged", "agent_identity_unchanged",
                            "classification_policy_unchanged", "drain_and_recovery_passed"):
                    report[key] = True
                counts = Counter(row["classification"] for entry in report["bursts"] for row in entry["burst"]["rows"])
                report.update(classified_burst_counts=dict(counts), capacity_rejection_observed=counts["capacity_rejection"] > 0,
                              exact_pool_identity_peak_observed=False, passed=counts["other_error"] == 0)
                result = auditor.analyze(launcher.canonical(report), root, HARNESS)
                self.assertTrue(result["evidence_verified"])
                self.assertEqual(result["diagnostic_passed"], not mixed)
                self.assertEqual(result["total_tool_calls"], 202)
                self.assertEqual(result["raw_transport"]["rpc_envelopes_independently_verified"], 204)
                type(self).audited_fake_calls += result["total_tool_calls"]
                type(self).audited_fake_frames += result["raw_transport"]["frames_rehashed"]
                if mixed:
                    expected = {"success": 41, "capacity_rejection": 16 if policy["rendering_verified"] else 0,
                                "other_error": 7 if policy["rendering_verified"] else 23}
                    self.assertEqual(result["counts"], expected)
                    altered = copy.deepcopy(report)
                    victim = next(row for row in altered["bursts"][0]["burst"]["rows"] if row["classification"] == "other_error")
                    victim["classification"] = "capacity_rejection"
                    with self.assertRaisesRegex(ValueError, "classification"):
                        auditor.analyze(launcher.canonical(altered), root, HARNESS)
                else:
                    self.assertEqual(result["counts"], {"success": 64, "capacity_rejection": 0, "other_error": 0})
                    self.assertFalse(report["capacity_rejection_observed"])
                    self.assertTrue(all(item["pool_identity_peak"] is None for item in result["bursts"]))
                raw_path = root / "controller/first/transport-responses.jsonl"
                raw_path.write_bytes(raw_path.read_bytes() + b"\n")
                with self.assertRaisesRegex(ValueError, "hash changed"):
                    auditor.analyze(launcher.canonical(report), root, HARNESS)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--harness-root", type=Path, default=HARNESS)
    args, remaining = parser.parse_known_args()
    HARNESS = args.harness_root.resolve()
    program = unittest.main(argv=[sys.argv[0], *remaining], verbosity=2, exit=False)
    result = program.result
    print(json.dumps({"schema": "hepta-native-boundary-selftest/v1", "tests_run": result.testsRun,
        "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
        "audited_fake_tool_calls": BoundaryTests.audited_fake_calls, "audited_fake_frames": BoundaryTests.audited_fake_frames,
        "success": result.wasSuccessful(), "accepted_preparation": result.wasSuccessful() and not result.skipped}))
    sys.exit(0 if result.wasSuccessful() else 1)
