#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Temporary-file and fake-service protocol checks; no native/service calls.

Every qualification/admission in this file is a deliberately synthetic fixture.
None is evidence for an installed host, live-state compatibility or production
writer coordination. Subprocess execution is disabled for every test.
"""
import copy
import fcntl
import json
import os
import pathlib
import plistlib
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import mac_hia_activation as A


class FakeService:
    def __init__(self, binary, config, label):
        self.binary, self.config, self.label = binary, config, label
        self.pid, self.generation, self.restarts = 1001, 1, 0
        self.behavior = "success"
        self.loaded_bytes = config.read_bytes()

    def observe(self):
        _, binary = A.snapshot(self.binary)
        return {"target": "gui/" + str(os.getuid()) + "/" + self.label,
                "pid": self.pid, "uid": os.getuid(), "start_identity": {"kind": "synthetic_fixture", "value": str(self.generation)},
                "loaded_binary_sha256": binary["sha256"],
                "loaded_binary_device": binary["device"], "loaded_binary_inode": binary["inode"],
                "loaded_configuration_sha256": None,
                "scope": "synthetic test process; no installed controller observation"}

    def restart(self):
        self.restarts += 1
        if self.behavior == "timeout_before":
            raise subprocess.TimeoutExpired(["INERT_FIXTURE"], 1)
        self.pid += 1
        self.generation += 1
        self.loaded_bytes = self.config.read_bytes()
        if self.behavior == "timeout_after":
            raise subprocess.TimeoutExpired(["INERT_FIXTURE"], 1)


class ActivationProtocol(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-mac-transition-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.root.chmod(0o700)
        self.no_process = mock.patch.object(A.subprocess, "run", side_effect=AssertionError("test attempted a native process"))
        self.no_process.start()
        self.addCleanup(self.no_process.stop)
        self.counter = 0
        self.label = "org.example.inert-hepta-fixture"
        self.old_pins = {"worker_sha256": "a" * 64, "backend_sha256": "b" * 64, "catalog_sha256": "c" * 64}
        self.new_pins = {"worker_sha256": "d" * 64, "backend_sha256": "e" * 64, "catalog_sha256": "c" * 64}
        self.live = {"state_dir": "/fixture/production-controller", "hosts": {"test-worker": {"platform": "linux"}},
                     "hia_worker": {"host": "test-worker", "working_directory": "/fixture/old-source",
                        "python_executable": "/fixture/old-venv/bin/python", "state_root": "/fixture/production-worker",
                        "artifact_roots": ["/fixture/artifacts"], "timeout_seconds": 120,
                        "memory_max_bytes": 1073741824, **self.old_pins}}
        self.target = copy.deepcopy(self.live)
        self.target["hia_worker"].update(self.new_pins)
        self.target["hia_worker"].update(working_directory="/fixture/new-source", python_executable="/fixture/new-venv/bin/python")
        self.probe = copy.deepcopy(self.target)
        self.probe["state_dir"] = "/fixture/isolated-probe-controller"
        self.probe["hia_worker"]["state_root"] = "/fixture/isolated-probe-worker"
        self.live_path = self.put("live.json", A.encode(self.live))
        self.target_path = self.put("target.json", A.encode(self.target))
        self.plist_path = self.put("agent.plist", b"INERT_PLIST_NOT_USED_BY_FAKE\n")
        self.binary_path = self.put("native", b"INERT_BINARY_MUST_NEVER_EXECUTE\n", 0o700)
        self.production_checker_pin = A.ONLINE_READBACK_CHECKER_SHA256
        self.checker_path = self.put("synthetic-original-checker.py", b"# Inert unit fixture, never executed.\n")
        # Unit fixtures have no Hepta checkout. The real fixed pin is asserted
        # separately; no synthetic source is accepted by an unpatched helper.
        self.fixture_checker_pin = mock.patch.object(A, "ONLINE_READBACK_CHECKER_SHA256",
            A.digest(self.checker_path.read_bytes()))
        self.fixture_checker_pin.start()
        self.addCleanup(self.fixture_checker_pin.stop)
        self.service = FakeService(self.binary_path, self.live_path, self.label)
        self.bundle = self.root / "operation"
        self.source_pair = {"hepta_commit": "1" * 40, "runtime_commit": A.BASE_RUNTIME,
                            "installation": self.new_pins}
        self.lock = {"schema": "hepta.hia.release-lock.v1", "sources": {
            "hepta": {"commit": "1" * 40, "tree": "2" * 40},
            "runtime": {"commit": A.BASE_RUNTIME, "tree": "3" * 40}}, "installation": self.new_pins}
        self.baseline_lock = copy.deepcopy(self.lock)
        self.baseline_lock["installation"] = self.old_pins
        self.baseline_lock["sources"]["hepta"]["commit"] = "4" * 40
        self.candidate = {"schema": "hepta.hia.unified-candidate.v1", "source_qualified": True,
            "source_pair": self.source_pair, "source_pair_sha256": A.digest(A.canonical(self.source_pair)),
            "configuration_sha256": A.digest(A.encode(self.probe)),
            "worker_profile_sha256": A.digest(A.canonical(self.probe["hia_worker"]))}
        names = {"host_list", "effective_config", "process_start", "process_status", "process_read", "process_wait", "process_cancel"}
        names.update("hia_" + name for name in ("describe", "read", "artifact", "context", "inspect", "candidate", "verify", "emit", "evaluate", "adopt", "rollback"))
        self.tools = [{"name": name, "description": "Synthetic contract fixture only",
            "inputSchema": {"type": "object", "properties": {}}, "annotations": {
                "readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}}
            for name in sorted(names)]
        self.contract = A.CONTRACT.make_contract(self.tools)
        self.qual = {"release_lock": self.ref_json("lock.json", self.lock),
                     "candidate": self.ref_json("candidate.json", self.candidate),
                     "probe_config": self.ref_json("probe.json", self.probe),
                     "full_contract": self.ref_json("contract.json", self.contract),
                     "native_tools": self.ref_json("tools.json", {"tools": self.tools}),
                     "worker_manifest": self.ref_json("worker.json", self.new_pins),
                     "stdio_transcript": self.ref_json("transcript.json", {"synthetic_fixture": True})}
        self.preflight = {"status": "entrypoint_observed", "entrypoint_observed": True,
            "release_lock_sha256": self.qual["release_lock"]["sha256"],
            "candidate_sha256": self.qual["candidate"]["sha256"],
            "configuration_sha256": self.qual["probe_config"]["sha256"],
            "full_contract_file_sha256": self.qual["full_contract"]["sha256"],
            "checks": {"whole_server_catalog_sha256": self.contract["catalog_sha256"],
                       "hia_catalog_sha256": self.new_pins["catalog_sha256"], "hia_tool_count": 11, "tool_count": len(self.tools)},
            "evidence": {"origin": "actual_configured_stdio_mcp", "runtime_binary": {
                "sha256": A.digest(self.binary_path.read_bytes())}, "captures": {
                "native-tools.json": self.qual["native_tools"]["sha256"],
                "worker-manifest.json": self.qual["worker_manifest"]["sha256"],
                "stdio-transcript.json": self.qual["stdio_transcript"]["sha256"]}}}
        self.qual["preflight"] = self.ref_json("preflight.json", self.preflight)
        self.request = {"schema": A.SCHEMA, "operation_id": "synthetic-fixture-01", "helper_identity": A.helper_identity(),
            "live_config": self.ref(self.live_path), "candidate_config": self.ref(self.target_path),
            "plist": self.ref(self.plist_path), "binary": self.ref(self.binary_path),
            "online_readback_checker": self.ref(self.checker_path),
            "live_release_lock": self.ref_json("old-lock.json", self.baseline_lock),
            "qualification": self.qual, "service": self.label}

    def put(self, name, raw, mode=0o600):
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def ref(self, path):
        return {"path": str(path), "sha256": A.digest(path.read_bytes())}

    def ref_json(self, name, value):
        return self.ref(self.put(name, A.encode(value)))

    def prepare(self):
        self.plan = A.freeze(self.request, self.bundle, self.service)
        self.plan_sha = A.digest((self.bundle / "plan.json").read_bytes())
        return self.plan

    def loaded_attestation(self, service, configuration_sha256, changes=None):
        value = {"schema": "hepta.mac.hia.loaded-configuration-attestation.v1",
            "status": "verified", "basis": "guarded_startup_receipt",
            "configuration_scope": "entire_runtime_configuration",
            "process": A.process_key(service), "configuration_sha256": configuration_sha256,
            "service_target": service["target"], "producer_source_sha256": "f" * 64,
            "synthetic_fixture_not_production_evidence": True}
        if changes:
            value.update(changes)
        self.counter += 1
        return self.ref_json("loaded-attestation-%d.json" % self.counter, value)

    def admitted(self, mutate=None):
        now = int(time.time())
        loaded = self.loaded_attestation(self.plan["baseline"]["service"], self.plan["baseline"]["config"]["sha256"])
        value = {"schema": "hepta.mac.hia.maintenance-admission.v1", "status": "admitted",
            "binding": {"operation_id": self.plan["operation_id"], "helper_identity": self.plan["helper_identity"],
                "baseline_sha256": A.digest(A.canonical(self.plan["baseline"])),
                "candidate_configuration_sha256": self.plan["candidate"]["sha256"],
                "release_lock_sha256": self.plan["qualification"]["release_lock_sha256"],
                "whole_contract_sha256": self.plan["qualification"]["whole_contract_sha256"]},
            "issued_unix": now - 1, "expires_unix": now + 600,
            "writers": {"model": "cooperating_same_uid_deployment_lock", "all_actual_writers_joined": True,
                "unknown_writer_present": False, "lease_path": self.plan["lease_path"]},
            "state": {"schema_compatibility": "confirmed", "inflight_operations": "drained", "rollback_compatibility": "confirmed"},
            "recovery": {"independent_of_target_service": True}, "reviewed_evidence_sha256": [loaded["sha256"]],
            "baseline_loaded_configuration": loaded}
        if mutate:
            mutate(value)
        self.counter += 1
        return self.ref_json("admission-%d.json" % self.counter, value)

    def events(self):
        with A.contextlib.closing(A.Journal(self.bundle)) as journal:
            return journal.events()

    def apply(self):
        return A.apply(self.bundle, self.plan_sha, self.admitted(), self.service)

    def test_prepare_is_private_and_never_starts_service(self):
        self.prepare()
        self.assertEqual(self.service.restarts, 0)
        self.assertEqual(self.live_path.read_bytes(), A.encode(self.live))
        self.assertEqual(self.bundle.stat().st_mode & 0o777, 0o700)
        self.assertFalse(pathlib.Path(self.plan["owner_path"]).exists())
        self.assertFalse(self.plan["qualification"]["production_state_compatibility_proven_by_probe"])
        self.assertEqual(self.plan["candidate"]["sha256"], A.digest(A.encode(self.target)))

    def test_successful_fake_cutover_remains_pending_real_loaded_readback(self):
        self.prepare()
        result = self.apply()
        self.assertEqual(result["status"], "ACTIVATE_RESTART_RETURNED_AWAITING_OBSERVATION")
        self.assertEqual(self.service.restarts, 1)
        self.assertEqual(self.service.loaded_bytes, A.encode(self.target))
        observed = A.observe(self.bundle, self.plan_sha, self.service)
        self.assertEqual(observed["status"], "ACTIVATE_CONFIG_AND_NEW_PROCESS_OBSERVED")
        self.assertFalse(observed["loaded_configuration_verified"])
        self.assertFalse(observed["formal_hia_verified"])
        self.assertTrue(pathlib.Path(self.plan["owner_path"]).exists())
        kinds = [x["kind"] for x in self.events()]
        self.assertLess(kinds.index("ACTIVATE_CONFIG_INTENT"), kinds.index("ACTIVATE_CONFIG_INSTALLED"))
        self.assertLess(kinds.index("ACTIVATE_RESTART_INTENT"), kinds.index("ACTIVATE_RESTART_RETURNED"))

    def test_pending_operation_is_not_reapplied(self):
        self.prepare()
        self.apply()
        with self.assertRaisesRegex(ValueError, "observe, never reapply"):
            self.apply()
        self.assertEqual(self.service.restarts, 1)

    def test_unknown_after_dispatch_is_observed_without_retry_then_explicit_rollback(self):
        self.prepare()
        self.service.behavior = "timeout_after"
        result = self.apply()
        self.assertEqual(result["status"], "ACTIVATE_RESTART_UNKNOWN")
        self.assertEqual(self.service.restarts, 1)
        A.observe(self.bundle, self.plan_sha, self.service)
        self.assertEqual(self.service.restarts, 1)
        self.service.behavior = "success"
        result = A.rollback(self.bundle, self.plan_sha, self.admitted(), self.service)
        self.assertEqual(result["status"], "ROLLBACK_RESTART_RETURNED_AWAITING_OBSERVATION")
        self.assertEqual(self.service.loaded_bytes, A.encode(self.live))
        self.assertIn("ACTIVATE_RESTART_UNKNOWN", [e["kind"] for e in self.events()])
        self.assertEqual(self.service.restarts, 2)

    def test_unknown_without_new_process_cannot_trigger_rollback_or_abort(self):
        self.prepare()
        self.service.behavior = "timeout_before"
        self.apply()
        result = A.observe(self.bundle, self.plan_sha, self.service)
        self.assertEqual(result["status"], "ACTIVATE_CONFIG_OBSERVED_BASELINE_PROCESS")
        with self.assertRaises(ValueError):
            A.rollback(self.bundle, self.plan_sha, self.admitted(), self.service)
        with self.assertRaises(ValueError):
            A.abort_before_restart(self.bundle, self.plan_sha, self.service)
        self.assertEqual(self.service.restarts, 1)

    def test_rollback_requires_separate_observation(self):
        self.prepare()
        self.apply()
        with self.assertRaisesRegex(ValueError, "observation required"):
            A.rollback(self.bundle, self.plan_sha, self.admitted(), self.service)
        self.assertEqual(self.service.restarts, 1)

    def test_same_bytes_foreign_config_inode_refuses_rollback(self):
        self.prepare()
        self.apply()
        A.observe(self.bundle, self.plan_sha, self.service)
        replacement = self.put("foreign-identical.json", self.live_path.read_bytes())
        os.replace(replacement, self.live_path)
        before = A.snapshot(self.live_path)[1]
        with self.assertRaisesRegex(ValueError, "own activation post-state"):
            A.rollback(self.bundle, self.plan_sha, self.admitted(), self.service)
        self.assertEqual(A.snapshot(self.live_path)[1], before)
        self.assertEqual(self.service.restarts, 1)

    def test_foreign_owner_fence_is_not_overwritten(self):
        self.prepare()
        owner = pathlib.Path(self.plan["owner_path"])
        owner.write_bytes(b"ANOTHER_COOPERATING_OPERATION\n")
        owner.chmod(0o600)
        with self.assertRaises(FileExistsError):
            self.apply()
        self.assertEqual(owner.read_bytes(), b"ANOTHER_COOPERATING_OPERATION\n")
        self.assertEqual(self.live_path.read_bytes(), A.encode(self.live))
        self.assertEqual(self.service.restarts, 0)

    def test_replaced_identical_owner_fence_is_refused(self):
        self.prepare()
        self.apply()
        owner = pathlib.Path(self.plan["owner_path"])
        replacement = self.put("foreign-owner", owner.read_bytes())
        os.replace(replacement, owner)
        with self.assertRaisesRegex(ValueError, "fence identity"):
            A.observe(self.bundle, self.plan_sha, self.service)

    def test_concurrent_cooperating_lock_holder_blocks_before_effect(self):
        self.prepare()
        with A.Lease(self.plan["lease_path"]):
            with self.assertRaises(BlockingIOError):
                self.apply()
        self.assertEqual(self.service.restarts, 0)
        self.assertEqual(self.live_path.read_bytes(), A.encode(self.live))

    def test_baseline_same_bytes_inode_replacement_is_not_accepted(self):
        self.prepare()
        replacement = self.put("replacement.json", self.live_path.read_bytes())
        os.replace(replacement, self.live_path)
        with self.assertRaisesRegex(ValueError, "baseline config"):
            self.apply()
        self.assertEqual(self.service.restarts, 0)

    def test_process_start_drift_is_not_accepted(self):
        self.prepare()
        self.service.generation += 1
        with self.assertRaisesRegex(ValueError, "actual baseline service"):
            self.apply()
        self.assertEqual(self.service.restarts, 0)

    def test_unknown_or_expired_admission_never_touches_live_state(self):
        self.prepare()
        changes = [
            lambda v: v["writers"].update(unknown_writer_present=True),
            lambda v: v["writers"].update(all_actual_writers_joined=False),
            lambda v: v["state"].update(schema_compatibility="unknown"),
            lambda v: v["state"].update(inflight_operations="unknown"),
            lambda v: v["state"].update(rollback_compatibility="unknown"),
            lambda v: v["recovery"].update(independent_of_target_service=False),
            lambda v: v["baseline_loaded_configuration"].update(basis="disk_only"),
            lambda v: v["baseline_loaded_configuration"].update(configuration_sha256="0" * 64),
            lambda v: v.update(issued_unix=1, expires_unix=2),
            lambda v: v["binding"].update(candidate_configuration_sha256="0" * 64),
        ]
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    A.apply(self.bundle, self.plan_sha, self.admitted(change), self.service)
        self.assertEqual(self.events(), [])
        self.assertEqual(self.service.restarts, 0)
        self.assertFalse(pathlib.Path(self.plan["lease_path"]).exists())

    def test_live_state_policy_or_budget_change_is_out_of_scope(self):
        for key, value in (("state_root", "/other"), ("timeout_seconds", 121),
                           ("host", "other"), ("catalog_sha256", "f" * 64),
                           ("artifact_roots", ["/other"])):
            changed = copy.deepcopy(self.target)
            changed["hia_worker"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                A.validate_profile_delta(self.live, changed)
        changed = copy.deepcopy(self.target)
        changed["hosts"]["test-worker"]["allow_write"] = True
        with self.assertRaises(ValueError):
            A.validate_profile_delta(self.live, changed)

    def test_whole_probe_configuration_binding_is_required(self):
        altered = copy.deepcopy(self.probe)
        altered["hosts"]["test-worker"]["changed_policy"] = True
        self.qual["probe_config"] = self.ref_json("altered-probe.json", altered)
        with self.assertRaises(ValueError):
            A.freeze(self.request, self.bundle, self.service)
        self.assertFalse(self.bundle.exists())

    def test_complete_contract_capture_binding_is_required(self):
        changed = copy.deepcopy(self.tools)
        changed[0]["description"] = "different actual definition"
        self.qual["native_tools"] = self.ref_json("altered-tools.json", {"tools": changed})
        with self.assertRaises(ValueError):
            A.freeze(self.request, self.bundle, self.service)
        self.assertFalse(self.bundle.exists())

    def test_failed_preflight_cannot_be_admitted(self):
        self.preflight["status"] = "unknown"
        self.qual["preflight"] = self.ref_json("not-passed.json", self.preflight)
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertFalse(self.bundle.exists())

    def test_helper_identity_is_not_inherited_from_runtime_pin(self):
        self.request["helper_identity"]["mac_hia_activation.py"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "helper identity"):
            self.prepare()
        self.assertFalse(self.bundle.exists())

    def test_fixed_original_checker_source_is_required_and_preserved(self):
        self.assertEqual(self.production_checker_pin,
            "ff9669c365b4056de643129376a3e4868396745f542adf90ef1fb4c114014542")
        original = self.request["online_readback_checker"]
        self.request["online_readback_checker"] = self.ref(self.put("other-checker.py", b"# Different inert bytes.\n"))
        with self.assertRaisesRegex(ValueError, "fixed original checker"):
            self.prepare()
        self.assertFalse(self.bundle.exists())
        self.request["online_readback_checker"] = original
        self.prepare()
        self.checker_path.write_bytes(b"# Changed after preparation.\n")
        with self.assertRaisesRegex(ValueError, "original checker source"):
            self.apply()
        self.assertEqual(self.service.restarts, 0)

    def test_admission_reads_loaded_attestation_bytes_and_checks_subject(self):
        self.prepare()
        changes = [{"configuration_sha256": "0" * 64},
            {"process": {**A.process_key(self.plan["baseline"]["service"]), "pid": 9999}},
            {"service_target": "gui/999/wrong"}, {"configuration_scope": "worker_profile_only"},
            {"basis": "disk_only"}]
        for change in changes:
            with self.subTest(change=change):
                def bad(value):
                    ref = self.loaded_attestation(self.plan["baseline"]["service"],
                        self.plan["baseline"]["config"]["sha256"], change)
                    value["baseline_loaded_configuration"] = ref
                    value["reviewed_evidence_sha256"] = [ref["sha256"]]
                with self.assertRaisesRegex(ValueError, "loaded-config receipt"):
                    A.apply(self.bundle, self.plan_sha, self.admitted(bad), self.service)
        self.assertEqual(self.events(), [])
        self.assertEqual(self.live_path.read_bytes(), A.encode(self.live))

    def test_pre_effect_failure_is_retained_and_can_only_abort_exact_baseline(self):
        self.prepare()
        with mock.patch.object(A.os, "replace", side_effect=OSError("synthetic before-effect failure")):
            with self.assertRaises(OSError):
                self.apply()
        self.assertIn("ACTIVATE_CONFIG_INTENT", [e["kind"] for e in self.events()])
        self.assertEqual(self.live_path.read_bytes(), A.encode(self.live))
        result = A.abort_before_restart(self.bundle, self.plan_sha, self.service)
        self.assertEqual(result["status"], "ABORTED_BASELINE_UNCHANGED")
        self.assertFalse(pathlib.Path(self.plan["owner_path"]).exists())
        self.assertEqual(self.service.restarts, 0)

    def test_interrupted_post_replace_receipt_is_observed_not_replayed(self):
        self.prepare()
        original = A.Journal.append
        def fail_after_config(journal, kind, data):
            if kind == "ACTIVATE_CONFIG_INSTALLED":
                raise OSError("synthetic receipt publication loss")
            return original(journal, kind, data)
        with mock.patch.object(A.Journal, "append", fail_after_config):
            with self.assertRaises(OSError):
                self.apply()
        self.assertEqual(self.live_path.read_bytes(), A.encode(self.target))
        self.assertEqual(self.service.restarts, 0)
        result = A.observe(self.bundle, self.plan_sha, self.service)
        self.assertEqual(result["status"], "ACTIVATE_CONFIG_OBSERVED_BASELINE_PROCESS")
        self.assertFalse(result["loaded_configuration_verified"])
        with self.assertRaises(ValueError):
            self.apply()
        def fail_after_restore(journal, kind, data):
            if kind == "RESTORE_CONFIG_INSTALLED":
                raise OSError("synthetic restore receipt publication loss")
            return original(journal, kind, data)
        with mock.patch.object(A.Journal, "append", fail_after_restore):
            with self.assertRaises(OSError):
                A.restore_before_restart(self.bundle, self.plan_sha, self.admitted(), self.service)
        self.assertEqual(self.live_path.read_bytes(), A.encode(self.live))
        restored = A.observe(self.bundle, self.plan_sha, self.service)
        self.assertEqual(restored["status"], "RESTORE_CONFIG_OBSERVED_PREDECESSOR_PROCESS")
        with self.assertRaises(ValueError):
            A.restore_before_restart(self.bundle, self.plan_sha, self.admitted(), self.service)
        result = A.abort_before_restart(self.bundle, self.plan_sha, self.service)
        self.assertEqual(result["status"], "ABORTED_CONFIG_RESTORED_WITHOUT_RESTART")
        self.assertEqual(self.service.restarts, 0)

    def pause_after_config_before_restart_intent(self):
        with mock.patch.object(A, "restart_once", side_effect=OSError("synthetic pre-intent interruption")):
            with self.assertRaises(OSError):
                self.apply()
        self.assertEqual(self.service.restarts, 0)
        self.assertFalse(any("RESTART_INTENT" in e["kind"] for e in self.events()))

    def test_config_only_restore_requires_observation_then_can_abort_without_restart(self):
        self.prepare()
        self.pause_after_config_before_restart_intent()
        with self.assertRaises(ValueError):
            A.restore_before_restart(self.bundle, self.plan_sha, self.admitted(), self.service)
        A.observe(self.bundle, self.plan_sha, self.service)
        result = A.restore_before_restart(self.bundle, self.plan_sha, self.admitted(), self.service)
        self.assertEqual(result["status"], "RESTORE_CONFIG_RETURNED_AWAITING_OBSERVATION")
        with self.assertRaises(ValueError):
            A.abort_before_restart(self.bundle, self.plan_sha, self.service)
        A.observe(self.bundle, self.plan_sha, self.service)
        result = A.abort_before_restart(self.bundle, self.plan_sha, self.service)
        self.assertEqual(result["status"], "ABORTED_CONFIG_RESTORED_WITHOUT_RESTART")
        self.assertEqual(self.live_path.read_bytes(), self.service.loaded_bytes)
        self.assertEqual(self.live_path.read_bytes(), A.encode(self.live))
        self.assertEqual(self.service.restarts, 0)

    def test_config_only_restore_refuses_same_bytes_foreign_inode(self):
        self.prepare()
        self.pause_after_config_before_restart_intent()
        A.observe(self.bundle, self.plan_sha, self.service)
        replacement = self.put("foreign-target.json", self.live_path.read_bytes())
        os.replace(replacement, self.live_path)
        with self.assertRaisesRegex(ValueError, "own activation post-state"):
            A.restore_before_restart(self.bundle, self.plan_sha, self.admitted(), self.service)
        self.assertEqual(self.live_path.read_bytes(), A.encode(self.target))
        self.assertEqual(self.service.restarts, 0)

    def test_expiry_after_config_intent_refuses_the_rename(self):
        self.prepare()
        admitted = self.admitted()
        expiry = A.decode(pathlib.Path(admitted["path"]).read_bytes())["expires_unix"]
        clock = [int(time.time())]
        original = A.Journal.append
        def expire_on_intent(journal, kind, data):
            result = original(journal, kind, data)
            if kind == "ACTIVATE_CONFIG_INTENT":
                clock[0] = expiry
            return result
        with mock.patch.object(A.time, "time", side_effect=lambda: clock[0]), \
                mock.patch.object(A.Journal, "append", expire_on_intent):
            with self.assertRaisesRegex(ValueError, "expired"):
                A.apply(self.bundle, self.plan_sha, admitted, self.service)
        self.assertEqual(self.live_path.read_bytes(), A.encode(self.live))
        self.assertEqual(self.service.restarts, 0)
        A.abort_before_restart(self.bundle, self.plan_sha, self.service)

    def test_expiry_after_config_install_refuses_restart_and_allows_explicit_restore(self):
        self.prepare()
        admitted = self.admitted()
        expiry = A.decode(pathlib.Path(admitted["path"]).read_bytes())["expires_unix"]
        clock = [int(time.time())]
        original = A.Journal.append
        def expire_after_install(journal, kind, data):
            result = original(journal, kind, data)
            if kind == "ACTIVATE_CONFIG_INSTALLED":
                clock[0] = expiry
            return result
        with mock.patch.object(A.time, "time", side_effect=lambda: clock[0]), \
                mock.patch.object(A.Journal, "append", expire_after_install):
            with self.assertRaisesRegex(ValueError, "expired"):
                A.apply(self.bundle, self.plan_sha, admitted, self.service)
        self.assertFalse(any("RESTART_INTENT" in e["kind"] for e in self.events()))
        A.observe(self.bundle, self.plan_sha, self.service)
        A.restore_before_restart(self.bundle, self.plan_sha, self.admitted(), self.service)
        A.observe(self.bundle, self.plan_sha, self.service)
        A.abort_before_restart(self.bundle, self.plan_sha, self.service)
        self.assertEqual(self.live_path.read_bytes(), A.encode(self.live))
        self.assertEqual(self.service.restarts, 0)

    def test_expiry_during_restart_intent_records_no_dispatch_without_replaying(self):
        self.prepare()
        admitted = self.admitted()
        expiry = A.decode(pathlib.Path(admitted["path"]).read_bytes())["expires_unix"]
        clock = [int(time.time())]
        original = A.Journal.append
        def expire_on_restart_intent(journal, kind, data):
            result = original(journal, kind, data)
            if kind == "ACTIVATE_RESTART_INTENT":
                clock[0] = expiry
            return result
        with mock.patch.object(A.time, "time", side_effect=lambda: clock[0]), \
                mock.patch.object(A.Journal, "append", expire_on_restart_intent):
            with self.assertRaisesRegex(ValueError, "expired"):
                A.apply(self.bundle, self.plan_sha, admitted, self.service)
        self.assertIn("ACTIVATE_RESTART_NOT_DISPATCHED", [e["kind"] for e in self.events()])
        A.observe(self.bundle, self.plan_sha, self.service)
        with self.assertRaisesRegex(ValueError, "restart or prior restoration intent"):
            A.restore_before_restart(self.bundle, self.plan_sha, self.admitted(), self.service)
        with self.assertRaises(ValueError):
            self.apply()
        self.assertEqual(self.service.restarts, 0)

    def test_interrupted_owner_acknowledgement_recovers_only_exact_original_claim(self):
        self.prepare()
        original = A.Journal.append
        def fail_after_owner(journal, kind, data):
            if kind == "OWNERSHIP_CLAIMED":
                raise OSError("synthetic owner acknowledgement loss")
            return original(journal, kind, data)
        with mock.patch.object(A.Journal, "append", fail_after_owner):
            with self.assertRaises(OSError):
                self.apply()
        self.assertEqual(self.service.restarts, 0)
        self.assertEqual(self.live_path.read_bytes(), A.encode(self.live))
        observed = A.observe(self.bundle, self.plan_sha, self.service)
        self.assertEqual(observed["status"], "NO_CONFIG_EFFECT_INTENT")
        self.assertIn("OWNERSHIP_CLAIM_RECOVERED", [e["kind"] for e in self.events()])
        A.abort_before_restart(self.bundle, self.plan_sha, self.service)
        self.assertEqual(self.service.restarts, 0)

    def test_hardlink_symlink_and_duplicate_json_are_refused(self):
        hard = self.root / "hardlink"
        os.link(self.target_path, hard)
        with self.assertRaises(ValueError):
            A.snapshot(self.target_path)
        hard.unlink()
        link = self.root / "symlink"
        link.symlink_to(self.target_path)
        with self.assertRaises(OSError):
            A.snapshot(link)
        with self.assertRaises(ValueError):
            A.decode(b'{"x":1,"x":2}')

    def test_native_adapter_refuses_this_test_environment(self):
        with mock.patch.object(A.sys, "platform", "linux"):
            with self.assertRaises(RuntimeError):
                A.MacGUI(self.label, str(self.plist_path), str(self.live_path), str(self.binary_path))

    @A.contextlib.contextmanager
    def mocked_mac_adapter(self, wrong_inode=False, changed_start=False):
        # Keep the simulated login consistent with real temporary-file owners.
        # Root-owned fixture files remain admissible on root-run test hosts.
        mac_uid = os.getuid() or 501
        token = self.put("never-read-token", b"SYNTHETIC_SECRET_MUST_NOT_BE_READ")
        pointer = self.root / "current-runtime"
        pointer.symlink_to(self.binary_path)
        argv = [str(pointer), "mcp", "--runtime-config", str(self.live_path),
                "--auth-token-file", str(token)]
        self.plist_path.write_bytes(plistlib.dumps({"Label": self.label, "ProgramArguments": argv}))
        info = self.binary_path.stat()
        count = [0]
        def output(args, timeout=10):
            if args[:2] == ["/bin/launchctl", "print"]:
                return ("fixture = {\n\tpath = " + str(self.plist_path) + "\n\tprogram = " + str(pointer)
                        + "\n\tpid = 700\n\tstate = running\n}\n")
            if args == ["/bin/ps", "-p", "700", "-o", "args="]:
                return shlex.join(argv) + "\n"
            if args == ["/bin/ps", "-p", "700", "-o", "uid="]:
                return str(mac_uid) + "\n"
            if args == ["/bin/ps", "-p", "700", "-o", "lstart="]:
                count[0] += 1
                return "SYNTHETIC_START_" + str(count[0] if changed_start else 1)
            if args[:1] == ["/usr/sbin/lsof"]:
                return "p700\nD0x%x\ni%d\nn%s\n" % (info.st_dev, info.st_ino + int(wrong_inode), self.binary_path)
            raise AssertionError("unexpected OS command: " + repr(args))
        lib = mock.Mock()
        def loaded_path(pid, buf, size):
            buf.value = str(self.binary_path).encode()
            return len(buf.value)
        lib.proc_pidpath.side_effect = loaded_path
        original_snapshot = A.snapshot
        def no_token(path, *args, **kwargs):
            if pathlib.Path(path) == token:
                raise AssertionError("credential reference was dereferenced")
            return original_snapshot(path, *args, **kwargs)
        with mock.patch.object(A.sys, "platform", "darwin"), mock.patch.object(A.os, "geteuid", return_value=mac_uid), \
                mock.patch.object(A.os, "getuid", return_value=mac_uid), \
                mock.patch.object(A.MacGUI, "run", side_effect=output), mock.patch.object(A.ctypes, "CDLL", return_value=lib), \
                mock.patch.object(A, "snapshot", side_effect=no_token):
            yield A.MacGUI(self.label, str(self.plist_path), str(self.live_path), str(self.binary_path))

    def test_mocked_mac_observer_binds_real_file_not_argv_pointer_or_credentials(self):
        with self.mocked_mac_adapter() as backend:
            result = backend.observe()
        self.assertEqual(result["loaded_binary_sha256"], A.digest(self.binary_path.read_bytes()))
        self.assertIsNone(result["loaded_configuration_sha256"])
        self.assertEqual(self.service.restarts, 0)

    def test_mocked_mac_observer_rejects_different_loaded_inode(self):
        with self.mocked_mac_adapter(wrong_inode=True) as backend:
            with self.assertRaisesRegex(ValueError, "loaded executable inode"):
                backend.observe()

    def test_mocked_mac_observer_rejects_start_identity_change(self):
        with self.mocked_mac_adapter(changed_start=True) as backend:
            with self.assertRaisesRegex(ValueError, "start identity changed"):
                backend.observe()

    def completion(self, observation, rolled_back=False):
        pins = self.old_pins if rolled_back else self.new_pins
        lock = self.plan["baseline_release_lock"]["sha256"] if rolled_back else self.plan["qualification"]["release_lock_sha256"]
        report = {"schema": "hepta.hia.online-release-readback.v1", "status": "PASS_CURRENT_INSTALLATION_READBACK",
            "passed": True, "release_lock_sha256": lock, "expected_installation": pins,
            "observed_installation": pins, "matches": {k: True for k in A.PINS}}
        report_ref = self.ref_json("synthetic-readback.json", report)
        execution_ref = self.ref_json("synthetic-checker-execution.json", {"exit_code": 0,
            "stdout_sha256": report_ref["sha256"], "checker_source_unchanged": True,
            "checker_sha256": self.plan["online_readback_checker"]["sha256"]})
        value = {"schema": "hepta.mac.hia.completion.v1", "plan_sha256": self.plan_sha,
            "process": A.process_key(observation["service"]),
            "configuration_sha256": A.digest(A.encode(self.live if rolled_back else self.target)),
            "loaded_configuration": self.loaded_attestation(observation["service"],
                A.digest(A.encode(self.live if rolled_back else self.target))),
            "readback_report": report_ref, "checker_execution": execution_ref}
        return value

    def test_owner_release_requires_external_loaded_config_and_checker_receipts(self):
        self.prepare()
        self.apply()
        observation = A.observe(self.bundle, self.plan_sha, self.service)
        complete = self.completion(observation)
        bad = copy.deepcopy(complete)
        bad["loaded_configuration"] = self.loaded_attestation(observation["service"],
            complete["configuration_sha256"], {"basis": "disk_only"})
        with self.assertRaises(ValueError):
            A.finish(self.bundle, self.plan_sha, self.ref_json("bad-completion.json", bad), self.service)
        self.assertTrue(pathlib.Path(self.plan["owner_path"]).exists())
        result = A.finish(self.bundle, self.plan_sha, self.ref_json("completion.json", complete), self.service)
        self.assertEqual(result["status"], "OWNER_RELEASED_AFTER_EXTERNAL_VERIFICATION")
        self.assertFalse(pathlib.Path(self.plan["owner_path"]).exists())
        self.assertEqual(self.service.restarts, 1)

    def test_completion_checks_original_checker_and_actual_loaded_subject_bytes(self):
        self.prepare()
        self.apply()
        observation = A.observe(self.bundle, self.plan_sha, self.service)
        changes = [{"configuration_sha256": "0" * 64},
            {"process": {**A.process_key(observation["service"]), "pid": 9999}},
            {"service_target": "gui/999/wrong"}, {"configuration_scope": "worker_profile_only"}]
        for change in changes:
            with self.subTest(change=change):
                value = self.completion(observation)
                value["loaded_configuration"] = self.loaded_attestation(observation["service"],
                    value["configuration_sha256"], change)
                with self.assertRaisesRegex(ValueError, "loaded-config receipt"):
                    A.finish(self.bundle, self.plan_sha, self.ref_json("bad-subject.json", value), self.service)
        value = self.completion(observation)
        execution = A.decode(pathlib.Path(value["checker_execution"]["path"]).read_bytes())
        execution["checker_sha256"] = "9" * 64
        value["checker_execution"] = self.ref_json("different-checker.json", execution)
        with self.assertRaisesRegex(ValueError, "original checker execution binding"):
            A.finish(self.bundle, self.plan_sha, self.ref_json("bad-checker-completion.json", value), self.service)
        value = self.completion(observation)
        pathlib.Path(value["loaded_configuration"]["path"]).write_bytes(b"{}\n")
        with self.assertRaisesRegex(ValueError, "bytes differ from pin"):
            A.finish(self.bundle, self.plan_sha, self.ref_json("changed-attestation-completion.json", value), self.service)
        self.assertTrue(pathlib.Path(self.plan["owner_path"]).exists())
        self.assertEqual(self.service.restarts, 1)

    def test_rollback_is_conditional_and_cannot_be_repeated(self):
        self.prepare()
        self.apply()
        A.observe(self.bundle, self.plan_sha, self.service)
        A.rollback(self.bundle, self.plan_sha, self.admitted(), self.service)
        observed = A.observe(self.bundle, self.plan_sha, self.service)
        self.assertEqual(observed["status"], "ROLLBACK_CONFIG_AND_NEW_PROCESS_OBSERVED")
        with self.assertRaises(ValueError):
            A.rollback(self.bundle, self.plan_sha, self.admitted(), self.service)
        self.assertEqual(self.service.restarts, 2)
        A.finish(self.bundle, self.plan_sha, self.ref_json("rollback-complete.json", self.completion(observed, True)), self.service)
        self.assertEqual(self.live_path.read_bytes(), A.encode(self.live))

    def test_rollback_timeout_before_restart_does_not_reuse_candidate_pid_as_new(self):
        self.prepare()
        self.apply()
        A.observe(self.bundle, self.plan_sha, self.service)
        self.service.behavior = "timeout_before"
        result = A.rollback(self.bundle, self.plan_sha, self.admitted(), self.service)
        self.assertEqual(result["status"], "ROLLBACK_RESTART_UNKNOWN")
        observed = A.observe(self.bundle, self.plan_sha, self.service)
        self.assertEqual(observed["status"], "ROLLBACK_CONFIG_OBSERVED_PREDECESSOR_PROCESS")
        self.assertEqual(self.service.restarts, 2)
        self.assertEqual(self.service.loaded_bytes, A.encode(self.target))
        self.assertEqual(self.live_path.read_bytes(), A.encode(self.live))
        with self.assertRaises(ValueError):
            A.finish(self.bundle, self.plan_sha,
                     self.ref_json("premature-rollback-completion.json", self.completion(observed, True)), self.service)

    def test_journal_refuses_insufficient_continuation_before_claim_or_live_effect(self):
        self.prepare()
        with mock.patch.object(A, "JOURNAL_CAPACITY", 15):
            with self.assertRaisesRegex(ValueError, "cannot reserve the required continuation"):
                self.apply()
            self.assertEqual(self.events(), [])
        self.assertFalse(pathlib.Path(self.plan["owner_path"]).exists())
        self.assertEqual(self.live_path.read_bytes(), A.encode(self.live))
        self.assertEqual(self.service.restarts, 0)

    def test_minimum_journal_budget_covers_activate_rollback_observations_and_finish(self):
        self.prepare()
        with mock.patch.object(A, "JOURNAL_CAPACITY", 16):
            self.apply()
            first = A.observe(self.bundle, self.plan_sha, self.service)
            self.assertTrue(first["journal_recorded"])
            self.assertEqual(first["reserved_slots"], 8)
            self.assertEqual(len(self.events()), 8)
            A.rollback(self.bundle, self.plan_sha, self.admitted(), self.service)
            restored = A.observe(self.bundle, self.plan_sha, self.service)
            self.assertEqual(restored["reserved_slots"], 2)
            A.finish(self.bundle, self.plan_sha,
                self.ref_json("minimum-budget-completion.json", self.completion(restored, True)), self.service)
            events = self.events()
            self.assertEqual(len(events), 16)
            self.assertEqual(events[-1]["reserved_slots"], 0)
            self.assertTrue(all(e["sequence"] + 1 + e["reserved_slots"] <= 16 for e in events))
        self.assertEqual(self.service.restarts, 2)
        self.assertFalse(pathlib.Path(self.plan["owner_path"]).exists())

    def test_unknown_reads_preserve_slots_for_later_observation_and_compensation(self):
        self.prepare()
        self.service.behavior = "timeout_before"
        with mock.patch.object(A, "JOURNAL_CAPACITY", 16):
            self.apply()
            for _ in range(3):
                observed = A.observe(self.bundle, self.plan_sha, self.service)
                self.assertFalse(observed["journal_recorded"])
                self.assertEqual(observed["journal_reason"], "continuation slots preserved")
                self.assertEqual(len(self.events()), 7)
                self.assertEqual(self.events()[-1]["reserved_slots"], 9)
            # Model completion of the original uncertain effect, not a retry.
            self.service.pid += 1
            self.service.generation += 1
            self.service.loaded_bytes = self.live_path.read_bytes()
            self.service.behavior = "success"
            observed = A.observe(self.bundle, self.plan_sha, self.service)
            self.assertTrue(observed["journal_recorded"])
            A.rollback(self.bundle, self.plan_sha, self.admitted(), self.service)
            restored = A.observe(self.bundle, self.plan_sha, self.service)
            A.finish(self.bundle, self.plan_sha,
                self.ref_json("uncertain-budget-completion.json", self.completion(restored, True)), self.service)
            self.assertEqual(len(self.events()), 16)
            self.assertIn("ACTIVATE_RESTART_UNKNOWN", [e["kind"] for e in self.events()])
        self.assertEqual(self.service.restarts, 2)

    def test_repeated_observation_does_not_spend_reserved_finish_slots(self):
        self.prepare()
        with mock.patch.object(A, "JOURNAL_CAPACITY", 16):
            self.apply()
            observed = A.observe(self.bundle, self.plan_sha, self.service)
            for _ in range(3):
                repeated = A.observe(self.bundle, self.plan_sha, self.service)
                self.assertFalse(repeated["journal_recorded"])
                self.assertEqual(repeated["journal_reason"], "unchanged observation")
                self.assertEqual(len(self.events()), 8)
            A.finish(self.bundle, self.plan_sha,
                self.ref_json("repeated-budget-completion.json", self.completion(observed)), self.service)
            self.assertEqual(len(self.events()), 10)
        self.assertEqual(self.service.restarts, 1)

    def test_minimum_journal_budget_retains_interrupted_owner_recovery_and_abort(self):
        self.prepare()
        original = A.Journal.append
        def lose_owner_ack(journal, kind, data):
            if kind == "OWNERSHIP_CLAIMED":
                raise OSError("synthetic owner acknowledgement loss at minimum budget")
            return original(journal, kind, data)
        with mock.patch.object(A, "JOURNAL_CAPACITY", 16):
            with mock.patch.object(A.Journal, "append", lose_owner_ack):
                with self.assertRaises(OSError):
                    self.apply()
            observed = A.observe(self.bundle, self.plan_sha, self.service)
            self.assertEqual(observed["status"], "NO_CONFIG_EFFECT_INTENT")
            self.assertFalse(observed["journal_recorded"])
            self.assertIn("OWNERSHIP_CLAIM_RECOVERED", [e["kind"] for e in self.events()])
            A.abort_before_restart(self.bundle, self.plan_sha, self.service)
            self.assertEqual(self.events()[-1]["reserved_slots"], 0)
        self.assertEqual(self.service.restarts, 0)
        self.assertEqual(self.live_path.read_bytes(), A.encode(self.live))


if __name__ == "__main__":
    unittest.main(verbosity=2)
