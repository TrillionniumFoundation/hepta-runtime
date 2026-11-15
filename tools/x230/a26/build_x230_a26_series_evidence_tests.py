#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Synthetic publisher checks only: no binaries, subprocesses, RPCs or SSH."""

import argparse
import copy
import gzip
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "a25-evidence-tools"))
import build_x230_a26_series_evidence as evidence

A20, A26 = "a" * 64, "b" * 64


def shutdown():
    return {"exit_code": 0, "shutdown_method": "stdin_eof", "reader_error": None,
            "unmatched_responses": 0, "observed_descendant_survivors": [],
            "resources": {"samples": 2, "peaks": {"controller_rss_kib": 1000}, "errors": []}}


def specs(root):
    rows = []
    for name in evidence.STAGE_IDS:
        compare = name.endswith("_compare")
        kind = "fairness" if name.startswith("fairness") else "observation" if name in evidence.STAGE_IDS[:8] else name
        helper = ("x230_observation_fairness.py" if kind == "fairness" else
                  "x230_observation_benchmark.py" if compare else "x230_observation_soak.py" if kind == "observation" else
                  "x230_controller_recovery_check.py" if kind == "completed_recovery" else
                  "x230_native_lifecycle_canary.py" if kind == "single_running" else "x230_six_running_recovery_canary.py")
        row = {"stage_id": name, "kind": kind, "helper": helper, "condition": "synthetic predeclared fixture",
               "output_directory": str(root / (name + "-a26-synthetic")),
               "role_by_slot": {"A": "A20" if compare else "A26", "B": "A26"}}
        if kind in {"observation", "fairness"}:
            row.update(order="ABBA" if compare or kind == "fairness" else "B",
                       calls=None if kind == "fairness" or name == "soak" else 192 if name == "calibration" else 96,
                       concurrency=None if kind == "fairness" else [1, 4, 8] if name.startswith("standard")
                           else [16] if name.startswith("capacity") else [8])
        if kind == "fairness":
            row.update(waves=8, gate_budget_ms=120)
        if name == "capacity_compare":
            row["capacity_exception"] = True
        if name == "soak":
            row["helper"] = "x230_observation_soak_resources_20261024.py"
        rows.append(row)
    return rows


def call(okay=True, index=0):
    return {"okay": okay, "elapsed_ms": 2.0, "tool": "process_status", "host": "mac",
            "index": index, **({} if okay else {"error_type": "SyntheticFailure", "native_error": "retained failure"})}


def observation(spec, baseline_failure=False, same_candidate=False):
    roles = spec["role_by_slot"]
    result = {"schema": "hepta-x230-readonly-observation-abba/v1", "passed": not baseline_failure,
        "order": spec["order"], "calls_per_cell": spec["calls"], "concurrency": spec["concurrency"], "tokio_workers": 2,
        "binary_sha256": {slot: A26 if role == "A26" else A20 for slot, role in roles.items()},
        "effect_starts": 0, "remote_mutation_tool_calls": 0, "automatic_rpc_retries": 0,
        "source_originals_unchanged": True, "binary_hashes_unchanged": True, "rounds": [],
        "started_unix": 1, "finished_unix": 2}
    for index, slot in enumerate(spec["order"]):
        cells = []
        fail = baseline_failure and roles[slot] == "A20"
        for concurrency in spec["concurrency"]:
            rows = [call(not fail, number) for number in range(spec["calls"])]
            cells.append({"concurrency": concurrency, "calls": len(rows), "successes": sum(row["okay"] for row in rows),
                "rows": rows, "seconds": 600.0 if spec["stage_id"] in {"calibration", "soak"} else 1.0,
                "controller_cpu_seconds": 0.1, "sampled_tree_cpu_seconds_delta": 0.2, "no_success_filtering": True})
        result["rounds"].append({"index": index, "version": slot, "passed": not fail, "cells": cells,
            "startup": {"pid": 84327, "birth_ticks": 1}, "restart_startup": {"pid": 84328, "birth_ticks": 2},
            "initial_complete_outputs": [call() for _ in range(6)], "restart_checks": [call() for _ in range(12)],
            "shutdown": shutdown(), "restart_shutdown": shutdown()})
    return result


def fairness(spec):
    result = observation({**spec, "calls": 1, "concurrency": [8]})
    result.update(schema="hepta-x230-readonly-observation-fairness/v1", waves_per_cell=8, calls_per_wave=10,
                  wave_retry_count=0, private_originals_unchanged=True, current_agent_unchanged=True)
    for rnd in result["rounds"]:
        rnd.pop("restart_startup")
        rnd.pop("restart_shutdown")
        rnd["final_complete_outputs"] = rnd.pop("restart_checks")[:6]
        rnd["metadata_observations"] = [call()]
        rnd["cells"] = []
        for name in ("balanced", "hot_only", "skew"):
            waves = [{"index": index, "rows": [call() for _ in range(10)], "metadata_observations": [call()],
                      "tail_calls_submitted": 2, "passed": True, "gate_passed": True,
                      "final_metadata_consistent": True, "all_final_metadata_completed": True} for index in range(8)]
            rnd["cells"].append({"name": name, "waves": waves, "requested_waves": 8, "calls": 80, "successes": 80,
                "gate_failures": 0, "metadata_failures": 0, "seconds": 1.0, "controller_cpu_seconds": 0.1,
                "sampled_tree_cpu_seconds_delta": 0.1, "passed": True})
    return result


def write(path, value, raw=False):
    data = value if raw else evidence.canonical(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"bytes": len(data), "sha256": evidence.sha(data)}


def minimal_series(root, report_state="parsed"):
    """A fully retained failed stage and explicitly unrun later work; missing qualification is deliberate."""
    series_root = root / "a26-series-synthetic"
    series_root.mkdir()
    planned = specs(root)
    spec = planned[0]
    output = Path(spec["output_directory"])
    output.mkdir()
    report = observation(spec, baseline_failure=True)
    report["rounds"][0]["cells"][0]["rows"][0].update(argv=["SYNTHETIC_PRIVATE_ARG"], stdin_base64="eA==",
        pid=84327, error="pid 84327 /home/synthetic-private/file")
    before = {"source": {"src/main.rs": "c" * 64}, "files": {}, "frozen_jobs": {"one.json": "d" * 64}}
    before_receipt = write(series_root / "inputs-before.json", before)
    after_receipt = write(series_root / "inputs-after.json", before)
    runner_receipt = write(series_root / "runner.py", b"# Synthetic input only; never executed.\n", True)
    plan = {"schema": evidence.PLAN_SCHEMA, "candidate": "A26", "specs": planned,
            "candidate_sha256": A26, "baseline_sha256": A20, "runner_sha256": runner_receipt["sha256"],
            "inputs_before_sha256": before_receipt["sha256"], "helpers": {}, "source_file_count": 1,
            "source_map_sha256": evidence.source_map_digest(before["source"]), "workers": 2,
            "automatic_rpc_retries": 0, "trial_retries": 0, "production_services_changed": False}
    plan_receipt = write(series_root / "plan.json", plan)
    report_receipt = write(output / "report.json", report)
    artifacts = {"report.json": report_receipt}
    for name in evidence.expected_controller_stderr(report, spec):
        artifacts[name] = write(output / name, b"", True)
    artifacts["ssh-profile/config"] = write(output / "ssh-profile/config", b"PRIVATE_SSH_CONFIGURATION", True)
    logs = {stream: write(series_root / (spec["stage_id"] + "." + stream + ".log"), b"", True)
            for stream in ("stdout", "stderr")}
    row = {"stage_id": spec["stage_id"], "kind": spec["kind"], "spec": spec, "role_by_slot": spec["role_by_slot"],
        "order": spec["order"], "output_directory": str(output), "report_path": str(output / "report.json"),
        "report_sha256": report_receipt["sha256"], "raw_passed": False, "driver_returncode": 1, "interrupted": False,
        "artifact_hashes": artifacts, "inputs_after": before, "inputs_unchanged": True, "driver_logs": logs,
        "spawn_proof_events": [], "expected_controller_stderr": evidence.expected_controller_stderr(report, spec),
        "collection_errors": [], "accepted_for_continuation": True,
        "assessment": {"safe_to_continue": True, "complete_for_scope": False, "candidate_failure": False,
            "candidate_coverage_complete": True, "baseline_only_failure": True, "shared_failures": []}}
    receipt_path = series_root / (spec["stage_id"] + ".receipt.json")
    row_receipt = write(receipt_path, row)
    series = {"schema": evidence.SERIES_SCHEMA, "candidate": "A26", "candidate_validation_passed": False,
        "comparison_valid": False, "comparison_invalid_reasons": [{"reason": "synthetic retained A20 failure"}],
        "completed": False, "final_inputs_unchanged": True, "plan_sha256": plan_receipt["sha256"],
        "inputs_before_sha256": before_receipt["sha256"], "inputs_after_sha256": after_receipt["sha256"],
        "runner_sha256": runner_receipt["sha256"], "candidate_sha256": A26, "baseline_sha256": A20,
        "started_unix": 1, "finished_unix": 2,
        "coverage": {key: {"state": "not-run", "evidence_stage_ids": []} for key in evidence.COVERAGE},
        "stages": {name: {"state": "not-run", "reason": "synthetic stop"} for name in evidence.STAGE_IDS},
        "experiments": [{**row, "receipt_path": str(receipt_path), "receipt_sha256": row_receipt["sha256"]}]}
    series["stages"][spec["stage_id"]] = {"state": "completed", "raw_passed": False, "accepted_for_continuation": True}
    if report_state == "missing":
        (output / "report.json").unlink()
    elif report_state == "unparseable":
        (output / "report.json").write_bytes(b"{")
    write(series_root / "series.json", series)
    return argparse.Namespace(series=series_root / "series.json", qualification=root / "missing-qualification.json",
        qualification_receipt=root / "missing-qualification-receipt.json", runner=series_root / "runner.py",
        output_dir=root / "publication"), report


class PublisherTests(unittest.TestCase):
    def test_qualification_bindings_positive_and_corruption_refused(self):
        source = {"src/main.rs": "c" * 64}
        digest = evidence.source_map_digest(source)
        stages = [{"name": name, "returncode": 0, "log_sha256": evidence.sha(name.encode())} for name in evidence.QUAL_STAGES]
        qualified = {"schema": "runtime-candidate-qualification/v1", "qualified": True, "service_changes": False,
            "source_tested": source, "source_after": source, "stages": stages,
            "binary": {"sha256": A26}, "test_binary": {"sha256": "e" * 64}}
        qraw = evidence.canonical(qualified)
        receipt = {"schema": "hepta-x230-qualification-independent-receipt/v1", "candidate": "A26", "qualified": True,
            "source_report_sha256": evidence.sha(qraw), "source_report_bytes": len(qraw), "success_checks_evaluated": True,
            "unmet_checks": [], "verification": {"synthetic_input_bindings": True},
            "source": {"tested_map_sha256": digest, "after_map_sha256": digest, "actual_map_sha256": digest,
                "tested_file_count": 1, "after_file_count": 1, "actual_file_count": 1},
            "stages": [{**row, "log_hash_verified": True, "actual_log_sha256": row["log_sha256"]} for row in stages]}
        for name in ("binary", "test_binary"):
            receipt[name] = {"verified": True, "reported_sha256": qualified[name]["sha256"],
                             "copied": {"sha256": qualified[name]["sha256"]}}
        rraw, runner = evidence.canonical(receipt), b"# synthetic input only\n"
        inputs = evidence.Inputs()
        for label, raw in (("qualification.json", qraw), ("qualification-receipt.json", rraw), ("runner.py", runner)):
            inputs.files[label] = {"present": True, "bytes": len(raw), "sha256": evidence.sha(raw)}
        helpers = {name: evidence.sha(name.encode()) for name in evidence.HELPER_NAMES}
        plan = {"helpers": helpers, "qualification_sha256": evidence.sha(qraw), "qualification_receipt_sha256": evidence.sha(rraw),
            "runner_sha256": evidence.sha(runner), "source_map_sha256": digest, "source_file_count": 1,
            "candidate_sha256": A26, "baseline_sha256": A20}
        files = {"/tmp/synthetic/" + key: value for key, value in inputs.files.items()}
        files.update({"/tmp/synthetic/" + name: {"sha256": digest, "bytes": 1} for name, digest in helpers.items()})
        files.update({"/tmp/synthetic/" + name: {"sha256": digest, "bytes": 1} for name, digest in (("A20", A20), ("A26", A26))})
        before = {"source": source, "files": files}
        checks, _summary = evidence.qualification_checks(qualified, receipt, inputs, plan, before, runner)
        self.assertTrue(all(checks.values()), checks)
        broken = copy.deepcopy(receipt)
        broken["binary"]["copied"]["sha256"] = "f" * 64
        checks, _summary = evidence.qualification_checks(qualified, broken, inputs, plan, before, runner)
        self.assertFalse(checks["both_compiled_artifacts_independently_bound"])

    def test_complete_failed_rounds_preserve_all_rows_and_candidate_scope(self):
        spec = specs(Path("/tmp/synthetic"))[0]
        report = observation(spec, baseline_failure=True)
        result = evidence.summarize_report(report, spec, A26, A20)
        self.assertTrue(result["structural_complete"])
        self.assertTrue(result["candidate_scope_passed"])
        self.assertFalse(result["slot_results"]["A"]["scope_passed"])
        self.assertEqual(result["call_groups"]["timed"], {"recorded_rows": 1152, "successes": 576, "failures": 576, "unknown_outcomes": 0})
        self.assertEqual(len(result["all_failure_rows"]["timed"]), 576)
        report["rounds"][1]["shutdown"]["exit_code"] = 1
        failed = evidence.summarize_report(report, spec, A26, A20)
        self.assertTrue(failed["structural_complete"])
        self.assertFalse(failed["candidate_scope_passed"])

    def test_same_candidate_fairness_slots_have_no_version_comparison(self):
        spec = next(row for row in specs(Path("/tmp/synthetic")) if row["stage_id"] == "fairness_candidate")
        result = evidence.summarize_report(fairness(spec), spec, A26, A20)
        self.assertTrue(result["structural_complete"])
        self.assertTrue(result["candidate_scope_passed"])
        self.assertTrue(result["same_binary_slots"])
        self.assertFalse(result["performance_comparison_generated"])
        self.assertEqual({row["runtime_role"] for row in result["slot_results"].values()}, {"A26"})
        self.assertEqual(result["call_groups"]["timed"]["recorded_rows"], 960)

    def test_six_host_raw_ssh_stderr_is_retained(self):
        with tempfile.TemporaryDirectory(prefix="a26-ssh-log-synthetic-") as temporary:
            directory = Path(temporary)
            name = "ssh-0001-mac-inspect.stderr"
            original = b"Synthetic transport failure for /home/private-person/job\n"
            declared = {name: write(directory / name, original, True)}
            result = evidence.artifacts_for_stage(directory, "six_running", declared, evidence.Inputs())
            self.assertTrue(result["all_actual_hashes_match"])
            public = evidence.CompleteSanitizer(result)(result["payloads"])
            value = public[name]
            self.assertEqual(value["complete_line_count"], 1)
            self.assertIn("Synthetic transport failure", value["lines"][0]["value"])
            self.assertNotIn("private-person", json.dumps(public))

    def test_candidate_structural_coverage_survives_later_baseline_abort(self):
        spec = specs(Path("/tmp/synthetic"))[0]
        report = observation(spec)
        report["rounds"][-1]["cells"] = []
        report["rounds"][-1]["passed"] = False
        report["passed"] = False
        result = evidence.summarize_report(report, spec, A26, A20)
        self.assertFalse(result["structural_complete"])
        self.assertTrue(result["candidate_structural_complete"])
        self.assertTrue(result["candidate_scope_passed"])

    def test_aborted_baseline_and_missing_candidate_are_not_a_candidate_pass(self):
        spec = specs(Path("/tmp/synthetic"))[0]
        report = observation(spec, True)
        report["rounds"] = report["rounds"][:1]
        result = evidence.summarize_report(report, spec, A26, A20)
        self.assertTrue(result["candidate_not_exercised"])
        self.assertFalse(result["candidate_scope_passed"])
        fallback = specs(Path("/tmp/synthetic"))[1]
        result = evidence.summarize_report(observation(fallback), fallback, A26, A20)
        self.assertTrue(result["candidate_scope_passed"])
        self.assertEqual(result["slot_results"]["A"]["requested_rounds"], 0)

    def test_payload_and_pid_redaction_without_row_filtering(self):
        raw = {"pid": 84327, "argv": ["PRIVATE_ARG"], "stdin_base64": "eA==", "start_monotonic": 1.5,
               "env": {"OPAQUE_VAR": "SYNTHETIC_PRIVATE_ENV"},
               "error": "pid 84327 /home/private-person/file", "rows": [call(False)],
               "pretty_log_line": '  "argv": ["PRIVATE_ARG"],\n', "digest": "c" * 64}
        public = evidence.CompleteSanitizer(raw)(raw)
        encoded = json.dumps(public)
        for secret in ("84327", "PRIVATE_ARG", "eA==", "private-person", "SYNTHETIC_PRIVATE_ENV"):
            self.assertNotIn(secret, encoded)
        self.assertEqual(public["start_monotonic"], 1.5)
        self.assertEqual(public["digest"], "c" * 64)
        self.assertEqual(len(public["rows"]), 1)
        self.assertFalse(public["rows"][0]["okay"])

    def test_end_to_end_failed_report_is_retained_with_not_run_stages(self):
        with tempfile.TemporaryDirectory(prefix="a26-publisher-synthetic-") as temporary:
            args, original = minimal_series(Path(temporary))
            result = evidence.build(args)
            self.assertFalse(result["candidate_validation_passed"])
            self.assertFalse(result["comparison_valid"])
            self.assertTrue(result["stages"]["standard_compare"]["recorded_artifact_integrity_passed"])
            self.assertTrue(result["stages"]["standard_compare"]["structural_complete"])
            self.assertTrue(result["preservation"]["all_recorded_report_rows_and_errors_retained"])
            self.assertEqual(result["stages"]["six_running"]["state"], "not-run")
            raw = (args.output_dir / "standard_compare.report.complete.sanitized.json.gz").read_bytes()
            retained = json.loads(gzip.decompress(raw))
            rows = [row for rnd in retained["rounds"] for cell in rnd["cells"] for row in cell["rows"]]
            self.assertEqual(len(rows), 1152)
            self.assertEqual(sum(row["okay"] is False for row in rows), 576)
            self.assertNotIn(b"SYNTHETIC_PRIVATE_ARG", gzip.decompress(raw))
            complete = gzip.decompress((args.output_dir / "standard_compare.complete.sanitized.json.gz").read_bytes())
            self.assertNotIn(b"PRIVATE_SSH_CONFIGURATION", complete)
            self.assertFalse(result["verification"]["qualification_raw_schema_and_pass"])
            repeat = copy.copy(args)
            repeat.output_dir = Path(temporary) / "publication-second"
            evidence.build(repeat)
            self.assertEqual(raw, (repeat.output_dir / "standard_compare.report.complete.sanitized.json.gz").read_bytes())
            with self.assertRaises(ValueError):
                evidence.build(args)

    def test_missing_or_unparseable_report_never_claims_preservation(self):
        for state in ("missing", "unparseable"):
            with self.subTest(state=state), tempfile.TemporaryDirectory(prefix="a26-publisher-incomplete-") as temporary:
                args, _report = minimal_series(Path(temporary), state)
                result = evidence.build(args)
                self.assertFalse(result["candidate_validation_passed"])
                self.assertFalse(result["artifact_integrity_passed"])
                self.assertFalse(result["preservation"]["all_recorded_report_rows_and_errors_retained"])
                self.assertTrue(result["input_errors"])

    def test_changed_artifact_and_unsafe_path_fail_binding(self):
        with tempfile.TemporaryDirectory(prefix="a26-publisher-changed-") as temporary:
            root = Path(temporary)
            args, _report = minimal_series(root)
            stage = root / "standard_compare-a26-synthetic"
            (stage / "ssh-profile/config").write_bytes(b"changed")
            result = evidence.build(args)
            self.assertFalse(result["stages"]["standard_compare"]["recorded_artifact_integrity_passed"])
            self.assertFalse(evidence.safe_relative("../private.json"))
            self.assertFalse(evidence.safe_relative("/private.json"))
            link = root / "link.json"
            link.symlink_to(args.series)
            with self.assertRaises(ValueError):
                evidence.read_file(link)

    def test_completed_recovery_does_not_claim_socket_cleanup(self):
        spec = next(row for row in specs(Path("/tmp/synthetic")) if row["stage_id"] == "completed_recovery")
        report = {"schema": "hepta-x230-controller-abrupt-readonly-recovery/v1", "passed": True,
            "automatic_rpc_retries": 0, "binary_sha256": A26, "binary_hash_unchanged": True,
            "before_checks": [call() for _ in range(12)], "after_checks": [call() for _ in range(12)],
            "read_only_recovery_passed": True, "controller_death_exit_code": -9,
            "initial_startup": {}, "recovery_startup": {}, "recovery_shutdown": shutdown(),
            "descendant_observation": {"all_sampled_descendants_exited": True, "remaining": [], "observation_errors": []},
            "abrupt_cleanup_complete": False, "socket_artifacts_before_death": [], "old_socket_artifacts_after_death": [],
            "old_socket_artifacts_after_recovery": [{"entries": [{"socket": True}]} for _ in range(6)]}
        for name in ("metadata_before_death", "metadata_after_death", "metadata_after_recovery", "metadata_final"):
            report[name] = {"source_originals_unchanged": True, "private_originals_unchanged": True}
        result = evidence.summarize_report(report, spec, A26, A20)
        self.assertTrue(result["candidate_scope_passed"])
        self.assertFalse(result["abrupt_cleanup_complete"])
        self.assertFalse(result["full_crash_cleanup_claim"])
        self.assertEqual(result["details"]["old_sockets_after_recovery"]["socket_entry_count"], 6)


if __name__ == "__main__":
    unittest.main()
