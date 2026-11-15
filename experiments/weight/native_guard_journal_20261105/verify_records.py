#!/usr/bin/env python3
"""Verify published evidence only; no runtime, model or crash experiment starts."""
import argparse
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(root, name):
    return json.loads((root / name).read_text())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    manifest = read(root, "MANIFEST.json")
    for item in manifest["files"]:
        path = root / item["path"]
        assert path.is_file() and path.stat().st_size == item["bytes"], item["path"]
        assert digest(path) == item["sha256"], item["path"]
    native = read(root, "qualification/combined_qualification.json")
    inner = read(root, "qualification/mcp_receipt.json")
    outer = read(root, "qualification/outer_receipt.json")
    protocol = read(root, "MCP_PROTOCOL_V2.json")
    outer_protocol = read(root, "MCP_OUTER_PROTOCOL.json")
    assert native["completed"] and native["passed"] and native["source_unchanged_after_format"]
    assert len(native["commands"]) == 6
    assert all(c["exit_code"] == 0 and c["timed_out"] is False for c in native["commands"])
    assert native["source_after_format"] == native["source_after_last_command"]
    binary = native["binary"]["sha256"]
    assert binary == inner["binary_sha256"] == outer["qualified_binary_sha256"]
    assert digest(root / "qualify_mcp_contract.py") == inner["driver_sha256"] == outer["driver_sha256"]
    assert inner["protocol_sha256"] == digest(root / "MCP_PROTOCOL_V2.json")
    assert outer["inner_protocol_sha256"] == inner["protocol_sha256"]
    assert digest(root / "MCP_OUTER_PROTOCOL.json") == outer["outer_protocol_sha256"]
    assert digest(root / "run_mcp_contract_outer.py") == outer["outer_source_sha256"]
    assert outer_protocol["inner_driver_sha256"] == inner["driver_sha256"]
    assert outer["inner_receipt_sha256"] == digest(root / "qualification/mcp_receipt.json")
    assert inner["complete"] and inner["passed"] and outer["passed"]
    assert inner["tools_call_count"] == outer["actual_tools_call_count"] == protocol["expected_tools_call_count"] == 11
    assert inner["driver_source_unchanged"] and inner["protocol_unchanged"] and inner["executed_binary_unchanged"]
    assert outer["exit_code"] == 0 and outer["timed_out"] is False
    assert outer["whole_driver_process_waited"] and outer["runtime_descendant_accounting_confirmed_complete"]
    assert outer["source_bindings_checked_before_launch"] and outer["source_bindings_unchanged_after_exit"]
    assert outer["internal_timers_overlap_wait4_do_not_add"]
    assert outer["wait4_total_cpu_seconds"] == outer["wait4_user_cpu_seconds"] + outer["wait4_system_cpu_seconds"]
    assert outer["wait4_max_rss_is_aggregate_concurrent_rss"] is False
    assert {x["case"] for x in inner["negative_cases"]} == set(protocol["fresh_negative_cases"])
    for case in inner["negative_cases"]:
        assert case["fresh_mcp_is_error"] and case["fresh_original_reason_retained"]
        assert case["expected_reason_family"] in case["fresh_error_sanitized"]
        assert case["retry_accepted"] is False and case["retry_recovery_verified"] is False
        assert case["retry_outcome"] == "rejected_recovery_unverified"
        assert case["completed_artifacts_published"] == 0 and case["source_bytes_unchanged"]
    positive = inner["positive"]
    assert positive["accepted"] and positive["durable_completion"] and positive["top_level_contract_preserved"]
    assert positive["completed_retry_full_guard_revalidation"] and positive["artifact_count"] == 1
    tamper = inner["accepted_artifact_tamper"]
    assert tamper["accepted"] is False and tamper["recovery_verified"] is False
    assert tamper["cached_acceptance_used"] is False and tamper["parent_unchanged"]
    phases = {"after_intent", "after_guard_before_candidate", "after_candidate_before_completion", "after_completion"}
    crash_count = 0
    for name, command_index in [("all_features_crash_records.json", 1), ("no_default_features_crash_records.json", 3)]:
        extract = read(root, "qualification/" + name)
        assert extract["raw_log_sha256"] == native["commands"][command_index]["log_sha256"]
        assert extract["raw_log_bytes"] == native["commands"][command_index]["log_bytes"]
        assert extract["trace_count"] == len(extract["traces"]) == 8
        boundaries = [r for r in extract["traces"] if r["type"] == "JOURNAL_CRASH_RECEIPT"]
        assert {r["phase"] for r in boundaries} == phases
        for row in boundaries:
            assert row["signal"] == 9 and row["child_restarted"] and row["source_bytes_unchanged"]
            assert row["prior_interrupted_child_cpu_known"] is False
            if row["phase"] == "after_completion":
                assert row["accepted"] and row["had_completion_at_kill"] and row["artifacts_after_reconcile"] == 1
            else:
                assert row["accepted"] is False and row["had_completion_at_kill"] is False
                assert row["outcome"] == "interrupted_rejected_and_restored"
                assert row["forced_restoration_sha256"] == row["parent_sha256"]
                assert row["artifacts_after_reconcile"] == 2
        failures = [r for r in extract["traces"] if r["type"] == "JOURNAL_CRASH_FAILURE_RECEIPT"]
        assert {r["case"] for r in failures} == {"missing_source", "changed_source", "artifact_quota"}
        for row in failures:
            assert row["signal"] == 9 and row["child_restarted"]
            assert row["accepted"] is False and row["recovery_verified"] is False
            assert row["artifacts_published"] == 0 and row["failure_durably_retained"]
        lock = [r for r in extract["traces"] if r["type"] == "JOURNAL_CONCURRENCY_RECEIPT"]
        assert len(lock) == 1 and lock[0]["owner_killed_signal"] == 9
        assert lock[0]["second_process_rejected_busy"] and lock[0]["live_cross_process_flock"]
        assert lock[0]["model_artifacts_while_locked"] == 0 and lock[0]["fresh_process_recovery_verified"]
        crash_count += len(extract["traces"])
    aborted = read(root, "qualification/attempt_1/ABORTED.json")
    partial = read(root, "qualification/attempt_1/qualification.json")
    assert aborted["tests_completed"] == 0 and aborted["claimed_test_pass"] is False
    assert aborted["compile_cpu_seconds"] is None and aborted["compile_cpu_accounting_complete"] is False
    assert aborted["exit_code"] == -15 and aborted["stopped_only_owned_job"]
    assert partial["complete"] is False and partial["passed"] is False
    assert aborted["partial_receipt_sha256"] == digest(root / "qualification/attempt_1/qualification.json")
    assert partial["protocol_sha256"] == digest(root / "qualification/attempt_1/PROTOCOL.json")
    assert partial["driver_sha256"] == digest(root / "qualification/attempt_1/run_qualification.py")
    repo = args.repo
    if repo is not None:
        for item in native["source_after_last_command"]:
            path = repo / item["path"]
            assert path.stat().st_size == item["bytes"] and digest(path) == item["sha256"], item["path"]
        assert digest(repo / "Cargo.lock") == native["cargo_lock_sha256"]
    for item in manifest["files"]:
        if item["path"].endswith((".json", ".log")):
            text = (root / item["path"]).read_text()
            assert "/home/" not in text and "/Users/" not in text, item["path"]
    assert inner["model_efficacy_qualified"] is False and inner["production_eligible"] is False
    print(json.dumps({"status": "PASS_RECORDS_ONLY", "manifest_files": len(manifest["files"]),
                      "recorded_actual_mcp_calls": inner["tools_call_count"],
                      "recorded_actual_sigkill_cases_across_configurations": crash_count,
                      "repository_source_verified": repo is not None,
                      "new_runtime_execution": False, "new_model_efficacy_claim": False}, sort_keys=True))


if __name__ == "__main__":
    main()
