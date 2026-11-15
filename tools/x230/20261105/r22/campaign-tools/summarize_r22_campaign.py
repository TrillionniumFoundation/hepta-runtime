#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bind the existing raw audits and apply the preregistered R22 adoption gates.

This is arithmetic over a single completed campaign, with no remote operations.
The original auditors remain responsible for transport, counters and lifecycle
proofs. The launcher must also close successfully with unchanged inputs.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

BASELINE_SHA = "adab5f27f89b3cac6adaec916110a48d80697db9667e3bd7ee0fc713fe770a09"
TOPOLOGY_SHA = "8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287"
POLICY_SHA = "206d1a99abc328948d8df893daa77a862b25de878a8b97379090da7ce84393d3"
HOSTS = {"ai395", "mac", "main", "pocket4", "rog", "x230"}
GATES = {
    "all_concurrency": [1, 8, 16],
    "throughput_b_over_a_min": 0.95,
    "p95_b_over_a_max": 1.10,
    "primary_concurrency": 8,
    "primary_throughput_b_over_a_min": 1.10,
    "primary_controller_cpu_b_over_a_max": 0.90,
    "controller_rss_extra_kib_max": 2048,
    "controller_rss_b_over_a_max": 1.15,
    "rss_combination": "both limits; B <= min(A + 2048 KiB, A * 1.15)",
    "rss_aggregation": "maximum sampled controller RSS across all four native controllers per arm, including restarts",
    "ssh_cache_target": "/usr/bin/ssh",
    "ssh_cache_target_bytes": 846888,
    "ssh_cache_hard_cap_bytes": 2097152,
    "cache_cap_evidence_scope": "source and qualification; RSS gate measures the actual process",
}


def need(value, message):
    if not value:
        raise ValueError(message)


def read_json(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, "noncanonical evidence path: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 128 * 1024 * 1024,
             "unsafe or oversized evidence file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(128 * 1024 * 1024 + 1)
        fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        stamp = lambda value: tuple(getattr(value, name) for name in fields)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             "evidence changed while reading")
    finally:
        os.close(fd)
    return json.loads(raw), {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def positive(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def summarize(args):
    need(args.expected_baseline_sha256 == BASELINE_SHA and
         re.fullmatch(r"[0-9a-f]{64}", args.expected_candidate_sha256), "binary SHA arguments differ")
    binary_hashes = {"A": BASELINE_SHA, "B": args.expected_candidate_sha256}
    objects, bindings = {}, {}
    for name in ("native_report", "native_analysis", "boundary_report", "boundary_analysis",
                 "lifecycle_report", "lifecycle_analysis"):
        objects[name], bindings[name] = read_json(getattr(args, name))
    raw, analysis = objects["native_report"], objects["native_analysis"]
    need(raw["schema"] == "hepta-x230-readonly-observation-abba/v2" and raw["passed"] is True
         and raw["binary_sha256"] == binary_hashes and raw["order"] == "ABBA"
         and raw["calls_per_cell"] == 192 and raw["concurrency"] == [1, 8, 16] and raw["tokio_workers"] == 2
         and raw["r16_measurement"]["balanced_warmup_calls_per_cell"] == 24
         and raw["source_originals_unchanged"] is True and raw["binary_hashes_unchanged"] is True
         and raw["effect_starts"] == raw["remote_mutation_tool_calls"] == raw["automatic_rpc_retries"] == 0,
         "native campaign differs from the fixed protocol")
    need(analysis["schema"] == "hepta-native-observation-independent-analysis/v3"
         and analysis["verified"] is True and analysis["original_sha256"] == bindings["native_report"]["sha256"]
         and analysis["original_bytes"] == bindings["native_report"]["bytes"]
         and analysis["binary_sha256"] == binary_hashes and analysis["failed_calls"] == 0
         and analysis["measured_calls"] == 2304 and analysis["warmup_calls"] == 288
         and analysis["preflight_restart_calls"] == 72 and analysis["total_calls"] == 2664,
         "native independent audit is incomplete or binds other bytes")
    topology = analysis["topology_verification"]
    need(topology["verified"] is True and topology["manifest_sha256"] == TOPOLOGY_SHA
         and topology["alias_count"] == topology["physical_machine_groups"] == 6,
         "historical six-machine topology differs")
    need([case["concurrency"] for case in analysis["cases"]] == [1, 8, 16], "concurrency case set differs")
    cases = []
    reasons = []
    for case in analysis["cases"]:
        a, b = case["arms"]["A"], case["arms"]["B"]
        fields = ("calls_per_second", "controller_cpu_ms_per_call", "p50_ms", "p95_ms", "p99_ms")
        need(all(positive(arm[key]) for arm in (a, b) for key in fields), "invalid native aggregate")
        ratios = {key: b[key] / a[key] for key in fields}
        passed = ratios["calls_per_second"] >= GATES["throughput_b_over_a_min"] and ratios["p95_ms"] <= GATES["p95_b_over_a_max"]
        row = {"concurrency": case["concurrency"], "A": {key: a[key] for key in fields},
               "B": {key: b[key] for key in fields}, "B_over_A": ratios,
               "change_percent": {key: 100 * (value - 1) for key, value in ratios.items()},
               "throughput_regression_gate_passed": ratios["calls_per_second"] >= GATES["throughput_b_over_a_min"],
               "p95_regression_gate_passed": ratios["p95_ms"] <= GATES["p95_b_over_a_max"],
               "regression_gate_passed": passed}
        if not passed:
            reasons.append("C%d regression gate" % case["concurrency"])
        if case["concurrency"] == 8:
            row["throughput_improvement_gate_passed"] = ratios["calls_per_second"] >= GATES["primary_throughput_b_over_a_min"]
            row["cpu_improvement_gate_passed"] = ratios["controller_cpu_ms_per_call"] <= GATES["primary_controller_cpu_b_over_a_max"]
            if not row["throughput_improvement_gate_passed"]:
                reasons.append("C8 throughput improvement below 10 percent")
            if not row["cpu_improvement_gate_passed"]:
                reasons.append("C8 controller CPU reduction below 10 percent")
        cases.append(row)

    resources = analysis["resources"]
    expected = {(number, arm, phase) for number, arm in enumerate("ABBA") for phase in ("shutdown", "restart_shutdown")}
    need(len(resources) == len(expected) and {(r["round"], r["version"], r["phase"]) for r in resources} == expected,
         "native resource controller set differs")
    rss_rows = []
    for row in resources:
        observed = row["observations"]
        samples = observed["metric_samples"].get("controller_rss_kib", 0)
        peak = observed["peaks"].get("controller_rss_kib")
        available = observed["sampler_error"] is None and type(samples) is int and samples > 0 and positive(peak)
        rss_rows.append({"round": row["round"], "arm": row["version"], "phase": row["phase"],
                         "sampled_controller_rss_peak_kib": peak, "rss_samples": samples, "available": available,
                         "controller_hwm_kib": observed["peaks"].get("controller_hwm_kib"),
                         "controller_fd_peak": observed["peaks"].get("controller_fd"),
                         "sampled_tree_rss_peak_kib": observed["peaks"].get("tree_rss_kib"),
                         "error_counts": observed["error_counts"], "sampler_error": observed["sampler_error"]})
    rss = {"rows": rss_rows, "available": all(row["available"] for row in rss_rows), "passed": False,
           "aggregation": GATES["rss_aggregation"], "sampling_interval_seconds": 0.1}
    if rss["available"]:
        peaks = {arm: max(row["sampled_controller_rss_peak_kib"] for row in rss_rows if row["arm"] == arm) for arm in "AB"}
        ceiling = min(peaks["A"] + GATES["controller_rss_extra_kib_max"], peaks["A"] * GATES["controller_rss_b_over_a_max"])
        rss.update(A_peak_kib=peaks["A"], B_peak_kib=peaks["B"], candidate_ceiling_kib=ceiling,
                   extra_kib=peaks["B"] - peaks["A"], B_over_A=peaks["B"] / peaks["A"], passed=peaks["B"] <= ceiling)
    if not rss["passed"]:
        reasons.append("controller RSS limit exceeded or RSS measurements unavailable")

    boundary, ba = objects["boundary_report"], objects["boundary_analysis"]
    need(boundary["passed"] is True and boundary["candidate_sha256"] == binary_hashes["B"]
         and boundary["attempts_per_burst"] == 32 and boundary["bursts_planned"] == 2
         and boundary["tokio_workers"] == 2 and boundary["arena_max"] == 1
         and ba["schema"] == "hepta-native-boundary-independent-analysis/v1"
         and ba["evidence_verified"] is True and ba["diagnostic_passed"] is True
         and ba["candidate_sha256"] == binary_hashes["B"] and ba["report_sha256"] == bindings["boundary_report"]["sha256"]
         and ba["classification_policy_sha256"] == POLICY_SHA and ba["capacity_rendering_verified"] is True
         and ba["drain_and_recovery_passed"] is True and len(ba["bursts"]) == 2
         and set(ba["counts"]) <= {"success", "capacity_rejection", "other_error"}
         and ba["counts"].get("other_error", 0) == 0 and sum(ba["counts"].values()) == 64
         and ba["automatic_rpc_retries"] == 0 and ba["total_tool_calls"] == 202,
         "capacity, drain or recovery evidence differs")
    lifecycle, la = objects["lifecycle_report"], objects["lifecycle_analysis"]
    need(lifecycle["schema"] == "hepta-six-host-cancel-recovery/v2" and lifecycle["passed"] is True
         and lifecycle["candidate_sha256"] == binary_hashes["B"]
         and lifecycle["production_service_mutations"] == lifecycle["remote_cleanup_operations"] == lifecycle["automatic_rpc_retries"] == 0
         and la["schema"] == "hepta-six-host-cancel-recovery-independent-verification/v2"
         and la["verified"] is True and la["candidate_sha256"] == binary_hashes["B"]
         and la["source_sha256"] == bindings["lifecycle_report"]["sha256"]
         and la["source_bytes"] == bindings["lifecycle_report"]["bytes"]
         and la["new_starts"] == 6 and la["same_key_lookups"] == la["cancellations"] == 12
         and la["automatic_rpc_retries"] == 0 and set(la["hosts"]) == HOSTS
         and la["private_transport_interruption"]["requested_host"] == "rog"
         and la["private_transport_interruption"]["passed"] is True
         and la["private_transport_interruption"]["signal_receipt"]["pidfd_terminal_observed"] is True,
         "cancellation, crash, same-key or transport recovery evidence differs")

    need(len(raw["rounds"]) == 4 and "".join(row["version"] for row in raw["rounds"]) == "ABBA", "raw ABBA differs")
    paired = []
    for left, right in ((0, 1), (3, 2)):
        a = next(cell for cell in raw["rounds"][left]["cells"] if cell["concurrency"] == 8)
        b = next(cell for cell in raw["rounds"][right]["cells"] if cell["concurrency"] == 8)
        keys = ("successful_rps", "controller_cpu_ms_per_call", "p95_ms")
        need(all(positive(cell[key]) for cell in (a, b) for key in keys), "invalid paired C8 values")
        paired.append({"baseline_round": left, "candidate_round": right,
                       "B_over_A": {key: b[key] / a[key] for key in keys}})
    return {"schema": "hepta-r22-campaign-gates/v1", "evidence_verified": True,
            "binary_sha256": binary_hashes, "evidence": bindings, "thresholds": GATES,
            "cases": cases, "controller_rss": rss, "C8_adjacent_pairs_diagnostic_only": paired,
            "boundary": {"verified": True, "counts": ba["counts"],
                         "capacity_rejection_observed": ba["counts"].get("capacity_rejection", 0) > 0,
                         "fixed_rejection_count_required": False, "drain_and_recovery_passed": True},
            "lifecycle": {"verified": True, "new_starts": 6, "same_key_lookups": 12, "cancellations": 12,
                          "native_calls": la["native_calls"], "independent_ssh_calls": la["independent_ssh_calls"],
                          "transport_interruption_host": "rog", "ABBA_performance_claim": False},
            "correctness_verified": True, "performance_gates_passed": not reasons,
            "adoption_gate_passed": not reasons, "rejection_reasons": reasons,
            "final_adoption_requires_completed_launcher_with_unchanged_inputs": True,
            "limitations": ["One finite six-machine campaign; no pooling with historical results or confidence claim.",
                            "P95 and throughput gates apply separately to C1, C8 and C16; improvement gates apply to C8.",
                            "CPU is synchronous same-controller CPU per measured call, excluding the Python harness and remote processes.",
                            "RSS is a sampled process peak, not an exact allocation bound or total cluster memory.",
                            "Capacity refusals are reported separately and never counted as successful throughput."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("native-report", "native-analysis", "boundary-report", "boundary-analysis", "lifecycle-report", "lifecycle-analysis", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("expected-baseline-sha256", "expected-candidate-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    result = summarize(args)
    output = args.output
    need(output.is_absolute() and output.resolve() == output and not os.path.lexists(output), "fresh direct summary output required")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(result, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({"evidence_verified": True, "adoption_gate_passed": result["adoption_gate_passed"],
                      "rejection_reasons": result["rejection_reasons"], "output": str(output)}), flush=True)


if __name__ == "__main__":
    main()
