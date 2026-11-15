#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Recompute one ABBA report from every raw call; do not pool separate campaigns."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import math
from pathlib import Path

import allocator_environment_audit as allocator_audit

HOSTS = {"ai395", "mac", "main", "pocket4", "rog", "x230"}
TOOLS = {"process_status", "process_read"}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)]


def aggregate(cells):
    rows = [r for cell in cells for r in cell["rows"]]
    seconds = math.fsum(c["seconds"] for c in cells)
    cpu = math.fsum(c["controller_cpu_seconds"] for c in cells)
    latency = [r["elapsed_ms"] for r in rows]
    rates = [c["calls"] / c["seconds"] for c in cells]
    return {"calls": len(rows), "seconds": seconds, "controller_cpu_seconds": cpu,
            "calls_per_second": len(rows) / seconds, "controller_cpu_ms_per_call": 1000 * cpu / len(rows),
            "p50_ms": percentile(latency, .5), "p95_ms": percentile(latency, .95),
            "p99_ms": percentile(latency, .99), "max_ms": max(latency),
            "round_calls_per_second": rates,
            "round_rate_max_min_spread_percent": 100 * (max(rates) / min(rates) - 1),
            "round_controller_cpu_ms_per_call": [c["controller_cpu_ms_per_call"] for c in cells]}


def inspect_cell(cell, count, identities):
    rows = cell["rows"]
    need(len(rows) == cell["calls"] == cell["successes"] == count and count % 12 == 0,
         "cell completeness/cardinality differs")
    need(all(r["okay"] is True and r["automatic_retry"] is False
             and r["job_id"] == identities[r["host"]] for r in rows), "failed/retried/changed original call")
    groups = Counter((r["host"], r["tool"]) for r in rows)
    need(set(groups) == {(h, t) for h in HOSTS for t in TOOLS}
         and set(groups.values()) == {count // 12}, "host/operation balance differs")
    need(cell["seconds"] > 0 and cell["controller_cpu_seconds"] >= 0
         and all(math.isfinite(r["elapsed_ms"]) and r["elapsed_ms"] >= 0 for r in rows), "invalid time")
    actual = aggregate([cell])
    for result, source in (("calls_per_second", "completion_rps"), ("calls_per_second", "successful_rps"),
                           ("controller_cpu_ms_per_call", "controller_cpu_ms_per_call"),
                           ("p50_ms", "p50_ms"), ("p95_ms", "p95_ms"), ("p99_ms", "p99_ms"), ("max_ms", "max_ms")):
        need(math.isclose(actual[result], cell[source], rel_tol=1e-12, abs_tol=1e-9), "reported statistic differs: " + source)
    need(cell["no_success_filtering"] is True, "successful-only filtering is not accepted")


def analyze(raw):
    report = json.loads(raw)
    need(report["schema"] == "hepta-x230-readonly-observation-abba/v1" and report["passed"] is True,
         "incomplete/unsupported campaign")
    need(report["order"] == "ABBA" and report["source_originals_unchanged"] is True
         and report["binary_hashes_unchanged"] is True and report["effect_starts"] == 0
         and report["remote_mutation_tool_calls"] == 0 and report["automatic_rpc_retries"] == 0,
         "unexpected effects/order or changed original inputs")
    allocator_proof = allocator_audit.validate_abba(report, "native")
    identities = {r["host"]: r["job_id"] for r in report["six_originals"]}
    need(len(report["six_originals"]) == 6 and set(identities) == HOSTS, "six-host original set differs")
    rounds = report["rounds"]
    need(len(rounds) == 4 and "".join(r["version"] for r in rounds) == "ABBA", "ABBA is incomplete")
    r12 = report.get("r12_measurement")
    if r12 is not None:
        need(r12["scripts_unchanged"] is True and r12["warmup_included_in_performance_denominator"] is False
             and r12["sampled_tree_cpu_used_for_performance"] is False, "R12 measurement provenance differs")
    measured = warmup = preflight = 0
    resources = []
    for number, round_ in enumerate(rounds):
        need(round_["passed"] is True and round_["index"] == number
             and [c["concurrency"] for c in round_["cells"]] == report["concurrency"], "round incomplete")
        for cell in round_["cells"]:
            inspect_cell(cell, report["calls_per_cell"], identities)
            measured += cell["calls"]
            if r12 is not None:
                inspect_cell(cell["warmup"], r12["balanced_warmup_calls_per_cell"], identities)
                need(cell["warmup"]["concurrency"] == cell["concurrency"], "warmup concurrency differs")
                warmup += cell["warmup"]["calls"]
        for phase, count in (("initial_complete_outputs", 6), ("restart_checks", 12)):
            rows = round_[phase]
            need(len(rows) == count and all(r["okay"] is True and r["automatic_retry"] is False
                 and r["job_id"] == identities[r["host"]] for r in rows), "preflight/restart failed")
            preflight += count
        for phase in ("shutdown", "restart_shutdown"):
            value = round_[phase]
            need(value["exit_code"] == 0 and value["shutdown_method"] == "stdin_eof"
                 and not value["observed_descendant_survivors"] and value["reader_error"] is None
                 and value["unmatched_responses"] == 0, "controller normal cleanup differs")
            resources.append({"round": number, "version": round_["version"], "phase": phase,
                              "observations": value["resources"]})
    cases = []
    keys = ("calls_per_second", "controller_cpu_ms_per_call", "p50_ms", "p95_ms", "p99_ms")
    for concurrency in report["concurrency"]:
        arms = {arm: aggregate([c for r in rounds if r["version"] == arm
                               for c in r["cells"] if c["concurrency"] == concurrency]) for arm in "AB"}
        cases.append({"concurrency": concurrency, "arms": arms, "change_percent": {
            key: 100 * (arms["B"][key] / arms["A"][key] - 1) if arms["A"][key] else None for key in keys}})
    return {"schema": "hepta-native-observation-independent-analysis/v2", "verified": True,
            "original_bytes": len(raw), "original_sha256": hashlib.sha256(raw).hexdigest(),
            "binary_sha256": report["binary_sha256"], "r12_measurement": r12,
            "allocator_environment_verification": allocator_proof,
            "measured_calls": measured, "warmup_calls": warmup, "preflight_restart_calls": preflight,
            "total_calls": measured + warmup + preflight, "failed_calls": 0,
            "cases": cases, "resources": resources, "not_covered": report["not_covered"],
            "limitations": ["One finite shared-host campaign; no pooling with another campaign.",
                            "Two processes per version do not establish statistical significance.",
                            "CPU/call uses synchronous controller counters; sampled tree CPU is diagnostic.",
                            "Warmup and restart checks are excluded from measured denominators.",
                            "Native rows retain DTO/response hashes, not complete transport-envelope bodies; no independent envelope rehash is claimed.",
                            "Sampled tree metrics are not complete or synchronized; all errors are retained."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.report.read_bytes()
    if args.report.suffix == ".gz":
        raw = gzip.decompress(raw)
    result = analyze(raw)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({k: result[k] for k in ("verified", "measured_calls", "warmup_calls", "total_calls")}))


if __name__ == "__main__":
    main()
