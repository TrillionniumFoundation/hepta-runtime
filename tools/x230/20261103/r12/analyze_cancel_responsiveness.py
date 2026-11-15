#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independently validate and summarize the retained cancellation ABBA report.

Does not import the benchmark or trust its precomputed percentiles. Every raw
response, digest, expected refusal and per-round percentile is checked before
combining the two runs for each arm. The harness records latency/CPU deltas,
not their complete clock endpoints; this analyzer does not recreate those clocks.
"""
import argparse
from collections import defaultdict
import hashlib
import json
import math
from pathlib import Path
import statistics


def require(value, reason):
    if not value:
        raise ValueError(reason)


def raw_digest(value):
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return hashlib.sha256(data).hexdigest()


def stats(samples):
    ordered = sorted(samples)
    require(ordered and all(math.isfinite(value) and value >= 0 for value in ordered),
            "missing or invalid latency sample")
    def rank(fraction):
        return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]
    return {"count": len(ordered), "minimum_ms": min(ordered), "maximum_ms": max(ordered),
            "p50_ms": rank(.5), "p95_ms": rank(.95)}


def change(before, after):
    return None if before == 0 else (after / before - 1) * 100


def validate_call(row, expected_tool):
    require(row["method"] == "tools/call" and row["params"]["name"] == expected_tool,
            "raw tool ordering changed")
    require(math.isfinite(row["elapsed_ms"]) and row["elapsed_ms"] >= 0, "invalid latency delta")
    response = row["response"]
    require(response.get("id") == row["rpc_id"], "original response identity differs")
    require(raw_digest(response) == row["response_sha256"], "original response digest differs")
    require(row.get("expected_result") is True, "runner did not validate this result")
    if expected_tool == "process_cancel":
        require(row["params"]["arguments"] == {"host": "other", "job_id": "cancel-responsiveness", "grace_seconds": 0},
                "cancellation fixture changed")
        message = "job `cancel-responsiveness` belongs to host `owner`, not `other`"
        require(("error" in response or response.get("result", {}).get("isError") is True)
                and message in json.dumps(response, ensure_ascii=False), "unexpected cancellation outcome")
    else:
        require(row["params"]["arguments"] == {} and "error" not in response,
                "host_list arguments or RPC outcome differ")
        result = response["result"]
        require(not result.get("isError"), "host_list was refused")
        texts = [part["text"] for part in result.get("content", []) if part.get("type") == "text"]
        require(texts and {host["name"] for host in json.loads(texts[0])["hosts"]} == {"other", "owner"},
                "host_list fixture membership differs")


def analyze(report, source_sha):
    require(report["schema"] == "hepta-x230-cancel-responsiveness/v1"
            and report.get("okay") is True and report.get("binaries_unchanged") is True,
            "campaign did not complete successfully")
    require(report["order"] == "ABBA" and report["automatic_retries"] == 0, "campaign order or retries differ")
    width, waves = report["concurrency"] + 1, report["waves"]
    groups = defaultdict(list)
    seen_processes = set()
    counts = {"measured": 0, "warmup": 0, "expected_cancel_refusals": 0, "host_list_successes": 0}
    checked_fields = 0
    for run in report["rounds"]:
        require(run.get("okay") is True and run["receipt_unchanged"] and run["no_cancel_intent"]
                and run["no_ssh_dispatch"], "round progressed beyond the permitted rejection fixture")
        shutdown = run["shutdown"]
        require(shutdown["exit_code"] == 0 and shutdown["method"] == "stdin_eof"
                and shutdown["unmatched"] == 0 and shutdown["reader_error"] is None, "shutdown/collection failed")
        original = (run["startup"]["pid"], run["startup"]["birth_ticks"])
        require(original not in seen_processes, "controller generation reused between rounds")
        seen_processes.add(original)
        require(math.isfinite(run["controller_cpu_seconds"]) and run["controller_cpu_seconds"] >= 0,
                "invalid CPU delta")
        require(math.isfinite(run["wall_seconds"]) and run["wall_seconds"] > 0, "invalid wall interval")
        identities = set()
        for collection, expected_waves in (("warmup", 2), ("measured", waves)):
            rows = run[collection]
            require(len(rows) == width * expected_waves, "round sample count differs")
            counts[collection] += len(rows)
            for offset in range(0, len(rows), width):
                for position, row in enumerate(rows[offset:offset + width]):
                    tool = "host_list" if position == width - 1 else "process_cancel"
                    validate_call(row, tool)
                    require(row["rpc_id"] not in identities, "duplicate raw RPC identity")
                    identities.add(row["rpc_id"])
                    if collection == "measured":
                        require(row["wave"] == offset // width, "wave label differs")
                    counts["host_list_successes" if tool == "host_list" else "expected_cancel_refusals"] += 1
        for tool in ("host_list", "process_cancel"):
            calculated = stats([row["elapsed_ms"] for row in run["measured"] if row["params"]["name"] == tool])
            require(run[tool] == calculated, "reported per-round distribution differs")
            checked_fields += len(calculated)
        groups[(run["workers"], run["receipt_bytes"])].append(run)
    results = []
    for (workers, size), runs in sorted(groups.items()):
        require([run["arm"] for run in runs] == list("ABBA")
                and [run["position"] for run in runs] == [0, 1, 2, 3], "complete ABBA block missing")
        require(len({run["receipt_sha256"] for run in runs}) == 1, "A/B fixture bytes differ")
        item = {"workers": workers, "receipt_bytes": size, "payload": report["payload"],
                "receipt_sha256": runs[0]["receipt_sha256"], "arms": {}}
        for arm in "AB":
            selected = [run for run in runs if run["arm"] == arm]
            wall = sum(run["wall_seconds"] for run in selected)
            cpu = sum(run["controller_cpu_seconds"] for run in selected)
            calls = sum(len(run["measured"]) for run in selected)
            values = {"runs": len(selected), "measured_mixed_rpc_count": calls,
                      "wall_seconds": wall, "controller_cpu_seconds": cpu,
                      "controller_cpu_ms_per_mixed_rpc": cpu * 1000 / calls,
                      "mixed_rpc_responses_per_second": calls / wall}
            for tool in ("host_list", "process_cancel"):
                values[tool] = stats([sample["elapsed_ms"] for run in selected for sample in run["measured"]
                                     if sample["params"]["name"] == tool])
            hwm = [run["memory_after"]["kib"]["VmHWM"] for run in selected
                   if "VmHWM" in run.get("memory_after", {}).get("kib", {})]
            values["whole_child_vm_hwm_kib"] = {"samples": hwm, "available": len(hwm),
                                                  "median": statistics.median(hwm) if hwm else None}
            values["memory_errors"] = [run.get("memory_after", {}).get("error") for run in selected
                                        if "error" in run.get("memory_after", {})]
            item["arms"][arm] = values
        before, after = item["arms"]["A"], item["arms"]["B"]
        item["change_percent"] = {
            "host_list_p50": change(before["host_list"]["p50_ms"], after["host_list"]["p50_ms"]),
            "host_list_p95": change(before["host_list"]["p95_ms"], after["host_list"]["p95_ms"]),
            "controller_cpu_ms_per_mixed_rpc": change(before["controller_cpu_ms_per_mixed_rpc"],
                                                       after["controller_cpu_ms_per_mixed_rpc"]),
            "mixed_rpc_responses_per_second": change(before["mixed_rpc_responses_per_second"],
                                                     after["mixed_rpc_responses_per_second"])}
        if before["whole_child_vm_hwm_kib"]["available"] == after["whole_child_vm_hwm_kib"]["available"] == 2:
            item["change_percent"]["whole_child_vm_hwm_median"] = change(
                before["whole_child_vm_hwm_kib"]["median"], after["whole_child_vm_hwm_kib"]["median"])
        results.append(item)
    require(results, "no complete measurement groups")
    return {"schema": "hepta-x230-cancel-responsiveness-analysis/v1", "source_sha256": source_sha,
            "binary_sha256": report["binary_sha256"], "harness_sha256": report["harness_sha256"],
            "rpc_responses_and_statistical_fields_validated": True,
            "per_round_statistic_fields_checked": checked_fields,
            "controller_generations": len(seen_processes), "counts": counts, "cases": results,
            "scope": "finite native MCP wrong-host rejection workload; not successful remote cancellation throughput",
            "method": "pool raw per-call latencies within each arm/case; nearest rank; sum recorded CPU/wall and divide by all mixed RPCs",
            "limits": ["two independent controller runs per arm/case", "no statistical significance claim",
                       "host_list includes ordinary audit and result-retention costs", "warm receipt cache after two mixed waves",
                       "whole-child VmHWM includes startup/warmup and is not incremental request memory",
                       "clock endpoints were not retained; recorded timing deltas cannot be independently re-created",
                       "all negative directional results retained"]}


def markdown(summary):
    lines = ["# Native cancellation-load responsiveness", "",
             summary["scope"] + ". Two runs per arm/case; no statistical-significance claim.", "",
             "| Workers | Receipt bytes | host_list p50 ms A → B | host_list p95 ms A → B | p95 change | CPU ms / mixed RPC A → B | VmHWM KiB median A → B |",
             "|---:|---:|---:|---:|---:|---:|---:|"]
    for case in summary["cases"]:
        a, b = case["arms"]["A"], case["arms"]["B"]
        def arrow(path, digits=3):
            left, right = a, b
            for key in path:
                left, right = left[key], right[key]
            return "unavailable" if left is None or right is None else f"{left:.{digits}f} → {right:.{digits}f}"
        p95 = case["change_percent"]["host_list_p95"]
        lines.append(f"| {case['workers']} | {case['receipt_bytes']} | "
                     + arrow(["host_list", "p50_ms"]) + " | " + arrow(["host_list", "p95_ms"]) + " | "
                     + ("unavailable" if p95 is None else f"{p95:+.2f}%") + " | "
                     + arrow(["controller_cpu_ms_per_mixed_rpc"]) + " | "
                     + arrow(["whole_child_vm_hwm_kib", "median"], 1) + " |")
    lines.extend(["", f"Validated {summary['counts']['measured']} measured and {summary['counts']['warmup']} warmup replies across "
                  f"{summary['controller_generations']} controller generations.", "", "Limitations:", ""])
    lines.extend("- " + limit + "." for limit in summary["limits"])
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args()
    raw = args.source.read_bytes()
    summary = analyze(json.loads(raw), hashlib.sha256(raw).hexdigest())
    args.summary.write_text(json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    args.markdown.write_text(markdown(summary))
    print(json.dumps({"rpc_responses_and_statistical_fields_validated": True,
                      "counts": summary["counts"], "cases": len(summary["cases"])}))


if __name__ == "__main__":
    main()
