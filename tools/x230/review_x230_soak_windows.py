#!/usr/bin/env python3
# Copyright (c) 2026 Muvon UnLimited
# SPDX-License-Identifier: Apache-2.0
"""Independent, create-only analysis of one frozen B-only observation cell.

This is an analysis helper, not a measurement driver. `inspect` accepts existing
ABBA data only to inspect its structure. It cannot create a soak verdict.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
from pathlib import Path
import re
import sys


SCHEMA = "hepta-x230-readonly-observation-abba/v1"
SHA = re.compile(r"[0-9a-f]{64}\Z")
EMPTY_SHA = hashlib.sha256(b"").hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_pinned(path, expected_sha):
    require(SHA.fullmatch(expected_sha) is not None, "invalid expected SHA256")
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    require(actual == expected_sha, "input SHA256 mismatch")
    value = json.loads(raw)
    require(isinstance(value, dict), "report must be an object")
    return value, {"sha256": actual, "bytes": len(raw)}


def finite_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def quantiles(rows):
    values = sorted(row["elapsed_ms"] for row in rows)
    if not values:
        return {"count": 0, "p50": None, "p95": None, "p99": None, "max": None}
    return {
        "count": len(values),
        **{name: values[math.ceil(len(values) * p) - 1]
           for name, p in [("p50", .50), ("p95", .95), ("p99", .99)]},
        "max": values[-1],
    }


def inspect_structure(report):
    require(report.get("schema") == SCHEMA, "unsupported source schema")
    return {
        "source_schema": report["schema"],
        "order": report.get("order"),
        "concurrency": report.get("concurrency"),
        "calls_per_cell": report.get("calls_per_cell"),
        "rounds": [{
            "index": row.get("index"), "version": row.get("version"),
            "cells": [{
                "concurrency": cell.get("concurrency"),
                "declared_calls": cell.get("calls"),
                "recorded_rows": len(cell.get("rows", [])),
                "driver_cell_seconds": cell.get("seconds"),
                "rows_with_valid_start_and_latency": sum(
                    finite_number(item.get("start_monotonic"))
                    and finite_number(item.get("elapsed_ms"))
                    and item["elapsed_ms"] >= 0 for item in cell.get("rows", [])),
            } for cell in row.get("cells", [])],
        } for row in report.get("rounds", [])],
        "soak_analysis_emitted": False,
        "soak_verdict": None,
    }


def make_windows(rows, window_seconds):
    """Keep all rows; start buckets and derived-completion buckets are distinct."""
    origin = min(row["start_monotonic"] for row in rows)
    finish = max(row["start_monotonic"] + row["elapsed_ms"] / 1000 for row in rows)
    span = finish - origin
    require(span > 0, "observed request span must be positive")
    count = max(1, math.ceil(span / window_seconds))
    normalized = []
    for ordinal, raw in enumerate(rows):
        start = raw["start_monotonic"] - origin
        complete = raw["start_monotonic"] + raw["elapsed_ms"] / 1000 - origin
        start_index = min(int(start // window_seconds), count - 1)
        complete_index = min(int(complete // window_seconds), count - 1)
        normalized.append({
            **{k: v for k, v in raw.items() if k not in ("start_monotonic", "start_unix")},
            "ordinal": ordinal, "start_seconds": start, "completion_seconds": complete,
            "start_window": start_index, "completion_window": complete_index,
            "crosses_window_boundary": start_index != complete_index,
        })
    windows = []
    for index in range(count):
        left, right = index * window_seconds, min((index + 1) * window_seconds, span)
        actual = right - left
        starts = [row for row in normalized if row["start_window"] == index]
        completes = [row for row in normalized if row["completion_window"] == index]
        successes = sum(row.get("okay") is True for row in completes)
        windows.append({
            "index": index, "start_seconds": left, "end_seconds": right,
            "actual_observed_span_seconds": actual,
            "nominal_window_seconds": window_seconds,
            "is_first": index == 0, "is_last": index == count - 1,
            "partial_window": actual < window_seconds,
            "right_endpoint_included": index == count - 1,
            "started_attempts": len(starts),
            "started_eventual_successes": sum(row.get("okay") is True for row in starts),
            "latency_ms_of_all_requests_started_here": quantiles(starts),
            "completed_attempts": len(completes), "completed_successes": successes,
            "completed_failures": len(completes) - successes,
            "completed_attempts_per_second": len(completes) / actual,
            "completed_successes_per_second": successes / actual,
            "latency_ms_of_all_requests_completed_here": quantiles(completes),
            "requests_started_here_finishing_in_later_windows": [
                row["ordinal"] for row in starts if row["crosses_window_boundary"]],
            "requests_finished_here_started_in_earlier_windows": [
                row["ordinal"] for row in completes if row["crosses_window_boundary"]],
        })
    require(sum(w["started_attempts"] for w in windows) == len(rows), "start windows lost rows")
    require(sum(w["completed_attempts"] for w in windows) == len(rows), "completion windows lost rows")
    return normalized, windows, span


def completion_gaps(rows, gap_ms):
    events = sorted({row["completion_seconds"] for row in rows})
    gaps = []
    for number, (left, right) in enumerate(zip([0.0] + events[:-1], events)):
        if (right - left) * 1000 < gap_ms:
            continue
        active_left = [row for row in rows if row["start_seconds"] <= left < row["completion_seconds"]]
        spanning = [row for row in active_left if row["completion_seconds"] >= right]
        new_starts = [row for row in rows if left < row["start_seconds"] < right]
        hosts = sorted({row["host"] for row in spanning})
        gaps.append({
            "start_seconds": left, "end_seconds": right,
            "gap_ms": (right - left) * 1000,
            "initial_interval_before_first_completion": number == 0,
            "inflight_ordinals_at_start": [row["ordinal"] for row in active_left],
            "spanning_request_ordinals": [row["ordinal"] for row in spanning],
            "spanning_hosts": hosts,
            "started_during_gap_ordinals": [row["ordinal"] for row in new_starts],
            "multiple_hosts_inflight_without_a_completion": len(hosts) >= 2,
            "cause": None,
        })
    return gaps


def analyze(report, originals_report, args):
    inspect_structure(report)
    require(report.get("order") == "B", "soak analysis requires the original B-only report")
    require(len(report.get("rounds", [])) == 1, "B-only report must contain one round")
    round_ = report["rounds"][0]
    require(round_.get("index") == 0 and round_.get("version") == "B", "wrong B round identity")
    require(report.get("concurrency") == [args.expected_concurrency], "concurrency differs from requested soak")
    require(len(round_.get("cells", [])) == 1, "one continuous concurrency cell is required")
    cell = round_["cells"][0]
    require(cell.get("concurrency") == args.expected_concurrency, "cell concurrency mismatch")
    rows = cell.get("rows", [])
    require(bool(rows), "no recorded requests")
    require(all(finite_number(x.get("start_monotonic")) and finite_number(x.get("elapsed_ms"))
                and x["elapsed_ms"] >= 0 for x in rows), "invalid or missing request timing")
    require(finite_number(cell.get("seconds")) and cell["seconds"] > 0, "invalid cell elapsed duration")
    issues = []

    def check(value, message):
        if not value:
            issues.append(message)

    check(report.get("binary_sha256", {}).get("B") == args.expected_binary_sha256,
          "measured B binary differs from expected qualified SHA256")
    check(SHA.fullmatch(args.expected_binary_sha256) is not None, "expected binary hash is invalid")
    check(report.get("binary_hashes_unchanged") is True, "binary immutability fence did not pass")
    check(report.get("source_originals_unchanged") is True, "original metadata immutability fence did not pass")
    for key in ("effect_starts", "remote_mutation_tool_calls", "automatic_rpc_retries"):
        check(report.get(key) == 0, key + " is not zero")
    check(report.get("calls_per_cell") == args.expected_calls, "declared calls differ from planned count")
    check(cell.get("calls") == args.expected_calls and len(rows) == args.expected_calls,
          "cell rows/count differ from planned count")
    check(cell.get("no_success_filtering") is True, "no-success-filtering fence missing")
    originals = report.get("six_originals", [])
    reference = originals_report.get("six_originals", [])
    check(originals == reference, "six original receipts differ from pinned reference")
    check(len(originals) == 6, "not exactly six original jobs")
    check(all(SHA.fullmatch(x.get("record_sha256", "")) and SHA.fullmatch(x.get("stdout_sha256", ""))
              for x in originals), "invalid original record/output hash")
    by_host = {item["host"]: item for item in originals}
    check(len(by_host) == 6, "original host aliases are not unique")
    phases = {
        "timed": rows,
        "initial": round_.get("initial_complete_outputs", []),
        "restart": round_.get("restart_checks", []),
    }
    check(len(phases["initial"]) == 6, "initial output check count differs")
    check(len(phases["restart"]) == 12, "same-job restart check count differs")
    dto_hashes = collections.defaultdict(set)
    checked_output_receipts = 0
    for phase, values in phases.items():
        for ordinal, row in enumerate(values):
            prefix = f"{phase}[{ordinal}]"
            host = row.get("host")
            original = by_host.get(host)
            check(original is not None and row.get("job_id") == original["job_id"], prefix + " job identity differs")
            check(row.get("automatic_retry") is False, prefix + " automatic-retry fence differs")
            check(isinstance(row.get("okay"), bool), prefix + " missing outcome")
            if not originals:
                continue
            expected_host = originals[ordinal % 6]["host"] if phase in ("timed", "initial") else originals[(ordinal // 2) % 6]["host"]
            expected_tool = ("process_status" if (ordinal // 6) % 2 == 0 else "process_read") if phase == "timed" else (
                "process_read" if phase == "initial" else ("process_status" if ordinal % 2 == 0 else "process_read"))
            check(host == expected_host and row.get("tool") == expected_tool, prefix + " workload order differs")
            if row.get("okay") is True:
                check(row.get("isError") is False and SHA.fullmatch(row.get("dto_sha256", "")) is not None,
                      prefix + " successful response receipt is invalid")
                dto_hashes[(host, row.get("tool"))].add(row.get("dto_sha256"))
                if row.get("tool") == "process_read" and original is not None:
                    check(row.get("stdout_sha256") == original["stdout_sha256"]
                          and row.get("stdout_bytes") == original["stdout_bytes"]
                          and row.get("stderr_sha256") == EMPTY_SHA and row.get("stderr_bytes") == 0,
                          prefix + " successful complete output differs")
                    checked_output_receipts += 1
    check(all(len(values) == 1 for values in dto_hashes.values()), "successful DTO changed within a host/tool pair")
    resources = {}
    for key in ("shutdown", "restart_shutdown"):
        shutdown = round_.get(key, {})
        check(shutdown.get("exit_code") == 0 and shutdown.get("shutdown_method") == "stdin_eof"
              and shutdown.get("reader_error") is None and shutdown.get("unmatched_responses") == 0
              and shutdown.get("observed_descendant_survivors") == [], key + " is not a clean normal shutdown")
        resource = shutdown.get("resources", {})
        resources[key] = {
            "lifetime_sampled_peaks": resource.get("peaks"),
            "sample_interval_seconds": resource.get("sample_interval_seconds"),
            "samples": resource.get("samples"), "sampling_errors": resource.get("errors", []),
            "sampled_peaks_are_lower_bounds": resource.get("sampled_peaks_and_tree_cpu_are_lower_bounds"),
            "rss_fd_time_series_available": False,
        }
    normalized, windows, span = make_windows(rows, args.window_seconds)
    # The driver does not retain the cell's absolute start, so do not invent it.
    check(span <= cell["seconds"] + 1e-6, "observed request span exceeds full cell duration")
    check(span >= args.minimum_observed_seconds, "observed span is below requested minimum")
    successes = sum(row.get("okay") is True for row in rows)
    check(cell.get("successes") == successes, "reported success count differs from rows")
    for key, actual in (("completion_rps", len(rows) / cell["seconds"]),
                        ("successful_rps", successes / cell["seconds"])):
        check(finite_number(cell.get(key)) and math.isclose(cell[key], actual, rel_tol=1e-10, abs_tol=1e-10),
              key + " differs from rows/full duration")
    q = quantiles(rows)
    for key in ("p50", "p95", "p99", "max"):
        check(finite_number(cell.get(key + "_ms")) and math.isclose(cell[key + "_ms"], q[key], abs_tol=1e-8),
              key + " differs from all-row nearest-rank quantile")
    cpu = cell.get("controller_cpu_seconds")
    check(finite_number(cpu) and cpu >= 0, "whole-cell controller CPU is invalid")
    if finite_number(cpu):
        check(finite_number(cell.get("controller_cpu_ms_per_call")) and math.isclose(
            cell["controller_cpu_ms_per_call"], 1000 * cpu / len(rows), abs_tol=1e-8), "CPU/call differs")
    failed = [row for row in normalized if row.get("okay") is not True]
    check_success = all(row.get("okay") is True for name in ("initial", "restart") for row in phases[name])
    workload_passed = not failed and check_success
    check(round_.get("passed") is workload_passed, "raw round verdict differs from all observation outcomes")
    expected_raw_pass = workload_passed and not report.get("error") and report.get("binary_hashes_unchanged") is True and report.get("source_originals_unchanged") is True
    check(report.get("passed") is expected_raw_pass, "raw top-level verdict differs")
    hosts = {}
    for host in by_host:
        values = [row for row in normalized if row.get("host") == host]
        hosts[host] = {
            "attempts": len(values), "successes": sum(row.get("okay") is True for row in values),
            "latency_ms_including_failures": quantiles(values),
            "long_request_ordinals": [row["ordinal"] for row in values if row["elapsed_ms"] >= args.long_request_ms],
            "longest_request_ordinals": [row["ordinal"] for row in sorted(values, key=lambda x: (-x["elapsed_ms"], x["ordinal"]))[:10]],
        }
    return {
        "schema": "hepta-x230-soak-window-review/v1",
        "integrity_passed": not issues, "integrity_issues": issues,
        "workload_passed": workload_passed, "passed": not issues and workload_passed and expected_raw_pass,
        "raw_report_passed": report.get("passed"), "raw_report_error": report.get("error"),
        "binary_sha256": report.get("binary_sha256"), "expected_binary_sha256": args.expected_binary_sha256,
        "original_receipts": originals,
        "method": {
            "window_seconds": args.window_seconds,
            "window_origin": "earliest recorded timed-request start_monotonic",
            "window_coverage": "first timed-request start through latest derived timed-request completion",
            "completion_time": "start_monotonic + elapsed_ms / 1000; derived caller completion, not a separately retained native response-arrival timestamp",
            "window_intervals": "left-closed/right-open; only the last window includes its right endpoint",
            "latency_quantile": "nearest rank across every request in the named start/completion group, including failures",
            "window_rate_denominator": "actual observed window span, including first/last partial windows",
            "full_cell_rate_denominator": "complete driver-reported cell seconds, including unlocated setup/drain overhead",
            "long_request_ms": args.long_request_ms, "completion_gap_ms": args.completion_gap_ms,
            "minimum_observed_seconds": args.minimum_observed_seconds,
            "cpu_allocated_to_windows_or_hosts": False,
            "master_lifecycle_timestamps_available": False,
            "renewal_count_measured": None,
        },
        "whole_cell": {
            "concurrency": cell["concurrency"], "attempts": len(rows), "successes": successes,
            "failures": len(failed), "driver_cell_seconds": cell["seconds"],
            "observed_request_span_seconds": span,
            "unlocated_cell_overhead_seconds": cell["seconds"] - span,
            "attempts_per_driver_cell_second": len(rows) / cell["seconds"],
            "successes_per_driver_cell_second": successes / cell["seconds"],
            "latency_ms_including_failures": q,
            "controller_cpu_seconds": cpu, "controller_cpu_source": cell.get("controller_cpu_source"),
        },
        "verification": {
            "timed_rows": len(rows), "initial_checks": len(phases["initial"]),
            "restart_checks": len(phases["restart"]),
            "initial_successes": sum(x.get("okay") is True for x in phases["initial"]),
            "restart_successes": sum(x.get("okay") is True for x in phases["restart"]),
            "successful_complete_output_receipts_checked": checked_output_receipts,
            "all_timed_rows_retained": len(normalized) == len(rows),
            "source_originals_unchanged": report.get("source_originals_unchanged"),
            "binary_hashes_unchanged": report.get("binary_hashes_unchanged"),
        },
        "windows": windows, "hosts": hosts,
        "cross_window_request_ordinals": [row["ordinal"] for row in normalized if row["crosses_window_boundary"]],
        "completion_gap_observations": completion_gaps(normalized, args.completion_gap_ms),
        "all_timed_rows": normalized,
        "non_timed_observations": {name: phases[name] for name in ("initial", "restart")},
        "all_failed_timed_request_ordinals": [row["ordinal"] for row in failed],
        "resources": resources,
        "limitations": [
            "This verifies recorded receipts and the pinned report bytes; it does not reread remote binaries, job records or native DTO bodies.",
            "The frozen driver records lifetime resource peaks and errors, not RSS/FD time series. No memory-growth slope or per-window resource peak can be inferred.",
            "Resource peaks are sampled lower bounds, with all sampling errors retained; descendants are not classified as SSH-only.",
            "Caller completion windows and cross-host gaps describe symptoms. They do not establish SSH renewal, lease turnover, maintenance-lock contention or any causal mechanism.",
            "No exact master lifecycle events are available. Duration exceeding a derived renewal window does not establish any measured number of renewals.",
            "Whole-cell CPU is not apportioned among time windows, host aliases or failed/successful calls.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "analyze"):
        command = subparsers.add_parser(name)
        command.add_argument("--input", type=Path, required=True)
        command.add_argument("--expected-input-sha256", required=True)
        if name == "analyze":
            command.add_argument("--output", type=Path, required=True)
            command.add_argument("--expected-binary-sha256", required=True)
            command.add_argument("--originals-report", type=Path, required=True)
            command.add_argument("--expected-originals-report-sha256", required=True)
            command.add_argument("--expected-calls", type=int, required=True)
            command.add_argument("--expected-concurrency", type=int, default=8)
            command.add_argument("--window-seconds", type=float, default=30.0)
            command.add_argument("--minimum-observed-seconds", type=float, default=0.0)
            command.add_argument("--long-request-ms", type=float, default=1000.0)
            command.add_argument("--completion-gap-ms", type=float, default=1000.0)
    args = parser.parse_args()
    report, input_receipt = load_pinned(args.input, args.expected_input_sha256)
    own_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if args.command == "inspect":
        print(json.dumps({**inspect_structure(report), "input": input_receipt, "review_script_sha256": own_sha}, sort_keys=True))
        return 0
    require(args.expected_calls > 0 and args.expected_calls % 12 == 0, "expected calls must be a positive multiple of 12")
    require(1 <= args.expected_concurrency <= 32, "unsupported expected concurrency")
    require(all(finite_number(x) and x > 0 for x in (args.window_seconds, args.long_request_ms, args.completion_gap_ms)), "invalid analysis threshold")
    require(finite_number(args.minimum_observed_seconds) and args.minimum_observed_seconds >= 0, "invalid minimum observed span")
    require(not args.output.exists(), "output already exists; analysis output is create-only")
    originals, originals_receipt = load_pinned(args.originals_report, args.expected_originals_report_sha256)
    result = analyze(report, originals, args)
    result.update({"source_report": input_receipt, "originals_reference_report": originals_receipt, "review_script_sha256": own_sha})
    encoded = (json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    with args.output.open("xb") as handle:
        handle.write(encoded)
    print(json.dumps({"output": str(args.output), "sha256": hashlib.sha256(encoded).hexdigest(), "bytes": len(encoded), "integrity_passed": result["integrity_passed"], "workload_passed": result["workload_passed"], "passed": result["passed"]}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(json.dumps({"error_type": type(error).__name__, "error": str(error), "analysis_output_claimed": False}), file=sys.stderr)
        sys.exit(2)
