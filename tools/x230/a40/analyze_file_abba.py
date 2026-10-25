#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independently verify a complete six-host file-observation ABBA report.

Reads the complete original report and calls.jsonl or calls.jsonl.gz, without
importing a benchmark or modifying any input. --out writes a new JSON file;
otherwise the complete analysis is written to stdout. Only a complete fixed
off/on/on/off comparison is accepted; this is not the soak analyzer.

Example:
  python3 analyze_file_abba.py --report /abs/report.json \
      --calls /abs/calls.jsonl.gz --out /abs/new-analysis.json

Call slots are not native/RPC request identities. This analysis cannot prove
wire exactly-once delivery or independently recover remote original bytes.
Reported cell wall times and waited child CPU are checked and aggregated;
they cannot be reconstructed from per-call latency rows alone.
"""

import argparse
from collections import Counter, defaultdict
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import statistics
import sys


HOSTS = ("ai395", "mac", "main", "pocket4", "rog", "x230")
TOOLS = ("file_info", "binary_read")
PHASES = ("warmup", "measured", "negative")
ORDER = ("off", "on", "on", "off")
HEX = re.compile(r"[0-9a-f]{64}\Z")
WAIT_SCOPE = ("controller and reaped local descendants for complete round, including "
              "warmup, rejection cases and shutdown; remote CPU excluded")


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_original(path):
    path = path.absolute()
    need(path.resolve(strict=True) == path, "input must have no symlink or dot-path aliases")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode), "input is not a regular file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read()
        need(len(data) == before.st_size and fingerprint(before) == fingerprint(os.fstat(fd))
             == fingerprint(path.lstat()), "input changed during complete read")
        return data, {"path": str(path), "bytes": len(data), "sha256": digest(data)}, fingerprint(before)
    finally:
        os.close(fd)


def no_duplicate_keys(pairs):
    result = {}
    for name, value in pairs:
        need(name not in result, "duplicate JSON object key: " + name)
        result[name] = value
    return result


def invalid_constant(value):
    raise ValueError("non-finite JSON number: " + value)


def decode(data):
    return json.loads(data, object_pairs_hook=no_duplicate_keys, parse_constant=invalid_constant)


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def hex_digest(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def stats(rows):
    values = sorted(row["elapsed_ms"] for row in rows)
    passed = sum(row["okay"] for row in rows)
    return {"count": len(rows), "passed_checks": passed, "failed_checks": len(rows) - passed,
        "all_okay": bool(rows) and passed == len(rows),
        "check_success_rate": passed / len(rows) if rows else None,
        "latency_ms_all_rows": None if not values else {
            "min": values[0], "mean": statistics.mean(values), "p50": statistics.median(values),
            "p95": values[math.ceil(.95 * len(values)) - 1],
            "p99": values[math.ceil(.99 * len(values)) - 1], "max": values[-1]}}


def slot(row):
    base = (row["round"], row["mode"], row["phase"])
    if row["phase"] == "measured":
        return base + (row["iteration"], row["concurrency"], row["index"])
    return base + (row["host"], row["tool"], row.get("expected_error"))


def parse_rows(raw):
    need(raw and raw.endswith(b"\n"), "complete calls JSONL must end with a newline")
    rows, errors = [], []
    for line_number, line in enumerate(raw.splitlines(), 1):
        try:
            need(line.strip(), "empty JSONL line")
            row = decode(line)
            need(isinstance(row, dict), "row is not an object")
            need(row.get("phase") in PHASES and row.get("mode") in ("off", "on")
                 and row.get("host") in HOSTS and row.get("tool") in TOOLS,
                 "unexpected phase, mode, host or tool")
            need(type(row.get("round")) is int and row["round"] >= 0
                 and type(row.get("okay")) is bool and type(row.get("automatic_retry")) is bool
                 and number(row.get("elapsed_ms")), "invalid outcome, round or latency")
            if row["phase"] == "measured":
                need(all(type(row.get(key)) is int and row[key] >= 0
                         for key in ("iteration", "concurrency", "index")), "invalid measured slot")
            if row["okay"]:
                need(hex_digest(row.get("response_sha256")), "successful check lacks response digest")
                if row["phase"] == "negative":
                    need(row["tool"] == "binary_read"
                         and row.get("expected_error") in ("stale_version", "outside_root"),
                         "negative check has unexpected refusal kind")
                else:
                    need(type(row.get("bytes")) is int and row["bytes"] > 0
                         and hex_digest(row.get("data_sha256"))
                         and isinstance(row.get("version"), str) and row["version"],
                         "successful observation lacks original size/hash/version")
            rows.append(row)
        except Exception as error:
            errors.append({"line": line_number, "error": type(error).__name__ + ": " + str(error)})
    need(not errors, "invalid raw rows; no successful subset analyzed: " + json.dumps(errors))
    return rows


def analyze(report, rows, calls_sha256):
    issues = []

    def check(condition, message):
        if not condition:
            issues.append(message)

    need(isinstance(report, dict) and report.get("schema") == "hepta-x230-file-pool-abba/v1",
         "unexpected report schema")
    check(report.get("complete") is True, "report is not complete")
    check(report.get("calls_sha256") == calls_sha256, "complete raw calls SHA differs from report")
    check(report.get("order") == list(ORDER), "comparison order is not fixed off/on/on/off")
    check(report.get("binary_unchanged") is True and report.get("agent_unchanged") is True,
          "binary or SSH agent unchanged binding is missing")
    check(report.get("remote_writes") is False
          and report.get("remote_operations") == list(TOOLS), "remote observation scope differs")
    for key in ("binary_sha256", "script_sha256", "ssh_wrapper_sha256"):
        check(hex_digest(report.get(key)), "invalid binding digest: " + key)
    calls, concurrencies = report.get("calls_per_cell"), report.get("concurrency")
    need(type(calls) is int and calls >= 12 and calls % 12 == 0, "unbalanced configured cell size")
    need(isinstance(concurrencies, list) and concurrencies
         and all(type(value) is int and 1 <= value <= 16 for value in concurrencies)
         and len(concurrencies) == len(set(concurrencies)), "invalid concurrency grid")
    rounds = report.get("rounds")
    need(isinstance(rounds, list) and len(rounds) == 4, "expected exactly four complete report rounds")
    phase_counts = Counter(row["phase"] for row in rows)
    expected_counts = {"warmup": 48, "negative": 48, "measured": 4 * len(concurrencies) * calls}
    check(dict(phase_counts) == expected_counts, "raw phase counts differ from the complete fixed plan")
    check(len(rows) == sum(expected_counts.values()), "raw total differs from the complete fixed plan")
    check({row["host"] for row in rows} == set(HOSTS), "raw host set differs")
    check(all(row["okay"] for row in rows), "one or more raw checks failed")
    check(all(row["automatic_retry"] is False for row in rows), "row reports automatic retry")
    check(all(0 <= row["round"] < 4 and row["mode"] == ORDER[row["round"]] for row in rows),
          "row round/mode does not match fixed order")
    slot_counts = Counter(slot(row) for row in rows)
    duplicates = [{"slot": list(key), "count": value} for key, value in slot_counts.items() if value > 1]
    check(not duplicates, "duplicate logical request slots")

    originals = defaultdict(set)
    for row in rows:
        if row["phase"] != "negative" and row["okay"]:
            originals[row["host"]].add((row["bytes"], row["data_sha256"], row["version"]))
    check(set(originals) == set(HOSTS) and all(len(values) == 1 for values in originals.values()),
          "original size/hash/version projection changed across observations")

    cells, cpu_rounds, resource_rounds, snapshots = [], [], [], []
    expected_mix = Counter({(host, tool): calls // 12 for host in HOSTS for tool in TOOLS})
    for position, round_ in enumerate(rounds):
        need(isinstance(round_, dict), "round is not an object")
        index, mode = round_.get("index"), round_.get("mode")
        check(index == position and mode == ORDER[position], "report round order/index differs")
        round_rows = [row for row in rows if row["round"] == position]
        check(len(round_rows) == len(concurrencies) * calls + 24, f"round {position} raw count differs")
        for phase in ("warmup", "negative"):
            selected = [row for row in round_rows if row["phase"] == phase]
            check(selected == round_.get(phase), f"round {position} {phase} full rows differ from report")
            observed = Counter((row["host"], row["tool"]) if phase == "warmup"
                               else (row["host"], row.get("expected_error")) for row in selected)
            wanted = Counter({(host, value): 1 for host in HOSTS
                              for value in (TOOLS if phase == "warmup" else ("stale_version", "outside_root"))})
            check(observed == wanted, f"round {position} {phase} host/tool or refusal coverage differs")
        reported_cells = round_.get("cells")
        need(isinstance(reported_cells, list), "round cells is not an array")
        check(len(reported_cells) == len(concurrencies), f"round {position} cell count differs")
        check([cell.get("concurrency") for cell in reported_cells] == concurrencies,
              f"round {position} cell order/concurrency differs")
        for cell in reported_cells:
            concurrency = cell.get("concurrency")
            check(cell.get("iteration") == 0, f"round {position} contains a non-ABBA iteration")
            selected = [row for row in round_rows if row["phase"] == "measured"
                        and row["concurrency"] == concurrency and row["iteration"] == 0]
            calculated = stats(selected)
            prefix = f"round {position} C{concurrency}: "
            check(len(selected) == calls and cell.get("calls") == calls, prefix + "cell call count differs")
            check(cell.get("success") == calculated["passed_checks"], prefix + "reported successes differ")
            check(Counter((row["host"], row["tool"]) for row in selected) == expected_mix,
                  prefix + "six-host/two-tool mix is not exactly balanced")
            check(Counter(row["index"] for row in selected) == Counter(range(calls)),
                  prefix + "logical call indices have missing/duplicate slots")
            quantiles = calculated["latency_ms_all_rows"]
            for name in ("p50", "p95", "p99"):
                check(quantiles is not None and quantiles[name] == cell.get(name + "_ms"),
                      prefix + "reported " + name + " differs from all raw rows")
            wall = cell.get("seconds")
            need(number(wall) and wall > 0, prefix + "invalid measured wall time")
            rate = calculated["passed_checks"] / wall
            check(rate == cell.get("successful_calls_per_second"), prefix + "reported rate differs")
            cells.append({"round": position, "mode": mode, "concurrency": concurrency,
                **calculated, "measured_wall_seconds_reported": wall,
                "successful_calls_per_second_recomputed": rate,
                "balanced_host_tool_calls_each": calls // 12,
                "controller_only_cpu_ms_per_call_reported": cell.get("cpu_ms_per_call")})
            need(isinstance(cell.get("resources"), dict), prefix + "resource snapshot absent")
            snapshots.append(cell["resources"])
        shutdown = round_.get("shutdown")
        need(isinstance(shutdown, dict), "shutdown receipt absent")
        check(shutdown.get("exit_code") == 0 and shutdown.get("shutdown_method") == "stdin_eof"
              and shutdown.get("unmatched_responses") == 0 and shutdown.get("reader_error") is None
              and shutdown.get("observed_descendant_survivors") == [],
              f"round {position} shutdown/observed-descendant checks differ")
        waited = round_.get("waited_process_tree_cpu_seconds")
        need(number(waited), "invalid waited CPU receipt")
        check(round_.get("waited_cpu_scope") == WAIT_SCOPE, "waited CPU scope differs")
        cpu_rounds.append({"round": position, "mode": mode, "seconds": waited})
        resource = shutdown.get("resources")
        need(isinstance(resource, dict), "shutdown resource snapshot absent")
        snapshots.append(resource)
        resource_rounds.append({"round": position, "mode": mode,
            "sampled_peaks": resource.get("peaks"), "samples": resource.get("samples"),
            "sample_interval_seconds": resource.get("sample_interval_seconds"),
            "sampled_tree_cpu_seconds": resource.get("sampled_tree_cpu_seconds")})
    check(sum(cell["count"] for cell in cells) == phase_counts["measured"],
          "not every raw measured row belongs to exactly one report cell")

    error_counts, error_values = Counter(), {}
    for snapshot in snapshots:
        need(isinstance(snapshot.get("errors"), list) and isinstance(snapshot.get("peaks"), dict),
             "invalid resource snapshot schema")
        check(snapshot.get("sampled_peaks_are_not_exhaustive_limits") is True,
              "resource snapshot lacks its non-exhaustive scope")
        need(all(number(value) for value in snapshot["peaks"].values()), "invalid resource peak")
        for error in snapshot["errors"]:
            key = canonical(error).decode()
            error_counts[key] += 1
            error_values[key] = error

    weighted = []
    for concurrency in concurrencies:
        arms = {}
        for mode in ("off", "on"):
            selected = [cell for cell in cells if cell["mode"] == mode and cell["concurrency"] == concurrency]
            successes = sum(cell["passed_checks"] for cell in selected)
            wall = sum(cell["measured_wall_seconds_reported"] for cell in selected)
            need(wall > 0, "arm has no measured wall denominator")
            arms[mode] = {"calls": sum(cell["count"] for cell in selected), "successful_calls": successes,
                          "measured_wall_seconds": wall, "successful_calls_per_second": successes / wall}
        weighted.append({"concurrency": concurrency, **arms,
            "on_vs_off_throughput_change_percent":
                100 * (arms["on"]["successful_calls_per_second"] / arms["off"]["successful_calls_per_second"] - 1)
                if arms["off"]["successful_calls_per_second"] else None})
    cpu_sums = {mode: sum(row["seconds"] for row in cpu_rounds if row["mode"] == mode) for mode in ("off", "on")}
    resource_arms = {mode: {name: [row["sampled_peaks"].get(name) for row in resource_rounds if row["mode"] == mode]
                           for name in ("tree_rss_kib", "controller_rss_kib", "tree_fd", "controller_fd")}
                     for mode in ("off", "on")}
    return {"valid": not issues, "errors": issues, "raw_rows": len(rows),
        "phase_counts": dict(phase_counts), "expected_phase_counts": expected_counts,
        "all_okay": all(row["okay"] for row in rows), "host_counts": dict(sorted(Counter(row["host"] for row in rows).items())),
        "phase_mode": [{"phase": phase, "mode": mode, **stats([row for row in rows
                         if row["phase"] == phase and row["mode"] == mode])} for phase in PHASES for mode in ("off", "on")],
        "automatic_retry_true_rows": sum(row["automatic_retry"] for row in rows),
        "logical_slots_unique": not duplicates, "duplicate_logical_slots": duplicates,
        "request_identity_scope": "logical schedule slots only; rows do not carry native/RPC request IDs; no wire exactly-once claim",
        "original_observation_projections": [{"host": host, "bytes": size, "data_sha256": sha, "version": version}
            for host in sorted(originals) for size, sha, version in sorted(originals[host])],
        "original_content_scope": "size/hash/version consistency across all recorded observations; remote original file bytes are not analyzer inputs",
        "cells": cells, "weighted_throughput": weighted if not issues else None,
        "throughput_scope": "total successful measured calls / sum of both recorded cell wall times per mode and concurrency; two rounds per mode, descriptive, no confidence interval",
        "waited_local_process_tree_cpu": {"rounds": cpu_rounds, "seconds_by_mode": cpu_sums,
            "on_vs_off_change_percent": 100 * (cpu_sums["on"] / cpu_sums["off"] - 1) if cpu_sums["off"] else None,
            "scope": "recorded RUSAGE_CHILDREN deltas after controller waits; whole rounds include startup, warmup, measured calls, rejection cases and shutdown; exclude remote host and external sampler CPU",
            "aggregation_of_reported_accounting": True,
            "per_cell_cpu_is_controller_only_and_not_substituted": True},
        "resources": {"rounds": resource_rounds, "per_round_peak_lists_by_mode": resource_arms,
            "distinct_error_count": len(error_counts),
            "distinct_errors": [{"error": error_values[key], "snapshot_occurrences": error_counts[key]} for key in sorted(error_counts)],
            "limits": ["sampled RSS/FD peaks are neither exhaustive nor atomic",
                       "cell snapshots repeat accumulated errors; occurrences are not independent errors",
                       "FD observations with permission failures are incomplete and do not prove a descriptor limit",
                       "RSS/CPU observations are independently sampled where readable",
                       "empty observed_descendant_survivors covers only processes actually sampled"]}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--calls", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = {"schema": "hepta-six-host-file-abba-independent-analysis/v1", "valid": False,
              "analysis_complete": False, "inputs_unchanged": False, "errors": [], "inputs": {}}
    originals = {}
    try:
        for name, path in (("report", args.report), ("calls", args.calls)):
            raw, receipt, identity = read_original(path)
            originals[name] = (path, receipt, identity)
            result["inputs"][name] = receipt
            if name == "report":
                report_raw = raw
            else:
                calls_raw = gzip.decompress(raw) if path.name.endswith(".gz") else raw
                result["inputs"]["uncompressed_calls"] = {"bytes": len(calls_raw), "sha256": digest(calls_raw)}
        calculated = analyze(decode(report_raw), parse_rows(calls_raw), digest(calls_raw))
        result.update(calculated, analysis_complete=True)
    except Exception as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
        result["valid"] = False
    finally:
        changed = []
        for name, (path, receipt, identity) in originals.items():
            try:
                _, after, after_identity = read_original(path)
                need(after == receipt and after_identity == identity, "original bytes or metadata changed")
            except Exception as error:
                changed.append(name + ": " + type(error).__name__ + ": " + str(error))
        result["inputs_unchanged"] = not changed and len(originals) == 2
        if changed:
            result["errors"].extend(changed)
        if not result["inputs_unchanged"]:
            result["valid"] = False
            result["weighted_throughput"] = None
    encoded = canonical(result)
    if args.out is None:
        sys.stdout.buffer.write(encoded)
    else:
        with args.out.open("xb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        print(json.dumps({"path": str(args.out.absolute()), "bytes": len(encoded), "sha256": digest(encoded),
            "valid": result["valid"], "raw_rows": result.get("raw_rows"), "phase_counts": result.get("phase_counts"),
            "weighted_throughput": result.get("weighted_throughput"),
            "waited_cpu": result.get("waited_local_process_tree_cpu"), "errors": result["errors"]}, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
