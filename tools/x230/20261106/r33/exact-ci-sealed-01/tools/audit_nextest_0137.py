#!/usr/bin/env python3
"""Exact-case audit for nextest0.9.137 JSON listing and human run output.

Schema/status syntax is bound to release commit
75ddba7e911b44c5c0700dac0415d824403de9bd in official-source-manifest.json.
Pure functions: no subprocesses, network, writes or workload retries.
"""
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def case_key(row):
    return row["target_name"], tuple(row["target_kind"]), row["name"]


def inventory(value, expected, source, target):
    need(type(value.get("test-count")) is int and value["test-count"] == expected["total"], "structured test count differs")
    suites = value["rust-suites"]
    need(isinstance(suites, dict) and suites, "empty suite inventory")
    need(value["rust-build-meta"]["target-directory"] == str(target), "nextest target directory differs")
    qualified_targets = {(row["target_name"], tuple(row["target_kind"])): row for row in expected["test_target_inventory"]}
    qualified_cases = {case_key(row): row for row in expected["exact_cases"]}
    need(len(qualified_cases) == expected["total"], "duplicate qualified case inventory")
    found, seen_targets, binary_paths, runtime_cases = {}, set(), {}, {}
    for binary_id, suite in suites.items():
        need(suite["binary-id"] == binary_id and suite["status"] == "listed", "suite identity or listing status differs")
        key = suite["binary-name"], (suite["kind"],)
        need(key in qualified_targets and key not in seen_targets, "unexpected or duplicate Cargo target")
        seen_targets.add(key)
        need(suite["cwd"] == str(source) and suite["build-platform"] == "target", "suite source/platform differs")
        path = Path(suite["binary-path"])
        need(path.is_absolute() and path.is_relative_to(target), "listed binary outside private target")
        binary_paths[binary_id] = {"path": str(path), "qualified": qualified_targets[key]["qualified_test_binary"]}
        cases = suite["testcases"]
        need(len(cases) == qualified_targets[key]["inventory_count"], "per-target inventory count differs")
        ignored_names = []
        for name, row in cases.items():
            ck = (*key, name)
            need(ck in qualified_cases and ck not in found and type(row["ignored"]) is bool, "unexpected or duplicate exact case")
            need(row.get("kind") in {None, "test"}, "unexpected benchmark or unknown case kind")
            ignored = row["ignored"]
            need(ignored is qualified_cases[ck]["ignored"], "ignored set differs")
            match = {"status": "mismatch", "reason": "ignored"} if ignored else {"status": "matches"}
            need(row["filter-match"] == match, "additional filter, partition, default-filter or replay selection detected")
            found[ck] = {"target_name": key[0], "target_kind": list(key[1]), "name": name, "ignored": ignored}
            runtime_cases[(binary_id, name)] = found[ck]
            if ignored:
                ignored_names.append(name)
        need(sorted(ignored_names) == sorted(qualified_targets[key]["ignored_names"]), "per-target ignored inventory differs")
    need(seen_targets == set(qualified_targets), "a qualified binary target is missing")
    need(set(found) == set(qualified_cases), "a qualified case is missing")
    canonical = sorted(found.values(), key=lambda row: (row["target_name"], row["target_kind"], row["name"]))
    digest = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    need(digest == expected["case_inventory_sha256"], "exact case inventory digest differs")
    return {"verified": True, "total": len(found), "ignored": sum(row["ignored"] for row in canonical),
            "suite_count": len(suites), "nonempty_suite_count": sum(bool(row["testcases"]) for row in suites.values()),
            "case_inventory_sha256": digest, "binary_paths": binary_paths,
            "runtime_cases": runtime_cases}


ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
STATUS = re.compile(r"^\s*(PASS|LEAK|TIMEOUT-PASS)\s+\[\s*([0-9]+(?:\.[0-9]+)?)s\]\s+(?:\(\s*(\d+)/(\d+)\)\s+)?(\S+)\s+(.+?)\s*$")
START = re.compile(r"^\s*Starting\s+(\d+) tests? across (\d+) binar(?:y|ies)(?: \((\d+) tests? skipped\))?\s*$")
SUMMARY = re.compile(r"^\s*Summary\s+\[\s*([0-9]+(?:\.[0-9]+)?)s\]\s+(\d+)(?:/(\d+))? tests? run: (\d+) passed(?: \(([^)]*)\))?, (\d+) skipped\s*$")
BAD_STATUS = re.compile(r"^\s*(?:TRY\s+\d|FLAKY\b|FLKY-FL\b|RETRY\b|FAIL\b|XFAIL\b|LEAK-FAIL\b|TIMEOUT\s|ABORT\b|SIG[A-Z]+\b)")


def run_output(raw, listed, expected):
    text = ANSI.sub("", raw.decode("utf-8"))
    starts, summaries, observed, durations, statuses, counters = [], [], {}, {}, Counter(), []
    runtime_cases = listed["runtime_cases"]
    need(all(type(row["ignored"]) is bool for row in runtime_cases.values()), "invalid bound inventory")
    wanted = {key for key, row in runtime_cases.items() if not row["ignored"]}
    for number, line in enumerate(text.splitlines(), 1):
        need(not BAD_STATUS.match(line), "failure/retry/abnormal status in original nextest output at line " + str(number))
        if line.lstrip().startswith("Starting "):
            match = START.fullmatch(line)
            need(match is not None, "unrecognized or filtered nextest Starting line")
            starts.append((number, match))
        if line.lstrip().startswith("Summary "):
            match = SUMMARY.fullmatch(line)
            need(match is not None, "nonpassing, partial, stress or unrecognized nextest summary")
            summaries.append((number, match))
        match = STATUS.fullmatch(line)
        if match:
            status, duration, index, total, binary_id, name = match.groups()
            key = binary_id, name
            need(key in wanted and key not in observed, "unknown, ignored or duplicate completed case")
            observed[key] = number
            durations[key] = float(duration)
            statuses[status] += 1
            if index is not None:
                need(int(total) == expected["passed"], "progress denominator differs")
                counters.append(int(index))
    need(len(starts) == len(summaries) == 1, "exactly one original run start and summary required")
    start_line, start = starts[0]
    summary_line, summary = summaries[0]
    need(int(start[1]) == expected["passed"] and int(start[3] or 0) == expected["skipped"], "run start counts differ")
    need(listed["nonempty_suite_count"] <= int(start[2]) <= listed["suite_count"], "run header binary count differs")
    need(set(observed) == wanted and all(start_line < line < summary_line for line in observed.values()), "run did not complete every expected case exactly once")
    if counters:
        need(len(counters) == len(observed) and sorted(counters) == list(range(1, expected["passed"] + 1)), "progress sequence incomplete or duplicated")
    need(int(summary[2]) == int(summary[4]) == expected["passed"]
         and (summary[3] is None or int(summary[3]) == expected["passed"])
         and int(summary[6]) == expected["skipped"], "final counts differ from qualified inventory")
    qualifiers = {}
    if summary[5]:
        for item in summary[5].split(", "):
            match = re.fullmatch(r"(\d+) (slow|flaky|leaky)", item)
            need(match is not None and match[2] not in qualifiers, "unknown or duplicate pass qualifier")
            qualifiers[match[2]] = int(match[1])
    need(qualifiers.get("flaky", 0) == 0, "flaky outcome violates zero retries")
    need(qualifiers.get("leaky", 0) == statuses["LEAK"], "leak status count differs from footer")
    need(all(value <= expected["passed"] for value in qualifiers.values()), "invalid pass qualifier count")
    return {"verified": True, "passed": len(observed), "failed": 0, "ignored": expected["skipped"],
            "selected": expected["total"], "retries": 0, "completed_exact_case_count": len(observed),
            "case_inventory_sha256": listed["case_inventory_sha256"], "success_status_counts": dict(statuses),
            "summary_pass_qualifiers": qualifiers, "nextest_seconds": float(summary[1]),
            "progress_counter_complete": bool(counters), "raw_bytes": len(raw),
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "success_semantics": "PASS, LEAK and TIMEOUT-PASS retain nextest's original successful-status semantics; nonplain successes are separately reported. Failed, partial, flaky or retried outcomes never pass this audit."}
