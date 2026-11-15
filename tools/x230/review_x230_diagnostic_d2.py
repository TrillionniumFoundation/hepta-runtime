#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Create-only, local-only independent review of four actual D2 calibration runs.

This is an analysis helper, not a measurement driver. It never launches a
controller, reads a remote path, retries an observation, or changes an input.
The explicitly SHA-pinned measured driver additionally checks stderr/event grammar. Metric
arithmetic, nested bounds, workload arithmetic, and cost gates are independent.
Synthetic fixture results must never be represented as runtime measurements.
"""
import argparse
import collections
import hashlib
import importlib.util
import json
import math
from pathlib import Path

SOURCE_MAP_FILE_SHA = "8f41879846cdf57964f1238de5e6db04d58333cd7797d32baa2325a957c512da"
SOURCE_MAP_CANONICAL_SHA = "ec4419489f6499bdbecab9402d78e1997171bfeea1eda4be193b0af5f9688dc2"
U64 = (1 << 64) - 1
FILES = ("profile", "ssh_config", "known_hosts", "ssh_executable",
         "false_executable", "shell_executable", "unclassified")
PHASES = ("total", "open_and_before_checks", "read_and_hash", "after_stamps_and_digest")
METRICS = [("verify_files", "total")] + [(f, p) for f in FILES for p in PHASES] + [
    ("shell_resolution", "total"), ("policy_parent_and_environment", "total"),
    ("agent_snapshot", "wall_only")]
NUMERIC = ("started_intervals", "closed_intervals", "marked_success", "not_marked_success",
           "wall_valid_samples", "wall_invalid_samples", "wall_ns_sum", "wall_ns_max",
           "cpu_valid_samples", "cpu_invalid_samples", "cpu_ns_sum", "cpu_ns_max",
           "bytes_on_marked_success")
GATES = {
    "pooled": {"cpu_ms_per_attempt_pct_max": 5.0, "successful_rps_pct_min": -5.0, "p95_ms_pct_max": 10.0},
    "each_temporal_pair": {"cpu_ms_per_attempt_pct_max": 10.0, "successful_rps_pct_min": -10.0, "p95_ms_pct_max": 20.0},
    "interpretation": "predeclared exploratory tolerances; not confidence intervals or proof of no instrumentation effect",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def strict_json(data):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key: " + key)
            value[key] = item
        return value
    def invalid(value):
        raise ValueError("nonfinite JSON number: " + value)
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)


def is_u64(value):
    return type(value) is int and 0 <= value <= U64


def is_sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def finite(value, positive=False):
    return type(value) in (int, float) and math.isfinite(value) and (value > 0 if positive else value >= 0)


def check(condition, issues, message):
    if not condition:
        issues.append(message)
    return bool(condition)


def close(actual, expected):
    return finite(actual) and math.isclose(actual, expected, rel_tol=1e-10, abs_tol=1e-8)


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def quantile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def payload(path, expected_sha, issues):
    data = Path(path).read_bytes()
    actual = sha(data)
    check(actual == expected_sha, issues, "input SHA differs: " + Path(path).name)
    return strict_json(data), {"file": Path(path).name, "bytes": len(data), "sha256": actual,
                               "expected_sha256": expected_sha}


def validate_summary(summary):
    """Independent fixed-metric validation; retain invalid raw summaries."""
    issues = []
    flags = {"enabled": True, "recording_incomplete": False,
             "owner_thread_cpu_is_whole_controller_cpu": False,
             "thread_cpu_recorded_only_for_synchronous_metrics": True,
             "all_metrics_include_startup_observations_and_shutdown": True,
             "includes_only_timed_benchmark_cells": False,
             "agent_wall_intervals_may_overlap": True,
             "parent_metrics_include_their_children": True,
             "measurement_overhead_in_parent_and_owner_totals": True,
             "abrupt_termination_may_omit_summary": True,
             "failure_event_logging_may_perturb_failure_timing": True}
    if not isinstance(summary, dict):
        return {"valid": False, "issues": ["summary missing or not an object"], "phase_attribution": None}
    check(summary.get("schema") == "hepta-x230-profile-diagnostic/v2", issues, "summary schema differs")
    for key, expected in flags.items():
        check(summary.get(key) is expected, issues, "scope/recorder flag invalid: " + key)
    check(summary.get("clock") == "CLOCK_THREAD_CPUTIME_ID around synchronous intervals only", issues, "clock scope differs")
    check(summary.get("owner_scope") == "diagnostic activation at owner thread entry through completed runtime drain/destruction; excludes summary serialization, stderr write and final thread teardown; excludes profile loading before owner thread creation", issues, "owner lifetime scope differs")
    check(summary.get("not_marked_success_definition") == "interval dropped without its explicit success marker; includes errors, cancellation and unwinding, and is not an RPC failure count", issues, "success-marker meaning differs")
    check(summary.get("bytes_definition") == "bytes counted only on a successfully completed read_and_hash interval; a later stamp/digest or request check can still fail", issues, "byte counter meaning differs")
    for key in ("owner_thread_cpu_ns", "owner_wall_ns"):
        check(is_u64(summary.get(key)) and summary[key] > 0, issues, "owner clock invalid: " + key)
    metrics = summary.get("metrics")
    if not isinstance(metrics, list):
        return {"valid": False, "issues": issues + ["metrics missing"], "phase_attribution": None}
    check(len(metrics) == 32, issues, "metric count must be exactly 32")
    found = {}
    for item in metrics:
        if not isinstance(item, dict):
            issues.append("metric is not an object")
            continue
        key = (item.get("category"), item.get("phase"))
        label = ".".join(str(x) for x in key)
        if not check(key in METRICS and key not in found, issues, "unknown or duplicated metric: " + label):
            continue
        found[key] = item
        parent = ("same_category.total" if key[0] in FILES and key[1] != "total" else
                  "verify_files.total" if key[0] in FILES or key[0] in ("shell_resolution", "policy_parent_and_environment") else None)
        check(item.get("parent_inclusive_metric") == parent, issues, "parent differs: " + label)
        check(item.get("counter_saturated") is False, issues, "counter saturated/missing: " + label)
        if not check(all(is_u64(item.get(name)) for name in NUMERIC), issues, "invalid u64 counters: " + label):
            continue
        count = item["closed_intervals"]
        check(item["started_intervals"] == count, issues, "unclosed interval: " + label)
        check(item["marked_success"] + item["not_marked_success"] == count, issues, "outcome count differs: " + label)
        check(item["wall_valid_samples"] == count and item["wall_invalid_samples"] == 0, issues, "wall samples incomplete: " + label)
        applicable = key != ("agent_snapshot", "wall_only")
        check(item.get("cpu_applicable") is applicable, issues, "CPU applicability differs: " + label)
        if applicable:
            check(item["cpu_valid_samples"] == count and item["cpu_invalid_samples"] == 0, issues, "CPU samples incomplete: " + label)
        else:
            check(all(item[name] == 0 for name in ("cpu_valid_samples", "cpu_invalid_samples", "cpu_ns_sum", "cpu_ns_max")), issues,
                  "asynchronous agent span has purported CPU: " + label)
        for clock in ("wall", "cpu"):
            valid, total, maximum = (item[clock + suffix] for suffix in ("_valid_samples", "_ns_sum", "_ns_max"))
            check(maximum <= total, issues, "maximum exceeds sum: " + label + "/" + clock)
            check(valid != 0 or (total == 0 and maximum == 0), issues, "duration without sample: " + label + "/" + clock)
            check(valid == 0 or total <= maximum * valid, issues, "sum exceeds sample-count times maximum: " + label + "/" + clock)
        if key[1] != "read_and_hash":
            check(item["bytes_on_marked_success"] == 0, issues, "bytes recorded outside read_and_hash: " + label)
        check(item["marked_success"] != 0 or item["bytes_on_marked_success"] == 0, issues, "bytes without successful span: " + label)
        if is_u64(summary.get("owner_thread_cpu_ns")) and applicable:
            check(item["cpu_ns_sum"] <= summary["owner_thread_cpu_ns"], issues, "one synchronous metric exceeds owner CPU: " + label)
        if is_u64(summary.get("owner_wall_ns")):
            check(item["wall_ns_max"] <= summary["owner_wall_ns"], issues, "span exceeds owner wall lifetime: " + label)
            if applicable:
                check(item["wall_ns_sum"] <= summary["owner_wall_ns"], issues, "synchronous metric exceeds owner wall lifetime: " + label)
    check(set(found) == set(METRICS), issues, "fixed metric set incomplete")
    residuals = {}
    if not issues:
        check(found[("verify_files", "total")]["closed_intervals"] > 0, issues, "no owner file validation measured")
        parents = {"verify_files": [(name, "total") for name in FILES] + [
            ("shell_resolution", "total"), ("policy_parent_and_environment", "total")]}
        parents.update({name: [(name, phase) for phase in PHASES[1:]] for name in FILES})
        for parent, children in parents.items():
            residuals[parent] = {}
            for clock in ("cpu", "wall"):
                field = clock + "_ns_sum"
                difference = found[(parent, "total")][field] - sum(found[key][field] for key in children)
                residuals[parent][clock + "_ns"] = difference
                check(difference >= 0, issues, "negative nested residual: " + parent + "/" + clock)
    return {"valid": not issues, "issues": issues,
            "signed_nested_residuals_ns": residuals,
            "phase_attribution": phase_profile([summary]) if not issues else None}


def phase_profile(summaries):
    """Only call with validated summaries belonging to one controller role."""
    owner_cpu = sum(s["owner_thread_cpu_ns"] for s in summaries)
    owner_wall = sum(s["owner_wall_ns"] for s in summaries)
    merged = {}
    for key in METRICS:
        members = [next(m for m in s["metrics"] if (m["category"], m["phase"]) == key) for s in summaries]
        item = {"category": key[0], "phase": key[1], "cpu_applicable": key[0] != "agent_snapshot"}
        for name in NUMERIC:
            item[name] = (max(m[name] for m in members) if name.endswith("_max") else sum(m[name] for m in members))
        item["mean_wall_ns"] = ratio(item["wall_ns_sum"], item["wall_valid_samples"])
        item["mean_cpu_ns"] = ratio(item["cpu_ns_sum"], item["cpu_valid_samples"]) if item["cpu_applicable"] else None
        item["inclusive_owner_cpu_fraction"] = ratio(item["cpu_ns_sum"], owner_cpu) if item["cpu_applicable"] else None
        merged[key] = item
    files_cpu = merged[("verify_files", "total")]["cpu_ns_sum"]
    categories = [{"category": name, "inclusive_cpu_ns": merged[(name, "total")]["cpu_ns_sum"],
                   "inclusive_fraction_of_verify_files_cpu": ratio(merged[(name, "total")]["cpu_ns_sum"], files_cpu),
                   "inclusive_fraction_of_owner_cpu": ratio(merged[(name, "total")]["cpu_ns_sum"], owner_cpu)} for name in FILES]
    phase_totals = {phase: sum(merged[(name, phase)]["cpu_ns_sum"] for name in FILES) for phase in PHASES[1:]}
    top_children = sum(item["inclusive_cpu_ns"] for item in categories) + merged[("shell_resolution", "total")]["cpu_ns_sum"] + merged[("policy_parent_and_environment", "total")]["cpu_ns_sum"]
    return {
        "controller_count": len(summaries), "owner_thread_cpu_ns": owner_cpu, "owner_wall_ns": owner_wall,
        "scope": "same-role owner lifetimes; includes startup/preflight/shutdown and instrumentation; not timed-cell or whole-controller CPU",
        "metrics": list(merged.values()), "file_categories_inclusive": categories,
        "verify_files_cpu_ns": files_cpu, "verify_files_fraction_of_owner_cpu": ratio(files_cpu, owner_cpu),
        "owner_cpu_outside_verify_files_ns": owner_cpu - files_cpu,
        "verify_files_cpu_outside_nonoverlapping_children_ns": files_cpu - top_children,
        "file_phase_cpu_ns": phase_totals,
        "file_phase_fraction_of_verify_files_cpu": {key: ratio(value, files_cpu) for key, value in phase_totals.items()},
        "file_cpu_residuals_ns": {name: merged[(name, "total")]["cpu_ns_sum"] - sum(merged[(name, phase)]["cpu_ns_sum"] for phase in PHASES[1:]) for name in FILES},
        "residual_is_pure_business_exclusive_cpu": False,
        "agent_cpu_attribution": None,
        "agent_wall_note": "sum/mean/max of overlapping async intervals; not additive elapsed time or CPU; no interval quantiles",
        "hash_only_cpu_attribution": None,
    }


def review_diagnostics(report, stderr_root, mode, driver):
    issues = []
    inventory = report.get("controller_diagnostics")
    if not isinstance(inventory, list):
        return {"valid": False, "issues": ["canonical controller inventory missing"], "controllers": []}
    records = []
    seen = set()
    for item in inventory:
        item_issues = []
        ident = item.get("controller_id")
        allowed = {"round-0-B/first", "round-0-B/restart"}
        if not check(ident in allowed and ident not in seen, item_issues, "controller ID invalid or duplicated"):
            records.append({"controller_id": ident, "valid": False, "issues": item_issues, "raw_inventory_record": item})
            issues.extend(item_issues)
            continue
        seen.add(ident)
        role = ident.rsplit("/", 1)[1]
        check(item.get("controller_role") == role and item.get("round_index") == 0 and item.get("version") == "B", item_issues, "controller inventory identity differs")
        check(item.get("lifecycle_receipt_present") is True and item.get("reference_matches") is True, item_issues, "normal lifecycle reference missing or changed")
        diagnostic = item.get("diagnostic", {})
        file = Path(stderr_root) / ident / "stderr.log"
        record = {"controller_id": ident, "controller_role": role, "raw_diagnostic": diagnostic}
        try:
            raw = file.read_bytes()
            check(sha(raw) == diagnostic.get("stderr_sha256") and len(raw) == diagnostic.get("stderr_bytes"), item_issues, "stderr byte binding differs")
            record["stderr_binding"] = {"sha256": sha(raw), "bytes": len(raw)}
            lines = [line for line in raw.splitlines(keepends=True)
                     if line.startswith(b"HEPTA_X230_PROFILE_DIAGNOSTIC_JSON ") or line.startswith(b"HEPTA_X230_SPAWN_PROOF_FAILURE_JSON ")]
            check(all(line.endswith(b"\n") for line in lines), item_issues, "diagnostic line missing terminal newline")
            for line in lines:
                strict_json(line.split(b" ", 1)[1])
            parsed = driver.diagnostic_summary(file, mode)
            check(parsed == diagnostic, item_issues, "frozen-driver stderr reparse differs from canonical inventory")
            check(parsed.get("diagnostic_record_complete") is True and parsed.get("passed") is True, item_issues, "diagnostic record incomplete or explicitly failed")
            check(parsed.get("mode") == mode, item_issues, "diagnostic mode differs")
            if mode == "on":
                validation = validate_summary(parsed.get("summary"))
                item_issues.extend(validation["issues"])
                record["independent_statistics"] = validation
            else:
                check(parsed.get("summary") is None and parsed.get("summary_count") == 0 and parsed.get("failure_events") == [], item_issues, "off mode emitted diagnostics")
                record["independent_statistics"] = {"valid": not item_issues, "phase_attribution": None,
                    "reason": "off mode contains no phase observations; missing phase values are not zeros"}
            check(parsed.get("runtime_proof_failure_observed") is False, item_issues, "runtime proof failure observed; calibration is not clean")
        except Exception as error:
            item_issues.append(type(error).__name__ + ": " + str(error))
        record.update(valid=not item_issues, issues=item_issues)
        records.append(record)
        issues.extend(ident + ": " + issue for issue in item_issues)
    check(seen == {"round-0-B/first", "round-0-B/restart"}, issues, "normal first/restart inventory not complete")
    check(report.get("missing_controller_diagnostic_refs") == [], issues, "missing diagnostic refs")
    check(report.get("diagnostic_record_complete") is True, issues, "report diagnostic completeness false or missing")
    check(report.get("runtime_proof_failure_observed") is False, issues, "report proof failure flag is not false")
    for row in report.get("rounds", []):
        for shutdown, role in (("shutdown", "first"), ("restart_shutdown", "restart")):
            ref = row.get(shutdown, {}).get("profile_diagnostic")
            match = next((r for r in records if r.get("controller_role") == role), None)
            if match and isinstance(ref, dict):
                expected = driver.diagnostic_reference(Path("round-0-B") / role, match["raw_diagnostic"])
                check(ref == expected, issues, "shutdown reference differs for " + role)
            else:
                issues.append("normal shutdown diagnostic reference missing for " + role)
    return {"valid": not issues, "issues": issues, "controllers": records,
            "canonical_inventory_counted_once": True,
            "frozen_driver_reused_for_stderr_event_grammar_and_exact_inventory_reparse": True}


def review_rows(rows, expected, purpose, issues, dto_sets):
    check(isinstance(rows, list), issues, purpose + ": rows missing")
    if not isinstance(rows, list):
        return {"rows": 0, "successes": 0, "failures": [], "latencies_ms": []}
    check(len(rows) == len(expected), issues, purpose + ": row count differs")
    failures, latencies = [], []
    successes = 0
    for ordinal, row in enumerate(rows):
        label = purpose + " row " + str(ordinal)
        if ordinal < len(expected):
            original, tool = expected[ordinal]
            check(row.get("host") == original["host"] and row.get("job_id") == original["job_id"] and row.get("tool") == tool, issues, label + ": host/tool/original order differs")
        else:
            original, tool = {}, row.get("tool")
        check(row.get("purpose") == purpose and row.get("automatic_retry") is False, issues, label + ": purpose or no-retry differs")
        check(type(row.get("okay")) is bool, issues, label + ": outcome missing")
        if check(finite(row.get("elapsed_ms")), issues, label + ": latency invalid"):
            latencies.append(row["elapsed_ms"])
        check(finite(row.get("start_monotonic"), True) and finite(row.get("start_unix"), True), issues, label + ": start clock invalid")
        if row.get("okay") is True:
            successes += 1
            check(row.get("isError") is False and is_sha(row.get("dto_sha256")) and is_sha(row.get("response_sha256")), issues, label + ": native successful receipt missing")
            dto_sets[(row.get("host"), tool)].add(row.get("dto_sha256"))
            if tool == "process_read":
                check(row.get("stdout_sha256") == original.get("stdout_sha256") and row.get("stdout_bytes") == original.get("stdout_bytes")
                      and row.get("stderr_sha256") == sha(b"") and row.get("stderr_bytes") == 0, issues, label + ": full original output differs")
        else:
            failures.append({"ordinal": ordinal, "row": row})
    return {"rows": len(rows), "successes": successes, "failures": failures, "latencies_ms": latencies,
            "failure_types": dict(collections.Counter(str(item["row"].get("native_error", item["row"].get("reason", item["row"].get("rpc_error", "outcome_missing")))) for item in failures))}


def review_cell(cell, originals, issues, dto_sets):
    check(cell.get("concurrency") == 8 and cell.get("calls") == 384, issues, "timed dimensions differ from fixed 384/C8 plan")
    expected = [(originals[i % 6], "process_status" if (i // 6) % 2 == 0 else "process_read") for i in range(384)] if len(originals) == 6 else []
    rows = review_rows(cell.get("rows"), expected, "C8", issues, dto_sets)
    seconds, cpu = cell.get("seconds"), cell.get("controller_cpu_seconds")
    check(finite(seconds, True) and finite(cpu), issues, "cell elapsed/controller CPU invalid")
    facts = {"attempts": rows["rows"], "successes": rows["successes"], "failures": rows["rows"] - rows["successes"],
             "seconds": seconds, "controller_cpu_seconds": cpu, "latencies_ms": rows["latencies_ms"],
             "failed_rows": rows["failures"], "failure_types": rows["failure_types"]}
    if finite(seconds, True) and finite(cpu) and rows["rows"]:
        facts.update(attempt_rps=rows["rows"] / seconds, successful_rps=rows["successes"] / seconds,
                     cpu_ms_per_attempt=1000 * cpu / rows["rows"],
                     total_cpu_ms_per_success=1000 * cpu / rows["successes"] if rows["successes"] else None,
                     p50_ms=quantile(rows["latencies_ms"], .5), p95_ms=quantile(rows["latencies_ms"], .95),
                     p99_ms=quantile(rows["latencies_ms"], .99), max_ms=max(rows["latencies_ms"], default=None))
        for reported, derived in (("successes", "successes"), ("completion_rps", "attempt_rps"), ("successful_rps", "successful_rps"),
                                  ("controller_cpu_ms_per_call", "cpu_ms_per_attempt"), ("p50_ms", "p50_ms"),
                                  ("p95_ms", "p95_ms"), ("p99_ms", "p99_ms"), ("max_ms", "max_ms")):
            check(facts[derived] is not None and close(cell.get(reported), facts[derived]), issues, "cell arithmetic differs: " + reported)
    check(cell.get("no_success_filtering") is True and cell.get("sampled_tree_cpu_seconds_delta_is_lower_bound") is True, issues, "cell scope flags differ")
    check(cell.get("controller_cpu_source") == "same-PID/start-ticks /proc/stat utime+stime before/after cell", issues, "controller CPU provenance differs")
    facts["fast_failed_attempts_are_not_a_performance_gain"] = rows["successes"] != rows["rows"]
    return facts


def review_run(specification, binary_sha, driver, expected_driver_sha):
    mode, path, expected_sha, stderr_root = specification
    issues, native_issues = [], []
    result = {"mode": mode, "input_file": Path(path).name, "expected_raw_sha256": expected_sha,
              "quality_passed": False, "issues": issues, "native_issues": native_issues}
    try:
        report, binding = payload(path, expected_sha, issues)
        result["raw_binding"] = binding
        result["raw_report_passed"] = report.get("passed")
        result["raw_report_error"] = report.get("error")
        result["started_unix"], result["finished_unix"] = report.get("started_unix"), report.get("finished_unix")
        check(report.get("schema") == "hepta-x230-readonly-profile-diagnostic/v2", issues, "raw schema differs")
        check(report.get("order") == "B" and report.get("concurrency") == [8] and report.get("calls_per_cell") == 384 and report.get("tokio_workers") == 2, issues, "fixed calibration dimensions/order differ")
        check(report.get("binary_sha256") == {"A": binary_sha, "B": binary_sha}, issues, "actual binary identity differs")
        check(report.get("driver_sha256") == expected_driver_sha and report.get("diagnostic_source_variant") == "A23-D2", issues, "driver/source variant identity differs")
        check(report.get("diagnostic_mode") == mode and report.get("diagnostic_environment_value") == ("1" if mode == "on" else "0"), issues, "explicit mode/environment differs")
        check(report.get("qualified_runtime_performance_comparison") is False, issues, "diagnostic comparison misrepresented as production comparison")
        for key in ("effect_starts", "remote_mutation_tool_calls", "automatic_rpc_retries"):
            check(type(report.get(key)) is int and report[key] == 0, issues, "effect/retry count invalid: " + key)
        for key in ("source_originals_unchanged", "binary_hashes_unchanged"):
            check(report.get(key) is True, issues, "immutability receipt false/missing: " + key)
        profile = report.get("profile", {})
        check(profile.get("current_agent_bound") is True and profile.get("historical_agent_not_reused") is True, issues, "current agent profile receipt missing")
        result["profile_receipt"] = profile
        originals = report.get("six_originals", [])
        check(len(originals) == 6 and len({o.get("host") for o in originals}) == 6 and len({o.get("job_id") for o in originals}) == 6, issues, "six original identities differ")
        check(all(is_sha(o.get("record_sha256")) and is_sha(o.get("stdout_sha256")) and is_u64(o.get("stdout_bytes")) for o in originals), issues, "original metadata/output hash receipts invalid")
        result["originals_receipt_sha256"] = sha(canonical(originals))
        result["six_originals"] = originals
        rounds = report.get("rounds", [])
        check(len(rounds) == 1, issues, "B-only run must have one round")
        dto_sets = collections.defaultdict(set)
        if rounds:
            row = rounds[0]
            check(row.get("index") == 0 and row.get("version") == "B", issues, "round identity differs")
            check(row.get("passed") is True, native_issues, "round explicitly failed or incomplete")
            preflight = review_rows(row.get("initial_complete_outputs"), [(o, "process_read") for o in originals],
                                    "preflight_complete_output", issues, dto_sets)
            restart = review_rows(row.get("restart_checks"), [(o, tool) for o in originals for tool in ("process_status", "process_read")],
                                  "restart_same_original", issues, dto_sets)
            result["preflight"], result["restart"] = preflight, restart
            check(preflight["rows"] == preflight["successes"] == 6, native_issues, "initial original-output observations failed or missing")
            check(restart["rows"] == restart["successes"] == 12, native_issues, "restart original observations failed or missing")
            cells = row.get("cells", [])
            check(len(cells) == 1, issues, "expected exactly one C8 timed cell")
            result["cells"] = [review_cell(cell, originals, issues, dto_sets) for cell in cells]
            check(len(cells) == 1 and all(c["successes"] == c["attempts"] == 384 for c in result["cells"]), native_issues, "timed observations failed or missing")
            result["lifecycles"] = []
            for startup_key, shutdown_key, role in (("startup", "shutdown", "first"), ("restart_startup", "restart_shutdown", "restart")):
                startup, shutdown = row.get(startup_key, {}), row.get(shutdown_key, {})
                check(startup.get("diagnostic_mode") == mode and startup.get("diagnostic_environment_value") == ("1" if mode == "on" else "0"), issues, role + ": actual controller mode/environment receipt differs")
                check(type(startup.get("pid")) is int and startup["pid"] > 0 and type(startup.get("birth_ticks")) is int and startup["birth_ticks"] > 0, issues, role + ": controller generation receipt missing")
                for key, expected in (("exit_code", 0), ("shutdown_method", "stdin_eof"), ("observed_descendant_survivors", []),
                                      ("unmatched_responses", 0), ("reader_error", None)):
                    check(key in shutdown and shutdown[key] == expected, native_issues, role + ": normal EOF/cleanup differs: " + key)
                resources = shutdown.get("resources", {})
                check(resources.get("sample_interval_seconds") == .1 and resources.get("sampled_peaks_and_tree_cpu_are_lower_bounds") is True, issues, role + ": resource sampling scope differs")
                result["lifecycles"].append({"role": role, "exit_code": shutdown.get("exit_code"),
                    "shutdown_method": shutdown.get("shutdown_method"), "resources": resources,
                    "resource_interpretation": "lifetime sampled lower bounds, including startup/shutdown; no time series or stable resource-level claim"})
            initial, reopened = row.get("startup", {}), row.get("restart_startup", {})
            check((initial.get("pid"), initial.get("birth_ticks")) != (reopened.get("pid"), reopened.get("birth_ticks")), issues, "restart controller generation not distinct")
        check(all(len(values) == 1 for values in dto_sets.values()), issues, "a successful host/tool DTO changed")
        result["dto_receipts"] = [{"host": host, "tool": tool, "hashes": sorted(values)} for (host, tool), values in sorted(dto_sets.items())]
        check(report.get("passed") is True, native_issues, "native raw report explicitly failed or incomplete")
        check(finite(report.get("started_unix"), True) and finite(report.get("finished_unix"), True) and report["finished_unix"] >= report["started_unix"], issues, "run wall clock invalid")
        result["diagnostics"] = review_diagnostics(report, stderr_root, mode, driver)
        issues.extend(result["diagnostics"]["issues"])
    except Exception as error:
        issues.append(type(error).__name__ + ": " + str(error))
    result["quality_passed"] = not issues and not native_issues
    return result


def pool_cells(cells):
    attempts = sum(cell["attempts"] for cell in cells)
    successes = sum(cell["successes"] for cell in cells)
    seconds = sum(cell["seconds"] for cell in cells)
    cpu = sum(cell["controller_cpu_seconds"] for cell in cells)
    latencies = [value for cell in cells for value in cell["latencies_ms"]]
    return {"attempts": attempts, "successes": successes, "seconds": seconds, "controller_cpu_seconds": cpu,
            "cpu_ms_per_attempt": 1000 * cpu / attempts, "successful_rps": successes / seconds,
            "p50_ms": quantile(latencies, .5), "p95_ms": quantile(latencies, .95), "p99_ms": quantile(latencies, .99),
            "max_ms": max(latencies), "latency_count": len(latencies)}


def compare(off, on, gate):
    changes = {key + "_pct": (on[key] / off[key] - 1) * 100 if off[key] > 0 else None
               for key in ("cpu_ms_per_attempt", "successful_rps", "p95_ms")}
    def within(value, limit, lower=False):
        return value is not None and ((value >= limit if lower else value <= limit)
                                      or math.isclose(value, limit, rel_tol=1e-12, abs_tol=1e-12))
    checks = {"cpu_within_tolerance": within(changes["cpu_ms_per_attempt_pct"], gate["cpu_ms_per_attempt_pct_max"]),
              "goodput_within_tolerance": within(changes["successful_rps_pct"], gate["successful_rps_pct_min"], lower=True),
              "p95_within_tolerance": within(changes["p95_ms_pct"], gate["p95_ms_pct_max"])}
    return {"off": off, "on": on, "on_relative_to_off": changes, "checks": checks, "within_predeclared_tolerances": all(checks.values())}


def calibration_comparison(runs, quality_passed):
    if not quality_passed:
        return {"emitted": False, "within_predeclared_tolerances": None,
                "reason": "qualification, workload, identity, native lifecycle or diagnostic evidence gate failed; all raw cell facts retained",
                "pooled": None, "temporal_pairs": None}
    cells = [run["cells"][0] for run in runs]
    pooled = compare(pool_cells([cells[0], cells[3]]), pool_cells([cells[1], cells[2]]), GATES["pooled"])
    pairs = [
        {"off_run": 1, "on_run": 2, "chronological_direction": "off then on",
         **compare(pool_cells([cells[0]]), pool_cells([cells[1]]), GATES["each_temporal_pair"])},
        {"off_run": 4, "on_run": 3, "chronological_direction": "on then off",
         **compare(pool_cells([cells[3]]), pool_cells([cells[2]]), GATES["each_temporal_pair"])},
    ]
    def sign(value):
        return (value > 0) - (value < 0) if value is not None else None
    direction = {key: sign(pairs[0]["on_relative_to_off"][key]) == sign(pairs[1]["on_relative_to_off"][key]) for key in pooled["on_relative_to_off"]}
    passed = pooled["within_predeclared_tolerances"] and all(pair["within_predeclared_tolerances"] for pair in pairs)
    return {"emitted": True, "within_predeclared_tolerances": passed, "pooled": pooled, "temporal_pairs": pairs,
            "temporal_pair_directions_agree": direction,
            "pair_direction_disagreement_is_descriptive_not_a_new_posthoc_gate": True,
            "scope": "same actual D2 binary, enabled versus disabled only; disabled hooks versus production A23 not measured",
            "interpretation": "within exploratory tolerances for this calibration, not proof of zero perturbation" if passed else
                              "instrumentation cost or calibration instability exceeds predeclared tolerances; no unperturbed-hotspot extrapolation"}


def review_qualification(args):
    issues = []
    report, binding = payload(args.qualification, args.qualification_sha256, issues)
    source_map, source_binding = payload(args.source_map, SOURCE_MAP_FILE_SHA, issues)
    check(sha(canonical(source_map)) == SOURCE_MAP_CANONICAL_SHA and len(source_map) == 151, issues, "r02 expected source map differs")
    check(report.get("schema") == "runtime-candidate-qualification/v1" and report.get("qualified") is True, issues, "actual qualification is not a pass")
    check(report.get("binary", {}).get("sha256") == args.binary_sha256, issues, "qualification binary SHA differs")
    check(report.get("source_tested") == source_map and report.get("source_after") == source_map, issues, "actual tested/after source map differs from all 151 r02 files")
    stages = report.get("stages", [])
    required = {"format", "fmt-check", "clippy", "test", "release"}
    names = collections.Counter(s.get("name") for s in stages)
    check(all(names[name] == 1 for name in required)
          and all(type(s.get("returncode")) is int and s["returncode"] == 0 for s in stages),
          issues, "qualification stages missing, duplicated, invalid or failed")
    local_map = {}
    for relative in source_map:
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts:
            issues.append("source map contains unsafe relative path")
            continue
        local_map[relative] = sha((Path(args.source_directory) / path).read_bytes())
    check(local_map == source_map, issues, "local formatted source tree differs")
    return {"valid": not issues, "issues": issues, "raw_binding": binding,
            "source_map_binding": source_binding, "source_map_canonical_sha256": sha(canonical(source_map)),
            "qualified_binary_sha256": report.get("binary", {}).get("sha256"), "source_files_rehashed": len(local_map),
            "stages": [{k: s[k] for k in ("name", "returncode", "log_sha256", "results") if k in s} for s in stages]}


def leading_categories(profile):
    categories = profile["file_categories_inclusive"]
    maximum = max((item["inclusive_cpu_ns"] for item in categories), default=0)
    return [item["category"] for item in categories if item["inclusive_cpu_ns"] == maximum] if maximum > 0 else []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--qualification-sha256", required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--source-map", type=Path, required=True)
    parser.add_argument("--source-directory", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--driver-sha256", required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--run", nargs=4, action="append", required=True, metavar=("MODE", "REPORT", "RAW_SHA", "STDERR_ROOT"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise FileExistsError("create-only output already exists")
    if len(args.run) != 4 or [r[0] for r in args.run] != ["off", "on", "on", "off"]:
        raise ValueError("exactly four explicit off/on/on/off actual raw inputs are required")
    if not all(is_sha(value) for value in [args.qualification_sha256, args.binary_sha256, args.driver_sha256] + [r[2] for r in args.run]):
        raise ValueError("actual input identity must be a lowercase SHA-256, never a placeholder")
    if sha(args.driver.read_bytes()) != args.driver_sha256:
        raise ValueError("explicit measured D2 driver SHA differs")
    spec = importlib.util.spec_from_file_location("frozen_d2_stderr_verifier", args.driver)
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    qualification = review_qualification(args)
    runs = [review_run(item, args.binary_sha256, driver, args.driver_sha256) for item in args.run]
    cross_issues = []
    check(len({run.get("raw_binding", {}).get("sha256") for run in runs}) == 4, cross_issues, "four raw inputs are not distinct")
    check(len({run.get("originals_receipt_sha256") for run in runs}) == 1 and runs[0].get("originals_receipt_sha256") is not None, cross_issues, "original jobs differ between runs or are missing")
    check(len({run.get("profile_receipt", {}).get("template_sha256") for run in runs}) == 1 and runs[0].get("profile_receipt", {}).get("template_sha256") is not None, cross_issues, "profile template differs between runs or is missing")
    for previous, current in zip(runs, runs[1:]):
        check(finite(previous.get("finished_unix"), True) and finite(current.get("started_unix"), True)
              and current["started_unix"] >= previous["finished_unix"], cross_issues, "runs not serial in declared order or wall-clock evidence missing")
    combined_dtos = collections.defaultdict(set)
    for run in runs:
        for item in run.get("dto_receipts", []):
            combined_dtos[(item["host"], item["tool"])].update(item["hashes"])
    check(len(combined_dtos) == 12 and all(len(values) == 1 for values in combined_dtos.values()), cross_issues, "successful host/tool DTOs differ across runs or are missing")
    quality = qualification["valid"] and not cross_issues and all(run["quality_passed"] for run in runs)
    comparison = calibration_comparison(runs, quality)
    qualified_phase_description = None
    if quality and comparison["within_predeclared_tolerances"]:
        qualified_phase_description = {}
        for role in ("first", "restart"):
            summaries = [next(c for c in run["diagnostics"]["controllers"] if c["controller_role"] == role)["raw_diagnostic"]["summary"]
                         for run in runs if run["mode"] == "on"]
            profiles = [phase_profile([summary]) for summary in summaries]
            leaders = [leading_categories(profile) for profile in profiles]
            qualified_phase_description[role] = {"per_on_controller": profiles, "pooled_same_role": phase_profile(summaries),
                "leading_measured_file_categories_per_on_controller": leaders,
                "same_unique_measured_file_category_leads_in_both": all(len(items) == 1 for items in leaders) and leaders[0] == leaders[1],
                "zero_cost_or_tied_categories_are_not_a_unique_observed_leader": True,
                "production_hotspot_proven": False,
                "interpretation": "description of measured owner lifetimes under enabled D2; no timed-cell phase allocation or uninstrumented extrapolation"}
    result = {
        "schema": "hepta-x230-d2-independent-calibration-review/v1",
        "analysis_only": True, "actual_remote_work_performed_by_helper": False,
        "helper": {"file": Path(__file__).name, "sha256": sha(Path(__file__).read_bytes())},
        "protocol": {"file": args.protocol.name, "sha256": sha(args.protocol.read_bytes())},
        "driver_sha256": args.driver_sha256, "predeclared_gates": GATES,
        "qualification": qualification, "runs_in_off_on_on_off_order": runs,
        "cross_run_issues": cross_issues, "all_quality_gates_passed": quality,
        "instrumentation_comparison": comparison,
        "qualified_phase_description": qualified_phase_description,
        "whole_controller_or_timed_cell_cpu_attribution_from_owner_counters": None,
        "agent_cpu_attribution": None, "hash_only_hotspot_claim": None,
        "scope_limits": [
            "raw inputs and failed cells are preserved; no replacement or success filtering",
            "first and restart owner lifetimes remain separate",
            "same ongoing forwarded-agent session and absence of concurrent builds are operator conditions, not independently attested by report timestamps",
            "sampling errors and resource lower bounds retained; no RSS/FD time-series, stable-level, or per-window CPU claim",
            "off summaries are intentionally absent; missing stderr or on summaries are invalid evidence, never zero cost",
            "two temporal pairs support a descriptive calibration only",
        ],
    }
    data = json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False).encode() + b"\n"
    with args.out.open("xb") as stream:
        stream.write(data)
    print(json.dumps({"output": str(args.out), "bytes": len(data), "sha256": sha(data),
                      "all_quality_gates_passed": quality,
                      "calibration_within_tolerances": comparison["within_predeclared_tolerances"]}))
    return 0 if quality and comparison["within_predeclared_tolerances"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
