#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create-only public evidence for the x230 8-head/2-tail fairness schema.

All waves, calls and failures are retained. A same-binary smoke is a pipeline
check; it never emits a performance comparison. This helper does not run a
controller, contact a host or decide whether a scheduler should be adopted.

Version 4 preserves the v3 arithmetic, evidence gates and qualified-registry
checks. It pins the actual A20/A21/A22/A23 originals and permits an A20/A24 run only
after a distinct original A24 qualification report and registry are available.
"""
import argparse
from collections import Counter
import json
import math
import os
from pathlib import Path
import re
import sys

import build_x230_evidence as core

CORE_SHA256 = "d868f8aab6db0b8d35fd38116241355660758a1e4b336b64cda3f7b945ffa4fb"
SCHEMA = "hepta-x230-readonly-observation-fairness/v1"
CELLS = ("balanced", "hot_only", "skew")
REGISTRY_SCHEMA = "hepta-x230-fairness-qualified-binaries/v1"
QUALIFICATION_SCHEMA = "runtime-candidate-qualification/v1"
PROVENANCE_FIELDS = {"label", "binary_sha256", "source_map_sha256", "source_file_count", "qualification_report_sha256"}
KNOWN_QUALIFIED = {
    "A20": {"label": "A20", "binary_sha256": "727c4661450fdb2a2a44b63f7f9442a5cd20ad854f1c26b043ac710b6fa2ea06",
            "source_map_sha256": "ad734d2154e5e329467ba3d4c0f48d415ae3c4594a490a7aa1c7721ae780d8bc",
            "source_file_count": 149,
            "qualification_report_sha256": "35ccff9730cf28330e9f3d646f04cd12d0b66ec5d457b9039d8d94b34a359461"},
    "A21": {"label": "A21", "binary_sha256": "626d338edd36075fc4cfb6f6215b34dc07dad50dde34c674fce8015afa8f2922",
            "source_map_sha256": "8459c942fae11a15c39902185859e6402f49f00093ff9f9a663b199ff38b3d62",
            "source_file_count": 149,
            "qualification_report_sha256": "4e888fc9f17127b197a009232241486f3f2479586ef1fa1bff6e0030127e6e7a"},
    "A22": {"label": "A22", "binary_sha256": "f57b6bf92012de15b2ffe81daedcc69688c65f3b6c63b67c95d486664de6d076",
            "source_map_sha256": "dcc6197816f1d36b515626390f128b6826abd47da30710ab4917ca418ef5c29c",
            "source_file_count": 149,
            "qualification_report_sha256": "356b87c027fb77444da3fcabe318b88c4b520873fb4def487d0359cec4863703"},
    "A23": {"label": "A23", "binary_sha256": "64416b53b63ffe7eac05b4d9eb6750092279b5f6e25dbad5a8cfd31067d206a1",
            "source_map_sha256": "5cf2e5cf8fca60e845a2c8f997abfc28017085bc809086a3ddb42448569a2b4f",
            "source_file_count": 149,
            "qualification_report_sha256": "f0758bbab9cd767b4601dec9236959a18766673e87e985729a741f8ccbde3584"},
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def source_map_sha256(source):
    # The qualification source-map receipt excludes a trailing newline.
    return core.sha(json.dumps(source, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode())


def qualified_provenance(report, baseline, candidate, mode, registry_path, baseline_qualification, candidate_qualification):
    require(registry_path is not None and baseline_qualification is not None and candidate_qualification is not None,
            "v4 requires the qualified-version registry and both original qualification reports")
    require(baseline in {"A20", "A21", "A22", "A23", "A24"} and candidate in {"A20", "A21", "A22", "A23", "A24"}, "unsupported version label")
    require((mode == "comparison" and baseline == "A20" and candidate in {"A21", "A22", "A23", "A24"})
            or (mode == "smoke" and baseline == candidate), "version labels do not match the explicit experiment mode")
    registry_raw = registry_path.read_bytes()
    registry = json.loads(registry_raw)
    require(isinstance(registry, dict) and set(registry) == {"schema", "versions"}
            and registry["schema"] == REGISTRY_SCHEMA, "invalid qualified-version registry schema")
    versions = registry.get("versions")
    require(isinstance(versions, dict) and versions and set(versions).issubset({"A20", "A21", "A22", "A23", "A24"}),
            "qualified-version registry contains unknown labels")
    require(set((baseline, candidate)).issubset(versions), "registry is missing a requested version")
    for label, entry in versions.items():
        require(isinstance(entry, dict) and set(entry) == PROVENANCE_FIELDS and entry.get("label") == label,
                "qualified-version entry has invalid fields or label")
        require(type(entry["source_file_count"]) is int and entry["source_file_count"] > 0, "invalid source file count")
        require(all(isinstance(entry[key], str) and re.fullmatch(r"[0-9a-f]{64}", entry[key])
                    for key in ("binary_sha256", "source_map_sha256", "qualification_report_sha256")),
                "qualified-version entry contains an invalid hash")
        if label in KNOWN_QUALIFIED:
            require(entry == KNOWN_QUALIFIED[label], "known qualified version has been relabeled or replaced")
        else:
            require(all(entry[key] != known[key] for known in KNOWN_QUALIFIED.values()
                        for key in ("binary_sha256", "source_map_sha256", "qualification_report_sha256")),
                    "A24 cannot relabel a known A20/A21/A22/A23 binary, source map or qualification report")
    require(len({entry["binary_sha256"] for entry in versions.values()}) == len(versions),
            "different version labels cannot share a binary")
    bindings = {}
    for code, label, path in (("A", baseline, baseline_qualification), ("B", candidate, candidate_qualification)):
        entry = versions[label]
        qualification_raw = path.read_bytes()
        require(core.sha(qualification_raw) == entry["qualification_report_sha256"], "qualification report hash differs from registry")
        qualification = json.loads(qualification_raw)
        require(qualification.get("schema") == QUALIFICATION_SCHEMA and qualification.get("qualified") is True,
                "qualification did not pass the expected qualification schema")
        stages = qualification.get("stages", [])
        require(isinstance(stages, list) and all(isinstance(stage, dict) for stage in stages)
                and Counter(stage.get("name") for stage in stages) == Counter(("format", "fmt-check", "clippy", "test", "release"))
                and all(type(stage.get("returncode")) is int and stage["returncode"] == 0 for stage in stages),
                "qualification stages are missing, duplicated or unsuccessful")
        source = qualification.get("source_tested")
        require(isinstance(source, dict) and len(source) == entry["source_file_count"]
                and all(isinstance(name, str) and isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                        for name, value in source.items()), "qualified source map is incomplete or malformed")
        require(qualification.get("source_after") == source, "source changed after qualification")
        require(source_map_sha256(source) == entry["source_map_sha256"], "qualified source map hash differs from registry")
        require(qualification.get("binary", {}).get("sha256") == entry["binary_sha256"], "qualified binary differs from registry")
        require(report.get("binary_sha256", {}).get(code) == entry["binary_sha256"], "measured binary differs from qualified version")
        bindings[code] = {**entry, "report_binary_matches_qualification": True,
                          "qualification_report_hash_locally_verified": True,
                          "source_tested_map_matches_registry_and_after": True,
                          "qualification_stage_returncodes": {stage["name"]: stage["returncode"] for stage in stages},
                          "binary_bytes_rehashed_locally": False,
                          "source_files_rehashed_locally": False}
    return {"registry_schema": REGISTRY_SCHEMA, "registry_sha256": core.sha(registry_raw),
            "versions": bindings,
            "meaning": "Explicit version labels bind the exact original qualification report, its tested source map and binary SHA, and the measured binary receipt. Qualification report bytes are read locally; executable/source bytes are not rehashed by this helper."}


def flatten(cells):
    return [{**cell, "rows": [row for wave in cell.get("waves", []) for row in wave.get("rows", [])]}
            for cell in cells]


def quantiles(values):
    complete = bool(values) and all(core.numeric(value) for value in values)
    ordered = sorted(values) if complete else []
    result = {"count": len(values), "complete": complete, "max": max(ordered) if ordered else None}
    for percentile in (50, 95, 99):
        result[f"p{percentile}"] = ordered[(len(ordered) * percentile + 99) // 100 - 1] if ordered else None
    return result


def failure_counts(rows):
    return {"successes": sum(row.get("okay") is True for row in rows),
            "failures": sum(row.get("okay") is not True for row in rows),
            "native_is_error_count": sum(row.get("isError") is True for row in rows),
            "rpc_error_count": sum("rpc_error" in row for row in rows),
            "refusal_response_count": sum(row.get("isError") is True or "rpc_error" in row
                                          or "full_refusal_response" in row for row in rows),
            "client_timeout_count": sum(row.get("error_type") in {"Empty", "TimeoutError"} for row in rows)}


def row_group(rows, seconds, clean):
    latency = quantiles([row.get("elapsed_ms") for row in rows])
    counts = failure_counts(rows)
    return {"calls": len(rows), **counts, "elapsed_complete_cell_seconds_sum": seconds,
            "completion_rps": len(rows) / seconds if seconds else None,
            "successful_rps": counts["successes"] / seconds if seconds else None,
            **{f"{key}_ms": latency[key] for key in ("p50", "p95", "p99", "max")},
            "latency_complete": latency["complete"], "latency_includes_failed_calls": True,
            "counts_by_host_alias": dict(sorted(Counter(row.get("host", "<missing>") for row in rows).items())),
            "counts_by_tool": dict(sorted(Counter(row.get("tool", "<missing>") for row in rows).items())),
            "errors": [clean(row) for row in rows if row.get("okay") is not True],
            "role_cpu_attribution_available": False}


def aggregate(cells, clean):
    flat = flatten(cells)
    total = core.aggregate(flat, clean)
    waves = [wave for cell in cells for wave in cell.get("waves", [])]
    rows = [row for cell in flat for row in cell["rows"]]
    metadata = [item for wave in waves for item in wave.get("metadata_observations", [])]
    total.update(failure_counts(rows))
    total.update(waves=len(waves), gate_passes=sum(wave.get("gate_passed") is True for wave in waves),
                 gate_failures=sum(wave.get("gate_passed") is not True for wave in waves),
                 independent_gate_validation_failure_count=sum(not gate_receipt_valid(wave) for wave in waves),
                 missing_gate_verdicts=sum("gate_passed" not in wave for wave in waves),
                 incomplete_final_history_count=sum(wave.get("final_metadata_consistent") is not True for wave in waves),
                 independent_final_history_validation_failure_count=sum(not final_history_valid(wave) for wave in waves),
                 noncompleted_final_history_count=sum(wave.get("all_final_metadata_completed") is not True for wave in waves),
                 independent_noncompleted_final_history_count=sum(final_history_completed(wave) is not True for wave in waves),
                 metadata_query_count=len(metadata), metadata_query_failures=sum(item.get("okay") is not True for item in metadata),
                 tail_calls_submitted_sum=sum(wave.get("tail_calls_submitted", 0) for wave in waves),
                 tail_not_fully_submitted_wave_count=sum(wave.get("tail_calls_submitted") != 2 for wave in waves),
                 gate_elapsed_ms=quantiles([wave.get("gate_elapsed_ms") for wave in waves]),
                 accepted_snapshot_to_first_tail_start_ms=quantiles([wave.get("accepted_snapshot_to_first_tail_start_ms") for wave in waves]),
                 all_failed_wave_indices=[{"cell_offset": ci, "wave_offset": wi, "wave_index": wave.get("index")}
                                          for ci, cell in enumerate(cells) for wi, wave in enumerate(cell.get("waves", []))
                                          if wave.get("passed") is not True])
    seconds = total["elapsed_cell_seconds_sum"]
    total["head"] = row_group([row for row in rows if row.get("role") == "head"], seconds, clean)
    total["tail"] = row_group([row for row in rows if row.get("role") == "tail"], seconds, clean)
    total["unclassified_role"] = row_group([row for row in rows if row.get("role") not in {"head", "tail"}], seconds, clean)
    total["response_sizes"] = {"recorded_calls": sum(core.numeric(row.get("canonical_response_json_bytes")) for row in rows),
                               "max_canonical_response_json_bytes": max((row["canonical_response_json_bytes"] for row in rows
                                                                        if core.numeric(row.get("canonical_response_json_bytes"))), default=None),
                               "meaning": "Observed serialized response sizes, not a native retained-buffer peak."}
    return total


def row_shape_issues(cell, expected_waves):
    issues = []
    waves = cell.get("waves", [])
    if len(waves) != expected_waves:
        issues.append("wave count differs from requested waves_per_cell")
    if [wave.get("index") for wave in waves] != list(range(expected_waves)):
        issues.append("wave indices are missing, duplicated or reordered")
    for index, wave in enumerate(waves):
        rows = wave.get("rows", [])
        ordinals = [row.get("ordinal") for row in rows]
        if len(rows) != 10 or Counter(ordinals) != Counter(range(10)):
            issues.append(f"wave {index}: expected exactly ten distinct call ordinals")
        if sum(row.get("role") == "head" for row in rows) != 8 or sum(row.get("role") == "tail" for row in rows) != 2:
            issues.append(f"wave {index}: expected eight head and two tail rows")
        if any(row.get("role") != ("head" if row.get("ordinal", 10) < 8 else "tail") for row in rows
               if type(row.get("ordinal")) is int):
            issues.append(f"wave {index}: role differs from call ordinal")
        if wave.get("tail_calls_submitted") != 2 or wave.get("tail_attempted") is not True:
            issues.append(f"wave {index}: two tail attempts were not confirmed")
        if any(not core.numeric(row.get("elapsed_ms")) for row in rows):
            issues.append(f"wave {index}: at least one call latency is missing or invalid")
    return issues


def gate_receipt_valid(wave):
    receipt = wave.get("gate_snapshot", {})
    ids = receipt.get("request_ids", [])
    snapshots = [item for item in wave.get("metadata_observations", [])
                 if str(item.get("purpose", "")).endswith(":admission_snapshot")]
    if not snapshots:
        return False
    snapshot = snapshots[-1]
    records = snapshot.get("requests", [])
    rows = wave.get("rows", [])
    heads = [row for row in rows if row.get("role") == "head"]
    tails = [row for row in rows if row.get("role") == "tail"]
    if (len(heads) != 8 or len(tails) != 2
            or not all(core.numeric(row.get("start_monotonic")) and core.numeric(row.get("elapsed_ms")) for row in rows)
            or not core.numeric(snapshot.get("snapshot_return_monotonic"))
            or not core.numeric(wave.get("tail_submission_monotonic"))):
        return False
    tail_start = min(row["start_monotonic"] for row in tails)
    snapshot_time = snapshot["snapshot_return_monotonic"]
    observed_gap = (tail_start - snapshot_time) * 1000
    return (wave.get("gate_passed") is True and receipt.get("metadata_query_okay") is True
            and receipt.get("native_admitted_count") == receipt.get("native_accepted_count")
            == receipt.get("head_futures_unfinished") == 8
            and receipt.get("head_tool_counts_match") is True
            and isinstance(ids, list) and len(ids) == len(set(ids)) == 8
            and snapshot.get("okay") is True and len(records) == 8
            and all(item.get("state") == "accepted" for item in records)
            and {item.get("request_id") for item in records} == set(ids)
            and Counter(item.get("tool_name") for item in records) == Counter(row.get("tool") for row in heads)
            and receipt.get("snapshot_return_monotonic") == snapshot_time
            and snapshot_time <= wave["tail_submission_monotonic"] <= tail_start
            and all(row["start_monotonic"] + row["elapsed_ms"] / 1000 > tail_start for row in heads)
            and wave.get("head_unfinished_at_tail_submission") == 8
            and wave.get("head_calls_completed_before_first_tail_start") == 0
            and core.numeric(wave.get("accepted_snapshot_to_first_tail_start_ms"))
            and math.isclose(wave["accepted_snapshot_to_first_tail_start_ms"], observed_gap, rel_tol=1e-9, abs_tol=1e-6))


def final_history_valid(wave):
    snapshots = [item for item in wave.get("metadata_observations", [])
                 if str(item.get("purpose", "")).endswith(":completed_metadata")]
    if len(snapshots) != 1 or snapshots[0].get("okay") is not True:
        return False
    records = snapshots[0].get("requests", [])
    rows = wave.get("rows", [])
    return (wave.get("final_metadata_consistent") is True and len(records) == 10
            and len({item.get("request_id") for item in records}) == 10
            and all(item.get("state") in {"completed", "failed", "unknown"} for item in records)
            and Counter(item.get("tool_name") for item in records) == Counter(row.get("tool") for row in rows))


def final_history_completed(wave):
    if not final_history_valid(wave):
        return None
    snapshot = next(item for item in wave["metadata_observations"]
                    if str(item.get("purpose", "")).endswith(":completed_metadata"))
    return all(item["state"] == "completed" for item in snapshot["requests"])


def history_chain_issues(round_):
    initial = round_.get("metadata_observations", [])
    if (len(initial) != 1 or initial[0].get("okay") is not True or initial[0].get("after_id") is not None
            or initial[0].get("purpose") != "initial_cursor_after_warmup"):
        return ["initial metadata cursor receipt incomplete"]
    records = initial[0].get("requests", [])
    if (len(records) != 6 or len({item.get("request_id") for item in records}) != 6
            or any(item.get("state") != "completed" or item.get("tool_name") != "process_read" for item in records)):
        return ["initial metadata does not bind exactly six completed read warmups"]
    seen = {item["request_id"] for item in records}
    cursor = records[-1]["request_id"]
    issues = []
    for cell in round_.get("cells", []):
        for wave in cell.get("waves", []):
            prefix = f"{cell.get('name')} wave {wave.get('index')}: "
            snapshots = wave.get("metadata_observations", [])
            if not snapshots or any(item.get("after_id") != cursor for item in snapshots):
                issues.append(prefix + "metadata cursor differs from the preceding completed wave")
            final = [item for item in snapshots if str(item.get("purpose", "")).endswith(":completed_metadata")]
            if len(final) != 1 or not final_history_valid(wave):
                issues.append(prefix + "cannot advance a verified final metadata cursor")
                break
            records = final[0]["requests"]
            ids = {item["request_id"] for item in records}
            if ids & seen:
                issues.append(prefix + "dispatch identity was reused across separate waves")
            if not set(wave.get("gate_snapshot", {}).get("request_ids", [])).issubset(ids):
                issues.append(prefix + "accepted snapshot identity absent from this wave's final history")
            seen.update(ids)
            cursor = records[-1]["request_id"]
    return issues


def plan_issues(cell, originals):
    by_host = {item.get("host"): item.get("job_id") for item in originals}
    hosts = sorted(by_host)
    if len(hosts) != 6:
        return ["original fixture does not identify six hosts"]
    issues = []
    for wave in cell.get("waves", []):
        for row in wave.get("rows", []):
            index, ordinal = wave.get("index"), row.get("ordinal")
            if type(index) is not int or type(ordinal) is not int or not 0 <= ordinal < 10:
                continue
            if cell.get("name") == "balanced":
                serial = index * 10 + ordinal
                host = hosts[serial % 6]
                tool = "process_status" if (serial // 6) % 2 == 0 else "process_read"
            elif cell.get("name") == "hot_only" or ordinal < 8:
                host, tool = "mac", "process_status"
            else:
                host, tool = "ai395", "process_read"
            if (row.get("host"), row.get("tool"), row.get("job_id")) != (host, tool, by_host.get(host)):
                issues.append(f"wave {index} call {ordinal}: original-job host/tool plan differs")
    return issues


def summarize_version(report, code, label, clean):
    rounds = [item for item in report.get("rounds", []) if item.get("version") == code]
    cells = [cell for item in rounds for cell in item.get("cells", [])]
    order = list(report.get("order", ""))
    expected_rounds = order.count(code)
    expected_waves = report.get("waves_per_cell")
    incomplete, failed = [], []
    if [item.get("index") for item in report.get("rounds", [])] != list(range(len(order))):
        incomplete.append("round indices must be continuous and equal their positions in the requested order")
    if len(rounds) != expected_rounds:
        incomplete.append("recorded round count differs from requested order")
    if type(expected_waves) is not int or not 1 <= expected_waves <= 8:
        incomplete.append("waves_per_cell is missing or outside the harness bound")
        expected_waves = 0
    for item in rounds:
        prefix = f"round {item.get('index')}: "
        if Counter(cell.get("name") for cell in item.get("cells", [])) != Counter(CELLS):
            incomplete.append(prefix + "expected one of each balanced/hot_only/skew cell")
        expected_cell_order = list(CELLS if item.get("index", 0) % 2 == 0 else reversed(CELLS))
        if item.get("cell_order") != expected_cell_order or [cell.get("name") for cell in item.get("cells", [])] != expected_cell_order:
            incomplete.append(prefix + "cell ordering does not match the counterbalanced plan")
        incomplete.extend(prefix + issue for issue in history_chain_issues(item))
        if item.get("passed") is not True:
            failed.append(prefix + "raw round did not pass")
        if not isinstance(item.get("startup"), dict):
            incomplete.append(prefix + "startup receipt missing")
        for name in ("initial_complete_outputs", "final_complete_outputs"):
            rows = item.get(name, [])
            if len(rows) != 6 or {row.get("host") for row in rows} != {job.get("host") for job in report.get("six_originals", [])}:
                incomplete.append(prefix + name + " does not cover all six originals exactly once")
            if any(row.get("okay") is not True for row in rows):
                failed.append(prefix + name + " contains a failed check")
        shutdown = core.normal_shutdown(item.get("shutdown"))
        if shutdown is None:
            incomplete.append(prefix + "shutdown receipt incomplete")
        elif not shutdown:
            failed.append(prefix + "controller shutdown did not confirm clean EOF and no observed survivors")
        if item.get("private_originals_unchanged") is not True:
            failed.append(prefix + "private original metadata immutability not confirmed")
        for cell in item.get("cells", []):
            incomplete.extend(prefix + str(cell.get("name")) + ": " + issue for issue in row_shape_issues(cell, expected_waves))
            incomplete.extend(prefix + str(cell.get("name")) + ": " + issue for issue in plan_issues(cell, report.get("six_originals", [])))
            if cell.get("passed") is not True:
                failed.append(prefix + str(cell.get("name")) + ": raw cell did not pass")
            for wave in cell.get("waves", []):
                actual_completed = final_history_completed(wave)
                if wave.get("all_final_metadata_completed") is not actual_completed:
                    incomplete.append(prefix + f"{cell.get('name')} wave {wave.get('index')}: completed-history boolean differs from actual final records")
                if wave.get("passed") is not True or actual_completed is not True:
                    failed.append(prefix + f"{cell.get('name')} wave {wave.get('index')}: raw wave or completed metadata verdict did not pass")
                if not gate_receipt_valid(wave):
                    failed.append(prefix + f"{cell.get('name')} wave {wave.get('index')}: native admission gate not verified")
                if not final_history_valid(wave):
                    incomplete.append(prefix + f"{cell.get('name')} wave {wave.get('index')}: final metadata is incomplete or inconsistent")
                if any(row.get("okay") is not True for row in wave.get("rows", [])):
                    failed.append(prefix + f"{cell.get('name')} wave {wave.get('index')}: original-job observation failed")
                if any(row.get("okay") is not True for row in wave.get("metadata_observations", [])):
                    failed.append(prefix + f"{cell.get('name')} wave {wave.get('index')}: metadata observation failed")
    aggregate_all = aggregate(cells, clean)
    if aggregate_all["integrity_issues"]:
        incomplete.append("aggregate count, cell elapsed time or CPU coverage is inconsistent/incomplete")
    common = {key: report.get(key) for key in ("source_originals_unchanged", "private_originals_unchanged",
                                              "binary_hashes_unchanged", "current_agent_unchanged")}
    if expected_rounds or rounds:
        passed = bool(rounds) and not incomplete and not failed and all(value is True for value in common.values())
        status = "passed" if passed else "incomplete" if incomplete else "failed"
    else:
        passed, status = None, "not_run"
    return {"code": code, "label": label, "passed": passed, "status": status,
            "requested_rounds": expected_rounds, "recorded_rounds": len(rounds),
            "raw_round_passed": [item.get("passed") for item in rounds], "common_immutability_fences": common,
            "incomplete_reasons": incomplete, "failure_reasons": failed,
            "by_cell": {name: aggregate([cell for cell in cells if cell.get("name") == name], clean) for name in CELLS},
            "all_serial_cells": aggregate_all,
            "controller_resources": core.sampling_summary([item.get("shutdown", {}).get("resources") for item in rounds], clean)}


def build(report, raw, baseline, candidate, mode, harness=None, base_driver=None,
          registry_path=None, baseline_qualification=None, candidate_qualification=None):
    core_bytes = Path(core.__file__).read_bytes()
    require(core.sha(core_bytes) == CORE_SHA256, "the pinned evidence sanitizer/helper changed")
    require(report.get("schema") == SCHEMA, "input is not the frozen fairness report schema")
    require(mode in {"smoke", "comparison"}, "mode must explicitly identify smoke or comparison")
    provenance = qualified_provenance(report, baseline, candidate, mode, registry_path,
                                      baseline_qualification, candidate_qualification)
    clean = core.Sanitizer(report)
    versions = {code: summarize_version(report, code, label, clean) for code, label in (('A', baseline), ('B', candidate))}
    binding = {}
    for name, path, field in (("fairness_harness", harness, "fairness_harness_sha256"),
                              ("base_driver", base_driver, "driver_sha256")):
        actual = core.sha(path.read_bytes()) if path else None
        binding[name] = {"reported_sha256": report.get(field), "locally_read_sha256": actual,
                         "locally_verified": actual == report.get(field) if path else None}
        if path:
            require(binding[name]["locally_verified"] is True, name + " differs from the measured original")
    rounds = report.get("rounds", [])
    strict_order = report.get("order") == "ABBA" and [item.get("version") for item in rounds] == list("ABBA")
    indices_valid = [item.get("index") for item in rounds] == list(range(len(report.get("order", ""))))
    shape = all(versions[code]["recorded_rounds"] == 2
                and all(versions[code]["by_cell"][name]["waves"] == 16
                        and versions[code]["by_cell"][name]["calls"] == 160
                        and versions[code]["by_cell"][name]["head"]["calls"] == 128
                        and versions[code]["by_cell"][name]["tail"]["calls"] == 32 for name in CELLS)
                for code in ("A", "B"))
    all_waves = [wave for item in rounds for cell in item.get("cells", []) for wave in cell.get("waves", [])]
    gates_valid = bool(all_waves) and all(gate_receipt_valid(wave) for wave in all_waves)
    histories_valid = bool(all_waves) and all(final_history_valid(wave) for wave in all_waves)
    cold_verified = all(versions[code]["by_cell"]["skew"]["tail"]["calls"] == 32
                        and versions[code]["by_cell"]["skew"]["tail"]["counts_by_host_alias"] == {"ai395": 32}
                        and versions[code]["by_cell"]["skew"]["tail"]["counts_by_tool"] == {"process_read": 32}
                        for code in ("A", "B"))
    binary_hashes = report.get("binary_sha256", {})
    qualified_shape = {"explicit_comparison_mode": mode == "comparison",
                       "labels_are_A20_then_qualified_A21_A22_A23_or_A24": baseline == "A20" and candidate in {"A21", "A22", "A23", "A24"},
                       "both_versions_match_explicit_qualified_provenance": True,
                       "exact_ABBA_round_order": strict_order, "eight_waves_requested_per_cell": report.get("waves_per_cell") == 8,
                       "contiguous_original_round_indices_verified": indices_valid,
                       "exact_16_waves_160_rows_per_cell_per_version": shape,
                       "exact_32_cold_read_rows_per_version": cold_verified,
                       "all_native_admission_gates_verified": gates_valid, "all_final_histories_verified": histories_valid,
                       "no_incomplete_version_evidence": all(not value["incomplete_reasons"] for value in versions.values()),
                       "all_common_immutability_fences_confirmed": all(value is True for item in versions.values() for value in item["common_immutability_fences"].values()),
                       "both_measured_helper_hashes_locally_verified": all(value["locally_verified"] is True for value in binding.values()),
                       "two_distinct_binary_hashes_recorded": all(isinstance(binary_hashes.get(code), str) and re.fullmatch(r"[0-9a-f]{64}", binary_hashes[code]) for code in ("A", "B")) and binary_hashes.get("A") != binary_hashes.get("B")}
    eligible = all(qualified_shape.values())
    comparison = None
    if eligible:
        comparison = {}
        for name in CELLS:
            a, b = (versions[code]["by_cell"][name] for code in ("A", "B"))
            comparison[name] = {"completion_rps_change_percent": core.percentage(b["completion_rps"], a["completion_rps"]),
                                "successful_rps_change_percent": core.percentage(b["successful_rps"], a["successful_rps"]),
                                "all_call_p50_change_percent": core.percentage(b["p50_ms"], a["p50_ms"]),
                                "all_call_p95_change_percent": core.percentage(b["p95_ms"], a["p95_ms"]),
                                "head_p95_change_percent": core.percentage(b["head"]["p95_ms"], a["head"]["p95_ms"]),
                                "tail_p50_change_percent": core.percentage(b["tail"]["p50_ms"], a["tail"]["p50_ms"]),
                                "tail_p95_change_percent": core.percentage(b["tail"]["p95_ms"], a["tail"]["p95_ms"]),
                                "tail_p99_change_percent": core.percentage(b["tail"]["p99_ms"], a["tail"]["p99_ms"]),
                                "controller_cpu_per_call_change_percent": core.percentage(b["controller_cpu_ms_per_call"], a["controller_cpu_ms_per_call"]),
                                "baseline_failures": a["failures"], "candidate_failures": b["failures"],
                                "baseline_refusal_responses": a["refusal_response_count"], "candidate_refusal_responses": b["refusal_response_count"],
                                "baseline_client_timeouts": a["client_timeout_count"], "candidate_client_timeouts": b["client_timeout_count"]}
    expected = list(report.get("order", ""))
    measured_passed = (report.get("passed") is True and expected in [list("AB"), list("ABBA")]
                       and [item.get("version") for item in rounds] == expected
                       and all(versions[code]["passed"] is True for code in set(expected)))
    resources = [item.get("shutdown", {}).get("resources") for item in rounds]
    if isinstance(report.get("interrupted_shutdown"), dict):
        resources.append(report["interrupted_shutdown"].get("resources"))
    return {"schema": "hepta-x230-fairness-public-evidence/v4", "mode": mode,
            "interpretation": "pipeline_check_only_no_performance_benefit_claim" if mode == "smoke" else "bounded_fairness_experiment",
            "baseline": baseline, "candidate": candidate, "controller_host_alias": "x230",
            "raw_report_passed": report.get("passed"), "passed": measured_passed,
            "baseline_passed": versions["A"]["passed"], "candidate_passed": versions["B"]["passed"],
            "source_report_sha256": core.sha(raw), "source_report_bytes": len(raw),
            "aggregation_script_sha256": core.sha(Path(__file__).read_bytes()), "pinned_core_helper_sha256": CORE_SHA256,
            "qualified_version_provenance": provenance,
            "measured_helper_bindings": binding, "versions": versions,
            "comparison_requirements": qualified_shape, "performance_comparison_emitted": eligible,
            "performance_comparison": comparison, "adoption_decision": "not_inferred_by_evidence_builder",
            "all_recorded_controller_resources": core.sampling_summary(resources, clean),
            "report": clean(report),
            "method": {"aggregation": "Every retained wave and row is included. Count/sum(full cell seconds), never a mean of rates; cell time and CPU include metadata gates/final queries.",
                       "latency": "Nearest-rank p50/p95/p99 over all calls in the relevant role, including refusals/timeouts. Missing/invalid latency makes the full quantile unavailable; no successful-only subset.",
                       "role_rates": "Head and tail rates share the full elapsed cell denominator. CPU is attributed only to the whole cell, not allocated to a role.",
                       "refusals": "Counts native isError or RPC/error responses; this is not a claim that every error occurred at pool admission. Original error details and hashes remain in the report.",
                       "gate": "Recheck native accepted count/IDs/tool-count receipt, unfinished heads and post-hoc call timing. Native dispatch admission does not prove pool permits, SSH dispatch or remote execution admission.",
                       "resources": "100ms controller/process-tree lifetime samples, including warmup/shutdown. Lower bounds with every recorded sampling error; descendants are not classified as SSH-only.",
                       "smoke": "Same-binary and abbreviated smoke data are pipeline checks. No performance comparison is emitted in smoke mode.",
                       "comparison": "Requires explicitly qualified A20/A21, A20/A22, A20/A23 or A20/A24 ABBA, two rounds per version, sixteen waves/160 calls per cell/version, 32 verified cold read rows/version, complete gate/history receipts, immutable inputs and locally verified measured helper and qualification hashes.",
                       "failures": "A complete comparison may retain RPC failures; both versions' verdicts and all failure counts remain explicit. No adoption recommendation is inferred."},
            "limitations": ["This is a bounded six-host read-only observation experiment, not launch throughput or HTTP capacity.",
                            "A native accepted snapshot and later tail start do not observe pool permit acquisition directly.",
                            "Only 32 cold calls per version in a complete run; no confidence interval or universal fairness guarantee.",
                            "Response byte sizes are not retained-buffer occupancy measurements.",
                            "Unknown/failed/incomplete/gate-invalid evidence is preserved and cannot establish a fairness benefit."],
            "privacy": {"core_sanitizer_sha256": CORE_SHA256, "retained": ["all raw outcome rows", "all recorded sampling errors", "socket/survivor uncertainty", "opaque IDs/hashes", "host aliases"],
                        "redacted": ["private account and network identifiers", "actual controller hostname", "process identities", "private paths"]}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--mode", choices=("smoke", "comparison"), required=True)
    parser.add_argument("--harness", type=Path)
    parser.add_argument("--base-driver", type=Path)
    parser.add_argument("--registry", type=Path, required=True,
                        help="Explicit label-to-binary/source-map/qualification-report SHA registry")
    parser.add_argument("--baseline-qualification", type=Path, required=True)
    parser.add_argument("--candidate-qualification", type=Path, required=True)
    args = parser.parse_args()
    raw = args.input.read_bytes()
    result = build(json.loads(raw), raw, args.baseline, args.candidate, args.mode, args.harness, args.base_driver,
                   args.registry, args.baseline_qualification, args.candidate_qualification)
    encoded = core.canonical(result)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("xb") as output:
        output.write(encoded)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(args.output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps({"output": str(args.output), "sha256": core.sha(encoded), "bytes": len(encoded),
                      "mode": args.mode, "raw_report_passed": result["raw_report_passed"],
                      "passed": result["passed"], "baseline_passed": result["baseline_passed"],
                      "candidate_passed": result["candidate_passed"],
                      "performance_comparison_emitted": result["performance_comparison_emitted"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
