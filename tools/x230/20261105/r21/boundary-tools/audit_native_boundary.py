#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independently audit bounded bursts, exact error envelopes and recovery.

No producer imports. The frozen raw transport/resource auditor remains the
authority for every retained frame, request binding, success DTO and /proc trace.
Unknown errors make the diagnostic fail, even when their evidence is complete.
"""
import argparse
from collections import Counter
import hashlib
import importlib
import json
import math
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
NAMES = {"run_native_boundary.py", "audit_native_boundary.py", "test_native_boundary.py",
         "harness-freeze.json", "capacity-policy.json"}
CAPACITY_TEXT = "observation pool capacity unavailable; no fallback or automatic retry"
CLASSES = ("success", "capacity_rejection", "other_error")


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def percentile(values, fraction):
    return sorted(values)[math.ceil(len(values) * fraction) - 1]


def error_class(reply, policy):
    # No substring or guessed wrapping. An empty/unverified policy accepts no
    # capacity errors. JSON-RPC errors remain distinct from native tool errors.
    result = reply.get("result")
    if "error" not in reply and isinstance(result, dict) and result.get("isError") is True:
        parts = result.get("content")
        if policy["rendering_verified"] and isinstance(parts, list) and len(parts) == 1:
            text = parts[0].get("text") if isinstance(parts[0], dict) and parts[0].get("type") == "text" else None
            if any(rule == {"kind": "native_single_text", "text": text} for rule in policy["accepted_error_envelopes"]):
                return "capacity_rejection"
    return "other_error"


def audit_row(evidence, transport, row, original, policy, phase):
    need(row["tool"] in {"process_status", "process_read"} and row["job_id"] == original["job_id"]
         and row["automatic_retry"] is False and row["boundary_phase"] == phase,
         "unexpected effect/retry/identity/phase")
    if row["okay"] is True:
        need(row["classification"] == "success"
             and row["rpc"]["boundary_envelope_classification"] == "candidate_success", "successful row was relabelled")
        transport.call(row, original)
        return "success"
    need(row["okay"] is False and isinstance(row.get("reason"), str) and isinstance(row.get("error_type"), str),
         "failed row lacks its original local error record")
    arguments = {"host": row["host"], "job_id": row["job_id"]}
    if row["tool"] == "process_read":
        arguments.update(stdout_offset=0, stderr_offset=0, limit=16384)
    reply = transport.rpc(row["rpc"], "tools/call", {"name": row["tool"], "arguments": arguments})
    need(evidence.sha(evidence.canonical(reply)) == row["response_sha256"], "error response canonical hash differs")
    need(row["start_monotonic_ns"] <= row["rpc"]["rpc_start_monotonic_ns"]
         <= row["rpc"]["rpc_end_monotonic_ns"] <= row["end_monotonic_ns"], "error RPC/row clocks differ")
    evidence.near((row["end_monotonic_ns"] - row["start_monotonic_ns"]) / 1e6, row["elapsed_ms"], "error latency differs")
    classified = error_class(reply, policy)
    need(row["classification"] == classified, "error envelope classification differs")
    if "error" in reply:
        need(row.get("rpc_error") == reply["error"], "JSON-RPC error detail differs")
    elif isinstance(reply.get("result"), dict) and reply["result"].get("isError") is True:
        texts = [part.get("text", "") for part in reply["result"].get("content", []) if part.get("type") == "text"]
        need(row["isError"] is True and row["native_error"] == "\n".join(texts)[:2048], "native error detail differs")
    # A nominal envelope that failed local validation is conservatively an
    # other_error, never counted as either success or a proven capacity refusal.
    if classified == "capacity_rejection":
        need(row["rpc"]["boundary_envelope_classification"] == classified, "capacity envelope proof differs")
    return classified


def worker_environment(evidence, startup, first_call_start):
    value = startup["boundary_worker_environment"]
    raw = bytes.fromhex(value["selected_raw_hex"])
    need(raw == b"TOKIO_WORKER_THREADS=2\0" and sha(raw) == value["sha256"]
         and value["observed_workers"] == 2 and value["full_environment_retained"] is False
         and value["source"] == "same-PID/start-ticks /proc/PID/environ", "live worker environment differs")
    before, after = value["controller_before"], value["controller_after"]
    evidence.stat_counters(before)
    evidence.stat_counters(after)
    need((before["pid"], before["birth_ticks"]) == (after["pid"], after["birth_ticks"])
         == (startup["pid"], startup["birth_ticks"]), "worker environment PID generation differs")
    need(startup["ready_monotonic_ns"] <= before["read_start_monotonic_ns"]
         and before["read_end_monotonic_ns"] <= value["read_start_monotonic_ns"]
         <= value["read_end_monotonic_ns"] <= after["read_start_monotonic_ns"]
         and after["read_end_monotonic_ns"] <= first_call_start, "worker observation clock brackets differ")


def cell_metrics(evidence, cell, startup):
    evidence.inspect_timing(cell)
    before = cell["raw_timing"]["controller_before"]
    need((before["pid"], before["birth_ticks"]) == (startup["pid"], startup["birth_ticks"]), "cell used another controller")
    rows = cell["rows"]
    need(len(rows) == cell["calls"] and sum(row["okay"] is True for row in rows) == cell["successes"], "cell counts differ")
    for name, expected in (("completion_rps", len(rows) / cell["seconds"]),
                           ("successful_rps", cell["successes"] / cell["seconds"]),
                           ("controller_cpu_ms_per_call", 1000 * cell["controller_cpu_seconds"] / len(rows))):
        evidence.near(cell[name], expected, "cell metric differs: " + name)
    latencies = [row["elapsed_ms"] for row in rows]
    for name, fraction in (("p50_ms", .5), ("p95_ms", .95), ("p99_ms", .99)):
        evidence.near(cell[name], percentile(latencies, fraction), "overall attempt latency differs")
    evidence.near(cell["max_ms"], max(latencies), "overall max latency differs")
    need(cell["no_success_filtering"] is True, "attempts were success-filtered")


def audit_burst(evidence, transport, cell, originals, policy, startup, number):
    cell_metrics(evidence, cell, startup)
    need(cell["concurrency"] == cell["calls"] == 32 and cell["burst_index"] == number,
         "bounded C32 dimensions differ")
    need(cell["pool_admitted_identities_observed"] is None, "client concurrency was mistaken for pool admission")
    gate = cell["client_gate"]
    need(gate["parties"] == gate["arrivals"] == 32 and gate["timeout_seconds"] == 10
         and gate["atomic_network_dispatch_claimed"] is False, "client gate contract differs")
    seen, counts, latencies, events = set(), Counter(), {key: [] for key in CLASSES}, []
    hosts = sorted(originals)
    for slot, row in enumerate(cell["rows"]):
        need(row["burst_slot"] == slot and row["host"] == hosts[slot % 6]
             and row["tool"] == ("process_status" if (slot // 6) % 2 == 0 else "process_read"), "burst request plan differs")
        arrival = row["burst_gate"]
        need(arrival["burst"] == number and arrival["arrival_index"] not in seen
             and 0 <= arrival["arrival_index"] < 32, "burst gate arrival repeated/missing")
        seen.add(arrival["arrival_index"])
        need(cell["raw_timing"]["start_monotonic_ns"] <= arrival["ready_monotonic_ns"]
             <= arrival["gate_open_monotonic_ns"] == gate["opened_monotonic_ns"]
             <= arrival["released_monotonic_ns"] <= row["start_monotonic_ns"], "gate/row clock brackets differ")
        kind = audit_row(evidence, transport, row, originals[row["host"]], policy, f"burst-{number}")
        counts[kind] += 1
        latencies[kind].append(row["elapsed_ms"])
        events.extend(((row["rpc"]["rpc_start_monotonic_ns"], 1), (row["rpc"]["rpc_end_monotonic_ns"], -1)))
    need(set(cell["classified"]) == set(CLASSES), "classification group missing")
    for kind in CLASSES:
        values, summary = latencies[kind], cell["classified"][kind]
        need(summary["count"] == counts[kind], "classification count differs")
        evidence.near(summary["rate_per_second"], counts[kind] / cell["seconds"], "classification rate differs")
        if not values:
            need(summary["latency_ms"] is None, "empty error/success group has fabricated latency")
        else:
            for key, fraction in (("p50", .5), ("p95", .95), ("p99", .99)):
                evidence.near(summary["latency_ms"][key], percentile(values, fraction), "per-class latency differs")
            evidence.near(summary["latency_ms"]["max"], max(values), "per-class maximum differs")
    evidence.near(cell["controller_cpu_ms_per_attempt"], cell["controller_cpu_ms_per_call"], "CPU denominator changed")
    pending = peak = 0
    for _, change in sorted(events):
        pending += change
        need(pending >= 0, "client pending interval ordering differs")
        peak = max(peak, pending)
    need(pending == 0, "client RPC interval did not close")
    return {"burst": number, "counts": {key: counts[key] for key in CLASSES}, "classified": cell["classified"],
            "seconds": cell["seconds"], "controller_cpu_ms_per_attempt": cell["controller_cpu_ms_per_attempt"],
            "client_rpc_pending_peak": peak,
            "all_rpc_started_before_first_response": max(row["rpc"]["rpc_start_monotonic_ns"] for row in cell["rows"])
                 <= min(row["rpc"]["transport_response"]["received_monotonic_ns"] for row in cell["rows"]),
            "serialized_send_span_ms": (max(row["rpc"]["send_end_monotonic_ns"] for row in cell["rows"])
                                         - min(row["rpc"]["send_start_monotonic_ns"] for row in cell["rows"])) / 1e6,
            "pool_identity_peak": None}


def analyze(raw, directory, harness_root):
    pins = json.loads((HERE / "harness-freeze.json").read_bytes())
    need(pins["schema"] == "hepta-r16-boundary-harness-freeze/v1" and len(pins["files"]) == 12, "freeze identity differs")
    frozen = {name: sha((harness_root / name).read_bytes()) for name in pins["files"]}
    need(frozen == pins["files"], "frozen source changed")
    sys.path.insert(0, str(harness_root))
    evidence = importlib.import_module("audit_native_evidence")
    allocator = importlib.import_module("allocator_environment_audit")
    native = importlib.import_module("analyze_native_observation")
    need(all(Path(module.__file__).resolve().parent == harness_root for module in (evidence, allocator, native)),
         "imported another frozen verifier")
    report = json.loads(raw)
    need(report["schema"] == "hepta-x230-native-boundary-diagnostic/v1" and report["bursts_planned"] in (2, 3, 4)
         and len(report["bursts"]) == report["bursts_planned"], "bounded diagnostic incomplete")
    need(report["attempts_per_burst"] == 32 and report["warmup_calls"] == report["post_drain_calls_per_cell"] == 24
         and report["post_drain_concurrency"] == [1, 8] and report["tokio_workers"] == 2 and report["arena_max"] == 1,
         "diagnostic configuration/dimensions differ")
    need(report["automatic_rpc_retries"] == report["effect_starts"] == report["remote_mutation_tool_calls"] == 0,
         "unexpected effects or retries")
    need(all(report.get(key) is True for key in ("sources_unchanged", "source_originals_unchanged", "copied_originals_unchanged",
         "binary_hashes_unchanged", "topology_manifest_unchanged", "profile_template_unchanged", "agent_identity_unchanged",
         "classification_policy_unchanged", "drain_and_recovery_passed")), "identity, drain or recovery contract failed")
    need(report["source_sha256"] == {name: sha((HERE / name).read_bytes()) for name in NAMES}
         and report["frozen_harness_sha256"] == frozen, "tool source provenance differs")
    policy_raw = evidence.bound_file(directory, report["classification_policy"])
    policy = json.loads(policy_raw)
    need(policy_raw == (HERE / "capacity-policy.json").read_bytes()
         and policy["schema"] == "hepta-native-capacity-error-policy/v1"
         and policy["rendering_verified"] is report["classification_policy"]["rendering_verified"], "error policy identity differs")
    need(policy["rendering_verified"] or not policy["accepted_error_envelopes"], "unverified whitelist accepted errors")
    need(all(rule == {"kind": "native_single_text", "text": CAPACITY_TEXT} for rule in policy["accepted_error_envelopes"]),
         "unsupported exact error whitelist")
    if policy["rendering_verified"]:
        need(policy.get("rendering_source_proof"), "error rendering source proof missing")
    topology = evidence.topology(directory, report)
    alloc = allocator.validate_metadata(report["allocator_configuration"], {"candidate": report["candidate_sha256"]}, {"candidate"})
    need(alloc["variants"]["candidate"]["environment"] == {"MALLOC_ARENA_MAX": "1"}, "allocator is not explicit arena1")
    originals = {item["host"]: item for item in report["six_originals"]}
    need(len(report["six_originals"]) == 6 and set(originals) == native.HOSTS, "original host set differs")
    identities = {host: item["job_id"] for host, item in originals.items()}
    for item in originals.values():
        copied = directory / "controller/state/jobs" / (item["job_id"] + ".json")
        need(sha(copied.read_bytes()) == item["record_sha256"], "copied original registry bytes changed")
    counts, resources, bursts = Counter(), [], []
    for phase, start_key, stop_key in (("first", "startup", "shutdown"), ("restart", "restart_startup", "restart_shutdown")):
        startup, shutdown = report[start_key], report[stop_key]
        allocator.validate_observation(startup["allocator_environment"], {"MALLOC_ARENA_MAX": "1"},
                                       startup["pid"], startup["birth_ticks"], True)
        need(shutdown["exit_code"] == 0 and shutdown["shutdown_method"] == "stdin_eof"
             and not shutdown["observed_descendant_survivors"] and shutdown["reader_error"] is None
             and shutdown["unmatched_responses"] == 0, "controller resources did not reclaim normally")
        folder = directory / "controller" / phase
        transport = evidence.Transport(folder, shutdown["transport_capture"])
        transport.initialize(startup)
        rows = report["initial_complete_outputs"] if phase == "first" else report["restart_checks"]
        expected_pairs = {(host, "process_read") for host in originals} if phase == "first" else {
            (host, tool) for host in originals for tool in ("process_status", "process_read")}
        need(len(rows) == len(expected_pairs) and {(row["host"], row["tool"]) for row in rows} == expected_pairs,
             "preflight/restart host-operation set differs")
        worker_environment(evidence, startup, min(row["start_monotonic_ns"] for row in rows))
        for row in rows:
            need(audit_row(evidence, transport, row, originals[row["host"]], policy,
                           "preflight" if phase == "first" else "normal-restart") == "success", "preflight/restart failed")
        if phase == "first":
            warmup = report["initial_warmup"]
            native.inspect_cell(warmup, 24, identities)
            cell_metrics(evidence, warmup, startup)
            need(warmup["concurrency"] == 8 and warmup["raw_timing"]["start_monotonic_ns"] >= max(row["end_monotonic_ns"] for row in rows),
                 "initial warmup ordering differs")
            for row in warmup["rows"]:
                audit_row(evidence, transport, row, originals[row["host"]], policy, "initial-warmup")
            previous_end = warmup["raw_timing"]["end_monotonic_ns"]
            for number, entry in enumerate(report["bursts"]):
                cell = entry["burst"]
                need(entry["index"] == number and cell["raw_timing"]["start_monotonic_ns"] >= previous_end,
                     "planned bursts overlap preceding probes")
                bursts.append(audit_burst(evidence, transport, cell, originals, policy, startup, number))
                drained = entry["drain"]
                need(drained["complete"] is True and drained["pending_rpc_ids"] == []
                     and drained["unmatched_responses"] == 0 and drained["reader_error"] is None
                     and drained["controller_running"] is True and drained["complete_responses"] == drained["completed_attempts"] == 32
                     and max(row["end_monotonic_ns"] for row in cell["rows"]) <= drained["start_monotonic_ns"]
                     <= drained["end_monotonic_ns"], "drain receipt incomplete")
                previous_end = drained["end_monotonic_ns"]
                need([part["concurrency"] for part in entry["post_drain_cells"]] == [1, 8], "post-drain probe plan differs")
                for part in entry["post_drain_cells"]:
                    native.inspect_cell(part, 24, identities)
                    cell_metrics(evidence, part, startup)
                    need(part["raw_timing"]["start_monotonic_ns"] >= previous_end, "probe began before drain/prior probe")
                    for row in part["rows"]:
                        audit_row(evidence, transport, row, originals[row["host"]], policy, f"post-drain-{number}-C{part['concurrency']}")
                    previous_end = part["raw_timing"]["end_monotonic_ns"]
        counts.update(transport.finish())
        resources.append({"phase": phase, **evidence.resources(folder, shutdown["resources"], startup)})
    classified = Counter()
    for burst in bursts:
        classified.update(burst["counts"])
    need({key: report["classified_burst_counts"].get(key, 0) for key in CLASSES} == dict(classified), "total outcome counts differ")
    passed = classified["other_error"] == 0
    need(report["passed"] is passed and report["capacity_rejection_observed"] is (classified["capacity_rejection"] > 0)
         and report["exact_pool_identity_peak_observed"] is False, "diagnostic acceptance/inference differs")
    return {"schema": "hepta-native-boundary-independent-analysis/v1", "evidence_verified": True, "diagnostic_passed": passed,
            "report_sha256": sha(raw), "candidate_sha256": report["candidate_sha256"],
            "capacity_rendering_verified": policy["rendering_verified"], "classification_policy_sha256": sha(policy_raw),
            "counts": dict(classified), "bursts": bursts, "drain_and_recovery_passed": True,
            "post_drain_calls": len(bursts) * 48, "warmup_calls": 24, "preflight_restart_calls": 18,
            "total_tool_calls": len(bursts) * 80 + 42, "automatic_rpc_retries": 0,
            "raw_transport": dict(counts), "resource_traces": resources, "topology": topology,
            "limitations": report["limitations"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--harness-root", type=Path, default=HERE.parent / "measurement-tools")
    args = parser.parse_args()
    raw = args.report.read_bytes()
    try:
        result = analyze(raw, args.report.parent, args.harness_root.resolve())
    except Exception as error:
        result = {"schema": "hepta-native-boundary-independent-analysis/v1", "evidence_verified": False,
                  "diagnostic_passed": False, "report_sha256": sha(raw),
                  "error": {"type": type(error).__name__, "reason": str(error)[:1000]}}
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({key: result.get(key) for key in ("evidence_verified", "diagnostic_passed", "counts", "error")}))
    return 0 if result["evidence_verified"] and result["diagnostic_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
