#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Pure D2 trace correlation copied from the completed D1 offline interpretation.

These definitions perform no process launch, host call, archive extraction,
native auditor execution or runtime mutation. The adapter supplies only its
already closed controller's byte-bound original raw transport/index inputs.
"""
from collections import defaultdict
import hashlib
import json

ROOT = "/home/qian/hepta-runtime-validation-cost-20261106-d2"
HOSTS = {"ai395", "mac", "main", "pocket4", "rog", "x230"}
TOOLS = {"process_status", "process_read"}

def need(value, reason):
    if not value:
        raise ValueError(reason)


def uint(value, reason):
    need(type(value) is int and 0 <= value < (1 << 64), reason)
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def json_object(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def canonical(value):
    # Exact canonical byte encoding used by the unchanged original native auditor.
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def transport_calls(archive, controller):
    binding, startup, shutdown = (controller[k] for k in ("binding", "startup", "shutdown"))
    relative = binding["directory"][len(ROOT) + 1:]
    capture = shutdown["transport_capture"]
    raw = archive.read(relative + "/transport-responses.jsonl")
    index_raw = archive.read(relative + "/transport-responses.index.jsonl")
    for value, name in ((raw, "raw"), (index_raw, "index")):
        need(len(value) == capture[name]["bytes"] and sha(value) == capture[name]["sha256"],
             "original shutdown transport identity differs")
    entries = [json_object(line) for line in index_raw.splitlines()]
    need(len(entries) == capture["frames"], "transport index frame count differs")
    frames, offset, last_receive = {}, 0, 0
    for sequence, entry in enumerate(entries):
        size = uint(entry["bytes"], "invalid frame size")
        need(size > 0 and entry["sequence"] == sequence and entry["offset"] == offset,
             "raw frame index is not complete and contiguous")
        frame = raw[offset:offset + size]
        need(len(frame) == size and frame.endswith(b"\n") and sha(frame) == entry["sha256"]
             and entry["complete_line"] is True and "parse_error" not in entry,
             "raw response frame identity differs")
        reply = json_object(frame)
        need(isinstance(reply, dict) and entry["has_id"] is ("id" in reply)
             and entry["rpc_id"] == reply.get("id")
             and 0 < entry["read_start_monotonic_ns"] <= entry["received_monotonic_ns"]
             and last_receive <= entry["received_monotonic_ns"], "frame ID or receive ordering differs")
        frames[sequence] = (entry, reply)
        offset += size
        last_receive = entry["received_monotonic_ns"]
    need(offset == len(raw), "unindexed response bytes remain")
    used, rpc_ids = set(), set()

    def rpc(proof, method, params):
        reference = proof["transport_response"]
        sequence = reference["sequence"]
        need(reference["file"] == "transport-responses.jsonl" and sequence in frames and sequence not in used,
             "missing or reused original response frame")
        entry, reply = frames[sequence]
        need({k: v for k, v in reference.items() if k != "file"} == entry
             and reply.get("id") == proof["request_id"] and reply.get("jsonrpc") == "2.0"
             and proof["request_id"] not in rpc_ids, "frame/index/RPC identity differs")
        request = canonical({"jsonrpc": "2.0", "id": proof["request_id"], "method": method, "params": params})
        need(len(request) == proof["request_bytes"] and sha(request) == proof["request_sha256"],
             "raw RPC request binding differs")
        times = [proof[k] for k in ("rpc_start_monotonic_ns", "send_start_monotonic_ns", "send_end_monotonic_ns",
                                   "response_dequeued_monotonic_ns", "rpc_end_monotonic_ns")]
        need(all(type(value) is int and value > 0 for value in times) and times == sorted(times)
             and times[1] <= entry["received_monotonic_ns"] <= times[3], "original RPC endpoints differ")
        # The reader can have been blocked before the RPC. Its read_start is NOT a lower bound.
        used.add(sequence)
        rpc_ids.add(proof["request_id"])
        return reply

    rpc(startup["initialize_rpc"], "initialize", {
        "protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "hepta-x230-observation-abba", "version": "1"}})
    result = []
    for category, rows, interval in controller["groups"]:
        for number, row in enumerate(rows):
            need(row["okay"] is True and row["automatic_retry"] is False
                 and row["tool"] in TOOLS and row["host"] in HOSTS, "unexpected original call")
            arguments = {"host": row["host"], "job_id": row["job_id"]}
            if row["tool"] == "process_read":
                arguments.update(stdout_offset=0, stderr_offset=0, limit=16384)
            reply = rpc(row["rpc"], "tools/call", {"name": row["tool"], "arguments": arguments})
            need(sha(canonical(reply)) == row["response_sha256"] and "error" not in reply
                 and reply["result"].get("isError", False) is False, "original response hash/outcome differs")
            need("io.hepta.runtime/request-v8" not in reply["result"].get("_meta", {}),
                 "this interpretation does not substitute for an observed wire native request ID")
            call = [row["start_monotonic_ns"], row["end_monotonic_ns"]]
            rpc_interval = [row["rpc"]["rpc_start_monotonic_ns"], row["rpc"]["rpc_end_monotonic_ns"]]
            need(0 < call[0] <= rpc_interval[0] <= rpc_interval[1] <= call[1], "RPC escaped original call interval")
            if interval is not None:
                need(interval["start_monotonic_ns"] <= call[0] <= call[1] <= interval["end_monotonic_ns"],
                     "call escaped original warmup/measured interval")
            result.append({
                "row_key": category + ":" + str(number), "category": category, "category_row_index": number,
                "operation": row["tool"], "host": row["host"], "job_id": row["job_id"],
                "rpc_id": row["rpc"]["request_id"], "rpc_request_sha256": row["rpc"]["request_sha256"],
                "response_sha256": row["response_sha256"], "raw_frame": row["rpc"]["transport_response"],
                "call_interval_monotonic_ns": call, "rpc_interval_monotonic_ns": rpc_interval,
                "cell_interval_monotonic_ns": ([interval["start_monotonic_ns"], interval["end_monotonic_ns"]]
                                                if interval is not None else None),
                "wire_native_request_id": None, "native_id_publicly_observed": False,
            })
    unused = [entry for sequence, (entry, _) in frames.items() if sequence not in used]
    need(all(not entry["has_id"] for entry in unused), "unmatched original RPC response remains")
    return result


def phase_values(rows, summary, parser):
    """New selective arithmetic, reconciled with every original parser total before use."""
    events = {row["event"]["span"]: row["event"] for row in rows if row["type"] == "event"}
    children = defaultdict(list)
    for event in events.values():
        if event["parent_sync_span"]:
            children[event["parent_sync_span"]].append(event)
    wall, inclusive, exclusive = (defaultdict(list) for _ in range(3))
    per_request = defaultdict(lambda: defaultdict(lambda: {"wall_nonadditive_ns": 0,
                                                          "cpu_inclusive_ns": 0, "cpu_exclusive_ns": 0,
                                                          "wall_events": 0, "cpu_events": 0}))
    scopes = {}
    for span, event in events.items():
        slot, phase = event["request"], event["phase"]
        own = per_request[slot][phase]
        duration = event["end_monotonic_ns"] - event["start_monotonic_ns"]
        wall[phase].append(duration)
        own["wall_nonadditive_ns"] += duration
        own["wall_events"] += 1
        if phase == "request":
            need(slot not in scopes, "duplicated validated request scope")
            scopes[slot] = [event["start_monotonic_ns"], event["end_monotonic_ns"]]
        if event["thread_cpu_start_ns"] is not None:
            cpu = event["thread_cpu_end_ns"] - event["thread_cpu_start_ns"]
            child_cpu = sum(child["thread_cpu_end_ns"] - child["thread_cpu_start_ns"] for child in children[span])
            value = cpu - child_cpu  # Same immediate synchronous children as the unchanged parser.
            need(value >= 0, "negative validated exclusive CPU")
            inclusive[phase].append(cpu)
            exclusive[phase].append(value)
            own["cpu_inclusive_ns"] += cpu
            own["cpu_exclusive_ns"] += value
            own["cpu_events"] += 1
    for actual, name in ((wall, "phase_wall_nonadditive"), (inclusive, "phase_thread_cpu_inclusive"),
                         (exclusive, "phase_thread_cpu_exclusive")):
        need({key: parser.distribution(values) for key, values in sorted(actual.items())} == summary[name],
             "selective arithmetic does not reproduce the original parser's full-trace " + name)
    for item in summary["requests"]:
        phases = per_request[item["slot"]]
        need(sum(value["cpu_exclusive_ns"] for value in phases.values())
             == item["recorded_synchronous_cpu_exclusive_ns"], "selective per-request CPU differs from original parser")
    need(sum(sum(values) for values in exclusive.values()) == summary["recorded_synchronous_cpu_exclusive_ns"],
         "selective arithmetic does not reproduce original total CPU")
    return {slot: dict(phases) for slot, phases in per_request.items()}, scopes


def correlate(calls, summary, scopes, per_request, record):
    forward, reverse = {}, {call["row_key"]: [] for call in calls}
    for item in summary["requests"]:
        host_index = item["host_index"]
        need(type(host_index) is int, "trace host is unavailable for strict correlation")
        host, span = summary["host_aliases"][host_index], scopes[item["slot"]]
        matches = [call["row_key"] for call in calls
                   if call["operation"] == item["operation"] and call["host"] == host
                   and call["rpc_interval_monotonic_ns"][0] <= span[0] <= span[1]
                   <= call["rpc_interval_monotonic_ns"][1]]
        forward[item["slot"]] = matches
        for key in matches:
            reverse[key].append(item["slot"])
    record["correlation_diagnostics"] = {
        "trace_requests_with_nonunique_match": [
            {"slot": item["slot"], "trace_native_request_id": item["native_request_id"],
             "candidate_row_keys": forward[item["slot"]]}
            for item in summary["requests"] if len(forward[item["slot"]]) != 1],
        "original_calls_with_nonunique_match": [
            {"row_key": call["row_key"], "candidate_trace_slots": reverse[call["row_key"]]}
            for call in calls if len(reverse[call["row_key"]]) != 1],
    }
    need(len(summary["requests"]) == len(calls)
         and not any(record["correlation_diagnostics"].values()), "strict bidirectional trace/RPC bijection is not established")
    by_key = {call["row_key"]: call for call in calls}
    return [{**by_key[forward[item["slot"]][0]],
             "trace_slot": item["slot"], "trace_native_request_id": item["native_request_id"],
             "trace_request_interval_monotonic_ns": scopes[item["slot"]],
             "recorded_synchronous_cpu_exclusive_ns": item["recorded_synchronous_cpu_exclusive_ns"],
             "derived_queue_spans": item["derived_queue_spans"],
             "phases": per_request[item["slot"]],
             "correlation_method": "unique_same_controller_host_operation_and_whole_trace_inside_original_rpc"}
            for item in summary["requests"]]


def aggregate(selected, parser):
    phases = sorted({phase for item in selected for phase in item["phases"]})
    tables = {}
    for phase in phases:
        values = [item["phases"].get(phase, {}) for item in selected]
        tables[phase] = {
            "exclusive_cpu_per_request_ns": parser.distribution([value.get("cpu_exclusive_ns", 0) for value in values]),
            "inclusive_cpu_per_request_ns": parser.distribution([value.get("cpu_inclusive_ns", 0) for value in values]),
            "wall_sum_per_request_nonadditive_ns": parser.distribution([value.get("wall_nonadditive_ns", 0) for value in values]),
            "cpu_event_count": sum(value.get("cpu_events", 0) for value in values),
            "wall_event_count": sum(value.get("wall_events", 0) for value in values),
        }
    return {"requests": len(selected),
            "recorded_synchronous_cpu_exclusive_ns": sum(item["recorded_synchronous_cpu_exclusive_ns"] for item in selected),
            "recorded_synchronous_cpu_exclusive_per_request_ns": parser.distribution(
                [item["recorded_synchronous_cpu_exclusive_ns"] for item in selected]),
            "phases": tables,
            "missing_recorded_phase_is_zero_filled_for_per_request_distribution": True,
            "cpu_event_count_zero_means_no_synchronous_cpu_observation": True,
            "phase_wall_sums_are_not_additive_request_or_network_time": True}


def measured_counter(cell, startup, selected):
    timing = cell["raw_timing"]
    before, after = timing["controller_before"], timing["controller_after"]
    need(before["pid"] == after["pid"] == startup["pid"]
         and before["birth_ticks"] == after["birth_ticks"] == startup["birth_ticks"]
         and before["clock_ticks_per_second"] == after["clock_ticks_per_second"] > 0
         and before["read_end_monotonic_ns"] <= timing["start_monotonic_ns"]
         < timing["end_monotonic_ns"] <= after["read_start_monotonic_ns"],
         "original measured controller counter window differs")
    ticks = after["utime_ticks"] + after["stime_ticks"] - before["utime_ticks"] - before["stime_ticks"]
    need(ticks >= 0 and len(selected) == 192, "invalid measured CPU denominator")
    hz = before["clock_ticks_per_second"]
    controller_ns = ticks * 1_000_000_000 / hz
    recorded = sum(item["recorded_synchronous_cpu_exclusive_ns"] for item in selected)
    return {
        "calls": 192, "controller_cpu_ticks_delta": ticks, "clock_ticks_per_second": hz,
        "controller_cpu_ns": controller_ns, "controller_cpu_ms_per_call": controller_ns / 192 / 1_000_000,
        "recorded_synchronous_cpu_exclusive_ns": recorded,
        "recorded_synchronous_cpu_ms_per_call": recorded / 192 / 1_000_000,
        "signed_controller_minus_recorded_sync_ns": controller_ns - recorded,
        "recorded_sync_fraction_of_controller_counter": recorded / controller_ns if controller_ns else None,
        "cpu_clock_tick_resolution_ns": 1_000_000_000 / hz,
        "original_raw_timing": timing,
        "residual_includes_uninstrumented_background_diagnostic_and_counter_window_difference": True,
        "residual_is_ssh_or_remote_or_network_cpu": False,
        "sampled_tree_cpu_used": False,
    }

