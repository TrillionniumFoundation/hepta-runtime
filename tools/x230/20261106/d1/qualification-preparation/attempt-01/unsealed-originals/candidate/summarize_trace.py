#!/usr/bin/env python3
"""Read one bounded raw diagnostic trace without executing runtime code.

The output is a raw-trace structural/phase summary, never an acceptance verdict.
Original native/controller/SSH/remote-job/harness receipts remain external.
"""
import argparse
import hashlib
import json
import os
import stat
import statistics
from collections import defaultdict

MAX_BYTES = 32 * 1024 * 1024
MAX_LINE = 64 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def stamp(value):
    return (
        value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
        value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns,
    )


def regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "bounded regular input required")
        parts = []
        total = 0
        while True:
            part = os.read(fd, min(65536, limit + 1 - total))
            if not part:
                break
            total += len(part)
            require(total <= limit, "input exceeded its byte bound")
            parts.append(part)
        require(total == before.st_size, "input size changed while reading")
        require(stamp(os.fstat(fd)) == stamp(before), "input descriptor changed while reading")
        require(stamp(os.stat(path, follow_symlinks=False)) == stamp(before), "input name changed while reading")
        return b"".join(parts)
    finally:
        os.close(fd)


def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def uint(value, field, maximum=(1 << 64) - 1):
    require(type(value) is int and 0 <= value <= maximum, "invalid unsigned integer: " + field)
    return value


def distribution(values):
    if not values:
        return {"count": 0, "sum_ns": 0, "median_ns": None, "p95_nearest_rank_ns": None, "maximum_ns": None}
    ordered = sorted(values)
    index = max(0, (95 * len(ordered) + 99) // 100 - 1)
    return {
        "count": len(values), "sum_ns": sum(values),
        "median_ns": statistics.median(ordered),
        "p95_nearest_rank_ns": ordered[index], "maximum_ns": ordered[-1],
    }


def summarize(raw, digest):
    require(raw.endswith(b"\n"), "raw trace must end at a complete JSONL boundary")
    lines = raw.splitlines()
    require(2 <= len(lines) <= 32768 + 2048 + 2, "raw row bound violated")
    require(all(0 < len(line) <= MAX_LINE for line in lines), "raw line bound violated")
    rows = [json.loads(line.decode("utf-8"), object_pairs_hook=object_pairs,
                       parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON"))) for line in lines]
    header, footer = rows[0], rows[-1]
    require(header.get("type") == "header" and footer.get("type") == "footer", "complete header/footer required")
    require(header.get("schema") == footer.get("schema") == "hepta-phase-cost-trace/v1", "trace schema mismatch")
    require(header.get("mode") in ("on", "off"), "trace mode missing")
    require(header.get("event_capacity") == 32768 and header.get("request_capacity") == 2048, "frozen slot bounds changed")
    require(header.get("output_limit") == MAX_BYTES, "output byte bound changed")
    require(header.get("wall_clock") == "CLOCK_MONOTONIC" and header.get("cpu_clock") == "CLOCK_THREAD_CPUTIME_ID", "clock domain changed")
    require(header.get("performance_acceptance_claim") is False and footer.get("performance_acceptance_claim") is False, "unsupported acceptance claim")
    start = uint(header.get("start_monotonic_ns"), "window start")
    finish = uint(footer.get("end_monotonic_ns"), "window end")
    require(finish >= start, "window clock reversed")
    hosts = header.get("host_aliases")
    require(isinstance(hosts, list) and len(hosts) <= 64 and all(isinstance(host, str) and len(host.encode("utf-8")) <= 128 for host in hosts), "host alias bound violated")
    require(len(set(hosts)) == len(hosts), "duplicate host alias")
    requests, events, event_slots, native_ids = {}, {}, set(), set()
    for row in rows[1:-1]:
        require(isinstance(row, dict), "non-object trace row")
        if row.get("type") == "request":
            slot = uint(row.get("slot"), "request slot", 2047)
            require(slot not in requests, "duplicate request slot")
            require(row.get("operation") in ("process_status", "process_read"), "unsupported request operation")
            host = row.get("host_index")
            require(host is None or (type(host) is int and 0 <= host < len(hosts)), "host index outside table")
            native = row.get("native_request_id")
            require(isinstance(native, str) and 0 < len(native) <= 128 and native.isascii() and all(ord(ch) >= 32 and ord(ch) != 127 for ch in native), "native request identity absent or invalid")
            require(native not in native_ids, "native identity bound to multiple requests")
            native_ids.add(native)
            requests[slot] = row
        elif row.get("type") == "event":
            slot = uint(row.get("slot"), "event slot", 32767)
            require(slot not in event_slots, "duplicate event slot")
            event_slots.add(slot)
            event = row.get("event")
            require(isinstance(event, dict), "event object missing")
            span = uint(event.get("span"), "span")
            require(span > 0 and span not in events, "duplicate or zero span")
            uint(event.get("request"), "event request", 2047)
            lo = uint(event.get("start_monotonic_ns"), "event wall start")
            hi = uint(event.get("end_monotonic_ns"), "event wall end")
            require(start <= lo <= hi <= finish, "event outside closed clock window")
            tid0 = uint(event.get("start_tid"), "start tid", (1 << 32) - 1)
            tid1 = uint(event.get("end_tid"), "end tid", (1 << 32) - 1)
            require(tid0 > 0 and tid1 > 0, "invalid Linux thread identity")
            require(isinstance(event.get("phase"), str) and event["phase"], "phase missing")
            require(event.get("end") in ("boundary_reached", "synchronous_scope_exit"), "abandoned or invalid event")
            parent = uint(event.get("parent_sync_span"), "parent span")
            cpu0, cpu1 = event.get("thread_cpu_start_ns"), event.get("thread_cpu_end_ns")
            if cpu0 is None:
                require(cpu1 is None and parent == 0 and event["end"] == "boundary_reached", "wall span contains CPU attribution")
            else:
                require(uint(cpu1, "cpu end") >= uint(cpu0, "cpu start"), "thread CPU clock reversed")
                require(tid0 == tid1 and event["end"] == "synchronous_scope_exit", "CPU span crossed thread or async boundary")
            events[span] = event
        else:
            raise ValueError("unexpected trace row kind")
    require(set(requests) == set(range(len(requests))) and event_slots == set(range(len(events))), "missing original slot")
    require(all(event["request"] in requests for event in events.values()), "event references unknown request")
    for field, actual in (
        ("request_rows", len(requests)), ("request_reserved", len(requests)),
        ("native_ids_bound", len(requests)), ("completed_request_scopes", len(requests)),
        ("event_rows", len(events)), ("event_reserved", len(events)),
    ):
        require(footer.get(field) == actual and type(footer.get(field)) is int, "footer count mismatch: " + field)
    for field in ("active_at_freeze", "request_dropped", "event_dropped", "errors", "abandoned_spans"):
        require(footer.get(field) == 0 and type(footer.get(field)) is int, "incomplete trace: " + field)
    require(footer.get("owners_joined") is True and footer.get("transport_returned_ok") is True and footer.get("early_drop") is False, "original owner/transport closing flags incomplete")
    if header["mode"] == "off":
        require(not requests and not events and footer.get("trace_window_complete") is None, "off mode unexpectedly recorded events")
    else:
        require(footer.get("trace_window_complete") is True and requests, "recording trace is not complete or has no requests")
    cpu_children, by_request = defaultdict(list), defaultdict(list)
    for span, event in events.items():
        by_request[event["request"]].append((span, event))
        parent = event["parent_sync_span"]
        if parent:
            require(parent in events and parent < span, "CPU parent missing or cyclic")
            outer = events[parent]
            require(outer["request"] == event["request"] and outer["start_tid"] == event["start_tid"], "CPU parent changed request/thread")
            require(outer["thread_cpu_start_ns"] is not None, "CPU parent is a wall span")
            require(outer["start_monotonic_ns"] <= event["start_monotonic_ns"] <= event["end_monotonic_ns"] <= outer["end_monotonic_ns"], "CPU child wall interval not nested")
            require(outer["thread_cpu_start_ns"] <= event["thread_cpu_start_ns"] <= event["thread_cpu_end_ns"] <= outer["thread_cpu_end_ns"], "CPU child counter interval not nested")
            cpu_children[parent].append(span)
    phase_wall, phase_cpu, phase_exclusive = defaultdict(list), defaultdict(list), defaultdict(list)
    exclusive = {}
    for span, event in events.items():
        phase_wall[event["phase"]].append(event["end_monotonic_ns"] - event["start_monotonic_ns"])
        if event["thread_cpu_start_ns"] is None:
            continue
        duration = event["thread_cpu_end_ns"] - event["thread_cpu_start_ns"]
        children = sorted((events[child] for child in cpu_children[span]), key=lambda item: item["thread_cpu_start_ns"])
        previous = event["thread_cpu_start_ns"]
        child_total = 0
        for child in children:
            require(child["thread_cpu_start_ns"] >= previous, "direct synchronous CPU children overlap")
            previous = child["thread_cpu_end_ns"]
            child_total += child["thread_cpu_end_ns"] - child["thread_cpu_start_ns"]
        require(child_total <= duration, "nested child CPU exceeds parent CPU")
        exclusive[span] = duration - child_total
        phase_cpu[event["phase"]].append(duration)
        phase_exclusive[event["phase"]].append(exclusive[span])
    request_summaries = []
    queue_pairs = (
        ("queue_submitted", "queue_received", "channel_wall_ns"),
        ("queue_received", "initial_capacity_granted", "pending_until_initial_global_grant_wall_ns"),
        ("initial_capacity_granted", "owner_execute", "dispatch_schedule_wall_ns"),
    )
    for slot, metadata in sorted(requests.items()):
        own = by_request[slot]
        phases = defaultdict(list)
        for span, event in own:
            phases[event["phase"]].append(event)
        require(len(phases["request"]) == 1, "request scope missing or duplicated")
        outer = phases["request"][0]
        for _, event in own:
            require(outer["start_monotonic_ns"] <= event["start_monotonic_ns"] <= event["end_monotonic_ns"] <= outer["end_monotonic_ns"], "request-owned span escaped original request window")
        derived = {}
        for before, after, key in queue_pairs:
            if len(phases[before]) == len(phases[after]) == 1:
                lo, hi = phases[before][0]["start_monotonic_ns"], phases[after][0]["start_monotonic_ns"]
                require(hi >= lo, "queue marker order reversed")
                derived[key] = hi - lo
            else:
                derived[key] = None
        request_summaries.append({
            "slot": slot, "native_request_id": metadata["native_request_id"],
            "operation": metadata["operation"], "host_index": metadata["host_index"],
            "request_wall_ns": outer["end_monotonic_ns"] - outer["start_monotonic_ns"],
            "recorded_synchronous_cpu_exclusive_ns": sum(exclusive.get(span, 0) for span, _ in own),
            "derived_queue_spans": derived,
            "effect_success_asserted": False,
        })
    return {
        "schema": "hepta-phase-cost-raw-summary/v1",
        "preparation_revision": "recovery-02",
        "raw": {"bytes": len(raw), "sha256": digest},
        "mode": header["mode"],
        "trace_structurally_complete": True,
        "original_controller_and_harness_closure_validated": False,
        "evidence_scope": "raw diagnostic trace only; this is not native operation success or acceptance",
        "pid": header.get("pid"), "start_ticks": header.get("start_ticks"), "boot_id": header.get("boot_id"),
        "declared_elf_sha256": header.get("declared_elf_sha256"),
        "elf_build_feature_and_custody_validated": False,
        "host_aliases": hosts,
        "counts": {"requests": len(requests), "events": len(events)},
        "recorded_synchronous_cpu_exclusive_ns": sum(exclusive.values()),
        "controller_total_cpu_ns": None, "ssh_child_cpu_ns": None, "remote_helper_cpu_ns": None,
        "network_only_wall_ns": None,
        "phase_wall_nonadditive": {key: distribution(values) for key, values in sorted(phase_wall.items())},
        "phase_thread_cpu_inclusive": {key: distribution(values) for key, values in sorted(phase_cpu.items())},
        "phase_thread_cpu_exclusive": {key: distribution(values) for key, values in sorted(phase_exclusive.items())},
        "requests": request_summaries,
        "limitations": [
            "Nested and concurrent wall sums are not request totals.",
            "Synchronous thread CPU excludes awaited time and uninstrumented/background work.",
            "Parent exclusive CPU can include diagnostic bookkeeping.",
            "OFF/ON overhead and original whole-controller CPU must be measured independently.",
            "A durable footer does not prove successful native operations or remote cleanup.",
        ],
        "performance_acceptance_claim": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--summary", required=True)
    args = parser.parse_args()
    raw = regular(args.raw, MAX_BYTES)
    digest = hashlib.sha256(raw).hexdigest()
    require(digest == args.expected_sha256, "raw SHA256 differs from supplied original pin")
    summary = summarize(raw, digest)
    encoded = (json.dumps(summary, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()
    require(len(encoded) <= 4 * 1024 * 1024, "summary exceeded explicit bound")
    fd = os.open(args.summary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
