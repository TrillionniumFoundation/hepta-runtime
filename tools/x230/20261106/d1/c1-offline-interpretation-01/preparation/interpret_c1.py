#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Interpret the preserved D1 C1 failure in a separate, create-only namespace.

This is offline correlation, not a replacement for the failed original adapter.
It never launches a process, contacts a host, extracts a tar member to disk,
executes the native auditor, or changes a runtime/qualification/performance gate.
Only two exact reviewed original modules are loaded under non-main names:
the adapter's pure closed_matrix and the unchanged raw trace parser.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import types

ROOT = "/home/qian/hepta-runtime-phase-cost-20261106-d1"
SCHEMA = "hepta-d1-c1-offline-interpretation/v1"
INPUT_SCHEMA = "hepta-d1-c1-offline-interpretation-input/v1"
HOSTS = {"ai395", "mac", "main", "pocket4", "rog", "x230"}
TOOLS = {"process_status", "process_read"}
MAX_FILE = 32 * 1024 * 1024
MAX_OUTPUT = 16 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
ARCHIVE = (2220914, "522f79c7601612adfc093df876fb2962b201551e08016e9293d01424bbea36cb")
MANIFEST = (408940, "15cf694a7366f666bebbe696d0a8ef3266a64bba0955974693952fa3b94de691")
PINS = {
    "c1-observation-01/report.json": (1254435, "58303fa9ccc4f9dcb9c4ca4587761ecfdb2f7789fc68446512d163a264667da9"),
    "c1-adapter-evidence-01/adapter-report.json": (14034, "0f2c2c504e2768b879ab3a2cfa56e21d3b1d28b6f5d7fce4d446e4d3f6abc8e2"),
    "c1-campaign-01/report.json": (460195, "9634d62d7bfd4ded40831306953f7c7cd69d105aedc3087755288069a0ea2990"),
    "c1-tools-01/run_c1_phase_cost.py": (34274, "0902f5a9bf4c085172a61010deb54c74d7b89516fb9cfe1255722ad97b25dea9"),
    "c1-tools-01/reference/summarize_trace.py": (15057, "f6e65c2e206d4aa90143a17893e5e57c158bca9f8eec5f74897b19c3596e32c5"),
    "c1-tools-01/reference/analyze_native_observation.py": (8708, "cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66"),
    "c1-tools-01/reference/audit_native_evidence.py": (17065, "b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28"),
    "c1-tools-01/reference/allocator_environment_audit.py": (6709, "4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727"),
    "c1-tools-01/reference/allocator_environment.py": (5879, "f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525"),
}
AUDIT_JOB = "1a1b09af362-fc05-71a6"
AUDIT_PINS = {
    "summary": (51552, "d7833ca3b5434de7ccc807ffa13be2ed66fab599ee31df45cd554f83ab83a6db"),
    "start": (1364, "88097e9f08019df73df1efe0ed1c65475b4a6d5cbbe33023dab93e04dc631bde"),
    "native": (727, "701a68d5a28f87b91bc9a5cc459ef4870035f9058910c363005d083c30f1b339"),
    "read": (574, "079ba103a62a4b3adfb1940a16bb8970f3a99742e05ad2a409123c7c5458ad36"),
}


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


def stamp(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def regular(path, maximum):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, "absolute direct input path required")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and before.st_size <= maximum, "bounded single-link regular input required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        need(stamp(os.fstat(fd)) == stamp(before), "input identity changed at open")
        pieces, size = [], 0
        while True:
            piece = os.read(fd, min(65536, maximum + 1 - size))
            if not piece:
                break
            size += len(piece)
            need(size <= maximum, "input exceeded its byte bound")
            pieces.append(piece)
        need(size == before.st_size and stamp(os.fstat(fd)) == stamp(before)
             == stamp(path.lstat()), "input changed during read")
        raw = b"".join(pieces)
        return raw, {"path": str(path), "bytes": size, "sha256": sha(raw)}
    finally:
        os.close(fd)


def bound(pin, fixed, bindings, maximum=MAX_FILE):
    need(isinstance(pin, dict) and set(pin) == {"path", "bytes", "sha256"}, "exact input pin required")
    need((pin["bytes"], pin["sha256"]) == fixed, "input differs from the fixed original identity")
    raw, current = regular(pin["path"], maximum)
    need(current == pin, "actual input bytes differ: " + pin["path"])
    bindings.append(current)
    return raw


def write_new(path, value=None, raw=None):
    if raw is None:
        raw = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode()
    need(len(raw) <= MAX_OUTPUT, "derived output exceeded its explicit byte bound")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


class Originals:
    """Read selected members from the already verified immutable archive, without extraction."""
    def __init__(self, raw, manifest_raw):
        self.manifest = json_object(manifest_raw)
        m = self.manifest
        need(m["schema"] == "hepta-d1-c1-evidence-archive/v1" and m["kind"] == "c1"
             and m["source_root"] == ROOT, "wrong original failure archive")
        need(m["summary"]["outcome"] == "not_passed"
             and m["summary"]["receipt_binding_errors"] == []
             and m["summary"]["raw_trace_file_count"] == 8,
             "original failure/trace inventory differs")
        self.tar = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
        members = self.tar.getmembers()
        names = [item.name for item in members]
        need(0 < len(members) <= 8193 and names[0] == "manifest.json"
             and len(set(names)) == len(names), "archive member inventory differs")
        need(set(names) == {"manifest.json"} | set(m["files"]), "archive and manifest member sets differ")
        self.members = {item.name: item for item in members}
        need(all(item.isfile() and not item.issym() and not item.islnk() for item in members),
             "archive member must be an ordinary file")
        need(self._read_member("manifest.json", 2 * 1024 * 1024) == manifest_raw,
             "side manifest is not the archive's exact original first member")
        for name, pin in m["files"].items():
            p = PurePosixPath(name)
            need(not p.is_absolute() and str(p) == name and ".." not in p.parts
                 and set(pin) == {"bytes", "sha256"} and HEX.fullmatch(pin["sha256"])
                 and 0 <= pin["bytes"] <= MAX_FILE and self.members[name].size == pin["bytes"],
                 "invalid original member identity")
        need(sum(pin["bytes"] for pin in m["files"].values()) == m["selected_bytes"]
             <= 384 * 1024 * 1024, "archive selected byte bound differs")
        self.reads = {}

    def _read_member(self, name, maximum):
        info = self.members[name]
        need(info.size <= maximum, "selected member exceeds its bound")
        with self.tar.extractfile(info) as stream:
            raw = stream.read(info.size + 1)
        need(len(raw) == info.size, "selected archive member size differs")
        return raw

    def read(self, name):
        pin = self.manifest["files"][name]
        raw = self._read_member(name, MAX_FILE)
        need(len(raw) == pin["bytes"] and sha(raw) == pin["sha256"], "selected original member bytes differ: " + name)
        if name in PINS:
            need((len(raw), sha(raw)) == PINS[name], "wrong fixed original source/report")
        self.reads[name] = dict(pin)
        return raw


def original_module(archive, member, name):
    raw = archive.read(member)
    need(member in ("c1-tools-01/run_c1_phase_cost.py", "c1-tools-01/reference/summarize_trace.py"),
         "only the two explicitly reviewed non-main modules may be loaded")
    module = types.ModuleType(name)
    module.__file__ = "archive-member:" + member
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        exec(compile(raw, module.__file__, "exec"), module.__dict__)
    finally:
        sys.dont_write_bytecode = previous
    return module


def native_audit(inputs, archive, bindings, report):
    """Bind the first already completed original auditor job; never execute it again."""
    records = {name: json_object(bound(inputs[name], AUDIT_PINS[name], bindings))
               for name in ("summary", "start", "native", "read")}
    summary, start, native, page = (records[k] for k in ("summary", "start", "native", "read"))
    expected_args = ["-B", ROOT + "/c1-tools-01/reference/analyze_native_observation.py",
                     "--report", ROOT + "/c1-observation-01/report.json", "--output",
                     ROOT + "/c1-offline-interpretation-01/native-independent-summary.json"]
    job = start["job"]
    need(start["audit_recorded"] is True and start["reused"] is False
         and start["local_record_pending"] is False and start["launch"]["ok"] is True
         and job["id"] == AUDIT_JOB and job["host"] == "x230"
         and job["executable"] == "/usr/bin/python3" and job["args"] == expected_args
         and job["cwd"] == ROOT and job["env_keys"] == []
         and job["launch_state"] == "launched" and job["launch_error"] is None,
         "the original auditor launch identity/argv differs")
    need(native["job_id"] == AUDIT_JOB and native["state"] == "succeeded" and native["exit_code"] == 0
         and native["audit_recorded"] is True and native["automatic_retry"] is False
         and native["cancelled"] is False and native["timed_out"] is False
         and all(native[k] is True for k in ("output_complete", "output_durable", "terminal_publication_confirmed")),
         "the original auditor native terminal is not complete success")
    need(page["job_id"] == AUDIT_JOB and page["audit_recorded"] is True, "auditor read belongs to another job")
    stdout = (json.dumps({"verified": True, "measured_calls": 768, "warmup_calls": 96, "total_calls": 936}) + "\n").encode()
    for channel, expected in (("stdout", stdout), ("stderr", b"")):
        part = page[channel]
        actual = bytes.fromhex(part["bytes_hex"])
        need(actual == expected and part["text"].encode() == actual
             and part["offset"] == 0 and part["next_offset"] == part["size"] == len(actual)
             and part["eof"] is True
             and native["log_bytes"][channel] == {"seen": len(actual), "stored": len(actual)}
             and native["log_synced"][channel] is True and native["log_truncated"][channel] is False
             and native["log_errors"][channel] is None, "original auditor streams are not byte-complete")
    for name in ("analyze_native_observation.py", "audit_native_evidence.py",
                 "allocator_environment_audit.py", "allocator_environment.py"):
        archive.read("c1-tools-01/reference/" + name)
    need(summary["schema"] == "hepta-native-observation-independent-analysis/v3"
         and summary["verified"] is True and summary["failed_calls"] == 0
         and (summary["original_bytes"], summary["original_sha256"]) == PINS["c1-observation-01/report.json"]
         and summary["binary_sha256"] == report["binary_sha256"]
         and [summary[k] for k in ("measured_calls", "warmup_calls", "preflight_restart_calls", "total_calls")]
         == [768, 96, 72, 936] and len(summary["raw_evidence"]) == 4,
         "original independent audit summary does not cover this complete matrix")
    need("c1-observation-01/independent-summary.json" not in archive.manifest["files"],
         "original missing audit output was unexpectedly supplied")
    return summary


def original_failure(archive, adapter):
    original = json_object(archive.read("c1-observation-01/report.json"))
    failed = json_object(archive.read("c1-adapter-evidence-01/adapter-report.json"))
    parent = json_object(archive.read("c1-campaign-01/report.json"))
    need(parent["passed"] is False and parent["diagnostic_evidence_passed"] is False
         and parent["performance_acceptance_claim"] is False and parent["candidate_adopted"] is False
         and len(parent["stages"]) == 1, "original failed parent state changed")
    stage = parent["stages"][0]
    need(stage["name"] == "native-observation" and stage["returncode"] == 1
         and stage["waited_and_reaped"] is True and stage["owned_process_absent"] is True
         and stage["owned_process_group_absent"] is True, "original failed stage did not close")
    need(failed["sealed_input"] == adapter.SPEC and failed["original_returncode"] == 0
         and failed["original_wrapper_returned"] is True
         and failed["controller_close_evidence_complete"] is True
         and failed["trace_interpretation_started"] is True and failed["traces"] == []
         and failed["analysis_complete"] is False
         and failed["errors"] == [{"reason": "unique original native request identity missing", "type": "ValueError"}],
         "original interpretation failure differs from the fixed case")
    expected = []
    for number, arm in enumerate("ABBA"):
        for phase in ("first", "restart"):
            directory = ROOT + f"/c1-observation-01/round-{number}-{arm}/{phase}"
            mode = "off" if arm == "A" else "on"
            trace = directory + "/phase-cost.trace.jsonl"
            expected.append({
                "index": len(expected), "round": number, "arm": arm, "phase": phase, "mode": mode,
                "directory": directory, "trace": trace,
                "profile": ROOT + "/c1-observation-01/profile/profile.json",
                "config": ROOT + f"/c1-observation-01/round-{number}-{arm}/runtime.json",
                "added_environment": dict(zip(adapter.ENV_KEYS, (mode, trace, adapter.SPEC["qualified_feature_binary"]["sha256"]))),
                "context_consumed_once": True, "owner_identity_available_before_Popen": False,
            })
    need(failed["bindings"] == expected, "original eight controller environment bindings differ")
    controllers = adapter.closed_matrix(original, failed["original_returncode"], failed["bindings"])
    identities = [(c["startup"]["pid"], c["startup"]["birth_ticks"]) for c in controllers]
    need(len(set(identities)) == 8, "controller generation reused between slots")
    return original, failed, parent, controllers


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


def interpret(inputs, out, archive, destination, bindings):
    adapter = original_module(archive, "c1-tools-01/run_c1_phase_cost.py", "_d1_original_adapter_readonly")
    parser = original_module(archive, "c1-tools-01/reference/summarize_trace.py", "_d1_original_trace_parser")
    report, failed, parent, controllers = original_failure(archive, adapter)
    audit = native_audit(inputs["original_native_audit"], archive, bindings, report)
    out["original_native_audit"] = {"job_id": AUDIT_JOB, "verified": True,
                                    "reexecuted_here": False, "counts": {key: audit[key] for key in
                                    ("measured_calls", "warmup_calls", "preflight_restart_calls", "total_calls", "failed_calls")}}
    out["off_on_campaign_description"] = {
        "original_auditor_cases": audit["cases"],
        "optimization_benefit_or_statistical_significance_asserted": False,
        "large_round_variation_retained": True,
    }
    out["original_failure"] = {"parent_passed": parent["passed"], "adapter_analysis_complete": failed["analysis_complete"],
                               "adapter_errors": failed["errors"], "native_workload_report_passed": report["passed"],
                               "original_native_summary_path_still_absent_in_archive": True}
    all_done = failed["original_wrapper_return_monotonic_ns"]
    boot_ids, all_native_ids, all_trace_keys = set(), set(), set()
    all_selected = []
    for number, controller in enumerate(controllers):
        binding, startup = controller["binding"], controller["startup"]
        record = {"index": number, "binding": binding, "startup": startup,
                  "interpretation_complete": False, "matched_requests": [], "errors": []}
        out["controllers"].append(record)
        try:
            calls = transport_calls(archive, controller)
            record["original_calls"] = calls
            expected_count = 222 if binding["phase"] == "first" else 12
            need(len(calls) == expected_count, "original controller call cardinality differs")
            trace_name = binding["trace"][len(ROOT) + 1:]
            trace = archive.read(trace_name)
            summary = parser.summarize(trace, sha(trace))
            record["original_parser_summary_output"] = write_new(destination / f"trace-summary-{number:02d}.json", summary)
            rows = [json_object(line) for line in trace.splitlines()]
            header, footer = rows[0], rows[-1]
            next_start = controllers[number + 1]["startup"]["start_monotonic_ns"] if number + 1 < 8 else all_done
            boot = header["boot_id"]
            need(isinstance(boot, str) and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot)
                 and header["pid"] == startup["pid"] and header["start_ticks"] == startup["birth_ticks"]
                 and header["mode"] == binding["mode"]
                 and header["declared_elf_sha256"] == adapter.SPEC["qualified_feature_binary"]["sha256"]
                 and header["elf_hash_verified_here"] is False and set(header["host_aliases"]) == HOSTS,
                 "trace/controller/host-table/declared ELF identity differs")
            need(startup["start_monotonic_ns"] <= header["start_monotonic_ns"] <= startup["ready_monotonic_ns"]
                 and footer["end_monotonic_ns"] <= min(all_done, next_start), "trace escaped original controller lifetime")
            boot_ids.add(boot)
            need(len(boot_ids) == 1, "original trace headers span different boots")
            record["trace"] = {"archive_member": trace_name, **archive.manifest["files"][trace_name]}
            record["controller_identity"] = {"boot_id": boot, "pid": startup["pid"], "start_ticks": startup["birth_ticks"]}
            record["trace_counts"] = summary["counts"]
            if binding["mode"] == "off":
                need(summary["requests"] == [] and summary["counts"] == {"requests": 0, "events": 0},
                     "OFF trace unexpectedly contains request/phase data")
                record["phase_cpu_available"] = False
                record["off_empty_trace_is_zero_work_cpu_claim"] = False
            else:
                per_request, scopes = phase_values(rows[1:-1], summary, parser)
                selected = correlate(calls, summary, scopes, per_request, record)
                for item in selected:
                    native = item["trace_native_request_id"]
                    key = (boot, startup["pid"], startup["birth_ticks"], item["trace_slot"])
                    need(native not in all_native_ids and key not in all_trace_keys,
                         "trace native identity or controller/slot was reused across original controllers")
                    all_native_ids.add(native)
                    all_trace_keys.add(key)
                    item["controller_index"] = number
                record["matched_requests"] = selected
                record["phase_cpu_available"] = True
                record["new_selective_phase_arithmetic_reconciled_with_original_parser"] = True
                record["category_counts"] = dict(Counter(item["category"] for item in selected))
                need(record["category_counts"] == ({"preflight": 6, "warmup": 24, "measured": 192}
                      if binding["phase"] == "first" else {"restart": 12}), "correlated category completeness differs")
                record["category_phase_summaries"] = {
                    category: aggregate([item for item in selected if item["category"] == category], parser)
                    for category in record["category_counts"]}
                if binding["phase"] == "first":
                    record["measured_controller_cpu_comparison"] = measured_counter(
                        report["rounds"][binding["round"]]["cells"][0], startup,
                        [item for item in selected if item["category"] == "measured"])
                all_selected.extend(selected)
            record["interpretation_complete"] = True
        except BaseException as error:
            record["errors"].append({"type": type(error).__name__, "reason": str(error)[:2000]})
            raise
        finally:
            record["derived_record_output"] = write_new(destination / f"controller-{number:02d}.json", record)
    need(len(out["controllers"]) == 8 and len(all_selected) == len(all_native_ids) == len(all_trace_keys) == 468,
         "complete ON/OFF matrix correlation was not established")
    measured = [item for item in all_selected if item["category"] == "measured"]
    need(len(measured) == 384 and Counter((item["host"], item["operation"]) for item in measured)
         == Counter({(host, tool): 32 for host in HOSTS for tool in TOOLS}), "measured six-host/op balance differs")
    out["same_boot_evidence"] = {
        "trace_header_boot_id": next(iter(boot_ids)), "all_eight_original_headers_equal": True,
        "original_adapter_had_passed_its_before_after_boot_check_before_the_recorded_failure": True,
        "adapter_before_boot_value_persisted_in_original_report": False,
        "current_machine_boot_read_or_substituted": False,
    }
    out["counts"] = {"original_calls": 936, "original_measured_calls": 768, "on_requests_bijected": 468,
                     "on_measured_requests_bijected": 384, "off_controllers_without_phase_data": 4,
                     "trace_native_ids_unique_across_controllers": len(all_native_ids)}
    out["measured_phase_summary"] = aggregate(measured, parser)
    out["measured_phase_by_operation"] = {tool: aggregate([item for item in measured if item["operation"] == tool], parser)
                                          for tool in sorted(TOOLS)}
    out["measured_phase_by_host"] = {host: aggregate([item for item in measured if item["host"] == host], parser)
                                     for host in sorted(HOSTS)}
    out["interpretation_complete"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--input-sha256", required=True)
    args = parser.parse_args()
    input_raw, input_pin = regular(args.input, 256 * 1024)
    need(input_pin["sha256"] == args.input_sha256, "sealed interpretation input hash differs")
    inputs = json_object(input_raw)
    need(inputs.get("schema") == INPUT_SCHEMA and inputs.get("sealed") is True,
         "actual archive/auditor pins must be sealed before any output or parsing")
    _, self_pin = regular(Path(__file__).resolve(), 256 * 1024)
    need(inputs["interpretation_source_sha256"] == self_pin["sha256"], "interpretation source differs from sealed input")
    destination = Path(inputs["output_directory"])
    need(destination.is_absolute() and destination.resolve() == destination, "absolute direct output directory required")
    need(not destination.exists(), "interpretation output must be a new directory; failed outputs are never retried in place")
    destination.mkdir(mode=0o700)
    bindings = [input_pin, self_pin]
    out = {"schema": SCHEMA, "interpretation_complete": False, "counts": None,
           "original_workflow_passed": False, "original_records_modified": False,
           "performance_acceptance_claim": False, "candidate_adopted": False,
           "new_runtime_or_workload_started": False, "native_auditor_executed_here": False,
           "source": self_pin, "input": input_pin, "controllers": [], "errors": [],
           "scope": "new offline interval correlation and selective phase arithmetic over original immutable C1 evidence",
           "limitations": [
               "Trace native IDs are internal observations; no public wire native ID is invented or recovered.",
               "Unique controller/host/operation/whole-RPC containment is a new correlation method, not an original protocol ID.",
               "All ON calls and trace requests must form a strict bidirectional bijection; no nearest-time or order guess is allowed.",
               "All phases for measured requests are selected only after full-trace parser and arithmetic reconciliation.",
               "Nested wall durations and queue/lock/child spans are nonadditive and do not isolate network or remote CPU.",
               "Only synchronous same-thread spans have CPU attribution; awaited time and uninstrumented/background work remain outside it.",
               "Diagnostic bookkeeping and the wider, quantized controller counter window affect the signed CPU residual.",
               "OFF traces have no phase observations; empty traces do not mean zero runtime CPU.",
               "Large original round variation precludes treating OFF/ON differences as an optimization benefit or significance claim.",
               "Original failed parent/adapter remain failed; this derived analysis grants no runtime adoption or new performance gate.",
           ]}
    archive = None
    try:
        write_new(destination / "input.json", raw=input_raw)
        archive_raw = bound(inputs["archive"], ARCHIVE, bindings)
        manifest_raw = bound(inputs["archive_manifest"], MANIFEST, bindings, 2 * 1024 * 1024)
        archive = Originals(archive_raw, manifest_raw)
        interpret(inputs, out, archive, destination, bindings)
        for pin in bindings:
            need(regular(pin["path"], MAX_FILE)[1] == pin, "bound local input changed during interpretation")
        out["bound_local_inputs_unchanged"] = True
    except BaseException as error:
        out["interpretation_complete"] = False
        out["errors"].append({"type": type(error).__name__, "reason": str(error)[:3000]})
    finally:
        out["input_bindings"] = bindings
        out["selected_archive_members_rehashed"] = dict(archive.reads) if archive is not None else {}
        out["files_extracted"] = 0
        if archive is not None:
            archive.tar.close()
        final_pin = write_new(destination / "report.json", out)
    print(json.dumps({"interpretation_complete": out["interpretation_complete"], "report": final_pin,
                      "original_workflow_passed": False, "performance_acceptance_claim": False}))
    return 0 if out["interpretation_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
