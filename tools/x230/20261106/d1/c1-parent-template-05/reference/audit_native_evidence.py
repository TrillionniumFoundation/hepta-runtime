#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Rehash R16 raw stdout and resource traces without importing the producer."""
from collections import Counter
import hashlib
import json
import math
from pathlib import Path


def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def near(left, right, reason):
    need(math.isfinite(left) and math.isfinite(right)
         and math.isclose(left, right, rel_tol=1e-12, abs_tol=1e-9), reason)


def bound_file(directory, manifest):
    name = manifest["file"]
    need(isinstance(name, str) and Path(name).name == name, "trace filename is not a basename")
    path = directory / name
    need(not path.is_symlink(), "trace file is a symlink")
    raw = path.read_bytes()
    need(len(raw) == manifest["bytes"] and sha(raw) == manifest["sha256"], "trace bytes/hash changed: " + name)
    return raw


def topology(directory, report):
    receipt = report["topology"]
    manifest = json.loads(bound_file(Path(directory), receipt))
    aliases = {"ai395", "mac", "main", "pocket4", "rog", "x230"}
    need(manifest["schema"] == "hepta-x230-benchmark-topology/v1"
         and manifest["hosts"] == receipt["hosts"] and set(manifest["hosts"]) == aliases
         and manifest["profile_template_sha256"] == receipt["profile_template_sha256"]
         == report["profile"]["template_sha256"], "topology manifest/profile binding differs")
    need(report["topology_manifest_unchanged"] is True and receipt["alias_count"] == len(aliases)
         and receipt["physical_machine_groups"] == len({x["machine_group"] for x in manifest["hosts"].values()})
         and all(x["platform"] in {"linux", "macos"} for x in manifest["hosts"].values()), "topology aliases/groups/platforms differ")
    return {"verified": True, "alias_count": receipt["alias_count"],
            "physical_machine_groups": receipt["physical_machine_groups"], "manifest_sha256": receipt["sha256"]}


def stat_counters(value):
    raw = value["raw_stat"]
    left, right = raw.find("("), raw.rfind(") ")
    fields = raw[right + 2:].split()
    need(left >= 0 and right > left and len(fields) >= 20, "raw proc stat malformed")
    expected = {"pid": int(raw[:left].strip()), "comm": raw[left + 1:right],
                "ppid": int(fields[1]), "birth_ticks": int(fields[19]),
                "utime_ticks": int(fields[11]), "stime_ticks": int(fields[12])}
    need(all(value[key] == item for key, item in expected.items()), "raw proc stat fields differ")
    need(fields[0] not in {"Z", "X"} and type(value["clock_ticks_per_second"]) is int
         and value["clock_ticks_per_second"] > 0, "invalid live CPU counter")
    need(type(value["read_start_monotonic_ns"]) is int and type(value["read_end_monotonic_ns"]) is int
         and 0 < value["read_start_monotonic_ns"] <= value["read_end_monotonic_ns"], "proc clock endpoints differ")
    need(value["utime_ticks"] >= 0 and value["stime_ticks"] >= 0, "negative CPU ticks")
    return (value["utime_ticks"] + value["stime_ticks"]) / value["clock_ticks_per_second"]


def inspect_timing(cell):
    timing = cell["raw_timing"]
    before, after = timing["controller_before"], timing["controller_after"]
    stat_counters(before)
    stat_counters(after)
    need((before["pid"], before["birth_ticks"], before["clock_ticks_per_second"])
         == (after["pid"], after["birth_ticks"], after["clock_ticks_per_second"]), "CPU endpoint generation differs")
    start, end = timing["start_monotonic_ns"], timing["end_monotonic_ns"]
    need(type(start) is int and type(end) is int and before["read_end_monotonic_ns"] <= start < end
         <= after["read_start_monotonic_ns"], "cell clock/counter ordering differs")
    near((end - start) / 1e9, cell["seconds"], "cell wall time differs from raw endpoints")
    cpu = (after["utime_ticks"] + after["stime_ticks"] - before["utime_ticks"] - before["stime_ticks"]) / before["clock_ticks_per_second"]
    near(cpu, cell["controller_cpu_seconds"], "cell CPU differs from raw ticks")
    for row in cell["rows"]:
        need(start <= row["start_monotonic_ns"] <= row["end_monotonic_ns"] <= end,
             "call clock lies outside measured cell")


class Transport:
    def __init__(self, directory, capture):
        need(capture["schema"] == "hepta-native-raw-transport/v1" and capture["reader_eof"] is True,
             "transport capture did not reach normal EOF")
        raw = bound_file(directory, capture["raw"])
        index = bound_file(directory, capture["index"])
        entries = [json.loads(line) for line in index.splitlines()]
        need(len(entries) == capture["frames"], "transport frame count differs")
        self.frames, self.used = {}, set()
        offset, last_receive = 0, 0
        for sequence, entry in enumerate(entries):
            count = entry["bytes"]
            need(entry["sequence"] == sequence and entry["offset"] == offset and type(count) is int and count > 0,
                 "transport offsets are not complete/contiguous")
            line = raw[offset:offset + count]
            need(len(line) == count and sha(line) == entry["sha256"]
                 and line.endswith(b"\n") and entry["complete_line"] is True
                 and "parse_error" not in entry, "raw response frame/hash differs")
            reply = json.loads(line)
            need(isinstance(reply, dict) and entry["has_id"] is ("id" in reply)
                 and entry["rpc_id"] == reply.get("id"), "raw response ID differs")
            need(0 < entry["read_start_monotonic_ns"] <= entry["received_monotonic_ns"]
                 and last_receive <= entry["received_monotonic_ns"], "transport receive clocks differ")
            self.frames[sequence] = (entry, reply)
            offset += count
            last_receive = entry["received_monotonic_ns"]
        need(offset == len(raw), "unindexed transport bytes remain")

    def rpc(self, proof, method, params):
        reference = proof["transport_response"]
        need(reference is not None and reference["file"] == "transport-responses.jsonl", "complete response reference missing")
        sequence = reference["sequence"]
        need(sequence in self.frames and sequence not in self.used, "duplicate/missing raw response reference")
        entry, reply = self.frames[sequence]
        need({key: value for key, value in reference.items() if key != "file"} == entry,
             "response reference differs from raw index")
        need(reply.get("id") == proof["request_id"], "response belongs to another RPC")
        request = canonical({"jsonrpc": "2.0", "id": proof["request_id"], "method": method, "params": params})
        need(sha(request) == proof["request_sha256"] and len(request) == proof["request_bytes"], "request binding differs")
        need(0 < proof["rpc_start_monotonic_ns"] <= proof["send_start_monotonic_ns"]
             <= proof["send_end_monotonic_ns"] <= proof["response_dequeued_monotonic_ns"] <= proof["rpc_end_monotonic_ns"],
             "RPC clock endpoints differ")
        need(proof["send_start_monotonic_ns"] <= entry["received_monotonic_ns"]
             <= proof["response_dequeued_monotonic_ns"], "receive timestamp outside RPC")
        self.used.add(sequence)
        return reply

    def initialize(self, startup):
        reply = self.rpc(startup["initialize_rpc"], "initialize", {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "hepta-x230-observation-abba", "version": "1"}})
        need("error" not in reply and reply["result"].get("serverInfo") == startup["server_info"]
             and reply["result"].get("protocolVersion") == startup["stdio_protocol"], "initialize envelope differs")

    def call(self, row, original):
        args = {"host": row["host"], "job_id": row["job_id"]}
        if row["tool"] == "process_read":
            args.update(stdout_offset=0, stderr_offset=0, limit=16384)
        reply = self.rpc(row["rpc"], "tools/call", {"name": row["tool"], "arguments": args})
        need(sha(canonical(reply)) == row["response_sha256"] and "error" not in reply, "canonical response hash/error differs")
        need(row["start_monotonic_ns"] <= row["rpc"]["rpc_start_monotonic_ns"]
             <= row["rpc"]["rpc_end_monotonic_ns"] <= row["end_monotonic_ns"], "row and RPC endpoints differ")
        near((row["end_monotonic_ns"] - row["start_monotonic_ns"]) / 1e6, row["elapsed_ms"], "call latency differs from raw clocks")
        result = reply["result"]
        need(not result.get("isError", False) and row["isError"] is False, "native result failed")
        texts = [part["text"] for part in result["content"] if part.get("type") == "text"]
        need(texts, "native response has no JSON text")
        dto = json.loads(texts[0])
        need(sha(canonical(dto)) == row["dto_sha256"] and dto.get("job_id") == original["job_id"]
             and dto.get("audit_recorded") is True and "audit_warning" not in dto, "raw DTO identity/hash/audit differs")
        if row["tool"] == "process_status":
            need(dto.get("state") == "succeeded" and dto.get("exit_code") == 0 and dto.get("output_complete") is True
                 and not dto.get("cancelled") and not dto.get("timed_out"), "raw terminal status differs")
            need(dto.get("log_bytes") == {"stdout": {"seen": original["stdout_bytes"], "stored": original["stdout_bytes"]},
                                         "stderr": {"seen": 0, "stored": 0}}
                 and dto.get("log_truncated") == {"stdout": False, "stderr": False}
                 and dto.get("log_errors") == {"stdout": None, "stderr": None}, "raw capture completeness differs")
        else:
            need(row["tool"] == "process_read", "unexpected effectful tool")
            for name in ("stdout", "stderr"):
                part = dto[name]
                content = bytes.fromhex(part["bytes_hex"])
                expected_hash = original["stdout_sha256"] if name == "stdout" else sha(b"")
                expected_size = original["stdout_bytes"] if name == "stdout" else 0
                need(sha(content) == row[name + "_sha256"] == expected_hash
                     and len(content) == row[name + "_bytes"] == expected_size
                     and part["offset"] == 0 and part["next_offset"] == part["size"] == expected_size
                     and part["eof"] is True, "raw output/cursor differs")

    def finish(self):
        unused = [entry for sequence, (entry, _) in self.frames.items() if sequence not in self.used]
        need(all(not entry["has_id"] for entry in unused), "unmatched raw RPC response remains")
        return {"frames_rehashed": len(self.frames), "rpc_envelopes_independently_verified": len(self.used),
                "notifications_retained": len(unused)}


def resources(directory, value, startup):
    need(value["sampler_error"] is None, "resource sampler failed")
    raw = bound_file(directory, value["trace"])
    records = [json.loads(line) for line in raw.splitlines()]
    need(len(records) == value["trace"]["records"] == value["samples"], "resource trace sample count differs")
    seen, kinds, missing, errors = {}, {}, Counter(), []
    peaks = {key: 0 for key in value["peaks"]}
    metrics = Counter()
    for index, sample in enumerate(records):
        need(sample["sample"] == index and 0 < sample["start_monotonic_ns"] <= sample["end_monotonic_ns"], "sample clocks/sequence differ")
        totals, counts, parents = Counter(), Counter(), {}
        for process in sample["processes"]:
            before, after = process["before"], process["after"]
            cpu = stat_counters(before)
            stat_counters(after)
            identity = (before["pid"], before["birth_ticks"])
            need(identity == (after["pid"], after["birth_ticks"]) and before["ppid"] == after["ppid"], "sample process identity differs")
            need(sample["start_monotonic_ns"] <= before["read_start_monotonic_ns"] <= before["read_end_monotonic_ns"]
                 <= after["read_start_monotonic_ns"] <= after["read_end_monotonic_ns"] <= sample["end_monotonic_ns"], "process sample clocks differ")
            need(before["pid"] not in parents, "duplicate sample PID")
            executable = process["executable_basename"]
            if identity == (startup["pid"], startup["birth_ticks"]):
                scope = "controller"
            else:
                need(parents.get(before["ppid"]) == process["parent_birth_ticks"], "descendant does not bind to observed parent generation")
                scope = ("unknown_descendants" if executable is None else "ssh_descendants"
                         if executable.removesuffix(" (deleted)") == "ssh" else "other_descendants")
            need(process["scope"] == scope, "SSH/controller resource classification differs")
            parents[before["pid"]] = before["birth_ticks"]
            seen[identity] = max(cpu, seen.get(identity, 0))
            kinds[identity] = scope if kinds.get(identity, scope) == scope else "mixed_descendants"
            metrics[scope + "_cpu"] += 1
            status = process["status_fields"] or {}
            for field, key in (("rss_kib", "VmRSS"), ("hwm_kib", "VmHWM")):
                expected = None if key not in status else int(status[key].split()[0])
                need(process[field] == expected, "raw selected status field differs")
            fds = process["fd_numbers"]
            need(fds is None or all(type(fd) is int and fd >= 0 for fd in fds) and fds == sorted(set(fds)), "raw FD enumeration differs")
            need(process["fd_count"] == (None if fds is None else len(fds)), "FD count differs")
            for suffix, field in (("rss_kib", "rss_kib"), ("fd", "fd_count")):
                number = process[field]
                if number is not None:
                    totals[scope + "_" + suffix] += number
                    counts[scope + "_" + suffix] += 1
                    totals["tree_" + suffix] += number
                    counts["tree_" + suffix] += 1
            if scope == "controller" and process["hwm_kib"] is not None:
                totals["controller_hwm_kib"] = process["hwm_kib"]
                counts["controller_hwm_kib"] = 1
        for key, count in counts.items():
            peaks[key] = max(peaks[key], totals[key])
            metrics[key] += 1
            metrics[key + "_process_observations"] += count
        peaks["descendants"] = max(peaks["descendants"], sum(p["scope"] != "controller" for p in sample["processes"]))
        for item in sample["missing"]:
            missing[item["stage"] + ":" + item["type"]] += 1
            if len(errors) < 16:
                errors.append(item)
    cpu_by_scope = {scope: 0.0 for scope in value["sampled_cpu_seconds_by_scope"]}
    generations = Counter()
    for identity, cpu in seen.items():
        cpu_by_scope[kinds[identity]] += cpu
        generations[kinds[identity]] += 1
    need(peaks == value["peaks"] and dict(metrics) == value["metric_samples"], "resource raw peaks/counts differ")
    need(dict(missing) == value["error_counts"] and errors == value["errors"], "missing resource observations were dropped")
    need(dict(generations) == value["sampled_process_generations_by_scope"]
         and len(seen) == value["sampled_process_generations"], "resource generation counts differ")
    for scope, cpu in cpu_by_scope.items():
        near(cpu, value["sampled_cpu_seconds_by_scope"][scope], "resource lifetime CPU class differs")
    near(sum(cpu_by_scope.values()), value["sampled_tree_cpu_seconds"], "resource tree CPU differs")
    return {"trace_records_recomputed": len(records), "process_generations": len(seen),
            "sampled_cpu_seconds_by_scope": cpu_by_scope, "missing_observations": dict(missing)}


def audit_round(directory, round_, originals):
    counts = Counter()
    resource_reports = []
    for phase, startup_key, shutdown_key in (("first", "startup", "shutdown"), ("restart", "restart_startup", "restart_shutdown")):
        startup, shutdown = round_[startup_key], round_[shutdown_key]
        transport = Transport(directory / phase, shutdown["transport_capture"])
        transport.initialize(startup)
        if phase == "first":
            rows = list(round_["initial_complete_outputs"])
            for cell in round_["cells"]:
                for part in (cell["warmup"], cell):
                    inspect_timing(part)
                    rows.extend(part["rows"])
        else:
            rows = round_["restart_checks"]
        for row in rows:
            transport.call(row, originals[row["host"]])
        counts.update(transport.finish())
        resource_reports.append({"phase": phase, **resources(directory / phase, shutdown["resources"], startup)})
    return {"transport": dict(counts), "resource_traces": resource_reports}
