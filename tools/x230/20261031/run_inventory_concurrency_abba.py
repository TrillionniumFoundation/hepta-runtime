#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fixed synthetic inventory concurrency comparison; no SSH or execution effects.

Two ABBA blocks, two APIs and C1/4/8 use 48 independent release controllers.
Each controller receives four waves of C requests plus periodic ping. Linux
wait4 accounts only its original child's complete lifetime, including initialize,
ping, the page continuation check and shutdown, not isolated list CPU/RSS.
"""
import argparse
import hashlib
import math
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import statistics
import sys
import time
import types


SUPPORT_SHA256 = "a9f840198a8d153862dd17732146039a50b45c969dad679173e5c447a79801ba"


def load_support():
    """Compile exactly the bounded bytes checked against the original helper pin."""
    path = Path(__file__).absolute().with_name("run_inventory_rss_abba.py")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 128 * 1024:
            raise RuntimeError("inventory support is not a bounded regular file")
        raw = stream.read(128 * 1024 + 1)
        stamp = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                              info.st_mtime_ns, info.st_ctime_ns)
        if (len(raw) != before.st_size or stamp(before) != stamp(os.fstat(stream.fileno()))
                or stamp(before) != stamp(path.lstat())
                or hashlib.sha256(raw).hexdigest() != SUPPORT_SHA256):
            raise RuntimeError("original inventory support bytes/identity differ")
    module = types.ModuleType("hepta_inventory_rss_support")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


s = load_support()
SCHEMA = "hepta-inventory-concurrency-abba/v1"
COUNT, PRIVATE_ARGUMENT_BYTES, WAVES, PAGE_LIMIT = 1024, 32 * 1024, 4, 128
CONCURRENCY, TOOLS = (1, 4, 8), ("process_list", "process_list_page")
PING_INTERVAL, MEASURE_TIMEOUT, RPC_TIMEOUT = 0.020, 120.0, 120.0
MAX_CAPTURE, MAX_INPUT = 16 * 1024 * 1024, 1024 * 1024
MAX_PINGS = math.ceil(MEASURE_TIMEOUT / PING_INTERVAL) + 1
MAX_REQUESTS = WAVES * max(CONCURRENCY) + MAX_PINGS + 2
PLAN = tuple({"attempt": index + 1, "block": block, "tool": tool,
              "concurrency": concurrency, "position": position, "arm": arm}
             for index, (block, tool, concurrency, position, arm) in enumerate(
                 (block, tool, concurrency, position, arm)
                 for block in (1, 2) for tool in TOOLS for concurrency in CONCURRENCY
                 for position, arm in enumerate("ABBA", 1)))


def public_row(index):
    return {"id": f"synthetic-list-{(index * 859) % COUNT:04d}",
            "host": s.HOSTS[index % len(s.HOSTS)], "created_unix_ms": 1700000000000 + index,
            "execution_mode": "operator", "launch_state": "launched"}


def synthetic_record(index):
    row = public_row(index)
    prefix = f"SYNTHETIC_PRIVATE_ARGUMENT_{index:04d}_"
    return {**row, "system_jobctl": False, "ssh_target": "synthetic.invalid",
            "unit": "synthetic-never-started", "remote_job_dir": "/synthetic/jobs/" + row["id"],
            "executable": "/synthetic/never-executed",
            "args": [prefix + "x" * (PRIVATE_ARGUMENT_BYTES - len(prefix))],
            "cwd": "/synthetic/workspace", "env_keys": ["SYNTHETIC_ENV"],
            "idempotency_key": None, "request_fingerprint": 0, "request_digest": None,
            "launch_error": None}


def make_fixture(directory):
    state, manifest = directory / "state", {}
    state.mkdir(mode=0o700)
    jobs = state / "jobs"
    jobs.mkdir(mode=0o700)
    for index in reversed(range(COUNT)):
        s.check_stop()
        raw = s.encoded(synthetic_record(index))
        name = public_row(index)["id"] + ".json"
        s.create(jobs / name, raw)
        manifest[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    config = {"state_dir": str(state), "hosts": {
        host: {"execution_mode": "operator", "ssh_target": "synthetic.invalid",
               "remote_state_dir": "/synthetic/never-contacted", "allow_execute": False,
               "allow_pty": False, "allow_write": False} for host in s.HOSTS}}
    path = directory / "synthetic-config.json"
    s.create(path, s.encoded(config) + b"\n")
    s.create(directory / "fixture-manifest.json", s.encoded(manifest) + b"\n")
    return path, jobs, manifest


class Expected:
    def __init__(self, namespace):
        chronological = [public_row(index) for index in range(COUNT)]
        self.rows = sorted(chronological, key=lambda row: row["id"])
        self.namespace = str(namespace)
        self.snapshot = hashlib.sha256(s.encoded(
            {"host": None, "namespace": self.namespace, "rows": self.rows})).hexdigest()
        self.legacy = s.encoded({"jobs": chronological, "total": COUNT,
                                "inventory_complete": True, "status_authoritative": False}).decode()
        self.pages = {}
        for start in (0, PAGE_LIMIT):
            end = start + PAGE_LIMIT
            self.pages[start] = s.encoded({"jobs": self.rows[start:end], "total": COUNT,
                "next_cursor": self.snapshot + ":" + self.rows[end - 1]["id"],
                "has_more": True, "inventory_complete": False,
                "snapshot_sha256": self.snapshot, "status_authoritative": False,
                "snapshot_semantics": "registry_metadata_at_observation"}).decode()


def validate_reply(reply, identity, kind, expected):
    s.need(isinstance(reply, dict) and set(reply) == {"jsonrpc", "id", "result"}
           and reply["jsonrpc"] == "2.0" and type(reply["id"]) is int
           and reply["id"] == identity, "RPC envelope/error differs")
    result = reply["result"]
    if kind == "initialize":
        s.need(isinstance(result, dict), "initialize result is not an object")
        return {"validated": True}
    if kind == "ping":
        s.need(result == {}, "ping result is not the empty success object")
        return {"validated": True}
    text = expected.legacy if kind == "process_list" else expected.pages[
        PAGE_LIMIT if kind == "continuation" else 0]
    s.need(isinstance(result, dict) and set(result) <= {"content", "isError"}
           and result.get("isError", False) is False
           and result.get("content") == [{"type": "text", "text": text}],
           "inventory result is not the exact complete expected page/ordered DTO")
    wire = s.encoded({"content": [{"type": "text", "text": text}], "isError": False})
    budget = s.WIRE_BUDGET if kind == "process_list" else 64 * 1024
    s.need(len(wire) < budget, "inventory SDK response exceeds the fixed wire allowance")
    return {"validated": True, "rows": COUNT if kind == "process_list" else PAGE_LIMIT,
            "inner_text_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "sdk_wire_bytes": len(wire),
            "snapshot_sha256": None if kind == "process_list" else expected.snapshot,
            "next_cursor": None if kind == "process_list" else s.decoded(text)["next_cursor"]}


class ConcurrentController(s.Controller):
    """Keep the original wait4 owner; only multiplex bounded request/response IO."""
    def __init__(self, directory):
        super().__init__(directory)
        self.files["stdin"] = (directory / "stdin.raw").open("xb")
        self.observed["stdin"] = 0
        self.requests, self.outstanding, self.received_set = {}, set(), set()

    def start(self, *args):
        super().start(*args)
        os.set_blocking(self.child.stdin.fileno(), False)

    def send(self, method, params, identity=None, kind=None, wave=None, scheduled=None):
        s.check_stop()
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        started = time.monotonic()
        if identity is not None:
            s.need(type(identity) is int and identity > 0 and identity not in self.requests
                   and len(self.requests) < MAX_REQUESTS, "duplicate or excessive request identity")
            message["id"] = identity
            self.requests[identity] = {"id": identity, "kind": kind, "wave": wave,
                "sent_monotonic": started, "submitted": False, "outcome": "not_submitted",
                "dispatch_lag_ms": None if scheduled is None else max(0, started - scheduled) * 1000}
        raw = s.encoded(message) + b"\n"
        s.need(len(raw) < 4096 and self.observed["stdin"] + len(raw) <= MAX_INPUT,
               "request or original-input capture budget exceeded")
        try:
            written = os.write(self.child.stdin.fileno(), raw)
        except (BlockingIOError, BrokenPipeError) as error:
            if identity is not None:
                self.requests[identity]["submission_error"] = type(error).__name__
            raise RuntimeError("original request pipe unavailable; no request retry") from error
        self.files["stdin"].write(raw[:written])
        self.observed["stdin"] += written
        if identity is not None:
            self.requests[identity]["written_bytes"] = written
            self.requests[identity]["submitted"] = written == len(raw)
            self.requests[identity]["outcome"] = "no_response" if written == len(raw) else "partial_write_unknown"
        s.need(written == len(raw), "partial original request write; outcome unknown, no retry")
        if identity is not None:
            self.outstanding.add(identity)
        return started

    def consume(self, name, raw):
        before = self.observed[name]
        self.observed[name] += len(raw)
        retained = raw[:max(0, MAX_CAPTURE - before)]
        if retained:
            self.files[name].write(retained)
        if self.observed[name] > MAX_CAPTURE and before <= MAX_CAPTURE:
            self.error(name + " capture exceeded its retained byte bound")
        if name != "stdout" or not self.parse_stdout:
            return
        try:
            self.buffer.extend(raw)
            while b"\n" in self.buffer:
                length = self.buffer.index(b"\n") + 1
                s.need(length <= s.MAX_LINE, "stdout protocol line exceeds its bound")
                value = s.decoded(bytes(self.buffer[:length]))
                del self.buffer[:length]
                s.need(isinstance(value, dict) and value.get("jsonrpc") == "2.0",
                       "invalid JSON-RPC message")
                if "id" not in value:
                    s.need(isinstance(value.get("method"), str) and "result" not in value
                           and "error" not in value, "invalid server notification")
                    self.notifications += 1
                    s.need(self.notifications <= 16, "too many server notifications")
                    continue
                identity = value["id"]
                s.need(type(identity) is int and identity in self.outstanding
                       and identity not in self.received_set, "unexpected or repeated RPC identity")
                s.need(set(value) in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"}),
                       "invalid RPC response envelope")
                received = time.monotonic()
                self.received_set.add(identity)
                self.received_ids.append(identity)
                self.outstanding.remove(identity)
                self.requests[identity].update(received_monotonic=received,
                    elapsed_ms=(received - self.requests[identity]["sent_monotonic"]) * 1000,
                    outcome="response_unvalidated")
                self.replies[identity] = (value, received)
            s.need(len(self.buffer) < s.MAX_LINE, "unterminated stdout line exceeds its bound")
        except Exception as error:
            self.error(error)
            self.parse_stdout = False
            self.buffer.clear()


def accept(controller, identity, expected):
    reply, received = controller.replies.pop(identity)
    row = controller.requests[identity]
    try:
        row["response"] = validate_reply(reply, identity, row["kind"], expected)
        row["outcome"] = "success"
    except Exception as error:
        row.update(outcome="invalid_response", error=str(error)[:500])
        raise
    return received


def measure(controller, tool, concurrency, expected):
    next_id, pings, next_ping = 2, 0, time.monotonic()
    started, waves, tool_ids = next_ping, [], []
    for wave in range(WAVES):
        ids = []
        for _ in range(concurrency):
            controller.send("tools/call", {"name": tool, "arguments":
                {} if tool == "process_list" else {"limit": PAGE_LIMIT}}, next_id, tool, wave)
            ids.append(next_id)
            tool_ids.append(next_id)
            next_id += 1
        while any(controller.requests[identity]["outcome"] != "success" for identity in ids):
            s.check_stop()
            s.need(not controller.errors, "; ".join(controller.errors))
            for identity in list(controller.replies):
                accept(controller, identity, expected)
            if all(controller.requests[identity]["outcome"] == "success" for identity in ids):
                break
            now = time.monotonic()
            s.need(now - started < MEASURE_TIMEOUT, "fixed measurement deadline exceeded; no retry")
            if now >= next_ping:
                s.need(pings < MAX_PINGS, "fixed ping submission bound exceeded")
                sent = controller.send("ping", {}, next_id, "ping", wave, next_ping)
                next_id += 1
                pings += 1
                # Target periodic sampling, without a catch-up burst after receiver delay.
                next_ping = sent + PING_INTERVAL
            s.need(bool(controller.selector.get_map()), "controller exited with unresolved requests")
            controller.pump(max(0, min(0.02, next_ping - time.monotonic())))
        waves.append({"wave": wave, "ids": ids,
            "seconds": max(controller.requests[i]["received_monotonic"] for i in ids)
                     - min(controller.requests[i]["sent_monotonic"] for i in ids)})
    measured_seconds = max(controller.requests[i]["received_monotonic"] for i in tool_ids) - started
    # Finish already submitted pings; these do not extend the inventory throughput denominator.
    deadline = time.monotonic() + RPC_TIMEOUT
    while controller.outstanding or controller.replies:
        s.check_stop()
        s.need(not controller.errors, "; ".join(controller.errors))
        for identity in list(controller.replies):
            accept(controller, identity, expected)
        if not controller.outstanding:
            break
        s.need(time.monotonic() < deadline and bool(controller.selector.get_map()),
               "pending ping timeout or original child exit")
        controller.pump(0.02)
    if tool == "process_list_page":
        cursor = controller.requests[tool_ids[0]]["response"]["next_cursor"]
        controller.send("tools/call", {"name": tool, "arguments":
            {"limit": PAGE_LIMIT, "cursor": cursor}}, next_id, "continuation")
        reply, received = controller.reply(next_id, RPC_TIMEOUT)
        controller.replies[next_id] = (reply, received)
        accept(controller, next_id, expected)
    return {"seconds": measured_seconds, "waves": waves, "tool_calls": len(tool_ids),
            "ping_calls": pings, "continuation_calls": int(tool == "process_list_page")}


def validate_completion(row):
    shutdown, requests = row["shutdown"], row["requests"]
    s.need(shutdown.get("started") is True and shutdown.get("reaped") is True
           and shutdown.get("exit_code") == 0 and shutdown.get("raw_wait_status") == 0
           and type(shutdown.get("original_pid")) is int and shutdown["original_pid"] > 0
           and type(shutdown.get("actual_wait4_pid")) is int
           and shutdown.get("actual_wait4_pid") == shutdown["original_pid"]
           and shutdown.get("shutdown_signals") == [] and shutdown.get("capture_errors") == [],
           "original child did not complete cleanly with its own wait4 receipt")
    identities = [request["id"] for request in requests]
    s.need(len(identities) == len(set(identities)) <= MAX_REQUESTS
           and sorted(shutdown.get("received_response_ids", [])) == sorted(identities)
           and all(request.get("submitted") is True and request.get("outcome") == "success"
                   and request.get("response", {}).get("validated") is True for request in requests),
           "missing, duplicate, unknown, failed or unvalidated original RPC")
    kinds = [request["kind"] for request in requests]
    s.need(kinds.count("initialize") == 1
           and kinds.count(row["tool"]) == WAVES * row["concurrency"]
           and 1 <= kinds.count("ping") <= MAX_PINGS
           and kinds.count("continuation") == int(row["tool"] == "process_list_page")
           and set(kinds) <= {"initialize", "ping", row["tool"], "continuation"},
           "original RPC matrix is incomplete")
    measurement = row["measurement"]
    s.need(type(measurement["seconds"]) in (int, float) and math.isfinite(measurement["seconds"])
           and 0 < measurement["seconds"] <= MEASURE_TIMEOUT
           and measurement["tool_calls"] == WAVES * row["concurrency"]
           and measurement["ping_calls"] == kinds.count("ping"), "measurement accounting differs")
    for wave in range(WAVES):
        expected = [request["id"] for request in requests
                    if request["kind"] == row["tool"] and request["wave"] == wave]
        s.need(len(expected) == row["concurrency"] and len(measurement["waves"]) == WAVES
               and measurement["waves"][wave]["wave"] == wave
               and measurement["waves"][wave]["ids"] == expected,
               "original measured wave membership differs")


def attempt(specification, binding, directory, wrapper, wrapper_sha):
    row = {**specification, "okay": False, "started_utc": s.utc(), "errors": [],
           "binary_sha256": binding["binary_sha256"]}
    directory.mkdir(mode=0o700)
    s.save(directory / "started.json", row)
    controller, fixture = ConcurrentController(directory), None
    try:
        config, jobs, manifest = make_fixture(directory)
        fixture = (config, jobs, manifest, s.sha(config))
        expected = Expected(jobs.parent)
        row["namespace"], row["snapshot_sha256"] = expected.namespace, expected.snapshot
        s.create(directory / "expected.json", s.encoded({"namespace": expected.namespace,
            "snapshot_sha256": expected.snapshot, "legacy": s.decoded(expected.legacy),
            "first_page": s.decoded(expected.pages[0]),
            "continuation": s.decoded(expected.pages[PAGE_LIMIT])}) + b"\n")
        s.verify_binding(binding)
        s.pinned_file(wrapper, wrapper_sha)
        denial = directory / "ssh-denied.log"
        s.create(denial, b"")
        # The identical full sorted read is the final fixture action before startup.
        row["fixture_before"] = s.verify_fixture(jobs, manifest)
        s.need(row["fixture_before"]["records"] == COUNT
               and COUNT * PRIVATE_ARGUMENT_BYTES <= row["fixture_before"]["bytes"] < 128 * 1024 * 1024,
               "synthetic fixture exceeds the unchanged page reader source budget")
        controller.start(binding["binary"], config, wrapper, denial)
        controller.send("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "hepta-inventory-concurrency-abba", "version": "1"}},
            1, "initialize")
        reply, received = controller.reply(1, 60)
        controller.replies[1] = (reply, received)
        accept(controller, 1, expected)
        controller.send("notifications/initialized", {})
        row["measurement"] = measure(controller, row["tool"], row["concurrency"], expected)
    except Exception as error:
        row["errors"].append(type(error).__name__ + ": " + str(error)[:500])
        if "timeout" in str(error).lower() or "deadline" in str(error).lower():
            row["timed_out"] = True
            for request in controller.requests.values():
                if request["outcome"] == "no_response":
                    request["outcome"] = "timeout_unknown"
    finally:
        try:
            row["shutdown"] = controller.close()
            row["requests"] = list(controller.requests.values())
            validate_completion(row)
        except Exception as error:
            row["shutdown"] = controller.reaped or {"started": False}
            row["requests"] = list(controller.requests.values())
            row["errors"].append("shutdown/RPC completeness: " + str(error)[:500])
        try:
            s.need(fixture is not None, "fixture was not completely created")
            config, jobs, manifest, config_sha = fixture
            row["fixture_after"] = s.verify_fixture(jobs, manifest)
            s.need(row.get("fixture_before") == row["fixture_after"], "fixture pre/post differs")
            s.pinned_file(config, config_sha)
            s.need(s.checked_file(directory / "ssh-denied.log", capture=True)["content"] == b"",
                   "synthetic list workload attempted SSH")
            s.verify_binding(binding)
            s.pinned_file(wrapper, wrapper_sha)
            row["inputs_unchanged"] = True
        except Exception as error:
            row["errors"].append("input verification: " + str(error)[:500])
        s.create(directory / "rpc-ledger.jsonl", b"".join(
            s.encoded(request) + b"\n" for request in row["requests"]))
        row["artifacts"] = {name: {"sha256": s.sha(path), "bytes": path.stat().st_size}
            for name in ("stdin.raw", "stdout.raw", "stderr.raw", "rpc-ledger.jsonl", "expected.json",
                         "fixture-manifest.json", "synthetic-config.json", "ssh-denied.log")
            if (path := directory / name).is_file()}
        row["finished_utc"], row["okay"] = s.utc(), not row["errors"]
        s.save(directory / "attempt.json", row)
    return row


def latency(values):
    s.need(values and all(type(value) in (int, float) and math.isfinite(value) and value >= 0
                         for value in values), "invalid or incomplete latency samples")
    ordered = sorted(values)
    return {"count": len(values), "mean": statistics.mean(values), "p50": statistics.median(values),
            "p95": ordered[math.ceil(len(values) * 0.95) - 1],
            "p99": ordered[math.ceil(len(values) * 0.99) - 1], "max": max(values)}


def summarize(rows):
    s.need(len(rows) == len(PLAN), "incomplete fixed experiment; no comparison")
    for specification, row in zip(PLAN, rows):
        s.need(all(type(row.get(key)) is type(value) and row[key] == value
                   for key, value in specification.items()) and row.get("okay") is True
               and row.get("errors") == [] and row.get("inputs_unchanged") is True,
               "changed order, failed attempt or excluded first attempt; no comparison")
        validate_completion(row)
        s.need(row.get("fixture_before") == row.get("fixture_after")
               and row["fixture_before"]["records"] == COUNT
               and COUNT * PRIVATE_ARGUMENT_BYTES <= row["fixture_before"]["bytes"] < 128 * 1024 * 1024,
               "incomplete or changed synthetic fixture")

    def section(selected):
        cells = []
        for tool in TOOLS:
            for concurrency in CONCURRENCY:
                cell = {"tool": tool, "concurrency": concurrency, "arms": {}}
                for arm in "AB":
                    group = [row for row in selected if row["tool"] == tool
                             and row["concurrency"] == concurrency and row["arm"] == arm]
                    calls = [request["elapsed_ms"] for row in group for request in row["requests"]
                             if request["kind"] == tool]
                    pings = [request["elapsed_ms"] for row in group for request in row["requests"]
                             if request["kind"] == "ping"]
                    seconds = sum(row["measurement"]["seconds"] for row in group)
                    cpu = sum(row["shutdown"]["child_cpu_ms"] for row in group)
                    cell["arms"][arm] = {"controllers": len(group), "calls": len(calls),
                        "seconds": seconds, "calls_per_second": len(calls) / seconds,
                        "latency_ms": latency(calls), "ping_ms": latency(pings),
                        "ping_dispatch_lag_ms": latency([request["dispatch_lag_ms"] for row in group
                            for request in row["requests"] if request["kind"] == "ping"]),
                        "whole_child_cpu_ms": s.numbers([row["shutdown"]["child_cpu_ms"] for row in group]),
                        "whole_child_cpu_ms_per_measured_call": cpu / len(calls),
                        "maxrss_kib": s.numbers([row["shutdown"]["maxrss_kib"] for row in group])}
                a, b = cell["arms"]["A"], cell["arms"]["B"]
                ratio = lambda first, second: 100 * (second / first - 1) if first else None
                cell["B_vs_A_percent"] = {"calls_per_second": ratio(a["calls_per_second"], b["calls_per_second"]),
                    "latency_p95": ratio(a["latency_ms"]["p95"], b["latency_ms"]["p95"]),
                    "latency_p99": ratio(a["latency_ms"]["p99"], b["latency_ms"]["p99"]),
                    "ping_p99": ratio(a["ping_ms"]["p99"], b["ping_ms"]["p99"]),
                    "peak_rss_median": ratio(a["maxrss_kib"]["median"], b["maxrss_kib"]["median"]),
                    "whole_child_cpu_per_call": ratio(a["whole_child_cpu_ms_per_measured_call"],
                                                     b["whole_child_cpu_ms_per_measured_call"])}
                cells.append(cell)
        return cells
    return {"pooled": section(rows), "per_block": [
        {"block": block, "cells": section([row for row in rows if row["block"] == block])}
        for block in (1, 2)], "inclusion": "all 48 original controllers; all four waves and every ping",
        "tail_scope": "raw-call nearest-rank p95/p99, median p50; finite samples, no significance claim"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("baseline", "candidate"):
        for kind in ("qualification", "source-map", "audit"):
            parser.add_argument("--" + label + "-" + kind, type=Path, required=True)
            parser.add_argument("--" + label + "-" + kind + "-sha256", required=True)
    parser.add_argument("--harness-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    s.need(sys.flags.isolated and sys.dont_write_bytecode, "launch with /usr/bin/python3 -I -B")
    s.need(sys.platform == "linux" and hasattr(os, "wait4"), "requires Linux wait4 RSS units")
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, s.stop_requested)
    harness = s.pinned_file(Path(__file__).absolute(), args.harness_sha256)
    support = s.pinned_file(Path(s.__file__), SUPPORT_SHA256)
    bindings = {arm: s.qualification_binding(*(
        getattr(args, label + "_" + suffix)
        for suffix in ("qualification", "qualification_sha256", "source_map", "source_map_sha256",
                       "audit", "audit_sha256")))
        for arm, label in (("A", "baseline"), ("B", "candidate"))}
    s.need(bindings["A"]["binary_sha256"] != bindings["B"]["binary_sha256"], "A/B retained ELF hashes are equal")
    output = args.output.absolute()
    s.need(output.parent.resolve(strict=True) == output.parent and not output.exists(),
           "output must be a fresh directory with a direct existing parent")
    for binding in bindings.values():
        s.need(all(not output.resolve().is_relative_to(path.resolve()) for path in
                   (binding["source"], binding["report"].parent, binding["summary"].parent)),
               "output cannot alter an original source/qualification/evidence tree")
    s.need(shutil.disk_usage(output.parent).free >= len(PLAN) * (
        COUNT * (PRIVATE_ARGUMENT_BYTES + 1024) + 2 * MAX_CAPTURE + MAX_INPUT) + 256 * 1024 * 1024,
        "insufficient space to retain all fixed fixtures and bounded original captures")
    output.mkdir(mode=0o700)
    tools = output / "deny-tools"
    tools.mkdir(mode=0o700)
    wrapper = tools / "ssh"
    s.create(wrapper, s.DENY_SSH, 0o700)
    wrapper_sha = hashlib.sha256(s.DENY_SSH).hexdigest()
    report = {"schema": SCHEMA, "complete": False, "started_utc": s.utc(), "attempts": [],
        "planned_attempts": list(PLAN), "automatic_retries": 0,
        "harness_sha256": args.harness_sha256, "support_sha256": SUPPORT_SHA256,
        "records": COUNT, "private_argument_bytes_per_record": PRIVATE_ARGUMENT_BYTES,
        "waves": WAVES, "page_limit": PAGE_LIMIT, "tokio_worker_threads": 2,
        "ping_target_interval_seconds": PING_INTERVAL, "measurement_timeout_seconds": MEASURE_TIMEOUT,
        "max_capture_bytes_per_output_stream": MAX_CAPTURE, "max_input_capture_bytes": MAX_INPUT,
        "max_rpc_requests_per_controller": MAX_REQUESTS,
        "latency_scope": "request write through complete JSON-RPC decode; validation happens afterward",
        "throughput_scope": "four waves, first tool submission through last tool response; no continuation",
        "ping_scope": "20 ms target during tool waves; actual dispatch lag retained; no catch-up bursts",
        "resource_scope": "original child wait4 lifetime RSS KiB and CPU including initialize, ping, continuation, shutdown",
        "cache_scope": "fresh controller/state per cell; identical full sorted receipt read/hash warming",
        "page_scope": "first page always rescans; one continuation is validated outside measured calls; per-state namespace hash",
        "bindings": {arm: {key: str(value) if isinstance(value, Path) else value
                            for key, value in binding.items() if key != "sources"}
                     for arm, binding in bindings.items()}}
    s.save(output / "report.json", report)
    try:
        for specification in PLAN:
            s.check_stop()
            s.pinned_file(harness, args.harness_sha256)
            s.pinned_file(support, SUPPORT_SHA256)
            report["current_attempt"] = specification
            s.save(output / "report.json", report)
            row = attempt(specification, bindings[specification["arm"]],
                          output / f"attempt-{specification['attempt']:02d}", wrapper, wrapper_sha)
            report["attempts"].append(row)
            s.save(output / "report.json", report)
            print(s.encoded({**specification, "okay": row["okay"]}).decode(), flush=True)
            s.need(row["okay"], "original attempt failed; retained without retry or replacement")
        report.pop("current_attempt", None)
        for binding in bindings.values():
            s.verify_binding(binding)
        s.pinned_file(harness, args.harness_sha256)
        s.pinned_file(support, SUPPORT_SHA256)
        s.pinned_file(wrapper, wrapper_sha)
        s.check_stop()
        report["summary"] = summarize(report["attempts"])
        report["inputs_unchanged"], report["complete"] = True, True
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)[:500]
    finally:
        s.refuse_stopped_report(report)
        report["finished_utc"] = s.utc()
        s.save(output / "report.json", report)
        if s.STOP_SIGNAL is not None and report["complete"]:
            s.refuse_stopped_report(report)
            s.save(output / "report.json", report)
        print(s.encoded({"complete": report["complete"], "attempts": len(report["attempts"]),
                        "report_sha256": s.sha(output / "report.json")}).decode(), flush=True)
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        sys.exit(1)
