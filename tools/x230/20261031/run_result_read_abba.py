#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Hot native request_status/request_result guard, two ABBA blocks at C1/C4/C8.

Uses a SHA-pinned existing controller for private fixtures, process creation,
wire archives and owned-child wait4 cleanup. Only its C1 response routing is
adapted to an ID-indexed rolling window. No SSH, authentication profile, remote
execution, production state, retries, or Rust build is performed by this script.

Each controller seeds 32 actual host_list results. Status/result observations
create additional audit records in this protocol; this is NOT a constant-size
32-record audit benchmark. All controllers receive the same ordered workload.
The measurement includes native auditing and the entire public read route, not
just the result-store semaphore. Results are descriptive guards, not proof of
statistical significance, p99 improvement, or global optimality.

First use --fingerprint-source ROOT to obtain each frozen source SHA256. Then
provide both source roots/hashes and both already-built binary paths/hashes.
Source pins prove freshness of the supplied trees, not that a supplied binary
was compiled from them; the independent build receipts remain necessary.
--self-test exercises pure-memory protocol routing and validators only.
"""

import argparse
import base64
import copy
import hashlib
import io
import json
import math
import os
from pathlib import Path
import queue
import signal
import stat
import statistics
import sys
import threading
import time
import types


HELPER_SHA256 = "98413b4b177ec3bf68b7fe67de153376465374a9e74690c337633b3b4a912ffb"
SEEDS = 32
WARMUP = 16
ORDER = ("A", "B", "B", "A")
CONCURRENCIES = (1, 4, 8)
TOOLS = ("request_status", "request_result")
WAIT_SECONDS = 10
SOURCE_ROOTS = ("src", "examples", "tools", ".cargo")
SOURCE_FILES = ("Cargo.toml", "Cargo.lock", "rustfmt.toml", "build.rs",
                "rust-toolchain", "rust-toolchain.toml")


def need(value, message):
    if not value:
        raise RuntimeError(message)


def load_helper(path):
    """Execute the same verified bytes, not a second unpinned import read."""
    path = Path(path).absolute()
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size <= 128 * 1024, "helper is not a bounded regular file")
        raw = stream.read(128 * 1024 + 1)
        after = os.fstat(stream.fileno())
    need((before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
         == (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
         "helper changed during read")
    need(hashlib.sha256(raw).hexdigest() == HELPER_SHA256, "helper SHA256 differs")
    module = types.ModuleType("pinned_small_archive_controller")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def controller_class(helper):
    class MultiplexController(helper.LocalController):
        """Original lifecycle with exactly-once writes and ID-indexed replies."""

        def __init__(self, *args, **kwargs):
            self.waiters = {}
            self.completed = queue.Queue()
            self.send_lock = threading.Lock()
            super().__init__(*args, **kwargs)

        def read_loop(self):
            try:
                while True:
                    wire = self.child.stdout.readline(helper.MAX_MESSAGE + 1)
                    received_ns = time.monotonic_ns()
                    if not wire:
                        break
                    offset = self.wire_out.tell()
                    self.wire_out.write(wire)
                    self.wire_out.flush()
                    item = {"wire_offset": offset, "wire_bytes": len(wire),
                            "wire_sha256": helper.sha256(wire),
                            "received_monotonic_ns": received_ns}
                    need(len(wire) <= helper.MAX_MESSAGE and wire.endswith(b"\n"),
                         "native response size/framing violation; bytes preserved")
                    reply = json.loads(wire)
                    need(isinstance(reply, dict), "native response is not an object")
                    if "id" not in reply:
                        need("method" in reply, "unidentified response is not a notification")
                        continue
                    request_id = reply["id"]
                    need(type(request_id) is int, "unexpected native response ID type")
                    with self.lock:
                        ticket = self.waiters.get(request_id)
                    if ticket is None:
                        self.unmatched.append({"id": request_id, **item})
                        raise RuntimeError("unmatched response; no request replay permitted")
                    item["reply"] = reply
                    ticket["queue"].put_nowait(item)
                    self.completed.put_nowait(request_id)
            except Exception as error:
                self.reader_error = type(error).__name__ + ": " + str(error)
            finally:
                with self.lock:
                    pending = list(self.waiters.items())
                for request_id, ticket in pending:
                    try:
                        ticket["queue"].put_nowait({
                            "transport_error": self.reader_error or "native stdio closed"})
                        self.completed.put_nowait(request_id)
                    except queue.Full:
                        pass

        def submit(self, method, params, row, client_timeout=WAIT_SECONDS):
            with self.send_lock:
                need(self.reader_error is None, "native reader failed: " + str(self.reader_error))
                self.serial += 1
                request_id = self.serial
                wire = helper.canonical({"jsonrpc": "2.0", "id": request_id,
                                         "method": method, "params": params})
                ticket = {"id": request_id, "queue": queue.Queue(maxsize=1), "row": row}
                row.update(rpc_id=request_id, request_wire_sha256=helper.sha256(wire),
                           request_wire_bytes=len(wire), write_attempts=0, sent=False,
                           response_received=False, automatic_retry=False)
                with self.lock:
                    self.waiters[request_id] = ticket
                try:
                    row["request_wire_offset"] = self.wire_in.tell()
                    self.wire_in.write(wire)
                    self.wire_in.flush()
                    row["start_monotonic_ns"] = time.monotonic_ns()
                    ticket["deadline_ns"] = row["start_monotonic_ns"] + int(client_timeout * 1e9)
                    row["write_attempts"] = 1
                    need(self.child.stdin.write(wire) == len(wire),
                         "partial RPC write; delivery unknown; never retried")
                    self.child.stdin.flush()
                    row["sent"] = True
                    return ticket
                except BaseException:
                    with self.lock:
                        self.waiters.pop(request_id, None)
                    raise

        def finish(self, ticket):
            row = ticket["row"]
            try:
                left = max(0, (ticket["deadline_ns"] - time.monotonic_ns()) / 1e9)
                item = ticket["queue"].get(timeout=left)
                row.update({"response_" + key: value for key, value in item.items() if key != "reply"})
                if "received_monotonic_ns" in item:
                    row["response_received"] = True
                    row["elapsed_ms"] = (item["received_monotonic_ns"] - row["start_monotonic_ns"]) / 1e6
                need("transport_error" not in item, item.get("transport_error", ""))
                need(self.reader_error is None, "native reader failed: " + str(self.reader_error))
                reply = item["reply"]
                need(reply.get("id") == ticket["id"] and reply.get("jsonrpc") == "2.0",
                     "native response identity/protocol differs")
                return reply
            finally:
                row["caller_wall_ms"] = (time.monotonic_ns() - row["start_monotonic_ns"]) / 1e6
                with self.lock:
                    self.waiters.pop(ticket["id"], None)

        def rpc(self, method, params, row, client_timeout=WAIT_SECONDS):
            return self.finish(self.submit(method, params, row, client_timeout))

        def next_completed(self, pending):
            while True:
                left = max(0, (min(ticket["deadline_ns"] for ticket in pending.values())
                               - time.monotonic_ns()) / 1e9)
                request_id = self.completed.get(timeout=left)
                if request_id in pending:
                    return request_id

    return MultiplexController


def source_fingerprint(helper, root):
    root = Path(root).resolve(strict=True)
    files = {}
    paths = [root / name for name in SOURCE_FILES if (root / name).exists()]
    for name in SOURCE_ROOTS:
        directory = root / name
        if not directory.exists():
            continue
        need(not directory.is_symlink() and directory.is_dir(), "source subtree is not direct")
        for parent, dirs, names in os.walk(directory, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            for d in dirs:
                need(not (Path(parent) / d).is_symlink(), "symlink in source tree")
            paths.extend(Path(parent) / name for name in sorted(names) if not name.endswith(".pyc"))
    for path in sorted(paths):
        info = helper.checked_file(path)
        files[str(path.relative_to(root))] = {"sha256": info["sha256"], "bytes": info["bytes"]}
    need("Cargo.toml" in files and "Cargo.lock" in files and any(p.startswith("src/") for p in files),
         "source pin lacks compiler inputs")
    return {"path": str(root), "sha256": helper.sha256(helper.canonical(files)),
            "files": files, "scope": {"roots": SOURCE_ROOTS, "root_files": SOURCE_FILES}}


def ownership(dto):
    for name, expected in (("ownership_scope", "native_mcp_session_only"),
                           ("session_scope", "native_mcp_session_only"),
                           ("authenticated_chatgpt_caller_isolation", False),
                           ("credential_metadata_resume", False),
                           ("cross_session_resume", False)):
        need(type(dto.get(name)) is type(expected) and dto[name] == expected,
             "public owner semantics differ: " + name)


def retained_snapshot(helper, state, seeds):
    maps, payloads = {}, {}
    for request_id, seed in seeds.items():
        path = state / "request-results-v2" / "archive" / request_id[:2] / (request_id + ".json")
        info, raw = helper.checked_file(path, maximum=96 * 1024, contents=True)
        record = json.loads(raw)
        need(record.get("request_id") == request_id and record.get("tool_name") == "host_list"
             and record.get("state") == "stored", "original retained record identity/state differs")
        payload = base64.b64decode(record["payload_base64"], validate=True)
        need(base64.b64encode(payload).decode() == record["payload_base64"], "noncanonical original base64")
        need(record["payload_bytes"] == len(payload) <= 16384
             and record["payload_sha256"] == helper.sha256(payload), "original payload length/hash differs")
        original, dto = helper.decode_result({"result": json.loads(payload)})
        need(dto == seed["dto"] and original.get("_meta", {}).get(helper.ID_META, {}).get("request_id")
             == request_id and helper.ACK_META not in original.get("_meta", {}),
             "original boundary is not this seed before retention acknowledgement")
        maps[str(path.relative_to(state))] = info
        payloads[request_id] = payload
    return {"files": maps, "sha256": helper.sha256(helper.canonical(maps))}, payloads


def validate_read(helper, reply, tool, request_id, payload):
    result, dto = helper.decode_result(reply)
    ownership(dto)
    meta = result.get("_meta", {})
    marker, ack = meta.get(helper.ID_META, {}), meta.get(helper.ACK_META, {})
    need(helper.ID_RE.fullmatch(str(marker.get("request_id", ""))) is not None
         and marker.get("automatic_retry") is False and marker.get("delivery_proven") is False,
         "read lacks its own native request identity")
    need(ack.get("result_state") == "not_retained_policy"
         and ack.get("audit_completion_durable") is True and ack.get("automatic_retry") is False,
         "read audit/retention acknowledgement differs")
    need(dto.get("request_id") == request_id and dto.get("automatic_retry") is False,
         "wrong original request or retry semantics")
    if tool == "request_status":
        need(dto.get("tool_name") == "host_list" and dto.get("dispatch_state") == "completed"
             and dto.get("result_state") == "stored" and dto.get("result_bytes") == len(payload)
             and dto.get("metadata_lookup_does_not_prove_delivery_or_business_success") is True,
             "status does not describe the original stored result")
    else:
        need(tool == "request_result", "unsupported read tool")
        need(dto.get("offset") == 0 and dto.get("next_offset") == len(payload)
             and dto.get("total_bytes") == len(payload) and dto.get("eof") is True
             and dto.get("immutable_snapshot") is True and dto.get("delivery_proven") is False,
             "original page framing/semantics differ")
        returned = base64.b64decode(dto["data_base64"], validate=True)
        need(returned == payload and dto.get("result_sha256") == helper.sha256(payload)
             and base64.b64encode(returned).decode() == dto["data_base64"],
             "returned original bytes/hash differ")
    return {"dto_sha256": helper.sha256(helper.canonical(dto)),
            "lookup_dispatch_id": marker["request_id"]}


def write_row(helper, journal, row):
    journal.write(helper.canonical(row))
    journal.flush()


def run_queries(helper, controller, journal, count, concurrency, context, payloads, purpose):
    ids = list(payloads)
    rows, pending, next_index = [], {}, 0
    dispatch_ids = set()
    failure = None

    def submit_one(index):
        tool = TOOLS[index % 2]
        request_id = ids[(index // 2) % len(ids)]
        arguments = {"request_id": request_id}
        if tool == "request_result":
            arguments.update(offset=0, limit=16384)
        row = {**context, "purpose": purpose, "index": index, "tool": tool,
               "arguments": arguments, "concurrency": concurrency, "okay": False,
               "start_unix_ns": time.time_ns()}
        rows.append(row)
        try:
            ticket = controller.submit("tools/call", {"name": tool, "arguments": arguments}, row)
            pending[ticket["id"]] = ticket
        except BaseException as error:
            row.update(error_type=type(error).__name__, error=str(error))
            write_row(helper, journal, row)
            raise

    def finish_one(ticket):
        row = ticket["row"]
        try:
            reply = controller.finish(ticket)
            row.update(validate_read(helper, reply, row["tool"], row["arguments"]["request_id"],
                                     payloads[row["arguments"]["request_id"]]))
            dispatch_id = row["lookup_dispatch_id"]
            need(dispatch_id not in payloads and dispatch_id not in dispatch_ids,
                 "read dispatch reused a seed or another observation identity")
            dispatch_ids.add(dispatch_id)
            row["okay"] = True
        except BaseException as error:
            row.update(error_type=type(error).__name__, error=str(error))
        write_row(helper, journal, row)
        return row["okay"]

    try:
        while next_index < min(count, concurrency):
            submit_one(next_index)
            next_index += 1
        while pending:
            request_id = controller.next_completed(pending)
            okay = finish_one(pending.pop(request_id))
            if not okay:
                failure = "at least one read failed; remaining in-flight calls drained without replay"
            if failure is None and next_index < count:
                submit_one(next_index)
                next_index += 1
    except BaseException as error:
        failure = type(error).__name__ + ": " + str(error)
    finally:
        for ticket in list(pending.values()):
            finish_one(ticket)
        pending.clear()
    return rows, failure


def summarize(rows, planned):
    result = {"planned": planned, "attempted": len(rows),
              "sent": sum(row.get("sent", False) for row in rows),
              "successes": sum(row.get("okay", False) for row in rows),
              "failures": sum(not row.get("okay", False) for row in rows),
              "unexecuted": planned - len(rows)}
    result["performance_valid"] = result["successes"] == planned and result["attempted"] == planned
    if not result["performance_valid"]:
        return result
    span = (max(r["response_received_monotonic_ns"] for r in rows)
            - min(r["start_monotonic_ns"] for r in rows)) / 1e9
    result.update(wire_window_seconds=span, successful_reads_per_second=len(rows) / span)
    result["tools"] = {}
    for tool in TOOLS:
        values = sorted(r["elapsed_ms"] for r in rows if r["tool"] == tool)
        result["tools"][tool] = {"count": len(values), "mean_ms": statistics.mean(values),
                                  "p50_ms": statistics.median(values),
                                  "p95_ms": values[math.ceil(.95 * len(values)) - 1], "max_ms": values[-1]}
    return result


def run_round(helper, controller_type, directory, binary, measured, workers, context):
    config, state = helper.make_fixture(directory)
    control_dir = directory / "controller"
    control_dir.mkdir(mode=0o700)
    journal = (directory / "calls.jsonl").open("xb")
    controller, initial, seeds, rows = None, None, {}, []
    result = {**context, "complete": False, "measured_planned": measured}
    try:
        controller = controller_type(binary, config, control_dir, workers)
        controller.initialize()
        result["startup"] = controller.startup
        for index in range(SEEDS):
            row = {**context, "purpose": "seed", "index": index, "tool": "host_list",
                   "arguments": {}, "concurrency": 1, "okay": False}
            try:
                reply = controller.rpc("tools/call", {"name": "host_list", "arguments": {}}, row)
                native, dto = helper.decode_result(reply)
                request_id = helper.validate_seed(native, dto)
                need(request_id not in seeds, "duplicate seed request identity")
                seeds[request_id] = {"dto": dto}
                row.update(okay=True, native_request_id=request_id)
            except BaseException as error:
                row.update(error_type=type(error).__name__, error=str(error))
                raise
            finally:
                write_row(helper, journal, row)
        initial, payloads = retained_snapshot(helper, state, seeds)
        helper.create_file(directory / "retained-before.json", helper.canonical(initial))
        warmup, failure = run_queries(helper, controller, journal, WARMUP, context["concurrency"],
                                      context, payloads, "warmup")
        result["warmup"] = summarize(warmup, WARMUP)
        need(failure is None and result["warmup"]["performance_valid"], "warmup failed: " + str(failure))
        result["before_measured"] = helper.process_snapshot(controller.child.pid, controller.birth)
        started = time.monotonic_ns()
        rows, failure = run_queries(helper, controller, journal, measured, context["concurrency"],
                                    context, payloads, "measured")
        result["phase_wall_seconds"] = (time.monotonic_ns() - started) / 1e9
        result["after_measured"] = helper.process_snapshot(controller.child.pid, controller.birth)
        result["measured_cpu_seconds"] = (result["after_measured"]["cpu_seconds"]
                                            - result["before_measured"]["cpu_seconds"])
        result["measured"] = summarize(rows, measured)
        need(failure is None and result["measured"]["performance_valid"], "measurement failed: " + str(failure))
        need(not ({row["lookup_dispatch_id"] for row in warmup}
                  & {row["lookup_dispatch_id"] for row in rows}),
             "measured reads reused warmup dispatch identities")
        final, _ = retained_snapshot(helper, state, seeds)
        helper.create_file(directory / "retained-after.json", helper.canonical(final))
        result["original_retained_files_unchanged"] = final == initial
        need(result["original_retained_files_unchanged"], "original retained files changed")
        result["complete"] = True
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if controller is not None:
            try:
                closing = controller.close()
                closing["cpu_scope"] = "wait4 original controller, entire round: startup, 32 seeds, warmup, measured reads and shutdown"
                result["shutdown"] = closing
                need(closing["original_child_reaped"] and not closing["errors"]
                     and closing["reader_error"] is None and not closing["unmatched"]
                     and closing["method"] == "stdin_eof" and closing["waited"]["exit_code"] == 0,
                     "owned controller shutdown was not clean")
            except BaseException as error:
                result["complete"] = False
                result["cleanup_error"] = {"type": type(error).__name__, "message": str(error)}
        journal.flush()
        os.fsync(journal.fileno())
        journal.close()
        result["measured"] = summarize(rows, measured)
        if not result["complete"]:
            result["measured"]["performance_valid"] = False
            for key in ("tools", "successful_reads_per_second", "wire_window_seconds"):
                result["measured"].pop(key, None)
        result["calls_file"] = helper.checked_file(directory / "calls.jsonl")
        helper.save_report(directory / "report.json", result)
    return result


def self_test(helper):
    """No executable, socket, subprocess, native owner, or benchmark is started."""
    cls = controller_class(helper)

    def memory_controller():
        controller = cls.__new__(cls)
        controller.waiters, controller.completed = {}, queue.Queue()
        controller.send_lock, controller.lock = threading.Lock(), threading.Lock()
        controller.serial, controller.reader_error, controller.unmatched = 0, None, []
        controller.wire_in, controller.wire_out = io.BytesIO(), io.BytesIO()
        controller.child = types.SimpleNamespace(stdin=io.BytesIO(), stdout=io.BytesIO())
        return controller

    controller = memory_controller()
    first = controller.submit("fixture", {}, {})
    second = controller.submit("fixture", {}, {})
    controller.child.stdout = io.BytesIO(b'{"jsonrpc":"2.0","id":2,"result":22}\n'
                                         b'{"jsonrpc":"2.0","id":1,"result":11}\n')
    controller.read_loop()
    assert controller.next_completed({1: first, 2: second}) == 2
    assert controller.finish(second)["result"] == 22
    assert controller.finish(first)["result"] == 11 and not controller.waiters
    assert first["row"]["write_attempts"] == second["row"]["write_attempts"] == 1
    controller = memory_controller()
    ticket = controller.submit("fixture", {}, {})
    controller.child.stdout = io.BytesIO(b'not-json\n')
    controller.read_loop()
    try:
        controller.finish(ticket)
    except RuntimeError:
        pass
    else:
        raise AssertionError("malformed response accepted")
    assert controller.wire_out.getvalue() == b'not-json\n'
    for response in (b'{"jsonrpc":"2.0","id":99,"result":1}\n',
                     b'{"jsonrpc":"2.0","id":1,"result":1}\n'
                     b'{"jsonrpc":"2.0","id":1,"result":2}\n'):
        controller = memory_controller()
        ticket = controller.submit("fixture", {}, {})
        controller.child.stdout = io.BytesIO(response)
        controller.read_loop()
        try:
            controller.finish(ticket)
        except RuntimeError:
            pass
        else:
            raise AssertionError("unmatched or duplicate response accepted")
        assert controller.wire_out.getvalue() == response
    controller = memory_controller()
    ticket = controller.submit("fixture", {}, {})
    ticket["deadline_ns"] = 0
    try:
        controller.finish(ticket)
    except queue.Empty:
        pass
    else:
        raise AssertionError("missing response accepted")
    assert not controller.waiters and ticket["row"]["write_attempts"] == 1
    request_id, payload = "a" * 64, b'{"original":"fixture"}'
    dto = {"request_id": request_id, "automatic_retry": False, "offset": 0,
           "next_offset": len(payload), "total_bytes": len(payload), "eof": True,
           "immutable_snapshot": True, "delivery_proven": False,
           "data_base64": base64.b64encode(payload).decode(), "result_sha256": helper.sha256(payload),
           "ownership_scope": "native_mcp_session_only", "session_scope": "native_mcp_session_only",
           "authenticated_chatgpt_caller_isolation": False, "credential_metadata_resume": False,
           "cross_session_resume": False}
    meta = {helper.ID_META: {"request_id": "b" * 64, "automatic_retry": False, "delivery_proven": False},
            helper.ACK_META: {"result_state": "not_retained_policy", "audit_completion_durable": True,
                              "automatic_retry": False}}
    reply = {"result": {"content": [{"type": "text", "text": json.dumps(dto)}], "_meta": meta}}
    validate_read(helper, reply, "request_result", request_id, payload)
    bad = copy.deepcopy(reply)
    changed = copy.deepcopy(dto)
    changed["result_sha256"] = "f" * 64
    bad["result"]["content"][0]["text"] = json.dumps(changed)
    try:
        validate_read(helper, bad, "request_result", request_id, payload)
    except RuntimeError:
        pass
    else:
        raise AssertionError("corrupt returned payload hash accepted")

    class MemoryWindow:
        def __init__(self, fail_at=None):
            self.serial, self.active, self.maximum = 0, {}, 0
            self.fail_at = fail_at

        def submit(self, method, params, row):
            assert method == "tools/call" and params["name"] in TOOLS
            self.serial += 1
            row.update(rpc_id=self.serial, sent=True, write_attempts=1,
                       start_monotonic_ns=time.monotonic_ns(), automatic_retry=False)
            ticket = {"id": self.serial, "row": row, "params": params}
            self.active[self.serial] = ticket
            self.maximum = max(self.maximum, len(self.active))
            return ticket

        def next_completed(self, pending):
            return max(pending)

        def finish(self, ticket):
            self.active.pop(ticket["id"])
            row = ticket["row"]
            received = time.monotonic_ns()
            row.update(response_received=True, response_received_monotonic_ns=received,
                       elapsed_ms=(received - row["start_monotonic_ns"]) / 1e6)
            if ticket["id"] == self.fail_at:
                return {"error": {"code": -32000, "message": "fixture refusal"}}
            output = copy.deepcopy(dto)
            output["request_id"] = ticket["params"]["arguments"]["request_id"]
            if ticket["params"]["name"] == "request_status":
                output.update(tool_name="host_list", dispatch_state="completed", result_state="stored",
                              result_bytes=len(payload), metadata_lookup_does_not_prove_delivery_or_business_success=True)
            metadata = copy.deepcopy(meta)
            metadata[helper.ID_META]["request_id"] = f"{ticket['id'] + 1000:064x}"
            return {"result": {"content": [{"type": "text", "text": json.dumps(output)}],
                               "_meta": metadata}}

    original_payloads = {f"{i + 1:064x}": payload for i in range(SEEDS)}
    for concurrency in CONCURRENCIES:
        window, journal = MemoryWindow(), io.BytesIO()
        rows, error = run_queries(helper, window, journal, 128, concurrency, {}, original_payloads, "measured")
        assert error is None and len(rows) == 128 and all(r["okay"] for r in rows)
        assert window.maximum == concurrency and not window.active
        assert len(journal.getvalue().splitlines()) == 128
    window, journal = MemoryWindow(fail_at=8), io.BytesIO()
    rows, error = run_queries(helper, window, journal, 128, 8, {}, original_payloads, "measured")
    assert error is not None and len(rows) == 8 and sum(r["okay"] for r in rows) == 7
    assert len(journal.getvalue().splitlines()) == 8 and not window.active
    assert summarize(rows, 128)["performance_valid"] is False
    assert summarize([{"okay": False, "sent": True}], 128)["performance_valid"] is False
    print(json.dumps({"pure_logic_self_test": "passed", "native_processes_started": 0,
                      "checks": ["out_of_order_routing", "single_write", "malformed_wire_retention",
                                 "unmatched_and_duplicate_refusal", "timeout_cleanup", "payload_validation",
                                 "corrupt_hash_refusal", "bounded_rolling_window_C1_C4_C8",
                                 "failure_drains_all_inflight_and_preserves_rows", "failed_run_excluded"]}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, default=Path(__file__).with_name("x230_small_archive_benchmark.py"))
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--fingerprint-source", type=Path)
    for arm in ("baseline", "candidate"):
        parser.add_argument("--" + arm, type=Path)
        parser.add_argument("--" + arm + "-sha256")
        parser.add_argument("--" + arm + "-source", type=Path)
        parser.add_argument("--" + arm + "-source-sha256")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--measured", type=int, choices=(128, 256), default=128)
    parser.add_argument("--workers", type=int, choices=(1, 2, 4), default=2)
    args = parser.parse_args()
    helper = load_helper(args.helper)
    if args.self_test:
        self_test(helper)
        return 0
    if args.fingerprint_source:
        print(json.dumps(source_fingerprint(helper, args.fingerprint_source), sort_keys=True))
        return 0
    need(sys.platform == "linux" and hasattr(os, "wait4"), "Linux /proc and wait4 required")
    need(args.out is not None, "--out is required")
    pins, sources, binaries = {}, {}, {}
    for arm, prefix in (("A", "baseline"), ("B", "candidate")):
        path, expected = getattr(args, prefix), getattr(args, prefix + "_sha256")
        source, expected_source = getattr(args, prefix + "_source"), getattr(args, prefix + "_source_sha256")
        need(path is not None and source is not None and expected and expected_source,
             "both binary/source paths and SHA256 pins are required")
        binaries[arm] = path.resolve(strict=True)
        pins[arm] = helper.checked_file(binaries[arm])
        need(pins[arm]["sha256"] == expected and os.access(binaries[arm], os.X_OK), "binary hash/executable pin failed")
        sources[arm] = source_fingerprint(helper, source)
        need(sources[arm]["sha256"] == expected_source, "source hash pin failed")
    output = args.out.absolute()
    need(output.parent.resolve(strict=True) == output.parent, "output parent must be direct and existing")
    output.mkdir(mode=0o700)
    script_path = Path(__file__).resolve(strict=True)
    script = helper.checked_file(script_path)
    plan = [{"block": block, "concurrency": concurrency, "position": position, "arm": arm}
            for block in range(2)
            for concurrency in (CONCURRENCIES if block == 0 else tuple(reversed(CONCURRENCIES)))
            for position, arm in enumerate(ORDER)]
    report = {"schema": "hepta-x230-retained-result-read-abba/v1", "complete": False,
              "comparison_valid": False, "round_plan": plan, "rounds": [], "script": script,
              "helper_sha256": HELPER_SHA256, "binary_inputs": pins,
              "binary_paths": {arm: str(path) for arm, path in binaries.items()},
              "source_sha256": {arm: value["sha256"] for arm, value in sources.items()},
              "measured_per_controller": args.measured, "seeds_per_controller": SEEDS,
              "warmup_per_controller": WARMUP, "tokio_workers": args.workers,
              "client_timeout_seconds": WAIT_SECONDS, "automatic_retries": 0,
              "ssh_or_production_state_used": False, "performance_adoption_claimed": False,
              "measurement": {"latency": "send start to reader receiving complete JSON-RPC line",
                              "throughput": "rolling window, including client validation/logging/refill gaps",
                              "resource": "measured /proc process CPU ticks and RSS endpoints; whole-controller wait4 CPU/maxRSS",
                              "audit_growth": "32 real seed admissions, then warmup/measured reads also append native audit records",
                              "source_binding": "fresh source/binary hashes; compile provenance requires external build receipts",
                              "limits": "two ABBA blocks per C; hot local stdio only; no p99 significance, cold-start, multi-host, crash recovery or global optimum claim"}}
    for arm, source in sources.items():
        helper.create_file(output / ("source-" + arm + ".json"), helper.canonical(source))
    helper.save_report(output / "plan.json", report)

    def interrupted(_number, _frame):
        raise KeyboardInterrupt("benchmark interrupted; owned child cleanup required")

    previous_term = signal.signal(signal.SIGTERM, interrupted)
    try:
        for index, context in enumerate(plan):
            arm = context["arm"]
            need(helper.checked_file(binaries[arm]) == pins[arm], "binary changed before round")
            directory = output / f"round-{index:02d}-C{context['concurrency']}-{arm}"
            current = run_round(helper, controller_class(helper), directory, binaries[arm],
                                args.measured, args.workers, {"round": index, **context})
            report["rounds"].append(current)
            helper.save_report(output / "report.json", report)
            need(current["complete"], "round failed; full comparison invalid")
        report["complete"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        try:
            report["final_binary_pins"] = {arm: helper.checked_file(path) for arm, path in binaries.items()}
            report["final_source_sha256"] = {arm: source_fingerprint(helper, source["path"])["sha256"]
                                              for arm, source in sources.items()}
            need(report["final_binary_pins"] == pins and report["final_source_sha256"] == report["source_sha256"]
                 and helper.checked_file(script_path) == script, "source/binary/script changed")
            load_helper(args.helper)
            report["inputs_unchanged"] = True
        except BaseException as error:
            report["complete"] = False
            report["final_pin_error"] = {"type": type(error).__name__, "message": str(error)}
        report["measured_planned"] = len(plan) * args.measured
        report["measured_attempted"] = sum(r["measured"]["attempted"] for r in report["rounds"])
        report["measured_unexecuted"] = report["measured_planned"] - report["measured_attempted"]
        report["comparison_valid"] = report["complete"] and len(report["rounds"]) == len(plan)
        if report["comparison_valid"]:
            comparisons = []
            for block in range(2):
                for concurrency in CONCURRENCIES:
                    chosen = [r for r in report["rounds"] if r["block"] == block and r["concurrency"] == concurrency]
                    means = {arm: statistics.mean(r["measured"]["successful_reads_per_second"]
                                                  for r in chosen if r["arm"] == arm) for arm in ("A", "B")}
                    comparisons.append({"block": block, "concurrency": concurrency,
                                        "round_rates": {arm: [r["measured"]["successful_reads_per_second"]
                                                              for r in chosen if r["arm"] == arm] for arm in ("A", "B")},
                                        "mean_rates": means,
                                        "candidate_rate_change_percent": 100 * (means["B"] / means["A"] - 1)})
            report["descriptive_comparisons"] = comparisons
        helper.save_report(output / "report.json", report)
    print(json.dumps({"report": str(output / "report.json"), "complete": report["complete"],
                      "comparison_valid": report["comparison_valid"]}, sort_keys=True))
    return 0 if report["comparison_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
