#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Fixed 64-record, hot, C1 native MCP metadata ABBA guard.

Each fresh native stdio owner seeds exactly 64 real host_list dispatches, then
observes usage_stats/request_history/request_archive without further admissions.
The order is baseline/candidate/candidate/baseline. This is not a cold-start,
large-archive, concurrent-query, SSH, recovery, or production qualification.

Example (paths must identify already qualified binaries):
  python3 x230_small_archive_benchmark.py --baseline /abs/A35 --candidate /abs/A38 \
      --out /abs/new-small-archive-run --measured 1024

There are exactly four rounds, eight warmup requests per round, and 128 measured
requests per round by default. --measured 1024 gives 4,096 measured requests.
Every request is sent once. A failure stops the run and invalidates the entire
comparison; unexecuted requests remain explicitly unexecuted. All received wire
bytes, errors, original-file maps, and original-process wait receipts are kept.
The product's internal metadata deadline is not configured or extended here.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import re
import signal
import stat
import statistics
import subprocess
import sys
import threading
import time


SEED_COUNT = 64
PAGE_SIZE = 32
WARMUP_COUNT = 8
ORDER = ("A", "B", "B", "A")
TOOLS = ("usage_stats", "request_history", "request_archive")
MAX_MESSAGE = 1024 * 1024
CLIENT_WAIT_SECONDS = 10
ID_META = "io.hepta.runtime/request-v8"
ACK_META = "io.hepta.runtime/retention-v8"
ID_RE = re.compile(r"[0-9a-f]{64}\Z")
RECORD_RE = re.compile(r"([0-9a-f]{64})\.json\Z")


def need(value, message):
    if not value:
        raise RuntimeError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def checked_file(path, maximum=512 * 1024 * 1024, contents=False):
    """Hash the complete single-link regular file with before/after identity."""
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
             "not a single-link regular file: " + str(path))
        need(before.st_size <= maximum, "file size bound exceeded: " + str(path))
        digest, size, chunks = hashlib.sha256(), 0, []
        while True:
            data = os.read(fd, 1024 * 1024)
            if not data:
                break
            size += len(data)
            need(size <= maximum, "file grew past size bound: " + str(path))
            digest.update(data)
            if contents:
                chunks.append(data)
        need(size == before.st_size and identity(before) == identity(os.fstat(fd))
             == identity(path.lstat()), "file changed while reading: " + str(path))
        info = {"bytes": size, "sha256": digest.hexdigest(),
                "identity": list(identity(before))}
        return (info, b"".join(chunks)) if contents else info
    finally:
        os.close(fd)


def create_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def save_report(path, value):
    temporary = path.with_name(path.name + ".next")
    create_file(temporary, canonical(value))
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def process_snapshot(pid, birth=None):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    actual_birth = int(fields[19])
    need(fields[0] != "Z", "controller exited before observation")
    need(birth is None or actual_birth == birth, "controller generation changed")
    status = {}
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            status[key] = value.strip()
    return {"pid": pid, "birth_ticks": actual_birth,
            "cpu_seconds": (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK"),
            "cpu_tick_hz": os.sysconf("SC_CLK_TCK"),
            "rss_kib": int(status.get("VmRSS", "0 kB").split()[0]),
            "hwm_kib": int(status.get("VmHWM", "0 kB").split()[0]),
            "fd_count": len(list(Path(f"/proc/{pid}/fd").iterdir()))}


class LocalController:
    """One owned controller, newline JSON-RPC, no SSH or profile configuration."""

    def __init__(self, binary, config, directory, workers):
        self.directory = directory
        self.serial = 0
        self.pending = None
        self.lock = threading.Lock()
        self.reader_error = None
        self.unmatched = []
        self.reaped = False
        self.shutdown = None
        self.wire_in = (directory / "requests.jsonl").open("xb")
        self.wire_out = (directory / "responses.jsonl").open("xb")
        self.stderr = (directory / "stderr.log").open("xb")
        argv = [str(binary), "mcp", "--runtime-config", str(config),
                "--runtime-audit-group-commit"]
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "SHELL": "/bin/sh",
               "TOKIO_WORKER_THREADS": str(workers), "RUST_LOG": "warn"}
        self.started_ns = time.monotonic_ns()
        self.child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=self.stderr, cwd=directory, env=env,
                                      start_new_session=True)
        self.birth = None
        self.reader = threading.Thread(target=self.read_loop, daemon=True)
        self.reader.start()
        self.startup = {"pid": self.child.pid, "argv": argv}

    def read_loop(self):
        try:
            while True:
                wire = self.child.stdout.readline(MAX_MESSAGE + 1)
                received_ns = time.monotonic_ns()
                if not wire:
                    break
                offset = self.wire_out.tell()
                self.wire_out.write(wire)
                self.wire_out.flush()
                item = {"wire_offset": offset, "wire_bytes": len(wire),
                        "wire_sha256": sha256(wire), "received_monotonic_ns": received_ns}
                try:
                    need(len(wire) <= MAX_MESSAGE and wire.endswith(b"\n"),
                         "native response size/framing violation; observed bytes preserved")
                    reply = json.loads(wire)
                    need(isinstance(reply, dict), "native response is not an object")
                    item["reply"] = reply
                except Exception as error:
                    item["transport_error"] = type(error).__name__ + ": " + str(error)
                    with self.lock:
                        pending = self.pending
                    if pending is not None:
                        pending[1].put_nowait(item)
                    raise
                if "id" not in reply:
                    continue
                with self.lock:
                    pending = self.pending
                if pending is not None and reply["id"] == pending[0]:
                    pending[1].put_nowait(item)
                else:
                    self.unmatched.append({"id": reply.get("id"), **{k: v for k, v in item.items() if k != "reply"}})
        except Exception as error:
            self.reader_error = type(error).__name__ + ": " + str(error)
        finally:
            with self.lock:
                pending = self.pending
            if pending is not None:
                try:
                    pending[1].put_nowait({"transport_error": self.reader_error or "native stdio closed"})
                except queue.Full:
                    pass

    def notify(self, method, params):
        wire = canonical({"jsonrpc": "2.0", "method": method, "params": params})
        self.wire_in.write(wire)
        self.wire_in.flush()
        need(self.child.stdin.write(wire) == len(wire), "partial notification write; never retried")
        self.child.stdin.flush()

    def rpc(self, method, params, row, client_timeout=CLIENT_WAIT_SECONDS):
        self.serial += 1
        request_id = self.serial
        waiter = queue.Queue(maxsize=1)
        with self.lock:
            need(self.pending is None, "C1 guard refuses overlapping RPCs")
            self.pending = (request_id, waiter)
        wire = canonical({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        row.update(rpc_id=request_id, request_wire_sha256=sha256(wire),
                   request_wire_bytes=len(wire), write_attempts=0, sent=False,
                   response_received=False, automatic_retry=False)
        try:
            row["request_wire_offset"] = self.wire_in.tell()
            self.wire_in.write(wire)
            self.wire_in.flush()
            row["start_monotonic_ns"] = time.monotonic_ns()
            row["write_attempts"] = 1
            written = self.child.stdin.write(wire)
            need(written == len(wire), "partial RPC write; delivery unknown; never retried")
            self.child.stdin.flush()
            row["sent"] = True
            item = waiter.get(timeout=client_timeout)
            row.update({"response_" + key: value for key, value in item.items() if key != "reply"})
            if "received_monotonic_ns" in item:
                row["response_received"] = True
                row["elapsed_ms"] = (item["received_monotonic_ns"] - row["start_monotonic_ns"]) / 1e6
            need("transport_error" not in item, item.get("transport_error", ""))
            reply = item["reply"]
            need(reply.get("id") == request_id and reply.get("jsonrpc") == "2.0",
                 "native response identity/protocol differs")
            return reply
        finally:
            ended_ns = time.monotonic_ns()
            row["caller_wall_ms"] = (ended_ns - row.get("start_monotonic_ns", ended_ns)) / 1e6
            with self.lock:
                self.pending = None

    def initialize(self):
        # Run fallible identity/handshake checks after the caller owns this
        # object, so an early startup failure still reaches original wait4.
        self.birth = process_snapshot(self.child.pid)["birth_ticks"]
        self.startup["birth_ticks"] = self.birth
        row = {}
        reply = self.rpc("initialize", {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "hepta-x230-small-archive-abba", "version": "1"}},
            row, client_timeout=60)
        self.startup["initialize"] = row
        need("result" in reply and "error" not in reply, "native MCP initialization failed")
        self.notify("notifications/initialized", {})
        self.startup.update(ready_ms=(time.monotonic_ns() - self.started_ns) / 1e6,
                            server_info=reply["result"].get("serverInfo"),
                            protocol_version=reply["result"].get("protocolVersion"))

    def _wait_until(self, seconds):
        deadline = time.monotonic() + seconds
        while True:
            pid, status, usage = os.wait4(self.child.pid, os.WNOHANG)
            if pid == self.child.pid:
                self.reaped = True
                self.child.returncode = os.waitstatus_to_exitcode(status)
                return {"pid": pid, "exit_code": self.child.returncode,
                        "user_cpu_seconds": usage.ru_utime, "system_cpu_seconds": usage.ru_stime,
                        "total_cpu_seconds": usage.ru_utime + usage.ru_stime,
                        "max_rss_kib": usage.ru_maxrss,
                        "voluntary_context_switches": usage.ru_nvcsw,
                        "involuntary_context_switches": usage.ru_nivcsw,
                        "minor_faults": usage.ru_minflt, "major_faults": usage.ru_majflt,
                        "input_blocks": usage.ru_inblock, "output_blocks": usage.ru_oublock}
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.01)

    def close(self):
        if self.shutdown is not None:
            return self.shutdown
        started = time.monotonic()
        errors, method, waited = [], "stdin_eof", None
        try:
            self.child.stdin.close()
        except Exception as error:
            errors.append("stdin close: " + repr(error))
        try:
            waited = self._wait_until(30)
            if waited is None:
                # No poll/reap precedes these signals. The owned original child
                # still reserves its PID; no saved/reconstructed group is used.
                method = "sigterm_after_eof_timeout"
                os.kill(self.child.pid, signal.SIGTERM)
                waited = self._wait_until(10)
            if waited is None:
                method = "sigkill_after_sigterm_timeout"
                os.kill(self.child.pid, signal.SIGKILL)
                waited = self._wait_until(10)
            need(waited is not None, "owned controller did not become waitable")
        except Exception as error:
            errors.append("wait/cleanup: " + repr(error))
        self.reader.join(2)
        if self.reader.is_alive():
            errors.append("native response reader remains alive")
        for stream in (self.wire_in, self.wire_out, self.stderr):
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
        if not self.reader.is_alive():
            self.child.stdout.close()
        self.shutdown = {"method": method, "waited": waited,
                         "wait_wall_seconds": time.monotonic() - started,
                         "original_child_reaped": self.reaped, "errors": errors,
                         "reader_error": self.reader_error, "unmatched": self.unmatched,
                         "cpu_scope": "wait4 original controller and any descendants it reaped; whole round including startup, 64 seeds, validation, warmup, measured queries and shutdown"}
        self.shutdown["files"] = {name: checked_file(self.directory / name)
                                  for name in ("requests.jsonl", "responses.jsonl", "stderr.log")}
        return self.shutdown


def make_fixture(directory):
    directory.mkdir(mode=0o700)
    state = directory / "state"
    state.mkdir(mode=0o700)
    config = {"state_dir": str(state), "controller_workspace_roots": [], "hosts": {
        "fixture": {"ssh_target": "unused.invalid", "platform": "linux",
                    "execution_mode": "isolated", "remote_state_dir": str(state / "unused"),
                    "allow_execute": False, "allow_pty": False, "allow_write": False,
                    "allow_job_network": False, "privileged_actions": {}}}}
    path = directory / "runtime.json"
    create_file(path, canonical(config))
    return path, state


def decode_result(reply):
    need("error" not in reply, "native RPC error: " + json.dumps(reply.get("error"), sort_keys=True))
    result = reply.get("result")
    need(isinstance(result, dict), "native CallToolResult missing")
    need(result.get("isError", False) is False,
         "native tool error: " + json.dumps(result, sort_keys=True))
    texts = [part["text"] for part in result.get("content", []) if part.get("type") == "text"]
    need(len(texts) == 1, "expected exactly one native JSON text result")
    dto = json.loads(texts[0])
    need(isinstance(dto, dict), "native JSON DTO is not an object")
    return result, dto


def validate_seed(result, dto):
    expected = [{"name": "fixture", "platform": "linux", "execution_mode": "isolated",
                 "operator_tools": False, "allow_execute": False, "allow_pty": False,
                 "allow_write": False, "privileged_actions": []}]
    need(dto == {"hosts": expected}, "host_list does not match the closed no-effect fixture")
    meta = result.get("_meta", {})
    marker, ack = meta.get(ID_META, {}), meta.get(ACK_META, {})
    request_id = marker.get("request_id")
    need(isinstance(request_id, str) and ID_RE.fullmatch(request_id), "seed lacks native request identity")
    need(marker.get("automatic_retry") is False and marker.get("delivery_proven") is False,
         "seed request identity semantics differ")
    need(ack.get("audit_completion_durable") is True and ack.get("result_state") == "stored"
         and ack.get("automatic_retry") is False, "seed audit or result retention was not acknowledged")
    return request_id


def snapshot_originals(state, expected_ids):
    """Read only authoritative record stores, never edit/migrate/synthesize them."""
    maps, logical = {}, {}
    for group, roots in (("hot", [state / "request-audit"]),
                         ("archive", [state / "request-archive-v11", state / "request-archive-v12"])):
        records, files = {}, {}
        for root in roots:
            if not root.exists():
                need(root.name == "request-archive-v12", "required original store absent: " + str(root))
                continue
            need(root.is_dir() and not root.is_symlink(), "original store is not a direct directory")
            for parent, dirs, names in os.walk(root, followlinks=False):
                need(len(Path(parent).relative_to(root).parts) <= 1, "unexpected original-store depth")
                for name in dirs:
                    entry = Path(parent) / name
                    need(not entry.is_symlink() and re.fullmatch(r"[0-9a-f]{2}", name),
                         "unexpected original shard directory")
                for name in names:
                    match = RECORD_RE.fullmatch(name)
                    need(match is not None, "unexpected/still-staging original entry: " + str(Path(parent) / name))
                    path = Path(parent) / name
                    info, raw = checked_file(path, maximum=2048, contents=True)
                    record = json.loads(raw)
                    request_id = match.group(1)
                    need(request_id not in records and record.get("request_id") == request_id,
                         "duplicate or mismatched original request id")
                    need(set(record) == {"request_id", "owner", "tool_name", "state", "accepted_unix_ms", "elapsed_ms"},
                         "unexpected original record schema")
                    need(record["tool_name"] == "host_list" and record["state"] == "completed",
                         "seed original is not a completed host_list dispatch")
                    need(type(record["accepted_unix_ms"]) is int and type(record["elapsed_ms"]) is int
                         and record["elapsed_ms"] >= 0 and ID_RE.fullmatch(record["owner"]),
                         "invalid original timing/owner identity")
                    records[request_id] = record
                    files[str(path.relative_to(state))] = info
        need(set(records) == expected_ids and len(records) == SEED_COUNT,
             group + " original coverage is not exactly the 64 successful seeds")
        need(len({record["owner"] for record in records.values()}) == 1,
             "original seeds do not share one native owner")
        logical[group], maps[group] = records, files
    need(logical["hot"] == logical["archive"], "hot and archive original records disagree")
    records = sorted(logical["archive"].values(), key=lambda row: (row["accepted_unix_ms"], row["request_id"]))
    public = [{key: value for key, value in row.items() if key != "owner"} for row in records]
    return {"logical_records": SEED_COUNT, "hot_files": len(maps["hot"]),
            "archive_files": len(maps["archive"]), "files": maps,
            "file_map_sha256": sha256(canonical(maps)),
            "public_record_projection_sha256": sha256(canonical(public))}, public


def page_arguments(records, page):
    need(page in (0, 1), "fixture only has two complete pages")
    return {"limit": PAGE_SIZE, **({"after_id": records[31]["request_id"]} if page else {})}


def validate_metadata(tool, dto, records, page=None):
    need(tool in TOOLS, "unsupported metadata tool")
    # server.rs annotates all three metadata results with OwnerScope before
    # publishing them. This harness opens native stdio sessions, so require the
    # final public scope, not request_audit's unannotated internal projection.
    for name, expected in (("ownership_scope", "native_mcp_session_only"),
                           ("session_scope", "native_mcp_session_only"),
                           ("authenticated_chatgpt_caller_isolation", False),
                           ("credential_metadata_resume", False),
                           ("cross_session_resume", False)):
        need(type(dto.get(name)) is type(expected) and dto[name] == expected,
             tool + " public ownership field differs: " + name)
    if tool == "usage_stats":
        need(dto.get("schema") == "hepta-private-usage-v1", "usage schema differs")
        for name, expected in (("total_requests", 64), ("completed", 64), ("failed", 0),
                               ("unknown", 0), ("active", 0)):
            need(type(dto.get(name)) is int and dto[name] == expected, "usage counter differs: " + name)
        need(dto.get("tool_counts") == {"host_list": 64}, "metadata observations changed their own totals")
        need(dto.get("first_accepted_unix_ms") == records[0]["accepted_unix_ms"]
             and dto.get("last_accepted_unix_ms") == records[-1]["accepted_unix_ms"],
             "usage first/last accepted times differ from the complete originals")
        need(dto.get("contains_parameters_or_output") is False
             and dto.get("scope") == "same_verified_credential_or_native_session",
             "usage scope/contents semantics differ")
    else:
        expected = records[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]
        next_id = records[31]["request_id"] if page == 0 else None
        need(dto.get("requests") == expected and dto.get("next_after_id") == next_id,
             tool + " page/cursor does not match every original record")
        need(dto.get("history_is_live") is True and dto.get("automatic_operation_retry") is False,
             tool + " observation semantics differ")
        if tool == "request_archive":
            need(type(dto.get("total")) is int and dto["total"] == 64
                 and dto.get("archive_retention") == "no_automatic_metadata_eviction"
                 and dto.get("contains_parameters_or_output") is False, "archive total/retention differs")
        else:
            # OwnerScope::annotate renames per_session to per_owner. Exact
            # object equality also rejects the old key or a mixed projection.
            need(dto.get("retention") == {"global": 512, "per_owner": 128},
                 "history public retention differs")


def observe(controller, journal, round_index, arm, tool, arguments, purpose, index,
            records=None, page=None):
    need(tool in (*TOOLS, "host_list"), "unsupported benchmark tool")
    row = {"round": round_index, "arm": arm, "tool": tool, "arguments": arguments,
           "purpose": purpose, "index": index, "concurrency": 1, "okay": False,
           "start_unix_ns": time.time_ns()}
    value = None
    try:
        reply = controller.rpc("tools/call", {"name": tool, "arguments": arguments}, row)
        result, dto = decode_result(reply)
        row["dto_sha256"] = sha256(canonical(dto))
        if tool == "host_list":
            value = validate_seed(result, dto)
            row["native_request_id"] = value
        else:
            validate_metadata(tool, dto, records, page)
            value = dto
        row["okay"] = True
    except Exception as error:
        row.update(error_type=type(error).__name__, error=str(error))
    journal.write(canonical(row))
    journal.flush()
    return row, value


def schedule(count):
    pages = {"request_history": 0, "request_archive": 0}
    for index in range(count):
        tool = TOOLS[index % len(TOOLS)]
        page = None
        if tool in pages:
            page = pages[tool] % 2
            pages[tool] += 1
        yield index, tool, page


def summarize(rows):
    result = {"attempted": len(rows), "sent": sum(row.get("sent", False) for row in rows),
              "successes": sum(row["okay"] for row in rows),
              "failures": sum(not row["okay"] for row in rows)}
    if not rows or result["failures"]:
        result["performance_valid"] = False
        return result
    result["performance_valid"] = True
    result["tools"] = {}
    for tool in TOOLS:
        values = sorted(row["elapsed_ms"] for row in rows if row["tool"] == tool)
        if not values:
            result["performance_valid"] = False
            result["tools"][tool] = {"calls": 0}
            continue
        result["tools"][tool] = {"calls": len(values), "mean_ms": statistics.mean(values),
            "p50_ms": statistics.median(values), "p95_ms": values[math.ceil(.95 * len(values)) - 1],
            "p99_ms": values[math.ceil(.99 * len(values)) - 1], "max_ms": values[-1]}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--measured", "--calls", dest="measured", type=int, default=128)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    need(sys.platform == "linux" and hasattr(os, "wait4"), "this harness measures Linux /proc and wait4 only")
    need(6 <= args.measured <= 4096 and 1 <= args.workers <= 8, "measurement/workers out of bounded range")
    binaries = {"A": args.baseline.resolve(strict=True), "B": args.candidate.resolve(strict=True)}
    inputs = {arm: {"path": str(path), **checked_file(path)} for arm, path in binaries.items()}
    for path in binaries.values():
        need(os.access(path, os.X_OK), "binary is not executable: " + str(path))
    output = args.out.absolute()
    need(output.parent.resolve(strict=True) == output.parent, "output parent must be a direct existing directory")
    output.mkdir(mode=0o700)
    script_info = checked_file(Path(__file__).resolve(strict=True))
    report = {"schema": "hepta-x230-small-archive-abba/v1", "scope": "64 real native host_list admissions per fresh stdio owner; hot C1 metadata observer guard only",
              "order": list(ORDER), "inputs": inputs, "script": script_info,
              "seed_records_per_round": 64, "warmup_per_round": 8,
              "measured_per_round": args.measured, "measured_planned": 4 * args.measured,
              "workers": args.workers, "query_client_wait_seconds": CLIENT_WAIT_SECONDS,
              "product_metadata_deadline_modified": False, "automatic_retries": 0,
              "ssh_or_profile_used": False, "rounds": [], "complete": False,
              "comparison_valid": False, "performance_adoption_claimed": False,
              "method": {"counts": "round-robin counts differ by at most one; identical tool/page sequence in all four rounds",
                         "data": "native owner, IDs and timestamps are fresh each round; identical count/schema and validated complete original projections, not byte-identical cross-arm fixtures",
                         "latency": "single send to full received JSON-RPC line, before response logging/validation",
                         "cpu": "measured /proc process ticks plus actual wait4 for complete round; no successful subset",
                         "limits": "one ABBA block; no cold, large-scale, concurrent, multi-host, failure-recovery or statistical speedup qualification"}}
    save_report(output / "plan.json", report)
    journal = (output / "calls.jsonl").open("xb")
    controller = None
    current = None
    originals_reference = None
    seed_ids = set()
    state = None
    all_measured = []
    try:
        for round_index, arm in enumerate(ORDER):
            originals_reference = None
            seed_ids = set()
            directory = output / f"round-{round_index}-{arm}"
            config, state = make_fixture(directory)
            controller_dir = directory / "controller"
            controller_dir.mkdir(mode=0o700)
            current = {"round": round_index, "arm": arm, "seeds": [], "warmup": [],
                       "measured": [], "validation": [], "complete": False,
                       "config": checked_file(config), "state": str(state)}
            report["rounds"].append(current)
            need(checked_file(binaries[arm]) == {key: value for key, value in inputs[arm].items() if key != "path"},
                 "binary changed before round")
            controller = LocalController(binaries[arm], config, controller_dir, args.workers)
            controller.initialize()
            current["startup"] = controller.startup
            for index in range(SEED_COUNT):
                row, request_id = observe(controller, journal, round_index, arm, "host_list", {}, "seed", index)
                current["seeds"].append(row)
                need(row["okay"], "seed failed; no replacement admission")
                need(request_id not in seed_ids, "duplicate native seed identity")
                seed_ids.add(request_id)
            initial, records = snapshot_originals(state, seed_ids)
            originals_reference = initial
            create_file(directory / "originals-after-seed.json", canonical(initial))
            create_file(directory / "expected-public-records.json", canonical(records))

            def validate_all(purpose):
                for index, (tool, page) in enumerate((("usage_stats", None), ("request_history", 0),
                        ("request_history", 1), ("request_archive", 0), ("request_archive", 1))):
                    arguments = {} if page is None else page_arguments(records, page)
                    row, _ = observe(controller, journal, round_index, arm, tool, arguments,
                                     purpose, index, records, page)
                    current["validation"].append(row)
                    need(row["okay"], "complete metadata validation failed; no retry")

            validate_all("preflight")
            for index, tool, page in schedule(WARMUP_COUNT):
                arguments = {} if page is None else page_arguments(records, page)
                row, _ = observe(controller, journal, round_index, arm, tool, arguments,
                                 "warmup", index, records, page)
                current["warmup"].append(row)
                need(row["okay"], "warmup failed; complete comparison invalid")
            before, before_records = snapshot_originals(state, seed_ids)
            create_file(directory / "originals-before-measured.json", canonical(before))
            need(before == initial and before_records == records, "metadata warmup mutated originals")
            current["process_before_measured"] = process_snapshot(controller.child.pid, controller.birth)
            started = time.monotonic()
            for index, tool, page in schedule(args.measured):
                arguments = {} if page is None else page_arguments(records, page)
                row, _ = observe(controller, journal, round_index, arm, tool, arguments,
                                 "measured", index, records, page)
                current["measured"].append(row)
                all_measured.append(row)
                need(row["okay"], "measured request failed; complete comparison invalid; no successful subset")
            current["measured_wall_seconds"] = time.monotonic() - started
            current["process_after_measured"] = process_snapshot(controller.child.pid, controller.birth)
            delta = current["process_after_measured"]["cpu_seconds"] - current["process_before_measured"]["cpu_seconds"]
            need(delta >= 0, "controller CPU counter moved backwards")
            current["measured_controller_cpu_seconds"] = delta
            current["measured_controller_cpu_ms_per_call"] = 1000 * delta / args.measured
            current["measured_summary"] = summarize(current["measured"])
            after, after_records = snapshot_originals(state, seed_ids)
            create_file(directory / "originals-after-measured.json", canonical(after))
            need(after == before and after_records == records, "measured metadata observations mutated originals")
            validate_all("postflight")
            current["shutdown"] = controller.close()
            controller = None
            need(current["shutdown"]["original_child_reaped"]
                 and current["shutdown"]["waited"]["exit_code"] == 0
                 and current["shutdown"]["method"] == "stdin_eof"
                 and not current["shutdown"]["errors"]
                 and current["shutdown"]["reader_error"] is None
                 and not current["shutdown"]["unmatched"], "controller did not complete normal original-child shutdown")
            final, final_records = snapshot_originals(state, seed_ids)
            create_file(directory / "originals-after-shutdown.json", canonical(final))
            need(final == before and final_records == records, "shutdown mutated original audit records")
            need(checked_file(config) == current["config"], "fixture config changed")
            current["originals_unchanged"] = True
            current["complete"] = True
            save_report(output / "report.json", report)
            print(json.dumps({"round": round_index, "arm": arm, "complete": True,
                              "measured": current["measured_summary"],
                              "waited_cpu_seconds": current["shutdown"]["waited"]["total_cpu_seconds"]}), flush=True)
        need(all(checked_file(path) == {key: value for key, value in inputs[arm].items() if key != "path"}
                 for arm, path in binaries.items()), "binary input changed during ABBA")
        need(checked_file(Path(__file__).resolve(strict=True)) == script_info, "harness source changed during run")
        need(len(all_measured) == 4 * args.measured and all(row["okay"] for row in all_measured),
             "measured coverage incomplete")
        report["complete"] = report["comparison_valid"] = True
        report["descriptive_comparison"] = {}
        for tool in TOOLS:
            means = {arm: statistics.mean(row["elapsed_ms"] for row in all_measured
                     if row["arm"] == arm and row["tool"] == tool) for arm in ("A", "B")}
            report["descriptive_comparison"][tool] = {"baseline_mean_ms": means["A"],
                "candidate_mean_ms": means["B"], "candidate_mean_change_percent": 100 * (means["B"] / means["A"] - 1)}
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if controller is not None:
            try:
                closing = controller.close()
                if current is not None:
                    current["shutdown"] = closing
            except BaseException as error:
                report["cleanup_error"] = {"type": type(error).__name__, "message": str(error)}
        if current is not None and not current["complete"] and originals_reference is not None:
            try:
                final_failure, _ = snapshot_originals(state, seed_ids)
                create_file(directory / "originals-after-failure.json", canonical(final_failure))
                current["failure_originals_unchanged"] = final_failure == originals_reference
            except BaseException as error:
                current["failure_originals_error"] = {"type": type(error).__name__, "message": str(error)}
        journal.flush()
        os.fsync(journal.fileno())
        journal.close()
        try:
            report["final_inputs"] = {arm: checked_file(path) for arm, path in binaries.items()}
            report["inputs_unchanged"] = all(report["final_inputs"][arm] == {
                key: value for key, value in inputs[arm].items() if key != "path"} for arm in binaries)
            report["script_unchanged"] = checked_file(Path(__file__).resolve(strict=True)) == script_info
            if not report["inputs_unchanged"] or not report["script_unchanged"]:
                report["complete"] = False
        except BaseException as error:
            report["complete"] = False
            report["final_input_error"] = {"type": type(error).__name__, "message": str(error)}
        report["measured_attempted"] = len(all_measured)
        report["measured_unexecuted"] = 4 * args.measured - len(all_measured)
        report["measured_coverage"] = summarize(all_measured)
        if not report["complete"]:
            report["comparison_valid"] = False
            report.pop("descriptive_comparison", None)
            report["measured_coverage"]["performance_valid"] = False
            report["measured_coverage"].pop("tools", None)
        report["calls_file"] = checked_file(output / "calls.jsonl")
        save_report(output / "report.json", report)
    raise SystemExit(0 if report["complete"] else 1)


if __name__ == "__main__":
    main()
