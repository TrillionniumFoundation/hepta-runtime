#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Two fixed ABBA blocks of one synthetic process_list per fresh release process.

Linux wait4 supplies each original child's lifetime peak RSS in KiB, including
startup and shutdown. This is a warm-filesystem-cache, single-list experiment;
it does not measure general service RSS, remote execution, or steady-state TPS.
No user receipts, SSH credentials, production configuration, or local helper
modules are imported. All failed attempts remain in the original report.
"""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import statistics
import subprocess
import sys
import time


SCHEMA = "hepta-inventory-release-rss-abba/v1"
COUNT = 2048
PRIVATE_ARGUMENT_BYTES = 64 * 1024
WIRE_BUDGET = 1024 * 1024
MAX_LINE = WIRE_BUDGET + 64 * 1024
MAX_CAPTURE = 4 * 1024 * 1024
HOSTS = tuple(f"fixture-{index}" for index in range(4))
STAGES = ("format", "fmt-check", "harness-tests", "clippy", "test-build",
          "isolated-tests", "audit-isolated-tests", "release")
PLAN = tuple({"attempt": block * 4 + position + 1, "block": block + 1,
              "position": position + 1, "arm": arm}
             for block in range(2) for position, arm in enumerate("ABBA"))
STOP_SIGNAL = None
DENY_SSH = b'''#!/usr/bin/python3 -I
import os
fd = os.open(os.environ["HEPTA_INVENTORY_SSH_DENIAL_LOG"],
             os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    if os.write(fd, b"denied-before-ssh-exec\\n") != 23:
        raise OSError("incomplete denial receipt")
finally:
    os.close(fd)
os._exit(125)
'''


def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def stop_requested(signum, _frame):
    # Never raise asynchronously between kernel wait4 and recording its result.
    global STOP_SIGNAL
    if STOP_SIGNAL is None:
        STOP_SIGNAL = signum


def check_stop():
    need(STOP_SIGNAL is None, "experiment stopped by " +
         (signal.Signals(STOP_SIGNAL).name if STOP_SIGNAL is not None else "signal"))


def refuse_stopped_report(report):
    if STOP_SIGNAL is not None:
        report["stopped_by_signal"] = signal.Signals(STOP_SIGNAL).name
        report["complete"] = False
        report.pop("summary", None)
        report.setdefault("error", "experiment stopped by " + signal.Signals(STOP_SIGNAL).name)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, "duplicate JSON object member")
        value[key] = item
    return value


def decoded(raw):
    def finite_float(value):
        result = float(value)
        need(math.isfinite(result), "non-finite JSON number")
        return result

    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_float=finite_float,
                      parse_constant=lambda _: need(False, "non-finite JSON number"))


def stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def checked_file(path, expected=None, capture=False, limit=1024 * 1024 * 1024):
    path = Path(path).absolute()
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
         "input is not a bounded regular file: " + path.name)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    digest, chunks, length, prefix = hashlib.sha256(), [], 0, b""
    with os.fdopen(fd, "rb") as stream:
        need(stamp(os.fstat(stream.fileno())) == stamp(before), "input identity changed before read")
        while True:
            raw = stream.read(min(65536, before.st_size + 1 - length))
            if not raw:
                break
            length += len(raw)
            need(length <= before.st_size, "input grew during read")
            digest.update(raw)
            prefix = (prefix + raw[:4])[:4] if len(prefix) < 4 else prefix
            if capture:
                chunks.append(raw)
        need(length == before.st_size and stamp(os.fstat(stream.fileno())) == stamp(before),
             "input changed during read")
    need(stamp(path.lstat()) == stamp(before), "input identity changed after read")
    actual = digest.hexdigest()
    if expected is not None:
        need(actual == valid_sha(expected), "pinned file SHA-256 differs: " + path.name)
    return {"path": path, "sha256": actual, "bytes": length, "stat": before,
            "prefix": prefix, "content": b"".join(chunks) if capture else None}


def sha(path):
    return checked_file(path)["sha256"]


def valid_sha(value):
    need(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
         "expected a lowercase SHA-256")
    return value


def pinned_file(path, expected):
    return checked_file(path, expected)["path"]


def create(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


def save(path, value):
    temporary = path.with_suffix(".next")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def current_sources(source):
    paths = [source / name for name in ("Cargo.toml", "Cargo.lock", "rustfmt.toml")]
    for directory in ("src", "examples"):
        paths.extend(path for path in (source / directory).rglob("*") if path.is_file())
    result = {}
    for path in sorted(paths):
        if not path.is_file():
            continue
        need(not path.is_symlink() and path.resolve().is_relative_to(source.resolve()),
             "compiler input escapes its source snapshot")
        result[str(path.relative_to(source))] = sha(path)
    return result


def qualification_binding(report_path, report_sha, map_path, map_sha, audit_path, audit_sha):
    checked_report = checked_file(report_path, report_sha, capture=True, limit=8 * 1024 * 1024)
    checked_map = checked_file(map_path, map_sha, capture=True, limit=8 * 1024 * 1024)
    checked_audit = checked_file(audit_path, audit_sha, capture=True, limit=32 * 1024 * 1024)
    report_path, map_path, audit_path = checked_report["path"], checked_map["path"], checked_audit["path"]
    # Parse exactly the stable bytes whose SHA was checked, without reopening.
    report, sources = decoded(checked_report["content"]), decoded(checked_map["content"])
    audit = decoded(checked_audit["content"])
    need(report.get("schema") == "hepta-x230-composed-qualification/v1"
         and report.get("qualified") is True
         and report.get("automatic_test_retries") == 0, "original qualification did not pass")
    stages = report.get("stages", [])
    need(tuple(stage.get("name") for stage in stages) == STAGES
         and all(type(stage.get("returncode")) is int and stage["returncode"] == 0
                 for stage in stages), "eight original qualification gates did not pass")
    need(isinstance(sources, dict) and len(sources) > 0
         and all(isinstance(name, str) and not Path(name).is_absolute()
                 and ".." not in Path(name).parts
                 and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
                 for name, digest in sources.items()), "invalid compiler-input map")
    need(report.get("source_tested") == sources == report.get("source_after"),
         "tested and post-qualification source maps differ")
    need(report.get("harness_before") == report.get("harness_after")
         and isinstance(report.get("harness_before"), dict), "qualification helper maps differ")
    need(audit.get("schema") == "hepta-isolated-libtest-audit/v1"
         and audit.get("success") is True and audit.get("expected_filter") == ""
         and audit.get("errors") == [] and not audit.get("fatal_error")
         and audit.get("auditor_sha256") == report["harness_before"].get("audit_isolated_tests.py"),
         "original complete-inventory audit did not pass with the pinned auditor")
    counts = {name: audit.get(name) for name in ("passed", "failed", "ignored", "selected", "executed")}
    need(all(type(value) is int and value >= 0 for value in counts.values())
         and counts["passed"] > 0 and counts["failed"] == 0
         and counts["executed"] == counts["passed"]
         and counts["selected"] == counts["passed"] + counts["ignored"], "audit counts differ")
    command = stages[6].get("command", [])

    def command_path(flag):
        need(isinstance(command, list) and command.count(flag) == 1
             and command.index(flag) + 1 < len(command), "audit stage argument differs")
        return Path(command[command.index(flag) + 1]).absolute()

    evidence = command_path("--evidence")
    need(command_path("--output") == audit_path and Path(audit["evidence"]).absolute() == evidence,
         "audit is not the original qualification-stage output")
    audit_inputs = audit.get("input_sha256", {})
    need(isinstance(audit_inputs, dict) and audit_inputs.get("source-manifest.input") == map_sha,
         "audit source-manifest input differs from the qualified map")
    summary_path = evidence / "summary.json"
    checked_summary = checked_file(summary_path, audit_inputs["summary.json"], capture=True,
                                   limit=8 * 1024 * 1024)
    summary = decoded(checked_summary["content"])
    need(summary.get("schema") == "hepta-isolated-libtest/v1" and summary.get("success") is True
         and summary.get("filter") == "" and type(summary.get("retries")) is int
         and summary["retries"] == 0 and not summary.get("fatal_error")
         and not summary.get("enumeration_errors")
         and all(type(summary.get(name)) is int and summary[name] == counts[name]
                 for name in ("passed", "failed", "ignored", "selected"))
         and summary.get("source_manifest_sha256") == map_sha
         and Path(summary["source_manifest_path"]).absolute() == map_path,
         "original isolated summary does not match the complete audit")
    source_input = evidence / "source-manifest.input"
    pinned_file(source_input, map_sha)
    source = Path(report["source"]).absolute()
    need(source.is_dir() and current_sources(source) == sources, "current compiler inputs differ")
    binary_info = report["binaries"]["hepta-runtime"]
    checked_binary = checked_file(binary_info["path"], binary_info["sha256"])
    binary = checked_binary["path"]
    need(os.access(binary, os.X_OK), "retained release binary is not executable")
    need(checked_binary["prefix"] == b"\x7fELF", "retained release binary is not ELF")
    return {"source": source, "sources": sources, "report": report_path,
            "report_sha256": report_sha, "map": map_path, "map_sha256": map_sha,
            "binary": binary, "binary_sha256": binary_info["sha256"],
            "audit": audit_path, "audit_sha256": audit_sha, "audit_counts": counts,
            "summary": summary_path, "summary_sha256": checked_summary["sha256"],
            "source_input": source_input}


def verify_binding(binding):
    pinned_file(binding["report"], binding["report_sha256"])
    pinned_file(binding["map"], binding["map_sha256"])
    pinned_file(binding["binary"], binding["binary_sha256"])
    pinned_file(binding["audit"], binding["audit_sha256"])
    pinned_file(binding["summary"], binding["summary_sha256"])
    pinned_file(binding["source_input"], binding["map_sha256"])
    need(current_sources(binding["source"]) == binding["sources"], "compiler inputs changed")


def public_row(index):
    # A permutation separates timestamp order from both filename and ID order.
    return {"id": f"synthetic-list-{(index * 859) % COUNT:04d}",
            "host": HOSTS[index % len(HOSTS)], "created_unix_ms": 1700000000000 + index,
            "execution_mode": "operator", "launch_state": "launched"}


def synthetic_record(index):
    row = public_row(index)
    prefix = f"SYNTHETIC_PRIVATE_ARGUMENT_{index:04d}_"
    argument = prefix + "x" * (PRIVATE_ARGUMENT_BYTES - len(prefix))
    return {**row, "system_jobctl": False, "ssh_target": "synthetic.invalid",
            "unit": "synthetic-never-started", "remote_job_dir": "/synthetic/jobs/" + row["id"],
            "executable": "/synthetic/never-executed", "args": [argument],
            "cwd": "/synthetic/workspace", "env_keys": ["SYNTHETIC_ENV"],
            "idempotency_key": None, "request_fingerprint": 0, "request_digest": None,
            "launch_error": None}


def expected_text():
    return encoded({"jobs": [public_row(index) for index in range(COUNT)], "total": COUNT,
                    "inventory_complete": True, "status_authoritative": False}).decode()


def make_fixture(directory):
    state = directory / "state"
    jobs = state / "jobs"
    state.mkdir(mode=0o700)
    jobs.mkdir(mode=0o700)
    manifest = {}
    for index in reversed(range(COUNT)):
        check_stop()
        raw = encoded(synthetic_record(index))
        name = public_row(index)["id"] + ".json"
        create(jobs / name, raw)
        manifest[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    config = {"state_dir": str(state), "hosts": {
        host: {"execution_mode": "operator", "ssh_target": "synthetic.invalid",
               "remote_state_dir": "/synthetic/never-contacted", "allow_execute": False,
               "allow_pty": False, "allow_write": False} for host in HOSTS}}
    config_path = directory / "synthetic-config.json"
    create(config_path, encoded(config) + b"\n")
    create(directory / "fixture-manifest.json", encoded(manifest) + b"\n")
    return config_path, jobs, manifest


def verify_fixture(jobs, manifest):
    need(sorted(path.name for path in jobs.iterdir()) == sorted(manifest),
         "synthetic receipt membership changed")
    total = 0
    # This identical, declared pre-controller pass intentionally warms page cache.
    for name in sorted(manifest):
        check_stop()
        path = jobs / name
        expected = manifest[name]
        checked = checked_file(path, expected["sha256"])
        info = checked["stat"]
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
             and info.st_nlink == 1 and info.st_uid == os.geteuid()
             and info.st_size == expected["bytes"], "synthetic receipt metadata changed")
        total += info.st_size
    return {"records": len(manifest), "bytes": total,
            "manifest_sha256": hashlib.sha256(encoded(manifest)).hexdigest()}


def validate_list_reply(reply, expected):
    need(isinstance(reply, dict) and reply.get("jsonrpc") == "2.0"
         and type(reply.get("id")) is int and reply["id"] == 2
         and set(reply) == {"jsonrpc", "id", "result"}, "list RPC envelope differs")
    result = reply["result"]
    need(isinstance(result, dict) and set(result) <= {"content", "isError"}
         and result.get("isError", False) is False, "list returned a tool error or extra payload")
    need(result.get("content") == [{"type": "text", "text": expected}],
         "list public text is not the exact complete ordered expected DTO")
    # Include the full SDK envelope, not only the inner JSON string. All fixture
    # strings are ASCII; this compact encoding has the same JSON wire length.
    wire = encoded(result)
    checked_wire = encoded({"content": [{"type": "text", "text": expected}], "isError": False})
    need(len(wire) < WIRE_BUDGET and len(checked_wire) < WIRE_BUDGET,
         "complete CallToolResult exceeds the strict fixture wire allowance")
    dto = decoded(expected)
    need(set(dto) == {"jobs", "total", "inventory_complete", "status_authoritative"}
         and dto["total"] == COUNT and len(dto["jobs"]) == COUNT
         and dto["inventory_complete"] is True and dto["status_authoritative"] is False,
         "fixture expected DTO is not complete")
    for index, row in enumerate(dto["jobs"]):
        need(row == public_row(index) and len(row) == 5, "fixture row/order differs")
    return {"rows": COUNT, "inner_text_sha256": hashlib.sha256(expected.encode()).hexdigest(),
            "inner_text_bytes": len(expected.encode()), "sdk_wire_bytes": len(wire),
            "budget_check_sdk_wire_bytes": len(checked_wire),
            "sdk_wire_encoding": "compact JSON re-encoding of the actual SDK result; ASCII fixture; original RPC stream retained separately",
            "sdk_wire_sha256": hashlib.sha256(wire).hexdigest()}


class Controller:
    """Exactly one owner of Popen and wait4; never call Popen.poll/wait/communicate."""

    def __init__(self, directory):
        self.directory = directory
        self.child = self.pidfd = self.reaped = None
        self.waited = None
        self.selector = selectors.DefaultSelector()
        self.files = {name: (directory / (name + ".raw")).open("xb")
                      for name in ("stdout", "stderr")}
        self.observed = {name: 0 for name in self.files}
        self.errors, self.replies, self.received_ids = [], {}, []
        self.notifications = 0
        self.outstanding = None
        self.buffer = bytearray()
        self.parse_stdout = True
        self.signals = []

    def error(self, reason):
        if len(self.errors) < 16:
            self.errors.append(str(reason)[:500])

    def start(self, binary, config, wrapper, denial_log):
        check_stop()
        env = {"PATH": str(wrapper.parent), "LANG": "C", "SHELL": "/bin/sh",
               "RUST_LOG": "warn", "TOKIO_WORKER_THREADS": "2",
               "HEPTA_INVENTORY_SSH_DENIAL_LOG": str(denial_log)}
        self.child = subprocess.Popen(
            [str(binary), "mcp", "--runtime-config", str(config),
             "--runtime-prewarm", "--runtime-audit-group-commit"],
            cwd=self.directory, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0)
        # Inherit the harness's owned job group so outer job teardown can still
        # reach the child if the harness itself is killed. This script signals
        # only its original child, never a process group or unrelated workload.
        try:
            self.pidfd = os.pidfd_open(self.child.pid)
        except (AttributeError, OSError):
            # The only fallback signal occurs after wait4 proves this original
            # direct child remains unreaped. A zombie cannot have a reused PID.
            self.pidfd = None
        for name in ("stdout", "stderr"):
            stream = getattr(self.child, name)
            os.set_blocking(stream.fileno(), False)
            self.selector.register(stream, selectors.EVENT_READ, name)

    def send(self, method, params, identity=None):
        check_stop()
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        if identity is not None:
            need(self.outstanding is None, "more than one controller RPC outstanding")
            self.outstanding = identity
            message["id"] = identity
        raw = encoded(message) + b"\n"
        need(len(raw) < 4096, "fixture request is too large")
        need(self.child.stdin.write(raw) == len(raw), "incomplete request write")

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
                position = self.buffer.index(b"\n") + 1
                need(position <= MAX_LINE, "stdout protocol line exceeds its bound")
                line = bytes(self.buffer[:position])
                del self.buffer[:position]
                value = decoded(line)
                need(isinstance(value, dict) and value.get("jsonrpc") == "2.0",
                     "invalid JSON-RPC protocol message")
                if "id" not in value:
                    need(isinstance(value.get("method"), str)
                         and "result" not in value and "error" not in value,
                         "invalid server notification")
                    self.notifications += 1
                    need(self.notifications <= 16, "too many server notifications")
                    continue
                identity = value["id"]
                need(type(identity) is int and identity == self.outstanding
                     and identity not in self.received_ids, "unexpected or repeated RPC identity")
                self.received_ids.append(identity)
                self.replies[identity] = (value, time.monotonic())
                self.outstanding = None
            need(len(self.buffer) < MAX_LINE, "unterminated stdout line exceeds its bound")
        except Exception as error:
            self.error(error)
            self.parse_stdout = False
            self.buffer.clear()

    def pump(self, timeout):
        for key, _ in self.selector.select(timeout):
            try:
                raw = os.read(key.fileobj.fileno(), 65536)
            except BlockingIOError:
                continue
            if not raw:
                self.selector.unregister(key.fileobj)
                key.fileobj.close()
            else:
                self.consume(key.data, raw)

    def reply(self, identity, timeout):
        deadline = time.monotonic() + timeout
        while identity not in self.replies:
            check_stop()
            need(not self.errors, "; ".join(self.errors))
            remaining = deadline - time.monotonic()
            need(remaining > 0, "controller RPC timeout")
            need(bool(self.selector.get_map()), "controller exited before its RPC response")
            self.pump(min(remaining, 0.2))
        need(not self.errors, "; ".join(self.errors))
        return self.replies.pop(identity)

    def close(self, grace=30.0, escalation=10.0):
        if self.reaped is not None:
            return self.reaped
        if self.child is None:
            for stream in self.files.values():
                stream.close()
            self.selector.close()
            return {"started": False}
        self.reaped = {"started": True, "reaped": False, "original_pid": self.child.pid}
        try:
            try:
                self.child.stdin.close()
            except (BrokenPipeError, OSError):
                pass
            deadline = time.monotonic() + grace
            while self.waited is None:
                pid, status, usage = os.wait4(self.child.pid, os.WNOHANG)
                if pid == self.child.pid:
                    # A signal handler only sets STOP_SIGNAL, so it cannot raise
                    # between the kernel reap and this saved original result.
                    self.waited = (status, usage)
                    self.child.returncode = os.waitstatus_to_exitcode(status)
                    self.reaped.update({"reaped": True, "actual_wait4_pid": pid,
                                        "exit_code": self.child.returncode, "raw_wait_status": status,
                                        "user_cpu_ms": usage.ru_utime * 1000,
                                        "system_cpu_ms": usage.ru_stime * 1000,
                                        "child_cpu_ms": (usage.ru_utime + usage.ru_stime) * 1000,
                                        "maxrss_kib": usage.ru_maxrss})
                    break
                need(pid == 0, "wait4 returned an unrelated child")
                if STOP_SIGNAL is not None:
                    if not self.signals:
                        deadline = min(deadline, time.monotonic() + 2)
                    escalation = min(escalation, 2)
                if time.monotonic() >= deadline:
                    need(len(self.signals) < 2, "original controller could not be reaped after SIGKILL")
                    sent = signal.SIGTERM if not self.signals else signal.SIGKILL
                    try:
                        if self.pidfd is not None:
                            signal.pidfd_send_signal(self.pidfd, sent)
                        else:
                            # The immediately preceding wait4 returned zero;
                            # ECHILD exits through the error path without signal.
                            os.kill(self.child.pid, sent)
                    except ProcessLookupError:
                        pass
                    self.signals.append(sent.name)
                    deadline = time.monotonic() + escalation
                try:
                    self.pump(0.02)
                except Exception as error:
                    self.error("shutdown capture: " + str(error))
            drain_deadline = time.monotonic() + 2
            while self.selector.get_map() and time.monotonic() < drain_deadline:
                try:
                    self.pump(0.02)
                except Exception as error:
                    self.error("final capture: " + str(error))
                    break
            if self.selector.get_map():
                self.error("stdout/stderr remained open after original child exit")
            if self.buffer:
                self.error("unterminated final stdout protocol message")
        except Exception as error:
            self.error("owned-child custody/cleanup: " + type(error).__name__ + ": " + str(error))
        finally:
            # Include pipes that start() may have created but not yet registered.
            for name in ("stdin", "stdout", "stderr"):
                stream = getattr(self.child, name, None)
                if stream is not None:
                    try:
                        stream.close()
                    except OSError as error:
                        self.error("pipe close: " + str(error))
            self.selector.close()
            if self.pidfd is not None:
                try:
                    os.close(self.pidfd)
                except OSError as error:
                    self.error("pidfd close: " + str(error))
                self.pidfd = None
            for stream in self.files.values():
                try:
                    stream.close()
                except OSError as error:
                    self.error("capture close: " + str(error))
            self.reaped.update({"shutdown_signals": self.signals,
                                "received_response_ids": self.received_ids,
                                "notifications": self.notifications, "capture_errors": self.errors,
                                "observed_stream_bytes": self.observed})
        return self.reaped


def attempt(specification, binding, directory, wrapper, wrapper_sha, expected):
    row = {**specification, "okay": False, "started_utc": utc(), "errors": [],
           "binary_sha256": binding["binary_sha256"]}
    directory.mkdir(mode=0o700)
    save(directory / "started.json", row)
    controller = Controller(directory)
    jobs = manifest = None
    try:
        config, jobs, manifest = make_fixture(directory)
        config_sha = sha(config)
        row["fixture_before"] = verify_fixture(jobs, manifest)
        verify_binding(binding)
        pinned_file(wrapper, wrapper_sha)
        denial_log = directory / "ssh-denied.log"
        create(denial_log, b"")
        startup = time.monotonic()
        controller.start(binding["binary"], config, wrapper, denial_log)
        controller.send("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                        "clientInfo": {"name": "hepta-inventory-rss-abba", "version": "1"}}, 1)
        initialized, ready = controller.reply(1, 60)
        need(set(initialized) == {"jsonrpc", "id", "result"}
             and isinstance(initialized["result"], dict), "MCP initialize failed")
        row["ready_ms"] = (ready - startup) * 1000
        controller.send("notifications/initialized", {})
        started = time.monotonic()
        controller.send("tools/call", {"name": "process_list", "arguments": {}}, 2)
        reply, received = controller.reply(2, 120)
        row["list_elapsed_ms"] = (received - started) * 1000
        row["response"] = validate_list_reply(reply, expected)
    except Exception as error:
        row["errors"].append(type(error).__name__ + ": " + str(error)[:500])
    finally:
        try:
            row["shutdown"] = controller.close()
            shutdown = row["shutdown"]
            need(shutdown.get("started") is True and shutdown.get("reaped") is True
                 and shutdown.get("exit_code") == 0
                 and shutdown.get("shutdown_signals") == []
                 and shutdown.get("capture_errors") == []
                 and shutdown.get("received_response_ids") == [1, 2],
                 "original controller did not complete cleanly and reap with exactly two RPC replies")
        except Exception as error:
            if controller.reaped is not None:
                row["shutdown"] = controller.reaped
            row["errors"].append("shutdown: " + type(error).__name__ + ": " + str(error)[:500])
        try:
            if jobs is not None and manifest is not None:
                row["fixture_after"] = verify_fixture(jobs, manifest)
                need(row["fixture_before"] == row["fixture_after"], "fixture pre/post differs")
                pinned_file(config, config_sha)
                need(denial_log.read_bytes() == b"", "SSH was attempted by the list workload")
            verify_binding(binding)
            pinned_file(wrapper, wrapper_sha)
            row["inputs_unchanged"] = True
        except Exception as error:
            row["errors"].append("input verification: " + type(error).__name__ + ": " + str(error)[:500])
        row["artifacts"] = {name: {"sha256": sha(path), "bytes": path.stat().st_size}
                            for name in ("stdout.raw", "stderr.raw", "ssh-denied.log",
                                         "fixture-manifest.json", "synthetic-config.json")
                            if (path := directory / name).is_file()}
        row["finished_utc"] = utc()
        row["okay"] = not row["errors"] and "response" in row
        save(directory / "attempt.json", row)
    return row


def numbers(values):
    need(values and all(type(value) in (int, float) and math.isfinite(value) and value >= 0
                        for value in values), "invalid metric sample")
    return {"count": len(values), "mean": statistics.mean(values),
            "median": statistics.median(values), "minimum": min(values), "maximum": max(values)}


def summarize(rows):
    need(len(rows) == len(PLAN), "cannot summarize an incomplete ABBA experiment")
    for expected, row in zip(PLAN, rows):
        need(all(type(row.get(key)) is type(value) and row[key] == value
                 for key, value in expected.items()) and row.get("okay") is True,
             "attempt order/inclusion differs or a failed attempt was excluded")
        shutdown, response = row["shutdown"], row["response"]
        need(row.get("errors") == [] and row.get("inputs_unchanged") is True
             and shutdown.get("started") is True and shutdown.get("reaped") is True
             and shutdown.get("exit_code") == 0
             and shutdown.get("raw_wait_status") == 0
             and type(shutdown.get("actual_wait4_pid")) is int and shutdown["actual_wait4_pid"] > 0
             and shutdown.get("shutdown_signals") == [] and shutdown.get("capture_errors") == []
             and shutdown.get("received_response_ids") == [1, 2],
             "attempt did not retain clean original-child completion and input verification")
        need(response.get("rows") == COUNT
             and type(response.get("sdk_wire_bytes")) is int
             and 0 < response["sdk_wire_bytes"] < WIRE_BUDGET
             and type(response.get("budget_check_sdk_wire_bytes")) is int
             and 0 < response["budget_check_sdk_wire_bytes"] < WIRE_BUDGET,
             "attempt did not retain a complete bounded response")
        need(row.get("fixture_before") == row.get("fixture_after")
             and row["fixture_before"].get("records") == COUNT
             and row["fixture_before"].get("bytes", 0) >= COUNT * PRIVATE_ARGUMENT_BYTES,
             "attempt fixture was incomplete or changed")

    def section(selected):
        result = {}
        for arm in "AB":
            group = [row for row in selected if row["arm"] == arm]
            result[arm] = {"list_elapsed_ms": numbers([row["list_elapsed_ms"] for row in group]),
                           "child_cpu_ms": numbers([row["shutdown"]["child_cpu_ms"] for row in group]),
                           "maxrss_kib": numbers([row["shutdown"]["maxrss_kib"] for row in group])}
        result["B_vs_A_percent"] = {
            metric: {kind: (100 * (result["B"][metric][kind] / result["A"][metric][kind] - 1)
                            if result["A"][metric][kind] else None)
                     for kind in ("mean", "median")}
            for metric in result["A"]}
        return result

    return {"pooled": section(rows),
            "per_block": [{"block": block, **section([row for row in rows if row["block"] == block])}
                          for block in (1, 2)],
            "inclusion": "all eight original attempts; four independent process peaks per arm",
            "tail_scope": "n=4 per arm; no steady-state or statistically established p99 claim"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arm in ("a", "b"):
        parser.add_argument("--qualification-" + arm, type=Path, required=True)
        parser.add_argument("--qualification-" + arm + "-sha256", required=True)
        parser.add_argument("--source-map-" + arm, type=Path, required=True)
        parser.add_argument("--source-map-" + arm + "-sha256", required=True)
        parser.add_argument("--audit-" + arm, type=Path, required=True)
        parser.add_argument("--audit-" + arm + "-sha256", required=True)
    parser.add_argument("--harness-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    need(sys.flags.isolated and sys.dont_write_bytecode, "launch with /usr/bin/python3 -I -B")
    need(sys.platform == "linux" and hasattr(os, "wait4"), "requires Linux wait4 RSS units")
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, stop_requested)
    harness = pinned_file(Path(__file__).absolute(), args.harness_sha256)
    bindings = {arm.upper(): qualification_binding(
        getattr(args, "qualification_" + arm), getattr(args, "qualification_" + arm + "_sha256"),
        getattr(args, "source_map_" + arm), getattr(args, "source_map_" + arm + "_sha256"),
        getattr(args, "audit_" + arm), getattr(args, "audit_" + arm + "_sha256"))
        for arm in ("a", "b")}
    need(bindings["A"]["binary_sha256"] != bindings["B"]["binary_sha256"], "A/B ELF hashes are equal")
    output = args.output.absolute()
    need(output.parent.is_dir() and not output.exists(), "output must be a new experiment directory")
    need(all(not output.resolve().is_relative_to(binding["source"].resolve())
             for binding in bindings.values()), "output cannot modify either source snapshot")
    need(shutil.disk_usage(output.parent).free >= len(PLAN) * COUNT * PRIVATE_ARGUMENT_BYTES
         + 256 * 1024 * 1024, "insufficient space to retain all eight synthetic fixtures")
    output.mkdir(mode=0o700)
    tools_dir = output / "deny-tools"
    tools_dir.mkdir(mode=0o700)
    wrapper = tools_dir / "ssh"
    create(wrapper, DENY_SSH, 0o700)
    wrapper_sha = hashlib.sha256(DENY_SSH).hexdigest()
    expected = expected_text()
    report = {"schema": SCHEMA, "complete": False, "started_utc": utc(),
              "harness_sha256": args.harness_sha256, "embedded_ssh_deny_sha256": wrapper_sha,
              "local_helper_imports": [], "planned_attempts": list(PLAN), "attempts": [],
              "automatic_retries": 0, "records_per_process": COUNT,
              "private_argument_bytes_per_record": PRIVATE_ARGUMENT_BYTES,
              "private_argument_bytes_per_process": COUNT * PRIVATE_ARGUMENT_BYTES,
              "methods_per_process": ["initialize", "notifications/initialized", "process_list"],
              "memory_scope": "Linux wait4.ru_maxrss KiB: original controller lifetime peak including startup/shutdown; one list per fresh process; not general service RSS",
              "cpu_scope": "wait4 user+system CPU for each original child lifetime, including startup/shutdown",
              "latency_scope": "request write through full response reception and JSON-RPC decode; expected DTO validation happens afterward",
              "cache_scope": "same sorted full receipt read/hash pass before every controller; intentionally warm filesystem page cache; no global cache dropping",
              "state_scope": "fresh exclusively created synthetic state per process; no user history or inherited SSH credentials",
              "bindings": {arm: {"qualification_sha256": value["report_sha256"],
                                  "source_map_sha256": value["map_sha256"],
                                  "isolated_audit_sha256": value["audit_sha256"],
                                  "isolated_summary_sha256": value["summary_sha256"],
                                  "audited_counts": value["audit_counts"],
                                  "source_files": len(value["sources"]),
                                  "release_elf_sha256": value["binary_sha256"]}
                           for arm, value in bindings.items()}}
    save(output / "report.json", report)
    try:
        for specification in PLAN:
            check_stop()
            pinned_file(harness, args.harness_sha256)
            for binding in bindings.values():
                verify_binding(binding)
            report["current_attempt"] = specification
            save(output / "report.json", report)
            row = attempt(specification, bindings[specification["arm"]],
                          output / f"attempt-{specification['attempt']:02d}",
                          wrapper, wrapper_sha, expected)
            report["attempts"].append(row)
            save(output / "report.json", report)
            print(encoded({**specification, "okay": row["okay"]}).decode(), flush=True)
            need(row["okay"], "original attempt failed; retained without retry")
        report.pop("current_attempt", None)
        check_stop()
        for binding in bindings.values():
            verify_binding(binding)
        pinned_file(harness, args.harness_sha256)
        pinned_file(wrapper, wrapper_sha)
        need(len({row["response"]["sdk_wire_sha256"] for row in report["attempts"]}) == 1,
             "A/B complete compact SDK results differ")
        check_stop()
        report["summary"] = summarize(report["attempts"])
        report["inputs_unchanged"] = True
        check_stop()
        report["complete"] = True
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)[:500]
    finally:
        refuse_stopped_report(report)
        report["finished_utc"] = utc()
        save(output / "report.json", report)
        # A signal can also arrive while flushing the final report. Keep the
        # complete attempts, but do not publish a stopped run as a successful one.
        if STOP_SIGNAL is not None and report["complete"]:
            refuse_stopped_report(report)
            save(output / "report.json", report)
        print(encoded({"complete": report["complete"], "attempts": len(report["attempts"]),
                       "report_sha256": sha(output / "report.json")}).decode(), flush=True)
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        sys.exit(1)
