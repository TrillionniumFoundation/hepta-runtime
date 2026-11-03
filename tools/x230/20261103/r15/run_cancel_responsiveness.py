#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bounded local MCP ABBA: host_list responsiveness during wrong-host cancels.

All receipts and hosts are synthetic. The requested host differs from the fully
validated receipt owner, so every process_cancel must fail before its operation
intent or SSH submission. Both versions retain their normal MCP request audits.
This measures rejection-load responsiveness, not successful remote cancellation
throughput. No SSH profile, agent, service or production state is used.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import queue
import subprocess
import threading
import time

import allocator_environment as allocator

MAX_MESSAGE = 1024 * 1024
MAX_RECEIPT = 4 * 1024 * 1024
JOB = "cancel-responsiveness"
EXPECTED_ERROR = f"job `{JOB}` belongs to host `owner`, not `other`"


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def create(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def save(path, value):
    temporary = path.with_suffix(".next")
    create(temporary, encoded(value))
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def process_stat(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    need(fields[0] != "Z", "controller exited during measurement")
    return int(fields[19]), (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def memory_snapshot(pid, birth):
    try:
        need(process_stat(pid)[0] == birth, "controller PID generation changed")
        fields = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines()
                      if ":" in line)
        result = {name: int(fields[name].split()[0]) for name in ("VmRSS", "VmHWM") if name in fields}
        need(process_stat(pid)[0] == birth, "controller PID generation changed")
        return {"kib": result, "source": "same-controller /proc/status", "scope": "whole child since exec"}
    except (OSError, ValueError, RuntimeError) as error:
        return {"error": {"type": type(error).__name__, "reason": str(error)[:300]}}


def distribution(values):
    values = sorted(values)
    need(values, "no measurement samples")
    return {"count": len(values), "minimum_ms": values[0], "maximum_ms": values[-1],
            "p50_ms": values[math.ceil(.5 * len(values)) - 1],
            "p95_ms": values[math.ceil(.95 * len(values)) - 1]}


def receipt(size, payload):
    row = {"execution_mode": "operator", "system_jobctl": False,
           "id": JOB, "host": "owner", "ssh_target": "never-connect.invalid",
           "unit": "hepta-runtime-job-" + JOB,
           "remote_job_dir": "/never-launch/state/jobs/" + JOB,
           "executable": "/usr/bin/true", "args": [""], "cwd": None, "env_keys": [],
           "created_unix_ms": 1, "idempotency_key": "fixture-never-executed",
           "request_fingerprint": 7, "request_digest": "a" * 64,
           "launch_state": "launched", "launch_error": None}
    spare = size - len(encoded(row))
    need(spare >= 0, "receipt size is below the schema overhead")
    row["args"] = ["x" * spare if payload == "plain" else "\n" * (spare // 2) + "x" * (spare % 2)]
    data = encoded(row)
    need(len(data) == size, "fixture encoding size differs")
    return data


def fixture(directory, data):
    directory.mkdir(mode=0o700)
    state = directory / "state"
    state.mkdir(mode=0o700)
    (state / "jobs").mkdir(mode=0o700)
    path = state / "jobs" / (JOB + ".json")
    create(path, data)
    host = {"execution_mode": "operator", "ssh_target": "never-connect.invalid",
            "platform": "linux", "remote_state_dir": "/never-launch/state",
            "allow_execute": False, "allow_pty": False, "allow_write": False,
            "allow_job_network": False, "privileged_actions": {}}
    config = directory / "runtime.json"
    create(config, encoded({"state_dir": str(state), "controller_workspace_roots": [],
                            "hosts": {"owner": host, "other": host}}))
    guard = directory / "guard"
    guard.mkdir(mode=0o700)
    trap = directory / "unexpected-ssh.txt"
    # A fixture-only diagnostic guard: any unexpected ordinary SSH dispatch
    # records a failure and refuses execution. No credentials are inherited.
    script = ("#!/usr/bin/python3\nimport os\n"
              f"fd=os.open({str(trap)!r},os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)\n"
              "os.write(fd,b'unexpected SSH dispatch\\n')\nos.close(fd)\nraise SystemExit(72)\n")
    create(guard / "ssh", script.encode(), 0o700)
    return config, path, guard, trap


class Controller:
    def __init__(self, binary, config, guard, directory, workers, allocator_values=None):
        self.pending = {}
        self.lock = threading.Lock()
        self.sequence = 0
        self.unmatched = 0
        self.reader_error = None
        self.stderr = (directory / "stderr.log").open("xb")
        argv = [str(binary), "mcp", "--runtime-config", str(config),
                "--runtime-prewarm", "--runtime-audit-group-commit"]
        env = {"PATH": str(guard) + ":/usr/bin:/bin", "LANG": "C", "SHELL": "/bin/sh",
               "TOKIO_WORKER_THREADS": str(workers), "RUST_LOG": "warn"}
        allocator_values = allocator.checked(allocator_values or {})
        env = allocator.child_environment(env, allocator_values)
        started = time.monotonic()
        self.child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=self.stderr, cwd=directory, env=env, start_new_session=True)
        self.birth = process_stat(self.child.pid)[0]
        self.reader = threading.Thread(target=self.read_loop, daemon=True)
        self.reader.start()
        try:
            reply = self.batch([("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                "clientInfo": {"name": "hepta-cancel-responsiveness", "version": "1"}})], 120)[0]
            need("result" in reply["response"] and "error" not in reply["response"], "initialization failed")
            self.child.stdin.write(encoded({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}))
            self.child.stdin.flush()
            self.startup = {"pid": self.child.pid, "birth_ticks": self.birth,
                            "ready_ms": (time.monotonic() - started) * 1000,
                            "server_info": reply["response"]["result"].get("serverInfo")}
            self.startup["allocator_environment"] = allocator.observe(
                self.child.pid, self.birth, allocator_values, env, "after-native-initialize")
        except BaseException:
            self.close()
            raise

    def read_loop(self):
        try:
            while True:
                line = self.child.stdout.readline(MAX_MESSAGE + 1)
                if not line:
                    break
                received = time.monotonic()
                need(len(line) <= MAX_MESSAGE and line.endswith(b"\n"), "response framing or size differs")
                response = json.loads(line)
                if "id" not in response:
                    continue
                with self.lock:
                    waiter = self.pending.pop(response["id"], None)
                    if waiter is None:
                        self.unmatched += 1
                if waiter is not None:
                    waiter.put((received, response))
        except Exception as error:
            self.reader_error = type(error).__name__ + ": " + str(error)
        finally:
            with self.lock:
                waiting = list(self.pending.values())
                self.pending.clear()
            for waiter in waiting:
                waiter.put((time.monotonic(), {"error": {"code": -32099,
                            "message": self.reader_error or "controller stdio closed"}}))

    def batch(self, calls, timeout=50):
        work = []
        with self.lock:
            for method, params in calls:
                self.sequence += 1
                waiter = queue.Queue(maxsize=1)
                self.pending[self.sequence] = waiter
                work.append((self.sequence, method, params, waiter))
        frames = b"".join(encoded({"jsonrpc": "2.0", "id": identity, "method": method,
                                   "params": params}) for identity, method, params, _ in work)
        started = time.monotonic()
        try:
            self.child.stdin.write(frames)
            self.child.stdin.flush()
            rows = []
            for identity, method, params, waiter in work:
                received, response = waiter.get(timeout=max(.001, timeout - (time.monotonic() - started)))
                need(response.get("id", identity) == identity, "response identity differs")
                rows.append({"rpc_id": identity, "method": method, "params": params,
                             "elapsed_ms": (received - started) * 1000,
                             "response_sha256": digest(encoded(response)), "response": response})
            return rows
        finally:
            with self.lock:
                for identity, _, _, _ in work:
                    self.pending.pop(identity, None)

    def close(self):
        method = "already_exited"
        if self.child.poll() is None:
            method = "stdin_eof"
            self.child.stdin.close()
            try:
                self.child.wait(30)
            except subprocess.TimeoutExpired:
                method = "sigterm_after_eof_timeout"
                self.child.terminate()
                try:
                    self.child.wait(10)
                except subprocess.TimeoutExpired:
                    method = "sigkill_after_sigterm_timeout"
                    self.child.kill()
                    self.child.wait(10)
        self.reader.join(2)
        self.stderr.close()
        return {"exit_code": self.child.returncode, "method": method,
                "unmatched": self.unmatched, "reader_error": self.reader_error}


def calls(concurrency):
    return [("tools/call", {"name": "process_cancel", "arguments": {
        "host": "other", "job_id": JOB, "grace_seconds": 0}})] * concurrency + [
        ("tools/call", {"name": "host_list", "arguments": {}})]


def validate(rows):
    for row in rows:
        response = row["response"]
        if row["params"]["name"] == "process_cancel":
            need(("error" in response or response.get("result", {}).get("isError") is True)
                 and EXPECTED_ERROR in json.dumps(response, ensure_ascii=False),
                 "cancel did not return the exact expected host-binding refusal: " + str(response)[:500])
        else:
            need("error" not in response and not response["result"].get("isError"), "host_list failed")
            content = response["result"].get("content", [])
            texts = [part["text"] for part in content if part.get("type") == "text"]
            need(texts and {host["name"] for host in json.loads(texts[0])["hosts"]} == {"owner", "other"},
                 "host_list did not return the fixture hosts")
        row["expected_result"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--candidate-arena-max", type=int, choices=allocator.ALLOWED_ARENA_MAX, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, nargs="+", default=[1, 2])
    parser.add_argument("--receipt-bytes", type=int, nargs="+", default=[1024, MAX_RECEIPT - 32])
    parser.add_argument("--payload", choices=["plain", "escaped"], default="escaped")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--waves", type=int, default=12)
    args = parser.parse_args()
    need(all(value in (1, 2, 4) for value in args.workers), "workers must be 1, 2 or 4")
    need(1 <= args.concurrency <= 16 and 1 <= args.waves <= 128, "work bounds exceeded")
    need(all(1024 <= size <= MAX_RECEIPT for size in args.receipt_bytes), "invalid receipt size")
    root = args.out.resolve()
    root.mkdir(mode=0o700)
    binaries = {"A": args.baseline.resolve(strict=True), "B": args.candidate.resolve(strict=True)}
    for path in binaries.values():
        need(path.is_file() and os.access(path, os.X_OK), "runtime binary is not executable")
    report = {"schema": "hepta-x230-cancel-responsiveness/v1", "started_unix": time.time(),
              "binary_sha256": {arm: file_digest(path) for arm, path in binaries.items()},
              "harness_sha256": file_digest(__file__), "automatic_retries": 0,
              "method": "ABBA, fresh local MCP controllers, two mixed warmup waves, identical fixture bytes",
              "metric_scope": "host_list latency under expected wrong-host cancel refusals, not remote job throughput",
              "order": "ABBA", "payload": args.payload, "concurrency": args.concurrency,
              "waves": args.waves, "rounds": [], "okay": False}
    allocator_arms = {"A": {}, "B": allocator.configured(args.candidate_arena_max)}
    report["allocator_configuration"] = allocator.run_metadata(allocator_arms, report["binary_sha256"])
    path = root / "report.json"
    save(path, report)
    try:
        for workers in args.workers:
            for size in args.receipt_bytes:
                data = receipt(size, args.payload)
                for position, arm in enumerate("ABBA"):
                    directory = root / f"w{workers}-b{size}-{position}-{arm}"
                    config, source, guard, trap = fixture(directory, data)
                    row = {"arm": arm, "position": position, "workers": workers, "receipt_bytes": size,
                           "receipt_sha256": digest(data), "warmup": [], "measured": []}
                    report["rounds"].append(row)
                    controller = None
                    try:
                        controller = Controller(binaries[arm], config, guard, directory, workers,
                                                allocator_values=allocator_arms[arm])
                        row["startup"] = controller.startup
                        # Validate the intended refusal before any timed work. All
                        # warmups and measured replies remain in the raw report.
                        for _ in range(2):
                            replies = controller.batch(calls(args.concurrency))
                            row["warmup"].extend(replies)
                            validate(replies)
                        birth, before_cpu = process_stat(controller.child.pid)
                        need(birth == controller.birth, "controller identity changed")
                        row["memory_before"] = memory_snapshot(controller.child.pid, controller.birth)
                        started = time.monotonic()
                        for wave in range(args.waves):
                            replies = controller.batch(calls(args.concurrency))
                            for reply in replies:
                                reply["wave"] = wave
                            row["measured"].extend(replies)
                            validate(replies)
                        row["wall_seconds"] = time.monotonic() - started
                        birth, after_cpu = process_stat(controller.child.pid)
                        need(birth == controller.birth and after_cpu >= before_cpu, "controller CPU identity differs")
                        row["controller_cpu_seconds"] = after_cpu - before_cpu
                        row["memory_after"] = memory_snapshot(controller.child.pid, controller.birth)
                        for tool in ("host_list", "process_cancel"):
                            row[tool] = distribution([sample["elapsed_ms"] for sample in row["measured"]
                                                       if sample["params"]["name"] == tool])
                        row["receipt_unchanged"] = file_digest(source) == digest(data)
                        row["no_cancel_intent"] = not (directory / "state/audit/events.jsonl").exists()
                        row["no_ssh_dispatch"] = not trap.exists()
                        need(row["receipt_unchanged"] and row["no_cancel_intent"] and row["no_ssh_dispatch"],
                             "fixture changed or cancellation advanced beyond rejection")
                        row["okay"] = True
                    finally:
                        if controller is not None:
                            row["shutdown"] = controller.close()
                        save(path, report)
                    need(row["shutdown"]["exit_code"] == 0 and row["shutdown"]["method"] == "stdin_eof"
                         and row["shutdown"]["unmatched"] == 0 and row["shutdown"]["reader_error"] is None,
                         "controller shutdown or response collection failed")
        report["binaries_unchanged"] = all(file_digest(binary) == report["binary_sha256"][arm]
                                             for arm, binary in binaries.items())
        need(report["binaries_unchanged"] and file_digest(__file__) == report["harness_sha256"],
             "benchmark input changed")
        need(allocator.source_sha256() == report["allocator_configuration"]["helper_sha256"],
             "allocator helper changed during experiment")
        report["okay"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
        raise
    finally:
        report["finished_unix"] = time.time()
        save(path, report)
    print(json.dumps({"okay": report["okay"], "report": str(path), "rounds": len(report["rounds"])}))


if __name__ == "__main__":
    main()
