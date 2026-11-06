#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualify cancellation of an owned, actually stopped JavaScript MCP worker.

Only the MCP process launched here and its observed direct worker may be signalled.
The fixed production 20-second deadline is not changed. A five-second cancellation
window and SIGSTOP prevent natural completion from becoming a cancellation pass.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import select
import shutil
import signal
import subprocess
import sys
import threading
import time

SCHEMA = "hepta.javascript-mcp-cancellation-qualification.v1"
CANCEL_SECONDS = 5.0
START_SECONDS = 10.0
PROTOCOL_SECONDS = 30.0
WORKER_ARG = "rea-javascript-worker"
SOURCE_COUNT = 4
EXPRESSIONS_PER_SOURCE = 90_000


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def now():
    return {"unix_ns": time.time_ns(), "monotonic_ns": time.monotonic_ns()}


def write_json(path, value):
    with Path(path).open("xb") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True).encode() + b"\n")


def identity(pid):
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    end = raw.rfind(")")
    if end < 0:
        raise RuntimeError("invalid /proc stat")
    fields = raw[end + 2:].split()
    return {
        "pid": pid, "state": fields[0], "ppid": int(fields[1]),
        "pgid": int(fields[2]), "start_ticks": int(fields[19]),
        "stat": raw,
    }


def same_identity(actual, expected):
    return actual is not None and actual["pid"] == expected["pid"] and \
        actual["start_ticks"] == expected["start_ticks"]


def command_line(pid):
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[:-1]
    except FileNotFoundError:
        return []


def direct_children(pid):
    children = set()
    try:
        tasks = list(Path(f"/proc/{pid}/task").iterdir())
    except FileNotFoundError:
        return []
    for task in tasks:
        try:
            children.update(int(v) for v in (task / "children").read_text().split())
        except FileNotFoundError:
            pass
    return sorted(children)


class Mcp:
    def __init__(self, runtime, config, workspace):
        self.stdout_path = workspace / "mcp.stdout.jsonl"
        self.stderr_path = workspace / "mcp.stderr.log"
        self.outbound_path = workspace / "mcp.requests.jsonl"
        self.responses = queue.Queue()
        self.pending = {}
        self.reader_errors = []
        self.child = subprocess.Popen(
            [str(runtime), "mcp", "--runtime-config", str(config)],
            cwd="/", env={}, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.owner = identity(self.child.pid)
        if self.owner is None:
            raise RuntimeError("MCP owner exited before identity observation")
        self.threads = [
            threading.Thread(target=self._stdout, daemon=True),
            threading.Thread(target=self._stderr, daemon=True),
        ]
        for thread in self.threads:
            thread.start()

    def _stdout(self):
        count = 0
        try:
            with self.stdout_path.open("xb") as output:
                while True:
                    line = self.child.stdout.readline(2 * 1024 * 1024 + 1)
                    if not line:
                        break
                    count += len(line)
                    if len(line) > 2 * 1024 * 1024 or count > 8 * 1024 * 1024:
                        raise RuntimeError("MCP stdout exceeded harness bound")
                    output.write(line)
                    output.flush()
                    self.responses.put((time.monotonic_ns(), json.loads(line)))
        except BaseException as error:
            self.reader_errors.append(f"stdout: {type(error).__name__}: {error}")

    def _stderr(self):
        count = 0
        try:
            with self.stderr_path.open("xb") as output:
                while True:
                    data = self.child.stderr.read(4096)
                    if not data:
                        break
                    count += len(data)
                    if count > 2 * 1024 * 1024:
                        raise RuntimeError("MCP stderr exceeded harness bound")
                    output.write(data)
                    output.flush()
        except BaseException as error:
            self.reader_errors.append(f"stderr: {type(error).__name__}: {error}")

    def alive(self):
        return self.child.poll() is None and same_identity(identity(self.child.pid), self.owner)

    def send(self, message):
        if not self.alive():
            raise RuntimeError("original MCP owner is no longer alive")
        encoded = json_bytes(message)
        with self.outbound_path.open("ab") as output:
            output.write(encoded)
        self.child.stdin.write(encoded)
        self.child.stdin.flush()
        return hashlib.sha256(encoded).hexdigest()

    def take_ready(self):
        if self.reader_errors:
            raise RuntimeError("; ".join(self.reader_errors))
        while True:
            try:
                observed, message = self.responses.get_nowait()
            except queue.Empty:
                break
            if "id" in message:
                self.pending[message["id"]] = {
                    "observed_monotonic_ns": observed, "message": message,
                }
        return self.pending

    def response(self, request_id, timeout=PROTOCOL_SECONDS):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.take_ready()
            if request_id in self.pending:
                observed = self.pending.pop(request_id)
                message = observed["message"]
                if "error" in message:
                    raise RuntimeError(f"MCP protocol error: {message}")
                return message["result"]
            if not self.alive():
                raise RuntimeError("original MCP owner exited while awaiting response")
            time.sleep(0.01)
        raise RuntimeError(f"MCP response {request_id} exceeded harness deadline")

    def request(self, request_id, method, params):
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        return self.response(request_id)

    def call(self, request_id, arguments):
        return self.request(request_id, "tools/call", {
            "name": "rea_inspect_javascript_graph", "arguments": arguments,
        })

    def close(self):
        result = {"owner_pid": self.child.pid}
        try:
            self.child.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            self.child.wait(timeout=5)
            result["shutdown"] = "stdin_eof"
        except subprocess.TimeoutExpired:
            self.child.terminate()
            try:
                self.child.wait(timeout=3)
                result["shutdown"] = "owned_parent_sigterm"
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=3)
                result["shutdown"] = "owned_parent_sigkill"
        for thread in self.threads:
            thread.join(timeout=3)
        result["exit_code"] = self.child.returncode
        result["owner_reaped"] = identity(self.child.pid) is None
        result["reader_threads_joined"] = all(not thread.is_alive() for thread in self.threads)
        result["reader_errors"] = self.reader_errors
        return result


def graph_report(result):
    if result.get("isError"):
        raise RuntimeError(f"graph tool refused: {result}")
    content = result.get("content", [])
    if len(content) != 1 or content[0].get("type") != "text":
        raise RuntimeError("unexpected graph result representation")
    value = json.loads(content[0]["text"])
    if value.get("record_format") != "hepta.rea-javascript-graph.v1":
        raise RuntimeError("unexpected graph record")
    return value


def copy_runtime(source, destination, expected):
    before = source.stat()
    observed = sha256(source)
    if observed != expected:
        raise RuntimeError(f"runtime SHA mismatch: {observed}")
    with source.open("rb") as reader, destination.open("xb") as writer:
        shutil.copyfileobj(reader, writer, 1024 * 1024)
        writer.flush()
        os.fsync(writer.fileno())
    destination.chmod(0o500)
    after = source.stat()
    copied = sha256(destination)
    if copied != expected or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != \
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise RuntimeError("runtime identity changed while creating qualified copy")
    return {
        "source_path": str(source), "copy_path": str(destination),
        "sha256": copied, "bytes": after.st_size,
        "source_dev": after.st_dev, "source_inode": after.st_ino,
        "source_mtime_ns": after.st_mtime_ns,
    }


def observe_owned_worker(mcp, runtime, request_id):
    deadline = time.monotonic() + START_SECONDS
    while time.monotonic() < deadline:
        if not mcp.alive():
            raise RuntimeError("MCP owner exited before worker observation")
        if request_id in mcp.take_ready():
            raise RuntimeError("graph completed before an owned live worker could be stopped")
        for pid in direct_children(mcp.child.pid):
            first = identity(pid)
            if first is None or first["ppid"] != mcp.child.pid:
                continue
            args = command_line(pid)
            if args != [os.fsencode(runtime), WORKER_ARG.encode()]:
                continue
            try:
                pidfd = os.pidfd_open(pid, 0)
            except ProcessLookupError:
                continue
            second = identity(pid)
            if not same_identity(second, first) or second["ppid"] != mcp.child.pid or \
                    command_line(pid) != args:
                os.close(pidfd)
                continue
            signal.pidfd_send_signal(pidfd, signal.SIGSTOP, None, 0)
            stop_deadline = time.monotonic() + 1
            while time.monotonic() < stop_deadline:
                stopped = identity(pid)
                if not same_identity(stopped, first):
                    os.close(pidfd)
                    raise RuntimeError("owned worker exited before SIGSTOP was confirmed")
                if stopped["state"] == "T":
                    return pidfd, {
                        "before_stop": first, "stopped": stopped,
                        "argv": [os.fsdecode(arg) for arg in args],
                        "pidfd_opened": True, "sigstop_via_pidfd": True,
                        "confirmed_at": now(),
                    }
                time.sleep(0.002)
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
            except ProcessLookupError:
                pass
            os.close(pidfd)
            raise RuntimeError("owned worker did not enter confirmed SIGSTOP state")
        time.sleep(0.002)
    raise RuntimeError("no owned JavaScript worker appeared within harness startup window")


def observe_cancel(mcp, pidfd, worker, workspace, sent_ns):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    expected = worker["before_stop"]
    deadline = time.monotonic() + CANCEL_SECONDS
    samples = 0
    last = None
    with (workspace / "cancel-observations.jsonl").open("xb") as output:
        while True:
            current = identity(expected["pid"])
            owner_alive = mcp.alive()
            children = direct_children(mcp.child.pid) if owner_alive else []
            ready = bool(poller.poll(0))
            last = {
                **now(), "owner_alive": owner_alive,
                "worker_state": current["state"] if same_identity(current, expected) else None,
                "worker_same_identity": same_identity(current, expected),
                "worker_proc_absent": current is None,
                "owner_all_task_children": children, "pidfd_exit_ready": ready,
            }
            output.write(json_bytes(last))
            output.flush()
            samples += 1
            if not owner_alive:
                raise RuntimeError("original MCP owner exited during cancellation observation")
            if current is None and expected["pid"] not in children and ready:
                return {
                    "passed": True, "window_seconds": CANCEL_SECONDS,
                    "duration_seconds": (time.monotonic_ns() - sent_ns) / 1e9,
                    "samples": samples, "final_observation": last,
                    "proof": "same original owner alive; stopped child exited and /proc absent; child absent from every owner task children list",
                }
            if time.monotonic() >= deadline:
                return {
                    "passed": False, "window_seconds": CANCEL_SECONDS,
                    "duration_seconds": (time.monotonic_ns() - sent_ns) / 1e9,
                    "samples": samples, "final_observation": last,
                    "reason": "MCP cancellation did not terminate and reap the confirmed stopped original worker within the fixed observation window",
                }
            time.sleep(0.02)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--expected-runtime-sha256", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--allow-owned-child-signals", action="store_true")
    parser.add_argument("--allow-local-mcp", action="store_true")
    args = parser.parse_args()
    if not args.allow_owned_child_signals or not args.allow_local_mcp:
        parser.error("explicit owned-child signals and local MCP flags are required")
    if sys.platform != "linux" or not hasattr(os, "pidfd_open") or \
            not hasattr(signal, "pidfd_send_signal"):
        parser.error("Linux pidfd_open and pidfd_send_signal are required")
    runtime_source = Path(args.runtime)
    workspace = Path(args.workspace)
    if not runtime_source.is_absolute() or not workspace.is_absolute():
        parser.error("runtime and workspace must be absolute paths")
    if len(args.expected_runtime_sha256) != 64 or \
            any(char not in "0123456789abcdef" for char in args.expected_runtime_sha256):
        parser.error("expected runtime SHA-256 must be lowercase and complete")
    workspace.mkdir(parents=True, mode=0o700, exist_ok=False)
    report = {
        "schema": SCHEMA, "qualified": False, "started": now(),
        "harness": {"path": str(Path(__file__).resolve()), "sha256": sha256(__file__)},
        "scope": "one owned Linux MCP parent and its actual stopped direct JavaScript worker; cancellation and same-owner recovery",
        "production_worker_deadline_seconds": 20,
        "cancellation_observation_seconds": CANCEL_SECONDS,
        "gates": {}, "events": [],
    }
    mcp = None
    pidfd = None
    worker = None
    cleanup = {}
    source_hashes = {}
    runtime_copy = workspace / "hepta-runtime-qualified"

    def progress(phase, **extra):
        event = {"phase": phase, **now(), **extra}
        report["events"].append(event)
        print(json.dumps(event, separators=(",", ":")), flush=True)

    try:
        report["runtime"] = copy_runtime(
            runtime_source, runtime_copy, args.expected_runtime_sha256)
        progress("runtime_copy_verified", sha256=report["runtime"]["sha256"])
        inputs = workspace / "inputs"
        inputs.mkdir(mode=0o700)
        small = inputs / "recovery.js"
        small.write_text("export const alive = 1;\n")
        large_sources = []
        for index in range(SOURCE_COUNT):
            path = inputs / f"owned-{index}.js"
            path.write_text("0;\n" * EXPRESSIONS_PER_SOURCE)
            digest = sha256(path)
            source_hashes[str(path)] = digest
            large_sources.append({
                "id": f"owned-{index}.js", "path": str(path),
                "syntax": "javascript", "module_kind": "module",
                "expected_sha256": digest,
            })
        source_hashes[str(small)] = sha256(small)
        report["fixture"] = {
            "authored_expected": "Each large source consists only of 90000 valid numeric expression statements; no execution or source imports",
            "source_count": SOURCE_COUNT, "expressions_per_large_source": EXPRESSIONS_PER_SOURCE,
            "per_large_source_bytes": (inputs / "owned-0.js").stat().st_size,
            "source_sha256": source_hashes,
            "recovery_expected": {"exported_name": "alive", "source_count": 1},
        }
        config = workspace / "runtime-config.json"
        write_json(config, {
            "state_dir": str(workspace / "state"),
            "controller_workspace_roots": [str(inputs)],
            "hosts": {"never-connect": {
                "ssh_target": "never-connect-invalid",
                "remote_state_dir": str(workspace / "never-used-remote-state"),
                "allow_execute": False, "allow_pty": False,
                "allow_write": False, "allow_job_network": False,
            }},
        })
        report["config"] = {"path": str(config), "sha256": sha256(config)}
        mcp = Mcp(runtime_copy, config, workspace)
        report["owner"] = {**mcp.owner, "argv": [
            str(runtime_copy), "mcp", "--runtime-config", str(config)]}
        report["initialize"] = mcp.request(1, "initialize", {
            "protocolVersion": "2026-07-28", "capabilities": {},
            "clientInfo": {"name": "hepta-js-owned-cancellation", "version": "1"},
        })
        mcp.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        recovery_arguments = {
            "sources": [{"id": "recovery.js", "path": str(small),
                         "expected_sha256": source_hashes[str(small)]}],
            "collection": "exports", "limit": 4,
        }
        baseline = graph_report(mcp.call(2, recovery_arguments))
        write_json(workspace / "baseline-graph.json", baseline)
        report["gates"]["baseline_mcp_worker_succeeds"] = (
            baseline["counts"]["sources"] == 1 and
            baseline["sources"][0]["sha256"] == source_hashes[str(small)] and
            baseline["javascript_executed"] is False)
        if not report["gates"]["baseline_mcp_worker_succeeds"]:
            raise RuntimeError("baseline worker report did not match independent source identity")
        progress("baseline_mcp_worker_succeeded", owner_pid=mcp.child.pid)
        request_id = 3
        large_request = {
            "jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"name": "rea_inspect_javascript_graph",
                       "arguments": {"sources": large_sources, "collection": "summary"}},
        }
        report["large_request"] = {
            "request_id": request_id, "sha256": mcp.send(large_request),
            "sent_at": now(),
        }
        pidfd, worker = observe_owned_worker(mcp, runtime_copy, request_id)
        report["worker"] = worker
        report["gates"]["actual_owned_worker_stopped"] = True
        write_json(workspace / "owned-worker-stopped.json", worker)
        progress("owned_worker_sigstop_confirmed",
                 worker_pid=worker["stopped"]["pid"],
                 worker_start_ticks=worker["stopped"]["start_ticks"])
        cancellation = {
            "jsonrpc": "2.0", "method": "notifications/cancelled",
            "params": {"requestId": request_id,
                       "reason": "owned stopped-worker cancellation qualification"},
        }
        sent_ns = time.monotonic_ns()
        report["cancellation_notification"] = {
            "request_id": request_id, "sent_at": now(),
            "sha256": mcp.send(cancellation),
        }
        outcome = observe_cancel(mcp, pidfd, worker, workspace, sent_ns)
        report["cancellation"] = outcome
        report["gates"]["cancelled_worker_terminated_and_reaped_by_live_original_owner"] = outcome["passed"]
        progress("cancellation_observed", passed=outcome["passed"],
                 elapsed_seconds=outcome["duration_seconds"])
        if not outcome["passed"]:
            report["gates"]["same_owner_next_call_recovers"] = None
            raise RuntimeError(outcome["reason"])
        if not mcp.alive():
            raise RuntimeError("original MCP owner unavailable for recovery")
        recovered = graph_report(mcp.call(4, recovery_arguments))
        write_json(workspace / "recovery-graph.json", recovered)
        recovery_ok = (
            mcp.alive() and recovered["counts"]["sources"] == 1 and
            recovered["sources"][0]["sha256"] == source_hashes[str(small)] and
            recovered["javascript_executed"] is False and
            any(row.get("exported_name") == "alive" for row in recovered["rows"])
        )
        report["gates"]["same_owner_next_call_recovers"] = recovery_ok
        if not recovery_ok:
            raise RuntimeError("same original MCP owner did not return the expected recovery graph")
        progress("same_owner_recovery_succeeded")
        report["qualified"] = all(value is True for value in report["gates"].values())
    except BaseException as error:
        report["qualified"] = False
        report["failure"] = {"type": type(error).__name__, "message": str(error)}
        progress("qualification_failed", error_type=type(error).__name__, message=str(error))
    finally:
        if pidfd is not None:
            expected = worker["before_stop"]
            present = same_identity(identity(expected["pid"]), expected)
            cleanup["worker_present_before_harness_cleanup"] = present
            cleanup["manual_worker_sigkill_sent"] = False
            if present:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
                    cleanup["manual_worker_sigkill_sent"] = True
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and identity(expected["pid"]) is not None:
                    time.sleep(0.02)
            cleanup["worker_proc_absent_before_parent_close"] = identity(expected["pid"]) is None
            cleanup["parent_alive_before_close"] = mcp.alive() if mcp else False
            cleanup["owner_children_before_close"] = direct_children(mcp.child.pid) if mcp else []
            os.close(pidfd)
        if mcp is not None:
            try:
                cleanup["parent"] = mcp.close()
            except BaseException as error:
                cleanup["parent_close_error"] = f"{type(error).__name__}: {error}"
                report["qualified"] = False
        report["cleanup"] = cleanup
        if worker:
            report["cleanup"]["observed_worker_absent_at_end"] = \
                identity(worker["before_stop"]["pid"]) is None
        if cleanup.get("manual_worker_sigkill_sent"):
            report["qualified"] = False
        if runtime_copy.exists():
            report["runtime_copy_sha256_after"] = sha256(runtime_copy)
            if report["runtime_copy_sha256_after"] != args.expected_runtime_sha256:
                report["qualified"] = False
        report["source_bytes_unchanged"] = all(
            sha256(path) == expected for path, expected in source_hashes.items())
        if not report["source_bytes_unchanged"]:
            report["qualified"] = False
        if mcp is not None and (mcp.reader_errors or
                not cleanup.get("parent", {}).get("owner_reaped") or
                not cleanup.get("parent", {}).get("reader_threads_joined")):
            report["qualified"] = False
        report["finished"] = now()
        report["artifacts"] = {
            str(path.relative_to(workspace)): {
                "sha256": sha256(path), "bytes": path.stat().st_size}
            for path in sorted(workspace.rglob("*"))
            if path.is_file() and not path.is_symlink() and
               path != runtime_copy and "state" not in path.relative_to(workspace).parts
        }
        write_json(workspace / "qualification.json", report)
        print(json.dumps({"qualified": report["qualified"],
                          "qualification": str(workspace / "qualification.json"),
                          "qualification_sha256": sha256(workspace / "qualification.json"),
                          "cleanup": cleanup}, separators=(",", ":")), flush=True)
    return 0 if report["qualified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
