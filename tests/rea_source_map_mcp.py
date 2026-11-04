#!/usr/bin/env python3
"""Actual MCP/worker source-map admission, pagination, refusal and cancellation.

The selected binary is immutable input. All inputs and state are owned fixtures.
This test does not use production credentials, ports, engines, or runtime state.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import tempfile
import threading
import time


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Mcp:
    def __init__(self, binary, policy, error_log):
        self.error_stream = open(error_log, "xb")
        self.process = subprocess.Popen(
            [str(binary), "mcp", "--runtime-config", str(policy)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.error_stream,
            env={}, cwd="/", text=True, bufsize=1,
        )
        self.messages = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.counter = 0
        self.request("initialize", {"protocolVersion": "2026-07-28", "capabilities": {},
                                     "clientInfo": {"name": "source-map-qualification", "version": "1"}})
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def _read(self):
        for line in self.process.stdout:
            try:
                self.messages.put(json.loads(line))
            except Exception as error:
                self.messages.put({"reader_error": str(error)})

    def send(self, value):
        self.process.stdin.write(json.dumps(value, separators=(",", ":")) + "\n")
        self.process.stdin.flush()

    def start(self, method, params):
        self.counter += 1
        self.send({"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params})
        return self.counter

    def wait(self, identity, seconds=25):
        deadline = time.monotonic() + seconds
        while True:
            item = self.messages.get(timeout=max(0.001, deadline - time.monotonic()))
            assert "reader_error" not in item, item
            if item.get("id") == identity:
                assert "error" not in item, item
                return item["result"]
            assert time.monotonic() < deadline, "MCP response exceeded original deadline"

    def request(self, method, params):
        return self.wait(self.start(method, params))

    def call(self, arguments):
        return self.request("tools/call", {"name": "rea_inspect_source_map", "arguments": arguments})

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        self.error_stream.close()


def report(reply):
    assert not reply.get("isError", False), reply
    return json.loads(reply["content"][0]["text"])


def children(parent):
    found = set()
    for item in Path(f"/proc/{parent}/task").glob("*/children"):
        try:
            found.update(map(int, item.read_text().split()))
        except FileNotFoundError:
            pass
    return found


def stop_owned_worker(mcp):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        for pid in children(mcp.process.pid):
            try:
                command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
                if b"rea-source-map-worker" not in command:
                    continue
                descriptor = os.pidfd_open(pid)
                try:
                    signal.pidfd_send_signal(descriptor, signal.SIGSTOP)
                except BaseException:
                    os.close(descriptor)
                    raise
                return pid, descriptor
            except (FileNotFoundError, ProcessLookupError):
                continue
        time.sleep(0.002)
    raise AssertionError("did not observe live parser; lifecycle gate is unqualified")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    args.output.mkdir(mode=0o700)
    results = []
    with tempfile.TemporaryDirectory(prefix="hepta-source-map-") as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        workspace.mkdir()
        path = workspace / "input.map"
        source = {"version": 3, "sources": ["original.js"], "names": ["symbol"],
                  "sourcesContent": ["const symbol = '🔥';"], "mappings": "AAAAA,KAAK;AACL"}
        raw = json.dumps(source, ensure_ascii=False, separators=(",", ":")).encode()
        path.write_bytes(raw)
        outside = root / "outside.map"
        outside.write_bytes(raw)
        symlink = workspace / "symlink.map"
        symlink.symlink_to(outside)
        policy = root / "policy.json"
        policy.write_text(json.dumps({"state_dir": str(root / "state"),
            "controller_workspace_roots": [str(workspace)], "hosts": {"never-connect": {
                "ssh_target": "never-connect-invalid", "remote_state_dir": str(root / "remote-state"),
                "allow_execute": False, "allow_pty": False, "allow_write": False, "allow_job_network": False}}}))
        mcp = Mcp(binary, policy, args.output / "mcp.stderr")
        stopped_pid = None
        stopped_fd = None
        cancellation_proven = False
        try:
            catalog = mcp.request("tools/list", {})
            assert any(t["name"] == "rea_inspect_source_map" for t in catalog["tools"])
            first = report(mcp.call({"path": str(path), "collection": "mappings", "limit": 1}))
            assert first["map_sha256"] == sha(raw)
            assert first["counts"]["mappings"] == 3
            assert first["rows"][0]["original"]["name"] == "symbol"
            results.append({"gate": "actual_mcp_worker_and_full_byte_identity", "pass": True})
            page = report(mcp.call({"path": str(path), "collection": "mappings", "offset": 1,
                                   "limit": 1, "expected_analysis_sha256": first["analysis_sha256"]}))
            assert page["rows"][0]["generated"] == {"line": 1, "column": 5}
            results.append({"gate": "bound_continuation", "pass": True})
            for arguments in [
                {"path": str(path), "collection": "mappings", "offset": 1},
                {"path": str(outside)}, {"path": str(symlink)},
                {"path": str(path), "expected_sha256": "0" * 64},
                {"path": str(path), "generated_position": {"line": 0, "column": 0}},
            ]:
                assert mcp.call(arguments).get("isError"), arguments
            results.append({"gate": "admission_and_identity_refusals", "pass": True, "cases": 5})
            invalid = workspace / "invalid.map"
            invalid.write_text(json.dumps({"version": 3, "sources": [], "names": [], "mappings": "g"}))
            assert mcp.call({"path": str(invalid)}).get("isError")
            path.write_bytes(raw + b" ")
            assert mcp.call({"path": str(path), "expected_analysis_sha256": first["analysis_sha256"]}).get("isError")
            path.write_bytes(raw)
            recovered = report(mcp.call({"path": str(path)}))
            assert recovered["analysis_sha256"] == first["analysis_sha256"]
            results.append({"gate": "malformed_and_stale_input_then_recovery", "pass": True})

            # A large but admitted request gives the observer time to identify and
            # SIGSTOP the actual owned parser. All claims use pidfd identity.
            large = workspace / "cancellation.map"
            large.write_text(json.dumps({"version": 3, "sources": ["never-open"],
                "sourcesContent": ["x" * (6 * 1024 * 1024)], "names": [],
                "mappings": ",".join(["AAAA"] * 100_000)}, separators=(",", ":")))
            request_id = mcp.start("tools/call", {"name": "rea_inspect_source_map", "arguments": {"path": str(large)}})
            stopped_pid, stopped_fd = stop_owned_worker(mcp)
            start = time.monotonic()
            mcp.send({"jsonrpc": "2.0", "method": "notifications/cancelled",
                      "params": {"requestId": request_id, "reason": "owned stopped-worker qualification"}})
            while time.monotonic() - start < 5 and Path(f"/proc/{stopped_pid}").exists():
                time.sleep(0.002)
            elapsed = time.monotonic() - start
            assert not Path(f"/proc/{stopped_pid}").exists(), "owned stopped worker survived original five-second cancellation budget"
            assert mcp.process.poll() is None
            assert not children(mcp.process.pid), "worker was not reaped from all parent tasks"
            cancellation_proven = True
            post = report(mcp.call({"path": str(path)}))
            assert post["analysis_sha256"] == first["analysis_sha256"]
            results.append({"gate": "ordinary_mcp_cancellation_kills_reaps_and_recovers", "pass": True,
                            "seconds": elapsed, "budget_seconds": 5, "owned_pid": stopped_pid,
                            "manual_worker_cleanup_used_for_pass": False})
            os.close(stopped_fd)
            stopped_pid, stopped_fd = None, None
            cancellation_proven = False

            # The same owned child must also be reaped when the runtime's fixed
            # 20-second wall deadline expires, without a cancellation request.
            started = time.monotonic()
            request_id = mcp.start("tools/call", {"name": "rea_inspect_source_map", "arguments": {"path": str(large)}})
            stopped_pid, stopped_fd = stop_owned_worker(mcp)
            failed = mcp.wait(request_id, seconds=max(0.001, 25 - (time.monotonic() - started)))
            elapsed = time.monotonic() - started
            assert failed.get("isError"), failed
            assert "20 second wall-clock deadline" in failed["content"][0]["text"], failed
            assert 19 <= elapsed < 25, elapsed
            assert not Path(f"/proc/{stopped_pid}").exists()
            assert not children(mcp.process.pid)
            assert mcp.process.poll() is None
            cancellation_proven = True
            post = report(mcp.call({"path": str(path)}))
            assert post["analysis_sha256"] == first["analysis_sha256"]
            results.append({"gate": "fixed_worker_deadline_kills_reaps_and_recovers", "pass": True,
                            "seconds": elapsed, "runtime_deadline_seconds": 20, "observation_budget_seconds": 25,
                            "owned_pid": stopped_pid, "manual_worker_cleanup_used_for_pass": False})
        finally:
            if stopped_fd is not None:
                if not cancellation_proven:
                    try:
                        signal.pidfd_send_signal(stopped_fd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                os.close(stopped_fd)
            mcp.close()
        # Cold process uses the same admitted bytes, not a retained-result handle.
        mcp = Mcp(binary, policy, args.output / "mcp-restart.stderr")
        try:
            again = report(mcp.call({"path": str(path)}))
            assert again["analysis_sha256"] == first["analysis_sha256"]
            results.append({"gate": "stateless_reinspection_after_controller_restart", "pass": True})
        finally:
            mcp.close()
    receipt = {"schema": "hepta.rea.source-map-mcp-qualification.v1", "status": "pass",
               "binary": {"sha256": sha(binary.read_bytes()), "bytes": binary.stat().st_size},
               "script_sha256": sha(Path(__file__).read_bytes()), "results": results,
               "scope": "Finite owned fixtures, actual MCP and bounded worker on Linux; no full REA compatibility claim."}
    (args.output / "qualification.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
