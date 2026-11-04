#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Public MCP APK admission and real owned-worker cancellation/deadline gates.

The binary and signed fixture are immutable fingerprinted inputs. The test owns
all created files, state, controllers and parser children. Linux pidfds identify
the actual child. Manual cleanup is recorded only after failure and never
satisfies a gate.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import threading
import time
import zipfile


TOOL = "rea_inspect_apk_signature"
WORKER = b"rea-apk-signature-worker"
CANCEL_BUDGET = 5
WORKER_DEADLINE = 30
DEADLINE_OBSERVATION_BUDGET = 35


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            result.update(chunk)
    return result.hexdigest()


def check(condition, message):
    if not condition:
        raise AssertionError(message)


class Mcp:
    def __init__(self, binary, policy, directory):
        directory.mkdir(mode=0o700)
        self.requests = (directory / "requests.jsonl").open("wb")
        self.stdout = (directory / "stdout.jsonl").open("wb")
        self.stderr = (directory / "stderr.log").open("wb")
        self.process = subprocess.Popen(
            [str(binary), "mcp", "--runtime-config", str(policy)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr,
            cwd="/", env={},
        )
        self.messages = queue.Queue()
        self.counter = 0
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        try:
            self.server_info = self.request("initialize", {
                "protocolVersion": "2026-07-28", "capabilities": {},
                "clientInfo": {"name": "apk-native-independent-mcp", "version": "1"},
            }).get("serverInfo")
            self.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        except BaseException:
            self.close()
            raise

    def _read(self):
        try:
            while True:
                line = self.process.stdout.readline(1024 * 1024 + 1)
                if not line:
                    self.messages.put(EOFError("MCP stdout closed"))
                    return
                check(len(line) <= 1024 * 1024, "MCP line exceeded 1 MiB")
                self.stdout.write(line)
                self.stdout.flush()
                self.messages.put(json.loads(line))
        except BaseException as error:
            self.messages.put(error)

    def send(self, message):
        data = (json.dumps(message, separators=(",", ":")) + "\n").encode()
        self.requests.write(data)
        self.requests.flush()
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def start(self, method, params):
        self.counter += 1
        self.send({"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params})
        return self.counter

    def wait(self, identifier, deadline=None):
        deadline = time.monotonic() + 20 if deadline is None else deadline
        while True:
            remaining = deadline - time.monotonic()
            check(remaining > 0, "MCP response exceeded its original observation budget")
            message = self.messages.get(timeout=remaining)
            if isinstance(message, BaseException):
                raise message
            if message.get("id") == identifier:
                check("error" not in message, "unexpected JSON-RPC error: " + str(message))
                return message["result"]

    def request(self, method, params):
        return self.wait(self.start(method, params))

    def call(self, arguments):
        return self.request("tools/call", {"name": TOOL, "arguments": arguments})

    def close(self):
        cleanup = []
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cleanup.append("controller_terminate_after_close_timeout")
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    cleanup.append("controller_kill_after_terminate_timeout")
                    self.process.kill()
                    self.process.wait(timeout=5)
        self.reader.join(timeout=5)
        self.requests.close()
        self.stdout.close()
        self.stderr.close()
        return {"exit_code": self.process.returncode, "teardown_actions": cleanup}


def report(reply, expected_hash):
    check(reply.get("isError") is not True, "unexpected tool failure: " + str(reply))
    value = json.loads(reply["content"][0]["text"])
    check(value.get("record_format") == "hepta.rea-apk-signature.v1", "wrong report profile")
    check(value["source"]["sha256"] == expected_hash, "wrong captured source identity")
    check(value["rea_evidence_compatible"] is False, "unexpected REA compatibility claim")
    check(value["verification"]["complete_android_verification"] is False, "unexpected complete Android claim")
    return value


def children(parent):
    result = set()
    for path in Path("/proc/" + str(parent) + "/task").glob("*/children"):
        try:
            result.update(map(int, path.read_text().split()))
        except FileNotFoundError:
            pass
    return result


def process_status(pid):
    return dict(
        line.split(":", 1) for line in Path("/proc/" + str(pid) + "/status").read_text().splitlines()
        if ":" in line
    )


def stop_owned_worker(mcp, binary_identity, manual_cleanup):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        for pid in children(mcp.process.pid):
            descriptor = None
            stop_sent = False
            try:
                path = Path("/proc/" + str(pid))
                if WORKER not in (path / "cmdline").read_bytes().split(b"\0"):
                    continue
                descriptor = os.pidfd_open(pid)
                executable = (path / "exe").stat()
                status = process_status(pid)
                check(int(status["PPid"]) == mcp.process.pid, "observed child changed parent")
                check((executable.st_dev, executable.st_ino) == binary_identity, "child executable differs from frozen runtime")
                check(pid in children(mcp.process.pid), "observed child no longer belongs to controller")
                signal.pidfd_send_signal(descriptor, signal.SIGSTOP)
                stop_sent = True
                while time.monotonic() < deadline:
                    if process_status(pid)["State"].strip().startswith("T"):
                        return pid, descriptor
                    time.sleep(0.002)
                raise AssertionError("worker did not enter stopped state within original observation budget")
            except (FileNotFoundError, ProcessLookupError):
                if descriptor is not None:
                    os.close(descriptor)
                continue
            except BaseException:
                if descriptor is not None:
                    if stop_sent:
                        manual_cleanup.append({"pid": pid, "reason": "failed stopped-state observation; never a passing gate"})
                        try:
                            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    os.close(descriptor)
                raise
        time.sleep(0.002)
    raise AssertionError("no live owned APK parser observed; lifecycle gate is unqualified")


def reap_observed(pid, parent):
    return not Path("/proc/" + str(pid)).exists() and pid not in children(parent)


def make_large_apk(path, fixture):
    with zipfile.ZipFile(fixture) as source:
        info = source.getinfo("AndroidManifest.xml")
        check(info.file_size <= 1024 * 1024, "fixture manifest exceeds test budget")
        manifest = source.read(info)
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        with archive.open("owned-padding.bin", "w", force_zip64=False) as member:
            for _ in range(64):
                member.write(b"x" * (1024 * 1024))
    check(path.stat().st_size < 128 * 1024 * 1024, "large fixture exceeds production admission bound")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--fixture-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    check(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"), "Linux pidfds required; no weaker lifecycle fallback")
    binary = args.binary.resolve(strict=True)
    fixture = args.fixture.resolve(strict=True)
    check(digest(binary) == args.binary_sha256, "frozen binary fingerprint differs before test")
    check(digest(fixture) == args.fixture_sha256, "signed fixture fingerprint differs before test")
    binary_stat = binary.stat()
    identity = (binary_stat.st_dev, binary_stat.st_ino)
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    workspace = output / "workspace"
    workspace.mkdir()
    captured = workspace / "signed.apk"
    captured.write_bytes(fixture.read_bytes())
    outside = output / "outside.apk"
    outside.write_bytes(captured.read_bytes())
    link = workspace / "symlink.apk"
    link.symlink_to(outside)
    malformed = workspace / "malformed.apk"
    malformed.write_bytes(captured.read_bytes()[:-7])
    large = workspace / "owned-large-unsigned.apk"
    make_large_apk(large, fixture)
    policy = output / "runtime-config.json"
    policy.write_text(json.dumps({
        "state_dir": str(output / "state"), "controller_workspace_roots": [str(workspace)],
        "hosts": {"never-connect": {
            "ssh_target": "never-connect-invalid", "remote_state_dir": str(output / "never-remote-state"),
            "allow_execute": False, "allow_pty": False, "allow_write": False, "allow_job_network": False,
        }},
    }) + "\n")
    receipt = {
        "schema": "hepta.rea.apk-signature-public-mcp-qualification.v1",
        "status": "running",
        "binary": {"sha256": args.binary_sha256, "bytes": binary_stat.st_size},
        "fixture": {"sha256": args.fixture_sha256, "bytes": fixture.stat().st_size},
        "script_sha256": digest(__file__),
        "large_owned_fixture_bytes": large.stat().st_size,
        "cancel_observation_budget_seconds": CANCEL_BUDGET,
        "worker_deadline_seconds": WORKER_DEADLINE,
        "deadline_observation_budget_seconds": DEADLINE_OBSERVATION_BUDGET,
        "results": [], "manual_worker_cleanup": [], "controllers": [],
        "full_upstream_parity_qualified": False,
        "scope": "Owned fixture admission, actual public MCP and native worker lifecycle on Linux; crypto/Android oracle is separately qualified.",
    }
    mcp = None
    stopped_pid = None
    stopped_fd = None

    def save():
        (output / "qualification.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")

    def passed(gate, **details):
        receipt["results"].append({"gate": gate, "pass": True, **details})
        save()

    def recover():
        check(mcp.process.poll() is None, "controller exited instead of reaping its worker")
        check(not children(mcp.process.pid), "controller still owns an unreaped parser")
        value = report(mcp.call({"path": str(captured), "expected_sha256": args.fixture_sha256}), args.fixture_sha256)
        check(value["verification"]["v2_v3_records"] == "verified", "signed reference did not recover")
        check(not children(mcp.process.pid), "successful parser was not reaped")
        return value

    save()
    try:
        mcp = Mcp(binary, policy, output / "mcp")
        receipt["server_info"] = mcp.server_info
        catalog = mcp.request("tools/list", {})
        check(any(item["name"] == TOOL for item in catalog["tools"]), "APK tool absent from actual MCP catalog")
        first = report(mcp.call({"path": str(captured), "expected_sha256": args.fixture_sha256}), args.fixture_sha256)
        check(first["verification"]["v2_v3_records"] == "verified", "reference fixture is not fully supported")
        check(first["source"]["byte_length"] == fixture.stat().st_size, "source length differs")
        check(not children(mcp.process.pid), "successful parser not reaped")
        passed("actual_public_mcp_worker_and_source_binding")
        for arguments in [
            {"path": str(outside)}, {"path": str(link)}, {"path": str(workspace)},
            {"path": str(captured), "expected_sha256": "0" * 64},
            {"path": str(captured), "expected_sha256": "ABC"},
        ]:
            check(mcp.call(arguments).get("isError") is True, "admission unexpectedly succeeded: " + str(arguments))
        passed("root_symlink_regular_file_and_identity_refusals", cases=5)
        check(mcp.call({"path": str(malformed)}).get("isError") is True, "malformed input unexpectedly succeeded")
        recover()
        passed("malformed_worker_input_then_successful_recovery")

        request_id = mcp.start("tools/call", {"name": TOOL, "arguments": {"path": str(large)}})
        stopped_pid, stopped_fd = stop_owned_worker(mcp, identity, receipt["manual_worker_cleanup"])
        started = time.monotonic()
        deadline = started + CANCEL_BUDGET
        mcp.send({"jsonrpc": "2.0", "method": "notifications/cancelled",
                  "params": {"requestId": request_id, "reason": "independent owned stopped APK worker gate"}})
        while time.monotonic() < deadline and not reap_observed(stopped_pid, mcp.process.pid):
            time.sleep(0.002)
        elapsed = time.monotonic() - started
        check(reap_observed(stopped_pid, mcp.process.pid), "owned stopped parser survived unchanged five-second cancellation budget")
        recover()
        passed("ordinary_mcp_cancellation_original_owner_kills_reaps_and_recovers",
               seconds=elapsed, budget_seconds=CANCEL_BUDGET, owned_pid=stopped_pid,
               manual_worker_cleanup_used_for_pass=False)
        os.close(stopped_fd)
        stopped_pid, stopped_fd = None, None

        requested = time.monotonic()
        request_id = mcp.start("tools/call", {"name": TOOL, "arguments": {"path": str(large)}})
        stopped_pid, stopped_fd = stop_owned_worker(mcp, identity, receipt["manual_worker_cleanup"])
        stopped_at = time.monotonic()
        response = mcp.wait(request_id, deadline=stopped_at + DEADLINE_OBSERVATION_BUDGET)
        elapsed = time.monotonic() - stopped_at
        text = "\n".join(item.get("text", "") for item in response.get("content", []) if item.get("type") == "text")
        check(response.get("isError") is True, "deadline unexpectedly returned success")
        check("30 second wall-clock deadline" in text, "failure was not the runtime fixed deadline: " + text)
        check(29 <= elapsed < DEADLINE_OBSERVATION_BUDGET, "fixed deadline timing outside unchanged observation budget")
        check(reap_observed(stopped_pid, mcp.process.pid), "deadline response preceded owner reaping")
        recover()
        passed("fixed_runtime_deadline_original_owner_kills_reaps_and_recovers",
               seconds_since_observed_stop=elapsed, seconds_since_request=time.monotonic() - requested,
               runtime_deadline_seconds=WORKER_DEADLINE, observation_budget_seconds=DEADLINE_OBSERVATION_BUDGET,
               owned_pid=stopped_pid, manual_worker_cleanup_used_for_pass=False)
        os.close(stopped_fd)
        stopped_pid, stopped_fd = None, None

        closed = mcp.close()
        receipt["controllers"].append(closed)
        mcp = None
        check(closed["exit_code"] == 0 and not closed["teardown_actions"], "first controller did not exit cleanly after stdin EOF")
        mcp = Mcp(binary, policy, output / "mcp-restart")
        again = recover()
        check([s["id"] for s in again["signers"]] == [s["id"] for s in first["signers"]], "cold reinspection changed source-bound signer IDs")
        passed("cold_controller_reinspection_preserves_captured_identity")
        closed = mcp.close()
        receipt["controllers"].append(closed)
        mcp = None
        check(closed["exit_code"] == 0 and not closed["teardown_actions"], "restarted controller did not exit cleanly")
        receipt["binary_sha256_after"] = digest(binary)
        receipt["fixture_sha256_after"] = digest(fixture)
        check(receipt["binary_sha256_after"] == args.binary_sha256, "runtime changed during test")
        check(receipt["fixture_sha256_after"] == args.fixture_sha256, "reference fixture changed during test")
        check(not receipt["manual_worker_cleanup"], "manual cleanup disqualifies a passing receipt")
        receipt["status"] = "pass"
    except BaseException as error:
        receipt["status"] = "fail"
        receipt["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        if stopped_fd is not None:
            if not reap_observed(stopped_pid, mcp.process.pid if mcp is not None else -1):
                receipt["manual_worker_cleanup"].append({"pid": stopped_pid, "reason": "failure teardown; never a passing gate"})
                try:
                    signal.pidfd_send_signal(stopped_fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            os.close(stopped_fd)
        if mcp is not None:
            receipt["controllers"].append(mcp.close())
        save()
        print(json.dumps(receipt, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
