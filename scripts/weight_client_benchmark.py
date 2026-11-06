#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Controlled Linux comparison of weight-client transport, worker RTT and MCP.

Uses only the standard library as a driver. A pre-existing CPU PyTorch Python,
an exact worker package and a built runtime must be supplied. Installs nothing,
creates synthetic fixtures only, and never edits an existing runtime profile.
The optional complete MCP layer requires already-authorized localhost SSH.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import queue
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

MAX_FRAME = 1024 * 1024
ROUTES = ("native_rust", "python_compat")
INPUT = [float(i % 8) / 8.0 for i in range(64)]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def save_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(json.dumps(value, sort_keys=True, indent=2).encode() + b"\n")
    temporary.replace(path)


def environment():
    result = {key: os.environ[key] for key in ("PATH", "HOME", "USER", "LOGNAME", "LANG") if key in os.environ}
    result.update(RUST_LOG="error", OMP_NUM_THREADS="1", MKL_NUM_THREADS="1",
                  OPENBLAS_NUM_THREADS="1", NUMEXPR_NUM_THREADS="1",
                  VECLIB_MAXIMUM_THREADS="1", GOTO_NUM_THREADS="1", PYTHONHASHSEED="0", PYTHONDONTWRITEBYTECODE="1")
    return result


def read_json_frame(raw):
    if len(raw) > MAX_FRAME or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise RuntimeError("expected one bounded JSONL response")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("response is not an object")
    return value


def process_usage(pid):
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
        fields = text[text.rfind(")") + 2:].split()
        ticks = os.sysconf("SC_CLK_TCK")
        result = {"user_cpu_seconds": int(fields[11]) / ticks,
                  "system_cpu_seconds": int(fields[12]) / ticks,
                  "rss_kib": int(fields[21]) * os.sysconf("SC_PAGE_SIZE") / 1024}
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                result["peak_rss_kib"] = int(line.split()[1])
        return result
    except (OSError, ValueError, IndexError):
        return None


def process_call(command, frame, output, label, timeout=60):
    request_path = output / "traces" / (label + ".request.jsonl")
    stdout_path = output / "traces" / (label + ".stdout.jsonl")
    stderr_path = output / "traces" / (label + ".stderr.txt")
    request_path.write_bytes(canonical(frame) + b"\n")
    with request_path.open("rb") as incoming, stdout_path.open("xb") as outgoing, stderr_path.open("xb") as errors:
        started = time.perf_counter_ns()
        child = subprocess.Popen(command, stdin=incoming, stdout=outgoing, stderr=errors, env=environment())
        pidfd = os.pidfd_open(child.pid)
        timed_out = threading.Event()

        def expire():
            timed_out.set()
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass

        timer = threading.Timer(timeout, expire)
        timer.daemon = True
        timer.start()
        try:
            _, status, usage = os.wait4(child.pid, 0)
            elapsed = (time.perf_counter_ns() - started) / 1_000_000
            child.returncode = os.waitstatus_to_exitcode(status)
        finally:
            timer.cancel()
            timer.join()
            os.close(pidfd)
    if timed_out.is_set():
        raise RuntimeError(f"owned client timed out: {label}")
    raw = stdout_path.read_bytes()
    if len(raw) > MAX_FRAME:
        raise RuntimeError("oversized client output")
    reply = read_json_frame(raw)
    expected_exit = 0 if reply.get("ok") else 1
    if child.returncode != expected_exit:
        raise RuntimeError(f"client exit mismatch: {label}: {child.returncode}")
    return reply, raw, {"wall_ms": elapsed, "client_user_cpu_ms": usage.ru_utime * 1000,
                        "client_system_cpu_ms": usage.ru_stime * 1000,
                        "client_peak_rss_kib": usage.ru_maxrss,
                        "exit_code": child.returncode}


def socket_call(path, frame):
    started = time.perf_counter_ns()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(60)
        connection.connect(str(path))
        connection.sendall(canonical(frame) + b"\n")
        parts = []
        size = 0
        while True:
            part = connection.recv(min(65536, MAX_FRAME + 1 - size))
            if not part:
                break
            parts.append(part)
            size += len(part)
            if size > MAX_FRAME:
                raise RuntimeError("oversized worker response")
    raw = b"".join(parts)
    elapsed = (time.perf_counter_ns() - started) / 1_000_000
    return read_json_frame(raw), raw, {"wall_ms": elapsed}


def fixture(path):
    header = canonical({"0.weight": {"dtype": "F32", "shape": [64, 64], "data_offsets": [0, 16384]}})
    header += b" " * (-len(header) % 8)
    data = b"".join(struct.pack("<f", float(row == column)) for row in range(64) for column in range(64))
    path.write_bytes(struct.pack("<Q", len(header)) + header + data)
    return sha_file(path)


def model_params(weights, weight_sha):
    return {"provider": "torch_sequential", "cpu_threads": 1, "idle_timeout_s": 600,
            "max_memory_bytes": 1024 * 1024 * 1024,
            "model": {"architecture": {"layers": [{"type": "Linear", "in_features": 64, "out_features": 64, "bias": False}]},
                      "weights_path": str(weights), "weights_sha256": weight_sha}}


def frame(session, identifier, operation, params):
    return {"id": identifier, "session_id": session, "op": operation, "params": params}


def ensure_ok(reply, label):
    if reply.get("ok") is not True:
        raise RuntimeError(f"{label}: {json.dumps(reply, sort_keys=True)}")


def require_values(reply):
    ensure_ok(reply, "query")
    if reply["result"]["values"] != INPUT:
        raise RuntimeError("identity model returned unexpected tensor values")


class Mcp:
    """Same shipped stdio protocol and local SSH owner route as weight_mcp_external."""
    def __init__(self, binary, config, log):
        self.log = log.open("xb")
        self.audit = log.with_name(log.name + ".rpc.jsonl").open("xb")
        self.child = subprocess.Popen([str(binary), "mcp", "--runtime-config", str(config)],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log,
                                      env=environment())
        self.sequence = 0
        self.replies = queue.Queue()

        def read():
            try:
                for line in self.child.stdout:
                    self.replies.put(line)
            finally:
                self.replies.put(None)

        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()
        try:
            self.request("initialize", {"protocolVersion": "2026-07-28", "capabilities": {},
                                        "clientInfo": {"name": "controlled-weight-benchmark", "version": "1"}})
            self.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        except BaseException:
            self.stop()
            raise

    def send(self, value):
        self.audit.write(canonical({"direction": "request", "message": value}) + b"\n")
        self.audit.flush()
        self.child.stdin.write(canonical(value) + b"\n")
        self.child.stdin.flush()

    def request(self, method, params):
        self.sequence += 1
        identifier = self.sequence
        self.send({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params})
        deadline = time.monotonic() + 120
        for _ in range(256):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("MCP reply deadline")
            raw = self.replies.get(timeout=remaining)
            if raw is None:
                raise RuntimeError("MCP process closed its output")
            value = json.loads(raw)
            self.audit.write(canonical({"direction": "response", "message": value}) + b"\n")
            self.audit.flush()
            if value.get("id") != identifier:
                continue
            if "error" in value:
                raise RuntimeError(f"MCP protocol error: {value['error']}")
            return value["result"]
        raise RuntimeError("too many unrelated MCP notifications")

    def call(self, tool, params):
        result = self.request("tools/call", {"name": tool, "arguments": params})
        if result.get("isError") is True:
            raise RuntimeError(f"{tool}: {result}")
        return json.loads(result["content"][0]["text"])

    def worker_reply(self, session, request=None):
        deadline = time.monotonic() + 120
        offset = 0
        accumulated = ""
        reads = 0
        while time.monotonic() < deadline:
            arguments = {"session_id": session, "stdout_offset": offset, "stderr_offset": 0, "limit": 65536}
            if request is not None:
                arguments["request_id"] = request
            result = self.call("weight_read", arguments)
            reads += 1
            accumulated += result["stdout"].get("text", "")
            offset = result["stdout"]["next_offset"]
            if "\n" in accumulated:
                return json.loads(accumulated.splitlines()[0]), reads
            time.sleep(0.02)
        raise TimeoutError(f"worker reply deadline: {session}/{request}")

    def operation(self, session, identifier, op, params):
        started = time.perf_counter_ns()
        accepted = self.call("weight_call", {"session_id": session, "request_id": identifier,
                                            "op": op, "params": params})
        submitted = time.perf_counter_ns()
        reply, reads = self.worker_reply(session, identifier)
        ended = time.perf_counter_ns()
        return reply, {"wall_ms": (ended - started) / 1_000_000,
                       "submit_ms": (submitted - started) / 1_000_000,
                       "result_observation_ms": (ended - submitted) / 1_000_000,
                       "weight_read_calls": reads, "job_id": accepted["job_id"]}

    def stop(self):
        if self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=10)
        self.reader.join(timeout=5)
        self.child.stdin.close()
        self.child.stdout.close()
        self.log.close()
        self.audit.close()


class Benchmark:
    def __init__(self, args):
        self.args = args
        self.output = Path(args.output).resolve()
        self.output.mkdir(mode=0o700)
        (self.output / "traces").mkdir(mode=0o700)
        (self.output / "bin").mkdir(mode=0o700)
        self.python = Path(os.path.abspath(args.python))
        self.worker = Path(args.worker).resolve()
        source_binary = Path(args.binary).resolve()
        self.binary = self.output / "bin" / "hepta-runtime"
        copied_hash = hashlib.sha256()
        with source_binary.open("rb") as source, self.binary.open("xb") as copied:
            before = os.fstat(source.fileno())
            for block in iter(lambda: source.read(1024 * 1024), b""):
                copied.write(block)
                copied_hash.update(block)
            copied.flush()
            os.fsync(copied.fileno())
            after = os.fstat(source.fileno())
        stamp = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if stamp(before) != stamp(after):
            raise RuntimeError("opened source runtime changed while taking benchmark snapshot")
        self.binary.chmod(0o500)
        self.binary_sha = copied_hash.hexdigest()
        if sha_file(self.binary) != self.binary_sha:
            raise RuntimeError("copied runtime differs from captured source descriptor bytes")
        self.identity = json.loads(subprocess.check_output([str(self.python), str(self.worker), "--print-identity"], env=environment()))
        self.samples = []
        self.trace_sequence = 0
        self.report = {"schema": "hepta.weight.client-benchmark.v1", "status": "running",
                       "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "scope": {"helper": "fresh helper process -> local socket -> shared resident worker -> exit",
                                 "worker_rtt": "driver direct socket -> same resident worker -> socket EOF",
                                 "mcp": "weight_call submission -> original local SSH job -> weight_read response",
                                 "engine": "identical Python/PyTorch CPU worker in every route; no engine rewrite measured",
                                 "cache_state": "fresh client processes; warmed, uncontrolled OS file cache",
                                 "worker_dispatch_cost_excludes": "pending/done ledger fsync and network/transport",
                                 "fixture": "one fixed F32 64x64 identity Linear; one example per probe"},
                       "environment": {"kernel": platform.release(), "machine": platform.machine(),
                                       "cpu_count": os.cpu_count(), "cpu_affinity": sorted(os.sched_getaffinity(0)),
                                       "load_average_start": os.getloadavg(), "driver_python": sys.version,
                                       "python": str(self.python), "worker": str(self.worker),
                                       "worker_identity": self.identity, "source_binary": str(source_binary),
                                       "immutable_benchmark_binary": str(self.binary),
                                       "runtime_sha256": self.binary_sha, "runtime_bytes": self.binary.stat().st_size,
                                       "captured_source_inode": before.st_ino,
                                       "captured_source_mtime_ns": before.st_mtime_ns,
                                       "build_profile": args.build_profile, "source_revision": args.source_revision},
                       "sample_counts_requested": {"helper_and_socket_per_operation": args.samples,
                                                   "complete_mcp_per_operation": args.mcp_samples if args.with_mcp else 0},
                       "semantics": [], "samples": self.samples}
        self.flush()

    def flush(self):
        save_json(self.output / "results.json", self.report)

    def commands(self, socket_path, session):
        common = ["--socket", str(socket_path), "--session-id", session,
                  "--expected-worker-sha256", self.identity["worker_sha256"],
                  "--expected-package-sha256", self.identity["package_sha256"],
                  "--timeout-ms", "30000", "--connect-timeout-ms", "5000"]
        return {"native_rust": [str(self.binary), "weight-client", "--worker-path", str(self.worker),
                                "--expected-client-sha256", self.binary_sha] + common,
                "python_compat": [str(self.python), str(self.worker), "--client"] + common}

    def retain(self, layer, route, operation, identifier, reply, raw, metrics, sample=True):
        record = {"layer": layer, "route": route, "operation": operation, "request_id": identifier,
                  "ok": reply.get("ok"), "response_sha256": hashlib.sha256(raw).hexdigest(), **metrics}
        cost = reply.get("result", {}).get("cost", {})
        for key in ("worker_wall_seconds", "worker_cpu_seconds"):
            if key in cost:
                record[key.replace("_seconds", "_ms")] = cost[key] * 1000
        record["forward_examples_total"] = cost.get("forward_examples_total")
        if sample:
            self.samples.append(record)
        return record

    def direct(self):
        with tempfile.TemporaryDirectory(prefix="hwb-") as temporary:
            root = Path(temporary)
            weights = root / "identity.safetensors"
            weight_sha = fixture(weights)
            session = "controlled-client-benchmark"
            socket_path = root / "worker.sock"
            params = {**model_params(weights, weight_sha), "input_roots": [str(root)], "output_root": str(root / "artifacts")}
            command = [str(self.python), str(self.worker), "--serve", "--socket", str(socket_path),
                       "--session-id", session, "--expected-worker-sha256", self.identity["worker_sha256"],
                       "--expected-package-sha256", self.identity["package_sha256"],
                       "--max-request-ms", "120000", "--lifetime-s", "1800"]
            log = (self.output / "direct-worker.stderr.txt").open("xb")
            started = time.perf_counter_ns()
            worker = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, env=environment())
            try:
                worker.stdin.write(canonical(frame(session, "open-1", "open", params)) + b"\n")
                worker.stdin.flush()
                if not select.select([worker.stdout], [], [], 120)[0]:
                    raise TimeoutError("resident worker open deadline")
                raw = worker.stdout.readline(MAX_FRAME + 1)
                (self.output / "traces" / "worker-open.stdout.jsonl").write_bytes(raw)
                if not raw:
                    raise RuntimeError("resident worker exited before open response: " +
                                       (self.output / "direct-worker.stderr.txt").read_text(errors="replace")[-4096:])
                opened = read_json_frame(raw)
                ensure_ok(opened, "worker open")
                self.report["resident_worker"] = {"startup_wall_ms": (time.perf_counter_ns() - started) / 1_000_000,
                                                  "open_response": opened, "resource_after_open": process_usage(worker.pid),
                                                  "source_weights_sha256": weight_sha}
                (self.output / "traces" / "worker-open.stdout.jsonl").write_bytes(raw)
                commands = self.commands(socket_path, session)

                def invoke(route, identifier, operation, arguments, measured=True):
                    request = frame(session, identifier, operation, arguments)
                    self.trace_sequence += 1
                    trace = f"{route}-{self.trace_sequence:04}-{identifier}"
                    if route == "direct_socket":
                        reply, response, metrics = socket_call(socket_path, request)
                        (self.output / "traces" / (trace + ".stdout.jsonl")).write_bytes(response)
                    else:
                        reply, response, metrics = process_call(commands[route], request, self.output, trace)
                    self.retain("resident_socket" if route == "direct_socket" else "cold_helper",
                                route, operation, identifier, reply, response, metrics, measured)
                    return reply, response

                cases = [("inspect", {"hash": True}), ("probe", {"inputs": {"x": [INPUT]}})]
                artifact = None
                for number, (operation, arguments) in enumerate(cases):
                    identifier = "semantic-" + operation
                    first, second = ROUTES if number % 2 == 0 else tuple(reversed(ROUTES))
                    one, raw_one = invoke(first, identifier, operation, arguments, False)
                    two, raw_two = invoke(second, identifier, operation, arguments, False)
                    ensure_ok(one, operation)
                    if raw_one != raw_two:
                        raise RuntimeError("same worker request replay differed by client")
                    self.report["semantics"].append({"case": operation + "_same_id_replay", "byte_equal": True,
                                                     "response_sha256": hashlib.sha256(raw_one).hexdigest()})
                    if operation == "probe":
                        artifact = one["result"]["outputs"]["artifact_id"]
                        if one["result"]["cost"]["forward_examples_total"] != 1:
                            raise RuntimeError("same-id semantic replay repeated a forward")
                query = {"artifact_id": artifact, "tensor": "output", "offset": 0, "limit": 64}
                for name, operation, arguments, expected in [
                    ("query", "query", query, True),
                    ("worker_error", "inspect", {"names": ["absent.weight"]}, False),
                    ("conflict", "inspect", {"hash": False}, False),
                ]:
                    identifier = "semantic-inspect" if name == "conflict" else "semantic-" + name
                    one, raw_one = invoke("native_rust", identifier, operation, arguments, False)
                    two, raw_two = invoke("python_compat", identifier, operation, arguments, False)
                    if one.get("ok") != expected or two.get("ok") != expected or raw_one != raw_two:
                        raise RuntimeError(f"semantic client mismatch: {name}")
                    if name == "query":
                        require_values(one)
                    self.report["semantics"].append({"case": name, "byte_equal": True,
                                                     "error_code": one.get("error", {}).get("code"),
                                                     "response_sha256": hashlib.sha256(raw_one).hexdigest()})
                operations = [("inspect", {"hash": True}), ("probe", {"inputs": {"x": [INPUT]}}), ("query", query)]
                for route in ("direct_socket",) + ROUTES:
                    reply, _ = invoke(route, "warm-" + route, "inspect", {"hash": True}, False)
                    ensure_ok(reply, "warmup")
                for number in range(self.args.samples):
                    for operation, arguments in operations:
                        clients = list(ROUTES if number % 2 == 0 else tuple(reversed(ROUTES)))
                        order = ["direct_socket"] + clients if number % 2 == 0 else clients + ["direct_socket"]
                        for route in order:
                            identifier = f"sample-{number:03}-{operation}-{route}"
                            reply, _ = invoke(route, identifier, operation, arguments)
                            ensure_ok(reply, identifier)
                            if operation == "query":
                                require_values(reply)
                    self.flush()
                self.report["resident_worker"]["resource_after_samples"] = process_usage(worker.pid)
                closed, _, _ = socket_call(socket_path, frame(session, "close-1", "close", {}))
                ensure_ok(closed, "close")
                worker.wait(timeout=30)
                if worker.returncode != 0:
                    raise RuntimeError("resident worker did not close cleanly")
                self.report["resident_worker"]["exit_code"] = worker.returncode
                if sha_file(weights) != weight_sha:
                    raise RuntimeError("benchmark modified source weights")
                self.report["resident_worker"]["source_unchanged"] = True
            finally:
                if worker.poll() is None:
                    worker.terminate()
                    try:
                        worker.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        worker.kill()
                        worker.wait(timeout=10)
                worker.stdin.close()
                worker.stdout.close()
                log.close()
        self.flush()

    def mcp_config(self, root, route):
        worker_parent = self.worker.parent
        config = {"state_dir": str(root / "controller-state"), "controller_workspace_roots": [str(root)],
                  "hosts": {"local": {"ssh_target": "localhost", "remote_state_dir": str(root / "jobs"),
                                      "execution_mode": "operator", "system_jobctl": False,
                                      "allow_execute": True, "allow_write": True, "allow_job_network": True,
                                      "allow_detached_fallback": False, "allowed_cwd_prefixes": [],
                                      "protected_path_prefixes": [], "protected_argument_substrings": [],
                                      "denied_executables": [], "allowed_dangerous_executables": [],
                                      "allowed_read_path_prefixes": [str(root), str(worker_parent), str(self.binary)],
                                      "allowed_write_path_prefixes": [str(root)]}},
                  "weight_workers": {"cpu": {"host": "local", "python_executable": str(self.python),
                                              "worker_path": str(self.worker),
                                              "worker_sha256": self.identity["worker_sha256"],
                                              "worker_package_sha256": self.identity["package_sha256"],
                                              "session_root": str(root / "sessions"), "input_roots": [str(root)],
                                              "allowed_providers": ["torch_sequential"], "max_lifetime_seconds": 1800,
                                              "max_request_ms": 120000, "max_active_sessions": 1,
                                              "max_requests_per_session": 128, "max_cpu_threads": 1,
                                              "max_memory_bytes": 1024 * 1024 * 1024}}}
        if route == "native_rust":
            config["weight_workers"]["cpu"]["native_client"] = {"executable": str(self.binary), "sha256": self.binary_sha}
        return config

    def complete_mcp(self):
        sessions = {}
        base = Path(tempfile.mkdtemp(prefix="hwmb-"))
        successful = False
        self.report["complete_mcp"] = {
            "execution_mode": "operator", "system_jobctl": False,
            "qualification_scope": "administrator-configured localhost SSH with user systemd; not isolated/jobctl mode",
            "poll_interval_ms_after_empty_read": 20, "fixture_directory": str(base),
            "fixture_retained": True, "routes": {}}
        self.flush()
        try:
            for route in ROUTES:
                root = base / route
                root.mkdir(mode=0o700)
                (root / "sessions").mkdir(mode=0o700)
                weights = root / "identity.safetensors"
                weight_sha = fixture(weights)
                config_path = root / "runtime.json"
                save_json(config_path, self.mcp_config(root, route))
                (self.output / ("mcp-" + route + "-config.json")).write_bytes(config_path.read_bytes())
                row = {"config_path": str(config_path), "source_weights_sha256": weight_sha}
                self.report["complete_mcp"]["routes"][route] = row
                self.flush()
                server = Mcp(self.binary, config_path, self.output / ("mcp-" + route + ".stderr.txt"))
                sessions[route] = {"server": server, "weights": weights, "weight_sha": weight_sha}
                profiles = server.call("weight_profiles", {})
                if profiles["profiles"][0]["client_transport"] != route:
                    raise RuntimeError("MCP did not choose requested helper transport")
                started = time.perf_counter_ns()
                identity_key = "controlled-benchmark-" + hashlib.sha256(str(root).encode()).hexdigest()[:12]
                admitted = server.call("weight_open", {"profile": "cpu", "idempotency_key": identity_key,
                                                      "params": model_params(weights, weight_sha)})
                session_id = admitted["session_id"]
                sessions[route]["session"] = session_id
                row["admission"] = admitted
                row["idempotency_key"] = identity_key
                self.flush()
                opened, reads = server.worker_reply(session_id)
                ensure_ok(opened, "MCP model open")
                row["open"] = {"wall_ms": (time.perf_counter_ns() - started) / 1_000_000,
                               "weight_read_calls": reads, "response": opened}
                self.flush()
                probe, _ = server.operation(session_id, "warm-probe", "probe", {"inputs": {"x": [INPUT]}})
                ensure_ok(probe, "MCP warm probe")
                sessions[route]["query"] = {"artifact_id": probe["result"]["outputs"]["artifact_id"],
                                            "tensor": "output", "offset": 0, "limit": 64}
                for op, arguments in [("inspect", {"hash": True}), ("query", sessions[route]["query"])]:
                    reply, _ = server.operation(session_id, "warm-" + op, op, arguments)
                    ensure_ok(reply, "MCP warm " + op)
                    if op == "query":
                        require_values(reply)
            for number in range(self.args.mcp_samples):
                for op in ("inspect", "probe", "query"):
                    for route in ROUTES if number % 2 == 0 else tuple(reversed(ROUTES)):
                        current = sessions[route]
                        params = {"hash": True} if op == "inspect" else {"inputs": {"x": [INPUT]}} if op == "probe" else current["query"]
                        identifier = f"mcp-{number:03}-{op}"
                        reply, metrics = current["server"].operation(current["session"], identifier, op, params)
                        ensure_ok(reply, identifier)
                        if op == "query":
                            require_values(reply)
                        raw = canonical(reply) + b"\n"
                        (self.output / "traces" / (route + "-" + identifier + ".stdout.jsonl")).write_bytes(raw)
                        self.retain("complete_mcp", route, op, identifier, reply, raw, metrics)
                self.flush()
            for route, current in sessions.items():
                server = current["server"]
                closed = server.call("weight_close", {"session_id": current["session"]})
                terminal = server.call("weight_status", {"session_id": current["session"], "wait_seconds": 30})
                if terminal["state"] not in ("cancelled", "succeeded"):
                    raise RuntimeError(f"owned worker is not terminal: {terminal}")
                current["closed"] = True
                if sha_file(current["weights"]) != current["weight_sha"]:
                    raise RuntimeError("MCP benchmark modified source weights")
                self.report["complete_mcp"]["routes"][route].update({
                    "close": closed, "terminal": terminal, "source_unchanged": True,
                    "controller_resource_after_samples": process_usage(server.child.pid)})
            successful = True
        finally:
            cleanup_errors = []
            for route, current in sessions.items():
                server = current["server"]
                if "session" in current and not current.get("closed"):
                    try:
                        closed = server.call("weight_close", {"session_id": current["session"]})
                        terminal = server.call("weight_status", {"session_id": current["session"], "wait_seconds": 30})
                        self.report["complete_mcp"]["routes"][route]["cleanup_close"] = closed
                        self.report["complete_mcp"]["routes"][route]["cleanup_status"] = terminal
                        if terminal["state"] not in ("cancelled", "succeeded"):
                            cleanup_errors.append(route + ": " + str(terminal))
                    except Exception as error:
                        cleanup_errors.append(route + ": " + repr(error))
                server.stop()
            if cleanup_errors:
                self.report["cleanup_errors"] = cleanup_errors
            if successful and not cleanup_errors:
                shutil.rmtree(base)
                self.report["complete_mcp"]["fixture_retained"] = False
            self.flush()
            if cleanup_errors:
                raise RuntimeError("owned worker cleanup not confirmed; original fixture retained: " +
                                   str(base) + ": " + "; ".join(cleanup_errors))
        self.flush()

    def summarize(self):
        groups = {}
        for sample in self.samples:
            key = (sample["layer"], sample["route"], sample["operation"])
            groups.setdefault(key, []).append(sample)
        summary = []
        metrics = ("wall_ms", "client_user_cpu_ms", "client_system_cpu_ms", "client_peak_rss_kib",
                   "worker_wall_ms", "worker_cpu_ms", "submit_ms", "result_observation_ms", "weight_read_calls")
        for key, rows in sorted(groups.items()):
            item = {"layer": key[0], "route": key[1], "operation": key[2], "n": len(rows)}
            for name in metrics:
                values = sorted(row[name] for row in rows if name in row)
                if values:
                    item[name] = {"min": values[0], "p50": values[math.ceil(len(values) * .5) - 1],
                                  "p95": values[math.ceil(len(values) * .95) - 1],
                                  "max": values[-1], "mean": sum(values) / len(values)}
            summary.append(item)
        self.report["summary"] = summary
        self.report["percentiles"] = "nearest-rank; exploratory shared-host measurements, no speedup confidence claim"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--python", required=True)
    parser.add_argument("--worker", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--build-profile", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--mcp-samples", type=int, default=5)
    parser.add_argument("--with-mcp", action="store_true")
    args = parser.parse_args()
    if not (1 <= args.samples <= 40 and 1 <= args.mcp_samples <= 20):
        parser.error("bounded samples required (helper <=40, MCP <=20)")
    if sys.platform != "linux" or not hasattr(os, "pidfd_open"):
        parser.error("Linux pidfd and wait4 are required for exact owned-child resource measurement")
    os.umask(0o077)
    benchmark = Benchmark(args)
    try:
        benchmark.direct()
        if args.with_mcp:
            benchmark.complete_mcp()
        benchmark.summarize()
        benchmark.report["status"] = "passed"
    except Exception as error:
        benchmark.report["status"] = "failed"
        benchmark.report["error"] = repr(error)
        benchmark.summarize()
        raise
    finally:
        benchmark.report["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        benchmark.report["environment"]["load_average_end"] = os.getloadavg()
        benchmark.flush()
    print("WEIGHT_CLIENT_BENCHMARK " + json.dumps({"status": benchmark.report["status"],
                                                  "results": str(benchmark.output / "results.json"),
                                                  "samples": len(benchmark.samples),
                                                  "runtime_sha256": benchmark.binary_sha}, sort_keys=True))


if __name__ == "__main__":
    main()
