#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""One-shot synthetic HTTP qualification of a previously qualified native Runtime.

Planning and this module's unit tests execute no Runtime. Execution is explicit,
uses only loopback, and cannot resume an uncertain run under a new request key.
"""

import argparse
import ctypes
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import resource
import secrets
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time

MAX_WIRE = 2 * 1024 * 1024
PROTOCOL = "2025-11-25"
SUPPORTED_PROTOCOLS = (PROTOCOL,)
BUDGET = {
    "server_starts": 4,
    "rpc_wire_calls": 34,
    "tool_calls": 23,
    "roundtrip_wire_calls": 5,
    "roundtrip_new_intents": 4,
    "recover_wire_calls": 5,
    "head_forward_upper_bound": 18,
    "head_multiply_add_upper_bound": 327732,
    "complete_model_forwards": 0,
    "training_steps": 0,
    "wall_seconds": 900,
    "server_cpu_seconds": 180,
    "server_address_space_bytes": 2 * 1024 * 1024 * 1024,
    "server_tokio_worker_threads": 2,
    "crash_attempts": 1,
    "automatic_retry": False,
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def finite_tree(value):
    if isinstance(value, float):
        require(math.isfinite(value), "nonfinite JSON value")
    elif isinstance(value, dict):
        for child in value.values():
            finite_tree(child)
    elif isinstance(value, list):
        for child in value:
            finite_tree(child)


def parse(raw):
    value = json.loads(raw, object_pairs_hook=unique)
    finite_tree(value)
    return value


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def read(path, limit=MAX_WIRE, private=False):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, "canonical non-symlink file required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "unexpected file or byte limit")
        if private:
            require(before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1, "evidence must be private, owned and single-linked")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) and len(raw) == before.st_size, "file changed during read")
        return raw
    finally:
        os.close(fd)


def write_bytes_once(path, raw, mode=0o600):
    path = Path(path)
    require(path.parent.resolve(strict=True) == path.parent, "canonical destination directory required")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return digest(raw)


def write_once(path, value):
    return write_bytes_once(path, encode(value))


def fixture(columns=2, rows=1, mode="positive"):
    require(columns in (2, 512) and rows in (1, 64), "fixture profile is frozen")
    require(mode in ("positive", "negative", "noop"), "unknown frozen fixture mode")
    weights = [0.0] * (2 * columns)
    weights[0], weights[columns + 1] = 1.0, 1.0
    weight_raw = struct.pack("<" + "f" * len(weights), *weights)
    bias_raw = struct.pack("<2f", 0.5, -0.5)
    n = len(weight_raw)
    header = canonical({
        "readout.weight": {"dtype": "F32", "shape": [2, columns], "data_offsets": [0, n]},
        "readout.bias": {"dtype": "F32", "shape": [2], "data_offsets": [n, n + 8]},
        "physics": {"dtype": "F64", "shape": [1], "data_offsets": [n + 8, n + 16]},
    })
    header += b" " * ((-len(header)) % 8)
    raw = struct.pack("<Q", len(header)) + header + weight_raw + bias_raw + struct.pack("<d", 0.25)
    offset = 8 + len(header)
    changed = bytearray(raw)
    new = 1.0 if mode == "noop" else 2.0
    changed[offset:offset + 4] = struct.pack("<f", new)
    target = [1.5, 1.5] if mode == "negative" else [2.5, 1.5]
    row = [1.0, 2.0] + [0.0] * (columns - 2)
    request = {
        "edits": [{"index": 0, "expected_hex": "0000803f", "replacement_hex": struct.pack("<f", new).hex()}],
        "inputs": [row[:] for _ in range(rows)], "bias": [0.5, -0.5],
        "objective": {"kind": "squared_error", "targets": [target[:] for _ in range(rows)]},
        "minimum_gain": 0.0, "constraints": [],
        "maximum_update_l2_norm": 0.0 if mode == "noop" else 1.0,
    }
    return {
        "source": raw, "candidate": bytes(changed), "request": request,
        "readout": {"weight_tensor": "readout.weight", "weight_payload_sha256": digest(weight_raw),
            "bias_tensor": "readout.bias", "bias_payload_sha256": digest(bias_raw), "outputs": 2, "columns": columns},
        "rows": rows, "columns": columns, "mode": mode,
    }


def package_check(binary, manifest, commit, tree):
    require(all(len(value) == 40 and all(char in "0123456789abcdef" for char in value) for value in (commit, tree)), "full Git source identities required")
    package_raw = read(manifest)
    package = parse(package_raw)
    require(package["schema"] == "hepta.weight.research-executable-package.v1", "wrong package schema")
    require(package["source_commit"] == commit and package["source_tree"] == tree, "package source identity differs")
    require(package["rustc"].startswith("rustc 1.95.0 ") and package["cargo"].startswith("cargo 1.95.0 "), "unqualified toolchain")
    lock_sha = package["cargo_lock_sha256"]
    require(len(lock_sha) == 64 and all(char in "0123456789abcdef" for char in lock_sha), "package lockfile binding is missing")
    require(package["build_command"] == "cargo build --locked --all-features --release --bins --examples", "package build command differs")
    require(package["model_execution_performed"] is False and package["deployment_performed"] is False and package["production_eligible"] is False, "package makes an unsupported qualification claim")
    entries = [entry for entry in package["files"] if entry["path"] == "bin/hepta-runtime"]
    require(len(entries) == 1, "package must contain exactly one Runtime binary")
    raw = read(binary, 512 * 1024 * 1024)
    require(entries[0]["sha256"] == digest(raw) and entries[0]["bytes"] == len(raw) and os.access(binary, os.X_OK), "actual executable differs from package")
    return {"package_manifest_sha256": digest(package_raw), "binary_sha256": digest(raw), "binary_bytes": len(raw),
        "source_commit": commit, "source_tree": tree, "rustc": package["rustc"], "cargo": package["cargo"],
        "cargo_lock_sha256": lock_sha, "build_command": package["build_command"],
        "ci_run_id": package.get("run_id"), "ci_run_attempt": package.get("run_attempt"),
        "qualification_provenance": "caller supplied CI package; workflow success must be verified by its operator"}


def plan(args):
    root = Path(args.root)
    require(sys.platform == "linux" and root.is_absolute() and root.resolve(strict=True) == root, "canonical isolated Linux root required")
    require(root.stat().st_uid == os.geteuid() and stat.S_IMODE(root.stat().st_mode) == 0o700, "isolated root must be owned mode 0700")
    binary, manifest = Path(args.binary), Path(args.package_manifest)
    require(binary.is_relative_to(root) and manifest.is_relative_to(root), "qualified package must be copied into this isolated root")
    identity = package_check(binary, manifest, args.source_commit, args.source_tree)
    for name in ("workspace", "state", "credentials", "evidence"):
        (root / name).mkdir(mode=0o700)
    for owner in ("a", "b"):
        write_bytes_once(root / "credentials" / f"operator-{owner}.token", secrets.token_hex(32).encode())
    config = {"state_dir": str(root / "state"), "controller_workspace_roots": [str(root / "workspace")],
        "hosts": {"denied": {"ssh_target": "never-connect-session-weight-qualification",
            "remote_state_dir": str(root / "no-remote"), "allow_execute": False,
            "allow_pty": False, "allow_write": False, "allow_job_network": False}}}
    config_sha = write_once(root / "policy.json", config)
    cases = {}
    for name, columns, rows, mode in (("positive", 2, 1, "positive"), ("negative", 2, 1, "negative"), ("noop", 2, 1, "noop"), ("crash", 512, 64, "positive")):
        case = fixture(columns, rows, mode)
        path = root / "workspace" / f"{name}.safetensors"
        write_bytes_once(path, case["source"])
        payload = {"source_path": str(path), "source_sha256": digest(case["source"]), "candidate_sha256": digest(case["candidate"]),
            "source_bytes": len(case["source"]), "readout": case["readout"], "request": case["request"], "rows": rows, "columns": columns, "mode": mode}
        case_path = root / "evidence" / f"case-{name}.json"
        cases[name] = {"path": str(case_path), "sha256": write_once(case_path, payload)}
    sockets = [socket.socket() for _ in range(4)]
    try:
        for item in sockets:
            item.bind(("127.0.0.1", 0))
        ports = [item.getsockname()[1] for item in sockets]
    finally:
        for item in sockets:
            item.close()
    value = {"schema": "hepta.rea.session-weight-http-qualification-plan.v1", "root": str(root),
        "binary": str(binary), "package_manifest": str(manifest), "identity": identity,
        "driver_sha256": digest(read(Path(__file__).resolve())), "policy_sha256": config_sha,
        "cases": cases, "ports": ports, "budget": BUDGET, "synthetic_only": True,
        "credential_material_in_manifest": False, "automatic_retry": False,
        "postpublication_kill_rule": "one IN_MOVED_TO observation; stop only the owned process group, verify complete candidate and absent inverse, then SIGKILL; a missed window is failure, never an automatic retry"}
    target = root / "plan.json"
    pin = write_once(target, value)
    print(json.dumps({"plan": str(target), "sha256": pin, "native_execution_performed": False, "credentials_printed": False}))


def decode_response(raw, request_id):
    require(len(raw) <= MAX_WIRE, "MCP response exceeds frozen wire budget")
    text = raw.decode("utf-8")
    if text.lstrip().startswith("{"):
        records = [parse(text)]
    else:
        records, data = [], []
        # SSE id/retry/comment fields are transport metadata. Empty data events
        # carry no JSON-RPC message; a nonempty malformed message still fails.
        for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n") + [""]:
            if not line:
                if data:
                    payload = "\n".join(data)
                    if payload != "":
                        records.append(parse(payload))
                    data = []
            elif line == "data" or line.startswith("data:"):
                value = "" if line == "data" else line[5:]
                data.append(value[1:] if value.startswith(" ") else value)
    require(all(isinstance(value, dict) for value in records), "MCP response must be an object")
    matches = [value for value in records if type(value.get("id")) is type(request_id) and value.get("id") == request_id]
    require(len(matches) == 1, "missing, duplicate or wrong MCP response identity")
    value = matches[0]
    require(value.get("jsonrpc") == "2.0" and "error" not in value and "result" in value, "MCP protocol error")
    return value["result"]


def negotiated_protocol(initialized):
    require(isinstance(initialized, dict), "initialize result must be an object")
    version = initialized.get("protocolVersion")
    require(isinstance(version, str) and version in SUPPORTED_PROTOCOLS,
            "unsupported negotiated MCP protocol")
    return version


class Recorder:
    def __init__(self, root, plan_value, tokens):
        self.root, self.plan, self.tokens = root, plan_value, tokens
        self.evidence_root, self.budget = root / "evidence", BUDGET
        self.counts = {"server_starts": 0, "rpc_wire_calls": 0, "tool_calls": 0, "roundtrip_wire_calls": 0, "roundtrip_new_intents": 0, "recover_wire_calls": 0, "crash_attempts": 0}
        self.started = time.monotonic()

    def remaining_seconds(self):
        remaining = BUDGET["wall_seconds"] - (time.monotonic() - self.started)
        require(remaining > 0, "qualification wall budget exceeded")
        return remaining

    def reserve(self, key):
        self.remaining_seconds()
        require(key in self.counts and self.counts[key] < BUDGET[key], "frozen qualification operation budget exceeded")
        self.counts[key] += 1

    def clean(self, value):
        if isinstance(value, str):
            for token in self.tokens.values():
                value = value.replace(token, "[REDACTED]")
        elif isinstance(value, dict):
            return {self.clean(key): self.clean(child) for key, child in value.items()}
        elif isinstance(value, list):
            return [self.clean(child) for child in value]
        return value

    def record(self, name, value):
        return write_once(self.evidence_root / name, self.clean(value))


class Client:
    def __init__(self, server, label):
        self.server, self.label = server, label
        self.session, self.request_id = None, 0
        self.protocol_version = PROTOCOL
        initialized = self.rpc("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
            "clientInfo": {"name": "session-weight-qualification", "version": "1"}})
        self.protocol_version = negotiated_protocol(initialized)
        require(isinstance(self.session, str) and 0 < len(self.session) <= 4096, "native transport did not issue a session identity")
        self.rpc("notifications/initialized", {}, notify=True)

    def rpc(self, method, params, notify=False):
        self.server.recorder.reserve("rpc_wire_calls")
        self.request_id += 1
        current = self.request_id
        body = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notify:
            body["id"] = current
        label = f"{self.server.label}-{self.label}-{current:03d}"
        self.server.recorder.record(label + "-intent.json", {"request": body, "transport_session_sha256": digest((self.session or "").encode()), "token_header_present": True})
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
            "X-Hepta-Runtime-Token": self.server.token, "MCP-Protocol-Version": self.protocol_version, "Mcp-Method": method}
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        if method == "tools/call":
            headers["Mcp-Name"] = params["name"]
        connection = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=min(430, self.server.recorder.remaining_seconds()))
        try:
            connection.request("POST", "/mcp", body=canonical(body), headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_WIRE + 1)
            self.session = response.getheader("Mcp-Session-Id", self.session)
            require(len(raw) <= MAX_WIRE, "MCP wire response exceeded budget")
            self.server.recorder.record(label + "-response.json", {"status": response.status,
                "content_type": response.getheader("Content-Type"), "transport_session_sha256": digest((self.session or "").encode()),
                "raw_utf8": raw.decode("utf-8"), "raw_sha256": digest(raw)})
            require(response.status in (200, 202, 204), f"HTTP {response.status} during {method}")
            self.server.recorder.remaining_seconds()
            return None if notify else decode_response(raw, current)
        except BaseException as error:
            self.server.recorder.record(label + "-error.json", {"error_type": type(error).__name__, "message": str(error), "automatic_retry": False})
            raise
        finally:
            connection.close()

    def call(self, tool, arguments, denied=False):
        self.server.recorder.reserve("tool_calls")
        if tool == "rea_model_session_weight":
            kind = arguments["operation"]["kind"]
            if kind == "f32_roundtrip":
                self.server.recorder.reserve("roundtrip_wire_calls")
            elif kind == "f32_recover":
                self.server.recorder.reserve("recover_wire_calls")
        result = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        if denied:
            require(result.get("isError") is True, "expected authenticated tool refusal did not occur")
            return None
        require(not result.get("isError", False), "native MCP tool refused a required qualification operation")
        text = "\n".join(item.get("text", "") for item in result.get("content", []) if item.get("type") == "text")
        return parse(text)


def lower_limits():
    for kind, requested in ((resource.RLIMIT_AS, BUDGET["server_address_space_bytes"]), (resource.RLIMIT_CPU, BUDGET["server_cpu_seconds"]), (resource.RLIMIT_CORE, 0)):
        soft, hard = resource.getrlimit(kind)
        finite = [value for value in (soft, hard, requested) if value != resource.RLIM_INFINITY]
        cap = min(finite)
        resource.setrlimit(kind, (cap, cap))


class Server:
    def __init__(self, recorder, label, owner, port):
        recorder.reserve("server_starts")
        self.recorder, self.label, self.port = recorder, label, port
        self.token = recorder.tokens[owner]
        self.process = None
        self.shutdown_recorded = False
        root = recorder.root
        log_path = root / "evidence" / f"{label}-server.log"
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.log = os.fdopen(fd, "wb")
        argv = [recorder.plan["binary"], "mcp", "--runtime-config", str(root / "policy.json"),
            "--bind", f"127.0.0.1:{port}", "--auth-token-file", str(root / "credentials" / f"operator-{owner}.token")]
        environment = dict(os.environ)
        environment["RUST_LOG"] = "error"
        environment["TOKIO_WORKER_THREADS"] = str(BUDGET["server_tokio_worker_threads"])
        try:
            self.process = subprocess.Popen(argv, cwd=root, env=environment, stdin=subprocess.DEVNULL,
                stdout=self.log, stderr=self.log, start_new_session=True, preexec_fn=lower_limits)
            recorder.record(label + "-process.json", {"argv": argv, "pid": self.process.pid, "private_process_group": True,
                "environment_inherited": True, "security_environment_removed": False,
                "tokio_worker_threads": BUDGET["server_tokio_worker_threads"], "operator_label": owner})
            deadline = time.monotonic() + min(15, recorder.remaining_seconds())
            while True:
                require(self.process.poll() is None, "isolated Runtime exited before readiness")
                require(time.monotonic() < deadline, "isolated Runtime readiness deadline exceeded")
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=min(1, recorder.remaining_seconds()))
                try:
                    connection.request("GET", "/readyz")
                    response = connection.getresponse()
                    data = response.read(256)
                    if response.status == 200 and data == b"ready\n":
                        break
                except OSError:
                    pass
                finally:
                    connection.close()
                time.sleep(0.05)
        except BaseException:
            self.stop(kill=True)
            raise

    def stop(self, kill=False):
        sent = []
        try:
            if self.process is not None and self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGKILL if kill else signal.SIGTERM)
                sent.append("SIGKILL" if kill else "SIGTERM")
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    sent.append("SIGKILL")
                    self.process.wait(timeout=10)
                    require(kill, "graceful isolated shutdown failed; killed only its owned process group")
        finally:
            self.log.close()
            if not self.shutdown_recorded:
                self.recorder.record(self.label + "-shutdown.json", {
                    "owned_pid": self.process.pid if self.process is not None else None,
                    "signals_sent": sent,
                    "observed_returncode": self.process.returncode if self.process is not None else None,
                    "independent_process_group_only": True,
                })
                self.shutdown_recorded = True


def source_arguments(case, session_id, operation):
    return {"session_id": session_id, "parent_sha256": case["source_sha256"], "readout": case["readout"], "operation": operation}


def check_outer(report):
    require(report["credential_metadata_resume"] is True and report["authenticated_chatgpt_caller_isolation"] is False, "real credential scope was not reported")
    for key in ("accepted_for_activation", "full_model_executed", "feature_provenance_verified", "production_eligible", "automatic_retry"):
        require(report[key] is False, "unsupported native scope or replay claim")
    return report["result"]


def artifact(root, receipt, target, parent=None):
    path = Path(receipt["artifact_path"])
    expected = root / "state" / "weight-artifacts-v1" / receipt["artifact_id"] / "model.safetensors"
    require(path == expected and receipt["sha256"] == target and receipt["source_modified"] is False and receipt["production_eligible"] is False, "canonical artifact receipt differs")
    raw = read(path, private=True)
    require(digest(raw) == target, "actual artifact differs from complete commitment")
    manifest = parse(read(path.with_name("manifest.json"), private=True))
    identity = dict(manifest)
    identity.pop("artifact_id")
    require("wa1_" + digest(canonical(identity)) == receipt["artifact_id"] == manifest["artifact_id"], "artifact manifest identity differs")
    require(manifest["target_sha256"] == target, "manifest target differs")
    if parent is not None:
        require(manifest["parent_artifact_id"] == parent and manifest["kind"] == "restore", "inverse is not the original candidate's canonical child")
    return raw


def original_intent(root, journal_id, session_id, case):
    raw = read(root / "state" / "weight-guard-journal-v1" / journal_id / "intent.json", private=True)
    require("wgj1_" + digest(raw) == journal_id, "original raw intent identity differs")
    value = parse(raw)
    authority = value["session_authority"]
    require(authority["session_id"] == session_id and authority["credential_bound"] is True, "intent is not the actual authenticated session authority")
    require(authority["source_path"] == case["source_path"] and authority["parent_sha256"] == case["source_sha256"] and authority["allowed_readout"] == case["readout"], "original authority differs from frozen parent or tensor scope")
    return raw


def fresh_head(value, case):
    forward = value["forward"]
    require(forward["source_sha256"] == case["source_sha256"] and forward["weight_shape"] == [2, case["columns"]], "fresh native head identity differs")
    require(forward["multiply_adds"] == case["rows"] * 2 * case["columns"], "fresh head work differs")
    outputs = forward["outputs"]
    require(len(outputs) == case["rows"] and all(len(row) == 2 for row in outputs), "fresh output shape differs")
    require(all(struct.pack("<2f", *row) == struct.pack("<2f", 1.5, 1.5) for row in outputs), "fresh restored F32 outputs differ")
    require(value["bias_evidence"]["caller_bias_matches_stored_bits"] is True, "stored bias was not authenticated")


def restore_check(root, result, case, candidate_id):
    require(result["restoration_verified"] is True, "restoration is unverified")
    raw = artifact(root, result["restoration"], case["source_sha256"], candidate_id)
    expected = fixture(case["columns"], case["rows"], case["mode"])["source"]
    require(raw == expected, "inverse differs from every original synthetic byte")
    fresh_head(result["new_request"], case)


def weight_inventory(root):
    result = {}
    for name in ("weight-artifacts-v1", "weight-guard-journal-v1", "rea-model-sessions-v1"):
        base = root / "state" / name
        if base.exists():
            for path in sorted(base.rglob("*")):
                if path.is_file():
                    result[str(path.relative_to(root))] = digest(read(path, private=True))
    return result


def weight_effect_inventory(root):
    """Capture only original weight stores; omit REA metadata and request auditing.

    This is a persistent-state boundary check, not a trace of transient syscalls.
    Directory identities and metadata also expose an empty entry or same-byte rewrite.
    """
    result = {}
    for name in ("weight-artifacts-v1", "weight-guard-journal-v1"):
        base = root / "state" / name
        if not os.path.lexists(base):
            result[name] = {"kind": "absent"}
            continue
        pending = [base]
        while pending:
            path = pending.pop()
            require(len(result) < 4096, "prepare weight inventory exceeds its fixed entry cap")
            before = path.lstat()
            require(path.resolve(strict=True) == path and not stat.S_ISLNK(before.st_mode), "prepare weight store contains a noncanonical entry")
            identity = {
                "device": before.st_dev, "inode": before.st_ino,
                "owner_uid": before.st_uid, "mode": stat.S_IMODE(before.st_mode),
                "links": before.st_nlink, "mtime_ns": before.st_mtime_ns,
                "ctime_ns": before.st_ctime_ns,
            }
            if stat.S_ISDIR(before.st_mode):
                require(before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o700, "prepare weight directory must remain private and owned")
                children = sorted(path.iterdir())
                identity.update({"kind": "directory", "children": [child.name for child in children]})
                pending.extend(reversed(children))
            else:
                require(stat.S_ISREG(before.st_mode), "prepare weight store contains a nonregular entry")
                raw = read(path, private=True)
                identity.update({"kind": "file", "bytes": len(raw), "sha256": digest(raw)})
            after = path.lstat()
            require((before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "prepare weight entry changed during inventory")
            result[str(path.relative_to(root / "state"))] = identity
    return result


def verify_prepare_inventory(root, before, after, journal_id):
    require(before == after, "prepare changed original weight artifact or journal state")
    require(isinstance(journal_id, str) and journal_id.startswith("wgj1_") and len(journal_id) == 69 and all(char in "0123456789abcdef" for char in journal_id[5:]), "prepared journal identity is malformed")
    require(not os.path.lexists(root / "state" / "weight-guard-journal-v1" / journal_id), "prepare has an actual journal entry despite its no-write claim")


def recover(client, root, case, session_id, prepared, candidate_id=None, denied=False):
    arguments = source_arguments(case, session_id, {"kind": "f32_recover", "journal_id": prepared["journal_id"],
        "expected_candidate_sha256": prepared["expected_candidate_sha256"], "candidate_artifact_id": candidate_id})
    report = client.call("rea_model_session_weight", arguments, denied=denied)
    if denied:
        return None
    result = check_outer(report)
    require(result["original_source_path_opened"] is False and result["parent_forward_replayed"] is False and result["candidate_forward_replayed"] is False and result["new_candidate_published"] is False, "recovery replayed or opened the original source")
    restore_check(root, result, case, result["candidate_artifact_id"])
    return result


def open_prepare(client, case):
    opened = client.call("rea_model_session_open", {"path": case["source_path"], "expected_sha256": case["source_sha256"]})
    session_id = opened["session_id"]
    recorder, root = client.server.recorder, client.server.recorder.root
    label = "prepare-weight-inventory-" + Path(case["source_path"]).stem
    before = weight_effect_inventory(root)
    recorder.record(label + "-before.json", before)
    try:
        report = client.call("rea_model_session_weight", source_arguments(case, session_id, {"kind": "f32_prepare", "request": case["request"]}))
    finally:
        after = weight_effect_inventory(root)
        recorder.record(label + "-after.json", after)
    result = check_outer(report)
    require(result["expected_candidate_sha256"] == case["candidate_sha256"] and result["parent_sha256"] == case["source_sha256"], "prepared candidate/source commitment differs")
    require(result["forward_calls"] == 0 and result["candidate_published"] is False and result["journal_written"] is False, "preparation crossed its no-forward/no-write boundary")
    verify_prepare_inventory(root, before, after, result["journal_id"])
    return session_id, result


def roundtrip_arguments(case, session_id, prepared):
    return source_arguments(case, session_id, {"kind": "f32_roundtrip", "request": case["request"], "expected_journal_id": prepared["journal_id"]})


class PublicationWatch:
    """Linux notification only; never a production failpoint or a filesystem mutation."""
    def __init__(self, directory):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.inotify_init1.argtypes = [ctypes.c_int]
        self.libc.inotify_init1.restype = ctypes.c_int
        self.libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self.libc.inotify_add_watch.restype = ctypes.c_int
        self.fd = self.libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        require(self.fd >= 0, "inotify admission failed")
        self.watch = self.libc.inotify_add_watch(self.fd, os.fsencode(directory), 0x00000080)
        if self.watch < 0:
            self.close()
            raise ValueError("cannot observe isolated publication directory")

    def next_name(self, deadline):
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.fd], [], [], max(0.0, min(0.2, deadline - time.monotonic())))
            if not ready:
                continue
            raw = os.read(self.fd, 65536)
            position = 0
            while position + 16 <= len(raw):
                _, mask, _, length = struct.unpack_from("iIII", raw, position)
                name = raw[position + 16:position + 16 + length].split(b"\0", 1)[0].decode()
                position += 16 + length
                require(mask & 0x00004000 == 0, "publication event overflow")
                if mask & 0x00000080 and name.startswith("wa1_"):
                    return name
        raise TimeoutError("fixed postpublication crash observation expired; no retry")

    def close(self):
        os.close(self.fd)


def wait_for_owned_stop(process, deadline):
    while time.monotonic() < deadline:
        require(process.poll() is None, "owned controller exited instead of stopping")
        event = os.waitid(os.P_PID, process.pid, os.WSTOPPED | os.WNOHANG)
        if event is not None:
            require(event.si_pid == process.pid and event.si_code == os.CLD_STOPPED and event.si_status == signal.SIGSTOP, "unexpected owned controller stop event")
            return
        time.sleep(0.001)
    raise TimeoutError("owned controller did not confirm SIGSTOP before the boundary deadline")


def crash_once(server, client, case, session_id, prepared):
    recorder, root = server.recorder, server.recorder.root
    recorder.reserve("crash_attempts")
    recorder.reserve("roundtrip_new_intents")
    store = root / "state" / "weight-artifacts-v1"
    watcher = PublicationWatch(store)
    outcome = {}
    def send():
        try:
            outcome["response"] = client.call("rea_model_session_weight", roundtrip_arguments(case, session_id, prepared))
        except BaseException as error:
            outcome["transport_error"] = type(error).__name__
    thread = threading.Thread(target=send, daemon=True)
    thread.start()
    try:
        name = watcher.next_name(time.monotonic() + min(60, recorder.remaining_seconds()))
        require(server.process.poll() is None, "owned server exited before crash boundary")
        os.killpg(server.process.pid, signal.SIGSTOP)
        wait_for_owned_stop(server.process, time.monotonic() + min(5, recorder.remaining_seconds()))
        candidate_path = store / name / "model.safetensors"
        manifest = parse(read(store / name / "manifest.json", private=True))
        identity = dict(manifest)
        identity.pop("artifact_id")
        require("wa1_" + digest(canonical(identity)) == name == manifest["artifact_id"], "observed publication manifest identity differs")
        require(manifest["kind"] == "patch" and manifest["source_path"] == case["source_path"] and manifest["source_sha256"] == case["source_sha256"] and manifest["target_sha256"] == case["candidate_sha256"], "observed publication is not the frozen crash candidate")
        candidate_raw = read(candidate_path, private=True)
        require(digest(candidate_raw) == case["candidate_sha256"] and candidate_raw == fixture(case["columns"], case["rows"], case["mode"])["candidate"], "published candidate bytes differ")
        inverse_ids = []
        for path in store.glob("wa1_*/manifest.json"):
            value = parse(read(path, private=True))
            if value["parent_artifact_id"] == name and value["kind"] == "restore":
                inverse_ids.append(value["artifact_id"])
        intent = original_intent(root, prepared["journal_id"], session_id, case)
        record = {"candidate_artifact_id": name, "candidate_sha256": case["candidate_sha256"],
            "original_intent_sha256": digest(intent), "inverse_ids_before_kill": inverse_ids,
            "complete_candidate_verified_before_kill": True, "owned_controller_stop_confirmed_by_waitid": True,
            "owned_process_group_stop_sent": True, "publication_directory_sync_observed": False,
            "guard_completion_present": (root / "state" / "weight-guard-journal-v1" / prepared["journal_id"] / "completion.json").exists(),
            "automatic_retry": False}
        recorder.record("crash-boundary.json", record)
        require(not inverse_ids, "postpublication pre-inverse window was missed; this attempt cannot qualify")
        server.stop(kill=True)
        require(server.process.returncode == -signal.SIGKILL, "owned controller was not observed killed by SIGKILL")
        thread.join(timeout=10)
        require(not thread.is_alive() and "transport_error" in outcome and "response" not in outcome, "crash RPC did not terminate as an interrupted request")
        recorder.record("crash-transport.json", outcome)
        return name, intent
    finally:
        watcher.close()
        if server.process.poll() is None:
            server.stop(kill=True)
        thread.join(timeout=10)


def run(args):
    plan_path = Path(args.plan)
    raw = read(plan_path, private=True)
    value = parse(raw)
    root = Path(value["root"])
    require(sys.platform == "linux" and root.is_absolute() and root.resolve(strict=True) == root, "canonical isolated Linux root required")
    require(root.stat().st_uid == os.geteuid() and stat.S_IMODE(root.stat().st_mode) == 0o700, "isolated root must remain owned mode 0700")
    require(plan_path == root / "plan.json" and value["schema"] == "hepta.rea.session-weight-http-qualification-plan.v1", "wrong qualification plan")
    require(value["driver_sha256"] == digest(read(Path(__file__).resolve())) and value["budget"] == BUDGET, "driver or frozen budget changed")
    require(digest(read(root / "policy.json", private=True)) == value["policy_sha256"], "policy changed after preparation")
    actual_identity = package_check(value["binary"], value["package_manifest"], value["identity"]["source_commit"], value["identity"]["source_tree"])
    require(actual_identity == value["identity"], "qualified executable package changed")
    require(len(value["ports"]) == 4 and len(set(value["ports"])) == 4 and all(type(port) is int and 1024 <= port <= 65535 for port in value["ports"]), "frozen distinct loopback ports changed")
    for name in ("workspace", "state", "credentials", "evidence"):
        directory = root / name
        require(directory.is_dir() and directory.resolve(strict=True) == directory and directory.stat().st_uid == os.geteuid() and stat.S_IMODE(directory.stat().st_mode) == 0o700, "isolated directory is not private and canonical")
    require(not any((root / "state").iterdir()), "qualification state must be empty before its one allowed launch")
    tokens = {owner: read(root / "credentials" / f"operator-{owner}.token", private=True).decode("ascii") for owner in ("a", "b")}
    require(tokens["a"] != tokens["b"] and all(len(token) == 64 and all(c in "0123456789abcdef" for c in token) for token in tokens.values()), "invalid private generated credentials")
    recorder = Recorder(root, value, tokens)
    recorder.record("run-intent.json", {"plan_sha256": digest(raw), "driver_sha256": value["driver_sha256"], "budget": BUDGET,
        "synthetic_only": True, "automatic_retry": False, "started_unix_ns": time.time_ns()})
    cases = {}
    require(set(value["cases"]) == {"positive", "negative", "noop", "crash"}, "frozen case identities changed")
    for name, pin in value["cases"].items():
        require(Path(pin["path"]) == root / "evidence" / f"case-{name}.json", "case evidence escaped the isolated root")
        body = read(pin["path"], private=True)
        require(digest(body) == pin["sha256"], "sealed synthetic case changed")
        cases[name] = parse(body)
        require(Path(cases[name]["source_path"]) == root / "workspace" / f"{name}.safetensors", "source escaped the synthetic workspace")
        expected = fixture(512 if name == "crash" else 2, 64 if name == "crash" else 1, "positive" if name == "crash" else name)
        require(cases[name]["source_sha256"] == digest(expected["source"]) and cases[name]["candidate_sha256"] == digest(expected["candidate"]) and cases[name]["request"] == expected["request"] and cases[name]["readout"] == expected["readout"], "case is not its frozen synthetic profile")
        require(digest(read(cases[name]["source_path"], private=True)) == cases[name]["source_sha256"], "synthetic source changed before launch")
    return run_cases(root, value, raw, actual_identity, cases, recorder)


def run_cases(root, value, raw, actual_identity, cases, recorder, label_prefix=""):
    server, status, failure = None, "FAIL", None
    receipts = {}
    try:
        server = Server(recorder, label_prefix + "a-first", "a", value["ports"][0])
        client = Client(server, "first")
        names = {tool["name"] for tool in client.rpc("tools/list", {})["tools"]}
        require("rea_model_session_weight" in names, "qualified executable does not expose the reviewed typed session route")
        for name in ("positive", "negative", "noop"):
            case = cases[name]
            sid, prepared = open_prepare(client, case)
            if name == "positive":
                before = weight_inventory(root)
                recover(client, root, case, sid, prepared, denied=True)
                require(weight_inventory(root) == before, "unpublished-intent recovery wrote weight state")
            recorder.reserve("roundtrip_new_intents")
            report = client.call("rea_model_session_weight", roundtrip_arguments(case, sid, prepared))
            result = check_outer(report)
            require(result["journal_id"] == prepared["journal_id"] and result["research_roundtrip_verified"] is True, "roundtrip identity or verdict differs")
            require(result["guard"]["accepted"] is (name == "positive"), "positive/negative/noop control was not distinguished")
            expected_gain = {"positive": 0.5, "negative": -0.5, "noop": 0.0}[name]
            require(result["guard"]["gain"] == expected_gain, "synthetic native guard score differs")
            actual = artifact(root, result["candidate"], case["candidate_sha256"])
            require(actual == fixture(case["columns"], case["rows"], case["mode"])["candidate"], "candidate differs from exact synthetic byte edit")
            restore_check(root, result, case, result["candidate"]["artifact_id"])
            intent = original_intent(root, prepared["journal_id"], sid, case)
            receipts[name] = {"session_id": sid, "prepared": prepared, "candidate": result["candidate"], "original_intent_sha256": digest(intent)}
        positive, case = receipts["positive"], cases["positive"]
        before = weight_inventory(root)
        client.call("rea_model_session_weight", roundtrip_arguments(case, positive["session_id"], positive["prepared"]), denied=True)
        require(weight_inventory(root) == before, "duplicate session roundtrip changed original weight evidence")
        Path(case["source_path"]).unlink()
        second = Client(server, "second")
        require(second.session != client.session, "same-owner check did not create a new native transport session")
        second.call("rea_model_session_query", {"session_id": positive["session_id"], "collection": "summary"})
        recover(second, root, case, positive["session_id"], positive["prepared"], positive["candidate"]["artifact_id"])
        require(not os.path.lexists(case["source_path"]), "same-owner recovery recreated the deleted positive source path")
        server.stop()
        server = Server(recorder, label_prefix + "b-restart", "b", value["ports"][1])
        other = Client(server, "first")
        require(other.call("rea_model_session_list", {})["sessions"] == [], "foreign credential listed owner A sessions")
        before = weight_inventory(root)
        other.call("rea_model_session_query", {"session_id": positive["session_id"], "collection": "summary"}, denied=True)
        recover(other, root, case, positive["session_id"], positive["prepared"], positive["candidate"]["artifact_id"], denied=True)
        require(weight_inventory(root) == before, "foreign credential changed weight state")
        server.stop()
        server = Server(recorder, label_prefix + "a-restart", "a", value["ports"][2])
        resumed = Client(server, "first")
        resumed.call("rea_model_session_query", {"session_id": positive["session_id"], "collection": "summary"})
        recover(resumed, root, case, positive["session_id"], positive["prepared"], positive["candidate"]["artifact_id"])
        require(not os.path.lexists(case["source_path"]), "cold same-owner recovery recreated the deleted positive source path")
        crash = cases["crash"]
        sid, prepared = open_prepare(resumed, crash)
        candidate_id, intent = crash_once(server, resumed, crash, sid, prepared)
        Path(crash["source_path"]).unlink()
        server = Server(recorder, label_prefix + "a-after-kill", "a", value["ports"][3])
        recovered_client = Client(server, "first")
        recovered_client.call("rea_model_session_query", {"session_id": sid, "collection": "summary"})
        restored = recover(recovered_client, root, crash, sid, prepared, None)
        require(restored["candidate_artifact_id"] == candidate_id, "recovery substituted a different candidate")
        require(original_intent(root, prepared["journal_id"], sid, crash) == intent, "recovery changed the original bound intent")
        require(not Path(crash["source_path"]).exists(), "recovery reconstructed or opened the old source path")
        receipts["crash"] = {"session_id": sid, "prepared": prepared, "candidate_artifact_id": candidate_id,
            "restored_artifact_id": restored["restoration"]["artifact_id"], "source_removed": True, "original_intent_sha256": digest(intent)}
        require(all(recorder.counts[key] == recorder.budget[key] for key in recorder.counts), "qualification omitted a frozen operation")
        recorder.remaining_seconds()
        status = "PASS"
    except BaseException as error:
        failure = {"type": type(error).__name__, "message": str(error)}
    finally:
        if server is not None:
            try:
                server.stop(kill=status != "PASS")
                if status == "PASS":
                    recorder.remaining_seconds()
            except BaseException as error:
                status, failure = "FAIL", {"type": type(error).__name__, "message": str(error)}
        result = {"schema": "hepta.rea.session-weight-http-qualification-result.v1", "status": status,
            "failure": failure, "plan_sha256": digest(raw), "identity": actual_identity,
            "counts": recorder.counts, "reserved_budget": recorder.budget, "receipts": receipts,
            "wall_seconds": time.monotonic() - recorder.started, "synthetic_only": True,
            "actual_smallhcsn_runs": 0, "training_steps": 0, "production_deployment": False,
            "head_forward_counts_are_source_control_flow_bounds": True, "automatic_retry": False,
            "credentials_printed": False, "credential_material_location": "private credentials directory, excluded from evidence exports"}
        pin = recorder.record("result.json", result)
        print(json.dumps({"status": status, "result": str(recorder.evidence_root / "result.json"), "sha256": pin, "credentials_printed": False}))
    return 0 if status == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    prepare = actions.add_parser("plan")
    for name in ("root", "binary", "package-manifest", "source-commit", "source-tree"):
        prepare.add_argument("--" + name, required=True)
    execute = actions.add_parser("run")
    execute.add_argument("--plan", required=True)
    args = parser.parse_args()
    return plan(args) if args.action == "plan" else run(args)


if __name__ == "__main__":
    sys.exit(main())
