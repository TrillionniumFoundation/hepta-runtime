#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under Apache-2.0
"""CI-only, two-runner native preview replay. NOT a signed remote worker,
cryptographic authentication or a production multi-tenant Evidence protocol.

The actual shipped Rust MCP executable writes and reads the on-disk preview.
The Python harness only drives JSON-RPC and copies a retained record as a
GitHub Actions artifact between independent ephemeral runners.
"""

import hashlib
import json
import os
import queue
import shutil
import stat
import subprocess
import sys
import threading
from pathlib import Path

PREFIX = "hepta_rea_preview_v1_"
SOURCE = b"\0asm\x01\0\0\0"


class ShippedMcp:
    def __init__(self, binary, config):
        self.process = subprocess.Popen(
            [str(binary), "mcp", "--runtime-config", str(config)],
            cwd="/",
            env={},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self.replies = queue.Queue()
        self.counter = 0

        def read_lines():
            for line in self.process.stdout:
                self.replies.put(line)
            self.replies.put(None)

        self.reader = threading.Thread(target=read_lines, daemon=True)
        self.reader.start()

    def request(self, method, params):
        self.counter += 1
        target = self.counter
        packet = {
            "jsonrpc": "2.0",
            "id": target,
            "method": method,
            "params": params,
        }
        self.process.stdin.write(json.dumps(packet, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        for _ in range(50):
            try:
                line = self.replies.get(timeout=15)
            except queue.Empty as error:
                raise RuntimeError(f"shipped MCP timeout on {method}") from error
            if line is None:
                raise RuntimeError(f"shipped MCP exited unexpectedly on {method}")
            response = json.loads(line)
            if response.get("id") != target:
                continue
            if "error" in response:
                raise RuntimeError(f"MCP transport error: {response['error']}")
            return response["result"]
        raise RuntimeError("MCP exhausted unrelated notifications")

    def initialize(self):
        self.request(
            "initialize",
            {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": {"name": "rea-crosshost-reference", "version": "0.1.0"},
            },
        )
        self.process.stdin.write(
            '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n'
        )
        self.process.stdin.flush()
        tools = self.request("tools/list", {})["tools"]
        names = {item["name"] for item in tools}
        if not {"rea_retain_preview", "rea_read_preview"} <= names:
            raise RuntimeError("policy-gated real preview MCP methods are missing")
        if "shell" in names:
            raise RuntimeError("unrestricted shell must not be advertised")

    def call(self, name, arguments, should_fail=False):
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        if bool(result.get("isError")) != should_fail:
            raise RuntimeError(f"Unexpected MCP tool result for {name}: {result}")
        if should_fail:
            return result
        text = result["content"][0]["text"]
        return json.loads(text)

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=5)

    def __enter__(self):
        self.initialize()
        return self

    def __exit__(self, *args):
        self.close()


def policy(root):
    workspace = root / "rea-crosshost-workspace"
    workspace.mkdir(mode=0o700, exist_ok=True)
    state = root / "rea-crosshost-state"
    config = root / "rea-crosshost-policy.json"
    config.write_text(
        json.dumps(
            {
                "state_dir": str(state),
                "controller_workspace_roots": [str(workspace)],
                "hosts": {
                    "no-remote-ci": {
                        "ssh_target": "never-connect-ci",
                        "remote_state_dir": str(root / "never-remote"),
                        "allow_execute": False,
                        "allow_pty": False,
                        "allow_write": False,
                        "allow_job_network": False,
                    }
                },
            }
        )
    )
    return workspace, state, config


def capture(root, binary):
    workspace, state, config = policy(root)
    transfer = root / "rea-crosshost-transfer"
    transfer.mkdir(mode=0o700, exist_ok=False)
    source = workspace / "crosshost.wasm"
    source.write_bytes(SOURCE)
    with ShippedMcp(binary, config) as mcp:
        receipt = mcp.call("rea_retain_preview", {"path": str(source)})
        identifier = receipt["native_evidence_id"]
        if receipt["status"] != "retained" or receipt["rea_evidence_compatible"] is not False:
            raise AssertionError("unexpected native-only retention receipt")
        restored = mcp.call("rea_read_preview", {"native_evidence_id": identifier})
        if restored["record"]["normalized_result"]["format"] != "wasm":
            raise AssertionError("original host's record is not WASM")
    if len(identifier) != len(PREFIX) + 64 or not identifier.startswith(PREFIX):
        raise AssertionError("unexpected native digest shape")
    record_path = state / "rea-preview-v1" / f"{identifier}.json"
    st = record_path.stat()
    if stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1:
        raise AssertionError("source store must be private and single-linked")
    record_bytes = record_path.read_bytes()
    (transfer / "record.json").write_bytes(record_bytes)
    manifest = {
        "schema": "hepta.rea.cross-runner-preview.v1",
        "source_job": os.environ["GITHUB_JOB"],
        "source_run": os.environ["GITHUB_RUN_ID"],
        "source_commit": os.environ["GITHUB_SHA"],
        "capture_runner": os.environ.get("RUNNER_NAME"),
        "native_evidence_id": identifier,
        "source_path": str(source),
        "source_sha256": hashlib.sha256(SOURCE).hexdigest(),
        "record_file_sha256": hashlib.sha256(record_bytes).hexdigest(),
        "rea_evidence_compatible": False,
        "limitations": [
            "GitHub artifact transport is a trusted intermediary, not attested host-to-host communication",
            "Native preview ID is not signed or MAC-authenticated REA Evidence",
            "Not a remote host worker or production cross-host authorization/restore",
        ],
    }
    (transfer / "capture-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"stage": "capture", "id": identifier, "sha256": manifest["record_file_sha256"]}))


def replay(root, binary):
    workspace, state, config = policy(root)
    transfer = root / "rea-crosshost-transfer-downloaded"
    manifest = json.loads((transfer / "capture-manifest.json").read_text())
    if manifest["schema"] != "hepta.rea.cross-runner-preview.v1":
        raise AssertionError("capture manifest schema mismatch")
    if manifest["source_commit"] != os.environ["GITHUB_SHA"]:
        raise AssertionError("different Git commit between runner jobs")
    if manifest["rea_evidence_compatible"] is not False:
        raise AssertionError("unexpected claimed original REA Evidence")
    ident = manifest["native_evidence_id"]
    if not ident.startswith(PREFIX) or len(ident) != len(PREFIX) + 64:
        raise AssertionError("invalid native identity")
    if Path(manifest["source_path"]).exists():
        raise AssertionError("source artifact must be absent on independent recovery runner")
    if (workspace / "crosshost.wasm").exists():
        raise AssertionError("recovery runner must not have original source bytes")
    if state.exists():
        raise AssertionError("recovery runner must start without a retained record directory")
    record_bytes = (transfer / "record.json").read_bytes()
    digest = hashlib.sha256(record_bytes).hexdigest()
    if digest != manifest["record_file_sha256"]:
        raise AssertionError("record transfer digest differs")
    state.mkdir(mode=0o700)
    store = state / "rea-preview-v1"
    store.mkdir(mode=0o700)
    dest = store / f"{ident}.json"
    with dest.open("xb") as fd:
        fd.write(record_bytes)
    dest.chmod(0o600)

    with ShippedMcp(binary, config) as mcp:
        recovered = mcp.call("rea_read_preview", {"native_evidence_id": ident})
        record = recovered["record"]
        if recovered["native_evidence_id"] != ident:
            raise AssertionError("cross-runner lookup ID changed")
        if record["subject"]["sha256"] != manifest["source_sha256"]:
            raise AssertionError("wrong original source byte identity after host transfer")
        if record["subject"]["local_path"] != manifest["source_path"]:
            raise AssertionError("stored capture display path unexpectedly rewritten")
        if record["normalized_result"]["format"] != "wasm":
            raise AssertionError("wrong format after host transfer")
        if record["rea_evidence_compatible"] is not False:
            raise AssertionError("cross-runner preview must not become REA Evidence")
        dest.chmod(0o644)
        mcp.call("rea_read_preview", {"native_evidence_id": ident}, should_fail=True)
        dest.chmod(0o600)
        if mcp.call("rea_read_preview", {"native_evidence_id": ident})["native_evidence_id"] != ident:
            raise AssertionError("private access did not recover after mode restoration")
        dest.write_bytes(b'{"corrupt":true}')
        mcp.call("rea_read_preview", {"native_evidence_id": ident}, should_fail=True)
        dest.write_bytes(record_bytes)
        if mcp.call("rea_read_preview", {"native_evidence_id": ident})["native_evidence_id"] != ident:
            raise AssertionError("repaired on-disk record did not replay")

    receipt = {
        "schema": "hepta.rea.cross-runner-recovery.v1",
        "capture_runner": manifest["capture_runner"],
        "recovery_runner": os.environ.get("RUNNER_NAME"),
        "capture_git_commit": manifest["source_commit"],
        "recovery_git_commit": os.environ["GITHUB_SHA"],
        "native_evidence_id": ident,
        "original_source_missing_on_recovery_runner": True,
        "cross_runner_native_preview_id_matched": True,
        "private_mode_and_corruption_negative_refused": True,
        "production_multi_host_qualified": False,
        "remote_signed_worker_qualified": False,
    }
    (root / "rea-crosshost-recovery.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"stage": "recovery", "id": ident, "source_missing": True}))


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"capture", "replay"}:
        raise SystemExit("Usage: rea-crosshost-preview.py capture|replay")
    base = Path(os.environ["RUNNER_TEMP"])
    runtime = Path(os.environ["GITHUB_WORKSPACE"]) / "target/release/hepta-runtime"
    if not runtime.is_file():
        raise SystemExit("Shipped Rust Release binary must exist")
    if sys.argv[1] == "capture":
        capture(base, runtime)
    else:
        replay(base, runtime)
