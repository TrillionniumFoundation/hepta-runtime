#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real two-controller owner-fence acceptance on disposable localhost state only.

Requires prebuilt debug binaries. Never touches any installed unit, token,
controller state, or remote host. Isolated loopback test ports and credentials.
The promotion publication below is FOR THIS PRIVATE FIXTURE ONLY; production
owner transfer requires independently proven all-ingress fenced admission.
"""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def publish(directory, doc):
    tmp = directory / (".owner.json.next." + secrets.token_hex(8))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(doc, out)
        out.flush()
        os.fsync(out.fileno())
    os.replace(tmp, directory / ".owner.json")
    d = os.open(directory, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(d)
    finally:
        os.close(d)


def local_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Client:
    def __init__(self, port, token):
        self.url = f"http://127.0.0.1:{port}/mcp"
        self.token = token
        self.session = None
        self.seq = 0
        assert "result" in self.rpc("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "isolated-fence-regression", "version": "1"}
        })
        self.rpc("notifications/initialized", {}, notification=True)

    def rpc(self, method, params, notification=False):
        self.seq += 1
        body = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notification:
            body["id"] = self.seq
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-06-18",
            "X-Hepta-Runtime-Token": self.token,
        }
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        request = urllib.request.Request(self.url,
                                         data=json.dumps(body).encode(),
                                         headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=12) as reply:
                self.session = reply.headers.get("Mcp-Session-Id", self.session)
                raw = reply.read(2 * 1024 * 1024)
        except urllib.error.HTTPError as err:
            return {"error": {"status": err.code}}
        if notification:
            return {}
        lines = [json.loads(line[5:].strip())
                 for line in raw.decode().splitlines()
                 if line.startswith("data:") and line[5:].strip()]
        return lines[-1] if lines else json.loads(raw)

    def tool(self, name, args):
        res = self.rpc("tools/call", {"name": name, "arguments": args})
        return "error" not in res and res.get("result", {}).get("isError") is not True


def run(binary, ownerctl, report_path):
    checks = []
    def ok(name, condition):
        if not condition:
            raise AssertionError(name)
        checks.append(name)
        print("PASS", name, flush=True)

    with tempfile.TemporaryDirectory(prefix="hepta-owner-mcp-") as temp:
        base = Path(temp)
        root = base / "authority"
        root.mkdir(mode=0o700)
        states = {}
        for name in ("v4", "v11", "v11-partial"):
            state, workspace = base / (name + "-state"), base / (name + "-workspace")
            state.mkdir(mode=0o700)
            workspace.mkdir(mode=0o700)
            token = secrets.token_hex(32)
            token_file = base / (name + "-token")
            fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(token + "\n")
            config = base / (name + "-runtime.json")
            config.write_text(json.dumps({
                "state_dir": str(state),
                "controller_workspace_roots": [str(workspace)],
                "hosts": {"fixture": {
                    "ssh_target": "unused-fixture.invalid", "platform": "linux",
                    "execution_mode": "isolated", "remote_state_dir": str(base / "unused"),
                    "allow_execute": name == "v11", "allow_pty": False, "allow_write": False
                }}
            }))
            config.chmod(0o600)
            states[name] = dict(state=state, workspace=workspace, token=token,
                                token_file=token_file, config=config)
        lock_file = root / ".owner.lock"
        fd = os.open(lock_file, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        publish(root, {
            "schema": "hepta-effect-owner-fence-v1",
            "owner": "v4", "epoch": 21, "phase": "admitting",
            "state_root": str(states["v4"]["state"])
        })

        processes = {}
        logs = {}
        ports = {}
        try:
            for name in states:
                port = local_port()
                assert port not in ports.values()
                ports[name] = port
                env = dict(os.environ)
                env["HEPTA_EFFECT_OWNER_FENCE_REQUIRED"] = "1"
                if name != "v11-partial":
                    env["HEPTA_EFFECT_OWNER_FENCE_DIR"] = str(root)
                    env["HEPTA_EFFECT_OWNER_SELF"] = name
                else:
                    env.pop("HEPTA_EFFECT_OWNER_FENCE_DIR", None)
                    env.pop("HEPTA_EFFECT_OWNER_SELF", None)
                env["RUST_LOG"] = "warn"
                log = (base / (name + ".log")).open("wb")
                logs[name] = log
                processes[name] = subprocess.Popen(
                    [str(binary), "mcp", "--path", str(states[name]["workspace"]),
                     "--bind", f"127.0.0.1:{port}",
                     "--runtime-config", str(states[name]["config"]),
                     "--auth-token-file", str(states[name]["token_file"])],
                    cwd=base, env=env, stdin=subprocess.DEVNULL,
                    stdout=log, stderr=subprocess.STDOUT,
                )
            for name, proc in processes.items():
                ready = False
                for _ in range(80):
                    if proc.poll() is not None:
                        break
                    try:
                        with urllib.request.urlopen(
                                f"http://127.0.0.1:{ports[name]}/readyz", timeout=0.7) as r:
                            ready = r.status == 200
                    except Exception:
                        time.sleep(0.1)
                    if ready:
                        break
                ok(name + "_loopback_server_ready", ready)
            clients = {name: Client(port, states[name]["token"])
                       for name, port in ports.items()}
            for name, client in clients.items():
                listed = client.rpc("tools/list", {})
                tools = {t["name"] for t in listed.get("result", {}).get("tools", [])}
                ok(name + "_mcp_catalog", {"host_list", "directory_create"} <= tools)
                ok(name + "_read_only_unaffected", client.tool("host_list", {}))

            def write(name, label):
                path = states[name]["workspace"] / label
                accepted = clients[name].tool("directory_create", {"path": str(path)})
                return accepted, path.exists()

            accepted, exists = write("v4", "old-owner-success")
            ok("v4_is_only_initial_effect_owner", accepted and exists)
            accepted, exists = write("v11", "premature-v11-denied")
            ok("v11_denied_before_transfer", not accepted and not exists)
            accepted, exists = write("v11-partial", "incomplete-env-denied")
            ok("required_without_full_env_fails_closed", not accepted and not exists)

            frozen = subprocess.run([str(ownerctl), "freeze", str(root), "v4", "21"],
                                    capture_output=True, text=True, timeout=10)
            ok("original_owner_freeze_committed", frozen.returncode == 0
               and "epoch=22 phase=frozen" in frozen.stdout)
            for name in states:
                accepted, exists = write(name, "frozen-denied")
                ok(name + "_denied_while_frozen", not accepted and not exists)
            for name, client in clients.items():
                ok(name + "_readable_while_frozen", client.tool("host_list", {}))

            with open(lock_file, "r+b") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                old = json.loads((root / ".owner.json").read_text())
                ok("pretransfer_epoch_and_owner_exact", old["owner"] == "v4"
                   and old["epoch"] == 22 and old["phase"] == "frozen")
                # Offline fixture promotion only; NOT a production administrative API.
                publish(root, {
                    "schema": "hepta-effect-owner-fence-v1", "owner": "v11",
                    "epoch": 23, "phase": "admitting",
                    "state_root": str(states["v11"]["state"]),
                    "predecessor_state_root": str(states["v4"]["state"])
                })
                fcntl.flock(lock, fcntl.LOCK_UN)
            # True MCP replay-negative with a disposable predecessor registry.
            # The fixture hostname's SSH target ends in .invalid and is never
            # contacted: process_start MUST refuse before durable allocation.
            old_jobs = states["v4"]["state"] / "jobs"
            old_jobs.mkdir(mode=0o700, exist_ok=True)
            legacy_key = "FIXTURE-PREVIOUS-V4-IDENTITY-NEVER-PRODUCTION"
            previous = old_jobs / "1a14-cafe-1.json"
            data = {"id": "1a14-cafe-1", "host": "fixture",
                    "idempotency_key": legacy_key,
                    "request_digest": "a"*64}
            with previous.open("x", encoding="utf-8") as stream:
                json.dump(data, stream)
            previous.chmod(0o600)
            before_entries = sorted(p.name for p in old_jobs.iterdir())
            native_jobs = states["v11"]["state"] / "jobs"
            native_initial = sorted(p.name for p in native_jobs.iterdir()) if native_jobs.exists() else []
            response = clients["v11"].rpc("tools/call", {
                "name": "process_start",
                "arguments": {"host": "fixture", "executable": "/usr/bin/true",
                              "idempotency_key": legacy_key, "timeout_seconds": 7}})
            content = response.get("result", {})
            reason = "\n".join(t.get("text", "") for t in content.get("content", [])
                                 if t.get("type") == "text")
            ok("V11_mcp_rejects_exact_V4_predecessor_idempotency_key",
               content.get("isError") is True and
               "original V4 has already accepted" in reason)
            ok("V11_replayed_key_allocated_zero_native_job_ids",
               (sorted(p.name for p in native_jobs.iterdir())
                if native_jobs.exists() else []) == native_initial)
            ok("V4_predecessor_identity_preserved_unmodified",
               sorted(p.name for p in old_jobs.iterdir()) == before_entries
               and json.loads(previous.read_text()) == data)
            ok("V11_read_only_stays_available_after_replay_refusal",
               clients["v11"].tool("host_list", {}))

            accepted, exists = write("v4", "v4-after-promotion-denied")
            ok("old_owner_revoked_after_transfer", not accepted and not exists)
            accepted, exists = write("v11", "v11-after-promotion-success")
            ok("new_owner_admitted_after_transfer", accepted and exists)
            accepted, exists = write("v11-partial", "partial-after-transfer-denied")
            ok("incomplete_env_still_denied", not accepted and not exists)

            frozen = subprocess.run([str(ownerctl), "freeze", str(root), "v11", "23"],
                                    capture_output=True, text=True, timeout=10)
            ok("new_owner_freeze_committed", frozen.returncode == 0
               and "epoch=24 phase=frozen" in frozen.stdout)
            for name in ("v4", "v11"):
                accepted, exists = write(name, "both-denied-after-freeze")
                ok(name + "_stays_blocked_after_new_freeze", not accepted and not exists)

            # Isolated reverse transfer. Production would also require a
            # separately verified old/new job-drain and routing reconciliation.
            with open(lock_file, "r+b") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                frozen_owner = json.loads((root / ".owner.json").read_text())
                ok("rollback_requires_exact_frozen_v11_epoch",
                   frozen_owner["owner"] == "v11" and frozen_owner["epoch"] == 24
                   and frozen_owner["phase"] == "frozen")
                publish(root, {
                    "schema": "hepta-effect-owner-fence-v1", "owner": "v4",
                    "epoch": 25, "phase": "admitting",
                    "state_root": str(states["v4"]["state"])
                })
                fcntl.flock(lock, fcntl.LOCK_UN)
            accepted, exists = write("v4", "rollback-v4-writes")
            ok("rollback_restores_only_original_effect_owner", accepted and exists)
            accepted, exists = write("v11", "rollback-v11-refused")
            ok("rollback_revokes_v11_new_effects", not accepted and not exists)
            ok("rollback_preserves_previous_v11_output",
               (states["v11"]["workspace"] / "v11-after-promotion-success").is_dir())
            ok("rollback_leaves_v11_read_tools_available",
               clients["v11"].tool("host_list", {}))
        finally:
            for p in processes.values():
                if p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(timeout=7)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=5)
            for log in logs.values():
                log.close()

    receipt = {
        "schema": "hepta-two-native-mcp-owner-fence-acceptance.v1",
        "time": datetime.datetime.now().astimezone().isoformat(),
        "checks_passed": checks, "checks_total": len(checks),
        "two_cooperative_effect_controllers": True,
        "incomplete_required_configuration_refused": True,
        "old_then_new_single_owner_tested": True,
        "isolated_reverse_transfer_tested": True,
        "only_disposable_localhost_state": True,
        "production_units_changed": False,
        "production_owner_cutover_proven": False,
        "promotion_uses_fixture_only_atomic_publication": True,
    }
    fd = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(receipt, out, indent=2, ensure_ascii=False)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    print("PASS", len(checks), "checks; report", report_path, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-bin", required=True)
    parser.add_argument("--ownerctl-bin", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    run(Path(args.runtime_bin), Path(args.ownerctl_bin), Path(args.report))
