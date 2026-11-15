#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Frozen 50-tool private stdio facade -> isolated native runtime -> six real SSH hosts.

Unlike tests/dc_parity_release_six_host_acceptance.py, each native RPC goes
through the same version-pinned Full Operator stdio adapter as the candidate
ChatGPT tunnel. This is local-origin qualification, never ChatGPT app approval.
Installed runtime, tunnel, Desktop Commander and their account access remain
untouched. All test controllers have private, throwaway credentials.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
import pathlib
import secrets
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from dc_parity_release_six_host_acceptance import HOSTS, digest, services

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT_EXPECTED_SHA256 = "d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1"
RELEASE_EXPECTED_SHA256 = "db181570e9e65f9e6a962d013dd4880eedc5b0cda1c71508f84388a4a8d8072b"
FACADE_EXPECTED_SHA256 = "71c339ec00d35c272162358f464a17b3e0ba6bdfad681558e02652a97f825a32"
RELEASE_SOURCE_HEAD = "874e801b92c1ec2fb3093b1934a5535a12eb1e64"


def exact_regular(path, executable=False):
    path = pathlib.Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("expected pinned regular candidate file")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or (info.st_mode & 0o022) or info.st_uid not in (0,os.getuid()):
        raise PermissionError("untrusted owner or group/world writable candidate")
    if executable and not os.access(path, os.X_OK):
        raise PermissionError("candidate native binary is not executable")
    return path


def choose_unused_loopback_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def prepare_target_test_state(alias, path):
    # This is an isolated test-owned state directory, not a service change.
    # Quoting is on the host SSH command, never forwarded from model input.
    code = (
        "from pathlib import Path; import os; "
        f"p=Path({path!r}); p.mkdir(mode=0o700); "
        "assert p.is_dir() and not p.is_symlink(); "
        "assert p.stat().st_uid==os.getuid(); "
        "print('TEST_STATE_READY')"
    )
    cmd = [
        "ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "ForwardAgent=no", "-o", "ConnectTimeout=8",
        alias, "/usr/bin/python3 -c " + shlex.quote(code),
    ]
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
    if done.returncode or done.stdout.strip() != "TEST_STATE_READY":
        raise RuntimeError("SSH test state preparation failed: " + alias)


def validate_private_config(host_name, alias, state_root):
    mac = host_name == "mac"
    target_prefix = "/private/tmp" if mac else "/tmp"
    host = {
        "ssh_target": alias,
        "platform": "macos" if mac else "linux",
        "remote_state_dir": state_root,
        "execution_mode": "operator",
        "allow_execute": True, "allow_pty": True, "allow_write": True,
        "allow_job_network": True, "allow_detached_fallback": True,
        "allowed_read_path_prefixes": [target_prefix],
        "allowed_write_path_prefixes": [target_prefix],
    }
    return host


def test_host(name, alias, binary, facade, contract, document_python, receipts):
    receipt = receipts / (name + ".json")
    log = receipts / (name + ".log")
    run_id = "hepta-v4-full-facade-" + uuid.uuid4().hex
    remote_root = ("/private/tmp/" if name == "mac" else "/tmp/") + run_id
    with tempfile.TemporaryDirectory(prefix="hepta-v4-facade-"+name+"-") as td:
        controller = pathlib.Path(td)
        (controller / "workspace").mkdir(mode=0o700)
        token_file = controller / "token"
        token_file.write_text(secrets.token_hex(32))
        token_file.chmod(0o600)
        config = controller / "runtime.json"
        config.write_text(json.dumps({
            "state_dir": str(controller / "state"),
            "controller_workspace_roots": [str(controller / "workspace")],
            "hosts": {name: validate_private_config(name, alias, remote_root)},
        }))
        port = choose_unused_loopback_port()
        prepare_target_test_state(alias, remote_root)
        native_log = controller / "native.log"
        with native_log.open("wb") as output:
            native = subprocess.Popen([
                str(binary), "mcp", "--path", str(controller / "workspace"),
                "--bind", f"127.0.0.1:{port}", "--runtime-config", str(config),
                "--auth-token-file", str(token_file),
            ], env={**os.environ, "HEPTA_RUNTIME_DOCUMENT_PYTHON": str(document_python)},
               stdin=subprocess.DEVNULL, stdout=output, stderr=output)
            try:
                # The acceptance launches the candidate facade itself, verifies
                # all pinned schema definitions and then exercises native writes.
                cmd = [
                    sys.executable, str(ROOT / "tests/full_operator_acceptance.py"),
                    "--host", name, "--ssh-target", alias, "--facade", str(facade),
                    "--contract", str(contract), "--token-file", str(token_file),
                    "--upstream", f"http://127.0.0.1:{port}/mcp", "--out", str(receipt),
                ]
                if name == "main":
                    cmd.append("--sudo-smoke")
                with log.open("x", encoding="utf-8") as stream:
                    # Let the isolated native service become ready. It is not
                    # the installed 8790 service, and never restarts production.
                    from runtime_http_acceptance import Client
                    for _ in range(120):
                        if native.poll() is not None:
                            raise RuntimeError("isolated native controller exited early")
                        try:
                            Client(f"http://127.0.0.1:{port}/mcp",token_file.read_text().strip())
                            break
                        except (RuntimeError, OSError):
                            time.sleep(.1)
                    else:
                        raise RuntimeError("isolated native controller not ready")
                    result = subprocess.run(cmd, stdout=stream, stderr=subprocess.STDOUT, timeout=300)
            finally:
                if native.poll() is None:
                    native.terminate()
                native.wait(timeout=12)
        row = json.loads(receipt.read_text()) if receipt.exists() else {}
        return {
            "host": name, "alias": alias, "exit_code": result.returncode,
            "complete": row.get("complete", False),
            "passed": row.get("passed", 0),
            "pinned_tool_count": row.get("pinned_tool_count"),
            "log_sha256": digest(log), "receipt": str(receipt),
            "target_test_directory": row.get("target_directory"),
            "remote_test_state_directory": remote_root,
            "isolated_controller": True, "runtime_service_restarted": False,
            "sudo_smoke": name == "main",
        }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--facade", required=True)
    ap.add_argument("--contract", required=True)
    ap.add_argument("--document-python", required=True, help="Existing admin-configured document worker for isolated native fixture")
    ap.add_argument("--source-head", required=True)
    ap.add_argument("--receipts", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--hosts", help="Optional comma-delimited subset for debugging")
    args = ap.parse_args()
    head = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    if head != args.source_head:
        raise ValueError("candidate source HEAD differs; do not mix tested releases")
    binary = exact_regular(args.binary, executable=True)
    facade = exact_regular(args.facade)
    contract = exact_regular(args.contract)
    if digest(binary) != RELEASE_EXPECTED_SHA256:
        raise ValueError("Native Release SHA256 differs from reviewed v4 root-guard artifact")
    if digest(facade) != FACADE_EXPECTED_SHA256:
        raise ValueError("Full Operator adapter SHA256 differs from reviewed v4 release")
    document_python = pathlib.Path(args.document_python)
    if not document_python.is_absolute() or not document_python.is_file() or not os.access(document_python, os.X_OK):
        raise ValueError("existing absolute executable document worker is required")
    if digest(contract) != CONTRACT_EXPECTED_SHA256:
        raise ValueError("frozen v4 contract digest mismatch")
    value = json.loads(contract.read_text())
    if len(value["tools"]) != 50 or value["tool_count"] != 50:
        raise ValueError("50-tool frozen contract required")
    chosen = HOSTS
    if args.hosts:
        names = set(args.hosts.split(","))
        chosen = tuple((name, alias) for name, alias in HOSTS if name in names)
        if len(chosen) != len(names):
            raise ValueError("only explicitly known target aliases allowed")
    before = services()
    if any(s["MainPID"] == "0" or s["ActiveState"] != "active" for s in before.values()):
        raise RuntimeError("protected services are not active")
    receipts = pathlib.Path(args.receipts)
    receipts.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {
        "schema": "hepta-v4-full-stdio-six-target-acceptance-v1",
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "harness_head": head, "native_release_source_head": RELEASE_SOURCE_HEAD,
        "native_sha256": digest(binary),
        "facade_sha256": digest(facade),
        "contract_sha256": digest(contract),
        "expected_tools": 50, "document_worker_explicitly_configured": True,
        "model_origin": False, "ChatGPT_origin": False,
        "installed_runtime_tunnel_or_DC_changed": False,
        "public_gateway_started": False,
        "before": before, "results": [], "complete": False,
    }
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = {pool.submit(test_host, name, alias, binary, facade, contract, document_python, receipts): name
                       for name, alias in chosen}
            for done in concurrent.futures.as_completed(futures):
                result = done.result()
                report["results"].append(result)
                print("HOST", result["host"], "EXIT", result["exit_code"],
                      "PASSED", result["passed"], flush=True)
    finally:
        report["after"] = services()
        report["identity_stable"] = report["after"] == before
        report["results"].sort(key=lambda row: next(
            i for i, x in enumerate(HOSTS) if x[0] == row["host"]))
        report["complete"] = (
            len(report["results"]) == len(chosen)
            and all(x["exit_code"] == 0 and x["complete"] and
                    x["pinned_tool_count"] == 50 and
                    x["passed"] == (9 if x["sudo_smoke"] else 8)
                    for x in report["results"])
            and report["identity_stable"]
        )
        with pathlib.Path(args.out).open("x", encoding="utf-8") as dest:
            dest.write(json.dumps(report, indent=2) + "\n")
        print("MATRIX_COMPLETE", report["complete"], flush=True)
    if not report["complete"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
