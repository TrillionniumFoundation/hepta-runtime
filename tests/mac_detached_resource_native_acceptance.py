#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Mac CPU/memory resource admission: reject before durable identity or SSH.

This uses a disposable loopback V10 controller and a PATH sentinel that must
never run. It never contacts Mac or edits an installed operator instance.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/mcp/runtime/jobs.rs"


def write_private(path: Path, raw: bytes, mode: int = 0o600) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as file:
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    binary = Path(args.binary).resolve(strict=True)
    root = Path(args.output).absolute()
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name in ["state", "workspace", "bin"]:
        (root / name).mkdir(mode=0o700)
    token = secrets.token_hex(32)
    write_private(root / "token", token.encode("ascii"))

    host = {
        "ssh_target": "must-not-dispatch-r7",
        "platform": "macos",
        "execution_mode": "operator",
        "remote_state_dir": str(root / "unreachable-remote-state"),
        "allow_execute": True,
        "allow_pty": False,
        "allow_write": False,
        "allow_job_network": True,  # required for an operator host; sentinel still blocks SSH
        "allow_detached_fallback": True,
        "allowed_read_path_prefixes": [str(root)],
        "allowed_write_path_prefixes": [str(root)],
    }
    config = {
        "state_dir": str(root / "state"),
        "controller_workspace_roots": [str(root / "workspace")],
        "hosts": {"mac": host},
    }
    write_private(root / "runtime.json", json.dumps(config).encode())

    # A shell-free SSH sentinel is never intended to execute. Even a
    # misrouted command is locally refused rather than dispatched externally.
    write_private(
        root / "bin/ssh",
        (
            "#!/usr/bin/python3\nimport os,sys\n"
            f"p={str(root / 'ssh-called')!r}\n"
            "fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n"
            "os.write(fd,b'unexpected-ssh-dispatch');os.close(fd)\n"
            "raise SystemExit(96)\n"
        ).encode(), 0o700
    )
    spec = importlib.util.spec_from_file_location(
        "v10_native_fixture",
        ROOT / "tests/dc_functional_v10_operation_explicit_state_acceptance.py",
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    env = dict(os.environ, PATH=str(root / "bin") + ":" + os.environ.get("PATH", ""))
    controller = mod.Controller(
        binary, root / "workspace", root / "runtime.json", root / "token", env
    )
    report = {
        "schema": "hepta-macos-resource-preflight-native-v1",
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "tests": [],
        "complete": False,
        "target_mac_ssh_contacted": False,
        "installed_runtime_changed": False,
        "business_effect": False,
    }
    receipt = root / "result.json"
    def save():
        receipt.write_text(json.dumps(report, indent=2) + "\n")
        receipt.chmod(0o600)
    try:
        client = controller.start()
        catalog = client.rpc("tools/list", {})["tools"]
        frozen = json.loads(
            (ROOT / "deploy/contracts/hepta-runtime-full-operator-v10.json").read_text()
        )["tools"]
        assert {v["name"]: v for v in catalog} == {v["name"]: v for v in frozen}
        assert len(catalog) == 66
        cases = [
            ("cpu", {"cpu_quota_percent": 25}),
            ("memory", {"memory_max_bytes": 32 * 1024 * 1024}),
            ("cpu_memory", {"cpu_quota_percent": 25, "memory_max_bytes": 32 * 1024 * 1024}),
        ]
        for tag, bounds in cases:
            params = {
                "host": "mac",
                "executable": "/usr/bin/python3",
                "args": ["-c", "print('unreachable')"],
                "cwd": str(root / "workspace"),
                "idempotency_key": "mac-preflight-r7-" + tag,
                "timeout_seconds": 25,
                **bounds,
            }
            reply = client.raw_call("process_start", params)
            assert reply.get("isError") is True, (tag, reply)
            text = "\n".join(
                v.get("text", "") for v in reply.get("content", [])
                if v.get("type") == "text"
            )
            assert "macOS detached job backend cannot enforce" in text
            assert "no new job identity allocated or remote launch submitted" in text
            jobs = root / "state/jobs"
            assert not jobs.exists() or not list(jobs.iterdir())
            assert not (root / "ssh-called").exists()
            assert not (root / "unreachable-remote-state").exists()
            report["tests"].append({
                "name": tag,
                "rejected_before_identity_and_ssh": True,
                "no_job_record": True,
                "no_remote_state": True,
            })
            save()
        report["complete"] = True
    finally:
        controller.cleanup()
        controller.close_logs()
        report["owned_controllers_exited"] = all(
            p.poll() is not None for p in controller.children
        )
        report["target_mac_ssh_contacted"] = (root / "ssh-called").exists()
        save()
    assert report["complete"]
    assert report["owned_controllers_exited"]
    assert not report["target_mac_ssh_contacted"]
    print(json.dumps({
        "passed": len(report["tests"]),
        "original_66_definitions_exact": True,
        "no_job_or_remote_ssh_side_effect": True,
        "owned_controller_exited": True,
        "binary_sha256": report["binary_sha256"],
    }))


if __name__ == "__main__":
    main()
