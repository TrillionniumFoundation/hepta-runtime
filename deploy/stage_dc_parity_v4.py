#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Stage the reviewed 50-tool v4 candidate, without deploying or enabling it.

This is deliberately NOT a production switch helper. The existing 46-tool
runtime, ChatGPT full-operator tunnel and Desktop Commander remain untouched.
One SHA-pinned native artifact and private read-only tunnel profile are staged
for independent qualification and a separate, explicitly permitted cutover.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import shlex
import stat
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"deploy"))
from mcp_tool_contract import ToolContract

def sha(data):
    return hashlib.sha256(data).hexdigest()

def exact_file(path, contents, mode):
    """Create-only, no symlink, never overwrite an unrelated existing release."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or path.read_bytes() != contents:
            raise FileExistsError("existing staged asset differs")
        if path.stat().st_mode & 0o022:
            raise PermissionError("staged asset is writable by others")
        return
    fd = os.open(path, os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(contents)
        handle.flush()
        os.fsync(handle.fileno())

def service_identity():
    env = {**os.environ,
           "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
           "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{os.getuid()}/bus"}
    identities = {}
    for name in ("hepta-runtime-operator.service", "desktop-commander-remote.service",
                 "hepta-openai-full-operator.service"):
        value = subprocess.check_output(
            ["systemctl", "--user", "show", name,
             "-p", "MainPID", "-p", "ActiveState"],
            env=env, text=True, timeout=10)
        fields = dict(row.split("=", 1) for row in value.splitlines() if "=" in row)
        if fields.get("ActiveState") != "active" or fields.get("MainPID") in (None, "0"):
            raise RuntimeError("protected service unavailable: " + name)
        identities[name] = fields
    return identities

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--output", required=True, help="New private receipt path")
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise PermissionError("stage under the existing user, not root")
    head = subprocess.check_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    if head != args.source_head:
        raise ValueError("source HEAD changed; frozen release identity required")
    for path in ("src/mcp", "Cargo.toml", "Cargo.lock"):
        result = subprocess.run(
            ["git", "-C", str(ROOT), "diff", "--quiet", "--", path])
        if result.returncode:
            raise ValueError("source differs from reviewed commit: " + path)
    binary = pathlib.Path(args.binary)
    if binary.is_symlink() or not stat.S_ISREG(binary.stat().st_mode):
        raise ValueError("release input must be a regular file")
    release_data = binary.read_bytes()
    actual = sha(release_data)
    if actual != args.expected_binary_sha256 or len(release_data) < 1000000:
        raise ValueError("binary SHA256 or minimum size mismatch")
    contract_path = ROOT/"deploy/contracts/hepta-runtime-full-operator-v4.json"
    contract_data = contract_path.read_bytes()
    contract_hash = sha(contract_data)
    contract = ToolContract.load(contract_path, contract_hash)
    if len(contract.tools) != 50:
        raise ValueError("exact v4 50 tools required")
    previous = ROOT/"deploy/contracts/hepta-runtime-full-operator-v3.json"
    prior = ToolContract.load(previous, sha(previous.read_bytes()))
    if len(prior.tools) != 49 or set(contract.by_name) - set(prior.by_name) != {"directory_move"}:
        raise ValueError("v4 must be exactly one additive native directory operation")
    for name, tool in prior.by_name.items():
        if contract.by_name[name] != tool:
            raise ValueError("previous tool schema changed: " + name)
    if contract.by_name["directory_move"]["annotations"] != {
        "readOnlyHint": False, "destructiveHint": True,
        "idempotentHint": False, "openWorldHint": False,
    }:
        raise ValueError("directory_move risk hints changed")
    before = service_identity()
    home = pathlib.Path.home()
    native_release = home/".local/lib/hepta-runtime/releases"/("operator-v4-"+actual[:16])
    native_file = native_release/"hepta-runtime"
    exact_file(native_file, release_data, 0o700)
    if sha(native_file.read_bytes()) != actual:
        raise ValueError("native staged artifact digest differs")
    facade_source = ROOT/"deploy/chatgpt_full_operator.py"
    facade_bytes = facade_source.read_bytes()
    adapter_release = home/".local/lib/hepta-chatgpt-full/releases"/("v4-"+sha(facade_bytes)[:16]+"-"+contract_hash[:12])
    facade = adapter_release/"chatgpt_full_operator.py"
    shared = adapter_release/"mcp_tool_contract.py"
    pinned = adapter_release/"hepta-runtime-full-operator-v4.json"
    exact_file(facade, facade_bytes, 0o600)
    exact_file(shared, (ROOT/"deploy/mcp_tool_contract.py").read_bytes(), 0o600)
    exact_file(pinned, contract_data, 0o600)
    command = shlex.join([
        "/usr/bin/python3", str(facade), "--stdio",
        "--token-file", str(home/".config/hepta-runtime-operator/token"),
        "--contract", str(pinned), "--contract-sha256", contract_hash,
        "--acknowledge-full-operator",
    ])
    live_profile = json.loads((home/".config/tunnel-client/hepta-full-operator.yaml").read_text())
    new_profile = dict(live_profile)
    new_profile["health"] = {"listen_addr": "127.0.0.1:8794"}
    new_profile["mcp"] = dict(live_profile["mcp"])
    new_profile["mcp"]["commands"] = [{"channel": "main", "command": command}]
    profile_path = home/".config/tunnel-client/hepta-full-operator-v4.yaml"
    profile_bytes = (json.dumps(new_profile, indent=2) + "\n").encode()
    exact_file(profile_path, profile_bytes, 0o600)
    tunnel_env = (home/".config/hepta-chatgpt-tunnel/tunnel.env").read_text().splitlines()
    tunnel_id = next((s.partition("=")[2] for s in tunnel_env
                      if s.startswith("CONTROL_PLANE_TUNNEL_ID=")), None)
    if not tunnel_id or not tunnel_id.startswith("tunnel_"):
        raise ValueError("existing restricted tunnel identity unavailable")
    env = {**os.environ, "CONTROL_PLANE_TUNNEL_ID": tunnel_id}
    doctor = subprocess.run([
        str(home/".local/bin/tunnel-client"), "doctor", "--profile",
        "hepta-full-operator-v4", "--health.listen-addr", "127.0.0.1:0",
    ], capture_output=True, text=True, env=env, timeout=60)
    if doctor.returncode != 0 or "RESULT ok" not in doctor.stdout:
        raise RuntimeError("staged v4 doctor did not pass; live tunnel unchanged")
    after = service_identity()
    if after != before:
        raise RuntimeError("protected service identity changed during staging")
    record = {
        "schema": "hepta-dc-v4-staged-no-activation-v1",
        "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_head": head,
        "native_release": str(native_file),
        "native_sha256": actual,
        "native_bytes": len(release_data),
        "adapter_release": str(adapter_release),
        "adapter_sha256": sha(facade_bytes),
        "pinned_contract": str(pinned),
        "contract_sha256": contract_hash,
        "catalog_sha256": contract.catalog_sha256,
        "tool_count": 50,
        "staged_profile": str(profile_path),
        "profile_sha256": sha(profile_bytes),
        "doctor": "RESULT ok",
        "service_identities_unchanged": True,
        "services_before_and_after": before,
        "native_runtime_replaced": False,
        "full_operator_tunnel_restarted": False,
        "desktop_commander_restarted": False,
        "model_origin_write_qualified": False,
        "candidate_profile_started": False,
        "public_gateway_started": False,
    }
    dest = pathlib.Path(args.output)
    exact_file(dest, (json.dumps(record, indent=2)+"\n").encode(), 0o600)
    print(json.dumps({"staged": True, "activated": False,
                      "native_release": str(native_file), "contract_count": 50,
                      "doctor": "RESULT ok", "protected_pids_unchanged": True}, indent=2))

if __name__ == "__main__":
    main()
