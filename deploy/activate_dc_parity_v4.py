#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Controlled private 46→50 tool cutover; exact-source and automatic rollback.

Switch only hepta-runtime-operator and the full-operator tunnel. Keep the
separate Desktop Commander service, SSH identities, PAM and runtime policy
unchanged. Use only after the frozen 50-tool release and six-host qualification.
Do not equate tunnel readiness with ChatGPT-originated write approval.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import sys
import time
import urllib.request

HOME = pathlib.Path.home()
ROOT = pathlib.Path(__file__).resolve().parents[1]
HEAD = "22986bab5e5c2b21f9dfd13befaee2046f7022cb"
OLD_NATIVE_SHA = "5bb9dadef53329caa13acec8965d2d6c074c17192c744078d76b689d8c3fb8b3"
NEW_NATIVE_SHA = "db181570e9e65f9e6a962d013dd4880eedc5b0cda1c71508f84388a4a8d8072b"
OLD_PROFILE_SHA = "1a6b9452159360bffee4b14e68f1355b360ef525e3500981dcfb7e780b0033ed"
NEW_CONTRACT_SHA = "d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1"
NATIVE_UNIT = "hepta-runtime-operator.service"
TUNNEL_UNIT = "hepta-openai-full-operator.service"
DC_UNIT = "desktop-commander-remote.service"
BIN = HOME / ".local/lib/hepta-runtime/releases/operator-v4-db181570e9e65f9e/hepta-runtime"
PROFILE = HOME / ".config/tunnel-client/hepta-full-operator.yaml"
V4_PROFILE = HOME / ".config/tunnel-client/hepta-full-operator-v4.yaml"
DROPIN = HOME / ".config/systemd/user/hepta-runtime-operator.service.d/60-parity-v4.conf"
INSTALLED = HOME / ".config/hepta-full-operator/installed.json"
BASE = HOME / ".config/hepta-full-operator"
TOKEN = HOME / ".config/hepta-runtime-operator/token"
ENV = dict(os.environ, XDG_RUNTIME_DIR=f"/run/user/{os.getuid()}",
           DBUS_SESSION_BUS_ADDRESS=f"unix:path=/run/user/{os.getuid()}/bus")

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def run(argv, check=True, timeout=30):
    p = subprocess.run(argv, env=ENV, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"Command {argv[0]} failed ({p.returncode})")
    return p

def system(*args, check=True):
    return run(["systemctl", "--user", *args], check=check)

def service(unit):
    v = run(["systemctl", "--user", "show", unit, "-p", "ActiveState",
             "-p", "MainPID", "-p", "UnitFileState"]).stdout
    return dict(line.split("=", 1) for line in v.splitlines() if "=" in line)

def atomic(path, data, mode=0o600):
    tmp = path.with_name(path.name + ".hepta-v4-atomic")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)

def private_backup(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

def catalog_count(expected):
    sys.path[:0] = [str(ROOT / "tests"), str(ROOT / "deploy")]
    from runtime_http_acceptance import Client
    from mcp_tool_contract import ToolContract
    with TOKEN.open() as f:
        token = f.read().strip()
    c = Client("http://127.0.0.1:8790/mcp", token)
    tools = c.rpc("tools/list", {})["tools"]
    if len(tools) != expected:
        raise RuntimeError(f"Native tool count differs from {expected}")
    if expected == 50:
        frozen = ToolContract.load(ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json",
                                   NEW_CONTRACT_SHA)
        frozen.verify(tools)
    return len(tools)

def wait_native(expected, timeout=45):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            if service(NATIVE_UNIT)["ActiveState"] == "active":
                return catalog_count(expected)
        except Exception as exc:
            last = type(exc).__name__
        time.sleep(0.5)
    raise RuntimeError("Native controller never returned the pinned tool count: " + str(last))

def ready(timeout=70):
    until = time.monotonic() + timeout
    last = "not ready"
    while time.monotonic() < until:
        try:
            with urllib.request.urlopen("http://127.0.0.1:8793/health?details=true", timeout=3) as r:
                obj = json.load(r)
            c = obj["components"]
            ok = (obj["ready"] and c["control-plane"]["status"] == "ok" and
                  bool(c["control-plane"]["details"].get("last_success")) and
                  c["mcp"]["details"].get("child_state") == "running")
            if ok:
                return {"ready": True, "control_plane": "ok",
                        "mcp_child": "running", "instance": obj["runtime"]["instance_id"]}
            last = "tunnel still initializing"
        except (OSError, ValueError, KeyError) as e:
            last = type(e).__name__
        time.sleep(1)
    raise RuntimeError(f"Tunnel failed readiness: {last}")

def preflight():
    if os.geteuid() == 0:
        raise PermissionError("Use the existing desktop user, not root")
    if run(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).stdout.strip() != HEAD:
        raise ValueError("Source commit changed since frozen 50-tool qualification")
    if run(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=no"]).stdout.strip():
        raise ValueError("Tracked source changed; require a new qualified source")
    if sha(BIN) != NEW_NATIVE_SHA or sha("/proc/" + service(NATIVE_UNIT)["MainPID"] + "/exe") != OLD_NATIVE_SHA:
        raise ValueError("Native binary release identity mismatch")
    if sha(PROFILE) != OLD_PROFILE_SHA or sha(ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json") != NEW_CONTRACT_SHA:
        raise ValueError("Profile or contract changed")
    if DROPIN.exists() or DROPIN.is_symlink():
        raise ValueError("An existing v4 unit override requires manual reconciliation")
    if any(service(u)["ActiveState"] != "active" for u in (DC_UNIT, TUNNEL_UNIT, NATIVE_UNIT)):
        raise ValueError("Protected services must all be active")
    if catalog_count(46) != 46:
        raise ValueError("Live runtime not at expected 46-tool baseline")
    activity = pathlib.Path("/tmp/hepta-v4-all-job-terminal-readonly-20261013.log")
    pty_activity = pathlib.Path("/tmp/hepta-v4-precutover-activity-20261012.log")
    for receipt in (activity, pty_activity):
        if not receipt.exists() or time.time()-receipt.stat().st_mtime > 900:
            raise RuntimeError("Require fresh independent full job and PTY scans")
    finals = [line[6:] for line in activity.read_text().splitlines()
              if line.startswith("FINAL ")]
    if len(finals) != 1:
        raise RuntimeError("Durable job scan missing one authoritative summary")
    jobs = json.loads(finals[0])
    if jobs.get("total") != 153 or jobs.get("nonterminal_count") != 0 or jobs.get("error_classes"):
        raise RuntimeError("Job scan contains active or unresolved work")
    import ast
    pty_lines = [line[12:] for line in pty_activity.read_text().splitlines()
                 if line.startswith("PTY_SUMMARY ")]
    if len(pty_lines) != 1:
        raise RuntimeError("PTY scan missing one authoritative summary")
    pty_summary = ast.literal_eval(pty_lines[0])
    if (pty_summary.get("checked") != 37 or pty_summary.get("pagination_had_more")
            or pty_summary.get("counts") != {"('main', 'exited', True)": 37}):
        raise RuntimeError("PTYs are not all finalized")
    # No new native jobs, PTYs or cooperative stream owners may have appeared
    # after the complete read-only maintenance inventory.
    sys.path.insert(0, str(ROOT / "tests"))
    from runtime_http_acceptance import Client
    with TOKEN.open() as fd:
        scan = Client("http://127.0.0.1:8790/mcp", fd.read().strip())
    if len(scan.call("process_list", {})["jobs"]) != 153:
        raise RuntimeError("Job list changed after the qualified maintenance inventory")
    sessions = scan.call("pty_list", {"host": "main", "limit": 128})
    if sessions.get("has_more") or len(sessions["sessions"]) != 37:
        raise RuntimeError("PTY inventory changed since qualified terminal scan")
    streams = scan.call("stream_handoff_list", {"limit": 100})["sessions"]
    if any(item.get("status", {}).get("state") != "exited" for item in streams):
        raise RuntimeError("Live cooperative stream owner blocks controller cutover")
    # This preflight observes, but never alters, the live dispatch queue.
    with urllib.request.urlopen("http://127.0.0.1:8793/health?details=true", timeout=3) as r:
        current = json.load(r)
    dispatcher = current["components"]["dispatcher"]["details"]
    queue = current["components"]["queue"]["details"]
    if dispatcher.get("active") != 0 or queue.get("depth") != 0:
        raise RuntimeError("Live tunnel still has active/queued requests")
    v4 = json.loads(V4_PROFILE.read_text())
    old = json.loads(PROFILE.read_text())
    new_args = shlex.split(v4["mcp"]["commands"][0]["command"])
    contract = pathlib.Path(new_args[new_args.index("--contract")+1])
    if sha(contract) != NEW_CONTRACT_SHA:
        raise ValueError("Staged profile doesn't carry frozen v4 contract")
    if new_args[0] != "/usr/bin/python3" or not pathlib.Path(new_args[1]).is_file():
        raise ValueError("Staged Full Operator facade is invalid")
    if sha(new_args[1]) != sha(ROOT / "deploy/chatgpt_full_operator.py"):
        raise ValueError("Staged facade differs from reviewed adapter")
    old["mcp"]["commands"][0]["command"] = v4["mcp"]["commands"][0]["command"]
    if old["health"]["listen_addr"] != "127.0.0.1:8793":
        raise ValueError("Cannot change production tunnel listener in this operation")
    old_cmd = shlex.split(json.loads(PROFILE.read_text())["mcp"]["commands"][0]["command"])
    if old_cmd[0] != "/usr/bin/python3" or "v1.json" not in " ".join(old_cmd):
        raise ValueError("Old tunnel facade identity was not as expected")
    for flag in ("--acknowledge-full-operator", "--stdio"):
        if flag not in new_args:
            raise ValueError("Full-operator acknowledgement or stdio flag missing")
    update = (json.dumps(old, indent=2) + "\n").encode()
    override = (
        "[Service]\nExecStart=\nExecStart=" + shlex.join([
            str(BIN), "mcp", "--path",
            str(HOME / ".local/share/hepta-runtime-operator/workspace"),
            "--bind", "127.0.0.1:8790", "--runtime-config",
            str(HOME / ".config/hepta-runtime-operator/runtime.json"),
            "--auth-token-file", str(TOKEN)]) + "\n"
    ).encode()
    return update, override

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--preflight", action="store_true")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    if args.preflight == args.apply:
        raise ValueError("Specify exactly one --preflight or --apply")
    update, override = preflight()
    print(json.dumps({"preflight": True, "candidate_tools": 50,
          "current_tools": 46, "schema_additions": 4,
          "runtime_sha256": NEW_NATIVE_SHA,
          "replacement_tunnel_profile_sha256": hashlib.sha256(update).hexdigest(),
          "protected_dc": service(DC_UNIT)["MainPID"]}, indent=2), flush=True)
    if not args.apply:
        return
    original_dc = service(DC_UNIT)["MainPID"]
    original_profile = PROFILE.read_bytes()
    original_manifest = INSTALLED.read_bytes()
    original_native_unit = service(NATIVE_UNIT)["MainPID"]
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = BASE / ("backup-before-v4-"+stamp)
    backup.mkdir(mode=0o700)
    private_backup(backup / "full-operator-profile.json", original_profile)
    private_backup(backup / "installed-manifest.json", original_manifest)
    switched = False
    try:
        system("stop", TUNNEL_UNIT)
        atomic(DROPIN, override)
        system("daemon-reload")
        system("restart", NATIVE_UNIT)
        wait_native(50)
        if service(DC_UNIT)["MainPID"] != original_dc:
            raise RuntimeError("Desktop Commander PID changed during upgrade")
        atomic(PROFILE, update)
        os.environ["CONTROL_PLANE_TUNNEL_ID"] = next(
            line.split("=",1)[1] for line in (HOME / ".config/hepta-chatgpt-tunnel/tunnel.env").read_text().splitlines()
            if line.startswith("CONTROL_PLANE_TUNNEL_ID=")
        )
        ENV["CONTROL_PLANE_TUNNEL_ID"] = os.environ["CONTROL_PLANE_TUNNEL_ID"]
        doctor = run([str(HOME / ".local/bin/tunnel-client"), "doctor",
                      "--profile", "hepta-full-operator",
                      "--health.listen-addr", "127.0.0.1:0"], timeout=60)
        if "RESULT ok" not in doctor.stdout:
            raise RuntimeError("New full tool tunnel doctor failed")
        system("start", TUNNEL_UNIT)
        signal = ready()
        if service(DC_UNIT)["MainPID"] != original_dc:
            raise RuntimeError("Desktop Commander PID changed during tunnel start")
        manifest = json.loads(original_manifest)
        new_command = shlex.split(json.loads(update)["mcp"]["commands"][0]["command"])
        manifest["release"] = str(pathlib.Path(new_command[1]).parent)
        manifest["facade_sha256"] = sha(new_command[1])
        manifest["contract_sha256"] = NEW_CONTRACT_SHA
        manifest["tool_contract_catalog_sha256"] = json.loads(
            (ROOT / "deploy/contracts/hepta-runtime-full-operator-v4.json").read_text()
        )["catalog_sha256"]
        manifest["tools"] = 50
        atomic(INSTALLED, (json.dumps(manifest, indent=2)+"\n").encode())
        switched = True
        evidence = {
            "status": "v4_server_activated",
            "native_tool_count": 50,
            "old_native_pid": original_native_unit,
            "new_native_pid": service(NATIVE_UNIT)["MainPID"],
            "protected_dc_pid_unchanged": original_dc,
            "tunnel_pid": service(TUNNEL_UNIT)["MainPID"],
            "health": signal,
            "backup_dir": str(backup),
            "model_originated_new_tools_approved": False,
            "chatgpt_workspace_rescan_required": True,
            "rollback_procedure": "restore backed-up profile/manifest, remove v4 drop-in, daemon-reload and restart native then tunnel",
        }
        receipt = backup / "activation.json"
        private_backup(receipt, (json.dumps(evidence, indent=2)+"\n").encode())
        print("ACTIVATION_SUCCESS", json.dumps(evidence, indent=2), flush=True)
    except BaseException as exc:
        print("ACTIVATION_ERROR", type(exc).__name__, str(exc)[:350], flush=True)
        # Restore trusted local routing before bringing the previous native back.
        system("stop", TUNNEL_UNIT, check=False)
        atomic(PROFILE, original_profile)
        atomic(INSTALLED, original_manifest)
        DROPIN.unlink(missing_ok=True)
        system("daemon-reload", check=False)
        system("restart", NATIVE_UNIT, check=False)
        try:
            old_tools = wait_native(46)
            system("start", TUNNEL_UNIT, check=False)
            ready(timeout=70)
            print("ROLLBACK_RESTORED", {"native_tools":old_tools,
                  "dc_pid_unchanged": service(DC_UNIT)["MainPID"] == original_dc}, flush=True)
        except Exception as rollback_error:
            print("ROLLBACK_NEEDS_MANUAL_INTERVENTION",
                  type(rollback_error).__name__, flush=True)
        raise
    if not switched:
        raise RuntimeError("Activation not completed")

if __name__ == "__main__":
    main()
