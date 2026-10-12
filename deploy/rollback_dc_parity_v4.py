#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Explicit rollback for the one-time v4 native+Full Operator tunnel cutover.

This intentionally requires --apply, the exact backed-up profile and known
v4 hashes. It never edits DC, sudoers, PAM, runtime.json or user tokens.
Before any rollback of a live installation, independently inventory jobs and
PTYs again. A changed durable-job inventory aborts automatic rollback.
"""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import time
import urllib.request

HOME = pathlib.Path.home()
BASE = HOME / ".config/hepta-full-operator"
PROFILE = HOME / ".config/tunnel-client/hepta-full-operator.yaml"
INSTALLED = BASE / "installed.json"
DROPIN = HOME / ".config/systemd/user/hepta-runtime-operator.service.d/60-parity-v4.conf"
OLD_PROFILE_SHA = "1a6b9452159360bffee4b14e68f1355b360ef525e3500981dcfb7e780b0033ed"
NEW_PROFILE_SHA = "c59977366cd38fb8316f31c711942b334f77b31318be5a7ca7803affab0cecf9"
OLD_NATIVE_SHA = "5bb9dadef53329caa13acec8965d2d6c074c17192c744078d76b689d8c3fb8b3"
NEW_NATIVE_SHA = "db181570e9e65f9e6a962d013dd4880eedc5b0cda1c71508f84388a4a8d8072b"
ENV = dict(os.environ, XDG_RUNTIME_DIR=f"/run/user/{os.getuid()}",
           DBUS_SESSION_BUS_ADDRESS=f"unix:path=/run/user/{os.getuid()}/bus")

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def system(*args):
    p = subprocess.run(["systemctl", "--user", *args], capture_output=True,
                       text=True, timeout=35, env=ENV)
    if p.returncode:
        raise RuntimeError("systemctl failed: " + args[0])

def pid(unit):
    p = subprocess.run(["systemctl", "--user", "show", unit, "-p", "MainPID",
                        "--value"], capture_output=True, text=True, timeout=8, env=ENV)
    if p.returncode or not p.stdout.strip().isdigit():
        raise RuntimeError("systemd unit identity unavailable")
    return p.stdout.strip()

def atomically_restore(path, content):
    other = path.with_name(path.name+".hepta-v4-rollback-tmp")
    fd = os.open(other, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(other, path)
    finally:
        other.unlink(missing_ok=True)

def native_tool_count():
    import sys
    sys.path.insert(0,str(HOME/"hepta-runtime-operator-20261006/tests"))
    from runtime_http_acceptance import Client
    with (HOME/".config/hepta-runtime-operator/token").open() as stream:
        token=stream.read().strip()
    client=Client("http://127.0.0.1:8790/mcp",token)
    return len(client.rpc("tools/list",{})["tools"])

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--backup-dir",required=True)
    ap.add_argument("--inspect",action="store_true")
    ap.add_argument("--apply",action="store_true")
    args=ap.parse_args()
    if args.apply==args.inspect:raise ValueError("Specify exactly one of --inspect or --apply")
    if os.geteuid()==0:raise PermissionError("Use desktop login, never root")
    backup=pathlib.Path(args.backup_dir).resolve(strict=True)
    if backup.parent!=BASE.resolve() or not backup.name.startswith("backup-before-v4-"):
        raise ValueError("Select the exact private pre-v4 cutover backup")
    old_profile=backup/"full-operator-profile.json"
    old_manifest=backup/"installed-manifest.json"
    if sha(old_profile)!=OLD_PROFILE_SHA or sha(PROFILE)!=NEW_PROFILE_SHA:
        raise ValueError("Live/backup tunnel identity differs; manual reconciliation required")
    manifest=json.loads(old_manifest.read_text())
    if manifest.get("tools")!=46:
        raise ValueError("Backup manifest is not the old 46-tool release")
    old_bin=HOME/".local/lib/hepta-runtime/releases/operator-5bb9dadef53329ca/hepta-runtime"
    if sha(old_bin)!=OLD_NATIVE_SHA or sha("/proc/"+pid("hepta-runtime-operator.service")+"/exe")!=NEW_NATIVE_SHA:
        raise ValueError("Native binary identities changed since the cutover")
    if not DROPIN.is_file():
        raise ValueError("Expected v4 unit override missing")
    dc_before=pid("desktop-commander-remote.service")
    if dc_before=="0":
        raise RuntimeError("Keep Desktop Commander online before rollback")
    # Do not roll back after somebody starts new model-origin native tasks:
    # their identities belong to the v4 state and could become orphaned.
    import sys
    sys.path.insert(0,str(HOME/"hepta-runtime-operator-20261006/tests"))
    from runtime_http_acceptance import Client
    with (HOME/".config/hepta-runtime-operator/token").open() as stream:
        token=stream.read().strip()
    client=Client("http://127.0.0.1:8790/mcp",token)
    jobs=client.call("process_list",{})["jobs"]
    ptys=client.call("pty_list",{"host":"main","limit":128})["sessions"]
    if len(jobs)!=153 or len(ptys)!=37:
        raise RuntimeError("Durable session inventory changed; rollback requires a new maintenance plan")
    print(json.dumps({"rollback_preflight":True,"current_native_tools":native_tool_count(),
          "backup_old_tools":manifest["tools"],"old_profile_sha256":sha(old_profile),
          "new_profile_sha256":sha(PROFILE),"current_jobs":len(jobs),
          "current_ptys":len(ptys),"desktop_commander_pid":dc_before},indent=2))
    if not args.apply:return
    system("stop","hepta-openai-full-operator.service")
    atomically_restore(PROFILE,old_profile.read_bytes())
    atomically_restore(INSTALLED,old_manifest.read_bytes())
    DROPIN.unlink()
    system("daemon-reload")
    system("restart","hepta-runtime-operator.service")
    until=time.monotonic()+50
    while time.monotonic()<until:
        try:
            if native_tool_count()==46:break
        except Exception:pass
        time.sleep(0.5)
    else:raise RuntimeError("Old native 46-tool controller not ready; do not start mismatched tunnel")
    system("start","hepta-openai-full-operator.service")
    until=time.monotonic()+70
    while time.monotonic()<until:
        try:
            with urllib.request.urlopen("http://127.0.0.1:8793/health?details=true",timeout=3) as r:health=json.load(r)
            if health["ready"] and health["components"]["control-plane"]["status"]=="ok":break
        except Exception:pass
        time.sleep(1)
    else:raise RuntimeError("Restored tunnel has not recovered readiness")
    if pid("desktop-commander-remote.service")!=dc_before:
        raise RuntimeError("Desktop Commander changed unexpectedly")
    print(json.dumps({"rollback_complete":True,"runtime_tools":46,
                      "full_tunnel_ready":True,"desktop_commander_unchanged":True}))

if __name__=="__main__":main()
