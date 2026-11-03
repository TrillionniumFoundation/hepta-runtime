#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualify the corrected R13 snapshot without changing existing qualification evidence."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

root = Path("/home/qian/hepta-runtime-optimization-20261103-r13")
source = root / "source"
cargo_home = Path("/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02")
previous = root / "qualification-02/report.json"
old = json.loads(previous.read_text())
if not old.get("finished_utc") or old.get("qualified") is not False:
    raise RuntimeError("Expected the preserved failed qualification-02")
if (root / "qualification-03").exists():
    raise RuntimeError("qualification-03 already exists; inspect the original job instead of repeating it")
env = dict(os.environ)
removed = sorted(k for k in env if k.startswith(("CARGO_PROFILE_", "CARGO_TARGET_", "CARGO_BUILD_")))
for key in removed:
    env.pop(key)
env["LC_ALL"] = "C.UTF-8"
def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()
def capture(command):
    result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=20)
    return {"command": command, "exit": result.returncode, "stdout": result.stdout}
command = ["/usr/bin/python3", "-B", "-u", str(source / "tools/x230/20261028/qualify.py"),
           "--source", str(source), "--output", str(root / "qualification-03"),
           "--target", str(root / "target"), "--cargo-home", str(cargo_home),
           "--jobs", "2", "--stage-timeout", "3600"]
preflight = {
    "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "host": platform.node(), "kernel": platform.release(), "cpu_count": os.cpu_count(),
    "removed_build_environment_names": removed, "cargo_home": str(cargo_home),
    "previous_failed_qualification_sha256": digest(previous),
    "qualification_launcher_sha256": digest(__file__),
    "qualification_harness_sha256": digest(source / "tools/x230/20261028/qualify.py"),
    "source_parent_r11": "fe7d2b8afba882d06b607ec00b8756eed62f6a1f",
    "r12_checkpoint_commit": "fd37e1aeed7f945b352d2a45bc13a8200cdb79fa",
    "r12_tested_runtime_sha256": "e7f1f8275c6735a6823f35b6367baf9fc9f943ea7e62a1114fe1187e82cd1c1f",
    "automatic_retries": 0, "qualification_command": command,
    "rustc": capture(["/home/qian/.cargo/bin/rustc", "+1.95.0", "-Vv"]),
    "uptime": capture(["/usr/bin/uptime"]),
    "memory": capture(["/usr/bin/free", "-m"]),
    "disk": capture(["/usr/bin/df", "-h", str(root)]),
}
if preflight["rustc"]["exit"] != 0:
    raise RuntimeError("Pinned compiler is unavailable")
with (root / "build-preflight-03.json").open("x") as stream:
    stream.write(json.dumps(preflight, indent=2) + "\n")
print("QUALIFICATION_COMMAND " + json.dumps(command), flush=True)
result = subprocess.run(command, cwd=source, env=env)
print("QUALIFICATION_EXIT " + str(result.returncode), flush=True)
sys.exit(result.returncode)
