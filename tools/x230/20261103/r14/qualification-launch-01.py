#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualify the frozen R14 preparation-admission candidate once."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

root = Path("/home/qian/hepta-runtime-optimization-20261103-r14")
source = root / "source"
baseline = Path("/home/qian/hepta-runtime-optimization-20261103-r13")
cargo_home = Path("/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02")
def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()
def source_map(directory):
    paths = [directory / name for name in ("Cargo.toml", "Cargo.lock", "rustfmt.toml")]
    for name in ("src", "examples"):
        paths.extend(p for p in (directory / name).rglob("*") if p.is_file())
    return {str(p.relative_to(directory)): digest(p) for p in sorted(paths) if p.is_file()}
ready_path = root / "implementation-ready.json"
ready = json.loads(ready_path.read_text())
previous = baseline / "qualification-03/report.json"
old = json.loads(previous.read_text())
if not old.get("finished_utc") or old.get("qualified") is not True:
    raise RuntimeError("Expected the preserved successful R13 qualification-03")
if old["source_tested"] != old["source_after"] or source_map(baseline / "source") != old["source_after"]:
    raise RuntimeError("R13 source baseline changed")
if digest(baseline / "qualification-03/hepta-runtime") != "91baf096139002075ead3c2b9043ffe12269c155650c41bd4258efd3ac5ef364":
    raise RuntimeError("R13 runtime baseline changed")
current = source_map(source)
if current != ready["source_after"]:
    raise RuntimeError("R14 candidate changed after implementation freeze")
if (root / "qualification-01").exists():
    raise RuntimeError("qualification-01 already exists; inspect its original job")
env = dict(os.environ)
removed = sorted(k for k in env if k.startswith(("CARGO_PROFILE_", "CARGO_TARGET_", "CARGO_BUILD_")))
for key in removed:
    env.pop(key)
env["LC_ALL"] = "C.UTF-8"
def capture(command):
    result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=20)
    return {"command": command, "exit": result.returncode, "stdout": result.stdout}
command = ["/usr/bin/python3", "-B", "-u", str(source / "tools/x230/20261028/qualify.py"),
           "--source", str(source), "--output", str(root / "qualification-01"),
           "--target", str(baseline / "target"), "--cargo-home", str(cargo_home),
           "--jobs", "2", "--stage-timeout", "3600"]
preflight = {
    "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "host": platform.node(), "kernel": platform.release(), "cpu_count": os.cpu_count(),
    "removed_build_environment_names": removed, "cargo_home": str(cargo_home),
    "r13_qualification_sha256": digest(previous),
    "implementation_ready_sha256": digest(ready_path),
    "qualification_launcher_sha256": digest(__file__),
    "qualification_harness_sha256": digest(source / "tools/x230/20261028/qualify.py"),
    "source_before": current,
    "target_cache": str(baseline / "target"),
    "target_cache_scope": "Build cache only; qualified R13 copies remain unchanged",
    "r12_checkpoint_commit": "fd37e1aeed7f945b352d2a45bc13a8200cdb79fa",
    "r13_runtime_sha256": "91baf096139002075ead3c2b9043ffe12269c155650c41bd4258efd3ac5ef364",
    "automatic_retries": 0, "qualification_command": command,
    "rustc": capture(["/home/qian/.cargo/bin/rustc", "+1.95.0", "-Vv"]),
    "uptime": capture(["/usr/bin/uptime"]),
    "memory": capture(["/usr/bin/free", "-m"]),
    "disk": capture(["/usr/bin/df", "-h", str(root)]),
}
if preflight["rustc"]["exit"] != 0:
    raise RuntimeError("Pinned compiler is unavailable")
with (root / "build-preflight-01.json").open("x") as stream:
    stream.write(json.dumps(preflight, indent=2) + "\n")
print("QUALIFICATION_COMMAND " + json.dumps(command), flush=True)
result = subprocess.run(command, cwd=source, env=env)
print("QUALIFICATION_EXIT " + str(result.returncode), flush=True)
sys.exit(result.returncode)
