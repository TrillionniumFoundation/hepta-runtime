#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Record a bounded, isolated local Rust qualification attempt without retries."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import tempfile
import time
from datetime import datetime, timezone


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["root", "target", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--attempt", type=int, required=True)
    args = parser.parse_args()
    root, target, output = args.root.resolve(), args.target.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    os.umask(0o022)
    temp = Path(tempfile.mkdtemp(prefix="hwt-", dir="/tmp"))
    temp.chmod(0o700)
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS="2", TMPDIR=str(temp), RUST_BACKTRACE="1")
    cargo = str(Path.home() / ".cargo/bin/cargo")
    commands = [
        [cargo, "fmt", "--all"],
        [cargo, "test", "--locked", "--offline", "--all-features", "--lib", "weight_", "--", "--test-threads=1"],
        [cargo, "clippy", "--locked", "--offline", "--all-features", "--all-targets", "--", "-D", "warnings"],
        [cargo, "test", "--locked", "--offline", "--no-default-features", "--lib", "weight_", "--", "--test-threads=1"],
        [cargo, "build", "--locked", "--offline", "--all-features", "--bin", "hepta-runtime"],
        [cargo, "fmt", "--all", "--", "--check"],
    ]
    protocol = root / "experiments/weight/native_trust_region_20261105/PROTOCOL.json"
    receipt = {
        "schema": "hepta.native-wsp-trust-region-local-qualification.v1",
        "attempt": args.attempt,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "protocol_sha256": sha(protocol),
        "base_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True).strip(),
        "rustc_version": subprocess.check_output([str(Path.home()/".cargo/bin/rustc"), "--version"], text=True).strip(),
        "cargo_version": subprocess.check_output([cargo, "--version"], text=True).strip(),
        "cargo_lock_sha256": sha(root / "Cargo.lock"),
        "cargo_build_jobs": 2,
        "test_threads": 1,
        "nofile_limit": 1024,
        "address_space_limit_bytes": 8 * 1024**3,
        "temporary_directory_outside_worktree": True,
        "temporary_directory_mode": "0700",
        "commands": [],
        "completed": False,
        "passed": False,
        "scope": "Focused weight-library tests and requested local format, Clippy, configuration and binary gates; not the complete repository suite or model-efficacy qualification.",
    }

    def save() -> None:
        (output / "qualification.json").write_text(json.dumps(receipt, indent=2, allow_nan=False)+"\n")

    def limits() -> None:
        _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        cap = 1024 if hard == resource.RLIM_INFINITY else min(1024, hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (cap, cap))
        _, hard = resource.getrlimit(resource.RLIMIT_AS)
        cap = 8 * 1024**3 if hard == resource.RLIM_INFINITY else min(8 * 1024**3, hard)
        resource.setrlimit(resource.RLIMIT_AS, (cap, cap))

    def source_identity() -> list[dict]:
        names = ["mod.rs", "server.rs", "weight_ridge.rs", "weight_ridge_tests.rs", "weight_guard.rs", "weight_guard_tests.rs", "weight_norm.rs", "weight_norm_tests.rs", "weight_trust_region.rs", "weight_trust_region_tests.rs"]
        return [{"path":"src/mcp/"+name, "bytes":(root/"src/mcp"/name).stat().st_size, "sha256":sha(root/"src/mcp"/name)} for name in names]

    receipt["source_before_format"] = source_identity()
    save()
    start = time.perf_counter()
    for index, command in enumerate(commands):
        log = output / f"command-{index+1}.log"
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        then = time.perf_counter()
        timed_out = False
        with log.open("wb") as stream:
            process = subprocess.Popen(command, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=limits)
            try:
                code = process.wait(timeout=1200)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    code = process.wait()
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        row = {
            "command": ["cargo"] + command[1:],
            "exit_code": code,
            "timed_out": timed_out,
            "wall_seconds": time.perf_counter()-then,
            "child_user_cpu_seconds": after.ru_utime-before.ru_utime,
            "child_system_cpu_seconds": after.ru_stime-before.ru_stime,
            "log_bytes": log.stat().st_size,
            "log_sha256": sha(log),
        }
        receipt["commands"].append(row)
        receipt["source_after_last_command"] = source_identity()
        if index == 0:
            receipt["source_after_format"] = receipt["source_after_last_command"]
        save()
        print(json.dumps(row), flush=True)
        if code != 0 or timed_out:
            break
    receipt["completed"] = True
    receipt["passed"] = len(receipt["commands"]) == len(commands) and all(x["exit_code"] == 0 and not x["timed_out"] for x in receipt["commands"])
    receipt["total_wall_seconds"] = time.perf_counter()-start
    receipt["completed_utc"] = datetime.now(timezone.utc).isoformat()
    receipt["source_unchanged_after_format"] = receipt.get("source_after_format") == receipt["source_after_last_command"]
    binary = target / "debug/hepta-runtime"
    if receipt["passed"]:
        receipt["binary"] = {"bytes":binary.stat().st_size, "sha256":sha(binary)}
    save()
    print(json.dumps({"passed":receipt["passed"], "wall_seconds":receipt["total_wall_seconds"]}), flush=True)
    raise SystemExit(0 if receipt["passed"] else 1)


if __name__ == "__main__":
    main()
