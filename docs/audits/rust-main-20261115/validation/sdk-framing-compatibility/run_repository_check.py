#!/usr/bin/env python3
"""Retain source-bound metadata/lint checks; never execute the full test binary."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parent
REPO = BASE.parent / "runtime-transport-fix"
FILES = ["Cargo.toml", "Cargo.lock", "src/mcp/rea_mcp_transport.rs", "src/mcp/rea_mcp_transport_tests.rs"]


def sources():
    return {p: hashlib.sha256((REPO / p).read_bytes()).hexdigest() for p in FILES}


def main():
    name, *args = sys.argv[1:]
    argv = ["/home/agent/.cargo/bin/cargo", "+1.95.0", *args]
    env = os.environ.copy()
    changes = {"CARGO_BUILD_JOBS": "1", "CARGO_INCREMENTAL": "0", "CARGO_TARGET_DIR": str(BASE.parent / "runtime-dependency-target")}
    env.update(changes)
    before = sources()
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    clock = time.monotonic()
    log = BASE / (name + ".log")
    with log.open("wb") as out:
        result = subprocess.run(argv, cwd=REPO, env=env, stdout=out, stderr=subprocess.STDOUT, timeout=600)
    receipt = {"argv": argv, "cwd": str(REPO), "environment_changes": changes, "started_utc": started, "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "elapsed_seconds": round(time.monotonic() - clock, 3), "exit_code": result.returncode, "source_before": before, "source_after": sources(), "source_unchanged_during_command": before == sources(), "log": log.name, "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(), "scope": "Full repository formatting or metadata-only lint check; no full runtime test codegen or execution"}
    (BASE / (name + ".json")).write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
