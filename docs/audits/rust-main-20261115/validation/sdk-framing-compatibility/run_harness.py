#!/usr/bin/env python3
"""Record focused tests of actual repository modules without building the runtime."""
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
HARNESS = BASE / "harness"
TARGET = BASE.parent / "runtime-transport-harness-target"
FILES = ["Cargo.toml", "Cargo.lock", "src/mcp/rea_mcp_transport.rs", "src/mcp/rea_mcp_transport_tests.rs"]


def sources():
    return {p: hashlib.sha256((REPO / p).read_bytes()).hexdigest() for p in FILES}


def main():
    name, *args = sys.argv[1:]
    argv = ["/home/agent/.cargo/bin/cargo", "+1.95.0", *args]
    env = os.environ.copy()
    changes = {"CARGO_BUILD_JOBS": "1", "CARGO_INCREMENTAL": "0", "CARGO_TARGET_DIR": str(TARGET)}
    env.update(changes)
    before = sources()
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    clock = time.monotonic()
    log = BASE / (name + ".log")
    with log.open("wb") as out:
        result = subprocess.run(argv, cwd=HARNESS, env=env, stdout=out, stderr=subprocess.STDOUT, timeout=900)
    receipt = {"argv": argv, "cwd": str(HARNESS), "environment_changes": changes, "started_utc": start, "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "elapsed_seconds": round(time.monotonic() - clock, 3), "exit_code": result.returncode, "source_before": before, "source_after": sources(), "source_unchanged_during_command": before == sources(), "log": log.name, "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(), "scope": "Focused actual transport/inline-order/structured-writer modules and exact extracted writer helpers; not full runtime coverage"}
    (BASE / (name + ".json")).write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
