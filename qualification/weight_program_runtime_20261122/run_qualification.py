#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Record bounded exact-source standalone gates, separately from root release gates."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import time


def pin(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def usage():
    r = resource.getrusage(resource.RUSAGE_CHILDREN)
    return r.ru_utime + r.ru_stime


def limit():
    os.setsid()
    resource.setrlimit(resource.RLIMIT_CPU, (180, 190))
    resource.setrlimit(resource.RLIMIT_AS, (3 * 1024**3, 3 * 1024**3))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parent
    sources = []
    for directory in [root, root.parent / "weight_semantic_adapter_20261120", root.parent / "weight_recovery_runtime_20261122"]:
        sources += sorted(p for p in directory.rglob("*") if p.is_file() and "target" not in p.relative_to(directory).parts
                          and (p.suffix == ".rs" or p.name in {"Cargo.toml", "Cargo.lock", "rustfmt.toml"}))
    sources.append(Path(__file__).resolve())
    pins = [pin(p) for p in sources]
    commands = [["cargo", "fmt", "--all", "--", "--check"]]
    for mode in ["--all-features", "--no-default-features"]:
        for gate in ["check", "clippy", "test"]:
            command = ["cargo", gate, "--offline", "--locked", "--all-targets", mode]
            if gate == "clippy":
                command += ["--", "-D", "warnings"]
            if gate == "test":
                command += ["--", "--test-threads=1"]
            commands.append(command)
    commands.append(["cargo", "build", "--offline", "--locked", "--all-features", "--bin", "hepta-weight-program-study"])
    protocol = {"schema": "hepta-weight-program-local-qualification.v1", "source_pins": pins, "commands": commands,
                "limits_per_command": {"cpu_soft_seconds": 180, "cpu_hard_seconds": 190, "wall_seconds": 240, "address_space_GiB": 3},
                "scope": "standalone crate and dependencies; cached development build; not complete-root release qualification"}
    (out / "PROTOCOL.json").write_text(json.dumps(protocol, indent=2) + "\n")
    wall = time.monotonic()
    supervisor = time.process_time()
    records = []
    success = True
    for index, command in enumerate(commands):
        before = usage()
        start = time.monotonic()
        log = out / f"gate_{index:02d}.log"
        with log.open("xb") as handle:
            proc = subprocess.Popen(command, cwd=root, stdout=handle, stderr=subprocess.STDOUT, preexec_fn=limit)
            try:
                code = proc.wait(timeout=240)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, 9)
                code = proc.wait()
        records.append({"command": command, "returncode": code, "child_cpu_seconds": usage() - before,
                        "wall_seconds": time.monotonic() - start, "log": pin(log)})
        if code:
            success = False
            break
    unchanged = pins == [pin(p) for p in sources]
    binary = root / "target/debug/hepta-weight-program-study"
    result = {"status": "PASS" if success and unchanged else "FAIL", "source_unchanged": unchanged, "records": records,
              "wall_seconds": time.monotonic() - wall, "supervisor_cpu_seconds": time.process_time() - supervisor,
              "child_cpu_seconds": sum(r["child_cpu_seconds"] for r in records),
              "peak_child_RSS_KiB": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
              "binary": pin(binary) if success else None,
              "excluded_costs": "earlier development builds, failed draft checks, CI, agent inference and independent experiment costs"}
    (out / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ["status", "source_unchanged", "child_cpu_seconds", "wall_seconds", "binary"]}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
