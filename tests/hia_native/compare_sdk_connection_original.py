#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Build three locked original SDK binaries and replay all six complete domains."""
from pathlib import Path
import argparse
import json
import os
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from connection_registry import source_pins
from hia_native_connection_reference import prepare_original_reference, check_project
from hia_native_connection_qualification import (REPLAYS, REMOVED_ENVIRONMENT, checked_native_result,
    compare_replay_to_native, encoded, object_at, read, require, sha)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--native-results", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cargo", required=True, type=Path)
    parser.add_argument("--rustc", required=True, type=Path)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    root = args.repo.resolve(strict=True)
    require(root == ROOT, "selected repository does not own this driver")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    native = checked_native_result(root, args.native_results)
    pins = source_pins(root)
    bundle = object_at(native["build"])
    # Preserve rustup shim argv[0]. Resolve only for file identity, never invocation.
    rustc, cargo = args.rustc.absolute(), args.cargo.absolute()
    env = {k: v for k, v in os.environ.items() if not k.startswith("HIA_") and k not in REMOVED_ENVIRONMENT}
    env.update(RUSTC=str(rustc), CARGO_TARGET_DIR=str(output / "target"))
    started = time.monotonic()
    result = {"schema": "hepta.sdk-connection.original-result.v1", "status": "RUNNING", "sources": pins,
              "native_result_sha256": sha(read(args.native_results)), "fresh_actual_cargo_build": False,
              "actual_original_processes": 0, "cases": 0, "native_calls_added": 0,
              "production_tool_dispatch_closed": False, "cargo": str(cargo), "rustc": str(rustc),
              "cargo_sha256": sha(read(cargo.resolve(strict=True))), "rustc_sha256": sha(read(rustc.resolve(strict=True))),
              "environment": {"removed": list(REMOVED_ENVIRONMENT), "removed_prefixes": ["HIA_"],
                              "RUSTC": str(rustc), "CARGO_TARGET_DIR": str(output / "target"), "offline": args.offline},
              "processes": [], "binaries": {}, "joins": [], "artifacts": {}}

    def save():
        result["elapsed_seconds"] = time.monotonic() - started
        (output / "result.json").write_bytes(encoded(result))

    def keep(path):
        raw = read(path)
        result["artifacts"][path.relative_to(output).as_posix()] = sha(raw)

    def run(name, command, cwd, limit, request=None):
        begin = time.monotonic()
        code, timed, start_error = None, False, None
        try:
            process = subprocess.run(list(map(str, command)), cwd=cwd, env=env, input=request,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=limit)
            out, err, code = process.stdout, process.stderr, process.returncode
        except subprocess.TimeoutExpired as error:
            out, err, timed = error.stdout or b"", error.stderr or b"", True
        except OSError as error:
            out, err, start_error = b"", b"", type(error).__name__ + ": " + str(error)
        for suffix, raw in (("stdout", out), ("stderr", err)):
            path = output / (name + "." + suffix)
            path.write_bytes(raw)
            keep(path)
        record = {"name": name, "command": list(map(str, command)), "cwd": str(cwd), "exit_code": code,
                  "timed_out": timed, "timeout_seconds": limit, "elapsed_seconds": time.monotonic() - begin,
                  "stdout_bytes": len(out), "stdout_sha256": sha(out), "stderr_bytes": len(err), "stderr_sha256": sha(err)}
        if start_error is not None:
            record["start_error"] = start_error
        if request is not None:
            record.update(input_bytes=len(request), input_sha256=sha(request))
        result["processes"].append(record)
        save()
        require(not timed and code == 0 and start_error is None, "actual reference process failed: " + name)
        return out, err

    save()
    try:
        project = output / "project"
        preparation = prepare_original_reference(root, project)
        for name in [*preparation["files"], "reference-inputs.json"]:
            keep(project / name)
        version, err = run("rustc-version", [rustc, "--version", "--verbose"], root, 10)
        require(not err and b"release: 1.95.0\n" in version, "original reference requires explicit Rust 1.95.0")
        command = [cargo, "build", "--release", "--locked", "--bins"] + (["--offline"] if args.offline else [])
        run("cargo-build", command, project, 120)
        result["fresh_actual_cargo_build"] = True
        for name in sorted({row[3] for row in REPLAYS}):
            binary = output / "target/release" / name
            raw = read(binary)
            result["binaries"][name] = {"path": str(binary), "bytes": len(raw), "sha256_before": sha(raw)}
            keep(binary)
        for replay in REPLAYS:
            name, domain, expected_name, binary, count = replay
            request = read(Path(bundle["reference_data"]) / domain / "requests.jsonl")
            out, err = run(name, [output / "target/release" / binary], project, 120, request)
            require(not err and out == read(Path(bundle["reference_data"]) / domain / expected_name),
                    "fresh original complete stdout differs: " + name)
            result["joins"].append(compare_replay_to_native(root, args.native_results, replay, out))
            result["cases"] += count
            result["actual_original_processes"] += 1
        check_project(project, preparation)
        for name, row in result["binaries"].items():
            row["sha256_after"] = sha(read(Path(row["path"])))
            require(row["sha256_after"] == row["sha256_before"], "reference binary changed during replay")
        require(checked_native_result(root, args.native_results) == native and source_pins(root) == pins,
                "native/source input changed during original execution")
        require(result["cases"] == 11789 and result["actual_original_processes"] == 6,
                "original domains incomplete")
        result["status"] = "PASS"
    except BaseException as error:
        result.update(status="FAIL", error=type(error).__name__ + ": " + str(error))
        raise
    finally:
        save()
        print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
