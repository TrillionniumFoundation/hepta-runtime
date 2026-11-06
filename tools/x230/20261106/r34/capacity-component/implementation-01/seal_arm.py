#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Retain one actual component ELF after original completed build receipts.

No compiler, subprocess, network or component execution. Call for A before the
shared target may be used for B. Missing/future receipts refuse before writes.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import time
import tomllib

import prepare_build as binding


def local_clock_identity():
    binding.need(sys.platform == "linux" and hasattr(time, "CLOCK_MONOTONIC"),
                 "arm sealing requires the build host's Linux monotonic clock")
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    binding.need(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id) is not None,
                 "actual Linux boot identity required")
    return {"kind": "linux:CLOCK_MONOTONIC", "boot_id": boot_id}


def expected_commands(plan, root, arm):
    manifest = str(root / "arms" / arm / "Cargo.toml")
    cargo = plan["cargo"]
    common = ["--manifest-path", manifest, "--bin", "hepta-direct-capacity-component",
              "--target", plan["target_triple"], "--jobs", "1"]
    return {
        "fmt-check": [cargo, "fmt", "--manifest-path", manifest, "--package", "hepta-direct-capacity-component", "--", "--check"],
        "clippy-release": [cargo, "clippy", "--offline", "--locked", "--release", *common, "--", "-D", "warnings"],
        "release": [cargo, "build", "--offline", "--locked", "--release", *common],
    }


def expected_environment(plan, root):
    return {"PATH": str(Path(plan["cargo"]).parent) + ":/usr/local/bin:/usr/bin:/bin",
            "RUSTC": plan["rustc"], "CARGO_HOME": plan["cargo_home"], "CARGO_TARGET_DIR": str(root / "target-component"),
            "CARGO_BUILD_JOBS": "1", "CARGO_NET_OFFLINE": "true", "CARGO_INCREMENTAL": "0"}


def terminal(raw, job):
    value = json.loads(raw)
    binding.need(value.get("job_id") == job and value.get("state") == "succeeded"
                 and type(value.get("exit_code")) is int and value["exit_code"] == 0
                 and value.get("terminal_publication_confirmed") is True
                 and value.get("automatic_retry") is False
                 and value.get("output_complete") is True and value.get("output_durable") is True
                 and value.get("timed_out") is False and value.get("cancelled") is False
                 and value.get("log_synced") == {"stdout": True, "stderr": True}
                 and value.get("log_errors") == {"stdout": None, "stderr": None}
                 and value.get("log_truncated") == {"stdout": False, "stderr": False},
                 "original complete successful build-stage native terminal required")
    return value


def seal(input_path):
    seal_raw = binding.regular(input_path)
    supplied = json.loads(seal_raw)
    binding.need(supplied.get("schema") == "hepta-r34-capacity-arm-seal-input/v1"
                 and supplied.get("status") == "sealed_actual_receipts" and supplied.get("arm") in ("A", "B"),
                 "component build receipt inputs remain unsealed")
    root = Path(supplied["prepared_root"])
    arm = supplied["arm"]
    prep_raw = binding.regular(root / "preparation.json")
    prep = json.loads(prep_raw)
    plan_raw = binding.regular(root / "input.json")
    plan = json.loads(plan_raw)
    binding.need(prep["plan_sha256"] == binding.sha(plan_raw), "prepared build input changed")
    graph_raw = binding.bound_file(supplied["graph_receipt"])
    graph = json.loads(graph_raw)
    binding.need(graph.get("schema") == "hepta-r34-capacity-component-graphs/v1" and graph.get("passed") is True
                 and graph.get("plan_sha256") == binding.sha(plan_raw)
                 and graph.get("preparation", {}).get("sha256") == binding.sha(prep_raw), "actual closed component graph receipt differs")
    runtime = plan["arms"][arm]
    binding.full_map(runtime["source_root"], runtime["compile_inputs"])
    binding.full_map(runtime["source_root"], runtime["include_inputs"])
    qualification = binding.qualified_arm(arm, runtime)
    lock_raw = binding.bound_file(graph["locks"][arm])
    binding.need(graph["locks"][arm]["path"] == str(root / "arms" / arm / "Cargo.lock"), "actual component lock path differs")
    sources = {}
    for name, expected in prep["files"].items():
        if not name.startswith("arms/" + arm + "/") or name.endswith("/Cargo.lock"):
            continue
        raw = binding.regular(root / name)
        binding.need(len(raw) == expected["bytes"] and binding.sha(raw) == expected["sha256"], "prepared component source changed")
        sources[name] = expected
    manifest_raw = binding.regular(root / "arms" / arm / "Cargo.toml")
    binding.need(tomllib.loads(manifest_raw.decode())["profile"]["release"] == binding.PROFILE, "effective root release declaration differs")
    commands = expected_commands(plan, root, arm)
    environment = expected_environment(plan, root)
    clock = local_clock_identity()
    binding.need(set(supplied["stages"]) == set(commands), "actual build stage inventory differs")
    stage_evidence, intervals = {}, []
    for name, expected in commands.items():
        stage = supplied["stages"][name]
        call_raw = binding.bound_file(stage["invocation"])
        call = json.loads(call_raw)
        binding.need(call.get("schema") == "hepta-r34-capacity-recorded-build-invocation/v1"
                     and call.get("command") == expected and call.get("cwd") == str(root / "arms" / arm)
                     and call.get("environment") == environment and call.get("automatic_retries") == 0
                     and call.get("clock") == clock
                     and isinstance(call.get("job_id"), str), "original recorded build invocation differs")
        # The original invocation envelope is the caller's retained actual submission,
        # not a claim that process_status itself echoes argv or environment.
        native = terminal(binding.bound_file(stage["native_terminal"]), call["job_id"])
        for stream in ("stdout", "stderr"):
            raw = binding.bound_file(stage[stream], 32 * 1024 * 1024)
            binding.need(native["log_bytes"][stream] == {"seen": len(raw), "stored": len(raw)}, "native build log is not complete")
        begin, end = call.get("submitted_monotonic_ns"), call.get("completed_monotonic_ns")
        binding.need(type(begin) is int and type(end) is int and 0 <= begin < end, "actual local build interval required")
        intervals.append((begin, end))
        stage_evidence[name] = stage
    binding.need(all(left[1] <= right[0] for left, right in zip(intervals, intervals[1:])), "component build stages overlapped")
    output = root / "artifacts" / arm
    previous_binding = None
    if arm == "B":
        previous_raw = binding.regular(root / "artifacts/A/build-report.json")
        previous = json.loads(previous_raw)
        binding.need(previous["schema"] == "hepta-r34-capacity-component-arm-build/v1" and previous["passed"] is True
                     and previous["arm"] == "A" and previous["plan_sha256"] == binding.sha(plan_raw)
                     and previous.get("clock") == clock
                     and previous["binary_preserved_monotonic_ns"] < intervals[0][0],
                     "A ELF must be actually preserved before B starts using the shared target")
        binding.bound_file(previous["binary"], 128 * 1024 * 1024)
        previous_binding = {"path": str(root / "artifacts/A/build-report.json"), "bytes": len(previous_raw),
                            "sha256": binding.sha(previous_raw)}
    else:
        binding.need(not os.path.lexists(root / "artifacts/B"), "A cannot be sealed after a B artifact attempt")
    binary_source = root / "target-component" / plan["target_triple"] / "release/hepta-direct-capacity-component"
    body = binding.regular(binary_source, 128 * 1024 * 1024)
    binding.need(body.startswith(b"\x7fELF") and not os.path.lexists(output), "actual ELF and create-only arm artifact required")
    (root / "artifacts").mkdir(exist_ok=True, mode=0o700)
    output.mkdir(mode=0o700)
    destination = output / "hepta-direct-capacity-component"
    binding.create(destination, body, 0o700)
    directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    preserved = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    binding.need(intervals[-1][1] <= preserved, "build receipt contains a future or foreign-clock completion")
    binary = {"path": str(destination), "bytes": len(body), "sha256": binding.sha(body)}
    report = {"schema": "hepta-r34-capacity-component-arm-build/v1", "passed": True, "arm": arm,
              "plan_sha256": binding.sha(plan_raw), "arm_seal_input_sha256": binding.sha(seal_raw),
              "component_source_manifest": plan["component_source_manifest"],
              "graph_receipt": supplied["graph_receipt"], "qualification": qualification,
              "runtime_compile_inputs": runtime["compile_inputs"], "runtime_include_inputs": runtime["include_inputs"],
              "component_sources": sources, "cargo_manifest_sha256": binding.sha(manifest_raw),
              "cargo_lock_sha256": binding.sha(lock_raw), "release_profile": binding.PROFILE,
              "command_environment": environment, "stages": stage_evidence,
              "clock": clock,
              "first_build_submitted_monotonic_ns": intervals[0][0],
              "last_build_completed_monotonic_ns": intervals[-1][1], "binary_preserved_monotonic_ns": preserved,
              "binary": binary, "baseline_arm_report": previous_binding, "pair_closed": arm == "B",
              "shared_target": str(root / "target-component"), "compiler_invoked_by_this_sealer": False,
              "component_executed": False, "capacity_established": False, "candidate_adopted": False}
    binding.create(output / "seal-input.json", seal_raw)
    binding.create(output / "build-report.json", binding.encoded(report))
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    report = seal(args.input)
    print(json.dumps({"passed": True, "arm": report["arm"], "binary": report["binary"], "capacity_established": False}, sort_keys=True))


if __name__ == "__main__":
    main()
