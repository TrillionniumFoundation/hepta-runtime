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


def original_native_reads(pins, job, streams):
    binding.need(isinstance(pins, list) and 1 <= len(pins) <= 2048,
                 "complete original native read-page bindings required")
    offsets = {name: 0 for name in streams}
    for pin in pins:
        value = json.loads(binding.bound_file(pin))
        binding.need(value.get("job_id") == job, "native read page belongs to another job")
        for name, raw in streams.items():
            row = value[name]
            binding.need(type(row.get("offset")) is int and row["offset"] == offsets[name]
                         and type(row.get("size")) is int and row["size"] == len(raw)
                         and isinstance(row.get("bytes_hex"), str), "native read offsets/total differ")
            block = bytes.fromhex(row["bytes_hex"])
            end = offsets[name] + len(block)
            binding.need(end <= len(raw) and row.get("next_offset") == end
                         and row.get("eof") is (end == len(raw))
                         and raw[offsets[name]:end] == block, "original native read is not the exact Cargo stream")
            offsets[name] = end
    binding.need(all(offsets[name] == len(raw) for name, raw in streams.items()),
                 "original native read pages are incomplete")


def recorded_call(call, stage, root, arm, name, expected, environment, clock, plan_raw, prep_raw, graph_pin):
    binding.need(call.get("schema") == "hepta-r34-capacity-recorded-build-invocation/v1"
                 and call.get("passed") is True and call.get("arm") == arm and call.get("stage") == name
                 and call.get("command") == expected and call.get("cwd") == str(root / "arms" / arm)
                 and call.get("environment") == environment and type(call.get("automatic_retries")) is int
                 and call["automatic_retries"] == 0 and call.get("clock") == clock
                 and isinstance(call.get("job_id"), str) and call.get("cargo_started") is True
                 and call.get("errors") == [] and call.get("interrupts") == [], "original producer invocation did not close")
    output = root / "build-stages" / (arm + "-" + name)
    binding.need(stage["invocation"]["path"] == str(output / "invocation.json"), "producer invocation path differs")
    for key, filename in (("input", "input.json"), ("native_request", "native-request.json"),
                          ("native_child", "native-child.json"), ("native_launch", "native-launch.json"),
                          ("native_cgroup", "native-cgroup.txt")):
        binding.need(call[key]["path"] == str(output / filename), "producer original path differs")
    request = json.loads(binding.bound_file(call["native_request"]))
    child = json.loads(binding.bound_file(call["native_child"]))
    launch = json.loads(binding.bound_file(call["native_launch"]))
    cgroup = binding.bound_file(call["native_cgroup"])
    supplied = json.loads(binding.bound_file(call["input"]))
    programs = call.get("programs")
    binding.need(isinstance(programs, dict)
                 and set(programs) == {"record_build_invocation.py", "prepare_build.py", "seal_arm.py"},
                 "frozen producer program inventory differs")
    for filename, pin in programs.items():
        binding.need(pin["path"] == str(Path(__file__).absolute().with_name(filename)), "frozen producer program path differs")
        binding.bound_file(pin)
    binding.need(supplied.get("schema") == "hepta-r34-capacity-build-stage-input/v1"
                 and supplied.get("status") == "sealed_actual_inputs"
                 and supplied.get("prepared_root") == str(root) and supplied.get("arm") == arm
                 and supplied.get("stage") == name and supplied.get("programs") == programs
                 and supplied.get("graph_receipt") == call.get("graph_receipt") == graph_pin,
                 "actual producer stage input differs")
    support = supplied.get("support_environment")
    binding.need(isinstance(support, dict) and set(support) == {"HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN"}
                 and all(isinstance(value, str) and value for value in support.values())
                 and call.get("effective_environment") == {**environment, **support}, "effective Cargo environment differs")
    own = call["producer_identity"]
    binding.need(type(own.get("pid")) is int and type(own.get("start_ticks")) is int
                 and child == {"pid": own["pid"], "identity": {"kind": "proc_start_ticks",
                     "value": clock["boot_id"] + ":" + str(own["start_ticks"])}}
                 and request.get("job_id") == call["job_id"]
                 and request.get("job_dir") == str(Path(supplied["native_jobs_root"]) / call["job_id"])
                 and request.get("launch_nonce") == call.get("launch_nonce")
                 and re.fullmatch(r"[0-9a-f]{32}", call.get("launch_nonce", "")) is not None
                 and request.get("request_fingerprint") == call.get("request_fingerprint")
                 and request.get("cwd") == call["cwd"] and request.get("env") in (None, {})
                 and not request.get("stdin_path") and request.get("terminal_publication_protocol") == 1
                 and request.get("executable") == "/usr/bin/python3"
                 and request.get("args") == ["-B", programs["record_build_invocation.py"]["path"],
                                             "--input", supplied_input_path(call, supplied)],
                 "actual native request/child/nonce does not bind this producer")
    binding.need(call.get("native_backend") == launch.get("backend") in ("systemd", "detached")
                 and launch.get("unit") == request.get("unit") == call.get("native_unit"), "native backend/unit differs")
    if call["native_backend"] == "systemd":
        unit = request["unit"] if request["unit"].endswith(".service") else request["unit"] + ".service"
        binding.need(call.get("original_systemd_cgroup_containment") is True
                     and any(parts[:2] == ["0", ""] and Path(parts[2]).name == unit
                             for parts in (line.split(":", 2) for line in cgroup.decode("ascii").splitlines()) if len(parts) == 3),
                     "native systemd membership differs")
    else:
        binding.need(call.get("original_systemd_cgroup_containment") is False, "detached invocation cannot claim systemd custody")
    cleanup = call.get("cleanup", {})
    binding.need(cleanup.get("closed") is True and cleanup.get("actual_waitpid") is True
                 and type(cleanup.get("returncode")) is int and cleanup["returncode"] == 0
                 and cleanup.get("timed_out") is False and cleanup.get("errors") == []
                 and cleanup.get("owned_process_absent") is True and cleanup.get("owned_group_absent") is True
                 and cleanup.get("adopted_children_absent") is True
                 and cleanup.get("parent_death_signal") == "SIGKILL"
                 and cleanup.get("original_native_cgroup_sha256") == binding.sha(cgroup), "original Cargo wait/custody is incomplete")
    binding.need(call["cargo_child"]["path"] == str(output / "cargo-child.json")
                 and json.loads(binding.bound_file(call["cargo_child"])) == cleanup["identity"], "original Cargo birth receipt differs")
    binding.need(call["invocation_intent"]["path"] == str(output / "invocation-intent.json"), "original pre-Cargo intent path differs")
    intent = json.loads(binding.bound_file(call["invocation_intent"]))
    binding.need(intent.get("passed") is False and intent.get("cargo_started") is False
                 and intent.get("cleanup") is None and intent.get("errors") == []
                 and all(intent.get(key) == call.get(key) for key in ("schema", "arm", "stage", "command", "cwd",
                         "environment", "effective_environment", "clock", "job_id", "launch_nonce", "programs", "plan",
                         "preparation", "producer_identity", "submitted_monotonic_ns", "native_request", "native_child",
                         "native_launch", "native_cgroup", "original_input_path")), "pre-Cargo intent/final invocation differs")
    binding.need(call.get("plan") == {"path": str(root / "input.json"), "bytes": len(plan_raw), "sha256": binding.sha(plan_raw)}
                 and call.get("preparation") == {"path": str(root / "preparation.json"), "bytes": len(prep_raw), "sha256": binding.sha(prep_raw)},
                 "producer preparation binding differs")
    from record_build_invocation import context_unchanged
    context_unchanged(call["configuration_inventory"], call["toolchain_executables"])
    native = terminal(binding.bound_file(stage["native_terminal"]), call["job_id"])
    binding.need(native.get("launch_nonce") == call["launch_nonce"] and native.get("terminal_publication_protocol") == 1,
                 "original native terminal nonce differs")
    streams = {}
    for stream in ("stdout", "stderr"):
        raw = binding.bound_file(stage[stream], 32 * 1024 * 1024)
        pin = call["streams"][stream]
        binding.need(pin["path"] == str(output / (stream + ".log"))
                     and pin["bytes"] == pin.get("forwarded_bytes") == len(raw) and pin["sha256"] == binding.sha(raw)
                     and binding.regular(Path(pin["path"]), 32 * 1024 * 1024) == raw
                     and native["log_bytes"][stream] == {"seen": len(raw), "stored": len(raw)}, "native/Cargo log differs")
        streams[stream] = raw
    original_native_reads(stage.get("native_reads"), call["job_id"], streams)
    return call["effective_environment"]


def supplied_input_path(call, supplied):
    # input.json is the exact create-only copy; the original request must name
    # the original sealed input, whose identity is also retained in the intent.
    path = call.get("original_input_path")
    binding.need(isinstance(path, str) and Path(path).is_absolute(), "original stage input path missing")
    binding.need(binding.regular(Path(path)) == binding.bound_file(call["input"]), "original stage input changed")
    return path


def seal_locked(input_path):
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
    stage_evidence, intervals, effective_environment, jobs = {}, [], None, set()
    toolchain_executables, configuration_inventory = None, None
    for name, expected in commands.items():
        stage = supplied["stages"][name]
        call_raw = binding.bound_file(stage["invocation"])
        call = json.loads(call_raw)
        actual_environment = recorded_call(call, stage, root, arm, name, expected, environment,
                                           clock, plan_raw, prep_raw, supplied["graph_receipt"])
        binding.need(effective_environment is None or actual_environment == effective_environment,
                     "effective build environment changed between stages")
        effective_environment = actual_environment
        binding.need(toolchain_executables is None or call["toolchain_executables"] == toolchain_executables,
                     "toolchain executable identity changed between stages")
        binding.need(configuration_inventory is None or call["configuration_inventory"] == configuration_inventory,
                     "effective build configuration changed between stages")
        toolchain_executables, configuration_inventory = call["toolchain_executables"], call["configuration_inventory"]
        binding.need(call["job_id"] not in jobs, "native job reused for different Cargo stages")
        jobs.add(call["job_id"])
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
                     and previous.get("effective_environment") == effective_environment
                     and previous.get("toolchain_executables") == toolchain_executables
                     and previous.get("graph_receipt") == supplied["graph_receipt"]
                     and previous["binary_preserved_monotonic_ns"] < intervals[0][0],
                     "A ELF must be actually preserved before B starts using the shared target")
        binding.bound_file(previous["binary"], 128 * 1024 * 1024)
        previous_binding = {"path": str(root / "artifacts/A/build-report.json"), "bytes": len(previous_raw),
                            "sha256": binding.sha(previous_raw)}
    else:
        binding.need(not os.path.lexists(root / "artifacts/B")
                     and not any(os.path.lexists(root / "build-stages" / ("B-" + name)) for name in commands),
                     "A cannot be sealed after any B build or artifact attempt")
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
              "effective_environment": effective_environment,
              "toolchain_executables": toolchain_executables,
              "configuration_inventory": configuration_inventory,
              "clock": clock,
              "first_build_submitted_monotonic_ns": intervals[0][0],
              "last_build_completed_monotonic_ns": intervals[-1][1], "binary_preserved_monotonic_ns": preserved,
              "binary": binary, "baseline_arm_report": previous_binding, "pair_closed": arm == "B",
              "shared_target": str(root / "target-component"), "compiler_invoked_by_this_sealer": False,
              "component_executed": False, "capacity_established": False, "candidate_adopted": False}
    binding.create(output / "seal-input.json", seal_raw)
    binding.create(output / "build-report.json", binding.encoded(report))
    from record_build_invocation import sync_dir
    sync_dir(output)
    sync_dir(output.parent)
    return report


def seal(input_path):
    # Producer and sealer share one lock, so ELF copying cannot race a build.
    from record_build_invocation import build_lock
    supplied = json.loads(binding.regular(input_path))
    binding.need(supplied.get("status") == "sealed_actual_receipts", "arm sealing input remains unsealed")
    with build_lock(Path(supplied["prepared_root"])):
        return seal_locked(input_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    report = seal(args.input)
    print(json.dumps({"passed": True, "arm": report["arm"], "binary": report["binary"], "capacity_established": False}, sort_keys=True))


if __name__ == "__main__":
    main()
