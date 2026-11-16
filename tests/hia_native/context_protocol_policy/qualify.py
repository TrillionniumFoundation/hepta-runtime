"""Isolated full recipe, plus a strictly read-only verification phase."""
from __future__ import annotations

import argparse
import gzip
import json
import os
from pathlib import Path
import shutil
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from cases import frame, versions
from common import BASE, document, encoded, packet, put, read, require, sha, source_evidence, tree_files
from reader import read_capture


def own_source(root, capture, source):
    for relative in list(source["files"]) + [BASE + "/source-pins.json"]:
        put(capture / "source" / relative, read(root / relative))


def qualification(output, pins_sha):
    capture = output / "capture"
    evidence = read_capture(capture, capture / "source", pins_sha)
    controls = document(output / "controls/report.json")
    from controls import NAMES, mutation_data
    require(controls["schema"] == "hepta.runtime.context-protocol-reader-controls.v1" and
            controls["base_capture_sha256"] == evidence["capture_sha256"] and controls["producer_unchanged"] is True and
            controls["restored_physical_copy_pass"] is True and controls["native_or_rust_executions"] == 0, "reader control domain")
    require(tuple(row["name"] for row in controls["rows"]) == NAMES, "reader refusal inventory")
    extra = {}
    for label, limit in (("reader-controls", 180), ("readonly-one", 60), ("readonly-two", 60)):
        record = document(output / "checks/processes" / (label + ".json"))
        require(record["label"] == label and record["started"] is True and record["returncode"] == 0 and
                type(record["returncode"]) is int and record["timed_out"] is False and record["timeout_seconds"] == limit and
                record["start_new_session"] is True and record["pgid"] == record["pid"], "actual reader process receipt")
        require(type(record["elapsed_ns"]) is int and 0 < record["elapsed_ns"] <= (limit + 1) * 1_000_000_000, "reader control process time")
        for key in ("stdout", "stderr"):
            member = "processes/" + label + "." + key
            raw = read(output / "checks" / member)
            require(record[key] == {"path": member, "bytes": len(raw), "sha256": sha(raw)}, "reader actual full logs")
        require(read(output / "checks/processes" / (label + ".stderr")) == b"", "reader emitted stderr")
        extra[label] = record
    require((controls["pid"], controls["ppid"], controls["pgid"]) ==
            tuple(extra["reader-controls"][key] for key in ("pid", "parent_pid", "pgid")), "actual control process attribution")
    for row, (name, relative, changed) in zip(controls["rows"], mutation_data(capture), strict=True):
        require(row["name"] == name and row["path"] == relative and row["base_capture_sha256"] == evidence["capture_sha256"], "exact reader mutation domain")
        require(row["original_sha256"] == sha(read(capture / relative)) and
                row["mutated_sha256"] == sha(changed) and row["mutated_bytes"] == len(changed) and
                read(output / "controls/mutations" / name / "bytes.bin") == changed, "complete retained mutation bytes")
        require(row["refusal_type"] in ("ValueError", "KeyError", "EOFError", "OSError", "JSONDecodeError") and
                type(row["refusal"]) is str and row["refusal"], "actual reader refusal missing")
        seal = document(capture / "CAPTURE.json")
        seal["files"][relative].update(bytes=len(changed), sha256=sha(changed))
        require(row["rebound_index_sha256"] == sha(encoded(seal)), "rebound mutation index differs")
    require(read(output / "checks/processes/reader-controls.stdout") == b"CONTEXT_PROTOCOL_READER_CONTROLS_PASS 16\n", "reader control actual stdout")
    read_reports = []
    expected_probes = ("python-file-write", "descriptor-open", "descriptor-write", "metadata-mode", "metadata-time",
                       "directory-create", "subprocess", "shell", "native-dlopen", "native-mmap", "producer-or-foreign-read")
    for label, folder in (("readonly-one", "relocated-one"), ("readonly-two", "relocated-two")):
        report = document(output / "checks/processes" / (label + ".stdout"))
        receipt = extra[label]
        require(report["schema"] == "hepta.runtime.context-protocol-readonly.v1" and
                (report["pid"], report["ppid"], report["pgid"]) == tuple(receipt[k] for k in ("pid", "parent_pid", "pgid")), "independent read-only process attribution")
        require(report["source_bound_guard"] is True and report["native_or_rust_executions"] == 0 and report["reader_writes"] == 0,
                "read-only execution scope")
        require(tuple(row["name"] for row in report["probes"]) == expected_probes and
                all(row["refusal"].startswith("context-protocol read-only guard: ") for row in report["probes"]), "read-only rejection coverage")
        require(report["before"] == report["after"] and report["evidence"] == evidence, "actual immutable relocated reader result")
        copy = output / folder
        require(read(copy / "CAPTURE.json") == read(capture / "CAPTURE.json"), "relocated source/capture index differs")
        require(read_capture(copy, copy / "source", pins_sha) == evidence, "complete relocated evidence differs")
        read_reports.append({"capture": folder, "pid": report["pid"], "guard_refusals": len(report["probes"]),
                             "snapshot_sha256": sha(encoded(report["before"]))})
    require(len({extra[name]["pid"] for name in extra}) == 3, "reader processes must be distinct")
    return {"schema": "hepta.runtime.context-protocol-final.v1", "status": "PASS", "evidence": evidence,
        "reader_refusals": len(controls["rows"]), "independent_readers": read_reports,
        "original_pending": False, "public_handler_qualified": False, "whole_runtime_replaced": False,
        "old_stack_removal_qualified": False, "production_activated": False}


def all_phases(root, hepta, output):
    from controls import copy_capture
    from execution import execute, reference_environment, registry_snapshot, seal
    source = source_evidence(root)
    pins_sha = source["pins_sha256"]
    output.mkdir(parents=True, exist_ok=False)
    capture = output / "capture"
    capture.mkdir()
    own_source(root, capture, source)
    native_env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="0")
    python = [sys.executable, "-I", "-S", "-B"]
    execute(capture, "native-build", python + [root / BASE / "build.py", "--source-root", root,
            "--hepta", hepta, "--capture", capture, "--source-pins-sha256", pins_sha], cwd=output, env=native_env)
    manifest = capture / "build/modules/context-protocol-policy/manifest.json"
    execute(capture, "native-replay", python + [root / BASE / "native.py", "--source-root", root,
            "--manifest", manifest, "--output", capture / "native", "--source-pins-sha256", pins_sha], cwd=output, env=native_env)
    with (capture / "semantic-input.bin").open("xb") as handle:
        for _, value in versions():
            handle.write(packet(frame(value)))
    # Build work stays outside the final evidence tree. It is newly created and
    # is never treated as an existing or cached original executable.
    work = output.parent / (output.name + "-fresh-original-work")
    work.mkdir(mode=0o700, exist_ok=False)
    oracle = work / "oracle"
    oracle.mkdir()
    workspace = {}
    for name in ("Cargo.toml", "Cargo.lock", "main.rs", "original_policy.rs"):
        raw = read(root / BASE / "oracle" / name)
        put(oracle / name, raw)
        workspace[name] = {"bytes": len(raw), "sha256": sha(raw)}
    env = reference_environment(work)
    cargo, rustc = shutil.which("cargo"), shutil.which("rustc")
    require(cargo and rustc, "Rust 1.95 tools must be explicitly installed by CI")
    execute(capture, "rustc-version", [rustc, "+1.95.0", "--version", "--verbose"], cwd=oracle, env=env)
    execute(capture, "cargo-version", [cargo, "+1.95.0", "--version"], cwd=oracle, env=env)
    execute(capture, "cargo-build", [cargo, "+1.95.0", "build", "--locked", "--bin", "g5-target-context-oracle"], cwd=oracle, env=env)
    binary_path = work / "cargo-target/debug/g5-target-context-oracle"
    binary = read(binary_path)
    put(capture / "original/oracle.bin", binary)
    for name in workspace:
        raw = read(oracle / name)
        require(raw == read(root / BASE / "oracle" / name), "fresh original workspace source changed")
        put(capture / "original/workspace" / name, raw)
    execute(capture, "cargo-metadata", [cargo, "+1.95.0", "metadata", "--locked", "--format-version", "1"], cwd=oracle, env=env)
    metadata = document(capture / "processes/cargo-metadata.stdout")
    registry_snapshot(capture, metadata, read(oracle / "Cargo.lock"), Path(env["CARGO_HOME"]))
    execute(capture, "original-replay", [binary_path], cwd=oracle, env=env, stdin=capture / "semantic-input.bin")
    require(read(binary_path) == binary, "actual original executable changed during replay")
    put(capture / "original-build.json", {"schema": "hepta.runtime.context-protocol-original-build.v1",
        "fresh_build": True, "locked": True, "binary_sha256": sha(binary), "binary_bytes": len(binary),
        "binary_after_replay_sha256": sha(read(binary_path)), "workspace_sources": workspace,
        "original_function_substitution": False, "actual_request_context": True})
    source_evidence(root, pins_sha)
    seal(capture, pins_sha)
    evidence = read_capture(capture, capture / "source", pins_sha)
    checks = output / "checks"
    checks.mkdir()
    execute(checks, "reader-controls", python + [root / BASE / "controls.py", "--capture", capture,
            "--output", output / "controls", "--source-pins-sha256", pins_sha], cwd=output, env=native_env)
    for label, name in (("readonly-one", "relocated-one"), ("readonly-two", "relocated-two")):
        copy = output / name
        copy_capture(capture, copy)
        execute(checks, label, python + [copy / "source" / BASE / "verify_readonly.py", "--capture", copy,
                "--source-root", copy / "source", "--source-pins-sha256", pins_sha,
                "--foreign-path", capture / "CAPTURE.json"], cwd=output, env=native_env)
    result = qualification(output, pins_sha)
    put(output / "QUALIFICATION.json", result)
    print(encoded(result).decode(), end="")


def verify(root, output):
    # This phase never imports execution.py, creates reports, launches processes
    # or maps native images. It compares the already published final report.
    source = source_evidence(root)
    import controls  # Preload only data-reader definitions before write guards.
    from verify_readonly import guarded
    expected = read(output / "QUALIFICATION.json")
    pins_sha = source["pins_sha256"]
    result = guarded(lambda: qualification(output, pins_sha), roots=[output],
                     foreign_path=output.parent / "outside-the-capture")
    require(encoded(result["evidence"]) == expected, "existing final qualification report differs")
    print(encoded({"status": "READ_ONLY_VERIFY_PASS", "source_pins_sha256": pins_sha,
                  "qualification_sha256": sha(expected), "guard_refusals": len(result["probes"]),
                  "tree_entries": len(result["before"]), "complete_tree_unchanged": True,
                  "native_or_rust_executions": 0, "reader_writes": 0}).decode(), end="")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("all", "verify", "source"), required=True)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--hepta", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = args.source_root.resolve()
    if args.phase == "source":
        print(encoded(source_evidence(root)).decode(), end="")
    elif args.phase == "verify":
        require(args.output is not None, "verification output path required")
        verify(root, args.output.absolute())
    else:
        require(args.output is not None and args.hepta is not None, "complete recipe paths required")
        all_phases(root, args.hepta.resolve(), args.output.absolute())
