#!/usr/bin/env python3
"""Fresh current original and complete rebuilt Batch private-core qualification."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from receipt_support import ROOT, PIN, SHA, require, regular, read_json, put, process, check_process
import source_check
import read_builds
import read_typed
import read_files
from qualify_typed import load_inputs
from corpus.batch_params_cases import sdk_cases, encode

TARGET = "d3d75c30719db966b004756f610007a7c723729e"
NAMES = ("target-identity", "target-prefetch", "original-build", "adapter-build", "body-build",
         "fixture-build", "typed-native", "typed-original", "body-pair", "evidence-controls")
TIMEOUTS = {name: 180 for name in NAMES}
TIMEOUTS.update({"adapter-build": 300, "body-pair": 380})


def command_tails(producer, source, hepta, target, rust_bin):
    producer, source = Path(producer), Path(source)
    return {
        "original-build": [str(source / "build_reference.py"), "--rust-bin", rust_bin, "--output", str(producer / "original")],
        "adapter-build": [str(source / "build_adapters.py"), "--hepta", hepta, "--output", str(producer / "build/adapters")],
        "body-build": [str(source / "build_body_graph.py"), "--hepta", hepta, "--bootstrap", str(producer / "build/adapters/bootstrap"),
            "--output", str(producer / "build/body")],
        "fixture-build": [str(source / "build_fixture.py"), "--hepta", hepta, "--bootstrap", str(producer / "build/body/bootstrap"),
            "--body-build", str(producer / "build/body"), "--output", str(producer / "build/fixture")],
        "typed-native": [str(source / "qualify_typed.py"), "--build", str(producer / "build/adapters"), "--output", str(producer / "typed")],
        "body-pair": [str(source / "run_body_pair.py"), "--native", str(producer / "build/fixture/local-batch-body.elf"),
            "--original", str(producer / "original/bin/hepta-batch-body-original-oracle"), "--output", str(producer / "body")],
        "evidence-controls": [str(source / "check_evidence.py"), "--output", str(producer)],
    }


def core(output, *, require_final=True):
    output = Path(output).absolute()
    report = read_json(output / "result.json")
    require(report["schema"] == "hepta.runtime.rebuilt-batch-private-recipe.v1" and report["target_commit"] == TARGET,
            "recipe identity")
    require(report["status"] == "PASS" if require_final else report["status"] in ("VERIFYING", "PASS"),
            "recipe did not complete its actual domains")
    require(report["fresh_original_build"] is True and report["new_version_not_lost_private91"] is True
        and report["lost_private91_evidence_reused"] is False, "fresh/new evidence identity")
    for key in ("public_batch_qualified", "gateway_caller_qualified", "full_async_cancellation_qualified",
                "remote_sftp_qualified", "whole_runtime_replaced"):
        require(report[key] is False, "private qualification scope inflated")
    profile = source_check.check(output / "source")
    require(profile == source_check.check(ROOT) and PIN(regular(output / "source/source-profile.json")) == report["source_profile"],
            "executed exact source snapshot")
    require(report["process_names"] == list(NAMES), "recipe fixed process inventory")
    producer = Path(report["producer_root"])
    source = producer / "source"
    commands = command_tails(producer, source, report["hepta_root"], report["target_root"], report["rust_bin"])
    records = {}
    for name in NAMES[:-1]:
        row, streams = check_process(output / "processes", name, timeout=TIMEOUTS[name])
        if name in commands:
            require(row["argv"] == [report["python"], "-B", *commands[name]], "complete process argv: " + name)
            require(row["cwd"] == str(producer), "recipe process cwd")
        elif name == "target-identity":
            require(row["argv"] == ["git", "-C", report["target_root"], "rev-parse", "HEAD"]
                and row["cwd"] == str(producer) and streams["stdout"] == (TARGET + "\n").encode(), "independent original Git commit")
        elif name == "target-prefetch":
            require(row["argv"] == [str(Path(report["rust_bin"]) / "cargo"), "fetch", "--locked"]
                and row["cwd"] == report["target_root"], "target-only exact locked prefetch")
        else:
            require(name == "typed-original" and row["argv"] == [str(producer / "original/bin/hepta-batch-params-original-oracle")]
                and row["cwd"] == str(producer), "actual typed original binary")
        require(row["controlled_env"] == {"PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C", "PYTHONPATH": ""},
                "recipe controlled process environment")
        if name != "typed-original":
            require(streams["stdin"] == b"", "unexpected recipe input")
        records[name] = (row, streams)
    original = read_builds.original(output / "original")
    native = read_builds.native(output / "build/adapters", output / "build/body", output / "build/fixture")
    summaries = {
        "original-build": ("original/BUILD.json", ("status", "fresh_original_build", "binaries",
            "actual_target_sdk", "actual_target_tokio", "actual_reference_executions")),
        "adapter-build": ("build/adapters/BUILD.json", None),
        "body-build": ("build/body/BUILD.json", ("status", "fresh_native_compilations", "elapsed_seconds", "boundary")),
        "fixture-build": ("build/fixture/BUILD.json", ("status", "artifacts", "elapsed_seconds")),
    }
    for name, (relative, keys) in summaries.items():
        actual = read_json(output / relative)
        expected = actual if keys is None else {key: actual[key] for key in keys}
        require(json.loads(records[name][1]["stdout"]) == expected and records[name][1]["stderr"] == b"",
                "actual complete build-runner output: " + name)
    inputs = encode(load_inputs() + list(sdk_cases()))
    require(records["typed-original"][1]["stdin"] == inputs and records["typed-original"][1]["stderr"] == b"", "complete current typed input/replay")
    typed = read_typed.read(output / "typed", original_stdout=records["typed-original"][1]["stdout"])
    typed_report = read_json(output / "typed/result.json")
    require(typed_report["source_root"] == str(source) and typed_report["build_root"] == str(producer / "build/adapters")
            and typed_report["output_root"] == str(producer / "typed"), "typed capture execution roots")
    a = read_json(output / "build/adapters/BUILD.json")
    expected_artifacts = {"BUILD.json": PIN(regular(output / "build/adapters/BUILD.json"))}
    for name in ("value", "batch_params_original", "batch_params"):
        mpath = Path(a["modules"][name]["manifest"])
        metadata = read_json(output / "build/adapters" / mpath)
        for relative in (mpath, mpath.parent / metadata["image"], mpath.parent / metadata["source"]):
            expected_artifacts[str(relative)] = PIN(regular(output / "build/adapters" / relative))
    require(typed_report["build_artifacts"] == expected_artifacts, "executed typed modules do not match actual fresh build")
    require(json.loads(records["typed-native"][1]["stdout"]) == read_json(output / "typed/result.json")
            and records["typed-native"][1]["stderr"] == b"", "typed actual runner output")
    body_report = read_json(output / "body/result.json")
    require(body_report["schema"] == "hepta.runtime.rebuilt-batch-body-pair.v1" and body_report["status"] == "PASS"
            and body_report["cases_per_side"] == 926 and body_report["process_names"] == ["native", "original"], "two complete body sessions")
    body = read_files.compare(output / "body/native", output / "body/original")
    require(read_json(output / "body/complete-comparison.json") == body == body_report["comparison"]
            and body_report["comparison_pin"] == PIN(regular(output / "body/complete-comparison.json")), "complete body comparison receipt")
    require(json.loads(records["body-pair"][1]["stdout"]) == {"status": "PASS", "comparison": body}
            and records["body-pair"][1]["stderr"] == b"", "body actual runner completion")
    for lane, binary in (("native", producer / "build/fixture/local-batch-body.elf"),
                         ("original", producer / "original/bin/hepta-batch-body-original-oracle")):
        row, streams = check_process(output / "body/processes", lane)
        expected = [report["python"], "-B", str(source / "run_file_lane.py"), "--binary", str(binary),
                    "--fixture", str(producer / "body/fixture-shared"), "--output", str(producer / "body" / lane)]
        require(row["argv"] == expected and row["cwd"] == str(source) and streams["stdin"] == b"" and streams["stderr"] == b"",
                "complete body lane process custody")
        capture = read_json(output / "body" / lane / "result.json")
        require(capture == json.loads(streams["stdout"]) and capture["process_group"] == row["process_group"], "actual body process and complete capture")
        expected_binary = native["fixed_elf"] if lane == "native" else original["binaries"]["hepta-batch-body-original-oracle"]
        require({"bytes": capture["binary_bytes"], "sha256": capture["binary_sha256"]}
                == {key: expected_binary[key] for key in ("bytes", "sha256")}, "body executed another binary")
        read_files.check_retired(output / "body" / lane)
    return {"schema": "hepta.runtime.rebuilt-batch-private-readonly.v1", "status": "PASS",
        "fresh_original_build": True, "target_commit": TARGET, "native_build": native, "original_build": original,
        "typed": typed, "body": body, "source_files": len(profile["files"]), "reader_process_launches": 0,
        "public_batch_qualified": False, "gateway_caller_qualified": False, "full_async_cancellation_qualified": False,
        "remote_sftp_qualified": False, "whole_runtime_replaced": False}


def verify(output):
    result = core(output)
    output = Path(output)
    report = read_json(output / "result.json")
    producer = Path(report["producer_root"])
    row, streams = check_process(output / "processes", "evidence-controls")
    require(row["argv"] == [report["python"], "-B", str(producer / "source/check_evidence.py"), "--output", str(producer)]
            and row["cwd"] == str(producer) and streams["stdin"] == streams["stderr"] == b"", "evidence-control process")
    from check_evidence import verify as verify_controls
    controls = verify_controls(output)
    require(controls["status"] == "PASS" and controls["actual_owner_processes"] == 0
            and json.loads(streams["stdout"]) == controls, "actual evidence refusal runner")
    result["evidence_controls"] = controls
    return result


def run(hepta, target, rust_bin, output):
    require(os.environ.get("GITHUB_ACTIONS") == "true", "fresh target reference recipe is CI-only")
    output, hepta, target, rust_bin = Path(output).absolute(), Path(hepta).resolve(strict=True), Path(target).resolve(strict=True), Path(rust_bin).resolve(strict=True)
    source_check.check(ROOT)
    output.mkdir(parents=True, exist_ok=False)
    source_check.snapshot(ROOT, output / "source")
    target_sources = read_json(ROOT / "reference/target-source.json")
    for name, expected in target_sources["files"].items():
        require(PIN(regular(target / name)) == {k: expected[k] for k in ("bytes", "sha256")}, "independent target source differs")
    report = {"schema": "hepta.runtime.rebuilt-batch-private-recipe.v1", "status": "RUNNING",
        "producer_root": str(output), "python": sys.executable, "hepta_root": str(hepta), "target_root": str(target),
        "rust_bin": str(rust_bin), "target_commit": TARGET, "source_profile": PIN(regular(ROOT / "source-profile.json")),
        "process_names": list(NAMES), "fresh_original_build": False, "new_version_not_lost_private91": True,
        "lost_private91_evidence_reused": False, "public_batch_qualified": False, "gateway_caller_qualified": False,
        "full_async_cancellation_qualified": False, "remote_sftp_qualified": False, "whole_runtime_replaced": False}
    put(output / "result.json", report)
    commands = command_tails(output, output / "source", str(hepta), str(target), str(rust_bin))
    environment = {"PYTHONPATH": ""}
    try:
        process(output / "processes", "target-identity", ["git", "-C", str(target), "rev-parse", "HEAD"], cwd=output, env=environment)
        process(output / "processes", "target-prefetch", [rust_bin / "cargo", "fetch", "--locked"], cwd=target, env=environment)
        for name in ("original-build", "adapter-build", "body-build", "fixture-build", "typed-native"):
            process(output / "processes", name, [sys.executable, "-B", *commands[name]], cwd=output, env=environment, timeout=TIMEOUTS[name])
        process(output / "processes", "typed-original", [output / "original/bin/hepta-batch-params-original-oracle"],
            cwd=output, stdin=encode(load_inputs() + list(sdk_cases())), env=environment)
        process(output / "processes", "body-pair", [sys.executable, "-B", *commands["body-pair"]],
            cwd=output, env=environment, timeout=TIMEOUTS["body-pair"])
        report.update(status="VERIFYING", fresh_original_build=True)
        put(output / "result.json", report)
        checked = core(output, require_final=False)
        put(output / "core-verification.json", checked)
        process(output / "processes", "evidence-controls", [sys.executable, "-B", *commands["evidence-controls"]],
            cwd=output, env=environment)
        report.update(status="PASS")
        put(output / "result.json", report)
        result = verify(output)
        put(output / "verification.json", result)
        # Cargo intermediates are not evidence inputs. Keep both exact fresh
        # executables in their recorded target paths and retire only this owned
        # completed target directory after the strict reader admitted them.
        binaries = {name: regular(output / "original/target/release" / name)
                    for name in result["original_build"]["binaries"]}
        target_dir = output / "original/target"
        require(target_dir.resolve(strict=True) == target_dir and target_dir.parent == output / "original", "owned Rust target retirement")
        shutil.rmtree(target_dir)
        (target_dir / "release").mkdir(parents=True)
        for name, raw in binaries.items():
            (target_dir / "release" / name).write_bytes(raw)
        require(verify(output) == result, "build-intermediate retirement changed evidence")
        return result
    except BaseException as error:
        report.update(status="FAIL", failure=repr(error))
        put(output / "result.json", report)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("all", "core", "verify"), required=True)
    parser.add_argument("--hepta", type=Path)
    parser.add_argument("--target", type=Path)
    parser.add_argument("--rust-bin", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.phase == "all":
        result = run(args.hepta, args.target, args.rust_bin, args.output)
    elif args.phase == "core":
        result = core(args.output, require_final=False)
    else:
        result = verify(args.output)
    print(json.dumps({"status": "REBUILT_BATCH_PRIVATE_CORE_PASS", "fresh_original_build": result["fresh_original_build"],
        "body_requests_per_side": 926, "typed_cases": 417, "typed_controls": 115,
        "actual_current_sdk_cases": 22, "reader_process_launches": result["reader_process_launches"],
        "public_batch_qualified": False, "gateway_caller_qualified": False, "whole_runtime_replaced": False}, sort_keys=True))
