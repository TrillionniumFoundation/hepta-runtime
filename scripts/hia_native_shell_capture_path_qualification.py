#!/usr/bin/env python3
"""Compare complete HIA capture-path bytes with a fresh original Rust projection.

Native controls remain separate from the registered semantic inputs. The
original uses standard-library paths and explicitly recorded typed primitive
observations. Python does not calculate expected path outputs.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
DRIVER = "scripts/hia_native_shell_capture_path_qualification.py"
REFERENCE = "scripts/hia_native_shell_capture_path_reference.py"
HELPERS = "scripts/hia_native_shell_process_reference.py"
CASES = "tests/hia_native/shell_capture_path_cases.py"
NATIVE = "tests/hia_native/shell_capture_path.py"
SCHEMA = "hepta.runtime.shell-capture-path-original-comparison.v1"
EVIDENCE_SCHEMA = "hepta.runtime.shell-capture-path-original-evidence.v1"
TIMEOUT = 180
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
DRIVER_BYTES = Path(__file__).read_bytes()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load source-bound reader: " + str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def modules(runtime):
    reference = load("hia_capture_original_build", runtime / REFERENCE)
    ref = reference.load_ref(runtime)
    ref.require(ref.read(runtime, DRIVER) == DRIVER_BYTES,
                "executing capture qualification driver differs from source")
    cases = load("hia_capture_semantic_cases", ref.owned(runtime, CASES))
    native = load("hia_capture_native_reader", ref.owned(runtime, NATIVE))
    return ref, cases, native, reference


def file_pin(path):
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            size += len(block)
            digest.update(block)
    return {"bytes": size, "sha256": digest.hexdigest()}


def sources(runtime, ref):
    return {name: ref.pin(ref.read(runtime, name)) for name in (DRIVER, REFERENCE, HELPERS, CASES, NATIVE)}


def scope():
    return {
        "original_path_equality_and_parent_compared": True,
        "original_capture_format_projection_compared": True,
        "actual_atomic_fetch_add_sequential_projection_compared": True,
        "tmpdir_and_pid_are_typed_observations": True,
        "real_environment_or_pid_acquisition_executed": False,
        "original_prepare_or_registry_executed": False,
        "original_filesystem_creation_executed": False,
        "concurrent_counter_or_registry_qualified": False,
        "native_transport_controls_are_original_semantics": False,
        "production_activated": False,
        "whole_runtime_replaced": False,
        "old_stack_removal_qualified": False,
    }


def native_evidence(runtime, native_corpus, native_manifest, ref, cases, native):
    ref.require(native_manifest is not None, "explicit current native build manifest required")
    evidence = native.read_evidence(native_corpus, native_manifest=native_manifest)
    ref.require(type(evidence) is dict and evidence.get("status") == "PASS",
                "native capture_path source/build/corpus evidence failed")
    specifications = cases.specifications()
    with ref.owned(native_corpus, "requests.bin").open("rb") as stream:
        for case in specifications:
            wire = cases.frame(**case["fields"])
            expected = struct.pack("<Q", len(wire)) + wire
            ref.require(stream.read(len(expected)) == expected,
                        "complete native request differs: " + case["name"])
        ref.require(stream.read(1) == b"", "extra native request bytes")
    return specifications, {
        "path": str(native_corpus),
        "manifest": {"path": str(native_manifest), **file_pin(native_manifest)},
        "evidence": evidence,
        "requests": file_pin(ref.owned(native_corpus, "requests.bin")),
        "responses": file_pin(ref.owned(native_corpus, "responses.bin")),
        "counts": cases.counts(specifications),
    }


def packet(stream, file_size, cases, ref):
    offset = stream.tell()
    header = stream.read(16)
    ref.require(len(header) == 16, "missing complete capture_path response packet")
    returned, extent = struct.unpack("<2Q", header)
    ref.require(returned == 80 and 80 <= extent <= file_size - offset - 16,
                "invalid fixed-return/u64-extent response")
    body = stream.read(extent)
    ref.require(len(body) == extent, "truncated capture_path response")
    cases.decode_body(body)
    return offset, body


def comparison_rows(output, specifications, cases, ref):
    request_path = ref.owned(output, "requests.bin")
    native_path = ref.owned(output, "native-responses.bin")
    original_path = ref.owned(output, "capture-path-render.stdout")
    native_size = native_path.stat().st_size
    original_size = original_path.stat().st_size
    with request_path.open("rb") as requests, native_path.open("rb") as native, original_path.open("rb") as original:
        for index, case in enumerate(specifications):
            request_offset = requests.tell()
            wire = cases.frame(**case["fields"])
            expected = struct.pack("<Q", len(wire)) + wire
            ref.require(requests.read(len(expected)) == expected,
                        "retained original input differs: " + case["name"])
            native_offset, native_body = packet(native, native_size, cases, ref)
            original_offset, original_body = packet(original, original_size, cases, ref)
            if native_body != original_body:
                at = next((i for i, pair in enumerate(zip(native_body, original_body))
                           if pair[0] != pair[1]), min(len(native_body), len(original_body)))
                raise ValueError("original/native capture_path mismatch: " + case["name"]
                                 + " at body byte " + str(at)
                                 + "; native=" + native_body[at:at + 16].hex()
                                 + "; original=" + original_body[at:at + 16].hex())
            yield {
                "index": index, "name": case["name"], "group": case["group"],
                "operation": case["fields"].get("op", 1),
                "request_offset": request_offset, "request": ref.pin(wire),
                "native_response_offset": native_offset,
                "original_response_offset": original_offset,
                "return_u64": 80, "extent_u64": len(native_body),
                "native_body": ref.pin(native_body), "original_body": ref.pin(original_body),
                "complete_bytes_equal": True,
            }
        ref.require(requests.read(1) == native.read(1) == original.read(1) == b"",
                    "extra capture_path input or response bytes")


def read_evidence(runtime, build_output, native_corpus, native_manifest, output,
                  rustc=None, linker=None):
    """Read complete retained evidence without builds, native entry or subprocesses."""
    runtime, build_output, native_corpus, native_manifest, output = (
        Path(item).absolute() for item in (runtime, build_output, native_corpus, native_manifest, output))
    ref, cases, native, reference = modules(runtime)
    report = ref.decode(ref.read(output, "result.json"))
    ref.require(report.get("schema") == SCHEMA and report.get("status") == "PASS"
                and report.get("error") is None, "original capture_path comparison incomplete")
    ref.exact(report.get("scope"), scope(), "capture_path qualification scope differs")
    ref.exact(report.get("sources"), sources(runtime, ref), "capture_path comparison sources changed")
    build = reference.read_evidence(runtime, build_output, rustc, linker)
    ref.exact(report.get("reference_build"), {
        "path": str(build_output), "report": ref.pin(ref.read(build_output, "result.json")),
        "evidence": build}, "current original reference identity differs")
    specifications, native_binding = native_evidence(
        runtime, native_corpus, native_manifest, ref, cases, native)
    ref.exact(report.get("native_corpus"), native_binding, "current native corpus identity differs")
    ref.exact(file_pin(ref.owned(output, "requests.bin")), native_binding["requests"],
              "original replay stdin differs from native corpus")
    ref.exact(file_pin(ref.owned(output, "native-responses.bin")), native_binding["responses"],
              "retained native response bytes differ")
    environment = {**ENVIRONMENT, "TMPDIR": str(output / "temporary")}
    ref.exact(report.get("execution_environment"), environment, "original capture_path environment changed")
    rows = report.get("processes")
    ref.require(type(rows) is list and len(rows) == 1, "exactly one original replay process required")
    ref.completed_process(output, "capture-path-render", rows[0],
                          [build["executable"]["launch_path"]],
                          output, TIMEOUT, "requests.bin")
    build_report = ref.decode(ref.read(build_output, "result.json"))
    ref.require(rows[0]["started_unix_ns"] >= build_report["processes"][-1]["finished_unix_ns"],
                "original capture_path replay predates this reference build")
    ref.require(ref.read(output, "capture-path-render.stderr") == b"", "original capture_path emitted errors")
    count = 0
    with ref.owned(output, "comparison.jsonl").open("rb") as stream:
        for row in comparison_rows(output, specifications, cases, ref):
            expected = (ref.canonical(row) + "\n").encode("utf-8")
            ref.require(stream.readline() == expected,
                        "full comparison row changed: " + row["name"])
            count += 1
        ref.require(stream.read(1) == b"", "extra capture_path comparison rows")
    expected = {"counts": cases.counts(specifications),
                "requests": file_pin(ref.owned(output, "requests.bin")),
                "native_responses": file_pin(ref.owned(output, "native-responses.bin")),
                "original_responses": file_pin(ref.owned(output, "capture-path-render.stdout")),
                "case_records": file_pin(ref.owned(output, "comparison.jsonl"))}
    ref.exact(report.get("comparison"), expected, "capture_path comparison summary changed")
    ref.require(count == expected["counts"]["semantic_cases"], "semantic case set incomplete")
    return {"schema": EVIDENCE_SCHEMA, "status": "PASS",
            "report_sha256": ref.sha(ref.read(output, "result.json")),
            "reference_report_sha256": build["report_sha256"],
            "reference_executable": build["executable"],
            "fresh_original_projection_build_qualified": True, "original_tests": 0,
            "actual_original_replay_processes": 1, "original_rust_compared": True,
            "comparison": expected, **scope()}


def copy_exact(source, destination):
    with Path(source).open("rb") as src, Path(destination).open("xb") as dst:
        while block := src.read(1024 * 1024):
            dst.write(block)


def run(runtime, build_output, native_corpus, native_manifest, output, rustc=None, linker=None):
    if output.exists():
        raise ValueError("capture_path output must be a fresh directory")
    output.mkdir(parents=True)
    report = {"schema": SCHEMA, "status": "RUNNING", "error": None,
              "scope": scope(), "processes": []}
    result = output / "result.json"

    def save():
        result.write_text(json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n")

    save()
    started = time.monotonic()
    try:
        ref, cases, native, reference = modules(runtime)
        report["sources"] = sources(runtime, ref)
        build = reference.read_evidence(runtime, build_output, rustc, linker)
        report["reference_build"] = {"path": str(build_output),
                                     "report": ref.pin(ref.read(build_output, "result.json")),
                                     "evidence": build}
        specifications, native_binding = native_evidence(
            runtime, native_corpus, native_manifest, ref, cases, native)
        report["native_corpus"] = native_binding
        copy_exact(ref.owned(native_corpus, "requests.bin"), output / "requests.bin")
        copy_exact(ref.owned(native_corpus, "responses.bin"), output / "native-responses.bin")
        (output / "temporary").mkdir()
        environment = {**ENVIRONMENT, "TMPDIR": str(output / "temporary")}
        report["execution_environment"] = environment
        row = ref.process(output, "capture-path-render", [build["executable"]["launch_path"]],
                          output, environment, TIMEOUT, "requests.bin")
        report["processes"].append(row)
        ref.require(row["passed"], "original capture_path process failed; retained stdout/stderr have details")
        ref.require(ref.read(output, "capture-path-render.stderr") == b"", "original capture_path emitted errors")
        with (output / "comparison.jsonl").open("xb") as stream:
            for case_row in comparison_rows(output, specifications, cases, ref):
                stream.write((ref.canonical(case_row) + "\n").encode("utf-8"))
        report["comparison"] = {"counts": cases.counts(specifications),
                                "requests": file_pin(output / "requests.bin"),
                                "native_responses": file_pin(output / "native-responses.bin"),
                                "original_responses": file_pin(output / "capture-path-render.stdout"),
                                "case_records": file_pin(output / "comparison.jsonl")}
        ref.exact(sources(runtime, ref), report["sources"], "capture_path source changed during replay")
        report["status"] = "PASS"
    except Exception as error:
        report["status"] = "FAIL"
        report["error"] = type(error).__name__ + ": " + str(error)
    report["duration_seconds"] = time.monotonic() - started
    save()
    if report["status"] == "PASS":
        try:
            evidence = read_evidence(runtime, build_output, native_corpus, native_manifest, output, rustc, linker)
            (output / "evidence.json").write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
        except Exception as error:
            report["status"] = "FAIL"
            report["error"] = "post-replay evidence reader: " + type(error).__name__ + ": " + str(error)
            save()
    return report, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=ROOT)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--native-corpus", type=Path, required=True)
    parser.add_argument("--native-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustc", type=Path)
    parser.add_argument("--linker", type=Path)
    parser.add_argument("--read-only", action="store_true")
    args = parser.parse_args()
    inputs = [item.absolute() for item in (args.runtime, args.reference_build,
                                          args.native_corpus, args.native_manifest, args.output)]
    if args.read_only:
        print(json.dumps(read_evidence(*inputs, args.rustc, args.linker), sort_keys=True))
        return 0
    report, result = run(*inputs, args.rustc, args.linker)
    print(json.dumps({"status": report["status"], "error": report["error"], "report": str(result),
                      "actual_original_replay_processes": len(report["processes"]),
                      "counts": report.get("comparison", {}).get("counts"),
                      "whole_runtime_replaced": False}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
