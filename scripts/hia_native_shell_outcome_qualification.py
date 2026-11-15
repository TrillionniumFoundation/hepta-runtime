#!/usr/bin/env python3
"""Compare every HIA outcome byte with a fresh source-bound original Rust owner.

The native corpus is admitted by its independent source/build/evidence reader.
The original executable is admitted by the complete original build reader.
Neither an expected-text table nor a host implementation of Shell is used here.
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
DRIVER = "scripts/hia_native_shell_outcome_qualification.py"
REFERENCE = "scripts/hia_native_shell_process_reference.py"
CASES = "tests/hia_native/shell_outcome_cases.py"
NATIVE = "tests/hia_native/shell_outcome_state.py"
SCHEMA = "hepta.runtime.shell-outcome-original-comparison.v1"
EVIDENCE_SCHEMA = "hepta.runtime.shell-outcome-original-evidence.v1"
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
    ref = load("hia_outcome_original_reference", runtime / REFERENCE)
    ref.require(ref.read(runtime, DRIVER) == DRIVER_BYTES,
                "executing outcome qualification driver differs from source")
    cases = load("hia_outcome_semantic_cases", ref.owned(runtime, CASES))
    native = load("hia_outcome_native_reader", ref.owned(runtime, NATIVE))
    return ref, cases, native


def file_pin(path):
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            size += len(block)
            digest.update(block)
    return {"bytes": size, "sha256": digest.hexdigest()}


def sources(runtime, ref):
    return {name: ref.pin(ref.read(runtime, name)) for name in (DRIVER, REFERENCE, CASES, NATIVE)}


def scope():
    return {
        "original_foreground_result_statement_projection": True,
        "original_promotion_result_statement_projection": True,
        "original_errno_display_executed": True,
        "errno_platform": "Linux GNU; C locale; signed i32",
        "original_filesystem_read_discard_executed": False,
        "original_process_wait_or_promotion_executed": False,
        "native_filesystem_read_discard_qualified": False,
        "native_transport_controls_are_original_semantics": False,
        "production_shell_execution_qualified": False,
        "production_activated": False,
        "whole_runtime_replaced": False,
        "old_stack_removal_qualified": False,
    }


def native_evidence(runtime, native_corpus, native_manifest, ref, cases, native):
    ref.require(native_manifest is not None, "explicit current native build manifest required")
    evidence = native.read_evidence(native_corpus, native_manifest=native_manifest)
    ref.require(type(evidence) is dict and evidence.get("status") == "PASS",
                "native outcome source/build/corpus evidence failed")
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
    ref.require(len(header) == 16, "missing complete outcome response packet")
    returned, extent = struct.unpack("<2Q", header)
    ref.require(returned == 40 and 40 <= extent <= file_size - offset - 16,
                "invalid fixed-return/u64-extent response")
    body = stream.read(extent)
    ref.require(len(body) == extent, "truncated outcome response")
    cases.decode_body(body)
    return offset, body


def comparison_rows(output, specifications, cases, ref):
    request_path = ref.owned(output, "requests.bin")
    native_path = ref.owned(output, "native-responses.bin")
    original_path = ref.owned(output, "outcome-render.stdout")
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
                raise ValueError("original/native outcome mismatch: " + case["name"]
                                 + " at body byte " + str(at)
                                 + "; native=" + native_body[at:at + 16].hex()
                                 + "; original=" + original_body[at:at + 16].hex())
            yield {
                "index": index, "name": case["name"], "group": case["group"],
                "operation": case["fields"].get("op", 1),
                "request_offset": request_offset, "request": ref.pin(wire),
                "native_response_offset": native_offset,
                "original_response_offset": original_offset,
                "return_u64": 40, "extent_u64": len(native_body),
                "native_body": ref.pin(native_body), "original_body": ref.pin(original_body),
                "complete_bytes_equal": True,
            }
        ref.require(requests.read(1) == native.read(1) == original.read(1) == b"",
                    "extra outcome input or response bytes")


def read_evidence(runtime, build_output, native_corpus, native_manifest, output,
                  rustc=None, cargo=None):
    """Read complete retained evidence without builds, native entry or subprocesses."""
    runtime, build_output, native_corpus, native_manifest, output = (
        Path(item).absolute() for item in (runtime, build_output, native_corpus, native_manifest, output))
    ref, cases, native = modules(runtime)
    report = ref.decode(ref.read(output, "result.json"))
    ref.require(report.get("schema") == SCHEMA and report.get("status") == "PASS"
                and report.get("error") is None, "original outcome comparison incomplete")
    ref.exact(report.get("scope"), scope(), "outcome qualification scope differs")
    ref.exact(report.get("sources"), sources(runtime, ref), "outcome comparison sources changed")
    build = ref.read_evidence(runtime, build_output, rustc, cargo)
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
    ref.exact(report.get("execution_environment"), environment, "original outcome environment changed")
    rows = report.get("processes")
    ref.require(type(rows) is list and len(rows) == 1, "exactly one original replay process required")
    ref.completed_process(output, "outcome-render", rows[0],
                          [build["executable"]["path"], "--outcome-render"],
                          output, TIMEOUT, "requests.bin")
    build_report = ref.decode(ref.read(build_output, "result.json"))
    ref.require(rows[0]["started_unix_ns"] >= build_report["processes"][-1]["finished_unix_ns"],
                "original outcome replay predates this reference build")
    ref.require(ref.read(output, "outcome-render.stderr") == b"", "original outcome emitted errors")
    count = 0
    with ref.owned(output, "comparison.jsonl").open("rb") as stream:
        for row in comparison_rows(output, specifications, cases, ref):
            expected = (ref.canonical(row) + "\n").encode("utf-8")
            ref.require(stream.readline() == expected,
                        "full comparison row changed: " + row["name"])
            count += 1
        ref.require(stream.read(1) == b"", "extra outcome comparison rows")
    expected = {"counts": cases.counts(specifications),
                "requests": file_pin(ref.owned(output, "requests.bin")),
                "native_responses": file_pin(ref.owned(output, "native-responses.bin")),
                "original_responses": file_pin(ref.owned(output, "outcome-render.stdout")),
                "case_records": file_pin(ref.owned(output, "comparison.jsonl"))}
    ref.exact(report.get("comparison"), expected, "outcome comparison summary changed")
    ref.require(count == expected["counts"]["semantic_cases"], "semantic case set incomplete")
    return {"schema": EVIDENCE_SCHEMA, "status": "PASS",
            "report_sha256": ref.sha(ref.read(output, "result.json")),
            "reference_report_sha256": build["report_sha256"],
            "reference_executable": build["executable"],
            "fresh_original_rust_build_qualified": True, "original_tests": 21,
            "actual_original_replay_processes": 1, "original_rust_compared": True,
            "comparison": expected, **scope()}


def copy_exact(source, destination):
    with Path(source).open("rb") as src, Path(destination).open("xb") as dst:
        while block := src.read(1024 * 1024):
            dst.write(block)


def run(runtime, build_output, native_corpus, native_manifest, output, rustc=None, cargo=None):
    if output.exists():
        raise ValueError("outcome output must be a fresh directory")
    output.mkdir(parents=True)
    report = {"schema": SCHEMA, "status": "RUNNING", "error": None,
              "scope": scope(), "processes": []}
    result = output / "result.json"

    def save():
        result.write_text(json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n")

    save()
    started = time.monotonic()
    try:
        ref, cases, native = modules(runtime)
        report["sources"] = sources(runtime, ref)
        build = ref.read_evidence(runtime, build_output, rustc, cargo)
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
        row = ref.process(output, "outcome-render", [build["executable"]["path"], "--outcome-render"],
                          output, environment, TIMEOUT, "requests.bin")
        report["processes"].append(row)
        ref.require(row["passed"], "original outcome process failed; retained stdout/stderr have details")
        ref.require(ref.read(output, "outcome-render.stderr") == b"", "original outcome emitted errors")
        with (output / "comparison.jsonl").open("xb") as stream:
            for case_row in comparison_rows(output, specifications, cases, ref):
                stream.write((ref.canonical(case_row) + "\n").encode("utf-8"))
        report["comparison"] = {"counts": cases.counts(specifications),
                                "requests": file_pin(output / "requests.bin"),
                                "native_responses": file_pin(output / "native-responses.bin"),
                                "original_responses": file_pin(output / "outcome-render.stdout"),
                                "case_records": file_pin(output / "comparison.jsonl")}
        ref.exact(sources(runtime, ref), report["sources"], "outcome source changed during replay")
        report["status"] = "PASS"
    except Exception as error:
        report["status"] = "FAIL"
        report["error"] = type(error).__name__ + ": " + str(error)
    report["duration_seconds"] = time.monotonic() - started
    save()
    if report["status"] == "PASS":
        try:
            evidence = read_evidence(runtime, build_output, native_corpus, native_manifest, output, rustc, cargo)
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
    parser.add_argument("--cargo", type=Path)
    parser.add_argument("--read-only", action="store_true")
    args = parser.parse_args()
    inputs = [item.absolute() for item in (args.runtime, args.reference_build,
                                          args.native_corpus, args.native_manifest, args.output)]
    if args.read_only:
        print(json.dumps(read_evidence(*inputs, args.rustc, args.cargo), sort_keys=True))
        return 0
    report, result = run(*inputs, args.rustc, args.cargo)
    print(json.dumps({"status": report["status"], "error": report["error"], "report": str(result),
                      "actual_original_replay_processes": len(report["processes"]),
                      "counts": report.get("comparison", {}).get("counts"),
                      "whole_runtime_replaced": False}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
