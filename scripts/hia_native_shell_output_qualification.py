#!/usr/bin/env python3
"""Compare retained native output I/O with unchanged original real syscalls.

The native phase has already read files and called the HIA outcome owner. This
phase runs only the original Rust fixture and compares complete retained bytes.
Its pure reader executes neither an owner nor a subprocess.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
DRIVER = "scripts/hia_native_shell_output_qualification.py"
REFERENCE = "scripts/hia_native_shell_process_reference.py"
ORIGINAL = "tests/hia_native/shell_output_original_io.py"
NATIVE = "tests/hia_native/shell_output_io.py"
SCHEMA = "hepta.runtime.shell-output-original-comparison.v1"
TIMEOUT = 180
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
DRIVER_BYTES = Path(__file__).read_bytes()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load source-owned reader")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def modules(runtime):
    reference = load("shell_output_qualification_reference", runtime / REFERENCE)
    reference.require(reference.read(runtime, DRIVER) == DRIVER_BYTES,
                      "executing output qualification differs from source")
    original = load("shell_output_original_io_reader", reference.owned(runtime, ORIGINAL))
    native = load("shell_output_native_io_reader", reference.owned(runtime, NATIVE))
    return reference, original, native


def source_pins(runtime, reference):
    return {name: reference.pin(reference.read(runtime, name))
            for name in (DRIVER, REFERENCE, ORIGINAL, NATIVE)}


def scope():
    return {
        "actual_original_wait_and_path_reads_executed": True,
        "actual_original_both_discards_executed": True,
        "actual_native_path_reads_and_discards_executed": True,
        "actual_native_outcome_entries_in_native_phase": True,
        "complete_native_original_read_result_bytes_compared": True,
        "complete_native_original_foreground_outcome_bytes_compared": True,
        "original_hints_retained": True, "native_hints_execution_compared": False,
        "actual_native_process_wait": False,
        "native_wait_is_provided_typed_input": True,
        "original_raw_wait_status_observable": False,
        "natural_wait_error_executed": False,
        "native_phase_cases_added_by_reference": 0,
        "production_shell_execution_qualified": False,
        "production_activated": False, "whole_runtime_replaced": False,
        "old_stack_removal_qualified": False,
    }


def native_binding(folder, manifest, outcome, reference, native):
    result = native.read_evidence(folder, native_manifest=manifest,
                                  outcome_manifest=outcome, require_full=True)
    reference.require(result.get("status") == "PASS"
                      and result.get("complete_registered_corpus") is True
                      and result.get("shared_original_io_cases") == 6
                      and result.get("io_only") is False
                      and result.get("native_phase_cases_added_by_reference") == 0
                      and result.get("actual_native_process_wait") is False,
                      "native real IO/outcome corpus is incomplete or has different scope")
    return {"path": str(folder), "manifest": {"path": str(manifest),
                **reference.pin(manifest.read_bytes())},
            "outcome_manifest": {"path": str(outcome), **reference.pin(outcome.read_bytes())},
            "evidence": result}


def original_command(runtime, build, output, strace):
    return [sys.executable, "-I", "-B", str(runtime / ORIGINAL),
            "--runtime", str(runtime), "--oracle-build", str(build),
            "--strace", str(strace), "--output", str(output / "original-io")]


def observed_loan(proof):
    """Encode actual original read bytes/errors at the private typed boundary."""
    kinds, errors, values = [], [], []
    for stream in ("stdout", "stderr"):
        observed = proof["streams"][stream]
        errno = observed["errno"]
        if type(errno) is not int or not 0 <= errno < (1 << 31):
            raise ValueError("invalid actual observed original errno")
        if errno:
            if observed["bytes_hex"] is not None:
                raise ValueError("failed original read has successful payload")
            kinds.append(2)
            values.append(b"")
        else:
            kinds.append(0)
            values.append(bytes.fromhex(observed["bytes_hex"]))
        errors.append(errno)
    code = proof["wait_exit_code"]
    if type(code) is not int or not 0 <= code <= 255:
        raise ValueError("original wait is not the shared normal-exit domain")
    words = [1, 0, code << 8, kinds[0], errors[0], kinds[1], errors[1],
             0, 0, len(values[0]), len(values[1]), 0, 0]
    return b"HSHOUT01" + struct.pack("<13Q", *words) + b"".join(values)


def original_body(foreground):
    if type(foreground.get("ok")) is not bool:
        raise ValueError("original foreground result has no boolean tag")
    success = foreground["ok"]
    text = foreground["text"] if success else foreground["error"]
    unused = foreground["error"] if success else foreground["text"]
    if type(text) is not str or unused is not None or foreground.get("hints") != []:
        raise ValueError("original foreground output is incomplete")
    raw = text.encode("utf-8")
    return b"HSHOUR01" + struct.pack("<4Q", 0 if success else 1, len(raw), 0, 0) + raw


def compare_case(spec, native_folder, original_folder, reference, native, original):
    name = spec["name"]
    folder = native_folder / "cases" / name
    reference.exact(reference.decode(reference.read(folder, "spec.json")), spec,
                    "native/original concrete input differs: " + name)
    proof = original.read_case(original_folder / name)
    reference.require(proof.get("both_reads_and_both_discards_observed") is True,
                      "original actual syscall ownership is incomplete")
    loan = native.decode_transport(reference.read(folder, "stdout.bin"))[3]
    original_loan = observed_loan(proof)
    reference.require(loan == original_loan,
                      "native/original complete read-result loan differs: " + name)
    outcome = reference.decode(reference.read(folder, "outcome/report.json"))
    reference.require(type(outcome.get("calls")) is list and outcome["calls"],
                      "native IO has no actual HIA outcome invocation")
    invocation = reference.decode(reference.read(folder, outcome["calls"][-1]))
    body = reference.read(folder, invocation["body"]["path"])
    expected_body = original_body(proof["foreground_outcome"])
    reference.require(body == expected_body,
                      "native/original complete foreground bytes differ: " + name)
    original_events = reference.decode(reference.read(original_folder / name, "events.json"))
    reference.require(original_events[-1].get("resource_uri") is None,
                      "original foreground unexpectedly published a resource URI")
    raw = {"native-loan.bin": loan, "original-loan.bin": original_loan,
           "native-outcome.bin": body, "original-outcome.bin": expected_body}
    row = {
        "name": name, "input": spec, "complete_read_results_equal": True,
        "complete_foreground_outcomes_equal": True,
        "original_hints": proof["foreground_outcome"]["hints"],
        "original_wait": proof["wait"], "original_wait_exit_code": proof["wait_exit_code"],
        "native_wait_is_provided_typed_input": True,
        "original_streams": proof["streams"], "original_discards": proof["discard"],
        "native_last_outcome_invocation": reference.pin(reference.read(folder, outcome["calls"][-1])),
        "native_raw_stdout": reference.pin(reference.read(folder, "stdout.bin")),
        "original_raw_stdout": reference.pin(reference.read(original_folder / name, "stdout.jsonl")),
        "bytes": {key: reference.pin(value) for key, value in raw.items()},
    }
    return row, raw


def read_evidence(runtime, build, native_corpus, native_manifest, outcome_manifest,
                  output, rustc=None, cargo=None):
    runtime, build, native_corpus, native_manifest, outcome_manifest, output = (
        Path(value).absolute() for value in
        (runtime, build, native_corpus, native_manifest, outcome_manifest, output))
    reference, original, native = modules(runtime)
    report = reference.decode(reference.read(output, "result.json"))
    reference.require(report.get("schema") == SCHEMA and report.get("status") == "PASS"
                      and report.get("error") is None and report.get("recorded_directory") == str(output),
                      "output IO comparison is incomplete or relocated")
    reference.exact(report.get("scope"), scope(), "output comparison scope changed")
    reference.exact(report.get("sources"), source_pins(runtime, reference), "comparison sources changed")
    strong = reference.read_evidence(runtime, build, rustc, cargo)
    reference.exact(report.get("reference_build"), {"path": str(build), "evidence": strong,
                    "report": reference.pin(reference.read(build, "result.json"))},
                    "complete current original build changed")
    binding = native_binding(native_corpus, native_manifest, outcome_manifest, reference, native)
    reference.exact(report.get("native_corpus"), binding, "native bytes changed during original comparison")
    original_evidence = original.read_evidence(output / "original-io", runtime, build, require_full=True)
    reference.exact(report.get("original_io"), original_evidence, "actual original syscall evidence changed")
    strace = Path(report["strace"]["path"])
    reference.exact(report["strace"], {"path": str(strace), **reference.pin(strace.read_bytes())},
                    "selected actual strace tool changed")
    reference.exact(report.get("execution_environment"), ENVIRONMENT, "replay environment changed")
    processes = report.get("processes")
    reference.require(type(processes) is list and len(processes) == 1, "expected one original IO controller")
    reference.completed_process(output, "original-io", processes[0],
        original_command(runtime, build, output, strace), output, TIMEOUT)
    build_report = reference.decode(reference.read(build, "result.json"))
    reference.require(processes[0]["started_unix_ns"] >= build_report["processes"][-1]["finished_unix_ns"],
                      "original IO controller predates fresh build")
    reference.require(reference.read(output, "original-io.stderr") == b"", "original IO controller emitted errors")
    specifications = original.io_specs()
    reference.require(len(specifications) == 6, "shared real IO inventory changed")
    records = []
    for spec in specifications:
        row, raw = compare_case(spec, native_corpus, output / "original-io", reference, native, original)
        for filename, expected in raw.items():
            reference.require(reference.read(output / "comparison" / spec["name"], filename) == expected,
                              "retained comparison bytes changed: " + spec["name"] + "/" + filename)
        records.append(row)
    reference.exact(reference.decode(reference.read(output, "comparison.json")), records,
                    "complete native/original comparison rows changed")
    reference.exact(report.get("case_names"), [row["name"] for row in specifications],
                    "paired original IO coverage differs")
    reference.exact(report.get("comparison"), reference.pin(reference.read(output, "comparison.json")),
                    "comparison file identity changed")
    stdout = [reference.decode(line) for line in reference.read(output, "original-io.stdout").splitlines()]
    original_report = reference.decode(reference.read(output / "original-io", "report.json"))
    expected_progress = [{"name": row["name"], "status": "PASS", "trace_files": len(row["trace_files"])}
                         for row in original_report["cases"]]
    expected_progress.append({"status": "PASS", "case_count": 6,
                              "report": str(output / "original-io/report.json"), "error": None})
    reference.exact(stdout, expected_progress, "original IO progress has missing or extra records")
    return {"schema": SCHEMA + ".readback", "status": "PASS", "paired_real_io_cases": 6,
            "native_io_cases": binding["evidence"]["cases"],
            "reference_report_sha256": strong["report_sha256"],
            "fresh_original_rust_build_qualified": True, "original_tests": 21,
            "original_rust_compared": True, "original_io": original_evidence,
            "comparison": reference.pin(reference.read(output, "comparison.json")),
            "report_sha256": reference.sha(reference.read(output, "result.json")), **scope()}


def run(runtime, build, native_corpus, native_manifest, outcome_manifest,
        output, rustc=None, cargo=None, strace=Path("/usr/bin/strace")):
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": SCHEMA, "status": "RUNNING", "error": None,
              "recorded_directory": str(output), "scope": scope(), "processes": []}
    result = output / "result.json"
    def save():
        result.write_text(json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n")
    save()
    started = time.monotonic()
    try:
        reference, original, native = modules(runtime)
        report["sources"] = source_pins(runtime, reference)
        strong = reference.read_evidence(runtime, build, rustc, cargo)
        report["reference_build"] = {"path": str(build), "evidence": strong,
                                     "report": reference.pin(reference.read(build, "result.json"))}
        report["native_corpus"] = native_binding(native_corpus, native_manifest, outcome_manifest, reference, native)
        strace = strace.resolve(strict=True)
        report["strace"] = {"path": str(strace), **reference.pin(strace.read_bytes())}
        report["execution_environment"] = ENVIRONMENT
        row = reference.process(output, "original-io", original_command(runtime, build, output, strace),
                                output, ENVIRONMENT, TIMEOUT)
        report["processes"].append(row)
        reference.require(row["passed"], "original IO failed; complete process streams retained")
        report["original_io"] = original.read_evidence(output / "original-io", runtime, build, require_full=True)
        specifications = original.io_specs()
        records = []
        for spec in specifications:
            case_row, raw = compare_case(spec, native_corpus, output / "original-io", reference, native, original)
            folder = output / "comparison" / spec["name"]
            folder.mkdir(parents=True)
            for filename, data in raw.items():
                (folder / filename).write_bytes(data)
            records.append(case_row)
        (output / "comparison.json").write_text(json.dumps(records, sort_keys=True, indent=2) + "\n")
        report["comparison"] = reference.pin(reference.read(output, "comparison.json"))
        report["case_names"] = [row["name"] for row in specifications]
        reference.exact(source_pins(runtime, reference), report["sources"], "comparison source changed during replay")
        reference.exact(native_binding(native_corpus, native_manifest, outcome_manifest, reference, native),
                        report["native_corpus"], "native evidence changed during original phase")
        report["status"] = "PASS"
    except Exception as error:
        report["status"] = "FAIL"
        report["error"] = type(error).__name__ + ": " + str(error)
    report["duration_seconds"] = time.monotonic() - started
    save()
    if report["status"] == "PASS":
        try:
            evidence = read_evidence(runtime, build, native_corpus, native_manifest, outcome_manifest,
                                     output, rustc, cargo)
            (output / "evidence.json").write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
        except Exception as error:
            report["status"] = "FAIL"
            report["error"] = "post-replay reader: " + type(error).__name__ + ": " + str(error)
            save()
    return report, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=ROOT)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--native-corpus", type=Path, required=True)
    parser.add_argument("--native-manifest", type=Path, required=True)
    parser.add_argument("--outcome-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustc", type=Path)
    parser.add_argument("--cargo", type=Path)
    parser.add_argument("--strace", type=Path, default=Path("/usr/bin/strace"))
    parser.add_argument("--read-only", action="store_true")
    args = parser.parse_args()
    paths = [item.absolute() for item in (args.runtime, args.reference_build, args.native_corpus,
                                        args.native_manifest, args.outcome_manifest, args.output)]
    if args.read_only:
        print(json.dumps(read_evidence(*paths, args.rustc, args.cargo), sort_keys=True))
        return 0
    report, result = run(*paths, args.rustc, args.cargo, args.strace)
    print(json.dumps({"status": report["status"], "error": report["error"], "report": str(result),
                      "paired_real_io_cases": len(report.get("case_names", [])),
                      "native_phase_cases_added_by_reference": 0,
                      "whole_runtime_replaced": False}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
