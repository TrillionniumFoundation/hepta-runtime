#!/usr/bin/env python3
"""Compare completed native foreground execution with the same fresh Rust oracle.

This phase rereads the complete native process/IO/outcome corpus and the six
already completed original IO probes. It starts no owner or original process.
The independent evidence reader performs no execution or filesystem writes.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
DRIVER = "scripts/hia_native_shell_foreground_qualification.py"
SHARED = "scripts/hia_native_shell_output_qualification.py"
REFERENCE = "scripts/hia_native_shell_process_reference.py"
ORIGINAL = "tests/hia_native/shell_output_original_io.py"
NATIVE = "tests/hia_native/shell_foreground_io.py"
SCHEMA = "hepta.runtime.shell-foreground-original-comparison.v1"
DRIVER_BYTES = Path(__file__).read_bytes()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load source-owned foreground reader")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def modules(runtime):
    reference = load("shell_foreground_reference", runtime / REFERENCE)
    reference.require(reference.read(runtime, DRIVER) == DRIVER_BYTES,
                      "executing foreground comparison differs from source")
    return (reference,
            load("shell_foreground_carriers", reference.owned(runtime, SHARED)),
            load("shell_foreground_original", reference.owned(runtime, ORIGINAL)),
            load("shell_foreground_native", reference.owned(runtime, NATIVE)))


def source_pins(runtime, reference):
    return {name: reference.pin(reference.read(runtime, name))
            for name in (DRIVER, SHARED, REFERENCE, ORIGINAL, NATIVE)}


def scope():
    return {
        "actual_native_process_wait": True,
        "actual_native_foreground_event_retained": True,
        "actual_native_wait_to_io_to_outcome_causality_qualified": True,
        "actual_native_path_reads_and_discards_executed": True,
        "actual_native_outcome_entries_in_native_phase": True,
        "native_wait_is_provided_typed_input": False,
        "actual_original_wait_and_path_reads_executed": True,
        "actual_original_both_discards_executed": True,
        "complete_native_original_commands_compared": True,
        "complete_native_original_read_result_bytes_compared": True,
        "complete_native_original_foreground_outcome_bytes_compared": True,
        "original_hints_retained": True, "native_hints_execution_compared": False,
        "original_raw_wait_status_observable": False,
        "natural_original_wait_error_executed": False,
        "native_phase_cases_added_by_reference": 0,
        "original_processes_added_by_comparison": 0,
        "reused_completed_original_io_corpus": True,
        "capture_preparation_qualified": False, "background_registry_qualified": False,
        "public_shell_dispatch_qualified": False, "production_shell_execution_qualified": False,
        "production_activated": False, "whole_runtime_replaced": False,
        "old_stack_removal_qualified": False,
    }


def original_binding(runtime, build, folder, reference, original, rustc, cargo):
    strong = reference.read_evidence(runtime, build, rustc, cargo)
    evidence = original.read_evidence(folder, runtime, build, require_full=True)
    reference.require(strong.get("fresh_original_rust_build_qualified") is True
                      and evidence.get("status") == "PASS" and evidence.get("case_count") == 6
                      and evidence.get("full_case_set") is True
                      and evidence.get("wait_reads_and_discards_from_actual_syscalls") is True,
                      "complete actual original foreground IO evidence is missing")
    built = reference.decode(reference.read(build, "result.json"))
    finished = built["processes"][-1]["finished_unix_ns"]
    reference.require(type(finished) is int, "original build has no finish time")
    for spec in original.io_specs():
        receipt = reference.decode(reference.read(folder / spec["name"], "process.json"))
        reference.require(type(receipt.get("started_unix_ns")) is int
                          and receipt["started_unix_ns"] >= finished,
                          "original foreground probe predates fresh build")
    return {"reference_build": {"path": str(build), "evidence": strong,
                "report": reference.pin(reference.read(build, "result.json"))},
            "original_io": {"path": str(folder), "evidence": evidence,
                "report": reference.pin(reference.read(folder, "report.json"))}}


def native_binding(folder, manifest, reference, native):
    evidence = native.read_evidence(folder, native_manifest=manifest, require_full=True)
    reference.require(evidence.get("schema") == "hepta.runtime.shell-foreground-io-read.v1"
                      and evidence.get("status") == "PASS"
                      and evidence.get("complete_registered_corpus") is True
                      and type(evidence.get("cases")) is int and type(evidence.get("retired_fixtures")) is int
                      and evidence.get("cases") == 12 and evidence.get("retired_fixtures") == 12
                      and evidence.get("shared_original_io_cases") == 6
                      and evidence.get("actual_native_process_wait") is True
                      and evidence.get("native_phase_cases_added_by_reference") == 0,
                      "native foreground process/IO/outcome causality is incomplete")
    return {"path": str(folder), "manifest": {"path": str(manifest),
            **reference.pin(manifest.read_bytes())}, "evidence": evidence}


def compare_case(spec, native_folder, native_manifest, original_folder,
                 reference, shared, original, native):
    name = spec["name"]
    folder = native_folder / "cases" / name
    reference.exact(reference.decode(reference.read(folder, "spec.json")), spec,
                    "native/original concrete foreground input differs: " + name)
    observed = native.read_case(folder, native_manifest)
    reference.require(observed.get("name") == name and observed.get("spec") == spec,
                      "actual native foreground case binding differs: " + name)
    for field in ("loan", "outcome", "process_event", "command"):
        reference.require(type(observed.get(field)) is bytes,
                          "missing actual native foreground bytes: " + name + "/" + field)
    reference.require(len(observed["process_event"]) == 96
                      and type(observed.get("causal")) is dict and bool(observed["causal"]),
                      "native foreground event or causal proof is absent: " + name)
    for field, filename in (("loan", "loan.bin"), ("outcome", "outcome.bin"),
                            ("process_event", "foreground-event.bin")):
        reference.require(reference.read(folder, filename) == observed[field],
                          "native foreground actual carrier file differs: " + name + "/" + field)
    proof = original.read_case(original_folder / name)
    reference.require(proof.get("both_reads_and_both_discards_observed") is True,
                      "actual original foreground syscall ownership is incomplete")
    original_input = reference.decode(reference.read(original_folder / name, "input.json"))
    command = bytes.fromhex(original_input["command_hex"])
    reference.require(command == original.command_for(spec).encode("utf-8")
                      and observed["command"] == command,
                      "actual native/original complete commands differ: " + name)
    loan = shared.observed_loan(proof)
    outcome = shared.original_body(proof["foreground_outcome"])
    reference.require(observed["loan"] == loan,
                      "native/original actual wait and complete read loan differ: " + name)
    reference.require(observed["outcome"] == outcome,
                      "native/original complete foreground outcomes differ: " + name)
    events = reference.decode(reference.read(original_folder / name, "events.json"))
    reference.require(events[-1].get("resource_uri") is None,
                      "original foreground unexpectedly published a resource URI")
    raw = {"native-command.bin": observed["command"], "original-command.bin": command,
           "native-loan.bin": observed["loan"], "original-loan.bin": loan,
           "native-outcome.bin": observed["outcome"], "original-outcome.bin": outcome,
           "native-foreground-event.bin": observed["process_event"]}
    row = {
        "name": name, "input": spec, "complete_commands_equal": True,
        "complete_read_results_equal": True, "complete_foreground_outcomes_equal": True,
        "actual_native_process_wait": True, "native_wait_is_provided_typed_input": False,
        "native_causal": observed["causal"], "original_wait": proof["wait"],
        "original_wait_exit_code": proof["wait_exit_code"],
        "original_streams": proof["streams"], "original_discards": proof["discard"],
        "original_hints": proof["foreground_outcome"]["hints"],
        "original_raw_stdout": reference.pin(reference.read(original_folder / name, "stdout.jsonl")),
        "bytes": {key: reference.pin(value) for key, value in raw.items()},
    }
    return row, raw


def paths(runtime, build, original_io, native_corpus, native_manifest, output):
    return tuple(Path(item).absolute() for item in
                 (runtime, build, original_io, native_corpus, native_manifest, output))


def context(runtime, build, original_io, native_corpus, native_manifest, output):
    return dict(zip(("runtime", "reference_build", "original_io_corpus", "native_corpus",
                     "native_manifest", "output"),
                    map(str, (runtime, build, original_io, native_corpus, native_manifest, output))))


def read_evidence(runtime, build, original_io, native_corpus, native_manifest,
                  output, rustc=None, cargo=None):
    runtime, build, original_io, native_corpus, native_manifest, output = paths(
        runtime, build, original_io, native_corpus, native_manifest, output)
    reference, shared, original, native = modules(runtime)
    report = reference.decode(reference.read(output, "result.json"))
    reference.require(report.get("schema") == SCHEMA and report.get("status") == "PASS"
                      and report.get("error") is None, "foreground original comparison is incomplete")
    reference.exact(report.get("context"), context(runtime, build, original_io, native_corpus,
                    native_manifest, output), "foreground comparison paths changed")
    reference.exact(report.get("scope"), scope(), "foreground comparison scope changed")
    reference.exact(report.get("sources"), source_pins(runtime, reference), "foreground comparison sources changed")
    original_bound = original_binding(runtime, build, original_io, reference, original, rustc, cargo)
    reference.exact(report.get("original"), original_bound,
                    "complete current original foreground build or corpus changed")
    reference.exact(report.get("native"), native_binding(native_corpus, native_manifest, reference, native),
                    "native foreground build or actual corpus changed")
    reference.exact(report.get("processes"), [], "comparison unexpectedly claims a new execution")
    specifications = original.io_specs()
    reference.require(len(specifications) == 6, "shared foreground inventory changed")
    records = []
    for spec in specifications:
        row, raw = compare_case(spec, native_corpus, native_manifest, original_io,
                                reference, shared, original, native)
        for filename, expected in raw.items():
            reference.require(reference.read(output / "comparison" / spec["name"], filename) == expected,
                              "retained foreground comparison bytes changed: " + spec["name"] + "/" + filename)
        records.append(row)
    reference.exact(reference.decode(reference.read(output, "comparison.json")), records,
                    "complete native/original foreground comparison rows changed")
    reference.exact(report.get("case_names"), [row["name"] for row in specifications], "paired foreground coverage differs")
    reference.exact(report.get("comparison"), reference.pin(reference.read(output, "comparison.json")),
                    "foreground comparison identity changed")
    return {"schema": SCHEMA + ".readback", "status": "PASS", "paired_real_foreground_cases": 6,
            "reference_report_sha256": original_bound["reference_build"]["evidence"]["report_sha256"],
            "original_io_report_sha256": original_bound["original_io"]["report"]["sha256"],
            "fresh_original_rust_build_qualified": True, "original_tests": 21, "original_rust_compared": True,
            "comparison": reference.pin(reference.read(output, "comparison.json")),
            "report_sha256": reference.sha(reference.read(output, "result.json")), **scope()}


def run(runtime, build, original_io, native_corpus, native_manifest,
        output, rustc=None, cargo=None):
    runtime, build, original_io, native_corpus, native_manifest, output = paths(
        runtime, build, original_io, native_corpus, native_manifest, output)
    output.mkdir(parents=True, exist_ok=False)
    report = {"schema": SCHEMA, "status": "RUNNING", "error": None, "scope": scope(),
              "context": context(runtime, build, original_io, native_corpus, native_manifest, output),
              "processes": []}
    result = output / "result.json"
    def save():
        result.write_text(json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n")
    save()
    started = time.monotonic()
    try:
        reference, shared, original, native = modules(runtime)
        report["sources"] = source_pins(runtime, reference)
        report["original"] = original_binding(runtime, build, original_io, reference, original, rustc, cargo)
        report["native"] = native_binding(native_corpus, native_manifest, reference, native)
        specifications = original.io_specs()
        reference.require(len(specifications) == 6, "shared foreground inventory changed")
        records = []
        for spec in specifications:
            row, raw = compare_case(spec, native_corpus, native_manifest, original_io,
                                    reference, shared, original, native)
            folder = output / "comparison" / spec["name"]
            folder.mkdir(parents=True)
            for filename, data in raw.items():
                (folder / filename).write_bytes(data)
            records.append(row)
        (output / "comparison.json").write_text(json.dumps(records, sort_keys=True, indent=2, allow_nan=False) + "\n")
        report["comparison"] = reference.pin(reference.read(output, "comparison.json"))
        report["case_names"] = [row["name"] for row in specifications]
        reference.exact(source_pins(runtime, reference), report["sources"],
                        "foreground comparison source changed while comparing")
        reference.exact(original_binding(runtime, build, original_io, reference, original, rustc, cargo),
                        report["original"], "original foreground evidence changed while comparing")
        reference.exact(native_binding(native_corpus, native_manifest, reference, native),
                        report["native"], "native foreground evidence changed while comparing")
        report["status"] = "PASS"
    except Exception as error:
        report["status"] = "FAIL"
        report["error"] = type(error).__name__ + ": " + str(error)
    report["duration_seconds"] = time.monotonic() - started
    save()
    if report["status"] == "PASS":
        try:
            evidence = read_evidence(runtime, build, original_io, native_corpus, native_manifest,
                                     output, rustc, cargo)
            (output / "evidence.json").write_text(json.dumps(evidence, sort_keys=True, indent=2, allow_nan=False) + "\n")
        except Exception as error:
            report["status"] = "FAIL"
            report["error"] = "post-comparison reader: " + type(error).__name__ + ": " + str(error)
            save()
    return report, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=ROOT)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--original-io-corpus", type=Path, required=True)
    parser.add_argument("--native-corpus", type=Path, required=True)
    parser.add_argument("--native-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustc", type=Path)
    parser.add_argument("--cargo", type=Path)
    parser.add_argument("--read-only", action="store_true")
    args = parser.parse_args()
    values = paths(args.runtime, args.reference_build, args.original_io_corpus,
                   args.native_corpus, args.native_manifest, args.output)
    if args.read_only:
        print(json.dumps(read_evidence(*values, args.rustc, args.cargo), sort_keys=True))
        return 0
    report, result = run(*values, args.rustc, args.cargo)
    print(json.dumps({"status": report["status"], "error": report["error"], "report": str(result),
                      "paired_real_foreground_cases": len(report.get("case_names", [])),
                      "native_phase_cases_added_by_reference": 0,
                      "original_processes_added_by_comparison": 0,
                      "whole_runtime_replaced": False}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
