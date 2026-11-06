#!/usr/bin/env python3
"""DERIVED field projection of one immutable, completed D2 C1 adapter report.

This does not execute the adapter, trace parser, native auditor, or any workload.
The original full report remains the evidence source. Only existing aggregate
values are copied; no cost, acceptance, or successful-operation claim is computed.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path("/home/qian/hepta-runtime-validation-cost-20261106-d2")
SOURCE = ROOT / "c1-adapter-evidence-02/adapter-report.json"
OUTPUT = ROOT / "c1-cost-projection-02.json"
SOURCE_BYTES = 8827749
SOURCE_SHA256 = "d882031e45096ddddee57dd83b580b5dc3ff15ebe2481b9c9a1dd2d109d44807"
MAX_READ = 32 * 1024 * 1024
MAX_DERIVED = 2 * 1024 * 1024
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
TOP_KEYS = (
    "schema", "order", "modes", "original_returncode", "original_wrapper_returned",
    "controller_close_evidence_complete", "all_trace_reads_after_original_matrix",
    "trace_interpretation_started", "analysis_complete", "original_native_audit_required",
    "performance_acceptance_claim", "parent_held_agent_quiet90_and_compiler_monitor_required",
    "errors", "strict_on_request_bijection_count", "measured_on_request_count",
    "wire_native_request_id_policy", "validation_whole_cost_field",
    "measured_phase_summary", "original_report", "adapter_source", "scope",
)
TRACE_KEYS = (
    "binding", "startup", "trace", "raw_transport", "raw_transport_index",
    "phase_cpu_available", "whole_trace_cpu_is_measured_cell_cpu",
    "native_auditor_reexecuted_here", "wire_native_id_source",
    "off_empty_trace_is_zero_work_cpu_claim", "validation_whole_cpu_uses_parent_inclusive_field",
    "read_loop_phase_includes_original_reads_comparison_or_hash_and_cancellation_checks",
    "new_selective_phase_arithmetic_reconciled_with_parser", "selected_on_counts",
    "measured_controller_cpu_comparison",
)
SUMMARY_KEYS = (
    "schema", "preparation_revision", "raw", "mode", "trace_structurally_complete",
    "original_controller_and_harness_closure_validated", "evidence_scope",
    "pid", "start_ticks", "boot_id", "declared_elf_sha256",
    "elf_build_feature_and_custody_validated", "host_aliases", "counts",
    "recorded_synchronous_cpu_exclusive_ns", "controller_total_cpu_ns",
    "ssh_child_cpu_ns", "remote_helper_cpu_ns", "network_only_wall_ns",
    "phase_wall_nonadditive", "phase_thread_cpu_inclusive", "phase_thread_cpu_exclusive",
    "limitations", "performance_acceptance_claim",
)


def need(okay, reason):
    if not okay:
        raise ValueError(reason)


def stamp(value):
    return tuple(getattr(value, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns"))


def read_bound(path, expected_bytes, expected_sha, maximum):
    need(path.is_absolute() and path.resolve() == path, "indirect input path")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_size == expected_bytes
         and 0 <= expected_bytes <= maximum, "input type or fixed size differs")
    fd = os.open(path, READ_FLAGS)
    try:
        need(stamp(os.fstat(fd)) == stamp(before), "input changed on open")
        chunks, total = [], 0
        while total <= maximum:
            block = os.read(fd, min(1024 * 1024, maximum + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
        need(total == expected_bytes and total <= maximum, "input read length differs")
        need(stamp(os.fstat(fd)) == stamp(before) == stamp(path.lstat()),
             "input changed while reading")
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    need(hashlib.sha256(raw).hexdigest() == expected_sha, "input SHA256 differs")
    return raw, stamp(before)


def pick(value, keys):
    need(isinstance(value, dict), "expected original JSON object")
    return {key: value[key] for key in keys if key in value}


def main():
    need(len(sys.argv) == 1 and not sys.flags.optimize, "fixed no-argument projection required")
    os.umask(0o077)
    raw, source_stamp = read_bound(SOURCE, SOURCE_BYTES, SOURCE_SHA256, MAX_READ)
    document = json.loads(raw)
    need(isinstance(document, dict) and document.get("schema") == "hepta-d2-c1-phase-cost-adapter/v1",
         "original adapter schema differs")
    sealed_input = document["sealed_input"]
    need(isinstance(sealed_input, dict)
         and sealed_input.get("evidence_output") == str(SOURCE.parent),
         "original evidence output differs")
    traces = document["traces"]
    need(isinstance(traces, list), "original trace list missing")
    selected = pick(document, TOP_KEYS)
    selected["sealed_input"] = {"evidence_output": sealed_input["evidence_output"]}
    selected["traces"] = []
    missing = {"top": [key for key in TOP_KEYS if key not in document], "traces": []}
    for index, trace in enumerate(traces):
        row = pick(trace, TRACE_KEYS)
        row["source_trace_index"] = index
        categories = trace.get("category_phase_summaries")
        if isinstance(categories, dict):
            row["category_phase_summaries"] = (
                {"measured": categories["measured"]} if "measured" in categories else {})
        else:
            need(categories is None, "unexpected original category summary shape")
            row["category_phase_summaries"] = None
        row["measured_summary_present_in_source"] = (
            isinstance(categories, dict) and "measured" in categories)
        if "trace_summary" in trace:
            row["trace_summary"] = pick(trace["trace_summary"], SUMMARY_KEYS)
        selected["traces"].append(row)
        missing["traces"].append({
            "source_trace_index": index,
            "optional_trace_keys_absent": [key for key in TRACE_KEYS if key not in trace],
        })
    projection = {
        "schema": "hepta-d2-c1-cost-projection/v1",
        "classification": "DERIVED selective copy of existing aggregate JSON fields",
        "original_report_replaced": False,
        "source": {"path": str(SOURCE), "bytes": SOURCE_BYTES, "sha256": SOURCE_SHA256},
        "source_regular_nofollow_and_before_after_stamp_verified": True,
        "source_sha256_verified_before_output_creation": True,
        "selection": {
            "$": list(TOP_KEYS),
            "$.sealed_input": ["evidence_output"],
            "$.traces[*]": list(TRACE_KEYS),
            "$.traces[*].category_phase_summaries": ["measured when present"],
            "$.traces[*].trace_summary": list(SUMMARY_KEYS),
            "output_container_for_selected_original_fields": "$.adapter",
            "all_original_trace_entries_retained_in_order": True,
            "excluded_large_arrays_and_maps": [
                "$.bindings", "$.traces[*].selected_on_requests",
                "$.traces[*].original_request_groups",
                "$.traces[*].correlation_diagnostics",
                "$.traces[*].trace_summary.requests",
            ],
            "other_files_read": [],
            "original_report_field_is_an_identity_not_its_body": True,
        },
        "observed_trace_count": len(traces),
        "absent_optional_source_fields": missing,
        "adapter": selected,
        "calculations_performed": False,
        "parser_executed": False,
        "auditor_executed": False,
        "workload_executed": False,
        "performance_acceptance_claim": False,
    }
    encoded = (json.dumps(projection, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    need(len(encoded) <= MAX_DERIVED, "derived projection exceeds original 2MiB bound")
    need(stamp(SOURCE.lstat()) == source_stamp, "source changed before output creation")
    need(ROOT.resolve() == ROOT, "indirect output directory")
    directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before_directory = os.fstat(directory)
        need(stat.S_ISDIR(before_directory.st_mode)
             and (before_directory.st_dev, before_directory.st_ino)
                 == (ROOT.lstat().st_dev, ROOT.lstat().st_ino), "output directory changed")
        fd = os.open(OUTPUT.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(fd, view)
                need(written > 0, "output write made no progress")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory)
    finally:
        os.close(directory)
    digest = hashlib.sha256(encoded).hexdigest()
    readback, _ = read_bound(OUTPUT, len(encoded), digest, MAX_DERIVED)
    need(readback == encoded and stamp(SOURCE.lstat()) == source_stamp,
         "output readback or original source stability differs")
    print(json.dumps({
        "classification": "DERIVED",
        "output": {"path": str(OUTPUT), "bytes": len(encoded), "sha256": digest},
        "source": projection["source"],
        "observed_trace_count": len(traces),
        "original_values_only": True, "parser_executed": False, "auditor_executed": False,
    }, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
