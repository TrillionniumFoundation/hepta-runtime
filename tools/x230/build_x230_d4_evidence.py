#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Publish a completed same-binary D4 series without rerunning anything.

--series is series.json; sibling plan/inputs/receipts/reports/stderr are read only.
Every recorded report row and receipt event is retained in sanitized artifacts.
Missing, failed, inconsistent, and unexecuted stages are explicit evidence; none
is promoted to a pass. No performance comparison or A20/A25 binary alias exists.
"""
import argparse
from collections import Counter
import gzip
import io
import json
import os
from pathlib import Path
import re
import stat
import sys

from build_x230_evidence import Sanitizer, canonical, normal_shutdown, sha


SERIES_SCHEMA = "hepta-x230-a25-d4-probe-series/v1"
EVENT_SCHEMA = "hepta-x230-spawn-proof-failure/v2-d4"
PREFIX = b"HEPTA_X230_SPAWN_PROOF_FAILURE_JSON "
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
LOG_NAME = re.compile(r"round-[0-9]+-[AB]/(?:first|restart)/stderr\.log\Z")
SPECS = {"initial": ("ABBA", 192, [1, 4, 8]), "extended": ("B", 12000, [8])}
QUAL_STAGES = ["format", "fmt-check", "clippy", "test", "release"]
JSON_LIMIT = 128 * 1024 * 1024
LOG_LIMIT = 64 * 1024 * 1024


def mapping(value):
    return value if isinstance(value, dict) else {}


def sequence(value):
    return value if isinstance(value, list) else []


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("non-finite JSON number")


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)


def fingerprint(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def read_file(path, limit):
    """Hash every byte; retain at most limit bytes; reject changing inputs."""
    import hashlib
    if path.absolute() != path.resolve():
        raise ValueError("symlink or indirect input path refused")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    hashed, content, size = hashlib.sha256(), bytearray(), 0
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("nonregular input refused")
        while True:
            block = source.read(65536)
            if not block:
                break
            hashed.update(block)
            size += len(block)
            if len(content) < limit:
                content.extend(block[:limit - len(content)])
        after = os.fstat(source.fileno())
    if (fingerprint(before) != fingerprint(after)
            or fingerprint(after) != fingerprint(path.lstat()) or size != before.st_size):
        raise ValueError("input changed during complete read")
    return {"present": True, "bytes": size, "sha256": hashed.hexdigest(),
            "retention_limit_exceeded": size > limit}, bytes(content)


class Inputs:
    def __init__(self):
        self.files = {}
        self.errors = []

    def read(self, path, label, limit=JSON_LIMIT, parse=True):
        try:
            receipt, raw = read_file(path, limit)
            self.files[label] = receipt
            if receipt["retention_limit_exceeded"]:
                raise ValueError("input exceeds bounded parsing limit; full hash retained")
            return decode(raw) if parse else raw
        except FileNotFoundError:
            self.files[label] = {"present": False}
        except (OSError, ValueError, UnicodeError) as error:
            self.files.setdefault(label, {"present": True})["read_error"] = {
                "type": type(error).__name__, "errno": getattr(error, "errno", None),
                "message": str(error)}
            self.errors.append({"input": label, **self.files[label]["read_error"]})
        return None


class CompleteSanitizer(Sanitizer):
    """Keep all keys/lists, including timestamps; replace private values in place."""
    private_keys = Sanitizer.identity_keys | Sanitizer.secret_keys | {
        "ppid", "owner_pid", "controller_pid", "birth", "start_ticks", "agent_identity",
        "process_identity", "agent_socket_identity", "uid", "gid", "dev", "ino"}
    opaque_keys = {"base64", "bytes_hex", "stdin_base64", "stdout_base64", "stderr_base64",
                   "argv", "args", "arguments", "command", "raw_argv", "argv_bytes"}

    def __init__(self, value):
        super().__init__(value)
        self.pids = set()

        def visit(item):
            if isinstance(item, dict):
                for key, value in item.items():
                    if (key.lower() in self.private_keys and "pid" in key.lower()
                            and (type(value) is int or isinstance(value, str) and value.isdigit())):
                        self.pids.add(str(value))
                    visit(value)
            elif isinstance(item, list):
                for value in item:
                    visit(value)
        visit(value)

    def string(self, value):
        if HEX256.fullmatch(value):
            return value
        value = super().string(value)
        value = re.sub(r'(?i)(\b(?:pid|ppid|child_pid|owner_pid|controller_pid)["\s:=]+)[0-9]+',
                       lambda match: match[1] + "<pid>", value)
        for pid in sorted(self.pids, key=len, reverse=True):
            value = re.sub(r"(?<![A-Za-z0-9_])" + re.escape(pid) + r"(?![A-Za-z0-9_])",
                           "<pid>", value)
        return value

    def __call__(self, value, scope=""):
        if isinstance(value, list):
            return [self(item, scope) for item in value]
        if isinstance(value, dict):
            if "event" in value and isinstance(value.get("path"), str):
                scope += "/" + value["path"]
            result = {}
            for key, item in value.items():
                public_key = self.string(key)
                if public_key in result:
                    raise ValueError("sanitized key collision; refusing lossy publication")
                if key.lower() == "owned_child_id":
                    result[public_key] = "owned-child:" + sha(canonical([scope, item]))[:16]
                elif key.lower() in self.private_keys or key.lower() in self.opaque_keys:
                    result[public_key] = self.receipt(item)
                else:
                    result[public_key] = self(item, scope)
            return result
        return self.string(value) if isinstance(value, str) else value


def receipt_matches(actual, declared):
    return (mapping(actual).get("present") is True
            and all(mapping(actual).get(key) == mapping(declared).get(key) for key in ("bytes", "sha256")))


def valid_source_map(value):
    return (isinstance(value, dict) and bool(value)
            and all(isinstance(key, str) and isinstance(digest, str)
                    and HEX256.fullmatch(digest) for key, digest in value.items()))


def counts(rows):
    return {"recorded_calls": len(rows),
            "successes": sum(mapping(row).get("okay") is True for row in rows),
            "failures": sum(mapping(row).get("okay") is False for row in rows),
            "unknown_outcomes": sum(type(mapping(row).get("okay")) is not bool for row in rows)}


def report_summary(report, spec, binary):
    if not isinstance(report, dict):
        return {"present_and_parsed": False, "call_counts": None, "complete_success": False}
    order, calls, concurrency = spec
    rounds = sequence(report.get("rounds"))
    measured, initial, restarted, shutdowns = [], [], [], []
    cell_integrity, rounds_complete = True, len(rounds) == len(order)
    for index, raw in enumerate(rounds):
        row = mapping(raw)
        cells = sequence(row.get("cells"))
        rounds_complete &= (index < len(order) and row.get("index") == index
            and row.get("version") == order[index]
            and [mapping(cell).get("concurrency") for cell in cells] == concurrency)
        for raw_cell in cells:
            cell = mapping(raw_cell)
            rows = sequence(cell.get("rows"))
            measured.extend(rows)
            cell_integrity &= (isinstance(cell.get("rows"), list) and len(rows) == cell.get("calls") == calls
                               and sum(mapping(r).get("okay") is True for r in rows) == cell.get("successes"))
        for key, target, expected in (("initial_complete_outputs", initial, 6), ("restart_checks", restarted, 12)):
            values = sequence(row.get(key))
            target.extend(values)
            rounds_complete &= isinstance(row.get(key), list) and len(values) == expected
        for key in ("shutdown", "restart_shutdown"):
            value = row.get(key)
            if value is not None:
                shutdowns.append(value)
            rounds_complete &= isinstance(value, dict)
    if "interrupted_shutdown" in report:
        shutdowns.append(report["interrupted_shutdown"])
    all_rows = measured + initial + restarted
    checks = {
        "plan_dimensions_match": report.get("order") == order and report.get("calls_per_cell") == calls
            and report.get("concurrency") == concurrency and report.get("tokio_workers") == 2,
        "same_qualified_binary_in_both_driver_slots": report.get("binary_sha256") == {"A": binary, "B": binary},
        "all_requested_rounds_and_checks_present": bool(rounds_complete),
        "all_recorded_rounds_reported_passed": bool(rounds)
            and all(mapping(row).get("passed") is True for row in rounds),
        "all_recorded_shutdowns_clean_eof": bool(shutdowns)
            and all(normal_shutdown(value) is True for value in shutdowns),
        "cell_declared_counts_match_every_retained_row": bool(cell_integrity),
        "all_recorded_calls_succeeded": bool(all_rows) and all(mapping(row).get("okay") is True for row in all_rows),
        "zero_effects_and_retries_reported": all(report.get(key) == 0 for key in
            ("effect_starts", "remote_mutation_tool_calls", "automatic_rpc_retries")),
        "inputs_unchanged_reported": report.get("source_originals_unchanged") is True
            and report.get("binary_hashes_unchanged") is True,
        "raw_report_passed": report.get("passed") is True,
    }
    return {"present_and_parsed": True, "call_counts": counts(all_rows),
            "call_groups": {"measured": counts(measured), "initial_output_checks": counts(initial),
                            "restart_checks": counts(restarted)},
            "shutdown_receipts": len(shutdowns),
            "clean_eof_shutdowns": sum(normal_shutdown(value) is True for value in shutdowns),
            "checks": checks, "complete_success": all(checks.values())}


def event_valid(event):
    event = mapping(event)
    terminal = mapping(event.get("initial_terminal_probe")).get("kind")
    valid = (event.get("schema") == EVENT_SCHEMA and event.get("initial_proof_passed") is False
        and type(event.get("pidfd_available")) is bool and type(event.get("identity_matches")) is bool
        and terminal in {"exited", "not_exited", "error"}
        and event.get("pool_stop_cancelled_before_cleanup") is True
        and event.get("no_retry_or_fallback") is True
        and event.get("flush_after_owner_cleanup_returned") is True)
    return valid and not (event["pidfd_available"] and terminal != "error"
                          and (terminal == "exited" or event["identity_matches"]))


def scan_events(root, name, receipt, inputs):
    directory = root / name
    declared = mapping(mapping(receipt).get("stderr_evidence"))
    declared_logs = sequence(declared.get("logs"))
    retained = sequence(declared.get("events"))
    actual = {path.relative_to(directory).as_posix()
              for phase in ("first", "restart") for path in directory.glob("*/" + phase + "/stderr.log")}
    wanted = {mapping(row).get("path") for row in declared_logs}
    errors, observed, log_checks = [], [], []
    for relative in sorted(actual | {path for path in wanted if isinstance(path, str)}):
        if not LOG_NAME.fullmatch(relative):
            errors.append({"path": relative, "reason": "unexpected stderr path; not followed"})
            continue
        raw = inputs.read(directory / relative, name + "/" + relative, LOG_LIMIT, parse=False)
        expected = [row for row in declared_logs if mapping(row).get("path") == relative]
        actual_receipt = inputs.files[name + "/" + relative]
        log_checks.append({"path": relative, "original": actual_receipt,
                           "declared_hash_matches": len(expected) == 1 and receipt_matches(actual_receipt, expected[0])})
        if raw is None:
            errors.append({"path": relative, "reason": "stderr missing or unreadable; event count unknown"})
            continue
        for number, line in enumerate(raw.splitlines(), 1):
            if PREFIX.rstrip() not in line:
                continue
            evidence = {"path": relative, "line": number, "line_sha256": sha(line)}
            try:
                if not line.startswith(PREFIX):
                    raise ValueError("event prefix is not at line start")
                event = decode(line[len(PREFIX):])
                if not isinstance(event, dict):
                    raise ValueError("event is not an object")
                observed.append({**evidence, "event": event})
                if not event_valid(event):
                    raise ValueError("event schema or original failure predicate is inconsistent")
            except (ValueError, UnicodeError) as error:
                errors.append({**evidence, "reason": str(error)})
    expected_paths = {f"round-{i}-{label}/{phase}/stderr.log"
                      for i, label in enumerate(SPECS[name][0]) for phase in ("first", "restart")}
    checks = {
        "receipt_evidence_present": isinstance(mapping(receipt).get("stderr_evidence"), dict),
        "declared_event_count_matches_retained_events": declared.get("event_count") == len(retained),
        "every_observed_log_hash_matches_receipt": bool(log_checks) and all(row["declared_hash_matches"] for row in log_checks),
        "declared_and_actual_log_sets_equal": wanted == actual and len(declared_logs) == len(wanted),
        "parsed_events_equal_receipt_without_filtering": observed == retained,
        "no_parse_errors": not errors and not sequence(declared.get("errors")),
        "all_planned_controller_logs_present": actual == expected_paths and declared.get("missing_logs") == [],
        "receipt_collection_complete": declared.get("complete") is True,
    }
    return {"from_driver_receipt": retained, "from_stderr": observed,
            "parsing_errors": errors, "log_checks": log_checks, "checks": checks,
            "parsed_event_count": len(observed) if log_checks and not errors else None,
            "receipt_event_count": declared.get("event_count"), "complete": all(checks.values())}


def compressed(value):
    raw = canonical(value)
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0, compresslevel=9) as target:
        target.write(raw)
    return output.getvalue(), {"uncompressed_bytes": len(raw), "uncompressed_sha256": sha(raw)}


def create_only(path, raw):
    with path.open("xb") as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    return {"bytes": len(raw), "sha256": sha(raw)}


def build(args):
    inputs = Inputs()
    root = args.series.absolute().parent
    series = inputs.read(args.series, "series.json")
    qualification = inputs.read(args.qualification, "qualification.json")
    runner = inputs.read(args.runner, "runner.py", 1024 * 1024, parse=False)
    if not isinstance(series, dict) or series.get("schema") != SERIES_SCHEMA or not series.get("finished_utc"):
        raise ValueError("a completed D4 series.json with the exact schema is required")
    plan = inputs.read(root / "plan.json", "plan.json")
    before = inputs.read(root / "inputs-before.json", "inputs-before.json")
    qualification, plan, before = mapping(qualification), mapping(plan), mapping(before)
    binary = mapping(qualification.get("binary")).get("sha256")
    source = qualification.get("source_tested")
    source_digest = (sha(json.dumps(source, sort_keys=True, separators=(",", ":")).encode())
                     if valid_source_map(source) else None)
    checks = {
        "qualification_report_passed": qualification.get("schema") == "runtime-candidate-qualification/v1"
            and qualification.get("qualified") is True and qualification.get("service_changes") is False,
        "qualification_five_successful_stages": [mapping(s).get("name") for s in sequence(qualification.get("stages"))] == QUAL_STAGES
            and all(mapping(s).get("returncode") == 0 for s in sequence(qualification.get("stages"))),
        "qualified_source_maps_equal": source_digest is not None and source == qualification.get("source_after"),
        "d4_modules_bound_in_qualified_source": isinstance(source, dict)
            and all("src/mcp/runtime/" + name in source for name in
                    ("ssh_observation_spawn_diagnostic.rs", "ssh_observation_spawn_diagnostic_tests.rs")),
        "qualification_bound_by_inputs": receipt_matches(inputs.files["qualification.json"], before.get("qualification")),
        "source_map_bound_by_inputs": source_digest is not None and source == before.get("source_files")
            and source_digest == before.get("source_map_sha256"),
        "runner_bound_by_predeclared_plan": runner is not None and receipt_matches(inputs.files["runner.py"], plan.get("runner_source")),
        "plan_and_inputs_hash_bindings": receipt_matches(inputs.files["plan.json"], series.get("plan"))
            and receipt_matches(inputs.files["inputs-before.json"], plan.get("qualified_inputs_receipt")),
        "same_d4_binary_identity": isinstance(binary, str) and HEX256.fullmatch(binary) is not None
            and binary == plan.get("binary_sha256") == mapping(mapping(before.get("binaries")).get("binary")).get("sha256"),
        "same_binary_diagnostic_scope": series.get("same_binary_only") is True
            and plan.get("both_labels_use_same_binary") is True
            and series.get("performance_adoption") is False and series.get("performance_comparison_generated") is False,
    }
    stages, payloads = {}, {"series": series, "plan": plan, "inputs_before": before}
    recorded = sequence(series.get("stages"))
    for name, spec in SPECS.items():
        receipt = inputs.read(root / (name + ".receipt.json"), name + ".receipt.json")
        report = inputs.read(root / name / "report.json", name + "/report.json")
        summary = report_summary(report, spec, binary)
        events = scan_events(root, name, receipt, inputs) if receipt is not None or report is not None else None
        declarations = [row for row in recorded if mapping(row).get("stage") == name]
        present = any(inputs.files[key].get("present") for key in (name + ".receipt.json", name + "/report.json"))
        if not present:
            stopped = (name == "extended" and series.get("stopped_after") == "initial"
                       and mapping(stages.get("initial")).get("reported_gate_passed") is False)
            status = "not_run_initial_gate_failed" if stopped else "not_recorded"
        else:
            status = "recorded_success" if mapping(receipt).get("gate_passed") is True else "recorded_failure_or_incomplete"
        stage_checks = {
            "one_series_declaration": len(declarations) == 1,
            "series_and_receipt_gate_agree": len(declarations) == 1
                and mapping(declarations[0]).get("gate_passed") == mapping(receipt).get("gate_passed"),
            "report_hash_bound_by_receipt": receipt_matches(inputs.files[name + "/report.json"], mapping(receipt).get("raw_report")),
            "stage_name_matches": mapping(receipt).get("stage") == name,
            "inputs_before_and_after_equal": bool(before)
                and isinstance(mapping(receipt).get("inputs_after"), dict)
                and mapping(receipt).get("inputs_after") == before,
            "completed_driver_zero_exit": mapping(receipt).get("driver_exit_observed") is True
                and mapping(receipt).get("returncode") == 0 and mapping(receipt).get("interrupted") is False,
            "reported_gate_passed": mapping(receipt).get("gate_passed") is True,
            "every_recorded_and_requested_call_passed": summary["complete_success"],
            "complete_zero_event_collection": events is not None and events["complete"] and events["parsed_event_count"] == 0,
        }
        stages[name] = {"status": status, "reported_gate_passed": mapping(receipt).get("gate_passed"),
                        "report": summary, "events": events, "checks": stage_checks,
                        "independent_diagnostic_stage_passed": present and all(stage_checks.values())}
        payloads[name] = {"receipt": receipt, "report": report}
    checks["exact_initial_then_extended_series_records"] = [mapping(row).get("stage") for row in recorded] == list(SPECS)
    checks["conditional_extension_respected"] = (stages["extended"]["status"] == "not_run_initial_gate_failed"
        or stages["initial"]["independent_diagnostic_stage_passed"])
    checks["all_present_inputs_read_without_error"] = not inputs.errors
    recorded_report_stages = {mapping(row).get("stage") for row in recorded
                              if isinstance(mapping(row).get("stage"), str)}
    recorded_report_stages.update(name for name in SPECS
                                  if inputs.files[name + "/report.json"].get("present") is True)
    reports_preserved = bool(recorded_report_stages) and all(
        name in payloads and isinstance(payloads[name].get("report"), dict)
        for name in recorded_report_stages)
    clean = CompleteSanitizer({"payloads": payloads, "qualification": qualification, "stages": stages, "inputs": inputs.files})
    artifacts = {}
    args.output_dir.mkdir(mode=0o700, parents=False, exist_ok=False)

    def emit(name, value, compress=False):
        if compress:
            raw, extra = compressed(value)
        else:
            raw, extra = canonical(value), {}
        artifacts[name] = {**create_only(args.output_dir / name, raw), **extra}

    emit("series.complete.sanitized.json", clean({key: payloads[key] for key in ("series", "plan", "inputs_before")}))
    for name in SPECS:
        for kind in ("receipt", "report"):
            if payloads[name][kind] is not None:
                emit(name + "." + kind + ".complete.sanitized.json.gz", clean(payloads[name][kind], name), compress=True)
    emit("d4-events.complete.sanitized.json", {name: clean(stages[name]["events"], name) for name in SPECS})
    public_stages = {name: {key: value for key, value in stage.items() if key != "events"}
                     for name, stage in stages.items()}
    for name, stage in stages.items():
        evidence = stage["events"]
        public_stages[name]["event_collection"] = (None if evidence is None else
            {key: evidence[key] for key in ("receipt_event_count", "parsed_event_count", "complete", "checks")})
    summary = {
        "schema": "hepta-x230-d4-public-evidence/v1", "subject": "D4 diagnostic binary",
        "qualified_binary_sha256": binary, "qualified_source_map_sha256": source_digest,
        "qualification_input": inputs.files["qualification.json"], "runner_input": inputs.files["runner.py"],
        "builder_sha256": sha(Path(__file__).read_bytes()),
        "sanitizer_source_sha256": sha((Path(__file__).parent / "build_x230_evidence.py").read_bytes()),
        "driver_slot_labels": {"A": "same D4 binary, driver slot A", "B": "same D4 binary, driver slot B"},
        "source_or_binary_alias_to_other_candidate": False,
        "performance_comparison_generated": False, "performance_adoption": False,
        "raw_series_diagnostic_gate_passed": series.get("diagnostic_gate_passed"),
        "independent_diagnostic_gate_passed": all(checks.values())
            and all(stage["independent_diagnostic_stage_passed"] for stage in stages.values())
            and series.get("diagnostic_gate_passed") is True,
        "verification": checks, "stages": public_stages, "raw_inputs": inputs.files,
        "input_errors": inputs.errors, "public_artifacts": artifacts,
        "preservation": {"all_recorded_report_rows_retained": reports_preserved,
                         "all_parsed_receipt_events_retained": True,
                         "unexecuted_or_missing_stages_not_fabricated": True,
                         "raw_pid_values_published": False,
                         "owned_child_labels_scoped_to_stage_and_controller_log": True},
        "limitations": ["Only supplied completed artifacts are verified; no binaries, tests, or RPCs are executed.",
                        "Input file hashes bind received bytes; qualification/source persistence is handled separately.",
                        "Missing or unreadable stderr cannot support a zero-event claim.",
                        "Report call preservation covers rows the frozen driver recorded, not unrecorded calls lost before its report write.",
                        "Receipt and independent stderr events are separate copies of evidence and must not be summed.",
                        "A passing diagnostic workload does not explain earlier incidents or justify performance adoption."]}
    create_only(args.output_dir / "summary.json", canonical(clean(summary)))
    descriptor = os.open(args.output_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("series", "qualification", "runner", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args(argv)
    if os.path.lexists(args.output_dir):
        parser.error("output directory must be fresh")
    try:
        result = build(args)
    except (OSError, ValueError, TypeError) as error:
        print(json.dumps({"publication_completed": False, "error_type": type(error).__name__,
                          "message": Sanitizer({})(str(error))}), file=sys.stderr)
        return 2
    print(json.dumps({"publication_completed": True,
                      "independent_diagnostic_gate_passed": result["independent_diagnostic_gate_passed"],
                      "performance_comparison_generated": False}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
