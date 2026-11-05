#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Verify complete fixed R29 performance originals without running archived code."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

HERE = Path(__file__).resolve().parent
EXPORTER_SHA256 = 'c9fd58c7aaebd51f60f1a2fdc3a01c52629b41d5a5818be124c79a547735872e'
HELPER_SHA256 = "8b7aa7ef3b3772da13ea4f7009d8c478e0c92bc207d65db3f45c23453097d7a2"
MONITOR_VALIDATOR_SHA256 = "d2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2"

def need(value, reason):
    if not value:
        raise ValueError(reason)

def digest(body):
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}

def local_read(path, maximum=16 * 1024**2):
    need(path.is_absolute() and path.resolve(strict=True) == path, "direct local original input required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
             "unsafe or oversized local metadata")
        body = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    final = path.lstat()
    need(len(body) == before.st_size and all(getattr(before, k) == getattr(after, k) == getattr(final, k)
                                           for k in fields), "local original input changed")
    return body

def reviewed(filename, expected):
    need(isinstance(expected, str) and len(expected) == 64, "reviewed source remains unbound")
    path = HERE / filename
    raw = local_read(path)
    need(digest(raw)["sha256"] == expected, "reviewed local source differs")
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(filename, loader=None))
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module

def original_capture(terminal_raw, read_raw, report_raw, report_path, original):
    terminal, read = json.loads(terminal_raw), json.loads(read_raw)
    need(isinstance(terminal, dict) and isinstance(read, dict), "original capture DTO objects required")
    outcome = original.validate_terminal(terminal, terminal.get("job_id"))
    need(outcome["state"] == "succeeded" and outcome["exit_code"] == 0
         and outcome["native_logs_lossless_complete"] is True
         and original.JOB.fullmatch(terminal["job_id"]), "original capture did not complete successfully")
    need(read["job_id"] == terminal["job_id"] and read.get("audit_recorded") is True,
         "original capture read belongs to another native operation")
    bodies = {}
    for stream in ("stdout", "stderr"):
        row = read[stream]
        body = bytes.fromhex(row["bytes_hex"])
        need(row["offset"] == 0 and row["eof"] is True
             and row["next_offset"] == row["size"] == len(body)
             and row["text"].encode("utf-8") == body
             and terminal["log_bytes"][stream]["seen"] == terminal["log_bytes"][stream]["stored"] == len(body),
             "original single full capture stream is incomplete or reencoded")
        bodies[stream] = body
    need(bodies["stderr"] == b"", "original exporter has unexpected stderr")
    footer = json.loads(bodies["stdout"])
    need(footer["passed"] is True and footer["candidate_adopted"] is False
         and footer["no_workload_executed"] is True
         and footer["report"]["source_path"] == report_path
         and all(footer["report"][k] == digest(report_raw)[k] for k in ("bytes", "sha256")),
         "original capture footer does not bind this exact report")
    return {"job_id": terminal["job_id"], "native_outcome": outcome,
            "native_terminal": digest(terminal_raw), "native_read": digest(read_raw),
            "stdout": digest(bodies["stdout"]), "stderr": digest(bodies["stderr"])}

def expected_source(name, original):
    path = PurePosixPath(name)
    original.need(not path.is_absolute() and len(path.parts) >= 2 and ".." not in path.parts,
                  "unsafe original archive namespace")
    label, relative = path.parts[0], PurePosixPath(*path.parts[1:])
    if label in original.DIRECTORIES:
        return original.DIRECTORIES[label] / str(relative)
    if label == "root-receipts":
        need(len(path.parts) == 2 and str(relative) in original.ROOT_FILES, "unknown fixed root receipt")
        return original.ROOT / str(relative)
    if label == "fixed-support":
        need(str(relative) in original.FIXED_SUPPORT, "unknown fixed support member")
        return original.FIXED_SUPPORT[str(relative)]
    if label == "qualification-reference":
        p = original.ROOT / str(relative)
        need(str(p) in original.QUALIFICATION_REFERENCES, "unknown small qualification reference")
        return p
    if label == "native-terminals":
        matching = [p for p in original.NATIVE_PATHS.values() if p.name == str(relative)]
        need(len(path.parts) == 2 and len(matching) == 1, "unknown original native terminal namespace")
        return matching[0]
    if label == "capture-tools":
        names = {"export_r29_performance_01.py": original.EXPORTER,
                 "stable_xz_archive.py": original.HELPER, "actual-input.json": original.INPUT}
        need(len(path.parts) == 2 and str(relative) in names, "unknown capture tool")
        return names[str(relative)]
    raise ValueError("archive member escaped fixed performance scope")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--export-report", required=True, type=Path)
    parser.add_argument("--report-sha256", required=True)
    parser.add_argument("--capture-native-terminal", required=True, type=Path)
    parser.add_argument("--capture-native-read", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    need(args.out.is_absolute() and args.out.parent.resolve(strict=True) == args.out.parent
         and not os.path.lexists(args.out), "fresh direct local verification receipt required")
    original = reviewed("export_r29_performance_01.py", EXPORTER_SHA256)
    helper = reviewed("stable_xz_archive.py", HELPER_SHA256)
    validator = reviewed("validate_compiler_monitor.py", MONITOR_VALIDATOR_SHA256)
    report_raw = local_read(args.export_report)
    need(digest(report_raw)["sha256"] == args.report_sha256, "original export report identity differs")
    report = json.loads(report_raw)
    need(report["schema"] == "hepta-r29-performance-evidence-export/v1" and report["passed"] is True
         and report["exporter"]["sha256"] == EXPORTER_SHA256
         and report["archive_helper"]["sha256"] == HELPER_SHA256
         and report["no_workload_executed"] is True and report["candidate_adopted"] is False
         and report["original_inputs_unchanged"] is True and report["original_outcomes_preserved"] is True,
         "incomplete or different original exporter")
    terminal_raw, read_raw = local_read(args.capture_native_terminal), local_read(args.capture_native_read)
    capture = original_capture(terminal_raw, read_raw, report_raw, str(original.OUT / "report.json"), original)
    archive_identity = helper.read(args.archive)[0]
    need(all(archive_identity[k] == report["archive"]["identity"][k] for k in ("bytes", "sha256")),
         "downloaded archive identity differs from actual capture")
    manifest_raw = helper.manifest_from_archive(args.archive, {k: report["manifest"][k] for k in ("bytes", "sha256")})
    manifest = json.loads(manifest_raw)
    need(manifest["schema"] == "hepta-r29-performance-archive-manifest/v1"
         and manifest["root"] == str(original.ROOT) and manifest["archive_name"] == original.ARCHIVE_NAME
         and manifest["exporter"] == report["exporter"] and manifest["archive_helper"] == report["archive_helper"]
         and manifest["input"] == report["input"] and manifest["candidate_adopted"] is False,
         "fixed embedded manifest differs")
    files, omissions = manifest["payloads"], manifest["omissions"]
    need(set(files).isdisjoint(omissions) and len(files) == report["payload_count"]
         and len(omissions) == report["omission_count"], "original payload/omission counts differ")
    verification = helper.verify_archive(args.archive, manifest_raw, files)
    expanded, _ = helper.expanded_xz(args.archive, archive_identity)
    identities, by_source = {}, {}
    for name, identity in files.items():
        path = expected_source(name, original)
        need(identity["source_path"] == str(path) and str(path) not in identities
             and identity["is_elf"] is False and original.omission_reason(path, "performance", identity) is None,
             "unsafe, duplicate or wrongly included original payload")
        identities[str(path)], by_source[str(path)] = identity, name
    for name, row in omissions.items():
        path, identity = expected_source(name, original), row["identity"]
        need(identity["source_path"] == str(path) and str(path) not in identities
             and row["reason"] == original.omission_reason(path, "performance", identity)
             and row["reason"] is not None, "unjustified or duplicate omission")
        identities[str(path)] = identity
    expected_directories = {str(p) for p in original.DIRECTORIES.values()}
    recorded_directories = set(manifest["fixed_directory_inventories"])
    absent = set(manifest["observed_absent_paths"])
    need(len(absent) == len(manifest["observed_absent_paths"])
         and recorded_directories <= expected_directories
         and recorded_directories.isdisjoint(absent)
         and recorded_directories | (absent & expected_directories) == expected_directories
         and {str(original.DIRECTORIES[name]) for name in original.REQUIRED_DIRECTORIES} <= recorded_directories,
         "fixed original directories lack exact inventory/absence coverage")
    for path, identity in identities.items():
        stamp = identity["original_identity"]
        need(stat.S_ISREG(stamp["st_mode"]) and stamp["st_uid"] == 1000 and stamp["st_nlink"] == 1
             and stamp["st_size"] == identity["bytes"] and 0 <= identity["bytes"] <= helper.MAX_FILE_BYTES,
             "original descriptor is outside the owned regular-file contract")
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        def body(path):
            name = by_source.get(str(path))
            need(name is not None, "required original body was omitted or absent: " + str(path))
            item = archive.getmember(name)
            need(item.size <= helper.MAX_RETAIN_BYTES, "oversized original JSON/source body")
            return archive.extractfile(item).read()
        def get_json(path):
            return json.loads(body(path))
        input_raw = body(original.INPUT)
        need(digest(input_raw) == {k: report["input"][k] for k in ("bytes", "sha256")}, "original input body differs")
        value = json.loads(input_raw)
        declarations = original.validate_input(value)
        need(declarations == manifest["declarations"], "original declaration changed in manifest")
        outcomes, original_reports = {}, {}
        for name in original.STAGES:
            row = declarations[name]
            native, result = None, None
            if row["executed"]:
                native_raw = body(original.NATIVE_PATHS[name])
                need(digest(native_raw) == {k: row["native_terminal"][k] for k in ("bytes", "sha256")},
                     "original native terminal pin differs")
                native = json.loads(native_raw)
                if row["report"] is not None:
                    raw = body(original.REPORT_PATHS[name])
                    need(digest(raw) == {k: row["report"][k] for k in ("bytes", "sha256")}, "original report pin differs")
                    try:
                        result = json.loads(raw)
                    except (ValueError, UnicodeError):
                        pass
                original_reports[name] = result
            outcomes[name] = original.original_outcome(name, row, native, result)
        need(outcomes == manifest["original_outcomes"] == report["original_outcomes"], "original outcome was promoted or changed")
        need(digest(body(original.ROOT / "tools-01/validate_compiler_monitor.py"))["sha256"] == MONITOR_VALIDATOR_SHA256,
             "archived pure validator differs from the reviewed local source")
        monitors = {name: original.inspect_monitor(name, original_reports.get(name), get_json, identities, validator)
                    for name in original.STAGES if declarations[name]["executed"]}
        need(monitors == report["compiler_monitor_verification"] == manifest["compiler_monitor_verification"],
             "source-bound independent original monitor verification differs")
        bindings = original.check_original_bindings(get_json, identities, declarations, outcomes, monitors)
        classification = original.disposition(outcomes, monitors, bindings)
        need(classification == report["candidate_disposition"] == manifest["candidate_disposition"],
             "original performance disposition was promoted or changed")
        need(bindings == report["original_bindings"] == manifest["original_bindings"], "original producer log/source bindings differ")
        need(digest(body(original.EXPORTER))["sha256"] == EXPORTER_SHA256
             and digest(body(original.HELPER))["sha256"] == HELPER_SHA256, "archived capture source differs")
    for label, directory in original.DIRECTORIES.items():
        if str(directory) not in manifest["fixed_directory_inventories"]:
            need(str(directory) in absent and not any(p == str(directory) or p.startswith(str(directory) + "/") for p in identities),
                 "absent original directory has payloads or no absence proof")
            continue
        expected = manifest["fixed_directory_inventories"][str(directory)]
        names = sorted(str(expected_source(name, original)) for name in set(files) | set(omissions)
                       if name.startswith(label + "/"))
        need(expected["files"] == names, "full original directory inventory differs")
    for path in original.required_absent_paths(declarations):
        need(str(path) in manifest["observed_absent_paths"]
             and not any(p == str(path) or p.startswith(str(path) + "/") for p in identities),
             "unexecuted lifecycle output has no original absence proof or has payloads")
    for filename in original.ROOT_FILES:
        path = str(original.ROOT / filename)
        need(path in identities or filename in original.OPTIONAL_ROOT_FILES and path in manifest["observed_absent_paths"],
             "fixed root receipt or explicit optional absence is missing")
    allowed_absent = expected_directories | {str(original.ROOT / name) for name in original.OPTIONAL_ROOT_FILES}
    allowed_absent |= {str(p) for p in original.required_absent_paths(declarations)}
    need(absent <= allowed_absent and report["actual_output_inventory_and_absence_verified"] is True,
         "original absence proof escaped its exact fixed scope")
    for name in original.STAGES:
        if not declarations[name]["executed"]:
            need(str(original.NATIVE_PATHS[name]) not in identities, "unsubmitted native terminal was invented")
    need(helper.read(args.archive)[0] == archive_identity, "downloaded archive changed")
    for path, raw in ((args.export_report, report_raw), (args.capture_native_terminal, terminal_raw),
                      (args.capture_native_read, read_raw)):
        need(local_read(path) == raw, "original local capture metadata changed")
    result = {"schema": "hepta-r29-performance-independent-verification/v1", "passed": True,
              "archive": {k: archive_identity[k] for k in ("bytes", "sha256")},
              "manifest": digest(manifest_raw), "archive_validation": verification,
              "original_capture": capture, "original_outcomes": outcomes, "original_bindings": bindings,
              "compiler_monitor_verification": monitors, "candidate_disposition": classification,
              "original_outcomes_preserved": True, "actual_output_inventory_and_absence_verified": True,
              "native_original_raw_and_Mac_companions_still_required": True,
              "qualification_ci_full_companion_still_required": True,
              "candidate_adopted": False, "hosted_CI_passed_inferred": False,
              "archive_code_executed": False, "archive_extracted": False, "remote_operations": 0,
              "original_export_report": digest(report_raw), "exporter_sha256": EXPORTER_SHA256,
              "archive_helper_sha256": HELPER_SHA256, "pure_monitor_validator_sha256": MONITOR_VALIDATOR_SHA256}
    helper.create(args.out, helper.encode(result))
    print(json.dumps({"passed": True, "verification": {"path": str(args.out), **digest(helper.encode(result))},
                      "regular_members": verification["regular_members"], "candidate_adopted": False}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
