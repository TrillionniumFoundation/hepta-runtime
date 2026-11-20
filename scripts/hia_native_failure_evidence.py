#!/usr/bin/env python3
"""Retain failed CI output without following or changing owned fixture links.

Diagnostics are copied before attempting the complete tar archive. Archive
failure remains a nonzero result, with its real receipt and partial bytes kept
beside the diagnostics. This helper does not qualify a failed test as passing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import time


SCHEMA = "hepta.runtime.native-failure-evidence.v1"
EXCERPT_BYTES = 4096
ARCHIVE_TIMEOUT_SECONDS = 120


def encode(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode()


def save(path, value):
    with path.open("xb") as stream:
        stream.write(encode(value))


def error_record(error):
    return {"type": type(error).__name__, "message": str(error)}


def metadata(value):
    return {"dev": value.st_dev, "inode": value.st_ino,
            "mode": value.st_mode, "nlink": value.st_nlink,
            "size": value.st_size, "mtime_ns": value.st_mtime_ns,
            "ctime_ns": value.st_ctime_ns}


def pin(path):
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode):
        raise ValueError("expected an ordinary retained file: " + str(path))
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    if metadata(path.lstat()) != metadata(value) or size != value.st_size:
        raise ValueError("retained file changed while hashing: " + str(path))
    return {"bytes": size, "sha256": digest.hexdigest()}


def copy_diagnostic(source, destination):
    result = {"source": str(source), "destination": "diagnostics/" + source.name,
              "complete": False, "error": None, "copy": None}
    try:
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("selected diagnostic is not a regular file")
        result["source_before"] = metadata(before)
        descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as reader:
            if metadata(os.fstat(reader.fileno())) != metadata(before):
                raise ValueError("diagnostic changed before opening")
            with destination.open("xb") as writer:
                for chunk in iter(lambda: reader.read(1 << 20), b""):
                    writer.write(chunk)
            after = os.fstat(reader.fileno())
        result["source_after"] = metadata(source.lstat())
        result["copy"] = pin(destination)
        if (metadata(after) != metadata(before)
                or result["source_after"] != metadata(before)
                or result["copy"]["bytes"] != before.st_size):
            raise ValueError("diagnostic changed while copying")
        result["complete"] = True
    except (OSError, ValueError) as error:
        result["error"] = error_record(error)
        if destination.is_file() and not destination.is_symlink():
            result["copy"] = pin(destination)
    return result


def excerpt(path):
    size = path.stat().st_size
    with path.open("rb") as stream:
        head = stream.read(EXCERPT_BYTES)
        tail_offset = max(len(head), size - EXCERPT_BYTES)
        stream.seek(tail_offset)
        tail = stream.read(EXCERPT_BYTES)
    return {"encoding": "UTF-8 with backslash replacement; JSON escaped",
            "head_offset": 0, "head_bytes": len(head),
            "head": head.decode("utf-8", "backslashreplace"),
            "tail_offset": tail_offset, "tail_bytes": len(tail),
            "tail": tail.decode("utf-8", "backslashreplace"),
            "truncated": len(head) + len(tail) < size,
            "omitted_bytes": max(0, tail_offset - len(head))}


def print_failure_checks(diagnostics, output):
    summaries = []
    for name, item in diagnostics.items():
        if not name.endswith(".json") or not item["complete"]:
            continue
        try:
            report = json.loads((output / item["destination"]).read_bytes())
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(report, dict) or not isinstance(report.get("checks"), list):
            continue
        for check in report["checks"]:
            if not isinstance(check, dict):
                continue
            failed = (bool(check.get("start_error")) or check.get("timed_out") is True
                      or (type(check.get("exit_code")) is int and check["exit_code"] != 0))
            if not failed:
                continue
            summary = {"source_report": name, "check": check.get("name"),
                       "exit_code": check.get("exit_code"), "timed_out": check.get("timed_out"),
                       "start_error": check.get("start_error"), "streams": {}}
            check_name = check.get("name")
            for stream in ("stdout", "stderr"):
                stream_name = str(check_name) + "." + stream
                retained = diagnostics.get(stream_name)
                if retained is None or not retained["complete"]:
                    summary["streams"][stream] = {"complete": False, "retained": retained}
                    continue
                actual = retained["copy"]
                summary["streams"][stream] = {
                    "complete": True, "retained_path": retained["destination"], **actual,
                    "recorded_hash_matches": actual["sha256"] == check.get(stream + "_sha256"),
                    "recorded_size_matches": actual["bytes"] == check.get(stream + "_bytes"),
                    "excerpt": excerpt(output / retained["destination"])}
            summaries.append(summary)
            # A single escaped JSON line cannot inject a GitHub workflow command.
            print("HIA_FAILED_CHECK " + json.dumps(summary, ensure_ascii=True, sort_keys=True), flush=True)
    return summaries


def archive(source, output):
    target = output / "failure-evidence.tar"
    tool = Path("/usr/bin/tar")
    argv = [str(tool), "--format=pax", "--create", "--file", str(target),
            "--directory", str(source), "--", "."]
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
    result = {"argv": argv, "cwd": str(output), "environment": environment,
              "deadline_seconds": ARCHIVE_TIMEOUT_SECONDS, "pid": None,
              "exit_code": None, "timed_out": False, "error": None,
              "source_links_dereferenced": False, "fixture_permissions_changed": False,
              "complete": False, "archive": None}
    started = time.monotonic_ns()
    result["started_unix_ns"] = time.time_ns()
    process = None
    try:
        if source.resolve(strict=True) != source or not stat.S_ISDIR(source.lstat().st_mode):
            raise ValueError("archive source must be an existing canonical directory")
        result["tool"] = {"path": str(tool), **pin(tool)}
        with (output / "tar.stdout").open("xb") as stdout, (output / "tar.stderr").open("xb") as stderr:
            process = subprocess.Popen(argv, cwd=output, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            result["pid"] = process.pid
            try:
                process.wait(timeout=ARCHIVE_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
                process.kill()
                process.wait()
            result["exit_code"] = process.returncode
        result["tool_after"] = {"path": str(tool), **pin(tool)}
    except (OSError, ValueError) as error:
        result["error"] = error_record(error)
    result["finished_unix_ns"] = time.time_ns()
    result["duration_ns"] = time.monotonic_ns() - started
    # Keep the actual process outcome in the job log before the potentially
    # long full-archive hash and member scan. A later archive/upload failure
    # must not erase whether this particular attempt reached its own deadline.
    print("HIA_ARCHIVE_PROCESS " + json.dumps({
        "source": str(source), "output": str(output), "argv": result["argv"],
        "pid": result["pid"], "deadline_seconds": result["deadline_seconds"],
        "started_unix_ns": result["started_unix_ns"],
        "finished_unix_ns": result["finished_unix_ns"],
        "duration_ns": result["duration_ns"], "timed_out": result["timed_out"],
        "exit_code": result["exit_code"], "error": result["error"]},
        ensure_ascii=True, sort_keys=True), flush=True)
    for stream in ("stdout", "stderr"):
        path = output / ("tar." + stream)
        if not path.exists():
            path.write_bytes(b"")
        result[stream] = {"path": path.name, **pin(path)}
    if target.exists():
        result["archive"] = {"path": target.name, **pin(target)}
        try:
            with tarfile.open(target, "r:") as retained:
                members = retained.getmembers()
            result["tar_members"] = len(members)
            result["symlink_members"] = sum(member.issym() for member in members)
            result["fifo_members"] = sum(member.isfifo() for member in members)
        except (tarfile.TarError, OSError) as error:
            result["archive_read_error"] = error_record(error)
    # GNU tar can warn about an omitted socket while returning zero. Such a
    # package is explicitly incomplete too; do not suppress warnings or errors.
    result["complete"] = (result["exit_code"] == 0 and not result["timed_out"]
                          and result["error"] is None and result["archive"] is not None
                          and "archive_read_error" not in result
                          and result["stderr"]["bytes"] == 0
                          and result.get("tool_after") == result.get("tool"))
    save(output / "tar.process.json", result)
    return result


def retain(source, output):
    source, output = Path(source).absolute(), Path(output).absolute()
    if output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError("failure package and source must be separate directories")
    if output.resolve(strict=False) != output:
        raise ValueError("failure package path has a symlink ancestor")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    if output.resolve(strict=True) != output:
        raise ValueError("failure package path has a symlink ancestor")
    (output / "diagnostics").mkdir(mode=0o700)
    report = {"schema": SCHEMA, "status": "INCOMPLETE", "source": str(source),
              "output": str(output), "diagnostics": {}, "diagnostic_scan_error": None,
              "archive": None, "failed_checks": [], "source_snapshot_guaranteed": False,
              "fixture_permissions_changed": False, "source_links_dereferenced": False,
              "original_failure_reclassified_as_pass": False}
    save(output / "initial.json", report)
    try:
        if source.resolve(strict=True) != source or not stat.S_ISDIR(source.lstat().st_mode):
            raise ValueError("failure source must be an existing canonical directory")
        for path in sorted(source.iterdir()):
            selected = path.name.endswith((".json", ".stdout", ".stderr", "-failure.txt"))
            if selected:
                report["diagnostics"][path.name] = copy_diagnostic(path, output / "diagnostics" / path.name)
    except (OSError, ValueError) as error:
        report["diagnostic_scan_error"] = error_record(error)
    save(output / "diagnostics.json", {"files": report["diagnostics"],
                                       "scan_error": report["diagnostic_scan_error"]})
    report["failed_checks"] = print_failure_checks(report["diagnostics"], output)
    report["archive"] = archive(source, output)
    diagnostics_complete = (report["diagnostic_scan_error"] is None
                            and all(row["complete"] for row in report["diagnostics"].values()))
    report["diagnostics_complete"] = diagnostics_complete
    if diagnostics_complete and report["archive"]["complete"]:
        report["status"] = "COMPLETE"
    save(output / "manifest.json", report)
    print("HIA_FAILURE_EVIDENCE " + json.dumps({
        "status": report["status"], "manifest": str(output / "manifest.json"),
        "diagnostics_complete": diagnostics_complete, "archive_complete": report["archive"]["complete"],
        "tar_exit_code": report["archive"]["exit_code"],
        "tar_timed_out": report["archive"]["timed_out"],
        "tar_duration_ns": report["archive"]["duration_ns"],
        "tar_error": report["archive"]["error"],
        "tar_process": {"path": str(output / "tar.process.json"),
                        **pin(output / "tar.process.json")},
        "original_failure_reclassified_as_pass": False}, sort_keys=True), flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    report = retain(args.source, args.output)
    return 0 if report["status"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
