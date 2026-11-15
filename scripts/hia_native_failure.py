#!/usr/bin/env python3
"""Preserve failure diagnostics without traversing or changing effect fixtures.

This is a diagnostic subset, never qualification evidence. The original failure,
fixture permissions and complete evidence remain untouched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


EXCLUDED_DIRECTORIES = frozenset(("fixture", "owned-mutation-fixture", "target", "build"))
DIAGNOSTIC_SUFFIXES = (".json", ".jsonl", ".json.gz", ".jsonl.gz", ".stdout", ".stderr",
                      ".stdout.log", ".stderr.log", ".stdout.gz", ".stderr.gz", ".log")


def capture(source: Path, destination: Path) -> dict:
    source, destination = Path(source).absolute(), Path(destination).absolute()
    actual_source, actual_destination = source.resolve(), destination.resolve()
    if (actual_source == actual_destination or actual_source in actual_destination.parents
            or actual_destination in actual_source.parents):
        raise ValueError("diagnostic destination must be separate from the evidence tree")
    destination.mkdir(parents=True, exist_ok=False)
    data = destination / "data"
    data.mkdir()
    receipt = {"schema": "hepta.runtime.failure-diagnostics.v1",
               "source": str(source), "diagnostic_subset_only": True,
               "qualification_admitted": False, "files": {}, "skipped": [], "errors": []}

    def error(path, reason):
        receipt["errors"].append({"path": str(path), "error": repr(reason)})

    def onerror(reason):
        error(getattr(reason, "filename", None), reason)

    def skip(path, reason):
        receipt["skipped"].append({"path": str(path), "reason": reason})

    root_fd = None
    try:
        root_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for folder, directories, files, folder_fd in os.fwalk(
                ".", topdown=True, onerror=onerror, follow_symlinks=False, dir_fd=root_fd):
            relative = Path(folder)
            retained = []
            for name in sorted(directories):
                path = relative / name
                try:
                    mode = os.stat(name, dir_fd=folder_fd, follow_symlinks=False).st_mode
                    if stat.S_ISLNK(mode):
                        skip(path, "symlink")
                    elif name in EXCLUDED_DIRECTORIES:
                        skip(path, "effect fixture or build directory")
                    else:
                        retained.append(name)
                except OSError as reason:
                    error(path, reason)
            directories[:] = retained
            for name in sorted(files):
                path = relative / name
                if not name.endswith(DIAGNOSTIC_SUFFIXES):
                    continue
                descriptor = None
                try:
                    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                         dir_fd=folder_fd)
                    before = os.fstat(descriptor)
                    if not stat.S_ISREG(before.st_mode):
                        skip(path, "not a regular file")
                        continue
                    copied = data / path
                    copied.parent.mkdir(parents=True, exist_ok=True)
                    digest, size = hashlib.sha256(), 0
                    with copied.open("xb") as output:
                        while block := os.read(descriptor, 1 << 20):
                            output.write(block)
                            digest.update(block)
                            size += len(block)
                    after = os.fstat(descriptor)
                    receipt["files"][path.as_posix()] = {
                        "bytes": size, "sha256": digest.hexdigest(),
                        "source_mode": stat.S_IMODE(before.st_mode)}
                    identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                              value.st_mtime_ns, value.st_ctime_ns)
                    if identity(before) != identity(after) or size != before.st_size:
                        error(path, ValueError("source changed during diagnostic capture"))
                except OSError as reason:
                    error(path, reason)
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
    except OSError as reason:
        error(source, reason)
    finally:
        if root_fd is not None:
            os.close(root_fd)

    report_path = data / "result.json"
    if report_path.is_file() and report_path.stat().st_size <= 8 << 20:
        try:
            report = json.loads(report_path.read_bytes())
            if isinstance(report, dict):
                receipt["original_status"] = report.get("status")
                receipt["original_failure"] = report.get("failure")
                receipt["failed_checks"] = [
                    {key: row[key] for key in ("name", "exit_code", "timed_out", "start_error")
                     if key in row}
                    for row in report.get("checks", []) if isinstance(row, dict)
                    and (row.get("timed_out") or row.get("start_error")
                         or row.get("exit_code") not in (None, 0))]
        except (ValueError, UnicodeError) as reason:
            error("result.json", reason)
    receipt["status"] = "DIAGNOSTICS_CAPTURED"
    receipt["capture_errors"] = len(receipt["errors"])
    (destination / "capture.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    receipt = capture(args.source, args.destination)
    summary = {key: value for key, value in receipt.items() if key not in ("files", "skipped", "errors")}
    summary["copied_files"] = len(receipt["files"])
    summary["skipped_paths"] = len(receipt["skipped"])
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
