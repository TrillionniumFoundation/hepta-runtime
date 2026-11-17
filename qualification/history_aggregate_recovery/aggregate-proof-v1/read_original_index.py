#!/usr/bin/env python3
"""Read the complete frozen original index ZIP and copy its exact failed report."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import time
import zipfile

ZIP_BYTES = 90869688
ZIP_SHA = "a0f581904dba96b2959da711542fded9f716e03c54d71ff924e737fbb5ae2a37"
REPORT_BYTES = 94614535
REPORT_SHA = "6159169d8c0763d2418c8f625e5cd67099a06179f69927f7a1e62972a1eafa41"
INDEX = "history-aggregate-index/tar-index.jsonl.gz"
INDEX_SHA = "ad4d01ef4fa926526bc0483a6160d0d9453e8529b8b2c770fe03d2345c3edf40"


def need(value, label):
    if not value:
        raise ValueError(label)


def identity(stream, output=None):
    digest = hashlib.sha256()
    count = 0
    while block := stream.read(1 << 20):
        digest.update(block)
        count += len(block)
        if output is not None:
            need(output.write(block) == len(block), "short report output")
    return {"bytes": count, "sha256": digest.hexdigest()}


def metadata(path):
    info = path.lstat()
    return tuple(getattr(info, key) for key in
                 ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    start = time.monotonic_ns()
    before = metadata(args.zip)
    need(stat.S_ISREG(before[2]) and args.zip.absolute().resolve() == args.zip.absolute(),
         "ordinary original ZIP")
    with args.zip.open("rb") as stream:
        need(identity(stream) == {"bytes": ZIP_BYTES, "sha256": ZIP_SHA}, "complete original ZIP pin")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    members = []
    names = set()
    with zipfile.ZipFile(args.zip) as archive:
        for item in archive.infolist():
            path = PurePosixPath(item.filename)
            need(not path.is_absolute() and str(path) == item.filename.rstrip("/")
                 and all(part not in ("", ".", "..") for part in path.parts)
                 and item.filename not in names, "unique canonical ZIP member")
            names.add(item.filename)
            mode = item.external_attr >> 16
            need(not stat.S_ISLNK(mode) and not item.flag_bits & 1, "ordinary unencrypted ZIP member")
            with archive.open(item) as stream:
                pin = identity(stream)
            need(pin["bytes"] == item.file_size, "complete ZIP member and CRC")
            members.append({"path": item.filename, "mode": mode, "directory": item.is_dir(), **pin})
        rows = [row for row in members if row["path"] == INDEX]
        need(len(rows) == 1 and rows[0]["sha256"] == INDEX_SHA, "complete original TAR index")
        reports = [row for row in members if row["bytes"] == REPORT_BYTES and row["sha256"] == REPORT_SHA]
        need(len(reports) == 1 and reports[0]["directory"] is False, "one exact original failed report")
        with archive.open(reports[0]["path"]) as stream, (args.output / "original-result.json").open("xb") as out:
            need(identity(stream, out) == {"bytes": REPORT_BYTES, "sha256": REPORT_SHA},
                 "entire exact failed report copy")
    need(metadata(args.zip) == before, "original ZIP bytes and metadata unchanged")
    result = {
        "schema": "hepta.history.original-index-complete-read.v1",
        "status": "COMPLETE_ORIGINAL_INDEX_AND_REPORT_READBACK_PASS",
        "zip": {"bytes": ZIP_BYTES, "sha256": ZIP_SHA}, "members": members,
        "original_report": reports[0], "input_zip_unchanged": True,
        "native_or_rust_executions": 0, "original_failure_reclassified_as_pass": False,
        "elapsed_ns": time.monotonic_ns() - start,
    }
    with (args.output / "INDEX_READBACK.json").open("xb") as out:
        out.write((json.dumps(result, sort_keys=True, indent=2) + "\n").encode())
    print(json.dumps({key: value for key, value in result.items() if key != "members"}, sort_keys=True))


if __name__ == "__main__":
    main()
