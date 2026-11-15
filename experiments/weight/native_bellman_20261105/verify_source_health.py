#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Recheck the qualified source/lockfile/executable after one execution phase."""

import argparse
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath


def measured(path):
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    assert tuple(getattr(before, field) for field in fields) == tuple(getattr(after, field) for field in fields)
    return {"bytes": after.st_size, "sha256": digest.hexdigest(), "stable_during_read": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["root", "binary", "qualification", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--phase", choices=["trust_regression", "journal_contract", "bellman_corpus"], required=True)
    args = parser.parse_args()
    qualification_bytes = args.qualification.read_bytes()
    qualification = json.loads(qualification_bytes)
    assert qualification["passed"] and qualification["completed"] and qualification["source_unchanged_after_format"]
    rows = []
    for expected in qualification["source_after_last_command"]:
        path = PurePosixPath(expected["path"])
        assert not path.is_absolute() and ".." not in path.parts and str(path).startswith("src/mcp/")
        actual = measured(args.root / path)
        rows.append({"path": str(path), "expected_sha256": expected["sha256"], **actual,
                     "matched": actual["bytes"] == expected["bytes"] and actual["sha256"] == expected["sha256"]})
    binary = measured(args.binary)
    binary["matched"] = binary["sha256"] == qualification["binary"]["sha256"] and binary["bytes"] == qualification["binary"]["bytes"]
    lockfile = measured(args.root / "Cargo.lock")
    lockfile["matched"] = lockfile["sha256"] == qualification["cargo_lock_sha256"]
    report = {"schema": "hepta.native-bellman-post-phase-source-health.v1", "phase": args.phase,
        "checked_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "qualification_sha256": hashlib.sha256(qualification_bytes).hexdigest(),
        "checker_sha256": measured(Path(__file__))["sha256"],
        "source_files": rows, "binary": binary, "cargo_lock": lockfile,
        "passed": len(rows) == 14 and all(row["matched"] for row in rows) and binary["matched"] and lockfile["matched"],
        "scope": "Post-phase read-time identity checks; the relevant phase separately pins and verifies the actually executed binary. Multiple source files are not an atomic filesystem snapshot."}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        stream.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"phase": args.phase, "passed": report["passed"], "source_files": len(rows), "binary_sha256": binary["sha256"]}))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
