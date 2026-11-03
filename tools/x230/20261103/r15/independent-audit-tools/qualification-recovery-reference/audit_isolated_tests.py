#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Audit retained libtest inventories, exact-case output and executable hashes."""
import argparse
from collections import deque
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import re
import time


SUMMARY = re.compile(
    rb"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    rb"(\d+) measured; (\d+) filtered out; finished in [0-9.]+s"
)
MAX_PROOF_LINE = 65536


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stamp(path):
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)


def read_gzip(path, expected_bytes=None, line_consumer=None):
    """Hash every byte while retaining at most one bounded line for parsing."""
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"log is not an original regular file: {path}")
    before = stamp(path)
    compressed_before = digest(path)
    plain = hashlib.sha256()
    count, pending, overlong = 0, b"", False
    with gzip.open(path, "rb") as stream:
        while chunk := stream.read(65536):
            plain.update(chunk)
            count += len(chunk)
            if line_consumer is None:
                continue
            pieces = chunk.split(b"\n")
            for index, piece in enumerate(pieces):
                if not overlong:
                    if len(pending) + len(piece) > MAX_PROOF_LINE:
                        overlong, pending = True, b""
                    else:
                        pending += piece
                if index < len(pieces) - 1:
                    line_consumer(None if overlong else pending.rstrip(b"\r"))
                    pending, overlong = b"", False
    if line_consumer is not None and (pending or overlong):
        line_consumer(None if overlong else pending.rstrip(b"\r"))
    compressed_after = digest(path)
    if before != stamp(path) or compressed_before != compressed_after:
        raise ValueError(f"log changed during audit: {path}")
    if expected_bytes is not None and count != expected_bytes:
        raise ValueError(f"log byte count differs from command record: {path}")
    return {"gzip_sha256": compressed_after, "plain_sha256": plain.hexdigest(), "bytes": count}


def case_stdout_proof(path, name, inventory_count, expected_bytes=None):
    """Require the outer harness's exact header and final completion, not child summaries.

    Libtest prints the parent header before running the case. An inherited child
    stdout can split that header from its final standalone `ok`, including when
    the child recursively runs the same test. Do not count every nested summary
    or substitute a child's complete same-name line for the parent's closure.
    """
    first, tail, nonempty = [], deque(maxlen=2), 0

    def line(value):
        nonlocal nonempty
        if value is not None and not value.strip():
            return
        nonempty += 1
        item = (nonempty, value)
        if len(first) < 2:
            first.append(item)
        tail.append(item)

    result = read_gzip(path, expected_bytes, line)
    errors = []
    if len(first) < 2 or first[0][1] != b"running 1 test":
        errors.append("outer harness did not announce exactly one test")
    header = first[1][1] if len(first) == 2 else None
    encoded = name.encode("utf-8")
    prefixes = (b"test " + encoded + b" ... ", b"test " + encoded + b" - should panic ... ")
    suffix = None
    if header is not None:
        for prefix in prefixes:
            if header.startswith(prefix):
                suffix = header[len(prefix):]
                break
    if suffix is None:
        errors.append("first outer test header does not contain the complete exact test name")
    final = tail[-1][1] if tail else None
    match = SUMMARY.fullmatch(final) if final is not None else None
    if match is None:
        errors.append("last nonempty stdout line is not a successful libtest summary")
    else:
        counts = tuple(int(item) for item in match.groups())
        if counts != (1, 0, 0, 0, inventory_count - 1):
            errors.append(f"outer summary counts differ from one exact runnable case: {counts}")
        result["summary_counts"] = dict(zip(
            ("passed", "failed", "ignored", "measured", "filtered_out"), counts
        ))
    previous = tail[-2] if len(tail) == 2 else None
    if suffix == b"ok":
        if previous != first[1]:
            errors.append("completed outer exact-name line is not immediately before the final summary")
    elif suffix is not None:
        if previous is None or previous[1] != b"ok" or previous[0] <= first[1][0]:
            errors.append("split outer test header lacks its own final standalone ok")
    result.update({"passed": not errors, "errors": errors, "exact_name": name})
    return result


def json_lines(path):
    values = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"non-object JSONL record at {path}:{number}")
        values.append(value)
    return values


def listing(path, expected_bytes):
    names, totals = [], []

    def line(raw):
        if raw is None:
            raise ValueError("overlong libtest inventory line")
        text = raw.decode("utf-8", errors="strict")
        if not text.strip():
            return
        total = re.fullmatch(r"(\d+) tests?, (\d+) benchmarks?", text)
        if total:
            totals.append(tuple(int(value) for value in total.groups()))
            return
        if not text.endswith(": test") or not text[:-6]:
            raise ValueError(f"unsupported libtest inventory line: {text!r}")
        names.append(text[:-6])

    proof = read_gzip(path, expected_bytes, line)
    if len(names) != len(set(names)):
        raise ValueError("duplicate exact names in one libtest inventory")
    if totals and totals != [(len(names), 0)]:
        raise ValueError("inventory totals disagree with exact test names or contain benchmarks")
    return names, proof


def audit(evidence, expected_filter, report):
    summary_path = evidence / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if summary.get("schema") != "hepta-isolated-libtest/v1":
        raise ValueError("unsupported runner summary schema")
    if summary.get("filter") != expected_filter:
        raise ValueError("runner filter differs from the explicitly expected filter")
    if summary.get("retries") != 0:
        raise ValueError("runner did not record zero retries")
    report["input_sha256"] = {"summary.json": digest(summary_path)}
    errors = report["errors"]
    if summary.get("success") is not True or summary.get("fatal_error") or summary.get("enumeration_errors"):
        errors.append("original runner did not report an unqualified successful run")
    for filename, field, original in (
        ("cargo-artifacts.jsonl", "artifacts_sha256", "artifacts_path"),
        ("source-manifest.input", "source_manifest_sha256", "source_manifest_path"),
    ):
        actual = digest(evidence / filename)
        report["input_sha256"][filename] = actual
        if actual != summary.get(field):
            raise ValueError(f"retained {filename} differs from runner's initial hash")
        current = Path(summary[original])
        if digest(current) != actual:
            raise ValueError(f"original {filename} changed after the runner copied it")
    events = json_lines(evidence / "cargo-artifacts.jsonl")
    finished = [event for event in events if event.get("reason") == "build-finished"]
    if len(finished) != 1 or finished[0].get("success") is not True:
        raise ValueError("expected exactly one successful original Cargo build-finished record")
    artifacts = {}
    for event in events:
        if event.get("reason") == "compiler-artifact" and event.get("profile", {}).get("test") is True and event.get("executable"):
            path = str(Path(event["executable"]).resolve())
            if path in artifacts and artifacts[path] != event.get("target"):
                raise ValueError("one retained executable represents conflicting Cargo targets")
            artifacts[path] = event.get("target")
    binaries = summary.get("binaries", [])
    if not artifacts or [item.get("path") for item in binaries] != list(artifacts):
        raise ValueError("summary executable inventory differs from original Cargo artifacts")
    commands = json_lines(evidence / "commands.jsonl")
    rows = json_lines(evidence / "tests.jsonl")
    report["input_sha256"].update({name: digest(evidence / name) for name in ("commands.jsonl", "tests.jsonl")})
    by_stdout, used_commands, used_logs = {}, set(), set()
    for index, command in enumerate(commands):
        stdout = command.get("stdout_gzip")
        if not isinstance(stdout, str) or stdout in by_stdout:
            raise ValueError("command stdout identity is missing or duplicated")
        by_stdout[stdout] = (index, command)

    def log_path(command, stream):
        filename = command.get(stream + "_gzip")
        if not isinstance(filename, str) or Path(filename).name != filename or filename in used_logs:
            raise ValueError("log name is unsafe, absent or reused by another command")
        used_logs.add(filename)
        return evidence / filename

    def use_command(stdout, argv):
        if stdout not in by_stdout:
            raise ValueError(f"missing original command for {stdout}")
        index, command = by_stdout[stdout]
        if index in used_commands or command.get("argv") != argv:
            raise ValueError("command is reused or its argv differs from the exact original invocation")
        used_commands.add(index)
        if command.get("exit_code") != 0 or command.get("timed_out") is not False or command.get("launch_error"):
            errors.append(f"command did not complete successfully: {stdout}")
        for stream in ("stdout", "stderr"):
            size = command.get(stream + "_bytes")
            if type(size) is not int or size < 0:
                raise ValueError("command log length is missing or invalid")
        return command

    expected = {}
    for index, binary in enumerate(binaries):
        path = Path(binary["path"])
        recorded = binary.get("sha256")
        current = digest(path)
        if not isinstance(recorded, str) or not re.fullmatch(r"[a-f0-9]{64}", recorded) or recorded != current:
            raise ValueError(f"test executable differs from its recorded pre-run hash: {path}")
        if binary.get("target") != artifacts[str(path)]:
            raise ValueError("summary target differs from the original Cargo target")
        inventories = []
        for ignored in (False, True):
            tag = f"binary-{index:03d}" + ("-ignored" if ignored else "-list")
            argv = [str(path), "--list", "--format", "terse"] + (["--ignored"] if ignored else [])
            command = use_command(tag + ".stdout.log.gz", argv)
            names, stdout = listing(log_path(command, "stdout"), command["stdout_bytes"])
            stderr = read_gzip(log_path(command, "stderr"), command["stderr_bytes"])
            report["commands"].append({"stdout_gzip": command["stdout_gzip"], "stdout": stdout, "stderr": stderr})
            inventories.append(names)
        names, ignored = inventories[0], set(inventories[1])
        if not ignored.issubset(names) or binary.get("inventory_count") != len(names) or binary.get("ignored_names") != sorted(ignored):
            raise ValueError("recorded inventory/ignored names differ from original executable listings")
        for name in names:
            if not expected_filter or expected_filter in name:
                expected[(str(path), name)] = (name in ignored, len(names), recorded)
        report["binaries"].append({"path": str(path), "recorded_before_sha256": recorded,
                                   "current_after_sha256": current, "inventory_count": len(names),
                                   "ignored_names": sorted(ignored)})
    actual = set()
    counts = {"passed": 0, "failed": 0, "ignored": 0}
    for number, row in enumerate(rows, 1):
        key = (row.get("binary"), row.get("name"))
        if key not in expected or key in actual:
            raise ValueError("test row is absent from the original inventory or duplicated")
        actual.add(key)
        ignored, total, recorded = expected[key]
        if row.get("binary_sha256") != recorded:
            raise ValueError("case binary hash differs from its original executable inventory")
        if ignored:
            if row.get("status") != "ignored" or row.get("executed") is not False or row.get("attempt") != 0:
                raise ValueError("an originally ignored test was executed or incorrectly classified")
            counts["ignored"] += 1
            continue
        if row.get("executed") is not True or row.get("attempt") != 1:
            raise ValueError("a runnable case was skipped or retried")
        argv = [key[0], key[1], "--exact", "--test-threads=1"]
        command = use_command(f"case-{number:06d}.stdout.log.gz", argv)
        for field in ("argv", "pid", "exit_code", "timed_out", "stdout_gzip", "stderr_gzip", "stdout_bytes", "stderr_bytes", "started_utc", "elapsed_seconds"):
            if row.get(field) != command.get(field):
                raise ValueError(f"case record differs from its original command: {field}")
        proof = case_stdout_proof(log_path(command, "stdout"), key[1], total, command["stdout_bytes"])
        stderr = read_gzip(log_path(command, "stderr"), command["stderr_bytes"])
        passed = proof["passed"] and command.get("exit_code") == 0 and command.get("timed_out") is False and not command.get("launch_error")
        counts["passed" if passed else "failed"] += 1
        report["commands"].append({"stdout_gzip": command["stdout_gzip"], "stdout": proof, "stderr": stderr})
        if not passed or row.get("status") != "passed":
            errors.append({"binary": key[0], "name": key[1], "reported_status": row.get("status"), "stdout_errors": proof["errors"], "exit_code": command.get("exit_code")})
    if actual != set(expected):
        errors.append({"missing_cases": [list(key) for key in sorted(set(expected) - actual)]})
    if len(used_commands) != len(commands):
        errors.append("extra original commands were not covered by inventory or exact-case records")
    if counts["passed"] + counts["failed"] == 0:
        errors.append("no runnable test was executed")
    for field, count in counts.items():
        if summary.get(field) != count:
            errors.append(f"runner {field} count {summary.get(field)} differs from independent count {count}")
    if summary.get("selected") != len(expected) or len(rows) != len(expected):
        errors.append("selected/recorded cases do not cover the complete requested inventory")
    for binary in report["binaries"]:
        if digest(Path(binary["path"])) != binary["current_after_sha256"]:
            errors.append(f"test executable changed during audit: {binary['path']}")
    for filename, initial in report["input_sha256"].items():
        if digest(evidence / filename) != initial:
            errors.append(f"original evidence changed during audit: {filename}")
    report.update(counts, selected=len(expected), executed=counts["passed"] + counts["failed"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True, help="original isolated-tests evidence directory")
    parser.add_argument("--output", type=Path, required=True, help="new audit JSON file; existing paths are refused")
    parser.add_argument("--expected-filter", default="", help="explicit expected filter; default requires the entire inventory")
    args = parser.parse_args()
    # Reserve a new result before reading; never replace any original evidence.
    with args.output.open("x", encoding="utf-8") as output:
        report = {"schema": "hepta-isolated-libtest-audit/v1", "success": False,
                  "evidence": str(args.evidence.resolve()), "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "auditor_sha256": digest(Path(__file__)), "expected_filter": args.expected_filter,
                  "errors": [], "binaries": [], "commands": []}
        started = time.monotonic()
        try:
            audit(args.evidence.resolve(), args.expected_filter, report)
        except Exception as error:
            report["fatal_error"] = f"{type(error).__name__}: {error}"
        report["success"] = not report["errors"] and "fatal_error" not in report
        report["elapsed_seconds"] = time.monotonic() - started
        output.write(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"audit": str(args.output.resolve()), "success": report["success"],
                      "passed": report.get("passed"), "failed": report.get("failed"),
                      "fatal_error": report.get("fatal_error")}), flush=True)
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
