#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Verify and publish a complete standalone post-spawn probe run, without rerunning it.

Inputs in --run-dir: probe.rs, probe, raw.jsonl, stderr.log, summary.json.
Only completed v1 runs with 2,000 true and 3,000 ssh_g attempts are accepted.
Proof/identity/terminal failures remain evidence: no attempt is filtered out.
Unknown raw fields are rejected; exact original JSONL bytes are gzip-compressed
with no filename and mtime=0. Outputs are create-only, with summary written last.
An interrupted publication can leave a new partial output; it is never replaced.
This helper never executes the probe, contacts a host, or modifies a runtime.
"""

import argparse
from collections import Counter
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys


SCHEMA = "hepta-postspawn-proof-probe/v1"
RECEIPT_SCHEMA = "hepta-x230-postspawn-mechanism-probe-receipt/v1"
COUNTS = ("attempted", "spawned", "reaped", "proof_false", "pidfd_failed",
          "identity_failed", "empty_argv", "terminal_false", "terminal_failed",
          "exit_unsuccessful")
PREFLIGHT = {"kind": "preflight", "schema": SCHEMA, "passed": True,
             "proc_self_getpid_agree": True, "pre_exec_parent_death_fence": True,
             "true_attempts": 2000, "ssh_g_attempts": 3000, "spawn_limit": 5000,
             "historical_attribution": False}
ATTEMPT_KEYS = frozenset((
    "kind", "sequence", "command", "spawn_ok", "pidfd_ok", "pidfd_errno",
    "identity_ok", "identity_stage", "identity_errno", "uid_match", "exe_match",
    "argv_match", "argv_empty", "matches", "terminal_ok", "terminal_done",
    "terminal_false", "terminal_errno", "proof", "wait_ok", "wait_errno",
    "exit_code", "exit_signal"))
SUMMARY_KEYS = frozenset(COUNTS) | {"kind", "completed", "stop_code", "historical_attribution"}
RECEIPT_KEYS = frozenset((
    "schema", "source_sha256", "binary_sha256", "raw_sha256", "raw_bytes",
    "driver_exit_code", "preflight", "summary", "failure_categories",
    "first_failures", "historical_attribution", "kernel_release", "machine",
    "started_unix", "finished_unix"))
CATEGORY_KEYS = ("command", "pidfd_errno", "identity_stage", "identity_errno",
                 "uid_match", "exe_match", "argv_match", "argv_empty",
                 "terminal_done", "exit_code")
IDENTITY_STAGES = {"stat_read", "stat_tail", "birth_missing", "birth_parse",
                   "exe_metadata", "proc_metadata", "cmdline_read"}
PLAIN_STAGES = {"stat_tail", "birth_missing", "birth_parse"}
HEX256 = re.compile(r"[0-9a-f]{64}\Z")
LIMITS = {"probe.rs": 1024 * 1024, "probe": 128 * 1024 * 1024,
          "raw.jsonl": 16 * 1024 * 1024, "stderr.log": 4 * 1024 * 1024,
          "summary.json": 4 * 1024 * 1024}


class InvalidEvidence(ValueError):
    pass


def require(value, message):
    if not value:
        raise InvalidEvidence(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def reject_constant(_value):
    raise InvalidEvidence("non-finite JSON number")


def decode(data):
    try:
        return json.loads(data, object_pairs_hook=unique_object,
                          parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InvalidEvidence("invalid JSON encoding or syntax") from error


def fields(value, expected, context):
    require(isinstance(value, dict) and set(value) == set(expected),
            context + " has missing or unrecognized fields")


def exact(value, expected, context):
    require(type(value) is type(expected) and value == expected,
            context + " has an unexpected value or type")


def integer(value, low, high, context):
    require(type(value) is int and low <= value <= high, context + " is not a bounded integer")


def optional_integer(value, low, high, context):
    if value is not None:
        integer(value, low, high, context)


def optional_bool(value, context):
    require(value is None or type(value) is bool, context + " is not boolean/null")


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def read_regular(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode), "input is not a regular file")
        require(before.st_size <= maximum, "input exceeds its size limit")
        raw = source.read(maximum + 1)
        require(len(raw) <= maximum, "input grew beyond its size limit")
        after = os.fstat(source.fileno())
        require(fingerprint(before) == fingerprint(after) == fingerprint(path.lstat()),
                "input changed or was replaced while reading")
    return raw


def verify_preflight(value):
    fields(value, PREFLIGHT, "preflight")
    for key, expected in PREFLIGHT.items():
        exact(value[key], expected, "preflight." + key)


def verify_attempt(row, sequence):
    fields(row, ATTEMPT_KEYS, "attempt")
    exact(row["kind"], "attempt", "attempt.kind")
    exact(row["sequence"], sequence, "attempt.sequence")
    exact(row["command"], "true" if sequence <= 2000 else "ssh_g", "attempt.command")
    for key in ("spawn_ok", "pidfd_ok", "identity_ok", "matches", "terminal_ok",
                "terminal_false", "proof", "wait_ok"):
        require(type(row[key]) is bool, "attempt." + key + " must be boolean")
    require(row["spawn_ok"] and row["wait_ok"], "only complete spawned-and-reaped runs can be published")
    for key in ("uid_match", "exe_match", "argv_match", "argv_empty", "terminal_done"):
        optional_bool(row[key], "attempt." + key)
    for key in ("pidfd_errno", "identity_errno", "terminal_errno", "wait_errno"):
        optional_integer(row[key], 1, 4095, "attempt." + key)
    optional_integer(row["exit_code"], 0, 255, "attempt.exit_code")
    optional_integer(row["exit_signal"], 1, 64, "attempt.exit_signal")
    require((row["exit_code"] is None) != (row["exit_signal"] is None),
            "waited child must have one exit code or signal")
    require(row["wait_errno"] is None, "successful wait cannot have an errno")
    require(not row["pidfd_ok"] or row["pidfd_errno"] is None,
            "successful pidfd open cannot have an errno")

    stage = row["identity_stage"]
    if row["identity_ok"]:
        require(stage is None and row["identity_errno"] is None,
                "successful identity read cannot have a failure stage")
        require(all(type(row[key]) is bool for key in ("exe_match", "uid_match", "argv_match", "argv_empty")),
                "complete identity needs complete comparisons")
    else:
        require(type(stage) is str and stage in IDENTITY_STAGES, "unknown identity failure stage")
        if stage in PLAIN_STAGES:
            require(row["identity_errno"] is None, "parse failure cannot have an OS errno")
        available = ({"exe_match", "uid_match"} if stage == "cmdline_read" else
                     {"exe_match"} if stage == "proc_metadata" else set())
        for key in ("exe_match", "uid_match", "argv_match", "argv_empty"):
            require(type(row[key]) is bool if key in available else row[key] is None,
                    "partial identity fields disagree with failure stage")
    require(not (row["argv_empty"] is True and row["argv_match"] is True),
            "empty argv cannot match a nonempty fixed command")
    expected_match = row["identity_ok"] and all(row[key] is True for key in ("uid_match", "exe_match", "argv_match"))
    exact(row["matches"], expected_match, "attempt.matches predicate")
    if row["terminal_ok"]:
        require(type(row["terminal_done"]) is bool and row["terminal_errno"] is None,
                "successful terminal check has inconsistent fields")
    else:
        require(row["terminal_done"] is None, "failed terminal check cannot report a terminal state")
    exact(row["terminal_false"], row["terminal_done"] is False, "attempt.terminal_false")
    proof = row["pidfd_ok"] and row["terminal_ok"] and (row["terminal_done"] is True or expected_match)
    exact(row["proof"], proof, "attempt.proof predicate")


def count_rows(rows):
    return {
        "attempted": len(rows), "spawned": sum(row["spawn_ok"] for row in rows),
        "reaped": sum(row["wait_ok"] for row in rows),
        "proof_false": sum(not row["proof"] for row in rows),
        "pidfd_failed": sum(not row["pidfd_ok"] for row in rows),
        "identity_failed": sum(not row["identity_ok"] for row in rows),
        "empty_argv": sum(row["argv_empty"] is True for row in rows),
        "terminal_false": sum(row["terminal_done"] is False for row in rows),
        "terminal_failed": sum(not row["terminal_ok"] for row in rows),
        "exit_unsuccessful": sum(row["exit_code"] != 0 for row in rows),
    }


def category(row):
    return {key: row[key] for key in CATEGORY_KEYS}


def category_counts(rows):
    return Counter(canonical(category(row)).decode("ascii").rstrip("\n")
                   for row in rows if not row["proof"])


def verify_summary(summary, counts):
    fields(summary, SUMMARY_KEYS, "raw summary")
    for key, value in {"kind": "summary", "completed": True, "stop_code": 0,
                       "historical_attribution": False, **counts}.items():
        exact(summary[key], value, "summary." + key)


def verify_receipt(receipt, files, preflight, summary, attempts):
    fields(receipt, RECEIPT_KEYS, "driver receipt")
    exact(receipt["schema"], RECEIPT_SCHEMA, "receipt.schema")
    exact(receipt["historical_attribution"], False, "receipt.historical_attribution")
    exact(receipt["driver_exit_code"], 0, "receipt.driver_exit_code")
    for key, name in (("source_sha256", "probe.rs"), ("binary_sha256", "probe"),
                      ("raw_sha256", "raw.jsonl")):
        require(type(receipt[key]) is str and HEX256.fullmatch(receipt[key]), "invalid receipt hash")
        require(receipt[key] == sha(files[name]), "actual " + name + " hash differs from receipt")
    exact(receipt["raw_bytes"], len(files["raw.jsonl"]), "receipt.raw_bytes")
    verify_preflight(receipt["preflight"])
    exact(receipt["preflight"], preflight, "receipt.preflight")
    verify_summary(receipt["summary"], count_rows(attempts))
    exact(receipt["summary"], summary, "receipt.summary")
    expected = category_counts(attempts)
    declared = receipt["failure_categories"]
    require(isinstance(declared, dict), "receipt failure categories must be an object")
    normalized = {}
    for key, value in declared.items():
        require(type(key) is str, "failure category key must be JSON text")
        signature = decode(key)
        fields(signature, CATEGORY_KEYS, "failure category")
        identity = canonical(signature).decode("ascii").rstrip("\n")
        require(identity in expected and identity not in normalized,
                "unknown or duplicate failure category")
        integer(value, 1, 5000, "failure category count")
        normalized[identity] = value
    require(normalized == dict(expected), "receipt failure categories differ from raw attempts")
    failures = [row for row in attempts if not row["proof"]]
    first = receipt["first_failures"]
    require(isinstance(first, list) and len(first) <= len(failures), "invalid first_failures length")
    for row in first:
        require(isinstance(row, dict) and type(row.get("sequence")) is int, "invalid failure row")
        verify_attempt(row, row["sequence"])
    require(first == failures[:len(first)], "receipt first_failures is not the raw failure prefix")
    exact(receipt["machine"], "x86_64", "receipt.machine")
    require(type(receipt["kernel_release"]) is str and
            re.fullmatch(r"[0-9][A-Za-z0-9._+-]{0,127}", receipt["kernel_release"]),
            "unsupported kernel release field")
    for key in ("started_unix", "finished_unix"):
        value = receipt[key]
        require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
                "invalid receipt time")
    require(receipt["finished_unix"] >= receipt["started_unix"], "receipt clock interval is reversed")


def deterministic_gzip(raw):
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0, compresslevel=9) as target:
        target.write(raw)
    return output.getvalue()


def build(run_dir):
    files = {name: read_regular(run_dir / name, limit) for name, limit in LIMITS.items()}
    raw = files["raw.jsonl"]
    require(raw.isascii() and raw.endswith(b"\n"), "raw JSONL must be newline-terminated ASCII")
    lines = raw.splitlines()
    require(len(lines) == 5002 and all(0 < len(line) <= 4096 for line in lines),
            "expected one preflight, 5000 attempts, and one summary")
    records = [decode(line) for line in lines]
    preflight, attempts, summary = records[0], records[1:-1], records[-1]
    verify_preflight(preflight)
    for sequence, row in enumerate(attempts, 1):
        verify_attempt(row, sequence)
    counts = count_rows(attempts)
    verify_summary(summary, counts)
    receipt = decode(files["summary.json"])
    verify_receipt(receipt, files, preflight, summary, attempts)
    compressed = deterministic_gzip(raw)
    signatures = category_counts(attempts)
    identity_errors = Counter((row["command"], row["identity_stage"], row["identity_errno"])
                              for row in attempts if not row["identity_ok"])
    evidence = {
        "schema": "hepta-x230-postspawn-probe-public-evidence/v1",
        "receipt_verified": True, "probe_completed": True,
        "mechanism_observed": counts["proof_false"] > 0,
        "historical_attribution": False, "production_runtime_changed": False,
        "counts": counts,
        "counts_by_command": {name: count_rows([row for row in attempts if row["command"] == name])
                              for name in ("true", "ssh_g")},
        "failure_categories": [{**decode(key), "count": value} for key, value in sorted(signatures.items())],
        "identity_failure_categories": [
            {"command": command, "identity_stage": stage, "identity_errno": errno, "count": count}
            for (command, stage, errno), count in sorted(identity_errors.items(), key=lambda item: canonical(item[0]))],
        "source_sha256": sha(files["probe.rs"]), "binary_sha256": sha(files["probe"]),
        "driver_receipt_sha256": sha(files["summary.json"]),
        "builder_sha256": sha(Path(__file__).read_bytes()),
        "preflight": preflight, "driver_exit_code": receipt["driver_exit_code"],
        "recorded_elapsed_seconds": receipt["finished_unix"] - receipt["started_unix"],
        "environment": {key: receipt[key] for key in ("kernel_release", "machine")},
        "stderr": {"bytes": len(files["stderr.log"]), "sha256": sha(files["stderr.log"]),
                   "text_published": False, "bound_by_original_receipt": False},
        "complete_raw": {"sha256": sha(raw), "bytes": len(raw), "records": len(records),
                         "attempts": len(attempts), "all_attempts_retained": True,
                         "gzip_sha256": sha(compressed), "gzip_bytes": len(compressed),
                         "gzip_mtime": 0, "gzip_filename": "", "gzip_compresslevel": 9},
        "verification": {"actual_source_binary_raw_hashes_match_receipt": True,
                         "raw_record_schema_and_order_checked": True,
                         "proof_predicate_recomputed_for_every_attempt": True,
                         "all_summary_counts_recomputed": True,
                         "receipt_failure_category_counts_recomputed": True,
                         "receipt_first_failures_match_raw_prefix": True,
                         "unknown_raw_fields_rejected": True},
        "scope": "Offline publication of a standalone fixed-workload mechanism probe; no probe execution or runtime write by this builder.",
        "limitations": [
            "This probe does not reproduce Tokio scheduling or the runtime's child registry bookkeeping.",
            "A proof refusal here does not attribute any historical mac, SSH, or production incident.",
            "Completed probe runs are diagnostic evidence, not runtime qualification or performance benchmarks.",
            "The no-production-change label records the standalone run scope, not an independent audit of host history.",
            "The original driver receipt has no stderr hash; this builder records the received stderr hash without publishing its text.",
        ],
    }
    return evidence, compressed


def create_only(path, data):
    with path.open("xb") as target:
        target.write(data)
        target.flush()
        os.fsync(target.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--output-summary", type=Path, required=True)
    parser.add_argument("--output-raw-gzip", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        outputs = (args.output_summary, args.output_raw_gzip)
        require(outputs[0].resolve() != outputs[1].resolve(), "output paths must differ")
        inputs = {(args.run_dir / name).resolve() for name in LIMITS}
        for path in outputs:
            require(path.resolve() not in inputs, "output path must not alias an input")
            require(not os.path.lexists(path), "create-only output already exists")
        evidence, compressed = build(args.run_dir)
        create_only(args.output_raw_gzip, compressed)
        summary_bytes = canonical(evidence)
        create_only(args.output_summary, summary_bytes)
        print(json.dumps({"receipt_verified": True, "counts": evidence["counts"],
                          "summary_sha256": sha(summary_bytes),
                          "raw_gzip_sha256": sha(compressed)}, sort_keys=True))
        return 0
    except (InvalidEvidence, OSError, OverflowError) as error:
        print("evidence publication refused: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
