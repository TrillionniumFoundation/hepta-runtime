#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Local synthetic evidence tests. No diagnostic binary or remote command runs."""

from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import build_x230_postspawn_probe_evidence as builder


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fixture_records(with_refusals=True):
    preflight = {"kind": "preflight", "schema": "hepta-postspawn-proof-probe/v1",
                 "passed": True, "proc_self_getpid_agree": True,
                 "pre_exec_parent_death_fence": True, "true_attempts": 2000,
                 "ssh_g_attempts": 3000, "spawn_limit": 5000,
                 "historical_attribution": False}
    rows = []
    for sequence in range(1, 5001):
        row = {"kind": "attempt", "sequence": sequence,
               "command": "true" if sequence <= 2000 else "ssh_g", "spawn_ok": True,
               "pidfd_ok": True, "pidfd_errno": None, "identity_ok": True,
               "identity_stage": None, "identity_errno": None, "uid_match": True,
               "exe_match": True, "argv_match": True, "argv_empty": False,
               "matches": True, "terminal_ok": True, "terminal_done": False,
               "terminal_false": True, "terminal_errno": None, "proof": True,
               "wait_ok": True, "wait_errno": None, "exit_code": 0, "exit_signal": None}
        if with_refusals and sequence <= 99:
            row.update(identity_ok=False, identity_stage="exe_metadata", identity_errno=2,
                       uid_match=None, exe_match=None, argv_match=None, argv_empty=None,
                       matches=False, terminal_done=sequence <= 95,
                       terminal_false=sequence > 95, proof=sequence <= 95)
        elif with_refusals and sequence == 100:
            row.update(argv_match=False, argv_empty=True, matches=False, proof=False)
        rows.append(row)
    summary = {"kind": "summary", "completed": True, "stop_code": 0,
               "attempted": 5000, "spawned": 5000, "reaped": 5000,
               "proof_false": 5 if with_refusals else 0, "pidfd_failed": 0,
               "identity_failed": 99 if with_refusals else 0,
               "empty_argv": 1 if with_refusals else 0,
               "terminal_false": 4905 if with_refusals else 5000,
               "terminal_failed": 0, "exit_unsuccessful": 0,
               "historical_attribution": False}
    return [preflight, *rows, summary]


def raw_bytes(records):
    return b"".join((json.dumps(row, separators=(",", ":")) + "\n").encode()
                    for row in records)


def write_fixture(directory, records):
    source, binary, raw = b"// synthetic test fixture, not a probe\n", b"NOT EXECUTABLE\n", raw_bytes(records)
    keys = ("command", "pidfd_errno", "identity_stage", "identity_errno", "uid_match",
            "exe_match", "argv_match", "argv_empty", "terminal_done", "exit_code")
    failures = [row for row in records[1:-1] if not row["proof"]]
    categories = Counter(json.dumps({key: row[key] for key in keys}, sort_keys=True)
                         for row in failures)
    receipt = {"schema": "hepta-x230-postspawn-mechanism-probe-receipt/v1",
               "source_sha256": digest(source), "binary_sha256": digest(binary),
               "raw_sha256": digest(raw), "raw_bytes": len(raw), "driver_exit_code": 0,
               "preflight": records[0], "summary": records[-1],
               "failure_categories": dict(categories), "first_failures": failures,
               "historical_attribution": False, "kernel_release": "6.8.0-test",
               "machine": "x86_64", "started_unix": 100.0, "finished_unix": 125.0}
    for name, data in (("probe.rs", source), ("probe", binary), ("raw.jsonl", raw),
                       ("stderr.log", b""), ("summary.json", json.dumps(receipt).encode())):
        (directory / name).write_bytes(data)
    return receipt


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="postspawn-evidence-selfcheck-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.records = fixture_records()
        self.receipt = write_fixture(self.directory, self.records)

    def rewrite_raw_and_receipt(self, records=None, receipt=None):
        records = self.records if records is None else records
        receipt = self.receipt if receipt is None else receipt
        raw = raw_bytes(records)
        receipt["raw_sha256"], receipt["raw_bytes"] = digest(raw), len(raw)
        (self.directory / "raw.jsonl").write_bytes(raw)
        (self.directory / "summary.json").write_text(json.dumps(receipt))

    def test_observed_pattern_counts_are_recomputed_and_all_raw_is_retained(self):
        evidence, zipped = builder.build(self.directory)
        self.assertEqual(evidence["counts"], {key: self.records[-1][key] for key in (
            "attempted", "spawned", "reaped", "proof_false", "pidfd_failed", "identity_failed",
            "empty_argv", "terminal_false", "terminal_failed", "exit_unsuccessful")})
        self.assertEqual(evidence["counts_by_command"]["true"]["proof_false"], 5)
        self.assertEqual(evidence["counts_by_command"]["ssh_g"]["proof_false"], 0)
        self.assertEqual(sorted(row["count"] for row in evidence["failure_categories"]), [1, 4])
        self.assertEqual(gzip.decompress(zipped), (self.directory / "raw.jsonl").read_bytes())
        self.assertEqual(len(gzip.decompress(zipped).splitlines()), 5002)
        self.assertFalse(evidence["historical_attribution"])
        self.assertFalse(evidence["production_runtime_changed"])

    def test_zero_refusal_run_is_valid_without_claiming_observed_mechanism(self):
        write_fixture(self.directory, fixture_records(False))
        evidence, _ = builder.build(self.directory)
        self.assertEqual(evidence["counts"]["proof_false"], 0)
        self.assertEqual(evidence["failure_categories"], [])
        self.assertFalse(evidence["mechanism_observed"])

    def test_gzip_has_fixed_header_and_is_deterministic(self):
        _, first = builder.build(self.directory)
        _, second = builder.build(self.directory)
        self.assertEqual(first, second)
        self.assertEqual(first[3] & 8, 0)
        self.assertEqual(first[4:8], b"\0\0\0\0")

    def test_each_actual_source_binary_and_raw_hash_is_verified(self):
        for name in ("probe.rs", "probe", "raw.jsonl"):
            with self.subTest(name=name):
                original = (self.directory / name).read_bytes()
                if name == "raw.jsonl":
                    changed = original.replace(b'"sequence":1,', b'"sequence":1, ', 1)
                else:
                    changed = original + b"changed\n"
                (self.directory / name).write_bytes(changed)
                with self.assertRaises(builder.InvalidEvidence):
                    builder.build(self.directory)
                (self.directory / name).write_bytes(original)

    def test_matching_receipt_does_not_bypass_false_summary_counts(self):
        self.records[-1]["identity_failed"] = 98
        self.rewrite_raw_and_receipt()
        with self.assertRaisesRegex(builder.InvalidEvidence, "identity_failed"):
            builder.build(self.directory)

    def test_false_failure_category_count_is_refused(self):
        key = next(iter(self.receipt["failure_categories"]))
        self.receipt["failure_categories"][key] += 1
        self.rewrite_raw_and_receipt()
        with self.assertRaisesRegex(builder.InvalidEvidence, "failure categories"):
            builder.build(self.directory)

    def test_wrong_first_failure_prefix_is_refused(self):
        self.receipt["first_failures"] = list(reversed(self.receipt["first_failures"]))
        self.rewrite_raw_and_receipt()
        with self.assertRaisesRegex(builder.InvalidEvidence, "first_failures"):
            builder.build(self.directory)

    def test_unknown_raw_field_cannot_publish_private_payload(self):
        self.records[1]["argv_bytes"] = "/private/example"
        self.rewrite_raw_and_receipt()
        with self.assertRaisesRegex(builder.InvalidEvidence, "unrecognized fields"):
            builder.build(self.directory)

    def test_proof_must_match_the_actual_predicate(self):
        self.records[101]["proof"] = False
        self.rewrite_raw_and_receipt()
        with self.assertRaisesRegex(builder.InvalidEvidence, "proof predicate"):
            builder.build(self.directory)

    def test_boolean_cannot_impersonate_integer_sequence(self):
        self.records[1]["sequence"] = True
        self.rewrite_raw_and_receipt()
        with self.assertRaisesRegex(builder.InvalidEvidence, "sequence"):
            builder.build(self.directory)

    def test_reordered_or_missing_attempts_are_refused(self):
        for records in (self.records[:100] + self.records[101:],
                        [self.records[0], self.records[2], self.records[1], *self.records[3:]]):
            with self.subTest(rows=len(records)):
                self.rewrite_raw_and_receipt(records=records)
                with self.assertRaises(builder.InvalidEvidence):
                    builder.build(self.directory)

    def test_duplicate_json_key_is_refused_even_with_updated_hash(self):
        raw = (self.directory / "raw.jsonl").read_bytes().replace(
            b'"proof":true', b'"proof":false,"proof":true', 1)
        self.receipt.update(raw_sha256=digest(raw), raw_bytes=len(raw))
        (self.directory / "raw.jsonl").write_bytes(raw)
        (self.directory / "summary.json").write_text(json.dumps(self.receipt))
        with self.assertRaisesRegex(builder.InvalidEvidence, "duplicate JSON"):
            builder.build(self.directory)

    def test_partial_identity_stage_must_match_available_comparisons(self):
        self.records[1]["uid_match"] = True
        self.rewrite_raw_and_receipt()
        with self.assertRaisesRegex(builder.InvalidEvidence, "partial identity"):
            builder.build(self.directory)

    def test_output_is_create_only_and_bad_evidence_creates_nothing(self):
        summary, zipped = self.directory / "public.json", self.directory / "complete.jsonl.gz"
        argv = ["--run-dir", str(self.directory), "--output-summary", str(summary),
                "--output-raw-gzip", str(zipped)]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(builder.main(argv), 0)
            saved = (summary.read_bytes(), zipped.read_bytes())
            self.assertEqual(builder.main(argv), 2)
        self.assertEqual(saved, (summary.read_bytes(), zipped.read_bytes()))
        bad_summary, bad_zipped = self.directory / "bad.json", self.directory / "bad.gz"
        self.records[101]["proof"] = False
        self.rewrite_raw_and_receipt()
        bad_argv = ["--run-dir", str(self.directory), "--output-summary", str(bad_summary),
                    "--output-raw-gzip", str(bad_zipped)]
        with redirect_stderr(io.StringIO()):
            self.assertEqual(builder.main(bad_argv), 2)
        self.assertFalse(bad_summary.exists())
        self.assertFalse(bad_zipped.exists())


if __name__ == "__main__":
    unittest.main()
