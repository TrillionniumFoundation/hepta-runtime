#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Regression checks for a pinned oracle while the current source tree advances."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from hia_native_local_read_qualification import (
    EXPECTED_SUITES, admit_suite, blob, check_unchanged, digest, materialize_reference,
)


class OriginalReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Reference Test")
        self.git("config", "user.email", "reference-test@example.invalid")
        self.name = "src/mcp/runtime/reference.py"
        self.original = b"original immutable helper\n"
        target = self.repo / self.name
        target.parent.mkdir(parents=True)
        target.write_bytes(self.original)
        self.git("add", self.name)
        self.git("commit", "--quiet", "-m", "Original")
        self.commit = self.git("rev-parse", "HEAD").decode().strip()
        self.spec = {self.name: {"blob": blob(self.original), "sha256": digest(self.original)}}
        target.write_bytes(b"current runtime changed independently\n")
        self.git("add", self.name)
        self.git("commit", "--quiet", "-m", "Current")
        self.destination = self.root / "reference"

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args],
                                       stderr=subprocess.PIPE)

    def test_declared_original_survives_current_head_and_worktree_changes(self):
        (self.repo / self.name).write_bytes(b"uncommitted current edit\n")
        identities = materialize_reference(self.repo, self.destination, self.commit, self.spec)
        self.assertEqual((self.destination / self.name).read_bytes(), self.original)
        self.assertEqual((self.repo / self.name).read_bytes(), b"uncommitted current edit\n")
        check_unchanged(self.destination, identities)
        self.assertEqual(materialize_reference(self.repo, self.destination, self.commit, self.spec),
                         identities)

    def test_wrong_commit_cannot_borrow_an_expected_blob(self):
        current = self.git("rev-parse", "HEAD").decode().strip()
        with self.assertRaisesRegex(ValueError, "commit/blob mismatch"):
            materialize_reference(self.repo, self.destination, current, self.spec)

    def test_wrong_sha256_remains_rejected(self):
        altered = json.loads(json.dumps(self.spec))
        altered[self.name]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            materialize_reference(self.repo, self.destination, self.commit, altered)

    def test_changed_materialized_reference_cannot_satisfy_a_rerun(self):
        identities = materialize_reference(self.repo, self.destination, self.commit, self.spec)
        (self.destination / self.name).write_bytes(b"modified oracle\n")
        with self.assertRaisesRegex(ValueError, "source changed"):
            check_unchanged(self.destination, identities)
        with self.assertRaisesRegex(ValueError, "existing original reference changed"):
            materialize_reference(self.repo, self.destination, self.commit, self.spec)

    def test_missing_commit_and_symbolic_head_do_not_fall_back(self):
        with self.assertRaises(subprocess.CalledProcessError):
            materialize_reference(self.repo, self.destination, "0" * 40, self.spec)
        with self.assertRaisesRegex(ValueError, "immutable"):
            materialize_reference(self.repo, self.destination, "HEAD", self.spec)

    def test_reference_symlink_is_rejected(self):
        other = self.root / "other"
        other.mkdir()
        self.destination.symlink_to(other, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            materialize_reference(self.repo, self.destination, self.commit, self.spec)


class SuiteCompletenessTests(unittest.TestCase):
    def result(self):
        return {"status": "pass", "manifest_sha256": "manifest", "executable_sha256": "elf",
                "tests_run": 6, "skipped": 0, "failures": 0, "errors": 0,
                "expected_failures": 0, "unexpected_successes": 0,
                "python_isolated": 1, "python_optimize": 0,
                "counts": dict(EXPECTED_SUITES["test_local_service"]["counts"])}

    def test_shortened_or_skipped_success_report_is_refused(self):
        complete = self.result()
        admit_suite("test_local_service", complete, "manifest", "elf")
        for key, value in [("tests_run", 5), ("skipped", 1), ("expected_failures", 1)]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "completeness"):
                admit_suite("test_local_service", dict(complete, **{key: value}), "manifest", "elf")
        short = self.result()
        short["counts"]["original_read_comparisons"] -= 1
        with self.assertRaisesRegex(ValueError, "case counts"):
            admit_suite("test_local_service", short, "manifest", "elf")

    def test_optimized_or_nonisolated_success_report_is_refused(self):
        for key, value in [("python_optimize", 1), ("python_isolated", 0)]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "isolation"):
                admit_suite("test_local_service", dict(self.result(), **{key: value}), "manifest", "elf")


if __name__ == "__main__":
    unittest.main(verbosity=2)
