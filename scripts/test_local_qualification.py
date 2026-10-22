"""Offline regressions for local dual-SHA qualification and log custody."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from local_qualification import (SHA_RE, blob_hash, check_source_bytes,
                                 execute_bounded, git, qualify, safe_env,
                                 QualificationError)


class LocalQualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def command(self, *args):
        return subprocess.run(args, cwd=self.root, check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def make_repo(self) -> str:
        self.command("git", "init", "-q")
        self.command("git", "config", "user.email", "local-test@example.invalid")
        self.command("git", "config", "user.name", "Local Test")
        (self.root / "hello.txt").write_text("stable\n")
        self.command("git", "add", "hello.txt")
        self.command("git", "commit", "-qm", "fixture")
        return self.command("git", "rev-parse", "HEAD").stdout.decode().strip()

    def test_git_blob_digest_matches_exact_byte_payload(self):
        self.assertEqual(blob_hash(b"hello\n", "sha1"),
                         hashlib.sha1(b"blob 6\0hello\n").hexdigest())
        self.assertFalse(SHA_RE.fullmatch("main"))
        self.assertTrue(SHA_RE.fullmatch("a" * 40))

    def test_tracked_bytes_detect_modification(self):
        self.make_repo()
        fmt, count = check_source_bytes(self.root)
        self.assertEqual(fmt, "sha1")
        self.assertEqual(count, 1)
        (self.root / "hello.txt").write_text("edited\n")
        with self.assertRaisesRegex(QualificationError, "source bytes differ"):
            check_source_bytes(self.root)

    def test_hidden_index_modification_is_denied(self):
        self.make_repo()
        self.command("git", "update-index", "--assume-unchanged", "hello.txt")
        with self.assertRaisesRegex(QualificationError, "index contains"):
            check_source_bytes(self.root)

    def test_untracked_source_is_denied(self):
        self.make_repo()
        (self.root / "surprise.rs").write_text("fn main() {}")
        with self.assertRaisesRegex(QualificationError, "untracked"):
            check_source_bytes(self.root)

    def test_bounded_capture_and_nonzero_are_distinct(self):
        pass_log = self.root / "pass.log"
        r = execute_bounded((sys.executable, "-c", "print('pass')"),
                            self.root, safe_env(), pass_log, 3, 2048)
        self.assertEqual(r["outcome"], "pass")
        self.assertEqual(r["log_sha256"], hashlib.sha256(pass_log.read_bytes()).hexdigest())
        err = execute_bounded((sys.executable, "-c", "raise SystemExit(7)"),
                              self.root, safe_env(), self.root / "err.log", 3, 2048)
        self.assertEqual(err["outcome"], "nonzero")
        self.assertEqual(err["exit_code"], 7)

    @unittest.skipUnless(os.name == "posix", "POSIX process-group termination required")
    def test_output_budget_and_timeout_fail_closed(self):
        oversize = execute_bounded((sys.executable, "-c", "print('x'*100000)"),
                                   self.root, safe_env(), self.root / "bounded.log", 3, 1024)
        self.assertEqual(oversize["outcome"], "log_limit")
        self.assertLessEqual((self.root / "bounded.log").stat().st_size, 1024)
        timed = execute_bounded((sys.executable, "-c", "import time; time.sleep(30)"),
                                self.root, safe_env(), self.root / "timeout.log", 1, 1024)
        self.assertEqual(timed["outcome"], "timeout")
        self.assertLess(timed["duration_seconds"], 4)

    def test_distinct_source_and_merge_lanes_run_in_isolated_worktrees(self):
        # Mock binaries validate the verifier's orchestration only; they are
        # NOT evidence that real Rust compilation or tests have passed.
        source = self.make_repo()
        (self.root / "hello.txt").write_text("merge candidate\n")
        self.command("git", "add", "hello.txt")
        self.command("git", "commit", "-qm", "synthetic merge fixture")
        merge = self.command("git", "rev-parse", "HEAD").stdout.decode().strip()
        fakebin = self.root / "fakebin"
        fakebin.mkdir()
        for binary in ("rustc", "cargo"):
            file = fakebin / binary
            file.write_text('#!/bin/sh\necho "' + binary + ' 1.95.0 (mock)"\n')
            file.chmod(0o755)
        with tempfile.TemporaryDirectory() as evidence, \
                mock.patch.dict(os.environ, {"PATH": str(fakebin) + os.pathsep + os.environ["PATH"]}), \
                mock.patch("local_qualification.CHECKS", (("mock", (sys.executable, "-c", "print('mock')")),)):
            result = qualify(self.root, source, merge, Path(evidence))
            self.assertEqual(result["status"], "LOCAL_CHECKS_PASS_NOT_PRODUCTION", result)
            self.assertEqual([entry["sha"] for entry in result["lanes"]], [source, merge])
            self.assertEqual([entry["status"] for entry in result["lanes"]],
                             ["LOCAL_CHECKS_PASS", "LOCAL_CHECKS_PASS"])
            self.assertFalse(result["production_authority"])
            self.assertTrue((Path(evidence) / "qualification.json").exists())

    def test_missing_merge_object_emits_blocked_receipt(self):
        original = self.make_repo()
        result = qualify(self.root, original, "f" * 40, self.root.parent / (self.root.name + "-evidence"))
        self.assertEqual(result["status"], "BLOCKED")
        self.assertFalse(result["production_authority"])
        self.assertIn("git rev-parse failed", result["error"])


if __name__ == "__main__":
    unittest.main()
