#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Exercise the qualification proof with retained and adversarial libtest logs."""
import copy
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from audit_isolated_tests import audit, case_stdout_proof, listing
from run_isolated_tests import inventory


NAME = "fixture::required_assertion"


def summary(filtered=3, passed=1, failed=0, ignored=0):
    return (f"test result: ok. {passed} passed; {failed} failed; {ignored} ignored; "
            f"0 measured; {filtered} filtered out; finished in 0.01s\n\n")


def normal(name=NAME, filtered=3, panic=False):
    return f"\nrunning 1 test\ntest {name}{' - should panic' if panic else ''} ... ok\n\n" + summary(filtered)


class StdoutProofTests(unittest.TestCase):
    def proof(self, text, count=4, expected_bytes=None):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "stdout.log.gz"
            with gzip.open(path, "wb") as output:
                output.write(text if isinstance(text, bytes) else text.encode())
            return case_stdout_proof(path, NAME, count, expected_bytes)

    def test_normal_and_expected_panic(self):
        for panic in (False, True):
            with self.subTest(panic=panic):
                self.assertTrue(self.proof(normal(panic=panic))["passed"])

    def test_nested_same_name_keeps_the_outer_closing_ok(self):
        for child in (NAME, "fixture::child"):
            text = f"\nrunning 1 test\ntest {NAME} ... \n" + normal(child)
            self.assertFalse(self.proof(text)["passed"])
            self.assertTrue(self.proof(text + "ok\n\n" + summary())["passed"])

    def test_nested_zero_test_summary_does_not_replace_outer_result(self):
        child = "running 0 tests\n\n" + summary(4, passed=0)
        text = f"\nrunning 1 test\ntest {NAME} ... {child}ok\n\n" + summary()
        self.assertTrue(self.proof(text)["passed"])

    def test_expected_child_failure_and_timeout_notice_are_body_output(self):
        text = (f"\nrunning 1 test\ntest {NAME} ... test {NAME} has been running for over 60 seconds\n"
                "running 1 test\ntest fixture::child ... FAILED\n\n"
                "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s\n\n"
                "ok\n\n" + summary())
        self.assertTrue(self.proof(text)["passed"])

    def test_exit_zero_and_zero_cases_are_not_success(self):
        for text in ("", "running 0 tests\n\n" + summary(4, passed=0),
                     f"running 1 test\ntest {NAME} ... "):
            with self.subTest(text=text):
                self.assertFalse(self.proof(text)["passed"])

    def test_wrong_case_count_filter_status_or_trailing_output_is_rejected(self):
        for text in (normal("fixture::different"), normal(filtered=2),
                     normal().replace("1 passed", "2 passed"),
                     normal().replace("0 failed", "1 failed"),
                     normal().replace("0 ignored", "1 ignored"),
                     normal().replace(" ... ok", " ... ignored"),
                     normal() + "unfinished child output\n"):
            with self.subTest(text=text):
                self.assertFalse(self.proof(text)["passed"])

    def test_body_bytes_are_streamed_without_requiring_utf8_or_an_unbounded_line(self):
        text = f"running 1 test\ntest {NAME} ... \n".encode() + b"\xff" * 200000
        text += b"\nok\n\n" + summary().encode()
        proof = self.proof(text, expected_bytes=len(text))
        self.assertTrue(proof["passed"])
        self.assertEqual(proof["plain_sha256"], hashlib.sha256(text).hexdigest())

    def test_recorded_raw_length_must_match(self):
        with self.assertRaises(ValueError):
            self.proof(normal(), expected_bytes=1)

    def test_optional_listing_totals_cannot_hide_tests_or_benchmarks(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "listing.gz"
            for footer in ("2 tests, 0 benchmarks", "1 test, 1 benchmark", "1 test, 0 benchmarks\n1 test, 0 benchmarks"):
                text = NAME + ": test\n" + footer + "\n"
                with gzip.open(path, "wb") as output:
                    output.write(text.encode())
                with self.subTest(footer=footer):
                    with self.assertRaises(ValueError):
                        listing(path, len(text.encode()))
                    with self.assertRaises(ValueError):
                        inventory(text)


class RetainedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / "test-binary"
        self.binary.write_bytes(b"retained binary image")
        self.binary_hash = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.target = {"name": "test-target"}
        self.names = [NAME, "fixture::opt_in"]
        artifact = [
            {"reason": "compiler-artifact", "profile": {"test": True}, "executable": str(self.binary), "target": self.target},
            {"reason": "build-finished", "success": True},
        ]
        self.write_rows("cargo-artifacts.jsonl", artifact)
        (self.root / "source-manifest.input").write_text('{}\n')
        self.commands = []
        self.command("binary-000-list", [str(self.binary), "--list", "--format", "terse"],
                     "".join(name + ": test\n" for name in self.names))
        self.command("binary-000-ignored", [str(self.binary), "--list", "--format", "terse", "--ignored"],
                     self.names[1] + ": test\n")
        case = self.command("case-000001", [str(self.binary), NAME, "--exact", "--test-threads=1"], normal(filtered=1))
        self.rows = [dict(case, binary=str(self.binary), binary_sha256=self.binary_hash,
                          name=NAME, attempt=1, executed=True, status="passed"),
                     {"binary": str(self.binary), "binary_sha256": self.binary_hash,
                      "name": self.names[1], "attempt": 0, "executed": False, "status": "ignored"}]
        self.summary = {"schema": "hepta-isolated-libtest/v1", "success": True, "filter": "", "retries": 0,
                        "passed": 1, "failed": 0, "ignored": 1, "selected": 2, "enumeration_errors": [],
                        "artifacts_path": str(self.root / "cargo-artifacts.jsonl"),
                        "source_manifest_path": str(self.root / "source-manifest.input"),
                        "artifacts_sha256": self.sha("cargo-artifacts.jsonl"),
                        "source_manifest_sha256": self.sha("source-manifest.input"),
                        "binaries": [{"path": str(self.binary), "sha256": self.binary_hash, "target": self.target,
                                      "inventory_count": 2, "ignored_names": [self.names[1]]}]}

    def sha(self, name):
        return hashlib.sha256((self.root / name).read_bytes()).hexdigest()

    def write_rows(self, name, values):
        (self.root / name).write_text("".join(json.dumps(value) + "\n" for value in values))

    def command(self, prefix, argv, stdout):
        row = {"argv": argv, "pid": 123, "exit_code": 0, "timed_out": False,
               "started_utc": "2026-10-28T00:00:00+00:00", "elapsed_seconds": 0.01}
        for stream, content in (("stdout", stdout.encode()), ("stderr", b"")):
            filename = prefix + "." + stream + ".log.gz"
            with gzip.open(self.root / filename, "wb") as output:
                output.write(content)
            row[stream + "_gzip"] = filename
            row[stream + "_bytes"] = len(content)
        self.commands.append(row)
        return row

    def inspect(self):
        (self.root / "summary.json").write_text(json.dumps(self.summary))
        self.write_rows("commands.jsonl", self.commands)
        self.write_rows("tests.jsonl", self.rows)
        report = {"errors": [], "binaries": [], "commands": []}
        try:
            audit(self.root, "", report)
        except Exception as error:
            report["fatal_error"] = str(error)
        report["success"] = not report["errors"] and "fatal_error" not in report
        return report

    def test_full_inventory_exact_case_and_ignored_case_pass(self):
        report = self.inspect()
        self.assertTrue(report["success"], report)
        self.assertEqual((report["passed"], report["ignored"], report["executed"]), (1, 1, 1))

    def test_missing_duplicate_or_foreign_cases_fail(self):
        original = copy.deepcopy(self.rows)
        variants = [original[:-1], original + [original[0]],
                    [dict(original[0], name="foreign"), original[1]]]
        for variant in variants:
            with self.subTest(variant=variant):
                self.rows = variant
                self.assertFalse(self.inspect()["success"])

    def test_binary_change_or_command_mismatch_fails(self):
        self.binary.write_bytes(b"a substituted executable")
        self.assertFalse(self.inspect()["success"])
        self.binary.write_bytes(b"retained binary image")
        self.rows[0]["exit_code"] = 9
        self.assertFalse(self.inspect()["success"])

    def test_extra_command_is_not_silently_excluded(self):
        self.command("unaccounted", [str(self.binary), "foreign"], normal("foreign", 1))
        self.assertFalse(self.inspect()["success"])

    def test_falsegreen_stdout_fails_independent_audit(self):
        self.commands.pop()
        case = self.command("case-000001", [str(self.binary), NAME, "--exact", "--test-threads=1"], "")
        self.rows[0].update(case)
        report = self.inspect()
        self.assertFalse(report["success"])
        self.assertEqual(report["failed"], 1)

    def test_entirely_ignored_inventory_does_not_qualify(self):
        self.commands.pop()
        ignored = self.commands.pop()
        self.command("binary-000-ignored", ignored["argv"],
                     "".join(name + ": test\n" for name in self.names))
        self.rows[0] = {"binary": str(self.binary), "binary_sha256": self.binary_hash,
                        "name": NAME, "attempt": 0, "executed": False, "status": "ignored"}
        self.summary.update(passed=0, ignored=2)
        self.summary["binaries"][0]["ignored_names"] = sorted(self.names)
        report = self.inspect()
        self.assertFalse(report["success"])
        self.assertIn("no runnable test was executed", report["errors"])


class RunnerIntegrationTests(unittest.TestCase):
    def test_runner_rejects_early_exit_and_zero_cases_but_accepts_real_proof(self):
        runner = Path(__file__).with_name("run_isolated_tests.py")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for mode, output in (("early_exit", ""), ("zero", "running 0 tests\n\n" + summary(1, 0)),
                                 ("valid", normal(filtered=0))):
                with self.subTest(mode=mode):
                    binary = root / (mode + ".py")
                    binary.write_text(f"#!{sys.executable}\nimport sys\n"
                                      "if '--list' in sys.argv:\n"
                                      f"    if '--ignored' not in sys.argv: print({NAME + ': test'!r})\n"
                                      f"else: sys.stdout.write({output!r})\n")
                    binary.chmod(0o700)
                    artifacts = root / (mode + ".jsonl")
                    artifacts.write_text(json.dumps({"reason": "compiler-artifact", "profile": {"test": True},
                                                     "executable": str(binary)}) + "\n" +
                                         json.dumps({"reason": "build-finished", "success": True}) + "\n")
                    source = root / (mode + ".source.json")
                    source.write_text('{}\n')
                    evidence = root / (mode + "-evidence")
                    result = subprocess.run([sys.executable, str(runner), "--artifacts", str(artifacts),
                                             "--source-manifest", str(source), "--output", str(evidence),
                                             "--timeout", "3"], capture_output=True, timeout=20)
                    retained = json.loads((evidence / "summary.json").read_text())
                    self.assertEqual(result.returncode, 0 if mode == "valid" else 1, result.stderr)
                    self.assertEqual(retained["success"], mode == "valid")


if __name__ == "__main__":
    unittest.main()
