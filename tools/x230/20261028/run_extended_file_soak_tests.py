#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independent duration, raw-sample and source-pinned loader validation guards."""
import contextlib
import copy
import hashlib
import io
import json
import unittest

import run_extended_file_soak as soak
import run_native_validation_tests as fixtures


class ExtendedSoakTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.FileValidationTests()
        self.fixture.setUp()
        self.native = soak.load_native()
        self.stage, self.value, self.rows = self.fixture.fixture(soak=True)
        self.stage.update(helper_elapsed_seconds=365.0,
            argv=["helper", "--calls", "96", "--concurrency", "8", "--soak-seconds", "360"])
        self.value["rounds"][0]["cells"][0]["seconds"] = 359.0

    def tearDown(self):
        self.fixture.tearDown()

    def validate(self):
        return soak.validate_extended(self.native, fixtures.Protocol, self.stage, self.value,
                                      self.fixture.root, "binary", 360)

    def rewrite_calls(self):
        raw = "".join(json.dumps(row) + "\n" for row in self.rows).encode()
        (self.fixture.root / "calls.jsonl").write_bytes(raw)
        self.value["calls_sha256"] = hashlib.sha256(raw).hexdigest()

    def test_parser_default_and_strict_duration_bounds(self):
        args = ["--qualification", "/q", "--qualification-sha256", "a", "--test-audit", "/a",
                "--test-audit-sha256", "b", "--out", "/o", "--socket-parent", "/s"]
        self.assertEqual(soak.parse_args(args).soak_seconds, 360)
        self.assertEqual(soak.parse_args(args + ["--soak-seconds", "900"]).soak_seconds, 900)
        for value in ("359", "901", "360.5", "nan"):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                soak.parse_args(args + ["--soak-seconds", value])

    def test_120_second_native_success_cannot_satisfy_extended_duration(self):
        self.stage["helper_elapsed_seconds"] = 125.0
        self.value["rounds"][0]["cells"][0]["seconds"] = 120.0
        proof = self.validate()
        self.assertTrue(proof["native_structure"]["passed"])
        self.assertFalse(proof["passed"])
        self.assertFalse(proof["assertions"]["elapsed_and_cell_times"])

    def test_configuration_and_cell_time_are_separately_checked(self):
        self.assertTrue(self.validate()["passed"])
        self.stage["argv"][-1] = "120"
        self.assertFalse(self.validate()["assertions"]["actual_configuration"])
        self.stage["argv"][-1] = "360"
        for seconds in (float("nan"), float("inf"), 366.0, -1.0):
            self.value["rounds"][0]["cells"][0]["seconds"] = seconds
            self.assertFalse(self.validate()["passed"])

    def test_missing_generations_are_unknown_and_measured_duration_is_not_relabelled(self):
        proof = self.validate()
        self.assertTrue(proof["passed"])
        details = proof["details"]
        self.assertEqual(details["configured_helper_soak_seconds"], 360)
        self.assertEqual(details["measured_cell_seconds"], 359.0)
        self.assertEqual(details["native_structure_minimum_seconds"], 120)
        self.assertIsNone(details["observed_master_generations_total"])
        self.assertEqual(details["per_host"]["x230"]["measured"], {"calls": 16, "success": 16, "failures": 0})
        self.value["rounds"][0]["shutdown"]["resources"]["observed_master_generations"] = [{"generation": i} for i in range(12)]
        self.assertEqual(self.validate()["details"]["observed_master_generations_total"], 12)

    def test_raw_host_failure_and_duplicate_samples_are_not_hidden_by_new_hash(self):
        originals = copy.deepcopy(self.rows)
        for change in ("host", "failed", "duplicate", "retry"):
            with self.subTest(change=change):
                self.rows = copy.deepcopy(originals)
                if change == "host":
                    self.rows[-1]["host"] = "rog"
                elif change == "failed":
                    self.rows[-1]["okay"] = False
                elif change == "duplicate":
                    self.rows[-1] = copy.deepcopy(self.rows[-2])
                else:
                    self.rows[-1]["automatic_retry"] = True
                self.rewrite_calls()
                self.assertFalse(self.validate()["passed"])

    def test_original_survivor_and_binary_guards_remain_active(self):
        self.value["rounds"][0]["shutdown"]["observed_descendant_survivors"] = [123]
        self.assertFalse(self.validate()["passed"])
        self.value["rounds"][0]["shutdown"]["observed_descendant_survivors"] = []
        self.value["binary_sha256"] = "wrong"
        self.assertFalse(self.validate()["passed"])


if __name__ == "__main__":
    unittest.main()
