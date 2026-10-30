#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Coverage guards for the new native file-series report validator."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import run_native_validation as native


class Protocol:
    HOSTS = ("ai395", "mac", "main", "pocket4", "rog", "x230")
    TRACE_PREFIX = b"HEPTA_OBSERVATION_TIMING "

    @staticmethod
    def receipt(path, contents=False):
        raw = path.read_bytes()
        row = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}
        return (row, raw) if contents else row


class FileValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        stderr = self.root / "round-0-on/controller/stderr.log"
        stderr.parent.mkdir(parents=True)
        stderr.write_bytes(b"")

    def tearDown(self):
        self.temporary.cleanup()

    def fixture(self, soak=False):
        concurrency = [8] if soak else [1, 4, 8]
        cells = [{"iteration": 0, "concurrency": c, "calls": 96, "success": 96, "seconds": 10.0}
                 for c in concurrency]
        warmup = [{"host": host, "okay": True, "phase": "warmup"} for host in Protocol.HOSTS for _ in range(2)]
        negative = [{"host": host, "okay": True, "phase": "negative", "expected_error": reason}
                    for host in Protocol.HOSTS for reason in ("stale_version", "outside_root")]
        rows = warmup + negative + [
            {"host": Protocol.HOSTS[(i // 2) % 6], "tool": "file_info" if i % 2 == 0 else "binary_read",
             "phase": "measured", "index": i, "concurrency": c, "iteration": 0, "okay": True}
            for c in concurrency for i in range(96)]
        rows = [{**row, "round": 0, "mode": "on"} for row in rows]
        raw = "".join(json.dumps(row) + "\n" for row in rows).encode()
        (self.root / "calls.jsonl").write_bytes(raw)
        value = {"schema": "hepta-x230-file-pool-abba/v1", "complete": True, "binary_sha256": "binary",
                 "remote_writes": False, "binary_unchanged": True, "agent_unchanged": True,
                 "order": ["on"], "calls_per_cell": 96, "concurrency": concurrency,
                 "calls_sha256": hashlib.sha256(raw).hexdigest(),
                 "rounds": [{"index": 0, "mode": "on", "cells": cells, "warmup": warmup, "negative": negative,
                             "waited_process_tree_cpu_seconds": 3.0,
                             "shutdown": {"exit_code": 0, "observed_descendant_survivors": [], "reader_error": None,
                                          "unmatched_responses": 0, "resources": {"peaks": {}, "errors": []}}}]}
        stage = {"kind": "soak" if soak else "file_abba", "helper_elapsed_seconds": 125.0}
        return stage, value, rows

    def validate(self, stage, value):
        return native.validate_files(Protocol, stage, value, self.root, "binary")

    def test_complete_abba_cell_inventory_is_accepted(self):
        stage, value, _ = self.fixture()
        self.assertTrue(self.validate(stage, value)["passed"])

    def test_duplicate_original_row_fails_even_with_recomputed_journal_hash(self):
        stage, value, rows = self.fixture()
        rows[-1] = copy.deepcopy(rows[-2])
        raw = "".join(json.dumps(row) + "\n" for row in rows).encode()
        (self.root / "calls.jsonl").write_bytes(raw)
        value["calls_sha256"] = hashlib.sha256(raw).hexdigest()
        proof = self.validate(stage, value)
        self.assertFalse(proof["passed"])
        self.assertFalse(proof["assertions"]["exact_balanced_calls"])

    def test_missing_cell_and_wrong_binary_both_fail(self):
        stage, value, _ = self.fixture()
        value["rounds"][0]["cells"].pop()
        value["binary_sha256"] = "different"
        proof = self.validate(stage, value)
        self.assertFalse(proof["passed"])
        self.assertFalse(proof["assertions"]["one_fixed_iteration"])
        self.assertFalse(proof["assertions"]["schema_complete_binary"])

    def test_soak_uses_120_seconds_and_discloses_actual_measured_time(self):
        stage, value, _ = self.fixture(soak=True)
        stage["helper_elapsed_seconds"] = 119.99
        self.assertFalse(self.validate(stage, value)["passed"])
        stage["helper_elapsed_seconds"] = 120.01
        proof = self.validate(stage, value)
        self.assertTrue(proof["passed"])
        self.assertEqual(proof["details"]["configured_soak_seconds"], 120)
        self.assertEqual(proof["details"]["measured_cell_seconds"], 10.0)

    def test_trace_and_descendant_survivors_fail(self):
        stage, value, _ = self.fixture()
        (self.root / "round-0-on/controller/stderr.log").write_bytes(Protocol.TRACE_PREFIX + b"event\n")
        value["rounds"][0]["shutdown"]["observed_descendant_survivors"] = [{"pid": 123}]
        proof = self.validate(stage, value)
        self.assertFalse(proof["passed"])
        self.assertFalse(proof["assertions"]["trace_disabled"])
        self.assertFalse(proof["assertions"]["owned_shutdown"])


if __name__ == "__main__":
    unittest.main()
