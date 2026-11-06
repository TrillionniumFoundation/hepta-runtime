#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Actual filesystem regressions for the unified execution-input snapshot."""

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rea_full_qualification as matrix


EXECUTION_INPUTS = (
    "config/provider.json", "deploy/hepta_browser_capture.py", "workers/model_worker.py",
    "vendor/parser/tables.bin", "src/mcp/bridge.java", "src/mcp/rea_frozen/schema.json",
    "docs/rea-native/PUBLISHED_6_8_0_ORACLE.json", "docs/rea-native/UPSTREAM.json",
    "docs/rea-native/compatibility/REA_6_8_0_INPUTS.json",
    "docs/rea-native/compatibility/REA_6_8_0_CAPABILITY_MAP.json",
    "tools/host/runner.py", "server.json",
)


class SourceBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.selection = matrix.Selection(self.repo, self.root / "target", self.root / "evidence")

    def write(self, name, raw=b"original\n"):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def test_snapshot_covers_native_and_non_rust_execution_inputs(self):
        for name in EXECUTION_INPUTS:
            self.write(name)
        names = {item["path"] for item in self.selection.snapshot()["files"]}
        self.assertEqual(set(EXECUTION_INPUTS), names)

    def test_each_input_mutation_changes_the_combination_identity(self):
        for name in EXECUTION_INPUTS:
            path = self.write(name)
            before = self.selection.snapshot()["tree_sha256"]
            path.write_bytes(b"replacement\n")
            with self.subTest(path=name):
                self.assertNotEqual(before, self.selection.snapshot()["tree_sha256"])

    @unittest.skipUnless(sys.platform == "linux", "actual Linux inotify observation")
    def test_replaced_then_restored_inputs_remain_observed(self):
        paths = [self.write(name) for name in EXECUTION_INPUTS]
        before = self.selection.snapshot()
        monitor = matrix.SourceMonitor(self.selection)
        monitor.start()
        try:
            for path in paths:
                path.write_bytes(b"changed and restored\n")
                path.write_bytes(b"original\n")
        finally:
            events = monitor.stop()
        self.assertEqual(before, self.selection.snapshot())
        self.assertEqual(events["errors"], [])
        observed = {row["path"] for row in events["retained_events"]}
        self.assertTrue(set(EXECUTION_INPUTS) <= observed, sorted(set(EXECUTION_INPUTS) - observed))

    def test_generated_qualification_outputs_are_not_source_inputs(self):
        for name in ("docs/qualification/run/result.json", "docs/rea-native/STATUS.md",
                     "docs/rea-native/compatibility/REA_6_8_0_LEDGER.json",
                     "docs/rea-native/compatibility/REA_6_8_0_QUALIFICATIONS.json",
                     "deploy/__pycache__/capture.pyc", "tests/test-output/temporary.rs"):
            self.write(name)
        self.assertEqual(self.selection.snapshot()["files"], [])

    def test_frozen_reference_symlinks_are_refused(self):
        target = self.root / "outside.json"
        target.write_bytes(b"{}")
        path = self.repo / "docs/rea-native/compatibility/REA_6_8_0_CAPABILITY_MAP.json"
        path.parent.mkdir(parents=True)
        path.symlink_to(target)
        with self.assertRaises(OSError):
            self.selection.snapshot()

    def test_reference_directory_symlinks_are_refused(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.repo / "docs").mkdir()
        (self.repo / "docs/rea-native").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "directory symlink"):
            self.selection.snapshot()

    def test_source_profile_explicitly_records_reference_inputs(self):
        selection = self.selection.snapshot()["selection"]
        self.assertEqual(selection.get("profile"), "hepta.rea.execution-inputs.v2")
        self.assertTrue(set(EXECUTION_INPUTS[6:10]) <= set(selection.get("reference_files", [])))

    def test_build_storage_cannot_hide_execution_inputs(self):
        for name in ("src/build-cache", "workers/results", "config", "deploy/target",
                     "vendor/cache", ".cargo", "docs/rea-native",
                     "docs/rea-native/compatibility"):
            with self.subTest(path=name):
                self.assertTrue(matrix.storage_overlaps_inputs(self.repo, self.repo / name))
        for path in (self.root / "target", self.repo / "docs/qualification/new-run"):
            self.assertFalse(matrix.storage_overlaps_inputs(self.repo, path))

    def test_storage_cannot_hide_an_additional_workspace_member(self):
        for name in ("extra/Cargo.toml", "extra/src/lib.rs", "generated/build.rs"):
            self.write(name)
        selected = {row["path"] for row in self.selection.snapshot()["files"]}
        self.assertIn("extra/Cargo.toml", selected)
        self.assertIn("extra/src/lib.rs", selected)
        self.assertIn("generated/build.rs", selected)
        for name in ("extra", "extra/src", "generated"):
            with self.subTest(path=name):
                self.assertTrue(matrix.storage_overlaps_inputs(self.repo, self.repo / name))


if __name__ == "__main__":
    unittest.main()
