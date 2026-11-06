#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Actual filesystem regressions for the unified execution-input snapshot."""

from pathlib import Path
import hashlib
import os
import subprocess
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

    def test_external_hardlink_alias_is_refused_before_source_monitoring(self):
        path = self.write("src/input.rs")
        os.link(path, self.root / "external-alias.rs")
        self.assertEqual(path.stat().st_nlink, 2)
        with self.assertRaisesRegex(RuntimeError, "single-link regular"):
            self.selection.snapshot()

    def test_cargo_output_hardlinks_are_observed_without_relaxing_source_inputs(self):
        target = self.root / "target"
        output = target / "debug/hepta-runtime"
        output.parent.mkdir(parents=True)
        payload = b"actual Cargo-style hardlinked output\n"
        output.write_bytes(payload)
        output.chmod(0o755)
        alias = target / "debug/deps/hepta_runtime-build"
        alias.parent.mkdir()
        os.link(output, alias)
        self.assertEqual(output.stat().st_nlink, 2)
        observed = matrix.observe_binary(target, Path("debug/hepta-runtime"))
        self.assertTrue(observed["exists"])
        self.assertEqual(observed["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(observed["bytes"], len(payload))
        self.assertEqual(alias.read_bytes(), payload)
        with self.assertRaisesRegex(RuntimeError, "single-link regular"):
            matrix.source_file(output, "src/not-an-artifact.rs")

    def test_generated_artifact_symlinks_and_directories_remain_refused(self):
        target = self.root / "target"
        target.mkdir()
        real = target / "real"
        real.write_bytes(b"binary")
        for name, destination in (("linked", real), ("dangling", target / "absent")):
            (target / name).symlink_to(destination)
            with self.subTest(name=name), self.assertRaises(OSError):
                matrix.observe_binary(target, Path(name))
        (target / "directory").mkdir()
        with self.assertRaises((OSError, RuntimeError)):
            matrix.observe_binary(target, Path("directory"))
        self.assertFalse(matrix.observe_binary(target, Path("missing"))["exists"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO output")
    def test_fifo_is_refused_without_blocking_artifact_observation(self):
        target = self.root / "target"
        target.mkdir()
        os.mkfifo(target / "output")
        command = [sys.executable, "-B", "-c",
                   "import sys;sys.path.insert(0,sys.argv[1]);"
                   "import rea_full_qualification as m;"
                   "m.observe_binary(m.Path(sys.argv[2]),m.Path('output'))",
                   str(Path(matrix.__file__).parent), str(target)]
        completed = subprocess.run(command, capture_output=True, timeout=2)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"non-regular build artifact", completed.stderr)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO input")
    def test_fifo_is_refused_without_blocking_source_acquisition(self):
        path = self.repo / "src/input.rs"
        path.parent.mkdir()
        os.mkfifo(path)
        command = [sys.executable, "-B", "-c",
                   "import sys;sys.path.insert(0,sys.argv[1]);"
                   "import rea_full_qualification as m;"
                   "m.source_file(m.Path(sys.argv[2]),'src/input.rs')",
                   str(Path(matrix.__file__).parent), str(path)]
        # subprocess.run kills and reaps the owned observer if the old blocking
        # open regresses; no FIFO writer or unrelated process is involved.
        completed = subprocess.run(command, capture_output=True, timeout=2)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(b"non-regular source input", completed.stderr)


if __name__ == "__main__":
    unittest.main()
