"""Controls for complete current capture before the fixed historical projection."""
from pathlib import Path
from unittest import mock
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tests/hia_native/historical_public58/materialize.py"
spec = importlib.util.spec_from_file_location("integrated_source_materializer", MODULE_PATH)
materialize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(materialize)


class IntegratedSourceTransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.transition = materialize.current_source_transition(ROOT)
        cls.profile = cls.transition["profile"]
        cls.output_temporary = tempfile.TemporaryDirectory(prefix="hia-integrated-output-")
        cls.addClassCleanup(cls.output_temporary.cleanup)
        cls.output = Path(cls.output_temporary.name) / "historical"
        process = subprocess.run(
            [sys.executable, "-I", "-B", str(MODULE_PATH), "--source", str(ROOT),
             "--output", str(cls.output)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        if process.returncode:
            raise AssertionError(process.stderr.decode(errors="replace"))
        cls.receipt = json.loads((cls.output / "HISTORICAL_PUBLIC_SOURCE.json").read_bytes())

    def current_root(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-integrated-source-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "source"
        root.mkdir()
        for name, captured in self.transition["captured"].items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(captured["raw"])
            path.chmod(captured["identity"][2] & 0o777)
        return root

    def reject(self, root):
        with self.assertRaises((ValueError, AssertionError, FileNotFoundError, NotADirectoryError)):
            materialize.current_source_transition(root)

    def test_complete_independent_root_uses_every_physical_source_and_no_ambient_inputs(self):
        root, reads = self.current_root(), set()
        original_read = materialize.read

        def explicit(base, name):
            path = base / name
            self.assertTrue(path.is_relative_to(root), str(path))
            reads.add(path.relative_to(root).as_posix())
            return original_read(base, name)

        with mock.patch.object(materialize, "read", side_effect=explicit):
            transition = materialize.current_source_transition(root)
        self.assertEqual(transition["profile"], self.profile)
        self.assertEqual(len(transition["native_names"]), 235)
        self.assertEqual(reads, set(transition["captured"]))
        self.assertTrue(set(self.profile["current_native_files"]) <= reads)
        self.assertTrue(set(self.profile["current_auxiliary_files"]) <= reads)
        self.assertTrue(set(self.profile["retained_profiles"]) <= reads)
        self.assertIn(materialize.MATERIALIZER_PATH.as_posix(), reads)

    def test_three_full_byte_inverse_results_keep_the_original_profiles_and_195_roster(self):
        transition = materialize.current_source_transition(self.current_root())
        reference = json.loads(transition["captured"][materialize.REFERENCE_PROFILE.as_posix()]["raw"])
        profile = json.loads(transition["captured"][(materialize.PREFIX / "PROFILE.json").as_posix()]["raw"])
        self.assertEqual(len(transition["predecessors"]), 3)
        for name, raw in transition["predecessors"].items():
            self.assertEqual(materialize.pin(raw), self.profile["transitions"][name]["predecessor"])
            self.assertNotEqual(materialize.pin(raw), self.profile["transitions"][name]["current"])
            expected = ({key: reference["native_inventory_authority"][key]
                         for key in ("bytes", "sha256", "git_blob")}
                        if name == "native/migration.json" else profile["current_workflow_files"][name])
            self.assertEqual(materialize.pin(raw), expected)
        old = json.loads(transition["predecessors"]["native/migration.json"])["native_components"]
        current = json.loads(transition["captured"]["native/migration.json"]["raw"])["native_components"]
        self.assertEqual(len(old), 195)
        self.assertEqual(len(current), 196)
        self.assertEqual(current[:-1], old)
        self.assertEqual(current[-1]["source"], "native/native_read_bootstrap.hepta")

    def test_fixed_transition_and_all_retained_authorities_reject_missing_or_changed_bytes(self):
        root = self.current_root()
        names = [materialize.CURRENT_SOURCE_TRANSITION.as_posix(), *self.profile["retained_profiles"]]
        for name in names:
            path, raw = root / name, (root / name).read_bytes()
            for missing in (False, True):
                try:
                    with self.subTest(path=name, missing=missing):
                        path.unlink() if missing else path.write_bytes(raw + b"\x00")
                        self.reject(root)
                finally:
                    path.write_bytes(raw)

    def test_current_transition_inputs_and_transport_sources_require_full_exact_bytes(self):
        root = self.current_root()
        names = [*self.profile["transitions"], *self.profile["current_auxiliary_files"]]
        for name in names:
            path, raw = root / name, (root / name).read_bytes()
            for missing in (False, True):
                try:
                    with self.subTest(path=name, missing=missing):
                        path.unlink() if missing else path.write_bytes(raw + b"\x00")
                        self.reject(root)
                finally:
                    path.write_bytes(raw)

    def test_all_five_new_native_sources_and_retained_native_endpoints_are_fixed(self):
        root = self.current_root()
        retained = sorted(set(self.profile["current_native_files"])
                          - set(self.profile["additional_current_only_files"]))
        names = [*self.profile["additional_current_only_files"], retained[0], retained[-1]]
        for name in names:
            path, raw = root / name, (root / name).read_bytes()
            for missing in (False, True):
                try:
                    with self.subTest(path=name, missing=missing):
                        path.unlink() if missing else path.write_bytes(raw + b"\x00")
                        self.reject(root)
                finally:
                    path.write_bytes(raw)

    def test_complete_roster_rejects_unregistered_source_and_execution_mode_changes(self):
        root = self.current_root()
        extra = root / "native/unregistered_current_source.hepta"
        extra.write_bytes(b"unregistered")
        self.reject(root)
        extra.unlink()
        name = self.profile["additional_current_only_files"][0]
        path, mode = root / name, (root / name).stat().st_mode & 0o777
        try:
            path.chmod(mode | 0o100)
            self.reject(root)
        finally:
            path.chmod(mode)

    def test_a_historical_projection_cannot_be_supplied_as_the_current_physical_input(self):
        root = self.current_root()
        for name, raw in self.transition["predecessors"].items():
            path, current = root / name, (root / name).read_bytes()
            try:
                with self.subTest(path=name):
                    path.write_bytes(raw)
                    self.reject(root)
            finally:
                path.write_bytes(current)

    def test_loaded_reader_binding_rejects_missing_or_different_root_copy(self):
        root = self.current_root()
        path = root / materialize.MATERIALIZER_PATH
        raw = path.read_bytes()
        path.write_bytes(raw + b"\n# different reader\n")
        self.reject(root)
        path.unlink()
        self.reject(root)

    def test_symlinked_file_and_parent_cannot_supply_a_foreign_source(self):
        root = self.current_root()
        name = self.profile["additional_current_only_files"][0]
        path, raw = root / name, (root / name).read_bytes()
        outside = root.parent / "outside.hepta"
        outside.write_bytes(raw)
        path.unlink()
        path.symlink_to(outside)
        self.reject(root)
        path.unlink()
        path.write_bytes(raw)
        moved = root.parent / "outside-native"
        (root / "native").rename(moved)
        (root / "native").symlink_to(moved, target_is_directory=True)
        self.reject(root)

    def test_every_changed_domain_and_authority_is_reread_at_terminal_admission(self):
        root, original_read = self.current_root(), materialize.read
        names = [materialize.CURRENT_SOURCE_TRANSITION.as_posix(), materialize.MATERIALIZER_PATH.as_posix(),
                 *self.profile["retained_profiles"], *self.profile["transitions"],
                 *self.profile["current_auxiliary_files"], *self.profile["additional_current_only_files"]]
        for name in names:
            path, raw, count = root / name, (root / name).read_bytes(), 0

            def drift(base, relative):
                nonlocal count
                if base / relative == path:
                    count += 1
                    if count == 2:
                        path.write_bytes(raw + b"\x00")
                return original_read(base, relative)

            try:
                with self.subTest(path=name), mock.patch.object(materialize, "read", side_effect=drift):
                    with self.assertRaisesRegex(ValueError, "terminal readback"):
                        materialize.current_source_transition(root)
                self.assertEqual(count, 2)
            finally:
                path.write_bytes(raw)

    def test_same_byte_inode_replacement_is_rejected_at_the_terminal_boundary(self):
        root, original_read = self.current_root(), materialize.read
        path = root / self.profile["additional_current_only_files"][0]
        raw, count = path.read_bytes(), 0

        def replace_inode(base, relative):
            nonlocal count
            if base / relative == path:
                count += 1
                if count == 2:
                    replacement = path.with_name(path.name + ".replacement")
                    replacement.write_bytes(raw)
                    replacement.chmod(path.stat().st_mode & 0o777)
                    os.replace(replacement, path)
            return original_read(base, relative)

        with mock.patch.object(materialize, "read", side_effect=replace_inode):
            with self.assertRaisesRegex(ValueError, "terminal readback"):
                materialize.current_source_transition(root)
        self.assertEqual(count, 2)
        self.assertEqual(path.read_bytes(), raw)

    def test_late_native_source_addition_is_rejected_before_current_admission(self):
        root, original_read = self.current_root(), materialize.read
        target, count = root / materialize.CURRENT_SOURCE_TRANSITION, 0
        extra = root / "native/late_unregistered.hepta"

        def add_source(base, relative):
            nonlocal count
            if base / relative == target:
                count += 1
                if count == 2:
                    extra.write_bytes(b"late")
            return original_read(base, relative)

        with mock.patch.object(materialize, "read", side_effect=add_source):
            with self.assertRaisesRegex(ValueError, "terminal readback"):
                materialize.current_source_transition(root)
        self.assertEqual(count, 2)

    def test_complete_materialized_output_preserves_131_and_199_domains_and_195_native_sources(self):
        result = materialize.verify_materialized(self.output)
        self.assertEqual(result["original_reference_domains"]["complete_declared_source_paths"], 131)
        self.assertEqual(result["metadata_reference_domains"]["complete_reference_and_metadata_paths"], 199)
        reference, _ = materialize.reference_authority(self.output)
        self.assertEqual(materialize.verify_native_reference_inventory(self.output, reference),
                         {"native_components": 195, "excluded_current_only_paths": 1})
        self.assertEqual(self.receipt["integrated_source_transition"], materialize._transition_report(self.profile))
        for name in self.profile["additional_current_only_files"]:
            self.assertFalse((self.output / name).exists())
        for name, raw in self.transition["predecessors"].items():
            self.assertEqual((self.output / name).read_bytes(), raw)
            self.assertEqual((ROOT / name).read_bytes(), self.transition["captured"][name]["raw"])
        self.assertEqual(materialize.current_source_transition(ROOT)["profile"], self.profile)

    def test_forged_receipt_cannot_admit_any_changed_historical_transition_output(self):
        receipt_path = self.output / "HISTORICAL_PUBLIC_SOURCE.json"
        receipt_raw = receipt_path.read_bytes()
        for name in self.profile["transitions"]:
            path, raw = self.output / name, (self.output / name).read_bytes()
            try:
                with self.subTest(path=name):
                    path.write_bytes(raw + b"\x00")
                    receipt = json.loads(receipt_raw)
                    receipt["files"][name] = materialize.pin(path.read_bytes())
                    receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
                    with self.assertRaises((ValueError, AssertionError)):
                        materialize.verify_materialized(self.output)
            finally:
                path.write_bytes(raw)
                receipt_path.write_bytes(receipt_raw)

    def test_each_integrated_current_only_source_is_rejected_in_historical_output(self):
        for name in self.profile["additional_current_only_files"]:
            path = self.output / name
            try:
                with self.subTest(path=name):
                    path.write_bytes(self.transition["captured"][name]["raw"])
                    with self.assertRaisesRegex(ValueError, "current-only source remains"):
                        materialize.verify_source_transition_output(self.output, self.receipt)
            finally:
                path.unlink(missing_ok=True)

    def test_optimized_parent_cannot_disable_the_complete_transition_authority(self):
        process = subprocess.run(
            [sys.executable, "-I", "-O", "-B", str(MODULE_PATH), "--source", str(ROOT), "--check-only"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn(b"requires assertions enabled", process.stderr)
        self.assertEqual(process.stdout, b"")


def load_tests(loader, tests, pattern):
    path = ROOT / "tests/hia_native/test_integrated_registry_transition.py"
    registry_spec = importlib.util.spec_from_file_location("integrated_registry_controls", path)
    registry = importlib.util.module_from_spec(registry_spec)
    registry_spec.loader.exec_module(registry)
    tests.addTests(loader.loadTestsFromModule(registry))
    return tests


if __name__ == "__main__":
    unittest.main()
