"""Actual 236-source catalog controls and the complete independent v2 fixture."""
from pathlib import Path
from unittest import mock
import ast
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tests/hia_native/historical_public58/materialize.py"
spec = importlib.util.spec_from_file_location("catalog_source_materializer", MODULE_PATH)
materialize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(materialize)


class CatalogSourceTransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.transition = materialize.current_source_transition(ROOT)
        cls.authority = cls.transition["catalog"]["authority"]
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-catalog-real-roots-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.previous = Path(cls.temporary.name) / "previous"
        cls.previous_report = materialize.prepare_previous_source(ROOT, cls.previous)
        cls.output = Path(cls.temporary.name) / "historical"
        process = subprocess.run(
            [sys.executable, "-I", "-B", str(MODULE_PATH), "--source", str(ROOT),
             "--output", str(cls.output)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        if process.returncode:
            raise AssertionError(process.stderr.decode(errors="replace"))
        cls.receipt = json.loads((cls.output / "HISTORICAL_PUBLIC_SOURCE.json").read_bytes())

    def current_root(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-catalog-current-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "source"
        root.mkdir()
        for name, row in self.transition["captured"].items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(row["raw"])
            path.chmod(row["identity"][2] & 0o777)
        return root

    def reject(self, root):
        with self.assertRaises((ValueError, AssertionError, FileNotFoundError, NotADirectoryError)):
            materialize.current_source_transition(root)

    def test_current_236_and_every_selected_input_are_read_from_the_explicit_root(self):
        root, reads, original = self.current_root(), set(), materialize.read
        def explicit(base, name):
            path = base / name
            self.assertTrue(path.is_relative_to(root), str(path))
            reads.add(path.relative_to(root).as_posix())
            return original(base, name)
        with mock.patch.object(materialize, "read", side_effect=explicit):
            transition = materialize.current_source_transition(root)
        self.assertEqual(len(transition["native_names"]), 236)
        self.assertEqual(set(transition["captured"]), transition["selected_names"])
        self.assertEqual(reads, transition["selected_names"])
        self.assertEqual(len(self.authority["catalog_files"]), 10)
        self.assertTrue(set(self.authority["catalog_files"]) <= reads)
        self.assertIn("asm/full_catalog_capability.S", reads)
        self.assertEqual(transition["catalog"]["inventory"]["source_file_count"], 13025)

    def test_complete_13025_file_previous_fixture_uses_the_actual_retained_reader_and_old_methods(self):
        report = materialize.verify_previous_source(self.previous, ROOT)
        self.assertEqual(report, self.previous_report)
        self.assertEqual(report["source_commit"], "e8ed8bcfbaa21c316f72bc52147cb701e8609635")
        self.assertEqual(report["source_files"], 13025)
        self.assertEqual(report["source_bytes"], 642157774)
        self.assertEqual(report["native_source_paths"], 235)
        path = self.previous / materialize.MATERIALIZER_PATH
        self.assertEqual(materialize.pin(path.read_bytes()), self.authority["previous_reader"]["identity"])
        old_spec = importlib.util.spec_from_file_location("actual_previous_v2_reader", path)
        old = importlib.util.module_from_spec(old_spec)
        old_spec.loader.exec_module(old)
        old.check(self.previous)
        previous_transition = old.current_source_transition(self.previous)
        self.assertEqual(len(previous_transition["native_names"]), 235)
        self.assertEqual(old.CURRENT_SOURCE_TRANSITION_PIN, materialize.CURRENT_SOURCE_TRANSITION_PIN)
        for relative, count in (
            ("tests/hia_native/test_integrated_source_transition.py", 16),
            ("tests/hia_native/test_integrated_registry_transition.py", 6)):
            def methods(raw):
                return {node.name: ast.dump(node, include_attributes=False)
                        for node in ast.walk(ast.parse(raw))
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and node.name.startswith("test_")}
            before = methods((self.previous / relative).read_bytes())
            after = methods((ROOT / relative).read_bytes())
            self.assertEqual(len(before), count)
            self.assertEqual(after, before)

    def test_all_ten_catalog_files_require_exact_bytes_presence_and_execution_modes(self):
        root = self.current_root()
        for name in self.authority["catalog_files"]:
            path, raw, mode = root / name, (root / name).read_bytes(), (root / name).stat().st_mode & 0o777
            for kind in ("bytes", "missing", "mode"):
                try:
                    with self.subTest(path=name, kind=kind):
                        if kind == "missing":
                            path.unlink()
                        elif kind == "mode":
                            path.chmod(mode ^ 0o100)
                        else:
                            path.write_bytes(raw + b"\0")
                        self.reject(root)
                finally:
                    path.write_bytes(raw)
                    path.chmod(mode)

    def test_both_prior_authorities_inventory_reader_and_new_controls_remain_physical_inputs(self):
        root = self.current_root()
        names = [materialize.CATALOG_SOURCE_TRANSITION.as_posix(),
                 *self.authority["retained_authorities"],
                 *self.authority["new_source_files"], materialize.MATERIALIZER_PATH.as_posix()]
        for name in names:
            path, raw = root / name, (root / name).read_bytes()
            for missing in (False, True):
                try:
                    with self.subTest(path=name, missing=missing):
                        path.unlink() if missing else path.write_bytes(raw + b"\0")
                        self.reject(root)
                finally:
                    path.write_bytes(raw)

    def test_full_prior_source_domain_and_unregistered_additions_are_rejected(self):
        root = self.current_root()
        names = ("Cargo.toml", "tests/hia_native/test_native_pipeline.py")
        for name in names:
            path, raw = root / name, (root / name).read_bytes()
            try:
                path.write_bytes(raw + b"\0")
                self.reject(root)
                path.unlink()
                self.reject(root)
            finally:
                path.write_bytes(raw)
        for name in ("tests/extra_current_source.py", "native/extra_current_source.hepta"):
            path = root / name
            try:
                path.write_bytes(b"unregistered")
                self.reject(root)
            finally:
                path.unlink()

    def test_no_workflow_or_control_predecessor_can_substitute_for_current_physical_bytes(self):
        root = self.current_root()
        for name in self.authority["source_transitions"]:
            path, raw = root / name, (root / name).read_bytes()
            try:
                with self.subTest(path=name):
                    path.write_bytes(self.transition["previous_inputs"][name])
                    self.reject(root)
            finally:
                path.write_bytes(raw)

    def test_catalog_file_and_parent_symlinks_cannot_supply_foreign_inputs(self):
        root = self.current_root()
        path = root / "asm/full_catalog_capability.S"
        raw = path.read_bytes()
        outside = root.parent / "outside.S"
        outside.write_bytes(raw)
        path.unlink()
        path.symlink_to(outside)
        self.reject(root)
        path.unlink()
        path.write_bytes(raw)
        moved = root.parent / "outside-asm"
        (root / "asm").rename(moved)
        (root / "asm").symlink_to(moved, target_is_directory=True)
        self.reject(root)

    def test_catalog_bytes_and_same_byte_inodes_are_reread_at_terminal_admission(self):
        original = materialize.read
        for same_bytes in (False, True):
            root = self.current_root()
            path = root / "asm/full_catalog_capability.S"
            raw, count = path.read_bytes(), 0
            def drift(base, name):
                nonlocal count
                if base / name == path:
                    count += 1
                    if count == 2:
                        if same_bytes:
                            replacement = path.with_name("replacement.S")
                            replacement.write_bytes(raw)
                            replacement.chmod(path.stat().st_mode & 0o777)
                            os.replace(replacement, path)
                        else:
                            path.write_bytes(raw + b"\0")
                return original(base, name)
            with self.subTest(same_bytes=same_bytes), mock.patch.object(materialize, "read", side_effect=drift):
                with self.assertRaisesRegex(ValueError, "terminal readback"):
                    materialize.current_source_transition(root)
            self.assertEqual(count, 2)

    def test_late_non_native_source_addition_is_rejected_before_current_admission(self):
        root, original = self.current_root(), materialize.read
        target, count = root / materialize.CATALOG_SOURCE_TRANSITION, 0
        def drift(base, name):
            nonlocal count
            if base / name == target:
                count += 1
                if count == 2:
                    (root / "tests/late_current_source.py").write_bytes(b"late")
            return original(base, name)
        with mock.patch.object(materialize, "read", side_effect=drift):
            with self.assertRaisesRegex(ValueError, "terminal readback"):
                materialize.current_source_transition(root)
        self.assertEqual(count, 2)

    def test_historical_output_keeps_131_199_195_and_all_nine_catalog_auxiliary_files(self):
        result = materialize.verify_materialized(self.output)
        self.assertEqual(result["original_reference_domains"]["complete_declared_source_paths"], 131)
        self.assertEqual(result["metadata_reference_domains"]["complete_reference_and_metadata_paths"], 199)
        self.assertEqual(self.receipt["native_reference_inventory"]["native_components"], 195)
        self.assertEqual(self.receipt["integrated_source_transition"]["current_native_source_paths"], 236)
        self.assertEqual(len(self.transition["profile"]["additional_current_only_files"]), 6)
        for name in self.transition["profile"]["additional_current_only_files"]:
            self.assertFalse((self.output / name).exists())
        for name in self.authority["catalog_files"]:
            if name not in self.authority["catalog_native_files"]:
                self.assertEqual((self.output / name).read_bytes(), (ROOT / name).read_bytes())
        for name, row in self.transition["captured"].items():
            self.assertEqual(materialize.read(ROOT, name), row["raw"])

    def test_forged_receipts_do_not_admit_changed_catalog_auxiliary_or_restored_workflow(self):
        receipt_path = self.output / "HISTORICAL_PUBLIC_SOURCE.json"
        receipt_raw = receipt_path.read_bytes()
        for name in ("asm/full_catalog_capability.S", ".github/workflows/hia-historical-source-custody.yml"):
            path, raw = self.output / name, (self.output / name).read_bytes()
            try:
                with self.subTest(path=name):
                    path.write_bytes(raw + b"\0")
                    receipt = json.loads(receipt_raw)
                    receipt["files"][name] = materialize.pin(path.read_bytes())
                    receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
                    with self.assertRaises((ValueError, AssertionError)):
                        materialize.verify_materialized(self.output)
            finally:
                path.write_bytes(raw)
                receipt_path.write_bytes(receipt_raw)

    def test_complete_previous_fixture_rejects_tampering_and_extra_sources_without_a_receipt(self):
        for name in ("tests/hia_native/historical_public58/materialize.py", "Cargo.toml"):
            path, raw = self.previous / name, (self.previous / name).read_bytes()
            try:
                with self.subTest(path=name):
                    path.write_bytes(raw + b"\0")
                    with self.assertRaises(ValueError):
                        materialize.verify_previous_source(self.previous, ROOT)
                    path.unlink()
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        materialize.verify_previous_source(self.previous, ROOT)
            finally:
                path.write_bytes(raw)
        extra = self.previous / "tests/extra_previous_source.py"
        try:
            extra.write_bytes(b"extra")
            with self.assertRaisesRegex(ValueError, "roster changed"):
                materialize.verify_previous_source(self.previous, ROOT)
        finally:
            extra.unlink()


if __name__ == "__main__":
    unittest.main()
