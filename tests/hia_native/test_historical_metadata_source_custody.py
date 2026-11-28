"""Complete production metadata source custody without changing old authorities."""
from pathlib import Path
from unittest import mock
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tests/hia_native/historical_public58/materialize.py"
spec = importlib.util.spec_from_file_location("historical_metadata_materializer", MODULE_PATH)
materialize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(materialize)


class HistoricalMetadataCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference, cls.required = materialize.reference_authority(ROOT)
        cls.profile = json.loads((ROOT / materialize.PREFIX / "PROFILE.json").read_bytes())
        cls.metadata = materialize.metadata_reference_authority(ROOT)
        cls.authorities = [
            materialize.METADATA_REFERENCE_PROFILE.as_posix(),
            materialize.REFERENCE_PROFILE.as_posix(),
            cls.metadata["original_source_authority"]["path"],
            cls.reference["workdir_authority"]["path"],
        ] + [(materialize.METADATA_REFERENCE_SOURCE / name).as_posix()
             for name in cls.metadata["restore"]]
        assert len(cls.authorities) == 6

    def directory(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-historical-metadata-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "source"
        root.mkdir()
        return root

    @staticmethod
    def copy(root, name, source=None):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((source or (ROOT / name)).read_bytes())
        return path

    def current_path(self, name):
        if name in self.metadata["restore"]:
            return Path(name)
        if name in self.reference["restore"]:
            return materialize.REFERENCE_SOURCE / name
        if name in self.profile["restore"]:
            return materialize.PREFIX / "source" / name
        return Path(name)

    def original_source(self, name):
        if name in self.metadata["restore"]:
            return ROOT / materialize.METADATA_REFERENCE_SOURCE / name
        return ROOT / self.current_path(name)

    def current_root(self):
        root = self.directory()
        names = set(self.authorities) | {self.current_path(name).as_posix()
                                         for name in self.metadata["original_metadata_files"]}
        for name in names:
            self.copy(root, name)
        return root

    def original_root(self):
        root = self.directory()
        for name in self.metadata["original_metadata_files"]:
            self.copy(root, name, self.original_source(name))
        return root

    def current_check(self, root):
        materialize.check_current_metadata_references(root, self.profile, self.reference, self.metadata)

    def test_independent_root_captures_all_metadata_and_fixed_authorities(self):
        root = self.current_root()
        original_read, reads = materialize.read, set()

        def isolated(base, name):
            path = base / name
            self.assertTrue(path.is_relative_to(root), str(path))
            reads.add(path.relative_to(root).as_posix())
            return original_read(base, name)

        with mock.patch.object(materialize, "read", side_effect=isolated):
            metadata = materialize.metadata_reference_authority(root)
            materialize.check_current_metadata_references(root, self.profile, self.reference, metadata)
        self.assertEqual(metadata, self.metadata)
        self.assertEqual(len(metadata["original_metadata_files"]), 71)
        self.assertEqual(len(set(self.required) | set(metadata["original_metadata_files"])), 199)
        self.assertEqual(len(metadata["restore"]), 2)
        self.assertTrue(set(self.authorities) <= reads)
        self.assertTrue({self.current_path(name).as_posix()
                         for name in metadata["original_metadata_files"]} <= reads)

    def test_each_fixed_authority_and_fixture_rejects_missing_or_changed_bytes(self):
        root = self.current_root()
        for name in self.authorities:
            path, original = root / name, (root / name).read_bytes()
            for missing in (False, True):
                try:
                    with self.subTest(path=name, missing=missing):
                        if missing:
                            path.unlink()
                        else:
                            path.write_bytes(original + b"\x00")
                        with self.assertRaises((ValueError, FileNotFoundError)):
                            materialize.metadata_reference_authority(root)
                finally:
                    path.write_bytes(original)

    def test_every_metadata_authority_is_reread_at_terminal_admission(self):
        root, original_read = self.current_root(), materialize.read
        for name in self.authorities:
            target, original = root / name, (root / name).read_bytes()
            count = 0

            def drift(base, relative):
                nonlocal count
                if base / relative == target:
                    count += 1
                    if count == 2:
                        target.write_bytes(original + b"\x00")
                return original_read(base, relative)

            try:
                with self.subTest(path=name), mock.patch.object(materialize, "read", side_effect=drift):
                    with self.assertRaisesRegex(ValueError, "terminal readback"):
                        materialize.metadata_reference_authority(root)
                self.assertEqual(count, 2)
            finally:
                target.write_bytes(original)

    def test_all_71_current_preimages_reject_mutation_and_terminal_drift(self):
        root, original_read = self.current_root(), materialize.read
        for name in self.metadata["original_metadata_files"]:
            target = root / self.current_path(name)
            original = target.read_bytes()
            try:
                with self.subTest(path=name, stage="current"):
                    target.write_bytes(original + b"\x00")
                    with self.assertRaisesRegex(ValueError, "differs from its fixed relation"):
                        self.current_check(root)
            finally:
                target.write_bytes(original)
            count = 0

            def drift(base, relative):
                nonlocal count
                if base / relative == target:
                    count += 1
                    if count == 2:
                        target.write_bytes(original + b"\x00")
                return original_read(base, relative)

            try:
                with self.subTest(path=name, stage="terminal"), mock.patch.object(materialize, "read", side_effect=drift):
                    with self.assertRaisesRegex(ValueError, "terminal readback"):
                        self.current_check(root)
                self.assertEqual(count, 2)
            finally:
                target.write_bytes(original)

    def test_all_71_original_outputs_reject_missing_modified_and_late_bytes(self):
        root, original_read = self.original_root(), materialize.read
        self.assertEqual(materialize.verify_metadata_reference_domains(root, self.metadata),
            {"original_production_metadata_paths": 71, "additional_restored_metadata_paths": 2,
             "complete_reference_and_metadata_paths": 199})
        for name in self.metadata["original_metadata_files"]:
            target, original = root / name, (root / name).read_bytes()
            for missing in (False, True):
                try:
                    with self.subTest(path=name, missing=missing):
                        if missing:
                            target.unlink()
                        else:
                            target.write_bytes(original + b"\x00")
                        with self.assertRaises((ValueError, FileNotFoundError)):
                            materialize.verify_metadata_reference_domains(root, self.metadata)
                finally:
                    target.write_bytes(original)
            count = 0

            def drift(base, relative):
                nonlocal count
                if base / relative == target:
                    count += 1
                    if count == 2:
                        target.write_bytes(original + b"\x00")
                return original_read(base, relative)

            try:
                with self.subTest(path=name, stage="terminal"), mock.patch.object(materialize, "read", side_effect=drift):
                    with self.assertRaisesRegex(ValueError, "terminal readback"):
                        materialize.verify_metadata_reference_domains(root, self.metadata)
                self.assertEqual(count, 2)
            finally:
                target.write_bytes(original)

    def test_fixture_inventory_and_symlinked_sources_cannot_expand_authority(self):
        root = self.current_root()
        extra = root / materialize.METADATA_REFERENCE_SOURCE / "extra"
        extra.write_bytes(b"unregistered source")
        with self.assertRaisesRegex(ValueError, "fixture inventory changed"):
            materialize.metadata_reference_authority(root)
        extra.unlink()
        original_read, count = materialize.read, 0
        target = root / materialize.METADATA_REFERENCE_PROFILE

        def drift(base, name):
            nonlocal count
            if base / name == target:
                count += 1
                if count == 2:
                    extra.write_bytes(b"late unregistered source")
            return original_read(base, name)

        with mock.patch.object(materialize, "read", side_effect=drift):
            with self.assertRaisesRegex(ValueError, "inventory changed at terminal readback"):
                materialize.metadata_reference_authority(root)
        extra.unlink()
        target = root / self.metadata["original_source_authority"]["path"]
        outside = root.parent / "outside-manifest.json"
        target.rename(outside)
        target.symlink_to(outside)
        with self.assertRaises(AssertionError):
            materialize.metadata_reference_authority(root)

    def test_original_production_materializer_refuses_the_prior_vendor_preimages(self):
        spec = importlib.util.spec_from_file_location(
            "original_shell_metadata_negative", ROOT / "scripts/hia_native_shell_process_reference.py")
        original = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(original)
        root = self.original_root()
        manifest = json.loads((ROOT / self.metadata["original_source_authority"]["path"]).read_bytes())
        provenance = {"production_metadata_inputs": manifest["production_metadata_inputs"],
                      "source_commit": manifest["source_commit"]}
        for name in self.metadata["restore"]:
            self.copy(root, name)
        output = root.parent / "prior-production-source"
        output.mkdir()
        with self.assertRaisesRegex(ValueError, "production metadata input differs: vendor/ruzstd/HEPTA_PATCH.md"):
            original.production_source(root, output, provenance, dict(os.environ), {"processes": []})

    def test_complete_output_passes_original_source_reader_and_rejects_forged_receipt(self):
        output = self.directory() / "materialized"
        process = subprocess.run(
            [sys.executable, "-I", "-B", str(MODULE_PATH), "--source", str(ROOT), "--output", str(output)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace"))
        result = materialize.verify_materialized(output)
        self.assertEqual(result["original_reference_domains"]["complete_declared_source_paths"], 131)
        self.assertEqual(result["metadata_reference_domains"]["complete_reference_and_metadata_paths"], 199)
        spec = importlib.util.spec_from_file_location(
            "original_shell_metadata_positive", output / "scripts/hia_native_shell_process_reference.py")
        original = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(original)
        provenance, _ = original.original_sources(output)
        self.assertEqual(provenance["original_test_count"], 21)
        target = output.parent / "production-source"
        target.mkdir()
        report = {"processes": []}
        production = original.production_source(output, target, provenance, dict(os.environ), report)
        self.assertEqual(report["processes"], [])
        self.assertEqual(report["production_source_materialization"]["method"], "source-files")
        self.assertEqual(len(report["production_source_materialization"]["files"]), 71)
        self.assertEqual((production / "vendor/ruzstd/HEPTA_PATCH.md").read_bytes(),
                         self.original_source("vendor/ruzstd/HEPTA_PATCH.md").read_bytes())
        name = "vendor/ruzstd/HEPTA_PATCH.md"
        path = output / name
        path.write_bytes(path.read_bytes() + b"\x00")
        receipt_path = output / "HISTORICAL_PUBLIC_SOURCE.json"
        receipt = json.loads(receipt_path.read_bytes())
        receipt["files"][name] = materialize.pin(path.read_bytes())
        receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
        with self.assertRaisesRegex(ValueError, "materialized original production metadata source differs"):
            materialize.verify_materialized(output)


if __name__ == "__main__":
    unittest.main()
