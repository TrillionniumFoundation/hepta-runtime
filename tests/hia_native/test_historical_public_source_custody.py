"""Controls for the complete, explicit historical source reference boundary.

These tests add no native executions to the historical qualification counts.
The original pipeline methods and their byte identities remain unchanged.
"""
from pathlib import Path
from unittest import mock
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tests/hia_native/historical_public58/materialize.py"
spec = importlib.util.spec_from_file_location("historical_source_materializer", MODULE_PATH)
materialize = importlib.util.module_from_spec(spec)
spec.loader.exec_module(materialize)


class HistoricalSourceCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference, cls.required = materialize.reference_authority(ROOT)
        cls.profile = json.loads((ROOT / materialize.PREFIX / "PROFILE.json").read_bytes())
        authority = cls.reference["native_inventory_authority"]
        cls.native_inventory_raw = materialize.current_native_inventory_predecessor(
            ROOT, (ROOT / authority["path"]).read_bytes(),
            {key: authority[key] for key in ("bytes", "sha256", "git_blob")})
        cls.authorities = [materialize.REFERENCE_PROFILE.as_posix()] + [
            cls.reference[field]["path"] for field in
            ("inventory_authority", "workdir_authority", "native_inventory_authority")
        ] + [
            (materialize.REFERENCE_SOURCE / name).as_posix()
            for name in cls.reference["restore"]
        ]
        assert len(cls.authorities) == 22

    def directory(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-historical-source-custody-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "source"
        root.mkdir()
        return root

    @staticmethod
    def copy_file(root, name, original=None):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((original or (ROOT / name)).read_bytes())
        return path

    def current_root(self):
        root = self.directory()
        names = set(self.authorities)
        names.add((materialize.PREFIX / "PROFILE.json").as_posix())
        names.update(self.reference["excluded_current_only_files"])
        for name in self.required:
            if name in self.profile["restore"] and name not in self.reference["restore"]:
                names.add((materialize.PREFIX / "source" / name).as_posix())
            else:
                names.add(name)
        for name in names:
            self.copy_file(root, name)
        # These original controls retain their exact preintegration source domain.
        (root / self.reference["native_inventory_authority"]["path"]).write_bytes(self.native_inventory_raw)
        return root

    def original_root(self, include_native=False):
        root = self.directory()
        for name in self.required:
            if name in self.reference["restore"]:
                source = ROOT / materialize.REFERENCE_SOURCE / name
            elif name in self.profile["restore"]:
                source = ROOT / materialize.PREFIX / "source" / name
            else:
                source = ROOT / name
            self.copy_file(root, name, source)
        if include_native:
            authority = self.reference["native_inventory_authority"]["path"]
            self.copy_file(root, authority).write_bytes(self.native_inventory_raw)
            rows = json.loads((root / authority).read_bytes())["native_components"]
            for row in rows:
                name = row["source"]
                source = ROOT / materialize.PREFIX / "source" / name if name in self.profile["restore"] else ROOT / name
                self.copy_file(root, name, source)
        return root

    def test_an_independent_source_root_captures_every_reference_without_ambient_reads(self):
        root = self.current_root()
        original_read = materialize.read
        reads = set()

        def isolated_read(base, name):
            path = base / name
            self.assertTrue(path.is_relative_to(root), str(path))
            reads.add(path.relative_to(root).as_posix())
            return original_read(base, name)

        with mock.patch.object(materialize, "read", side_effect=isolated_read):
            reference, required = materialize.reference_authority(root)
            materialize.check_current_references(root, self.profile, reference, required)
        self.assertEqual(reference, self.reference)
        self.assertEqual(required, self.required)
        self.assertEqual(len(required), 131)
        self.assertEqual(len(reference["original_runtime_files"]), 53)
        self.assertEqual(len(json.loads((root / reference["workdir_authority"]["path"]).read_bytes())["files"]), 84)
        self.assertTrue(set(self.authorities) <= reads)

    def test_every_fixed_authority_and_original_fixture_rejects_missing_or_changed_bytes(self):
        root = self.current_root()
        for name in self.authorities:
            path = root / name
            original = path.read_bytes()
            for missing in (False, True):
                with self.subTest(path=name, missing=missing):
                    try:
                        if missing:
                            path.unlink()
                        else:
                            path.write_bytes(original + b"\x00")
                        with self.assertRaises((ValueError, FileNotFoundError, AssertionError)):
                            materialize.reference_authority(root)
                    finally:
                        path.write_bytes(original)

    def test_all_current_preimages_and_the_extra_current_source_are_exact(self):
        root = self.current_root()
        paths = set(self.reference["current_inputs"]) | set(self.reference["excluded_current_only_files"])
        self.assertEqual(len(paths), 19)
        for name in sorted(paths):
            path = root / name
            original = path.read_bytes()
            try:
                with self.subTest(path=name):
                    path.write_bytes(original + b"\x00")
                    with self.assertRaisesRegex(ValueError, "changed|differs"):
                        materialize.check_current_references(root, self.profile, self.reference, self.required)
            finally:
                path.write_bytes(original)

    def test_every_authority_is_reread_after_capture(self):
        root = self.current_root()
        original_read = materialize.read
        for name in self.authorities:
            target = root / name
            original = target.read_bytes()
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
                        materialize.reference_authority(root)
                self.assertEqual(count, 2)
            finally:
                target.write_bytes(original)

    def test_every_current_reference_is_reread_after_capture(self):
        root = self.current_root()
        original_read = materialize.read
        names = [(root, name) for name in self.reference["excluded_current_only_files"]]
        for name in self.required:
            base = root / materialize.PREFIX / "source" if name in self.profile["restore"] and name not in self.reference["restore"] else root
            names.append((base, name))
        self.assertEqual(len(names), 132)
        for base, name in names:
            target = base / name
            original = target.read_bytes()
            count = 0

            def drift(read_root, relative):
                nonlocal count
                if read_root / relative == target:
                    count += 1
                    if count == 2:
                        target.write_bytes(original + b"\x00")
                return original_read(read_root, relative)

            try:
                with self.subTest(path=name), mock.patch.object(materialize, "read", side_effect=drift):
                    with self.assertRaisesRegex(ValueError, "terminal readback"):
                        materialize.check_current_references(root, self.profile, self.reference, self.required)
                self.assertEqual(count, 2)
            finally:
                target.write_bytes(original)

    def test_all_131_materialized_original_sources_remain_exact(self):
        root = self.original_root()
        self.assertEqual(materialize.verify_reference_domains(root, self.reference, self.required),
            {"original_runtime_paths": 53, "workdir_source_paths": 84,
             "complete_declared_source_paths": 131, "restored_reference_paths": 18})
        for name in self.required:
            path = root / name
            original = path.read_bytes()
            for missing in (False, True):
                try:
                    with self.subTest(path=name, missing=missing):
                        if missing:
                            path.unlink()
                        else:
                            path.write_bytes(original + b"\x00")
                        with self.assertRaises((ValueError, FileNotFoundError)):
                            materialize.verify_reference_domains(root, self.reference, self.required)
                finally:
                    path.write_bytes(original)

    def test_every_materialized_original_source_is_reread_at_the_terminal_boundary(self):
        root = self.original_root()
        original_read = materialize.read
        for name in self.required:
            target = root / name
            original = target.read_bytes()
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
                        materialize.verify_reference_domains(root, self.reference, self.required)
                self.assertEqual(count, 2)
            finally:
                target.write_bytes(original)

    def test_reference_fixture_roster_rejects_an_extra_file_at_terminal_readback(self):
        root = self.current_root()
        original_read = materialize.read
        target = root / materialize.REFERENCE_PROFILE
        extra = root / materialize.REFERENCE_SOURCE / "extra.rs"
        count = 0

        def drift(base, name):
            nonlocal count
            if base / name == target:
                count += 1
                if count == 2:
                    extra.write_bytes(b"late addition")
            return original_read(base, name)

        with mock.patch.object(materialize, "read", side_effect=drift):
            with self.assertRaisesRegex(ValueError, "inventory changed at terminal readback"):
                materialize.reference_authority(root)
        self.assertEqual(count, 2)

    def test_historical_native_roster_rejects_missing_extra_and_terminal_additions(self):
        root = self.original_root(include_native=True)
        self.assertEqual(materialize.verify_native_reference_inventory(root, self.reference),
            {"native_components": 195, "excluded_current_only_paths": 1})
        authority = self.reference["native_inventory_authority"]["path"]
        first = json.loads((root / authority).read_bytes())["native_components"][0]["source"]
        path = root / first
        original = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(ValueError, "inventory changed"):
            materialize.verify_native_reference_inventory(root, self.reference)
        path.write_bytes(original)
        extra = root / "native/context_protocol_policy.hepta"
        extra.write_bytes((ROOT / "native/context_protocol_policy.hepta").read_bytes())
        with self.assertRaisesRegex(ValueError, "inventory changed"):
            materialize.verify_native_reference_inventory(root, self.reference)
        extra.unlink()
        original_read = materialize.read
        count = 0

        def drift(base, name):
            nonlocal count
            if base / name == root / authority:
                count += 1
                if count == 2:
                    extra.write_bytes(b"late addition")
            return original_read(base, name)

        with mock.patch.object(materialize, "read", side_effect=drift):
            with self.assertRaisesRegex(ValueError, "inventory changed at terminal readback"):
                materialize.verify_native_reference_inventory(root, self.reference)
        self.assertEqual(count, 2)

    def test_symlinked_authority_parent_cannot_supply_an_ambient_source(self):
        root = self.current_root()
        moved = root.parent / "outside-scripts"
        (root / "scripts").rename(moved)
        (root / "scripts").symlink_to(moved, target_is_directory=True)
        with self.assertRaises(AssertionError):
            materialize.reference_authority(root)

    def test_optimized_parent_cannot_disable_historical_checks(self):
        process = subprocess.run(
            [sys.executable, "-I", "-O", "-B", str(MODULE_PATH), "--source", str(ROOT), "--check-only"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        self.assertNotEqual(process.returncode, 0)
        self.assertIn(b"requires assertions enabled", process.stderr)
        self.assertEqual(process.stdout, b"")

    def test_rewriting_output_receipt_cannot_admit_modified_original_bytes(self):
        output = self.directory() / "materialized"
        process = subprocess.run(
            [sys.executable, "-I", "-B", str(MODULE_PATH), "--source", str(ROOT), "--output", str(output)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        self.assertEqual(process.returncode, 0, process.stderr.decode(errors="replace"))
        self.assertEqual(materialize.verify_materialized(output)["original_reference_domains"]["complete_declared_source_paths"], 131)
        path = output / "Cargo.lock"
        path.write_bytes(path.read_bytes() + b"\x00")
        receipt_path = output / "HISTORICAL_PUBLIC_SOURCE.json"
        receipt = json.loads(receipt_path.read_bytes())
        receipt["files"]["Cargo.lock"] = materialize.pin(path.read_bytes())
        receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
        with self.assertRaisesRegex(ValueError, "materialized original reference source differs"):
            materialize.verify_materialized(output)


if __name__ == "__main__":
    unittest.main()
