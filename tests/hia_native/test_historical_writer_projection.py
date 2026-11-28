"""Keep the complete writer source and historical authorities independently bound."""
from pathlib import Path
from unittest import mock
import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "tests/hia_native/historical_public58/writer_projection.py"
SPEC = importlib.util.spec_from_file_location("writer_projection", PATH)
projection = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(projection)


class WriterHistoricalProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-writer-historical-controls-")
        cls.base = Path(cls.temporary.name)
        cls.source = cls.base / "current"
        cls.source.mkdir()
        reader, cls.authority = projection.manifest(ROOT)
        previous = reader.manifest(ROOT)
        binding = json.loads((ROOT / "native/runtime_mcp_sources.json").read_bytes())
        names = set(binding["sources"]) | set(previous["current_native_sources"])
        names.update(previous["restore"])
        names.update(cls.authority["restore"])
        names.update(row["fixture"] for row in cls.authority["restore"].values())
        names.update(cls.authority["workflow_inputs"])
        names.update((str(projection.PROFILE), str(projection.READER), str(reader.PROFILE)))
        names.update(row["path"] for row in (previous["profile"], previous["reference_profile"]))
        names.update(str(reader.FIXTURE / name) for name in previous["restore"])
        names.add(str(reader.FIXTURE / previous["original_reader"]["path"]))
        for name in sorted(names):
            path = cls.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)
            path.chmod((ROOT / name).stat().st_mode & 0o777)
        projection.admit(cls.source)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_every_restored_or_excluded_current_preimage_is_required(self):
        names = set(self.authority["restore"]) | set(self.authority["exclude_native_sources"])
        for name in sorted(names):
            path = self.source / name
            original = path.read_bytes()
            try:
                with self.subTest(path=name):
                    path.write_bytes(original + b"\x00")
                    with self.assertRaisesRegex(ValueError, "preimage changed"):
                        projection.admit(self.source)
            finally:
                path.write_bytes(original)

    def test_all_retained_source_preimages_and_authorities_are_fixed(self):
        for row in self.authority["restore"].values():
            path = self.source / row["fixture"]
            original = path.read_bytes()
            try:
                with self.subTest(fixture=row["fixture"]):
                    path.write_bytes(original + b"\x00")
                    with self.assertRaisesRegex(ValueError, "preimage changed"):
                        projection.admit(self.source)
            finally:
                path.write_bytes(original)
        path = self.source / projection.PROFILE
        original = path.read_bytes()
        try:
            changed = json.loads(original)
            changed["restore"].clear()
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "authority changed"):
                projection.admit(self.source)
        finally:
            path.write_bytes(original)

    def test_unrestored_source_changes_and_new_native_inputs_are_refused(self):
        binding = json.loads((self.source / "native/runtime_mcp_sources.json").read_bytes())
        name = next(name for name in binding["sources"]
                    if name.startswith("tests/") and name not in self.authority["restore"])
        path = self.source / name
        original = path.read_bytes()
        try:
            path.write_bytes(original + b"\x00")
            with self.assertRaisesRegex(ValueError, "preimage changed"):
                projection.admit(self.source)
        finally:
            path.write_bytes(original)
        extra = self.source / "native/unregistered_writer_projection.hepta"
        try:
            extra.write_bytes(b"unowned source\n")
            with self.assertRaisesRegex(ValueError, "native inventory changed"):
                projection.admit(self.source)
        finally:
            extra.unlink()

    def test_all_output_bytes_modes_and_receipts_are_bound_and_current_stays_intact(self):
        output = self.base / "retained-read"
        before = projection.snapshot(self.source)
        receipt = projection.project(self.source, output)
        self.assertEqual(projection.snapshot(self.source), before)
        self.assertEqual(projection.verify(self.source, output)["status"], "WRITER_SOURCE_PROJECTION_VERIFIED")
        self.assertEqual(receipt["restored_paths"], sorted(self.authority["restore"]))
        self.assertTrue((self.source / "native/public_io_gateway.hepta").is_file())
        self.assertFalse((output / "native/public_io_gateway.hepta").exists())
        self.assertTrue((output / "asm/binary_read_body_callable.S").is_file())
        projection.old_reader(output).admit_current(output)
        path = output / "scripts/hia_native_runtime_mcp_build.py"
        original = path.read_bytes()
        try:
            path.write_bytes(original + b"\x00")
            with self.assertRaisesRegex(ValueError, "receipt or files changed"):
                projection.verify(self.source, output)
        finally:
            path.write_bytes(original)
        original_mode = path.stat().st_mode & 0o777
        try:
            path.chmod(original_mode ^ 0o100)
            with self.assertRaisesRegex(ValueError, "receipt or files changed"):
                projection.verify(self.source, output)
        finally:
            path.chmod(original_mode)
        path = output / projection.RECEIPT
        original = path.read_bytes()
        try:
            forged = json.loads(original)
            forged["projected_files"].pop("asm/binary_read_body_callable.S")
            path.write_text(json.dumps(forged))
            with self.assertRaisesRegex(ValueError, "receipt or files changed"):
                projection.verify(self.source, output)
        finally:
            path.write_bytes(original)
        self.assertEqual(projection.snapshot(self.source), before)

    def test_original_reader_and_original_profile_are_not_redefined(self):
        path = self.source / projection.READER
        original = path.read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), projection.READER_SHA256)
        try:
            path.write_bytes(original + b"\n")
            with self.assertRaisesRegex(ValueError, "original current projection reader changed"):
                projection.admit(self.source)
        finally:
            path.write_bytes(original)
        reader = projection.old_reader(self.source)
        self.assertEqual(reader.pin(reader.read(self.source, reader.PROFILE)), reader.PROFILE_PIN)

    def test_source_drift_at_terminal_readback_is_refused(self):
        reader = projection.old_reader(self.source)
        path = self.source / "native/jobs_audit_namespace.hepta"
        original = path.read_bytes()
        original_read = reader.read
        calls = 0

        def drift(root, name):
            nonlocal calls
            if root / name == path:
                calls += 1
                if calls == 3:
                    path.write_bytes(original + b"\x00")
            return original_read(root, name)

        try:
            with mock.patch.object(projection, "old_reader", return_value=reader), \
                    mock.patch.object(reader, "read", side_effect=drift):
                with self.assertRaisesRegex(ValueError, "terminal readback"):
                    projection.admit(self.source)
            self.assertEqual(calls, 3)
        finally:
            path.write_bytes(original)

    def test_symbolic_sources_and_in_tree_or_existing_destinations_are_refused(self):
        reader = projection.old_reader(self.source)
        name = next(iter(self.authority["restore"]))
        path = self.source / name
        original = path.read_bytes()
        saved = self.base / "saved-current-file"
        saved.write_bytes(original)
        try:
            path.unlink()
            path.symlink_to(saved)
            with self.assertRaisesRegex(ValueError, "symbolic links"):
                projection.admit(self.source)
        finally:
            path.unlink()
            path.write_bytes(original)
        for output in (self.source / "inside", self.base):
            with self.subTest(output=output), self.assertRaisesRegex(ValueError, "fresh independent output"):
                projection.project(self.source, output)


if __name__ == "__main__":
    unittest.main()
