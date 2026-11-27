"""Verify retained executable identity and rejection of unsafe packaging inputs."""

import contextlib
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import package_weight_research as package


class PackageWeightResearchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "Cargo.lock").write_bytes(b"frozen lock\n")
        for source, _target in package.BINARIES:
            path = self.root / source
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"\x7fELF\0synthetic test payload:" + source.encode())
            path.chmod(0o755)

    def command(self, _root, *args):
        return {
            ("git", "status", "--porcelain", "--untracked-files=no"): "",
            ("git", "rev-parse", "HEAD"): "a" * 40,
            ("git", "rev-parse", "HEAD^{tree}"): "b" * 40,
            ("rustc", "--version"): "rustc 1.95.0 (fixture)",
            ("cargo", "--version"): "cargo 1.95.0 (fixture)",
        }[args]

    def test_archive_payloads_match_manifest_and_original_bytes(self):
        output = self.root / "output"
        with mock.patch.object(package, "command", side_effect=self.command):
            with contextlib.redirect_stdout(io.StringIO()):
                package.package(self.root, output)
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["source_commit"], "a" * 40)
        with tarfile.open(output / "weight-source-bound-research.tar.gz") as archive:
            self.assertEqual(archive.extractfile("manifest.json").read(), (output / "manifest.json").read_bytes())
            for entry in manifest["files"]:
                data = archive.extractfile(entry["path"]).read()
                self.assertEqual(data, (self.root / entry["build_path"]).read_bytes())
                self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])
                self.assertEqual(archive.getmember(entry["path"]).mode, 0o755)
        self.assertFalse(manifest["model_execution_performed"])
        self.assertFalse(manifest["production_eligible"])

    def test_dirty_source_and_changed_toolchain_reject_before_output(self):
        for rejected in ("dirty", "compiler"):
            def modified(root, *args):
                if rejected == "dirty" and args[1] == "status":
                    return " M src/lib.rs"
                if rejected == "compiler" and args[0] == "rustc":
                    return "rustc 1.96.0 (fixture)"
                return self.command(root, *args)
            output = self.root / rejected
            with mock.patch.object(package, "command", side_effect=modified):
                with self.assertRaises(ValueError):
                    package.package(self.root, output)
            self.assertFalse(output.exists())

    def test_existing_output_is_not_replaced(self):
        output = self.root / "output"
        output.mkdir()
        sentinel = output / "retained"
        sentinel.write_bytes(b"old evidence")
        with mock.patch.object(package, "command", side_effect=self.command):
            with self.assertRaises(FileExistsError):
                package.package(self.root, output)
        self.assertEqual(sentinel.read_bytes(), b"old evidence")

    def test_symlink_and_nonexecutable_source_reject(self):
        source, target = package.BINARIES[0]
        path = self.root / source
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            package.stage_binary(self.root, source, self.root / "stage", target)
        path.unlink()
        path.symlink_to(self.root / "Cargo.lock")
        with self.assertRaises(ValueError):
            package.stage_binary(self.root, source, self.root / "stage", target)

    def test_changed_copy_rejects_before_manifest(self):
        source, target = package.BINARIES[0]
        def corrupt(_source, destination):
            destination.write_bytes(b"different executable")
        with mock.patch.object(package.shutil, "copyfile", side_effect=corrupt):
            with self.assertRaises(ValueError):
                package.stage_binary(self.root, source, self.root / "stage", target)


if __name__ == "__main__":
    unittest.main()
