#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Synthetic Git/source custody controls; no fixture is a native executable."""
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "hia_native_bootstrap_distribution", Path(__file__).with_name("hia_native_bootstrap_distribution.py"))
distribution = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(distribution)


class NativeBootstrapDistributionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        self.git(self.source, "init", "-q", "--template=", "--initial-branch=fixture")
        self.names = sorted(distribution.REQUIRED_SOURCES | {"docs/HIA_SELFHOST_CORE_SUPPORT.json"})
        for name in self.names:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"non-executable source fixture\n" + name.encode())
        self.write_json(self.source / "docs/HIA_NATIVE_SOURCE_AUTHORITY.json", {
            "schema": "hepta.hia.native-source-authority.v1", "paths": self.names})
        self.write_json(self.source / "docs/HIA_SELFHOST_CORE_SUPPORT.json", {
            "schema": "hepta.hia.selfhost-core-support.v1", "profile": "distribution-custody-fixture",
            "native_cold_qualification": {"schema": "hepta.hia.selfhost-cold-replay.v2"},
            "source_identity": {"files": {name: sha256((self.source / name).read_bytes()).hexdigest()
                                for name in self.names if name != "docs/HIA_SELFHOST_CORE_SUPPORT.json"}}})
        self.git(self.source, "add", ".")
        self.commit(self.source, "source custody fixture")
        self.source_sha = self.git(self.source, "rev-parse", "HEAD")
        self.source_tree = self.git(self.source, "rev-parse", "HEAD^{tree}")
        self.published = self.root / "published"
        subprocess.run(["git", "clone", "--shared", "--template=", "--quiet",
                        str(self.source), str(self.published)], check=True)
        self.base = self.published / distribution.PREFIX
        (self.base / "bin").mkdir(parents=True)
        (self.base / "evidence").mkdir()
        for name in (*distribution.ROOT_NAMES, distribution.ENTRY):
            path = self.base / "bin" / name
            path.write_bytes(b"non-executable bootstrap custody fixture: " + name.encode())
            path.chmod(0o755)
        self.write_json(self.base / "evidence/construction.json", {
            "scope": "non-executable custody fixture", "native_execution_claimed": False})
        self.manifest = {
            "schema": "hepta.hia.native-bootstrap-distribution.v1", "target": "linux-x86_64",
            "source": {"repository": "TrillionniumFoundation/Hepta", "commit": self.source_sha,
                       "tree": self.source_tree},
            "source_files": {name: self.row(self.source / name) for name in distribution.REQUIRED_SOURCES},
            "executables": {name: {"path": "bin/" + name, **self.row(self.base / "bin" / name)}
                            for name in (*distribution.ROOT_NAMES, distribution.ENTRY)},
            "evidence": {"evidence/construction.json": self.row(self.base / "evidence/construction.json")},
        }
        self.write_manifest()

    @staticmethod
    def git(root, *arguments):
        return subprocess.check_output(["git", "-C", str(root), *arguments], text=True).strip()

    def commit(self, root, message, *, amend=False):
        args = ["-c", "user.name=HIA custody fixture", "-c", "user.email=fixture@example.invalid",
                "-c", "commit.gpgsign=false", "commit", "-qm", message]
        if amend:
            args.append("--amend")
        self.git(root, *args)

    @staticmethod
    def row(path):
        raw = path.read_bytes()
        return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    def write_manifest(self):
        self.write_json(self.base / "manifest.json", self.manifest)
        self.git(self.published, "add", ".")
        previous = self.git(self.published, "rev-parse", "HEAD")
        self.commit(self.published, "distribution custody fixture", amend=previous != self.source_sha)
        self.distribution_sha = self.git(self.published, "rev-parse", "HEAD")

    def admit(self):
        return distribution.admit_distribution(self.source, self.published, self.source_sha, self.distribution_sha)

    def test_exact_pinned_distribution_stages_all_roots_entry_and_only_native_sources(self):
        output = self.root / "staged"
        binding = distribution.stage_distribution(self.source, self.published,
            self.source_sha, self.distribution_sha, output)
        self.assertEqual(binding["source"]["commit"], self.source_sha)
        self.assertEqual(binding["distribution"]["commit"], self.distribution_sha)
        self.assertEqual({p.name for p in (output / "bootstrap").iterdir()}, set(distribution.ROOT_NAMES))
        self.assertEqual((output / distribution.ENTRY).stat().st_mode & 0o777, 0o500)
        for name in self.names:
            self.assertEqual((output / "source" / name).read_bytes(), (self.source / name).read_bytes())
            self.assertEqual((output / "source" / name).stat().st_mode & 0o777, 0o400)
        self.assertFalse((output / "source/.git").exists())
        with self.assertRaisesRegex(RuntimeError, "fresh ordinary output"):
            distribution.stage_distribution(self.source, self.published,
                self.source_sha, self.distribution_sha, output)

    def test_source_tree_and_required_source_pins_cannot_be_rebound(self):
        self.manifest["source"]["tree"] = "0" * 40
        self.write_manifest()
        with self.assertRaisesRegex(RuntimeError, "exact frozen source and target"):
            self.admit()
        self.manifest["source"]["tree"] = self.source_tree
        first = sorted(distribution.REQUIRED_SOURCES)[0]
        self.manifest["source_files"][first]["sha256"] = "f" * 64
        self.write_manifest()
        with self.assertRaisesRegex(RuntimeError, "file differs from its manifest"):
            self.admit()

    def test_missing_root_or_undeclared_extra_file_is_refused(self):
        name = distribution.ROOT_NAMES[0]
        row = self.manifest["executables"].pop(name)
        self.write_manifest()
        with self.assertRaisesRegex(RuntimeError, "exactly seven initial roots"):
            self.admit()
        self.manifest["executables"][name] = row
        self.write_manifest()
        (self.base / "bin/unlisted").write_bytes(b"not a declared root")
        with self.assertRaisesRegex(RuntimeError, "missing or undeclared"):
            self.admit()

    def test_assume_unchanged_cannot_hide_executable_drift(self):
        relative = distribution.PREFIX + "/bin/" + distribution.ROOT_NAMES[0]
        self.git(self.published, "update-index", "--assume-unchanged", relative)
        (self.published / relative).write_bytes(b"different fixture bytes")
        self.assertEqual(self.git(self.published, "status", "--porcelain", "--untracked-files=no"), "")
        with self.assertRaisesRegex(RuntimeError, "file differs from its manifest"):
            self.admit()

    def test_symlinked_or_hardlinked_executable_is_refused(self):
        name = distribution.ROOT_NAMES[0]
        relative = distribution.PREFIX + "/bin/" + name
        path = self.published / relative
        original = path.read_bytes()
        outside = self.root / "outside"
        outside.write_bytes(original)
        self.git(self.published, "update-index", "--assume-unchanged", relative)
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, "symbolic links"):
            self.admit()
        path.unlink()
        path.hardlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, "file type or extent differs"):
            self.admit()

    def test_unsafe_evidence_paths_and_duplicate_manifest_keys_are_refused(self):
        self.manifest["evidence"] = {"../escape": self.row(self.base / "evidence/construction.json")}
        self.write_manifest()
        with self.assertRaisesRegex(RuntimeError, "unsafe relative path"):
            self.admit()
        path = self.base / "manifest.json"
        raw = path.read_text().rstrip()
        path.write_text(raw[:-1] + ',"target":"linux-x86_64"}\n')
        self.git(self.published, "add", ".")
        self.commit(self.published, "duplicate-key fixture", amend=True)
        self.distribution_sha = self.git(self.published, "rev-parse", "HEAD")
        with self.assertRaisesRegex(RuntimeError, "duplicate key"):
            self.admit()

    def test_roots_keep_64_MiB_and_current_entry_keeps_one_MiB_bounds(self):
        root = distribution.ROOT_NAMES[0]
        path = self.base / "bin" / root
        path.write_bytes(b"x" * (1024 * 1024 + 1))
        self.manifest["executables"][root].update(self.row(path))
        self.write_manifest()
        self.admit()
        for name, size in ((root, 64 * 1024 * 1024 + 1), (distribution.ENTRY, 1024 * 1024 + 1)):
            with self.subTest(name=name):
                original = self.manifest["executables"][name]["bytes"]
                self.manifest["executables"][name]["bytes"] = size
                self.write_manifest()
                with self.assertRaisesRegex(RuntimeError, "invalid file extent or pin"):
                    self.admit()
                self.manifest["executables"][name]["bytes"] = original

    def test_distribution_cannot_change_other_source_or_add_another_parent_generation(self):
        (self.published / "unrelated.txt").write_text("outside the sole distribution delta\n")
        self.write_manifest()
        with self.assertRaisesRegex(RuntimeError, "outside its sole added directory"):
            self.admit()
        self.git(self.published, "-c", "user.name=HIA custody fixture", "-c",
                 "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                 "commit", "--allow-empty", "-qm", "foreign parent generation")
        self.distribution_sha = self.git(self.published, "rev-parse", "HEAD")
        with self.assertRaisesRegex(RuntimeError, "direct child"):
            self.admit()

    def test_existing_report_is_not_overwritten_on_refusal(self):
        report = self.root / "retained.json"
        report.write_bytes(b"original retained outcome\n")
        with self.assertRaisesRegex(RuntimeError, "fresh ordinary admission report"):
            distribution.main(["--hepta", str(self.source), "--distribution", str(self.published),
                "--expected-hepta-source", self.source_sha, "--expected-distribution", self.distribution_sha,
                "--output", str(self.root / "staged"), "--report", str(report)])
        self.assertEqual(report.read_bytes(), b"original retained outcome\n")
        self.assertFalse((self.root / "staged").exists())


if __name__ == "__main__":
    unittest.main()
