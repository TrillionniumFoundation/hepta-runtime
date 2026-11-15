#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Pinned dependency builds reject altered inputs and publish atomically."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build_tunnel_client", ROOT / "deploy/build_tunnel_client.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class TunnelClientPatchTests(unittest.TestCase):
    def test_repository_patch_matches_the_pinned_manifest(self):
        manifest, patch = builder.load_manifest()
        self.assertEqual(hashlib.sha256(patch.read_bytes()).hexdigest(), manifest["patch_sha256"])

    def test_modified_patch_is_rejected_before_source_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            patch = root / "change.patch"
            patch.write_bytes(b"original patch")
            manifest = {"schema": 1, "patch": patch.name, "patch_sha256": builder.digest(patch)}
            manifest_path = root / "source.json"
            manifest_path.write_text(json.dumps(manifest))
            patch.write_bytes(b"modified patch")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                builder.load_manifest(manifest_path)

    def test_patch_path_cannot_escape_the_deployment_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deploy = root / "deploy"
            deploy.mkdir()
            outside = root / "outside.patch"
            outside.write_bytes(b"not a bundled patch")
            path = deploy / "source.json"
            path.write_text(json.dumps({"schema": 1, "patch": "../outside.patch",
                                        "patch_sha256": builder.digest(outside)}))
            with self.assertRaisesRegex(ValueError, "inside the deployment directory"):
                builder.load_manifest(path)

    def test_failed_copy_preserves_the_installed_binary_and_cleans_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / "built", root / "installed"
            source.write_bytes(b"new binary")
            destination.write_bytes(b"original binary")
            with mock.patch.object(builder.shutil, "copyfile", side_effect=OSError("injected copy failure")):
                with self.assertRaises(OSError):
                    builder.atomic_copy(source, destination)
            self.assertEqual(destination.read_bytes(), b"original binary")
            self.assertEqual(sorted(path.name for path in root.iterdir()), ["built", "installed"])

    def test_local_source_uses_only_the_exact_commit_and_preserves_local_edits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / "original", root / "build"
            source.mkdir()

            def git(*args, input=None):
                return subprocess.check_output(["git", *args], cwd=source, input=input, text=True).strip()

            git("init", "--quiet")
            blob = git("hash-object", "-w", "--stdin", input="committed source\n")
            tree = git("mktree", input=f"100644 blob {blob}\ttracked.txt\n")
            revision = git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                           "commit-tree", tree, "-m", "isolated source fixture")
            git("update-ref", "refs/heads/main", revision)
            git("symbolic-ref", "HEAD", "refs/heads/main")
            git("checkout", "--quiet", "--force")
            (source / "tracked.txt").write_text("local edit\n")
            (source / "untracked.txt").write_text("local only\n")
            builder.checkout_source({"commit": revision}, destination, source)
            self.assertEqual((destination / "tracked.txt").read_text(), "committed source\n")
            self.assertFalse((destination / "untracked.txt").exists())
            self.assertEqual((source / "tracked.txt").read_text(), "local edit\n")
            self.assertEqual((source / "untracked.txt").read_text(), "local only\n")


if __name__ == "__main__":
    unittest.main()
