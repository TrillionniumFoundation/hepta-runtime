#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic local safety/transport tests; never contacts X230."""
import gzip
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

import package_x230_evidence as p
import publication_transfer as t


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-publication-test-")
        self.root = Path(self.temp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.original = b'{"value":"unchanged"}\n' + b"x" * 100000
        (self.evidence / "original.json").write_bytes(self.original)
        (self.evidence / "empty.stderr").write_bytes(b"")
        (self.evidence / "worker-environment.bin").write_bytes(b"TOKIO_WORKER_THREADS=2\0MALLOC_ARENA_MAX=1\0")
        self.package = {"id": "fixture", "archive_stem": "fixture", "repo_dir": "tools/x230/20261104/r16",
                        "bundle_prefix": "r16", "kind": "selectors", "state": "complete", "selectors": [
            {"root": "test", "base": "", "bundle": "r16", "files": ["original.json", "empty.stderr"]},
            {"root": "test", "base": "", "bundle": "r16", "files": ["worker-environment.bin"], "role": "worker-env"}]}
        self.plan = {"schema": p.SCHEMA, "roots": {"test": str(self.evidence)}, "packages": [self.package]}
        self.plan_path = self.root / "plan.json"
        self.plan_path.write_bytes(p.encoded(self.plan))

    def tearDown(self):
        self.temp.cleanup()

    def packed(self):
        inventory = self.root / "inventory.json"
        p.inventory(self.plan_path, "fixture", inventory)
        p.pack(inventory, self.root / "out")
        return inventory, self.root / "out/fixture.tar.gz"

    def test_roundtrip_and_transfer(self):
        _, archive = self.packed()
        self.assertTrue(p.verify(archive, self.root / "out/fixture.manifest.json")["verified"])
        extras = self.root / "extras.json"
        extras.write_bytes(p.encoded({"files": [{"repo_path": "src/example.json", "absolute_remote_path": str(self.evidence / "original.json"), "sha256": p.digest(self.original)}]}))
        remote_index = self.root / "remote-index.json"
        t.remote_index([self.root / "out/fixture.archive.json"], extras, self.root / "stage", remote_index)
        transfer = self.root / "transfer.json"
        t.chunks(remote_index, self.root / "pieces", transfer)
        manifest = json.loads(transfer.read_bytes())
        self.assertTrue(all(piece["base64_bytes"] <= 60000 for entry in manifest["files"] for piece in entry["pieces"]))
        t.assemble(transfer, self.root / "pieces", self.root / "stage", self.root / "local-index.json")
        self.assertEqual((self.root / "stage/src/example.json").read_bytes(), self.original)
        staged = self.root / "stage/tools/x230/20261104/r16/fixture.tar.gz"
        self.assertEqual(staged.read_bytes(), archive.read_bytes())
        expected_git = hashlib.sha1(f"blob {len(self.original)}\0".encode() + self.original, usedforsecurity=False).hexdigest()
        self.assertEqual(t.hashes(self.root / "stage/src/example.json")["git_blob_sha1"], expected_git)
        # An already present, matching source is verified and left untouched.
        t.assemble(transfer, self.root / "pieces", self.root / "stage", self.root / "local-index-again.json")

    def test_buffered_nonzero_tar_tail(self):
        _, archive = self.packed()
        raw = bytearray(gzip.decompress(archive.read_bytes()))
        raw[-100] = 88
        bad = self.root / "bad-tail.tar.gz"
        bad.write_bytes(gzip.compress(bytes(raw), mtime=0))
        with self.assertRaises(ValueError):
            p.verify(bad)

    def test_source_mutation(self):
        inventory = self.root / "inventory.json"
        p.inventory(self.plan_path, "fixture", inventory)
        (self.evidence / "original.json").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            p.pack(inventory, self.root / "out")

    def test_links_and_disguised_payloads(self):
        collector = p.Collector(self.plan, self.package)
        os.symlink(self.evidence / "original.json", self.evidence / "linked.json")
        with self.assertRaises(OSError):
            collector.add("test", "linked.json", "r16/linked.json")
        os.link(self.evidence / "original.json", self.evidence / "hard.json")
        with self.assertRaises(ValueError):
            collector.add("test", "hard.json", "r16/hard.json")
        (self.evidence / "hard.json").unlink()
        for name, payload in [("binary.log", b"\x7fELF" + b"\0" * 32),
                              ("credential.log", b"-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n")]:
            (self.evidence / name).write_bytes(payload)
            with self.assertRaises(ValueError):
                collector.add("test", name, "r16/" + name)

    def test_worker_environment_rejects_other_keys(self):
        (self.evidence / "worker-environment.bin").write_bytes(b"TOKIO_WORKER_THREADS=2\0PRIVATE_TOKEN=not-published\0")
        with self.assertRaises(ValueError):
            p.inventory(self.plan_path, "fixture", self.root / "inventory.json")

    def test_pending_state(self):
        self.package["state"] = "pending"
        self.plan_path.write_bytes(p.encoded(self.plan))
        with self.assertRaises(ValueError):
            p.inventory(self.plan_path, "fixture", self.root / "inventory.json")


if __name__ == "__main__":
    unittest.main(verbosity=2)
