#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Offline pinned contract and create-only release-staging safety tests.

No native services, tunnel processes, SSH peers, user credentials or actual
release directories are accessed or modified.
"""
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"deploy"))
import stage_dc_parity_v4 as S
from mcp_tool_contract import ToolContract

class FrozenCatalog(unittest.TestCase):
    def open_contract(self, version):
        path = ROOT/f"deploy/contracts/hepta-runtime-full-operator-v{version}.json"
        return ToolContract.load(path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_v4_is_only_four_real_file_primitives_beyond_original(self):
        initial = self.open_contract(1)
        current = self.open_contract(4)
        self.assertEqual(len(initial.tools), 46)
        self.assertEqual(len(current.tools), 50)
        self.assertEqual(set(current.by_name)-set(initial.by_name), {
            "directory_create", "file_move", "text_file_write", "directory_move"})
        for name, tool in initial.by_name.items():
            self.assertEqual(current.by_name[name], tool, name)
        self.assertEqual(current.catalog_sha256,
                         "63742708c287e8468d73f27ba85ecc6585afd4adcd76d06b618456730cfaf8ad")
        for name in ("directory_create", "file_move", "text_file_write", "directory_move"):
            self.assertIs(current.by_name[name]["annotations"]["readOnlyHint"], False)
            self.assertIs(current.by_name[name]["annotations"]["openWorldHint"], False)

    def test_every_version_is_monotonically_additive_without_schema_drift(self):
        for version, expected in ((2,48),(3,49),(4,50)):
            previous=self.open_contract(version-1)
            current=self.open_contract(version)
            self.assertEqual(len(current.tools), expected)
            for name,tool in previous.by_name.items():
                self.assertEqual(current.by_name[name],tool,name)

    def test_stager_rejects_overwrite_different_or_untrusted_assets(self):
        with tempfile.TemporaryDirectory() as d:
            path=pathlib.Path(d)/"nested/binary"
            S.exact_file(path, b"safe", 0o600)
            S.exact_file(path, b"safe", 0o600)
            self.assertEqual(path.read_bytes(), b"safe")
            with self.assertRaises(FileExistsError):
                S.exact_file(path, b"changed", 0o600)
            self.assertEqual(path.read_bytes(), b"safe")
            path.chmod(0o666)
            with self.assertRaises(PermissionError):
                S.exact_file(path, b"safe", 0o600)

    def test_stager_does_not_follow_symlink_output(self):
        with tempfile.TemporaryDirectory() as d:
            parent=pathlib.Path(d)
            origin=parent/"original"
            origin.write_bytes(b"do not touch")
            symlink=parent/"output"
            symlink.symlink_to(origin)
            with self.assertRaises(FileExistsError):
                S.exact_file(symlink, b"do not touch", 0o600)
            self.assertEqual(origin.read_bytes(), b"do not touch")

if __name__=="__main__":
    unittest.main(verbosity=2)
