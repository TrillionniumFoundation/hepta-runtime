#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Read-only consumer rejection controls; not native cache execution evidence."""

import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import rea_operation_qualification as q
import rea_readback_capacity_evidence as evidence
import rea_readback_capacity_qualification as capacity


class RetainedInputTests(unittest.TestCase):
    def test_disk_export_does_not_expand_the_mcp_receive_boundary(self):
        allowance = q.MAX_WIRE_BYTES
        raw = b'{"payload":"' + b'x' * (allowance + 8) + b'"}'
        self.assertEqual(len(capacity.parse_export(raw)["payload"]), allowance + 8)
        with self.assertRaises(ValueError):
            q.parse_json(raw)
        self.assertEqual(q.MAX_WIRE_BYTES, allowance)
        for malformed in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}'):
            with self.subTest(raw=malformed), self.assertRaises(ValueError):
                capacity.parse_export(malformed)

    def test_expected_factory_does_not_create_or_repair_the_original_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "workspace"
            inputs = capacity.fixtures(workspace, write=False)
            self.assertEqual(set(inputs), {"small", "aggregate", "single"})
            self.assertFalse(workspace.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_valid_tampered_and_deleted_inputs_are_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir()
            path = workspace / "small.elf"
            raw = q.elf(q.note())
            path.write_bytes(raw)
            expected = {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            before = path.stat()
            evidence.validate_input(root, "small", expected, expected)
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(path.stat().st_mtime_ns, before.st_mtime_ns)
            changed = raw[:-1] + bytes([raw[-1] ^ 1])
            path.write_bytes(changed)
            before = path.stat()
            with self.assertRaises(ValueError):
                evidence.validate_input(root, "small", expected, expected)
            self.assertEqual(path.read_bytes(), changed)
            self.assertEqual(path.stat().st_mtime_ns, before.st_mtime_ns)
            path.unlink()
            before = workspace.stat()
            with self.assertRaises((ValueError, OSError)):
                evidence.validate_input(root, "small", expected, expected)
            self.assertFalse(path.exists())
            self.assertEqual(workspace.stat().st_mtime_ns, before.st_mtime_ns)


if __name__ == "__main__":
    unittest.main()
