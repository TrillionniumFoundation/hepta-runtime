#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Negative checks for the independent public MCP qualification producer."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rea_apk_export_qualification as runner


class ProducerBoundaries(unittest.TestCase):
    def test_rebinding_preserves_numeric_spelling_and_nested_order(self):
        raw = ' { "z":1,"path":"/old\\u96ea.apk", "view":{"z":1,"offset":-0,"limit":2e0,"a":2},"a":2 } '
        rebound = runner.replace_root_path(raw, '/new/quote"雪.apk')
        self.assertIn('"offset":-0,"limit":2e0', rebound)
        self.assertEqual(rebound[:raw.index('"/old')], raw[:raw.index('"/old')])
        self.assertEqual(json.loads(rebound), {**json.loads(raw), "path": '/new/quote"雪.apk'})
        self.assertEqual(rebound[rebound.index(', "view"'):], raw[raw.index(', "view"'):])

    def test_rebinding_refuses_duplicate_or_missing_root_path(self):
        for raw in ('{"path":"a","path":"b"}', '{"view":{"path":"nested"}}', '[]'):
            with self.assertRaises(ValueError):
                runner.replace_root_path(raw, "/new")

    def test_order_hints_cannot_hide_unknown_properties(self):
        for keys in (["path"], ["path", "z", "z"], ["path", "z", "missing"]):
            with self.assertRaises(ValueError):
                runner.ordered_arguments({"path": "/owned/file", "z": 1}, keys)
        self.assertEqual(list(runner.ordered_arguments({"a": 1, "z": 2}, ["z", "a"])), ["z", "a"])

    def test_full_comparator_keeps_meta_path_provider_errors_and_boolean_type(self):
        original = {"_meta": {"provenance": "target"}, "result": {"path": "/one", "provider": "original", "n": 1},
                    "error": 'Unrecognized keys: "z", "a"'}
        changed = {"result": {"path": "/two", "provider": "native", "n": True},
                   "error": 'Unrecognized keys: "a", "z"'}
        paths = {row["path"] for row in runner.differences(original, changed)}
        self.assertEqual(paths, {"$/_meta", "$/result/path", "$/result/provider", "$/result/n", "$/error"})
        self.assertEqual(runner.differences({"n": 2}, {"n": 2.0}), [])

    def test_mcp_normalizer_never_hides_result_type(self):
        response = {"jsonrpc": "2.0", "id": 1, "result": {
            "content": [{"type": "text", "text": '{"result":{}}'}],
            "structuredContent": {"result": {}}, "resultType": "complete"}}
        normalized = runner.q.tool_value(response)
        self.assertEqual(normalized["resultType"], "complete")
        original = {key: value for key, value in normalized.items() if key != "resultType"}
        self.assertEqual([d["path"] for d in runner.differences(original, normalized)], ["$/resultType"])

    def test_sparse_copy_checks_every_byte_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, target = root / "source", root / "target"
            raw = b"\0" * (2 * 1024 * 1024) + b"tail"
            source.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            fact = runner.sparse_copy(source, target, len(raw), digest)
            self.assertEqual(fact["sha256"], digest)
            self.assertEqual(target.read_bytes(), raw)
            with self.assertRaises(FileExistsError):
                runner.sparse_copy(source, target, len(raw), digest)
            with self.assertRaises(ValueError):
                runner.sparse_copy(source, root / "bad-digest", len(raw), "0" * 64)

    def test_owned_export_cleanup_refuses_changed_or_linked_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs, copies = root / "outputs", root / "copies"
            outputs.mkdir(); copies.mkdir()
            owner = runner.OwnedExports(outputs, copies)
            target = outputs / "complete.json"
            target.write_bytes(b"original")
            captured = owner.observe("first")
            target.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                owner.cleanup()
            self.assertEqual(target.read_bytes(), b"changed")
            self.assertEqual(Path(captured["complete.json"]["saved"]).read_bytes(), b"original")
            target.unlink()
            target.symlink_to(copies / "first-complete.json")
            with self.assertRaises(ValueError):
                owner.observe("second")

    def test_only_verified_owned_exports_are_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outputs, copies = root / "outputs", root / "copies"
            outputs.mkdir(); copies.mkdir()
            target = outputs / "complete.json"
            target.write_bytes(b"canonical\n")
            unrelated = outputs / "not-owned.json"
            unrelated.write_bytes(b"untouched")
            owner = runner.OwnedExports(outputs, copies)
            owner.observe("capture")
            removed = owner.cleanup()
            self.assertEqual([row["path"] for row in removed], [str(target)])
            self.assertFalse(target.exists())
            self.assertEqual(unrelated.read_bytes(), b"untouched")


if __name__ == "__main__":
    unittest.main()
