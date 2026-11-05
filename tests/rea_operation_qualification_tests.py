#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Refusal and wire-integrity checks; fake MCPs never qualify an operation."""

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rea_operation_qualification as q


class OperationQualificationTests(unittest.TestCase):
    def test_duplicate_members_and_nonfinite_numbers_fail_closed(self):
        for raw in (b'{"x":1,"x":2}', b'NaN', b'1e400', b'-Infinity'):
            with self.subTest(raw=raw), self.assertRaises(q.QualificationError):
                q.parse_json(raw)

    def test_text_json_key_order_is_not_a_behavior_difference(self):
        left = {"id": 1, "result": {"content": [{"type": "text", "text": '{"b":2,"a":1}'}],
                                   "structuredContent": {"a": 1, "b": 2}, "_meta": q.TARGET_META}}
        right = deepcopy(left)
        right["result"]["content"][0]["text"] = '{ "a" : 1, "b" : 2 }'
        self.assertEqual(q.tool_value(left), q.tool_value(right))

    def test_result_envelope_is_not_removed_from_comparison(self):
        left = {"result": {"content": [{"type": "text", "text": '{"x":1}'}], "structuredContent": {"x": 1}}}
        right = deepcopy(left)
        right["result"]["_meta"] = q.TARGET_META
        self.assertNotEqual(q.tool_value(left), q.tool_value(right))
        right = deepcopy(left)
        right["result"]["isError"] = True
        self.assertNotEqual(q.tool_value(left), q.tool_value(right))

    def test_structured_text_disagreement_is_rejected(self):
        with self.assertRaisesRegex(q.QualificationError, "disagreement"):
            q.tool_value({"result": {"content": [{"type": "text", "text": '{"x":1}'}],
                                     "structuredContent": {"x": 2}}})

    def test_non_json_text_is_compared_exactly(self):
        left = {"result": {"content": [{"type": "text", "text": 'not JSON'}]}}
        right = {"result": {"content": [{"type": "text", "text": 'different text'}]}}
        self.assertEqual(q.tool_value(left)["content"][0]["text"], "not JSON")
        self.assertNotEqual(q.tool_value(left), q.tool_value(right))

    def test_missing_route_and_full_schema_drift_are_rejected(self):
        rows = [{"name": name, "inputSchema": {"type": "object", "additionalProperties": False},
                 "outputSchema": {"type": "object"}, "annotations": {"readOnlyHint": False}}
                for name in ("inspect_elf_notes", "get_evidence_bundle")]
        native = [{**row, "name": "rea_" + row["name"]} for row in rows]
        self.assertEqual(len(q.compare_registration(rows, native)), 6)
        native[0] = {**native[0], "inputSchema": {"type": "object", "additionalProperties": True}}
        with self.assertRaisesRegex(q.QualificationError, "inputSchema"):
            q.compare_registration(rows, native)
        with self.assertRaisesRegex(q.QualificationError, "missing public MCP"):
            q.compare_registration(rows, native[1:])

    def test_elf_fixture_bytes_have_independent_endianness_and_alias_facts(self):
        for bits in (32, 64):
            for order, prefix in (("little", "<"), ("big", ">")):
                raw = q.elf(q.note(order=order), bits=bits, order=order, section=True)
                self.assertEqual(raw[:4], b"\x7fELF")
                self.assertEqual(raw[4], 1 if bits == 32 else 2)
                self.assertEqual(raw[5], 1 if order == "little" else 2)
                if bits == 64:
                    phoff, shoff = struct.unpack_from(prefix + "QQ", raw, 32)
                    offset, size = struct.unpack_from(prefix + "Q16xQ", raw, phoff + 8)
                    section_offset, section_size = struct.unpack_from(prefix + "QQ", raw, shoff + 64 + 24)
                else:
                    phoff, shoff = struct.unpack_from(prefix + "II", raw, 28)
                    offset, size = struct.unpack_from(prefix + "I8xI", raw, phoff + 4)
                    section_offset, section_size = struct.unpack_from(prefix + "II", raw, shoff + 40 + 16)
                self.assertEqual((offset, size), (section_offset, section_size))
                self.assertEqual(struct.unpack_from(prefix + "III", raw, offset), (4, 20, 3))
                self.assertEqual(raw[offset + 12:offset + 16], b"GNU\0")
                self.assertEqual(raw[offset + 16:offset + 36], bytes(range(20)))

    def test_fixture_manifest_contains_contract_boundary_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            fixtures, cases = q.fixture_cases(Path(directory))
            ids = [case["id"] for case in cases]
            self.assertEqual(len(ids), len(set(ids)))
            self.assertTrue({"explicit_defaults", "integer_spelling_1_0", "integer_spelling_1e0",
                             "unknown_key", "max_entries_invalid_0", "aliased_program_section",
                             "entry_budget", "file_budget", "nonzero_tail"} <= set(ids))
            for fixture in fixtures.values():
                self.assertEqual(q.file_hash(fixture["path"]), fixture["sha256"])

    def test_integer_only_evidence_verifier_refuses_float_or_hidden_semantic_change(self):
        value = {key: None for key in ("analysis_profile", "raw_result", "environment", "relationship_coverage")}
        value.update(subject={"digest": {"sha256": "0" * 64}, "format": "elf", "architecture": None,
                              "name": "display", "local_path": "/display"},
                     provider=q.PROVIDER, predicate_type="rea.analysis", operation="inspect_elf_notes",
                     parameters={"max_entries": 32}, normalized_result={"count": 1}, confidence="observed",
                     authority="shipped-artifact", limitations=[], locations=[], evidence_links=[])
        original = q.semantic_evidence_id(value)
        value["subject"]["local_path"] = "/changed-display"
        self.assertEqual(q.semantic_evidence_id(value), original)
        value["normalized_result"]["count"] = 2
        self.assertNotEqual(q.semantic_evidence_id(value), original)
        value["normalized_result"]["count"] = 1.0
        with self.assertRaises(q.QualificationError):
            q.semantic_evidence_id(value)

    def test_package_authentication_checks_all_installed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "package"
            (package / "dist").mkdir(parents=True)
            files = {"package.json": b'{"name":"rea-agents","version":"6.8.0"}',
                     "dist/mcp-catalog-full.json": b'[]', "implementation.js": b'original\n'}
            archive = root / "package.tgz"
            with tarfile.open(archive, "w:gz") as bundle:
                for name, raw in files.items():
                    (package / name).write_bytes(raw)
                    info = tarfile.TarInfo("package/" + name)
                    info.size = len(raw)
                    bundle.addfile(info, io.BytesIO(raw))
            with mock.patch.object(q, "PACKAGE_SHA256", q.file_hash(archive)), mock.patch.object(
                    q, "CATALOG_SHA256", hashlib.sha256(b'[]').hexdigest()):
                self.assertEqual(q.reference_package(package, archive)["file_count"], 3)
                (package / "implementation.js").write_bytes(b'modified\n')
                with self.assertRaisesRegex(q.QualificationError, "differs from the frozen"):
                    q.reference_package(package, archive)

    def test_package_extra_file_and_symlink_are_not_authenticated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "package.tgz"
            package = root / "package"
            package.mkdir()
            with tarfile.open(archive, "w:gz") as bundle:
                raw = b'{}'
                info = tarfile.TarInfo("package/package.json")
                info.size = len(raw)
                bundle.addfile(info, io.BytesIO(raw))
                (package / "package.json").write_bytes(raw)
            with mock.patch.object(q, "PACKAGE_SHA256", q.file_hash(archive)):
                (package / "extra.js").write_bytes(b'not from npm')
                with self.assertRaisesRegex(q.QualificationError, "differs from the frozen"):
                    q.reference_package(package, archive)
                (package / "extra.js").unlink()
                (package / "extra.js").symlink_to(package / "package.json")
                with self.assertRaisesRegex(q.QualificationError, "symlink"):
                    q.reference_package(package, archive)


if __name__ == "__main__":
    unittest.main()
