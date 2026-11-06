#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Refusal and wire-integrity checks; fake MCPs never qualify an operation."""

from copy import deepcopy
from contextlib import redirect_stdout
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
    def test_actual_operation_entrypoint_reaches_argument_parser(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            q.main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("--reference-tarball", output.getvalue())

    def test_build_summary_and_pin_are_required_together_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "not-created"
            argv = ["--operation", "inspect_elf_notes", "--repo", "/unused/repo",
                    "--binary", "/unused/native", "--binary-sha256", "0" * 64,
                    "--reference-package", "/unused/package", "--reference-tarball", "/unused/package.tgz",
                    "--node", "/unused/node", "--output-dir", str(output)]
            for extra in (["--build-summary", "/unused/summary.json"],
                          ["--build-summary-sha256", "0" * 64]):
                with self.subTest(extra=extra), mock.patch.object(q, "reference_package") as package, \
                        mock.patch.object(q.subprocess, "run") as process, \
                        self.assertRaisesRegex(q.QualificationError, "must be supplied together"):
                    q.main(argv + extra)
                package.assert_not_called()
                process.assert_not_called()
                self.assertFalse(output.exists())

    def test_duplicate_members_and_nonfinite_numbers_fail_closed(self):
        for raw in (b'{"x":1,"x":2}', b'NaN', b'1e400', b'Infinity', b'-Infinity'):
            with self.subTest(raw=raw), self.assertRaises(q.QualificationError):
                q.parse_json(raw)

    def test_json_equality_distinguishes_every_kind_and_nested_boolean_numbers(self):
        values = [None, False, 0, "0", [], {}]
        for left_index, left in enumerate(values):
            for right_index, right in enumerate(values):
                with self.subTest(left=left, right=right):
                    self.assertEqual(q.json_equal(left, right), left_index == right_index)
        for left, right in ((False, 0), (False, 0.0), (True, 1), (True, 1.0)):
            with self.subTest(left=left, right=right):
                self.assertFalse(q.json_equal({"nested": [{"value": left}]}, {"nested": [{"value": right}]}))
                self.assertFalse(q.json_equal([right], [left]))
        self.assertFalse(q.json_equal({}, {"omitted": None}))
        self.assertFalse(q.json_equal([1, 2], [2, 1]))
        self.assertTrue(q.json_equal({"a": [1, False], "b": None}, {"b": None, "a": [1, False]}))

    def test_numeric_equality_preserves_reviewed_spellings_without_rounding_integers(self):
        for left, right in ((1, 1.0), (1, q.parse_json(b'1e0')), (0, -0.0),
                            (10 ** 400, 10 ** 400), (9007199254740992, 9007199254740992.0)):
            with self.subTest(left=left, right=right):
                self.assertTrue(q.json_equal({"value": left}, {"value": right}))
        self.assertFalse(q.json_equal(9007199254740993, float(9007199254740993)))
        self.assertFalse(q.json_equal(10 ** 400, 10 ** 400 + 1))

    def test_nonfinite_and_non_json_values_cannot_compare_equal(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                self.assertFalse(q.finite_number(value))
                self.assertFalse(q.json_equal(value, value))
                self.assertFalse(q.json_equal({"nested": [value]}, {"nested": [value]}))
        for value in ((1,), {1: "numeric key"}, {True: "boolean key"}, {1}, b"text"):
            with self.subTest(value=value):
                self.assertFalse(q.json_equal(value, value))
        self.assertFalse(q.finite_number(True))
        self.assertFalse(q.finite_number(False))

    def test_raw_request_cannot_replace_numeric_argument_with_boolean(self):
        client = q.Mcp.__new__(q.Mcp)
        client.process, client._log = mock.Mock(), mock.Mock()
        params = {"name": "inspect_elf_notes", "arguments": {"max_entries": 1}}
        raw = b'{"name":"inspect_elf_notes","arguments":{"max_entries":true}}'
        with self.assertRaisesRegex(q.QualificationError, "parsed facts"):
            client.send("tools/call", params, 1, raw)
        client.process.stdin.write.assert_not_called()
        client._log.assert_not_called()
        client.send("tools/call", params, 1, raw.replace(b'true', b'1e0'))
        self.assertIn(b'"max_entries":1e0', client.process.stdin.write.call_args.args[0])

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

    def test_structured_content_cannot_change_boolean_number_types(self):
        for text, structured in ((False, 0), (True, 1), (1, True), (0.0, False)):
            with self.subTest(text=text, structured=structured), \
                    self.assertRaisesRegex(q.QualificationError, "disagreement"):
                q.tool_value({"result": {"content": [{"type": "text", "text": json.dumps({"nested": [text]})}],
                                         "structuredContent": {"nested": [structured]}}})

    def test_complete_result_rejects_numeric_retryable_and_error_flags(self):
        def response(retryable=False, is_error=True):
            return {"result": {"isError": is_error, "content": [{"type": "text", "text": json.dumps(
                {"error": {"code": "invalid_request", "retryable": retryable}})}]}}
        for changed in (response(retryable=0), response(is_error=1)):
            with self.subTest(changed=changed), \
                    self.assertRaisesRegex(q.QualificationError, "full public MCP result differs"):
                q.compare_case({"kind": "error"}, response(), changed)

    def test_evidence_provenance_requires_a_boolean_untrusted_flag(self):
        response = {"result": {"content": [{"type": "text", "text": "{}"}], "structuredContent": {},
                               "_meta": {"provenance": {"untrusted_content": 1, "source": "analysis_target"}}}}
        with self.assertRaisesRegex(q.QualificationError, "target provenance"):
            q.evidence_value(response)

    def test_summary_counts_cannot_be_booleans(self):
        payload = {"kind": "evidence-bundle-summary", "filters": {}, "total_retained_records": 0,
                   "matching_records": 0, "unknown_revisions": 0, "records": []}
        query = {"arguments": {"detail": "summary"}}
        for field in ("total_retained_records", "matching_records", "unknown_revisions"):
            with self.subTest(field=field), self.assertRaisesRegex(q.QualificationError, "summary/filter projection"):
                structured = {"result": {**payload, field: False}}
                response = {"result": {"content": [{"type": "text", "text": json.dumps(structured)}],
                                       "structuredContent": structured, "_meta": q.TARGET_META}}
                q.check_retention_response(query, response, [])

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

    def test_schema_keywords_and_annotations_cannot_change_boolean_number_types(self):
        rows = [{"name": name, "inputSchema": {"type": "object", "additionalProperties": False},
                 "outputSchema": {"type": "object"}, "annotations": {"readOnlyHint": True}}
                for name in ("inspect_elf_notes", "get_evidence_bundle")]
        for field, keyword, replacement in (("inputSchema", "additionalProperties", 0),
                                            ("annotations", "readOnlyHint", 1)):
            native = [{**deepcopy(row), "name": "rea_" + row["name"]} for row in rows]
            native[0][field][keyword] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(q.QualificationError, field):
                q.compare_registration(rows, native)

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
