#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Negative tests for qualification receipt consumption, never parity fixtures."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rea_operation_evidence as evidence
q = evidence.q


def wire_pair(arguments, result, name="inspect_elf_notes", identifier=1, raw_arguments=None):
    request = {"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
               "params": {"name": name, "arguments": arguments}}
    response = {"jsonrpc": "2.0", "id": identifier, "result": result}
    request_raw = json.dumps(request)
    if raw_arguments is not None:
        request_raw = request_raw.replace(json.dumps(arguments), raw_arguments)
    return b"".join(json.dumps({"direction": direction, "monotonic_ns": index,
                                "wire_utf8": raw + "\n"}).encode() + b"\n"
                    for index, (direction, raw) in enumerate((("sent", request_raw),
                                                             ("received", json.dumps(response))), 1)), response


class OperationEvidenceTests(unittest.TestCase):
    def test_artifact_tamper_size_path_and_symlink_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "result.json"
            path.write_bytes(b'{}\n')
            reference = q.artifact_reference(path, root)
            self.assertEqual(evidence.read_artifact(root, reference), b'{}\n')
            path.write_bytes(b'[]\n')
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                evidence.read_artifact(root, reference)
            for unsafe in ("../escape", "/absolute", "x\\y", "C:escape"):
                with self.subTest(path=unsafe), self.assertRaises(ValueError):
                    evidence.contained_path(root, unsafe)
            (root / "link").symlink_to(path)
            with self.assertRaisesRegex(ValueError, "symlink"):
                evidence.read_artifact(root, {**reference, "path": "link"})

    def test_response_and_input_must_both_exist_on_original_wire(self):
        arguments = {"path": "/tmp/fixture"}
        raw, response = wire_pair(arguments, {"content": [{"type": "text", "text": "{}"}]})
        wire = evidence.wire_index(raw)
        evidence.bind_call(wire, response, "inspect_elf_notes", arguments)
        with self.assertRaisesRegex(ValueError, "actual public MCP request"):
            evidence.bind_call(wire, response, "inspect_elf_notes", {"path": "/tmp/other"})
        changed = deepcopy(response)
        changed["result"]["content"][0]["text"] = '{"invented":true}'
        with self.assertRaisesRegex(ValueError, "absent from the original wire"):
            evidence.bind_call(wire, changed, "inspect_elf_notes", arguments)

    def test_duplicate_response_and_unmatched_response_are_refused(self):
        raw, _ = wire_pair({}, {"content": []})
        with self.assertRaisesRegex(ValueError, "duplicate"):
            evidence.wire_index(raw + raw.splitlines(keepends=True)[1])
        with self.assertRaisesRegex(ValueError, "no original request"):
            evidence.wire_index(raw.splitlines(keepends=True)[1])

    def test_numeric_spellings_are_bound_to_actual_wire_bytes(self):
        args = {"max_entries": 1}
        raw, response = wire_pair(args, {"content": []}, raw_arguments='{"max_entries":1e0}')
        wire = evidence.wire_index(raw)
        evidence.bind_call(wire, response, "inspect_elf_notes", args, ["max_entries", "1e0"])
        with self.assertRaisesRegex(ValueError, "not transmitted"):
            evidence.bind_call(wire, response, "inspect_elf_notes", args, ["max_entries", "1.0"])

    def test_schema_summary_cannot_replace_the_original_tools_list(self):
        rows = [{"name": "inspect_elf_notes", "inputSchema": {"additionalProperties": False}}]
        wire = {"sent": {1: {"method": "tools/list"}}, "received": {1: {"result": {"tools": rows}}}}
        evidence.bind_tools(wire, rows)
        with self.assertRaisesRegex(ValueError, "original tools/list"):
            evidence.bind_tools(wire, [{"name": "inspect_elf_notes", "inputSchema": {"additionalProperties": True}}])

    def test_missing_or_duplicated_cases_are_not_qualified(self):
        cases = [{"id": "boundary", "kind": "error", "arguments": {}}]
        for observations in ([], [{"id": "invented"}], [{"id": "boundary"}, {"id": "boundary"}]):
            with self.subTest(observations=observations), self.assertRaisesRegex(ValueError, "required case set"):
                evidence.case_results(cases, observations, Path("/unused"), {}, {})

    def test_handwritten_case_pass_does_not_override_different_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = [{"id": "boundary", "kind": "error", "arguments": {}}]
            left_raw, left = wire_pair({}, {"content": [{"type": "text", "text": '{"error":{"code":"invalid_request"}}'}], "isError": True})
            right_raw, right = wire_pair({}, {"content": [{"type": "text", "text": '{"error":{"code":"provider_failed"}}'}], "isError": True}, "rea_inspect_elf_notes")
            row = {"id": "boundary", "status": "PASS", "comparison": {"full_envelope_equal": True},
                   "reference": q.artifact_json(root, "left.json", left), "native": q.artifact_json(root, "right.json", right)}
            result, retained = evidence.case_results(cases, [row], root,
                evidence.wire_index(left_raw), evidence.wire_index(right_raw))
            self.assertFalse(result["boundary"]["passed"])
            self.assertEqual(retained, {})

    def test_manual_cleanup_is_not_owner_completion(self):
        original = {"returncode": 0, "forced_cleanup": [], "reader_stopped": True, "elapsed_seconds": 0.2,
                    "owner_pidfd_exited": True, "process_group_gone": True}
        self.assertTrue(evidence.owner_closed(original))
        for changes in ({"forced_cleanup": ["SIGTERM"]}, {"returncode": -9},
                        {"reader_stopped": False}, {"elapsed_seconds": q.EOF_SECONDS + 2},
                        {"owner_pidfd_exited": False}, {"process_group_gone": False}):
            self.assertFalse(evidence.owner_closed({**original, **changes}))

    def test_finite_success_stays_open_when_profile_requirements_are_unimplemented(self):
        result = evidence.derive_assessment({"sample": {"passed": True}}, True, True, True,
                                            q.UNIMPLEMENTED_REQUIREMENTS)
        self.assertEqual(result["status"], "OPEN")
        self.assertNotIn("limits_and_cancellation", result["passed_gates"])
        self.assertNotIn("typed_outcomes", result["passed_gates"])
        self.assertNotIn("format_architecture_corpus", result["passed_gates"])

    def test_index_does_not_accept_pass_fields_or_unknown_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / evidence.INDEX_PATH
            path.parent.mkdir(parents=True)
            self.assertEqual(evidence.consume_index(root, [], {}), {})
            path.write_text(json.dumps({"schema": evidence.INDEX_SCHEMA, "entries": [], "qualified": True}))
            with self.assertRaisesRegex(ValueError, "handwritten PASS"):
                evidence.consume_index(root, [], {})
            path.write_text(json.dumps({"schema": evidence.INDEX_SCHEMA, "entries": [
                {"operation": "inspect_elf_notes", "profile": "invented", "report": "r.json", "sha256": "0" * 64}]}))
            with self.assertRaisesRegex(ValueError, "unknown or duplicate"):
                evidence.consume_index(root, [{"upstream_tool": "inspect_elf_notes"}], {})

    def test_partial_implementation_cannot_be_promoted_by_a_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / evidence.INDEX_PATH
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({"schema": evidence.INDEX_SCHEMA, "entries": [
                {"operation": "inspect_elf_notes", "profile": q.PROFILE, "report": "r.json", "sha256": "0" * 64}]}))
            mapping = {"family_defaults": {"native": {"implementation": "partial_operation"}}, "overrides": {}}
            with mock.patch.object(evidence, "validate_report", return_value={"status": "QUALIFIED"}):
                actual = evidence.consume_index(root, [{"upstream_tool": "inspect_elf_notes", "family": "native"}], mapping)
            self.assertEqual(actual["inspect_elf_notes"]["status"], "OPEN")


if __name__ == "__main__":
    unittest.main()
