#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Faults in qualification bookkeeping must not become successful engine claims."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rea_ghidra_analysis_external as harness


class PrivateController:
    def __init__(self, root, response=None, normal=True, error=None):
        self.session_id = "private-controller-fixture"
        self.capture_root = root / self.session_id
        self._client = types.SimpleNamespace(owner={"pid": 7, "start_time": "123", "private_test_fixture": True})
        self.response = response
        self.error = error
        self.close_record = {"schema": "private-test-receipt", "session_id": self.session_id,
                             "normal_close": normal, "owner_close": {"private_test_fixture": True}}

    def raw(self, name, arguments):
        assert name == "rea_get_evidence_bundle" and arguments == {}
        return self.response

    def close(self):
        if self.error:
            raise self.error
        return self.close_record


def bundle_response(records=None, unknowns=None):
    payload = {"result": {key: [] for key in
               ("artifacts", "providers", "environments", "scenarios", "captures", "unknowns", "records")}}
    payload["result"]["records"] = [] if records is None else records
    payload["result"]["unknowns"] = [] if unknowns is None else unknowns
    # Deliberate whitespace and insertion order verify that opaque text survives.
    text = json.dumps(payload, indent=2)
    return {"content": [{"type": "text", "text": text}], "structuredContent": payload,
            "_meta": {"private_test_fixture": True}}


class GhidraHarnessObservationTests(unittest.TestCase):
    def oracle_observation(self, selector):
        oracle = json.loads((Path(__file__).resolve().parent / "fixtures/rea_ghidra_1214_owned_xrefs.json").read_bytes())
        value = {"source_sha256": oracle["artifact_sha256"],
                 "function": {"entry_address": oracle["selected_entry"], "body_ranges": oracle["selected_body_ranges"]},
                 "function_address_requested": oracle["cases"][selector]["requested_address"],
                 "incoming_scope": "selected_function_body_and_entry", "outgoing_scope": "selected_function_body_and_entry",
                 "reference_default_address_space": "ram",
                 "reference_address_format": "default-space-hex-or-utf8-space-unsigned64.v1",
                 "reference_filter": "exclude-isEntryPointReference",
                 "reference_deduplication": "from,to,type,operand,primary",
                 "reference_order": "ghidra-address-from-to-type-operand-primary",
                 "reference_scan_accounting": "raw-includes-entrypoint-filter-and-duplicates.v1"}
        for direction in ("incoming", "outgoing"):
            value[direction + "_references"] = [dict(row, entry_point_reference=False)
                                                 for row in oracle["cases"][selector][direction]["rows"]]
            expected = oracle["native_count_expectations"][direction]
            for field, name in (("scanned_", "scanned"), ("returned_", "returned"), ("budget_omitted_", "budget_omitted")):
                value[field + direction + "_references"] = expected[name]
            value["filtered_" + direction + "_entry_point_references"] = expected["filtered_entry_point"]
            for field, name in (("duplicate_", "duplicate"), ("unique_", "unique"), ("omitted_", "omitted")):
                value[field + direction + "_references_in_scan"] = expected[name]
            value[direction + "_scan_complete"] = expected["scan_complete"]
        return oracle, value

    def test_real_oracle_projection_keeps_order_and_narrow_scope(self):
        for selector in ("entry", "interior"):
            oracle, value = self.oracle_observation(selector)
            counters = harness.assert_revision_four_xrefs(value)
            checked = harness.assert_owned_xref_oracle(value, counters, oracle, selector)
            self.assertFalse(checked["full_evidence_equivalent"])
            self.assertEqual(checked["directions"]["incoming"]["rows"], 3)
            self.assertEqual(checked["directions"]["outgoing"]["rows"], 2)
            changed = copy.deepcopy(value)
            changed["incoming_references"].reverse()
            with self.assertRaises(AssertionError):
                harness.assert_owned_xref_oracle(changed, counters, oracle, selector)
            changed = copy.deepcopy(value)
            changed["outgoing_references"][0]["to_address"] = "Stack[-0xc]"
            with self.assertRaises(AssertionError):
                harness.assert_owned_xref_oracle(changed, counters, oracle, selector)

    def test_raw_count_filter_and_duplicate_faults_cannot_pass(self):
        _, value = self.oracle_observation("entry")
        for field, replacement in (("scanned_incoming_references", 5),
                                    ("filtered_incoming_entry_point_references", 0),
                                    ("duplicate_incoming_references_in_scan", 1),
                                    ("budget_omitted_incoming_references", 1),
                                    ("incoming_scan_complete", 1)):
            changed = copy.deepcopy(value)
            changed[field] = replacement
            with self.assertRaises(AssertionError):
                harness.assert_revision_four_xrefs(changed)
        changed = copy.deepcopy(value)
        changed["incoming_references"][0]["entry_point_reference"] = True
        with self.assertRaises(AssertionError):
            harness.assert_revision_four_xrefs(changed)

    def test_complete_empty_bundle_is_retained_and_exposes_after_analysis_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            response = bundle_response()
            server = PrivateController(root, response)
            before = harness.capture_native_evidence(server, root, "before")
            after = harness.capture_native_evidence(server, root, "after")
            self.assertEqual(before["status"], "CAPTURED_COMPLETE_BUNDLE")
            self.assertEqual(after["record_count"], 0)
            self.assertEqual(after["unknown_count"], 0)
            saved = json.loads((root / after["artifacts"]["call-tool-result"]["path"]).read_bytes())
            self.assertEqual(saved, response)
            self.assertEqual(saved["content"][0]["text"], response["content"][0]["text"])
            assessment = harness.assess_native_evidence(before, after)
            self.assertEqual(assessment["status"], "DIFF_EMPTY_NATIVE_BUNDLE_AFTER_PROVIDER_ANALYSIS")
            self.assertFalse(assessment["qualified"])

    def test_nonempty_bundle_counts_and_unknowns_do_not_self_qualify(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            server = PrivateController(root, bundle_response([{"private_fixture": 1}], [{"private_future": 2}]))
            before = harness.capture_native_evidence(server, root, "before")
            after = harness.capture_native_evidence(server, root, "after")
            self.assertEqual((after["record_count"], after["unknown_count"]), (1, 1))
            self.assertEqual(harness.assess_native_evidence(before, after)["status"], "OPEN_FULL_EVIDENCE_COMPARISON")
            changed_owner = dict(after, owner={"pid": 8, "start_time": "124"})
            with self.assertRaisesRegex(AssertionError, "different original owners"):
                harness.assess_native_evidence(before, changed_owner)

    def test_tool_error_and_incompatible_content_are_never_empty_bundles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for phase, response, expected in (
                ("tool-error", {"isError": True, "content": [{"type": "text", "text": "opaque failure"}]}, "CAPTURED_TOOL_ERROR"),
                ("malformed", {"content": [{"type": "text", "text": "not JSON"}]}, "CAPTURED_INCOMPATIBLE_RESULT"),
                ("disagree", dict(bundle_response(), structuredContent={}), "CAPTURED_INCOMPATIBLE_RESULT"),
            ):
                value = harness.capture_native_evidence(PrivateController(root, response), root, phase)
                self.assertEqual(value["status"], expected)
                self.assertFalse(value["qualified"])
                self.assertEqual(json.loads((root / value["artifacts"]["call-tool-result"]["path"]).read_bytes()), response)

    def test_idempotent_close_retains_one_complete_original_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            server = PrivateController(Path(directory))
            result = {"qualified": False}
            harness.close_controller(server, result, "restart")
            harness.close_controller(server, result, "final")
            self.assertEqual(len(result["controller_sessions"]), 1)
            session = result["controller_sessions"][0]
            self.assertEqual(session["phases"], ["restart", "final"])
            self.assertIs(session["receipt"], server.close_record)

    def test_final_abnormal_close_downgrades_success_and_raises(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            root = Path(directory)
            result = {"qualified": True}
            with self.assertRaisesRegex(AssertionError, "did not close normally"):
                harness.finalize_qualification(root, result, PrivateController(root, normal=False), None)
            saved = json.loads((root / "qualification.json").read_bytes())
            self.assertFalse(saved["qualified"])
            self.assertFalse(saved["controller_sessions"][0]["normal_close"])
            self.assertIn("final_controller_close_failure", saved)

    def test_primary_analysis_failure_survives_close_and_receipt_faults(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            root = Path(directory)
            primary = ValueError("private primary analysis failure")
            result = {"qualified": False, "failure": repr(primary)}
            with self.assertRaises(ValueError) as captured:
                try:
                    raise primary
                finally:
                    with mock.patch.object(harness, "private_write", side_effect=OSError("private write failure")):
                        harness.finalize_qualification(root, result,
                            PrivateController(root, normal=False, error=RuntimeError("private close failure")), primary)
            self.assertIs(captured.exception, primary)
            self.assertEqual(result["failure"], repr(primary))
            self.assertFalse(result["qualified"])
            self.assertEqual(len(primary.__notes__), 2)

    def test_failed_constructor_close_receipt_is_retained(self):
        class FailedController(PrivateController):
            def __init__(self, runtime, root):
                super().__init__(root, normal=False)
                raise ValueError("private initialization failure")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(harness, "Mcp", FailedController):
            result = {"qualified": False}
            with self.assertRaisesRegex(ValueError, "private initialization failure"):
                harness.open_controller(Path("/private/runtime"), Path(directory), result, "restart")
            self.assertEqual(len(result["controller_sessions"]), 1)
            self.assertEqual(result["controller_sessions"][0]["phases"], ["restart-initialization-failed"])
            self.assertFalse(result["controller_sessions"][0]["normal_close"])

    def test_evidence_transport_error_survives_observation_write_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            server = PrivateController(root)
            original = RuntimeError("private transport failure")
            with mock.patch.object(server, "raw", side_effect=original), \
                    mock.patch.object(harness, "private_write", side_effect=OSError("private write failure")):
                with self.assertRaises(RuntimeError) as captured:
                    harness.capture_native_evidence(server, root, "before")
            self.assertIs(captured.exception, original)
            self.assertEqual(len(original.__notes__), 1)


if __name__ == "__main__":
    unittest.main()
