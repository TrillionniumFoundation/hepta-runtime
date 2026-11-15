#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Negative checks for the independent actual analysis-view MCP producer."""
import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rea_analysis_view_qualification as runner


def record(path):
    value = {field: None for field in ("provider", "analysis_profile", "predicate_type", "raw_result",
                                      "confidence", "authority", "environment", "relationship_coverage")}
    value.update({"operation": "inspect_apk_signature",
                  "subject": {"digest": "same-sha256", "format": "apk", "architecture": None, "local_path": path},
                  "parameters": {"path": path}, "normalized_result": {"artifact": {"path": path}},
                  "limitations": [], "locations": [], "evidence_links": []})
    value["evidence_id"] = runner.q.semantic_evidence_id(value)
    return value


def templates():
    parent = record("/old/rotation-v31.apk")
    result = []
    for index in range(48):
        arguments = {"source": {"zzz": 1, "kind": "retained-evidence", "evidence_id": parent["evidence_id"], "aaa": 2},
                     "view": {"kind": "apk-signature", "collection": "lineage", "offset": 1.0, "limit": 1.0}}
        result.append({"name": "case-" + str(index), "arguments": arguments,
                       "raw_arguments": runner.a.encoded(arguments).replace('"offset":1.0', '"offset":1e0')})
    for name, source in (("inline-valid-parent", {"kind": "inline", "evidence": parent}),
                         ("file", {"kind": "evidence-file", "path": "/old/bundle.json"})):
        arguments = {"source": source, "view": {"kind": "summary"}}
        result.append({"name": name, "arguments": arguments, "raw_arguments": runner.a.encoded(arguments)})
    return result


def value(body):
    return {"content": [{"type": "text", "text": copy.deepcopy(body)}],
            "structuredContent": body, "_meta": runner.q.TARGET_META}


def origins():
    parent = record("/new/rotation-v31.apk")
    first = copy.deepcopy(parent)
    first["operation"] = "inspect_analysis_view"
    first["parameters"] = {"parent_evidence_id": parent["evidence_id"], "view": {
        "kind": "apk-signature", "offset": 0, "limit": 32, "collection": "signers"}}
    first["normalized_result"] = {"parent_evidence_id": parent["evidence_id"]}
    first["evidence_links"] = [parent["evidence_id"]]
    first["evidence_id"] = runner.q.semantic_evidence_id(first)
    second = copy.deepcopy(first)
    second["parameters"]["view"] = {"offset": 0, "limit": 32, "collection": "signers", "kind": "apk-signature"}
    bundle = {key: [] for key in runner.a.BUNDLE_KEYS}
    bundle["records"] = sorted([parent, first], key=lambda item: item["evidence_id"])
    values = [value(parent), value(first), value(second), value({"result": bundle})]
    return SimpleNamespace(rows=[{"value": v, "view_order": runner.view_order(v)} for v in values])


class AnalysisViewProducerBoundaries(unittest.TestCase):
    def test_materialization_changes_only_input_binding_and_keeps_raw_tokens(self):
        parent = record('/new/quote"雪/rotation-v31.apk')
        cases = runner.materialize_cases(templates(), parent, Path('/new/quote"雪'))
        self.assertEqual(len(cases), 50)
        self.assertIn('"offset":1e0,"limit":1.0', cases[0]["raw_arguments"])
        self.assertEqual(list(cases[0]["arguments"]["source"]), ["zzz", "kind", "evidence_id", "aaa"])
        self.assertEqual(cases[-2]["arguments"]["source"]["evidence"], parent)
        self.assertEqual(cases[-1]["arguments"]["source"]["path"], '/new/quote"雪/bundle.json')

    def test_materialization_refuses_changed_reference_record_or_case_set(self):
        parent = record("/new/rotation-v31.apk")
        changed = copy.deepcopy(parent)
        changed["raw_result"] = "unexpected producer change"
        changed["evidence_id"] = runner.q.semantic_evidence_id(changed)
        with self.assertRaisesRegex(ValueError, "beyond paths"):
            runner.materialize_cases(templates(), changed, Path("/new"))
        with self.assertRaisesRegex(ValueError, "incomplete"):
            runner.materialize_cases(templates()[:-1], parent, Path("/new"))

    def test_same_semantic_value_still_exposes_both_key_orders(self):
        session = origins()
        self.assertEqual(runner.a.differences(session.rows[1]["value"], session.rows[2]["value"]), [])
        self.assertNotEqual(session.rows[1]["view_order"], session.rows[2]["view_order"])
        runner.verify_origin(session, ("direct-apk", "analysis-view"))

    def test_replacing_first_retained_order_cannot_pass(self):
        session = origins()
        session.rows[3]["view_order"] = copy.deepcopy(session.rows[2]["view_order"])
        with self.assertRaisesRegex(ValueError, "first origin"):
            runner.verify_origin(session, ("direct-apk", "analysis-view"))


if __name__ == "__main__":
    unittest.main()
