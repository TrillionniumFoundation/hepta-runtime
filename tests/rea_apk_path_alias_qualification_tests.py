#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Negative checks for the path-sensitive retained Evidence gate producer."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rea_apk_path_alias_qualification as runner


def record(path, parent=None):
    value = {field: None for field in ("provider", "analysis_profile", "predicate_type", "raw_result",
                                      "confidence", "authority", "environment", "relationship_coverage")}
    value.update({"operation": "inspect_analysis_view" if parent else "inspect_apk_signature",
                  "subject": {"digest": "same-sha256", "format": "apk", "architecture": None, "local_path": path},
                  "parameters": {"parent_evidence_id": parent, "view": {"kind": "summary"}} if parent else {"path": path},
                  "normalized_result": {"parent_evidence_id": parent} if parent else {"artifact": {"path": path}},
                  "limitations": [], "locations": [], "evidence_links": [parent] if parent else []})
    value["evidence_id"] = runner.q.semantic_evidence_id(value)
    return value


def payload(value):
    return {"content": [{"type": "text", "text": value}], "structuredContent": value,
            "_meta": runner.q.TARGET_META}


def fixture(selected="/owned/./A.apk"):
    first, later = record("/owned/A.apk"), record(selected)
    child = record(selected, later["evidence_id"])
    bundle = {key: [] for key in runner.a.BUNDLE_KEYS}
    bundle["records"] = sorted([first, later, child], key=lambda value: value["evidence_id"])
    return {"complete-A": payload(first), "summary-selected": payload(child),
            "complete-selected": payload(later), "retained": payload({"result": bundle})}


class RetentionGateBoundaries(unittest.TestCase):
    def test_distinct_path_and_dot_alias_are_preserved(self):
        for path in ("/owned/B.apk", "/owned/./A.apk"):
            runner.validate_retention(fixture(path), "/owned/A.apk", path)

    def test_response_path_normalization_cannot_pass(self):
        values = fixture()
        values["complete-selected"]["structuredContent"]["subject"]["local_path"] = "/owned/A.apk"
        with self.assertRaisesRegex(ValueError, "normalized"):
            runner.validate_retention(values, "/owned/A.apk", "/owned/./A.apk")

    def test_validly_rehashed_child_cannot_reference_first_parent(self):
        values = fixture()
        wrong = record("/owned/./A.apk", values["complete-A"]["structuredContent"]["evidence_id"])
        values["summary-selected"] = payload(wrong)
        with self.assertRaisesRegex(ValueError, "parent"):
            runner.validate_retention(values, "/owned/A.apk", "/owned/./A.apk")

    def test_missing_or_changed_complete_record_cannot_pass(self):
        for mutation in ("missing", "changed"):
            values = copy.deepcopy(fixture())
            values["retained"] = copy.deepcopy(values["retained"])
            records = values["retained"]["structuredContent"]["result"]["records"]
            if mutation == "missing":
                records.pop()
            else:
                records[0]["raw_result"] = "changed retained record"
            with self.assertRaisesRegex(ValueError, "three observed records"):
                runner.validate_retention(values, "/owned/A.apk", "/owned/./A.apk")


if __name__ == "__main__":
    unittest.main()
