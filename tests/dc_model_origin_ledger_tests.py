#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Fail-closed evidence ledger integrity for the frozen 50-tool private catalog.

Only checks committed evidence files and pinned tool definitions. No service
start/stop, model call, shell or external provider access is performed.
"""
import hashlib
import json
import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
DOCS=ROOT/"docs/qualification"
LEDGER=json.loads((DOCS/"dc-parity-v4-model-origin-tool-ledger-20261013.json").read_text())
CONTRACT_PATH=ROOT/"deploy/contracts/hepta-runtime-full-operator-v4.json"
CONTRACT=json.loads(CONTRACT_PATH.read_text())

class LedgerIntegrity(unittest.TestCase):
    def test_exact_frozen_contract_and_counts(self):
        self.assertEqual(CONTRACT["schema"],"hepta-native-tool-contract-v1")
        self.assertEqual(CONTRACT["catalog_sha256"],LEDGER["catalog_sha256"])
        self.assertEqual(
            hashlib.sha256(CONTRACT_PATH.read_bytes()).hexdigest(),
            LEDGER["contract_file_sha256"],
        )
        self.assertEqual(len(CONTRACT["tools"]),50)
        self.assertEqual(LEDGER["live_tool_count"],50)
        self.assertEqual(LEDGER["read_only_count"],19)
        self.assertEqual(LEDGER["non_read_only_count"],31)

    def test_positive_and_unverified_are_complete_disjoint_partition(self):
        positive=LEDGER["model_positive_nonreadonly_tools"]
        unverified=LEDGER["model_unverified_nonreadonly_tools"]
        self.assertEqual(len(positive),22)
        self.assertEqual(len(unverified),9)
        self.assertEqual(positive,sorted(set(positive)))
        self.assertEqual(unverified,sorted(set(unverified)))
        self.assertFalse(set(positive)&set(unverified))
        nonread={
            t["name"] for t in CONTRACT["tools"]
            if not t["annotations"]["readOnlyHint"]
        }
        self.assertEqual(set(positive)|set(unverified),nonread)

    def test_truthful_annotations_are_identical_to_server_contract(self):
        declared={t["name"]:t for t in CONTRACT["tools"]}
        evidence=LEDGER["positive_tool_definitions"]
        self.assertEqual(len(evidence),31)
        for item in evidence:
            tool=declared[item["tool"]]
            self.assertEqual(tool["annotations"],item["annotations"])
            self.assertFalse(item["annotations"]["readOnlyHint"])
            self.assertEqual(
                item["status"],
                ("positive_bounded_model_origin"
                 if item["tool"] in LEDGER["model_positive_nonreadonly_tools"]
                 else "not_verified_from_chatgpt"),
            )
            if item["status"]=="positive_bounded_model_origin":
                self.assertIn(item["evidence"],LEDGER["evidence_receipt_sha256"])
            else:
                self.assertIsNone(item["evidence"])

    def test_evidence_files_are_exact_and_deduplicated(self):
        references=LEDGER["evidence_receipt_sha256"]
        self.assertGreaterEqual(len(references),6)
        for filename,expected_digest in references.items():
            self.assertNotIn("/",filename)
            path=DOCS/filename
            self.assertTrue(path.is_file(),filename)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),expected_digest)
            self.assertLess(path.stat().st_size,256*1024)
        self.assertIn("dc-parity-v4-model-origin-expanded-writes-20261013.json",references)
        self.assertIn("dc-parity-v4-chatgpt-six-host-pty-and-safe-shell-20261013.json",references)

    def test_no_unsafe_generalization_or_public_release(self):
        self.assertEqual(LEDGER["desktop_commander"]["bounded_model_origin_parity_categories_with_hepta"],9)
        self.assertEqual(LEDGER["desktop_commander"]["direct_core_modify_execute_categories"],10)
        self.assertEqual(LEDGER["public_gateway"].split()[0],"HOLD")
        nonverified=set(LEDGER["model_unverified_nonreadonly_tools"])
        self.assertTrue({"sudo_start","process_checkpoint","privileged_action",
                         "stream_handoff_write","binary_patch_inode"}<=nonverified)
        qualifying=LEDGER["qualification_semantics"]
        self.assertIn("not",qualifying["unverified"].lower())
        self.assertIn("not",qualifying["workdir"].lower())
        self.assertIn("not",qualifying["pty_close"].lower())

    def test_expanded_receipt_values_were_read_only_verified(self):
        x=json.loads((DOCS/"dc-parity-v4-model-origin-expanded-writes-20261013.json").read_text())
        self.assertEqual(len(x["new_positive_nonreadonly_tools"]),8)
        self.assertEqual(len(x["files"]),7)
        self.assertEqual(x["xlsx_independent_validation"]["B4_cached_value"],40)
        self.assertIs(x["xlsx_independent_validation"]["macro_or_external_link_parts_present"],False)
        self.assertEqual(x["xlsx_independent_validation"]["formula_errors"],0)
        self.assertEqual(x["pdf_independent_validation"]["pdfinfo_pages"],[1,2])
        self.assertTrue(x["pdf_independent_validation"]["source_sha256_unchanged_after_edit"])
        self.assertTrue(x["pdf_independent_validation"]["visual_preview_reviewed"])

if __name__=="__main__":
    unittest.main(verbosity=2)
