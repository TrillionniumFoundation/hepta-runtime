#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Adversarial verification of the bounded DC→Hepta parity ledger.

Only read committed receipts; no real hosts, subprocesses or writable MCP calls.
"""
import copy
import importlib.util
import json
import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("dc_replacement_gate", ROOT/"deploy/dc_replacement_gate.py")
G=importlib.util.module_from_spec(SPEC)
import sys
sys.path.insert(0,str(ROOT/"deploy"))
SPEC.loader.exec_module(G)

class Gate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=json.loads(G.LEDGER.read_text())
        cls.catalog=json.loads(G.CONTRACT.read_text())

    def result(self, ledger=None, contract=None):
        return G.evaluate(
            copy.deepcopy(self.source if ledger is None else ledger),
            copy.deepcopy(self.catalog if contract is None else contract),
            evidence_root=ROOT,
        )

    def test_exact_31_dc_and_50_hepta_are_accounted_for(self):
        result=self.result()
        self.assertEqual(result["original_dc_tool_count"],31)
        self.assertEqual(result["installed_hepta_tool_count"],50)
        self.assertEqual(result["categories"],{
            "bounded":14,"partial":9,"unimplemented":3,"vendor_specific":5,
        })
        self.assertEqual(result["integrity_problems"],[])
        self.assertFalse(result["full_dc_replacement_qualified"])
        self.assertEqual(len(result["functional_parity_unresolved"]),12)

    def test_duplicate_and_missing_dc_tools_are_detected(self):
        data=copy.deepcopy(self.source)
        data["entries"][1]["dc_tool"]=data["entries"][0]["dc_tool"]
        self.assertTrue(any("31 Desktop Commander tools" in p for p in self.result(data)["integrity_problems"]))
        data=copy.deepcopy(self.source)
        data["entries"].pop()
        self.assertTrue(self.result(data)["integrity_problems"])

    def test_unpinned_or_modified_catalog_is_rejected(self):
        data=copy.deepcopy(self.catalog)
        data["tools"][0]["description"]="do anything without review"
        errors=self.result(contract=data)["integrity_problems"]
        self.assertTrue(any("contract" in p.lower() for p in errors),errors)
        data=copy.deepcopy(self.source)
        data["pinned_hepta_catalog_sha256"]="0"*64
        self.assertTrue(self.result(data)["integrity_problems"])

    def test_unsupported_equivalent_is_not_parity(self):
        data=copy.deepcopy(self.source)
        data["entries"][0]["hepta_tools"]=["unreviewed_shell_alias"]
        self.assertTrue(any("not in the pinned contract" in p for p in self.result(data)["integrity_problems"]))
        data=copy.deepcopy(self.source)
        data["entries"][0]["hepta_tools"]=[]
        self.assertTrue(any("requires one actual" in p for p in self.result(data)["integrity_problems"]))

    def test_receipt_hash_and_path_are_frozen(self):
        data=copy.deepcopy(self.source)
        data["entries"][0]["evidence"]["sha256"]="0"*64
        self.assertTrue(any("changed" in p for p in self.result(data)["integrity_problems"]))
        data=copy.deepcopy(self.source)
        data["entries"][0]["evidence"]["path"]="../../private-secret"
        self.assertTrue(self.result(data)["integrity_problems"])
        data=copy.deepcopy(self.source)
        data["source_receipts"].clear()
        self.assertTrue(any("not pinned" in p for p in self.result(data)["integrity_problems"]))

    def test_no_scope_inference_from_unreviewed_cutover_flags(self):
        data=copy.deepcopy(self.source)
        data["cutover_gates"]["independent_dc_off_smoke"]=True
        self.assertTrue(any("requires a frozen evidence" in p for p in self.result(data)["integrity_problems"]))
        data=copy.deepcopy(self.source)
        data["full_replacement_claimed"]=True
        self.assertTrue(any("falsely asserts" in p for p in self.result(data)["integrity_problems"]))

    def test_cannot_hide_unfinished_search_or_dc_specific_config(self):
        result=self.result()
        self.assertIn("start_search",result["functional_parity_unresolved"])
        self.assertIn("list_searches",result["functional_parity_unresolved"])
        rows={x["dc_tool"]:x for x in self.source["entries"]}
        self.assertEqual(rows["set_config_value"]["status"],"vendor_specific")
        self.assertIn("administrator",rows["set_config_value"]["next_gate"])
        self.assertNotIn("shell_start",rows["set_config_value"]["hepta_tools"])

if __name__=="__main__":
    unittest.main(verbosity=2)
