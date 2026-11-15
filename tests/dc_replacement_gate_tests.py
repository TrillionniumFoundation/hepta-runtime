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

class SemanticEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger=json.loads(G.LEDGER.read_text())
        cls.contract=json.loads(G.CONTRACT.read_text())
        cls.old_ref=cls.ledger["source_receipts"]["dc-parity-v4-chatgpt-model-origin-accepted-20261013.json"]
        cls.old_receipt=json.loads((ROOT/cls.old_ref["path"]).read_text())

    def promoted(self):
        value=copy.deepcopy(self.ledger)
        for row in value["entries"]:
            if row["status"] in ("partial","unimplemented"):
                row.update(status="bounded",hepta_tools=["view"],evidence=self.old_ref)
        return value

    def test_old_bounded_receipt_cannot_authorize_any_cutover_gate(self):
        for name in G.CUTOVER_CHECKS:
            with self.subTest(gate=name):
                value=copy.deepcopy(self.ledger)
                value["cutover_gates"][name]=True
                value["cutover_evidence"]={name:self.old_ref}
                result=G.evaluate(value,self.contract,evidence_root=ROOT)
                self.assertFalse(result["full_dc_replacement_qualified"])
                self.assertTrue(any("exact cutover gate" in error for error in result["integrity_problems"]))
                self.assertFalse(G.cutover_receipt_valid(name,self.old_receipt))

    def test_reclassifying_every_gap_with_view_and_old_receipts_never_qualifies(self):
        value=self.promoted()
        value["cutover_gates"]={name:True for name in G.CUTOVER_CHECKS}
        value["cutover_evidence"]={name:self.old_ref for name in G.CUTOVER_CHECKS}
        value["full_replacement_claimed"]=True
        result=G.evaluate(value,self.contract,evidence_root=ROOT)
        self.assertFalse(result["full_dc_replacement_qualified"])
        self.assertEqual(len(result["required_workflow_qualification_pending"]),26)
        self.assertTrue(any("falsely asserts" in error for error in result["integrity_problems"]))

    def test_unrelated_hash_valid_receipt_is_not_a_functional_qualification(self):
        value=self.promoted()
        for row in value["entries"]:
            if row["status"]=="bounded":row["functional_qualification"]=self.old_ref
        result=G.evaluate(value,self.contract,evidence_root=ROOT)
        self.assertFalse(result["full_dc_replacement_qualified"])
        self.assertTrue(any("functional qualification" in error for error in result["integrity_problems"]))

    def test_typed_drill_requires_exact_gate_approval_and_every_actual_check(self):
        for name,checks in G.CUTOVER_CHECKS.items():
            receipt={"schema":"hepta-dc-cutover-gate-evidence-v1","gate":name,"scope":G.CUTOVER_SCOPE,
                     "complete":True,"authorization":{"approved":True,"scope":name,"record_reference":"explicit-test-fixture-authorization"},
                     "checks":{key:True for key in checks}}
            self.assertTrue(G.cutover_receipt_valid(name,receipt))
            for field,replacement in (("gate","other-gate"),("scope","bounded-tool-call"),("complete",False)):
                wrong=copy.deepcopy(receipt);wrong[field]=replacement
                self.assertFalse(G.cutover_receipt_valid(name,wrong))
            wrong=copy.deepcopy(receipt);wrong["authorization"]["approved"]=False
            self.assertFalse(G.cutover_receipt_valid(name,wrong))
            wrong=copy.deepcopy(receipt);wrong["checks"][next(iter(checks))]=False
            self.assertFalse(G.cutover_receipt_valid(name,wrong))

    def test_workflow_receipt_binds_tool_workflow_native_model_hosts_and_acceptance(self):
        row=next(row for row in self.ledger["entries"] if row["dc_tool"]=="read_file")
        receipt={"schema":"hepta-dc-functional-qualification-v1","dc_tool":row["dc_tool"],
                 "hepta_tools":row["hepta_tools"],"scope":G.FUNCTIONAL_SCOPE,"complete":True,
                 "universal_parity_claimed":False,"business_workflow_accepted":True,
                 "required_workflows":["read the required real business document"],
                 "native_hosts":sorted(G.SIX_HOSTS),"model_origin_hosts":sorted(G.SIX_HOSTS)}
        self.assertTrue(G.functional_receipt_valid(row,receipt))
        for field,replacement in (("dc_tool","start_search"),("hepta_tools",["view"]),
                                  ("required_workflows",[]),("business_workflow_accepted",False),
                                  ("native_hosts",["main"]),("model_origin_hosts",["main"]),
                                  ("universal_parity_claimed",True)):
            wrong=copy.deepcopy(receipt);wrong[field]=replacement
            self.assertFalse(G.functional_receipt_valid(row,wrong),field)

if __name__=="__main__":
    unittest.main(verbosity=2)
