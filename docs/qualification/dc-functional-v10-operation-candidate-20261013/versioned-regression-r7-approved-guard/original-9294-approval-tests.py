#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""V10 approval negatives and preserved native business assertion provenance."""
import ast
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
NEW_LOADER_SHA256 = "4623c4da9493dccfc4bcef18c7267ba96ba7f5f1ddd799441214948c9da161fe"
OLD_LOADER_SHA256 = "0b039e2d667314fec32bde7827fd0f9ad01d35b8d3199e73a1e036c7b1eb3dde"
V10_SHA256 = "12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553"
V9_SHA256 = "3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761"
FOUR = {"operation_start", "operation_status", "operation_result", "operation_cancel"}
OLD_SCRIPTS = {
    "dc_functional_v9_catalog_acceptance.py": "11b63309855d41f6001bdc985537152c89fbb50ac87562999953351323cc37c8",
    "dc_functional_v9_request_results_acceptance.py": "c213903f862e2b952d2d0e46432d1b9f2417c2bfd32d629e09ea59abe111f782",
    "dc_functional_v9_request_async_acceptance.py": "340279bf402b9975e2877a83f4c59a4dd386fbe872ab51bda7a7e045c5ef00fa",
    "dc_parity_native_acceptance.py": "347d695ae672ecefe7489cb083788ea21f0812a051855eff4a0e3ecef2f197b9",
    "dc_parity_directory_move_acceptance.py": "ce1ffddb7db370fbfe2e14a1c9a91be1cbc14cb56e75c67d12b53d72e5cbd280",
    "dc_parity_workspace_root_guard_acceptance.py": "744d804b22af86c3cdef4b5115b1322ebdf7411f9311c319c611e9b55865ff26",
    "dc_parity_concurrent_text_acceptance.py": "4c923ef5f3d38da4684c450a66d8267496f074532146925ec54e9e24c898aa9b",
}
COPIES = {
    "dc_functional_v9_catalog_acceptance.py": "dc_functional_v10_catalog_acceptance.py",
    "dc_functional_v9_request_results_acceptance.py": "dc_functional_v10_request_results_acceptance.py",
    "dc_functional_v9_request_async_acceptance.py": "dc_functional_v10_request_async_acceptance.py",
    "dc_parity_native_acceptance.py": "dc_functional_v10_legacy_native_acceptance.py",
    "dc_parity_directory_move_acceptance.py": "dc_functional_v10_legacy_directory_move_acceptance.py",
    "dc_parity_workspace_root_guard_acceptance.py": "dc_functional_v10_legacy_workspace_root_guard_acceptance.py",
    "dc_parity_concurrent_text_acceptance.py": "dc_functional_v10_legacy_concurrent_text_acceptance.py",
}


def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


assert digest(ROOT / "tests/dc_successor_contract.py") == OLD_LOADER_SHA256
assert digest(ROOT / "tests/dc_successor_contract_v10.py") == NEW_LOADER_SHA256
sys.path.insert(0, str(ROOT / "tests"))
from dc_successor_contract_v10 import ToolContract, verify_successor, frozen
from mcp_tool_contract import make_contract


class Approval(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = ROOT / "deploy/contracts/hepta-runtime-full-operator-v10.json"
        cls.catalog = ToolContract.load(cls.path, V10_SHA256)

    def rejected(self, tools, path=None):
        with self.assertRaises((AssertionError, ValueError)):
            verify_successor(tools, self.path if path is None else path)

    def test_entire_66_approved_before_legacy_projection(self):
        selected = verify_successor(self.catalog.tools, self.path)
        self.assertEqual(len(self.catalog.tools), 66)
        old = frozen(4, "d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1")
        self.assertEqual({tool["name"]: tool for tool in selected}, old.by_name)

    def test_all_62_previous_definitions_exact(self):
        previous = ToolContract.load(ROOT / "deploy/contracts/hepta-runtime-full-operator-v9.json", V9_SHA256)
        self.assertEqual(set(self.catalog.by_name) - set(previous.by_name), FOUR)
        for name, definition in previous.by_name.items():
            with self.subTest(name=name):
                self.assertEqual(self.catalog.by_name[name], definition)

    def test_every_66_live_description_mutation_refused(self):
        for index, tool in enumerate(self.catalog.tools):
            with self.subTest(name=tool["name"]):
                changed = copy.deepcopy(self.catalog.tools)
                changed[index]["description"] += " unexpected live drift"
                self.rejected(changed)

    def test_each_of_four_missing_definitions_refused(self):
        for name in FOUR:
            with self.subTest(name=name):
                self.rejected([tool for tool in self.catalog.tools if tool["name"] != name])

    def test_legacy_projection_cannot_stand_in_for_full_catalog(self):
        old = frozen(4, "d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1")
        self.rejected(old.tools)

    def test_extra_and_duplicate_live_tool_refused(self):
        extra = copy.deepcopy(self.catalog.tools[0]);extra["name"] = "unreviewed_extra"
        self.rejected(self.catalog.tools + [extra])
        self.rejected(self.catalog.tools + [copy.deepcopy(self.catalog.tools[0])])

    def test_recomputed_unknown_self_consistent_catalog_refused(self):
        for kind in ("description", "readonly_hint", "owner_input", "extra_tool"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix="hepta-v10-approval-negative-") as root:
                tools = copy.deepcopy(self.catalog.tools)
                operation = next(tool for tool in tools if tool["name"] == "operation_start")
                if kind == "description":operation["description"] += " unreviewed"
                elif kind == "readonly_hint":operation["annotations"]["readOnlyHint"] = True
                elif kind == "owner_input":operation["inputSchema"]["properties"]["owner"] = {"type":"string"}
                else:
                    extra=copy.deepcopy(tools[0]);extra["name"]="unknown-extra";tools.append(extra)
                path=pathlib.Path(root)/"unknown.json"
                path.write_text(json.dumps(make_contract(tools),indent=2)+"\n");path.chmod(0o600)
                self.rejected(tools,path)

    def test_historical_v5_through_v9_still_approved_by_original_program(self):
        for version, pin in [
            (5,"f3fd365ae69e1189c550c4314c4fdfb12f4c80d8cc86d1bc0aca6bd1bf7c4cba"),
            (6,"de23cec290a0c22d248575c92b656d2a194a8306b85cc92b68aedea4fe0db3c8"),
            (7,"8ad53842e4aa41bbd1567ed99e956088baafea108b6fb0b9a8df979c72c794cc"),
            (8,"b64769210b9913fbdab28f7d0e95b7ef300d8710b3f1eeea74afcfac25b08318"),
            (9,V9_SHA256),
        ]:
            with self.subTest(version=version):
                path=ROOT/f"deploy/contracts/hepta-runtime-full-operator-v{version}.json"
                reviewed=ToolContract.load(path,pin)
                self.assertEqual(len(verify_successor(reviewed.tools,path)),50)

    def test_original_legacy_sources_byte_exact(self):
        self.assertEqual(digest(ROOT/"tests/dc_successor_contract.py"),OLD_LOADER_SHA256)
        for name,pin in OLD_SCRIPTS.items():
            with self.subTest(name=name):
                self.assertEqual(digest(ROOT/"tests"/name),pin)

    def test_preserved_business_assertions_with_only_catalog_adaptation(self):
        class CatalogInverse(ast.NodeTransformer):
            def visit_Constant(self,node):
                if type(node.value) is int and node.value==66:
                    return ast.copy_location(ast.Constant(62),node)
                if node.value=="unreviewed V10 contract file":
                    return ast.copy_location(ast.Constant("unreviewed V9 contract file"),node)
                return node
            def visit_BinOp(self,node):
                node=self.generic_visit(node)
                if isinstance(node.op,ast.BitOr) and isinstance(node.right,ast.Set):
                    values={v.value for v in node.right.elts if isinstance(v,ast.Constant)}
                    if values==FOUR:return node.left
                return node
        def assertions(source,adapted):
            result=[]
            for node in ast.walk(ast.parse(source)):
                if not isinstance(node,ast.Assert):continue
                text=ast.unparse(node.test)
                if adapted and ("v9.by_name" in text):
                    continue  # Explicit newly added full62 comparison; never an old assertion.
                if adapted:node=CatalogInverse().visit(node)
                result.append(ast.dump(node,include_attributes=False))
            return result
        for old,new in COPIES.items():
            with self.subTest(original=old):
                self.assertEqual(assertions((ROOT/"tests"/old).read_text(),False),
                                 assertions((ROOT/"tests"/new).read_text(),True))

    def test_operation_harness_alias_is_byte_exact_r4(self):
        self.assertEqual((ROOT/"tests/dc_functional_v10_operation_acceptance.py").read_bytes(),
                         (ROOT/"tests/dc_functional_v10_operation_async_acceptance.py").read_bytes())


if __name__=="__main__":
    unittest.main()
