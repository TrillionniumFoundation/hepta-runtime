import pathlib,hashlib,json,ast,datetime,subprocess,sys
R=pathlib.Path("/home/qian-qi/hepta-runtime-operation-v10-20261013")
D=R/"docs/qualification/dc-functional-v10-operation-candidate-20261013/versioned-regression-package"
D.mkdir(mode=0o700,exist_ok=True)
def sha(b):return hashlib.sha256(b).hexdigest()
def write(p,s):
 b=s.encode() if isinstance(s,str) else s
 if p.exists():
  assert p.read_bytes()==b, "do not overwrite a different version candidate"
 else:
  with p.open("xb") as f:f.write(b)
 p.chmod(0o600)
 return sha(b)
oldloader=R/"tests/dc_successor_contract.py";assert sha(oldloader.read_bytes())=="0b039e2d667314fec32bde7827fd0f9ad01d35b8d3199e73a1e036c7b1eb3dde"
loader="#!/usr/bin/env python3\n# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0\n\"\"\"Reviewed V10 full catalog approval before any historical v4 projection.\n\nThe immutable legacy loader retains historical V5..V9 behavior. V10 approval\nrequires the independently reviewed exact file digest, all 62 V9 definitions,\nand exactly four new operation definitions. Tool counts never approve a catalog.\nProjection is returned only after full 66-tool verification, for old regression.\n\"\"\"\nimport hashlib\nimport importlib.util\nimport pathlib\nimport sys\n\nROOT = pathlib.Path(__file__).resolve().parents[1]\nLEGACY_LOADER_SHA256 = \"0b039e2d667314fec32bde7827fd0f9ad01d35b8d3199e73a1e036c7b1eb3dde\"\nTOOL_HELPER_SHA256 = \"e2b29f987d3aaa863d7bf6879d0d6a835a807c133c5c355b6a4e69bce9c3e216\"\nV10_SHA256 = \"12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553\"\nV10_OPERATION_ADDITIONS = {\"operation_start\", \"operation_status\", \"operation_result\", \"operation_cancel\"}\n\n\ndef digest(path):\n    path = pathlib.Path(path)\n    if not path.is_file() or path.is_symlink():\n        raise ValueError(\"ordinary reviewed input required\")\n    return hashlib.sha256(path.read_bytes()).hexdigest()\n\n\nif digest(ROOT / \"tests/dc_successor_contract.py\") != LEGACY_LOADER_SHA256:\n    raise ValueError(\"immutable legacy approval loader drift\")\nif digest(ROOT / \"deploy/mcp_tool_contract.py\") != TOOL_HELPER_SHA256:\n    raise ValueError(\"reviewed tool helper drift\")\nsys.path.insert(0, str(ROOT / \"deploy\"))\nfrom mcp_tool_contract import ToolContract\n\n_spec = importlib.util.spec_from_file_location(\"_hepta_immutable_approval_v9\", ROOT / \"tests/dc_successor_contract.py\")\n_legacy = importlib.util.module_from_spec(_spec)\n_spec.loader.exec_module(_legacy)\nV4_SHA256 = _legacy.V4_SHA256\nV5_SHA256 = _legacy.V5_SHA256\nV6_SHA256 = _legacy.V6_SHA256\nV7_SHA256 = _legacy.V7_SHA256\nV8_SHA256 = _legacy.V8_SHA256\nV9_SHA256 = _legacy.V9_SHA256\nfrozen = _legacy.frozen\n\n\ndef verify_successor(tools, path):\n    if digest(path) != V10_SHA256:\n        return _legacy.verify_successor(tools, path)\n    reviewed = ToolContract.load(path, V10_SHA256)\n    reviewed.verify(tools)  # Verify the entire actual catalog, never a projection.\n    previous_path = ROOT / \"deploy/contracts/hepta-runtime-full-operator-v9.json\"\n    previous = ToolContract.load(previous_path, V9_SHA256)\n    _legacy.verify_successor(previous.tools, previous_path)\n    assert set(reviewed.by_name) - set(previous.by_name) == V10_OPERATION_ADDITIONS\n    assert set(previous.by_name) <= set(reviewed.by_name)\n    assert all(reviewed.by_name[name] == definition for name, definition in previous.by_name.items())\n    assert len(tools) == len(reviewed.by_name) == 66\n    baseline = frozen(4, V4_SHA256)\n    return [tool for tool in tools if tool[\"name\"] in baseline.by_name]\n"
loader_sha=write(R/"tests/dc_successor_contract_v10.py",loader)
version='''#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""V10 reviewed helper closure; no subprocess, network or controller effects."""
import hashlib
import pathlib

V10_SHA256 = "12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553"
V9_SHA256 = "3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761"
HELPER_PINS = {
    "tests/dc_successor_contract_v10.py": "LOADER_SHA",
    "tests/dc_successor_contract.py": "0b039e2d667314fec32bde7827fd0f9ad01d35b8d3199e73a1e036c7b1eb3dde",
    "deploy/mcp_tool_contract.py": "e2b29f987d3aaa863d7bf6879d0d6a835a807c133c5c355b6a4e69bce9c3e216",
    "tests/runtime_http_acceptance.py": "8b7ee206ccfc7978ac4abdf3eac3ddb8f7e7c36d053f601b5cfcb66f52fb8dba",
}


def verify_import_pins(root):
    for relative, pin in HELPER_PINS.items():
        path = pathlib.Path(root) / relative
        if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != pin:
            raise ValueError("reviewed V10 helper closure differs: " + relative)
    return dict(HELPER_PINS)
'''.replace("LOADER_SHA",loader_sha)
version_sha=write(R/"tests/dc_functional_v10_version_pin.py",version)
bootstrap='''# V10 copies verify all executable helper bytes before importing them.
_V10_ROOT = pathlib.Path(__file__).resolve().parents[1]
_V10_VERSION = _V10_ROOT / "tests/dc_functional_v10_version_pin.py"
if not _V10_VERSION.is_file() or _V10_VERSION.is_symlink() or hashlib.sha256(_V10_VERSION.read_bytes()).hexdigest() != "VERSION_SHA":
    raise ValueError("reviewed V10 version helper differs")
sys.path.insert(0, str(_V10_ROOT / "tests"))
from dc_functional_v10_version_pin import verify_import_pins as _v10_verify_import_pins
_v10_verify_import_pins(_V10_ROOT)
'''.replace("VERSION_SHA",version_sha)
specs=[
("dc_functional_v9_catalog_acceptance.py","dc_functional_v10_catalog_acceptance.py"),
("dc_functional_v9_request_results_acceptance.py","dc_functional_v10_request_results_acceptance.py"),
("dc_functional_v9_request_async_acceptance.py","dc_functional_v10_request_async_acceptance.py"),
("dc_parity_native_acceptance.py","dc_functional_v10_legacy_native_acceptance.py"),
("dc_parity_directory_move_acceptance.py","dc_functional_v10_legacy_directory_move_acceptance.py"),
("dc_parity_workspace_root_guard_acceptance.py","dc_functional_v10_legacy_workspace_root_guard_acceptance.py"),
("dc_parity_concurrent_text_acceptance.py","dc_functional_v10_legacy_concurrent_text_acceptance.py"),
]
manifest={"schema":"hepta-v10-versioned-native-regression-copy-v1","recorded_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"legacy_sources_unchanged":True,"full_catalog_verified_before_any_historical_projection":True,"old_loader_sha256":sha(oldloader.read_bytes()),"new_loader_sha256":loader_sha,"new_version_helper_sha256":version_sha,"contract_sha256":"12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553","source_code_fingerprint":"498cca6da8c442c70534b0a35807c94d7b5f7fbef4b2b4d8f15fa9c22484e33c","copies":[],"copy_whitelist":{},"execution_qualified":False,"full_dc_replacement_qualified":False}
four='{"operation_start", "operation_status", "operation_result", "operation_cancel"}'
for oldname,newname in specs:
 oldp=R/"tests"/oldname;orig=oldp.read_text();s=orig
 s=s.replace("from dc_successor_contract import", "from dc_successor_contract_v10 import")
 s=s.replace('"tests/dc_successor_contract.py"','"tests/dc_successor_contract_v10.py"')
 if oldname.startswith("dc_functional_v9_"):
  s=s.replace('V9_SHA256 = "3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761"','V9_SHA256 = "12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553"')
  s=s.replace('== 62','== 66')
  s=s.replace('"tool_count": 62','"tool_count": 66')
  s=s.replace('== {"request_start", "request_cancel"}','== {"request_start", "request_cancel"} | '+four)
  if oldname.endswith("catalog_acceptance.py"):
   anchor='            reviewed.verify(tools)\n'
   addition='            v9 = ToolContract.load(ROOT / "deploy/contracts/hepta-runtime-full-operator-v9.json", "3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761")\n            assert all(byname[name] == definition for name, definition in v9.by_name.items())\n            assert set(byname) - set(v9.by_name) == '+four+'\n'
   assert s.count(anchor)==1;s=s.replace(anchor,addition+anchor)
  elif oldname.endswith("request_results_acceptance.py"):
   anchor='            assert all(actual[name] == definition for name, definition in v8.by_name.items())\n'
   addition='            v9 = ToolContract.load(ROOT / "deploy/contracts/hepta-runtime-full-operator-v9.json", "3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761")\n            assert all(actual[name] == definition for name, definition in v9.by_name.items())\n            assert set(actual) - set(v9.by_name) == '+four+'\n'
   assert s.count(anchor)==1;s=s.replace(anchor,anchor+addition)
  else:
   anchor='    assert all(actual[name] == definition for name, definition in v8.by_name.items())\n'
   addition='    v9 = ToolContract.load(ROOT / "deploy/contracts/hepta-runtime-full-operator-v9.json", "3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761")\n    assert all(actual[name] == definition for name, definition in v9.by_name.items())\n    assert set(actual) - set(v9.by_name) == '+four+'\n'
   assert s.count(anchor)==1;s=s.replace(anchor,anchor+addition)
  # Version labels only; state directories, legacy wire fields and operation names stay immutable.
  s=s.replace('V9 exact','V10 exact').replace('native V9','native V10').replace('reviewed V9','reviewed V10').replace('pinned V9','pinned V10').replace('exact V9','exact V10').replace('unreviewed V9 contract','unreviewed V10 contract')
  s=s.replace('"only_v9_added_names": ["request_start", "request_cancel"]','"v8_added_names_in_v10": ["request_start", "request_cancel", "operation_start", "operation_status", "operation_result", "operation_cancel"]')
  s=s.replace('native V10 exact catalog preserves all60 V8 definitions and adds only request_start/request_cancel','native V10 exact catalog preserves all62 V9 definitions and adds only four operation definitions')
  s=s.replace('V8 exact predecessor definitions plus two pinned native additions','V10 exact catalog preserves V8 and V9 predecessors plus four operation definitions')
  s=s.replace('"additions": ["request_start", "request_cancel"]','"v8_added_names_in_v10": ["request_start", "request_cancel", "operation_start", "operation_status", "operation_result", "operation_cancel"]')
 if oldname=="dc_parity_workspace_root_guard_acceptance.py" and "import hashlib\n" not in s:
  s=s.replace("import argparse\n","import argparse\nimport hashlib\n")
 # AST-selected first helper import, after all standard library imports and before effects.
 tree=ast.parse(s);lines=s.splitlines(keepends=True)
 choices=[n.lineno-1 for n in tree.body if isinstance(n,ast.ImportFrom) and n.module in {"runtime_http_acceptance","mcp_tool_contract"}]
 first=choices[0] if choices else next(i for i,line in enumerate(lines) if line.startswith("ROOT =") or line.startswith("ROOT="))
 lines.insert(first,bootstrap+"\n");s="".join(lines)
 if oldname=="dc_parity_concurrent_text_acceptance.py":
  anchor='                contract=ToolContract.load(file,hashlib.sha256(file.read_bytes()).hexdigest())\n'
  assert s.count(anchor)==1
  s=s.replace(anchor,'                from dc_successor_contract_v10 import verify_successor\n                verify_successor(catalog, file)  # Full approved V10 catalog; never a count-only gate.\n'+anchor)
 newp=R/"tests"/newname;newsha=write(newp,s)
 assert oldp.read_text()==orig
 def fnmap(source):return {n.name:ast.dump(n,include_attributes=False) for n in ast.parse(source).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
 a,b=fnmap(orig),fnmap(s);same=sorted(k for k in a if k in b and a[k]==b[k]);changed=sorted(k for k in a if k in b and a[k]!=b[k])
 manifest["copies"].append({"original_path":str(oldp.relative_to(R)),"original_sha256":sha(orig.encode()),"new_path":str(newp.relative_to(R)),"new_sha256":newsha,"top_level_function_and_class_AST_identical":same,"AST_changed_nodes":changed,"permitted_change":"V10 approved catalog/helper pins and exact four-addition predecessor check; execution/recovery assertions preserved"})
for name in ["dc_successor_contract_v10.py","dc_functional_v10_version_pin.py",*[n for _,n in specs]]:
 p=R/"tests"/name;manifest["copy_whitelist"][str(p.relative_to(R))]={"sha256":sha(p.read_bytes()),"bytes":p.stat().st_size};compile(p.read_bytes(),str(p),"exec")
op=R/"tests/dc_functional_v10_operation_acceptance.py"
write(op,(R/"tests/dc_functional_v10_operation_async_acceptance.py").read_bytes())
manifest["copy_whitelist"][str(op.relative_to(R))]={"sha256":sha(op.read_bytes()),"bytes":op.stat().st_size,"byte_exact_R4_harness_alias":True}
write(D/"manifest.json",(json.dumps(manifest,indent=2,sort_keys=True)+"\n").encode())
print(json.dumps({"manifest":str(D/"manifest.json"),"sha256":sha((D/"manifest.json").read_bytes()),"loader_sha256":loader_sha,"version_sha256":version_sha,"copies":manifest["copies"],"whitelist":manifest["copy_whitelist"]},sort_keys=True))
