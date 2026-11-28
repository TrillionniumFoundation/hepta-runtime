#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Add one installed-name SSH target read; retain the complete prior owner."""
from pathlib import Path
import argparse
import copy
import hashlib
import importlib.util
import json
import sys

ROOT = Path(__file__).resolve().parents[2]
BASELINE = "cb22aa72a33b4a429356fdb7d70dd33828492676de1a89c11837d9d8f68a55b5"
SCHEMA = "08d824139f405928b7f30f264158d4756d67daf7d8997aa97bff6e5b0601a6dc"

def require(ok, message):
    if not ok:
        raise ValueError(message)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    args = parser.parse_args()
    support_path = ROOT / "authoring/public_publication_v1/source_support.py"
    spec = importlib.util.spec_from_file_location("public_read_source_support", support_path)
    support = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(support)
    api = support.tools(args.hepta)
    _, _, _, assemble, render = api
    predecessor = ROOT / "qualification/binary_root/v1/source/native"
    raw = (predecessor / "config_directory_owner_span.hepta").read_bytes()
    require(support.SHA(raw) == BASELINE, "exact installed root-owner source differs")
    schema_raw = (ROOT / "scripts/config_schema.py").read_bytes()
    require(support.SHA(schema_raw) == SCHEMA, "installed typed schema differs")
    schema_spec = importlib.util.spec_from_file_location("public_read_config_schema", ROOT / "scripts/config_schema.py")
    schema = importlib.util.module_from_spec(schema_spec)
    schema_spec.loader.exec_module(schema)
    require(schema.SCHEMAS[101][2][3] == ("ssh_target", 1, None, False),
            "original SSH target field layout differs")
    comp = json.loads((predecessor / "config_binary_root_span_composition.json").read_bytes())
    before = assemble(raw).as_dict()
    old = {f["name"]: f for f in before["functions"]}
    require(len(old) == 60 and comp["source_sha256"] == BASELINE,
            "complete original installed query index differs")
    seed = copy.deepcopy(before)
    entry = seed["functions"][0]
    found = 0
    old_anchor = {"args": ["v642", "v643"], "attrs": {}, "op": "bool.or",
                  "out": [{"name": "v370", "type": "bool"}]}
    for block in entry["blocks"]:
        for index, operation in enumerate(block["ops"]):
            if operation == old_anchor:
                require(block["id"] == "b39", "installed query admission block moved")
                retained = copy.deepcopy(operation)
                retained["out"][0]["name"] = "v646"
                block["ops"][index:index+1] = [
                    {"args": [], "attrs": {"value": 10}, "op": "const",
                     "out": [{"name": "v644", "type": "u64"}]},
                    {"args": ["v369", "v644"], "attrs": {}, "op": "compare.ge",
                     "out": [{"name": "v645", "type": "bool"}]},
                    {"args": [], "attrs": {"value": 12}, "op": "const",
                     "out": [{"name": "v647", "type": "u64"}]},
                    {"args": ["v369", "v647"], "attrs": {}, "op": "compare.le",
                     "out": [{"name": "v648", "type": "bool"}]},
                    {"args": ["v645", "v648"], "attrs": {}, "op": "bool.and",
                     "out": [{"name": "v649", "type": "bool"}]},
                    retained,
                    {"args": ["v646", "v649"], "attrs": {}, "op": "bool.or",
                     "out": [{"name": "v370", "type": "bool"}]},
                ]
                found += 1
                break
    require(found == 1, "unique original query admission anchor missing")
    retained_query = copy.deepcopy(old["f8"])
    retained_query["name"] = "f60"
    seed["functions"].append(retained_query)
    aliases = dict(comp["aliases"])
    aliases["retained_target_query"] = "f60"
    constants = {"REQUEST": support.WORD("HRCFGQ01"), "INVALID": 0xffffffff,
                 "CAPACITY": 0xfffffffe, "LIMIT": 0xffff0000,
                 "RESPONSE": support.WORD("HRCFGM01"), "MODE_REPLY": support.WORD("HRCFMOD1")}
    pseudo_path = ROOT / "authoring/public_read/config_target.pseudo"
    result, names, generated = support.compile_delta(api, render(seed).encode(), aliases,
        pseudo_path.read_text(), constants, before["module"])
    after = {f["name"]: f for f in assemble(result).as_dict()["functions"]}
    retained = {}
    for name, function in old.items():
        if name not in ("f0", "f8"):
            require(after[name] == function, "original owner function changed: " + name)
            retained[name] = support.SHA(support.CANON(function))
    restored = copy.deepcopy(after["f60"])
    restored["name"] = "f8"
    require(restored == old["f8"], "complete original query relocation differs")
    inverse = copy.deepcopy(after["f0"])
    anchor_block = next(b for b in inverse["blocks"] if b["id"] == "b39")
    start = next(i for i, op in enumerate(anchor_block["ops"])
                 if op["out"] == [{"name": "v644", "type": "u64"}])
    require(anchor_block["ops"][start:start+7] == next(b for b in entry["blocks"] if b["id"] == "b39")["ops"][
        next(i for i, op in enumerate(next(b for b in entry["blocks"] if b["id"] == "b39")["ops"])
             if op["out"] == [{"name": "v644", "type": "u64"}]):][:7],
        "added admission operations changed")
    anchor_block["ops"][start:start+7] = [old_anchor]
    require(inverse == old["f0"], "complete original entry inverse differs")
    proof = {
        "schema": "hepta.runtime.installed-read-target-source.v1",
        "baseline_commit": "8ac803a79135f4cd2d5efc93c77905d63f4bc2ea",
        "baseline": support.identity(raw),
        "source": support.identity(result), "function_names": names,
        "source_schema": {"path": "scripts/config_schema.py", "sha256": SCHEMA},
        "new_operations": [10, 11, 12], "configured_name_only": True,
        "ssh_alias_fallback": False, "exports_raw_installed_ssh_target": True, "exports_installed_execution_mode": True,
        "multi_read_root_uses_original_permission_and_longest_prefix": True,
        "lookup_operations_grant_no_root_or_remote_policy": True, "public_stdin_selector": False,
        "retained_exact_functions": retained,
        "retained_query": {"f8": "f60"},
        "complete_original_entry_inverse_exact": True,
        "complete_original_query_inverse_exact": True,
        "request_magic": "HRCFGQ01", "result_magic": "HRCFGM01",
        "name_offset": 64, "host_target_field_index": 3,
        "host_target_offset_field": 224, "host_target_length_field": 232,
        "native_executed": False, "public_route_qualified": False,
        "author_sources": {
            str(p.relative_to(ROOT)): support.identity(p.read_bytes())
            for p in [Path(__file__), pseudo_path, support_path]
        },
        "generated": generated,
    }
    (ROOT / "native/config_directory_owner_span.hepta").write_bytes(result)
    (ROOT / "native/config_read_target_composition.json").write_bytes(support.ENCODE(proof))
    print(json.dumps({"source": proof["source"], "functions": len(after),
                      "new_operations": [10, 11, 12]}, sort_keys=True))

if __name__ == "__main__":
    main()
