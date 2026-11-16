"""Author a new-version projection from the existing native authority state.

This source author is not a runtime implementation. It preserves all existing
authority functions, changing only the operation bound and adding a post-bind
dispatch edge to the small serializer. The previous lost candidate is not an
input and is not treated as qualified evidence.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys

BASE_SHA = "4bf4a50d560db251b5d6e1eaad59c53b67796c1da2c749e4a9d3985587f22af6"
TARGET = "d3d75c30719db966b004756f610007a7c723729e"
SERIALIZER = '''
def export_owner(w:mutbuf, o:mutbuf) -> u64:
    put(w, 2097152, 3544386036950848072)
    put(w, 2097160, get(w, 88))
    i = 0
    while i < 32:
        value = byte(w, 352 + i)
        store(w, 2097168 + i * 2, nibble(value >> 4))
        store(w, 2097169 + i * 2, nibble(value & 15))
        i = i + 1
    return reply(w, o, 0, 80)
'''


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def author(hepta, root, *, check=False):
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import _parse_assembly_document, render_assembly
    from hepta.hia_program import verify_program
    from tools.generate_hia_selfhost import Builder

    original_path = root / "tests/hia_native/caller_owner_export/reference/caller_authority.hepta"
    original = original_path.read_bytes()
    assert digest(original) == BASE_SHA
    before = _parse_assembly_document(original)
    assert len(before["functions"]) == 32
    result = copy.deepcopy(before)
    dispatch = result["functions"][7]
    assert dispatch["name"] == "f7"
    blocks = {row["id"]: row for row in dispatch["blocks"]}
    bound = blocks["b2"]["ops"][2]
    assert bound == {"op": "const", "args": [], "out": [{"name": "v21", "type": "u64"}], "attrs": {"value": 2}}
    bound["attrs"]["value"] = 3
    old_term = copy.deepcopy(blocks["b12"]["term"])
    assert old_term == {"op": "branch", "cond": "v80", "then": {"target": "b13", "args": ["v73", "v74"]}, "else": {"target": "b14", "args": ["v73", "v74"]}}
    blocks["b12"]["ops"].extend([
        {"op": "const", "args": [], "out": [{"name": "v147", "type": "u64"}], "attrs": {"value": 3}},
        {"op": "compare.eq", "args": ["v75", "v147"], "out": [{"name": "v148", "type": "bool"}], "attrs": {}},
    ])
    blocks["b12"]["term"] = {"op": "branch", "cond": "v148", "then": {"target": "b19", "args": ["v73", "v74"]}, "else": {"target": "b20", "args": ["v73", "v74", "v80"]}}
    dispatch["blocks"].extend([
        {"id": "b19", "params": [{"name": "v149", "type": "mutbuf"}, {"name": "v150", "type": "mutbuf"}],
         "ops": [{"op": "call", "args": ["v149", "v150"], "out": [{"name": "v151", "type": "u64"}], "attrs": {"function": "f32"}}],
         "term": {"op": "ret", "values": ["v151"]}},
        {"id": "b20", "params": [{"name": "v152", "type": "mutbuf"}, {"name": "v153", "type": "mutbuf"}, {"name": "v154", "type": "bool"}], "ops": [],
         "term": {"op": "branch", "cond": "v154", "then": {"target": "b13", "args": ["v152", "v153"]}, "else": {"target": "b14", "args": ["v152", "v153"]}}},
    ])

    node = ast.parse(SERIALIZER).body[0]
    names = {"get": "f22", "put": "f23", "nibble": "f27", "reply": "f14", "export_owner": "f32"}
    signatures = {"get": (["mutbuf", "u64"], "u64"), "put": (["mutbuf", "u64", "u64"], "u64"),
                  "nibble": (["u64"], "u64"), "reply": (["mutbuf", "mutbuf", "u64", "u64"], "u64"),
                  "export_owner": (["mutbuf", "mutbuf"], "u64")}
    builder = Builder(node, names, signatures)
    builder.statements(node.body)
    result["functions"].append({"name": "f32", "params": [builder.param(v) for v in builder.params],
        "returns": ["u64"], "effects": ["read", "write", "trap"], "entry": "b0", "blocks": builder.blocks})
    verify_program(result)
    # The inverse proof covers every original dispatcher node, not just a count.
    inverse = copy.deepcopy(dispatch)
    old_blocks = {row["id"]: row for row in inverse["blocks"]}
    old_blocks["b2"]["ops"][2]["attrs"]["value"] = 2
    old_blocks["b12"]["ops"] = old_blocks["b12"]["ops"][:-2]
    old_blocks["b12"]["term"] = old_term
    inverse["blocks"] = inverse["blocks"][:-2]
    assert inverse == before["functions"][7]
    retained = [index for index in range(32) if index != 7]
    assert all(result["functions"][index] == before["functions"][index] for index in retained)
    assert int.from_bytes(b"HROWR001", "little") == 3544386036950848072
    raw = render_assembly(result).encode()
    assert _parse_assembly_document(raw) == result
    proof = {"schema": "hepta.runtime.caller-owner-export.author.v2", "status": "SOURCE_ONLY_PASS",
        "new_version": True, "target_commit": TARGET, "baseline_source_sha256": BASE_SHA,
        "source_sha256": digest(raw), "source_bytes": len(raw), "functions": len(result["functions"]),
        "blocks": sum(len(row["blocks"]) for row in result["functions"]),
        "retained_original_functions": retained, "dispatcher_inverse_exact": True,
        "binding_f8_exact": True, "lost_candidate_reused": False,
        "source_author_sha256": digest(Path(__file__).read_bytes()),
        "serializer_source_sha256": digest(SERIALIZER.encode()),
        "old_function_ast_sha256": {row["name"]: digest(encoded(row)) for row in before["functions"]},
        "original_rust_executed": False, "native_executed": False,
        "public_route_qualified": False, "whole_runtime_replaced": False}
    targets = {root / "native/caller_authority.hepta": raw,
               root / "native/caller_owner_export_source_proof.json": encoded(proof)}
    for path, value in targets.items():
        if check:
            assert path.read_bytes() == value, str(path)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--hepta", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    print(json.dumps(author(args.hepta, args.source_root, check=args.check), sort_keys=True))
