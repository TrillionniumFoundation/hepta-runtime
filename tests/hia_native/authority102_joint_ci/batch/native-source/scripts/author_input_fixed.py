"""Unroll six proven fixed-eight-byte accessors inside Batch Planner input.

Every read/write stays a checked byte access in the same address order. The
parser, validation, typed operations, response, growth and error ASTs remain
byte-identical; no bounds, frame or admitted input limit changes.
"""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import json
import sys

sys.dont_write_bytecode = True
BASE_SHA = "6a054cdbfe2d481900cc725b97cba73181afb4331192a0de81af4f8b2aff1492"
ACCESSORS = {"f16": "readbuf", "f17": "mutbuf", "f18": "store",
             "f24": "mutbuf", "f25": "store", "f30": "store"}

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

def generate(hepta, baseline, output):
    raw = baseline.read_bytes()
    assert sha(raw) == BASE_SHA
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    from tools.generate_hia_selfhost import Builder, total_scalar_functions
    old = assemble_program(raw).as_dict()
    assert len(old["functions"]) == 32
    dsl = ""
    for name, kind in ACCESSORS.items():
        if kind == "store":
            dsl += f"def {name}(w:mutbuf,at:u64,value:u64) -> u64:\n"
            for i in range(8):
                dsl += f"    store(w,at+{i},value>>{8*i})\n"
            dsl += "    return value\n\n"
        else:
            dsl += f"def {name}(s:{kind},at:u64) -> u64:\n    value=0\n"
            for i in range(8):
                dsl += f"    value=value|(byte(s,at+{i})<<{8*i})\n"
            dsl += "    return value\n\n"
    nodes = ast.parse(dsl).body
    names = {node.name: node.name for node in nodes}
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    replacements = {}
    for node in nodes:
        b = Builder(node, names, signatures, total_scalar_functions(nodes))
        b.statements(node.body)
        replacements[node.name] = {"name": node.name, "params": [b.param(p) for p in b.params],
            "returns": [b.returns], "effects": ["read", "write", "trap"], "entry": "b0", "blocks": b.blocks}
    new = copy.deepcopy(old)
    new["functions"] = [replacements.get(f["name"], f) for f in new["functions"]]
    emitted = render_assembly(new).encode()
    checked = assemble_program(emitted).as_dict()
    assert checked == new
    before = {f["name"]: f for f in old["functions"]}
    for f in new["functions"]:
        if f["name"] not in ACCESSORS:
            assert f == before[f["name"]]
    proof = {"schema": "hepta.batch-input-fixed-access.v1", "baseline_sha256": BASE_SHA,
        "source_sha256": sha(emitted), "source_bytes": len(emitted),
        "author_sha256": sha(Path(__file__).read_bytes()), "dsl_sha256": sha(dsl.encode()),
        "changed": {name: {"before_ast": sha(canonical(before[name])), "after_ast": sha(canonical(replacements[name])),
            "operations": "same checked byte accesses at at+0..7, same wrapping address arithmetic, same shifts, same return"}
            for name in ACCESSORS},
        "unchanged_functions": [f["name"] for f in new["functions"] if f["name"] not in ACCESSORS],
        "entry_unchanged": True, "all_parser_and_semantic_functions_unchanged": True,
        "functions": len(new["functions"]), "blocks": sum(len(f["blocks"]) for f in new["functions"]),
        "ops": sum(len(b["ops"]) for f in new["functions"] for b in f["blocks"]),
        "native_executed": False}
    output.mkdir(parents=True, exist_ok=False)
    (output / "batch_plan_input.hepta").write_bytes(emitted)
    (output / "fixed_access.pseudo").write_text(dsl)
    (output / "proof.json").write_text(json.dumps(proof, sort_keys=True, indent=2)+"\n")
    print(json.dumps(proof, sort_keys=True))

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hepta", type=Path, required=True)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    generate(a.hepta.resolve(), a.baseline.resolve(), a.output.resolve())
