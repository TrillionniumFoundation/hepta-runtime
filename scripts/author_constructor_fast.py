"""Add a bounded eight-byte ordinary-ASCII path to the private constructor.

The retained quote body, scalar escape path, entry, UTF-8 validator and all
other imported graphs stay exact. No global serde owner is changed.
"""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import json
import sys

sys.dont_write_bytecode = True
BASE_SHA = "3a4c9b40136e0c3dbf3b580e475447e94fb79913f93416a0ec906da6d294996d"
DSL = '''
def ordinary_eight(o:mutbuf,w:mutbuf,at:u64,remaining:u64) -> u64:
    if remaining<8:
        return 0
    word=get(w,16384+at)
    high=9259542123273814144
    if (word&high)!=0:
        return 0
    inverse=word^18446744073709551615
    controls=(word-2314885530818453536)&inverse&high
    quote=word^2459565876494606882
    slash=word^6655295901103053916
    quote_zero=(quote-72340172838076673)&(quote^18446744073709551615)&high
    slash_zero=(slash-72340172838076673)&(slash^18446744073709551615)&high
    if (controls|quote_zero|slash_zero)!=0:
        return 0
    cursor=get(w,8248)
    if get(w,8232)!=0:
        put(o,cursor,word)
    put(w,8248,cursor+8)
    return 8
'''

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

def generate(hepta, baseline, output):
    raw = baseline.read_bytes()
    assert sha(raw) == BASE_SHA
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    original = assemble_program(raw).as_dict()
    assert len(original["functions"]) == 16
    document = copy.deepcopy(original)
    nodes = ast.parse(DSL).body
    node = nodes[0]
    names = {"ordinary_eight": "f16", "get": "f6", "put": "f7"}
    signatures = {"ordinary_eight": (["mutbuf", "mutbuf", "u64", "u64"], "u64"),
                  "get": (["mutbuf", "u64"], "u64"),
                  "put": (["mutbuf", "u64", "u64"], "u64")}
    b = Builder(node, names, signatures, total_scalar_functions(nodes))
    b.statements(node.body)
    helper = {"name": "f16", "params": [b.param(p) for p in b.params], "returns": [b.returns],
        "effects": ["read", "write", "trap"], "entry": "b0", "blocks": b.blocks}
    helper = compact_authoring_cfg({"schema": "hepta.hia.program.v8", "module": "text_result_constructor",
        "functions": copy.deepcopy(original["functions"]) + [helper]})["functions"][-1]
    quote = document["functions"][14]
    assert quote["name"] == "f14"
    entry = next(block for block in quote["blocks"] if block["id"] == "b1")
    assert entry["term"]["op"] == "branch"
    # Replace just the true edge entering the existing scalar byte body.
    assert entry["term"]["then"] == {"target": "b2", "args": ["v7", "v8", "v9", "v10", "v11"]}
    entry["term"]["then"]["target"] = "b13"
    def params(start, types):
        return [{"name": "v" + str(start+i), "type": t} for i,t in enumerate(types)]
    def op(name, result, ty, args, attrs=None):
        return {"op": name, "out": [{"name": result, "type": ty}], "args": args, "attrs": attrs or {}}
    quote["blocks"].extend([
        {"id": "b13", "params": params(135, ["mutbuf", "mutbuf", "u64", "u64", "u64"]),
         "ops": [op("int.add.wrap", "v140", "u64", ["v137", "v139"]),
                 op("int.sub.wrap", "v141", "u64", ["v138", "v139"]),
                 op("call", "v142", "u64", ["v135", "v136", "v140", "v141"], {"function": "f16"}),
                 op("const", "v143", "u64", [], {"value": 0}),
                 op("compare.ne", "v144", "bool", ["v142", "v143"])],
         "term": {"op": "branch", "cond": "v144",
                  "then": {"target": "b14", "args": ["v135", "v136", "v137", "v138", "v139", "v142"]},
                  "else": {"target": "b2", "args": ["v135", "v136", "v137", "v138", "v139"]}}},
        {"id": "b14", "params": params(145, ["mutbuf", "mutbuf", "u64", "u64", "u64", "u64"]),
         "ops": [op("int.add.wrap", "v151", "u64", ["v149", "v150"])],
         "term": {"op": "jump", "target": "b1", "args": ["v145", "v146", "v147", "v148", "v151"]}},
    ])
    document["functions"].append(helper)
    emitted = render_assembly(document).encode()
    checked = assemble_program(emitted).as_dict()
    assert checked == document
    for i in range(16):
        if i != 14:
            assert checked["functions"][i] == original["functions"][i]
    restored = copy.deepcopy(checked["functions"][14])
    restored["blocks"] = [block for block in restored["blocks"] if block["id"] not in ("b13", "b14")]
    next(block for block in restored["blocks"] if block["id"] == "b1")["term"]["then"]["target"] = "b2"
    assert restored == original["functions"][14]
    for f in checked["functions"]:
        assert len(f["blocks"]) <= 256
        assert max(len(b["params"]) for b in f["blocks"]) <= 16
    output.mkdir(parents=True, exist_ok=False)
    (output / "text_result_constructor.hepta").write_bytes(emitted)
    proof = {"schema": "hepta.text-result-constructor-ordinary-eight.v1", "baseline_sha256": BASE_SHA,
        "source_sha256": sha(emitted), "source_bytes": len(emitted),
        "author_sha256": sha(Path(__file__).read_bytes()), "dsl_sha256": sha(DSL.encode()),
        "new_helper": helper["name"], "unchanged_functions": ["f"+str(i) for i in range(16) if i != 14],
        "quote_restoration": "remove b13/b14 and restore b1.then=b2; complete original f14 AST equal",
        "entry_unchanged": True, "utf8_unchanged": True, "scalar_quote_blocks_unchanged": True,
        "output_and_workspace_behavior": "same cursor and bytes; same capacity/growth; no new state",
        "functions": len(checked["functions"]), "blocks": sum(len(f["blocks"]) for f in checked["functions"]),
        "ops": sum(len(b["ops"]) for f in checked["functions"] for b in f["blocks"]),
        "native_executed": False}
    (output / "proof.json").write_text(json.dumps(proof, indent=2, sort_keys=True)+"\n")
    print(json.dumps(proof, sort_keys=True))

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hepta", type=Path, required=True)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    generate(a.hepta.resolve(), a.baseline.resolve(), a.output.resolve())
