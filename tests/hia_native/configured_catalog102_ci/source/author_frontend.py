"""Bind tools/list to the installed config owner and fixed 102 capabilities.

The original 73-function frontend is an immutable input. This author replaces
three dispatch wrappers, retains their exact graphs at new function numbers,
and extends only the two entry phase bounds. Batch and Authority paths retain
their original graphs. The installed mask is a build constant, not public data.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
BASE_SHA = "68aa8e005ed38ff778988e0a75bc19588da44de703c0ecc2e642675b5799fdd5"
BASE_BLOB = "138c2e379e79050a883dd10d975bdae4dddc9ac3"
ABSENT = b"runtime tools are disabled; start with --runtime-config <file>"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def graph_pin(value):
    return sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def generate(hepta, source, output):
    raw = (source / "entry_baseline/runtime_mcp.hepta").read_bytes()
    assert sha(raw) == BASE_SHA
    assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == BASE_BLOB
    metadata = json.loads((source / "entry_baseline/runtime_mcp_composition.json").read_bytes())
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    from tools.generate_hia_selfhost import Builder, total_scalar_functions
    baseline = assemble_program(raw).as_dict()
    assert len(baseline["functions"]) == 73
    assert [f["name"] for f in baseline["functions"]] == [f"f{i}" for i in range(73)]
    functions = {f["name"]: f for f in baseline["functions"]}
    # after_catalog uses operation only to recognize get_info=2. Our private
    # list markers 7/8 cannot enter the initialization path.
    after = next(b for b in functions["f5"]["blocks"] if b["id"] == "b15")
    assert [(op["op"], op["attrs"]) for op in after["ops"]] == [
        ("const", {"value": 120}), ("call", {"function": "f31"}),
        ("const", {"value": 2}), ("compare.eq", {})]
    # This is the existing byte-exact absence predicate; no substring or
    # status-only approximation is introduced by the new query consumer.
    assert functions["f68"]["returns"] == ["bool"]
    lines = '''def catalog(s:readbuf, o:mutbuf, w:mutbuf, operation:u64, argument:u64, payload_size:u64) -> u32:
    if operation != 1:
        return retained_catalog(s, o, w, operation, argument, payload_size)
    put(w, 120, operation)
    put(w, 128, argument)
    put(w, 144, payload_size)
    return prepare(s, o, w, 18)

def prepare(s:readbuf, o:mutbuf, w:mutbuf, phase:u64) -> u32:
    if phase == 18:
        put(w, 8, 118)
        if reserve(w, 0, 24) == 0:
            return pending_grow(o, w)
        if reserve(w, 1, 256) == 0:
            return pending_grow(o, w)
        at = region(w, 0)
        put(w, at, CONFIG_QUERY)
        put(w, at + 8, 3)
        put(w, at + 16, 0)
        return child(w, 6, 24, 18)
    if phase == 4:
        operation = get(w, 120)
        if operation == 7 or operation == 8:
            if get(w, 144) != 0:
                return INVALID
            put(w, 8, 104)
            if reserve(w, 0, 40) == 0:
                return pending_grow(o, w)
            if reserve(w, 1, 32) == 0:
                return pending_grow(o, w)
            at = region(w, 0)
            put(w, at, CATALOG_QUERY)
            put(w, at + 8, 7)
            put(w, at + 16, get(w, 128))
            put(w, at + 24, operation - 7)
            put(w, at + 32, 1)
            return child(w, 2, 40, 4)
    return retained_prepare(s, o, w, phase)

def after_authority(s:readbuf, o:mutbuf, w:mutbuf, code:u64, size:u64, phase:u64) -> u32:
    if phase == 18:
        return after_catalog_presence(s, o, w, code, size)
    return retained_after_authority(s, o, w, code, size, phase)

def after_catalog_presence(s:readbuf, o:mutbuf, w:mutbuf, code:u64, size:u64) -> u32:
    if code != size or size < 32:
        return INVALID
    at = region(w, 1)
    if get(w, at) != CONFIG_RESULT:
        return INVALID
    count = get(w, at + 24)
    if count != size - 32:
        return INVALID
    status = get(w, at + 8)
    if status == 0:
        if count != 32 or get(w, at + 16) != 0:
            return INVALID
        put(w, 120, 8)
        return prepare(s, o, w, 4)
    if status == 1:
        if count == CONFIG_ABSENT_SIZE and get(w, at + 16) == 9:
            if config_absent(w, at + 32):
                put(w, 120, 7)
                return prepare(s, o, w, 4)
    return INVALID
'''
    constants = {"CONFIG_QUERY": int.from_bytes(b"HRCFGQ01", "little"),
        "CONFIG_RESULT": int.from_bytes(b"HRCFGM01", "little"),
        "CATALOG_QUERY": int.from_bytes(b"HRMCD002", "little"),
        "CONFIG_ABSENT_SIZE": len(ABSENT), "INVALID": 0xffffffff}
    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            return ast.copy_location(ast.Constant(constants[node.id]), node) if node.id in constants else node
    nodes = ast.fix_missing_locations(Constants().visit(ast.parse(lines))).body
    mapping = {"catalog":"f7", "prepare":"f8", "after_authority":"f62", "after_catalog_presence":"f76",
        "retained_catalog":"f73", "retained_prepare":"f74", "retained_after_authority":"f75",
        "put":"f32", "get":"f31", "reserve":"f21", "region":"f18", "pending_grow":"f23",
        "child":"f12", "config_absent":"f68"}
    relocation = {"f7":"f73", "f8":"f74", "f62":"f75"}
    signatures = {}
    for alias, name in mapping.items():
        original = next((key for key, new in relocation.items() if new == name), name)
        if original in functions:
            f = functions[original]
            signatures[alias] = ([p["type"] for p in f["params"]], f["returns"][0])
    signatures.update({n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes})
    added = {}
    for node in nodes:
        builder = Builder(node, mapping, signatures, total_scalar_functions(nodes))
        builder.statements(node.body)
        added[mapping[node.name]] = {"name": mapping[node.name],
            "params": [builder.param(v) for v in builder.params], "returns": [builder.returns],
            "effects": ["read", "write", "trap"], "entry": "b0", "blocks": builder.blocks}
    document = copy.deepcopy(baseline)
    document["module"] = "runtime_mcp_configured102"
    for index in (7, 8, 62): document["functions"][index] = added[f"f{index}"]
    for old, new in relocation.items():
        f = copy.deepcopy(functions[old]); f["name"] = new; document["functions"].append(f)
    document["functions"].append(added["f76"])
    edits = []
    for block_id, value_id, old, new in (("b19", "v161", 114, 118), ("b21", "v177", 14, 18)):
        block = next(b for b in document["functions"][0]["blocks"] if b["id"] == block_id)
        op = next(op for op in block["ops"] if op["out"] == [{"name": value_id, "type": "u64"}])
        assert op["op"] == "const" and op["attrs"] == {"value": old}
        op["attrs"]["value"] = new
        edits.append({"block": block_id, "value": value_id, "before": old, "after": new})
    restored = copy.deepcopy(document["functions"][0])
    for edit in edits:
        b = next(b for b in restored["blocks"] if b["id"] == edit["block"])
        op = next(op for op in b["ops"] if op["out"] == [{"name":edit["value"],"type":"u64"}])
        assert op["attrs"]["value"] == edit["after"]; op["attrs"]["value"] = edit["before"]
    assert restored == baseline["functions"][0]
    for index in range(1, 73):
        if index not in (7, 8, 62): assert document["functions"][index] == baseline["functions"][index]
    for old, new in relocation.items():
        f = copy.deepcopy(document["functions"][int(new[1:])]); f["name"] = old
        assert f == functions[old]
    result = render_assembly(document).encode()
    assert assemble_program(result).as_dict() == document
    stats = {"functions":len(document["functions"]),
        "blocks":sum(len(f["blocks"]) for f in document["functions"]),
        "instructions":sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"])}
    assert stats["functions"] <= 128 and stats["blocks"] <= 1536 and stats["instructions"] <= 8192
    proof = {"schema":"hepta.runtime.catalog-configured102-frontend-author.v1",
        "author_sha256":sha(Path(__file__).read_bytes()), "baseline_source_sha256":BASE_SHA,
        "baseline_source_blob":BASE_BLOB, "baseline_commit":"0a8f9d6603abaf85f702ff2626dbe75f5d5f841c",
        "baseline_composition_sha256":sha((source/"entry_baseline/runtime_mcp_composition.json").read_bytes()),
        "source_bytes":len(result), "source_sha256":sha(result), **stats,
        "entry_inverse_restores_exact_baseline":True, "entry_constant_changes":edits,
        "retained_function_graphs":{f["name"]:graph_pin(f) for f in baseline["functions"]},
        "relocations":relocation, "unchanged_functions":69,
        "config_query":{"child":6,"magic":"HRCFGQ01","operation":3,"bytes":24},
        "config_absence":{"status":1,"reason":9,"message_hex":ABSENT.hex(),"predicate":"f68"},
        "catalog_child":2, "catalog_operation":7, "installed_capability_mask":1,
        "config_phase":18,"config_grow_phase":118,"catalog_phase":4,
        "batch_child":13,"authority_child":12, "bellman_public_route_installed":False,
        "public_all_configuration_qualified":False,"whole_runtime_replaced":False}
    output.mkdir(parents=True, exist_ok=False)
    (output/"runtime_mcp.hepta").write_bytes(result)
    (output/"catalog_frontend.pseudo").write_text(lines)
    (output/"catalog_frontend_composition.json").write_bytes(encoded(proof))
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = generate(args.hepta.resolve(strict=True), args.source.resolve(strict=True), args.output.absolute())
    print(json.dumps({k: result[k] for k in ("source_sha256","source_bytes","functions","blocks","instructions")}, sort_keys=True))
