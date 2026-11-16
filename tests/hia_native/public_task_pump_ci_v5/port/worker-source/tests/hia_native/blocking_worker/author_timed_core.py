"""Add resumable deadlines while proving the old numeric graph is retained."""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys

from timed_core_source import SOURCE

CHECKPOINTS = {1: "b14", 2: "b71", 3: "b73", 4: "b112", 5: "b113"}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def author(root, hepta):
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import _parse_assembly_document, render_assembly
    from hepta.hia_program import verify_program
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

    baseline = (root / "native/bellman_core.hepta").read_bytes()
    before = _parse_assembly_document(baseline)
    assert len(before["functions"]) == 19
    result = copy.deepcopy(before)
    result["module"] = "bellman_timed_core"
    source = SOURCE
    for name, value in {
        "INIT_MAGIC": b"HBTMIN01", "STATE_MAGIC": b"HBTMST01",
        "INIT_RESULT_MAGIC": b"HBTMIR01", "CORE_MAGIC": b"HIABELL1",
        "EFFECT_MAGIC": b"HBTMEF01", "ACK_MAGIC": b"HBTMAK01",
    }.items():
        source = source.replace(name, str(int.from_bytes(value, "little")))
    nodes = ast.parse(source).body
    names = {node.name: "f" + str(19 + i) for i, node in enumerate(nodes)}
    names.update(read64="f5", get="f6", put="f7")
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    signatures.update(read64=(["readbuf", "u64"], "u64"), get=(["mutbuf", "u64"], "u64"),
                      put=(["mutbuf", "u64", "u64"], "u64"))
    helpers = []
    for node in nodes:
        builder = Builder(node, names, signatures, total_scalar_functions(nodes))
        builder.statements(node.body)
        helpers.append({"name": names[node.name], "params": [builder.param(p) for p in builder.params],
                        "returns": [builder.returns], "effects": ["read", "write", "trap"],
                        "entry": "b0", "blocks": builder.blocks})
    helper_doc = compact_authoring_cfg({"schema": before["schema"], "module": "timed_core_helpers",
                                       "functions": copy.deepcopy(before["functions"]) + helpers})
    result["functions"].extend(helper_doc["functions"][19:])

    f = result["functions"][0]
    old_blocks = {b["id"]: b for b in f["blocks"]}
    extra = []
    next_value = 3000
    next_block = 200

    def value(typ):
        nonlocal next_value
        result = {"name": "v" + str(next_value), "type": typ}
        next_value += 1
        return result

    def block(types):
        nonlocal next_block
        b = {"id": "b" + str(next_block), "params": [value(t) for t in types], "ops": [], "term": {}}
        next_block += 1
        extra.append(b)
        return b

    def op(b, name, args, typ, attrs=None):
        v = value(typ)
        b["ops"].append({"op": name, "args": args, "out": [v], "attrs": attrs or {}})
        return v["name"]

    def const(b, n):
        return op(b, "const", [], "u64", {"value": n})

    def ret_u64(b, value_name):
        v = op(b, "int.cast", [value_name], "u32", {"mode": "wrap"})
        b["term"] = {"op": "ret", "values": [v]}

    def call(b, target, args):
        return op(b, "call", args, "u64", {"function": names[target]})

    redirects = {}
    for pc, target in CHECKPOINTS.items():
        original = old_blocks[target]
        b = block([p["type"] for p in original["params"]])
        args = [p["name"] for p in b["params"]]
        assert [p["type"] for p in original["params"]] == ["readbuf", "mutbuf", "mutbuf"] + ["u64"] * (2 if pc in (2, 5) else 3)
        p = const(b, pc)
        index = const(b, 0) if pc in (2, 5) else args[5]
        ret_u64(b, call(b, "pause", args[:3] + [p, args[3], args[4], index]))
        redirects[target] = b["id"]

    # Redirect only the original incoming edges. Resume edges below target the
    # original blocks themselves, so a completed effect is never replayed.
    redirected_edges = []
    for b in f["blocks"]:
        term = b["term"]
        edges = [term] if term["op"] == "jump" else [term["then"], term["else"]] if term["op"] == "branch" else []
        for e in edges:
            if e["target"] in redirects:
                redirected_edges.append((b["id"], e["target"], redirects[e["target"]]))
                e["target"] = redirects[e["target"]]

    returns = {}
    for b in f["blocks"]:
        if b["term"]["op"] != "ret":
            continue
        returns[b["id"]] = {"term": copy.deepcopy(b["term"]), "ops": len(b["ops"])}
        w = b["params"][2]
        assert w["type"] == "mutbuf"
        code = op(b, "int.cast", b["term"]["values"], "u64", {"mode": "wrap"})
        ret_u64(b, call(b, "finish", [w["name"], code]))

    entry = block(["readbuf", "mutbuf", "mutbuf"])
    args = [p["name"] for p in entry["params"]]
    status = call(entry, "admit", args)
    cases = [block(["readbuf", "mutbuf", "mutbuf", "u64"]) for _ in range(6)]
    fallback = block(["u64"])
    ret_u64(fallback, fallback["params"][0]["name"])
    entry["term"] = {"op": "jump", "target": cases[0]["id"], "args": args + [status]}
    for pc, case in enumerate(cases):
        a = [p["name"] for p in case["params"]]
        match = op(case, "compare.eq", [a[3], const(case, pc)], "bool")
        if pc == 0:
            target, target_args = "b0", a[:3]
        else:
            resume = block(["readbuf", "mutbuf", "mutbuf"])
            ra = [p["name"] for p in resume["params"]]
            scalars = [call(resume, "saved", [ra[2], const(resume, i)]) for i in range(2 if pc in (2, 5) else 3)]
            resume["term"] = {"op": "jump", "target": CHECKPOINTS[pc], "args": ra + scalars}
            target, target_args = resume["id"], a[:3]
        otherwise = {"target": cases[pc + 1]["id"], "args": a} if pc < 5 else {"target": fallback["id"], "args": [a[3]]}
        case["term"] = {"op": "branch", "cond": match, "then": {"target": target, "args": target_args}, "else": otherwise}
    f["entry"] = entry["id"]
    f["params"] = copy.deepcopy(entry["params"])
    f["blocks"].extend(extra)

    # This inverse is checked before rendering: every original opcode, constant,
    # edge argument, and block parameter is restored exactly.
    inverse = copy.deepcopy(f)
    inverse["entry"] = before["functions"][0]["entry"]
    inverse["params"] = copy.deepcopy(before["functions"][0]["params"])
    inverse["blocks"] = inverse["blocks"][:len(before["functions"][0]["blocks"])]
    backwards = {v: k for k, v in redirects.items()}
    for b in inverse["blocks"]:
        if b["id"] in returns:
            record = returns[b["id"]]
            b["ops"] = b["ops"][:record["ops"]]
            b["term"] = record["term"]
        term = b["term"]
        edges = [term] if term["op"] == "jump" else [term["then"], term["else"]] if term["op"] == "branch" else []
        for e in edges:
            e["target"] = backwards.get(e["target"], e["target"])
    assert inverse == before["functions"][0]
    assert result["functions"][1:19] == before["functions"][1:19]
    verify_program(result)
    raw = render_assembly(result).encode()
    assert _parse_assembly_document(raw) == result
    target = root / "native/bellman_timed_core.hepta"
    target.write_bytes(raw)
    proof = {"schema": "hepta.runtime.bellman-timed-core.source-proof.v1", "status": "SOURCE_ONLY_PASS",
             "baseline_source_sha256": digest(baseline), "source_sha256": digest(raw), "source_bytes": len(raw),
             "source_author_sha256": digest(Path(__file__).read_bytes()),
             "helper_source_sha256": digest((Path(__file__).parent / "timed_core_source.py").read_bytes()),
             "functions": len(result["functions"]), "blocks": sum(len(x["blocks"]) for x in result["functions"]),
             "core_inverse_exact": True, "old_math_functions_exact": list(range(1, 19)),
             "redirected_edges": redirected_edges, "checkpoint_original_blocks": CHECKPOINTS,
             "old_function_asts": {x["name"]: digest(encoded(x)) for x in before["functions"]},
             "native_executed": False, "original_executed": False,
             "timed_commitment_qualified": False, "public_handler_qualified": False}
    (root / "native/bellman_timed_core_source_proof.json").write_bytes(encoded(proof))
    return proof


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-root", type=Path, required=True)
    p.add_argument("--hepta", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(author(a.source_root.resolve(), a.hepta.resolve()), sort_keys=True))
