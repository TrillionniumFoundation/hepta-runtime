#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author parent normalization, acquisition, borrowed child and final close in HIA."""
import argparse
import ast
import copy
import hashlib
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CANON = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "hepta", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    root = args.source.resolve(strict=True)
    hepta = args.hepta.resolve(strict=True)
    out = args.output.absolute()
    if out.exists():
        raise ValueError("fresh author output is required")
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly

    baseline = (root / "dependency/native/binary_write_body.hepta").read_bytes()
    composition_raw = (root / "dependency/native/binary_write_body_composition.json").read_bytes()
    assert SHA(baseline) == "ae2bacd915ea008143821b09b1be49f5a1121d278e8f82937ff2b73f7480f251"
    original = assemble_program(baseline).as_dict()
    composition = json.loads(composition_raw)
    assert composition["source_sha256"] == SHA(baseline)
    functions = {f["name"]: f for f in original["functions"]}
    assert len(functions) == len(original["functions"]) == 43
    for name, function in functions.items():
        assert SHA(CANON(function)) == composition["function_sha256"][name]
    roots = ("load", "get", "put", "copy_in", "copy_out", "copy_within", "utf8", "negative", "equal", "error_class")
    selected = {composition["aliases"][name] for name in roots}
    todo = list(selected)
    while todo:
        name = todo.pop()
        for block in functions[name]["blocks"]:
            for op in block["ops"]:
                if op["op"] == "call":
                    child = op["attrs"]["function"]
                    assert child in functions
                    if child not in selected:
                        selected.add(child)
                        todo.append(child)
    assert "f0" not in selected
    ordered = sorted(selected, key=lambda name: int(name[1:]))
    rename = {old: "f" + str(i + 1) for i, old in enumerate(ordered)}
    inverse = {new: old for old, new in rename.items()}

    def relocate(function, mapping):
        value = copy.deepcopy(function)
        value["name"] = mapping[value["name"]]
        for block in value["blocks"]:
            for op in block["ops"]:
                if op["op"] == "call":
                    op["attrs"]["function"] = mapping[op["attrs"]["function"]]
        return value

    retained = [relocate(functions[name], rename) for name in ordered]
    assert all(relocate(new, inverse) == functions[old] for old, new in zip(ordered, retained))
    constants = dict(
        LIMIT=4294901760, INVALID=4294967295, CAPACITY=4294967294,
        NEXT=4294967293, MAXIMUM=18446744073709551615, BASE=4096,
        ROOT="get(w,104)", PATH="get(w,112)", PRIOR="get(w,120)",
        DATA="get(w,128)", CHILD="get(w,136)", ERROR="get(w,144)",
        REPLY="get(w,152)", RESULT="get(w,160)",
        FLAGS=720896,
    )
    for name, magic in (("REQUEST", b"HBPWQ001"), ("RESPONSE", b"HBPWR001"),
                        ("WORK", b"HBPWW001"), ("BODY_REQUEST", b"HBWTQ001"),
                        ("BODY_RESPONSE", b"HBWTR001"), ("ERROR_RESPONSE", b"HBRDS001"),
                        ("META_ERROR", b"HMDSR001"), ("PATH_ERROR", b"HOSER001")):
        constants[name] = int.from_bytes(magic, "little")
    pseudo = (root / "authoring/binary_parent_owner.pseudo").read_text()
    literals = {
        "literal_absolute": "absolute non-traversing file path required",
        "literal_outside": "file outside configured root",
        "literal_sidecar": "capability root and runtime sidecars are not file targets",
        "literal_null": "embedded null byte",
    }
    for name, value in literals.items():
        raw = value.encode()
        pseudo += "\ndef " + name + "(w:mutbuf,at:u64) -> u64:\n"
        for i, byte in enumerate(raw):
            pseudo += "    store(w,at+" + str(i) + "," + str(byte) + ")\n"
        pseudo += "    return at+" + str(len(raw)) + "\n"
    pseudo = re.sub(r"\b(" + "|".join(constants) + r")\b", lambda match: str(constants[match[0]]), pseudo)
    nodes = ast.parse(pseudo).body
    assert nodes[0].name == "entry"
    names = {alias: rename[name] for alias, name in composition["aliases"].items() if name in rename}
    names["entry"] = "f0"
    for i, node in enumerate(nodes[1:]):
        assert node.name not in names
        names[node.name] = "f" + str(len(retained) + i + 1)
    signatures = {alias: ([p["type"] for p in functions[name]["params"]], functions[name]["returns"][0])
                  for alias, name in composition["aliases"].items() if name in rename}
    for node in nodes:
        signatures[node.name] = ([p.annotation.id for p in node.args.args], node.returns.id)
    total = total_scalar_functions(nodes)
    fresh = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        fresh.append(dict(name=names[node.name], params=[builder.param(p) for p in builder.params],
                          returns=[builder.returns], effects=["read", "write", "trap"], entry="b0", blocks=builder.blocks))
    document = dict(schema="hepta.hia.program.v8", module="binary_parent_owner",
                    functions=[fresh[0], *retained, *fresh[1:]])
    compact = compact_authoring_cfg(document)
    compact["functions"][1:len(retained) + 1] = retained
    raw = render_assembly(compact).encode()
    actual = assemble_program(raw).as_dict()
    assert render_assembly(actual).encode() == raw
    assert actual["functions"][1:len(retained) + 1] == retained
    operations = sum(len(block["ops"]) for f in actual["functions"] for block in f["blocks"])
    blocks = sum(len(f["blocks"]) for f in actual["functions"])
    limits = json.loads((hepta / "docs/HIA_SELFHOST_CORE_SUPPORT.json").read_bytes())["limits"]
    assert len(actual["functions"]) <= limits["functions"] == 128
    assert operations <= 8192 and blocks <= limits["blocks_total"] == 1536
    for function in actual["functions"]:
        assert len(function["blocks"]) <= 256, function["name"]
        assert max(len(block["params"]) for block in function["blocks"]) <= 16, function["name"]
        assert len(set(re.findall(r'"(v[0-9]+)"', json.dumps(function)))) <= limits["ssa_names_per_function"] == 2048
    receipt = dict(schema="hepta.runtime.binary-parent-owner.author.v1", source_sha256=SHA(raw), source_bytes=len(raw),
                   functions=len(actual["functions"]), instructions=operations, blocks=blocks,
                   aliases=names, constants=constants,
                   function_sha256={f["name"]: SHA(CANON(f)) for f in actual["functions"]},
                   retained=dict(source_sha256=SHA(baseline), composition_sha256=SHA(composition_raw),
                                 roots=list(roots), functions=len(retained), relocations=rename,
                                 complete_inverse_ir=True),
                   original_source_sha256=SHA((root / "reference/binary_file.py").read_bytes()),
                   private_protocol="HBPWQ001/HBPWR001", borrowed_body="HBWTQ001/HBWTR001",
                   runtime_python_required=False, native_compiled=False, native_executed=False,
                   original_compared=False, public_route=False, whole_runtime_replaced=False)
    out.mkdir(parents=True)
    (out / "binary_parent_owner.hepta").write_bytes(raw)
    (out / "binary_parent_owner_composition.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    (out / "binary_parent_owner.pseudo").write_text(pseudo)
    print(json.dumps({key: receipt[key] for key in ("schema", "source_sha256", "source_bytes", "functions", "instructions", "blocks")}, sort_keys=True))


if __name__ == "__main__":
    main()
