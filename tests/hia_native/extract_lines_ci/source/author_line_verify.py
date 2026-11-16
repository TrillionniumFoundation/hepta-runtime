#!/usr/bin/env python3
"""Preserve HLINE001 and add an explicit wide HLINE002 admission to the same owner."""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import json
import sys

PIN = "2a0cefe5c81a9659e7965c5d35b83e42d19efd6ad3b5c2c179f934f23b04c6e2"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    raw = args.source.read_bytes()
    assert sha(raw) == PIN
    old = assemble_program(raw).as_dict()
    assert [f["name"] for f in old["functions"]] == ["f" + str(n) for n in range(22)]
    retained = copy.deepcopy(old["functions"][1:])
    legacy = copy.deepcopy(old["functions"][0])
    legacy["name"] = "f22"
    wide_validator = copy.deepcopy(old["functions"][2])
    wide_validator["name"] = "f23"
    replacements = {8388608: (1 << 64) - 1,
        int.from_bytes(b"HLINE001", "little"): int.from_bytes(b"HLINE002", "little")}
    counts = {key: 0 for key in replacements}
    for block in wide_validator["blocks"]:
        for op in block["ops"]:
            if op["op"] == "const" and op["attrs"]["value"] in replacements:
                before = op["attrs"]["value"]
                op["attrs"]["value"] = replacements[before]
                counts[before] += 1
    assert all(count == 1 for count in counts.values()), counts
    wide_entry = copy.deepcopy(old["functions"][0])
    wide_entry["name"] = "f24"
    changed_calls = 0
    for block in wide_entry["blocks"]:
        for op in block["ops"]:
            if op["op"] == "call" and op["attrs"]["function"] == "f2":
                op["attrs"]["function"] = "f23"
                changed_calls += 1
    assert changed_calls == 1
    pseudo = (
        "def entry(s: readbuf, o: mutbuf, w: mutbuf) -> u32:\n"
        f"    if length(s) >= 8 and load(s, 0) == {int.from_bytes(b'HLINE002', 'little')}:\n"
        "        return wide(s, o, w)\n"
        "    return legacy(s, o, w)\n"
    )
    nodes = ast.parse(pseudo).body
    names = {"entry": "f0", "load": "f19", "wide": "f24", "legacy": "f22"}
    signatures = {"entry": (["readbuf", "mutbuf", "mutbuf"], "u32"),
        "wide": (["readbuf", "mutbuf", "mutbuf"], "u32"),
        "legacy": (["readbuf", "mutbuf", "mutbuf"], "u32"), "load": (["readbuf", "u64"], "u64")}
    builder = Builder(nodes[0], names, signatures, total_scalar_functions(nodes))
    builder.statements(nodes[0].body)
    entry = {"name": "f0", "params": [builder.param(v) for v in builder.params],
        "returns": [builder.returns], "effects": ["read", "write", "trap"], "entry": "b0", "blocks": builder.blocks}
    all_functions = [entry] + retained + [legacy, wide_validator, wide_entry]
    temp = {"schema": old["schema"], "module": "line_verify_wide_entry", "functions": all_functions}
    entry = next(f for f in compact_authoring_cfg(temp)["functions"] if f["name"] == "f0")
    functions = [entry] + retained + [legacy, wide_validator, wide_entry]
    for index in range(1, 22):
        assert functions[index] == old["functions"][index]
    restored = copy.deepcopy(legacy)
    restored["name"] = "f0"
    assert restored == old["functions"][0]
    document = {"schema": old["schema"], "module": "runtime_line_verify_dual_extent", "functions": functions}
    encoded = render_assembly(document).encode()
    assert assemble_program(encoded).as_dict() == document
    stats = {"functions": len(functions), "blocks": sum(len(f["blocks"]) for f in functions),
             "operations": sum(len(b["ops"]) for f in functions for b in f["blocks"])}
    assert stats["functions"] <= 128 and stats["blocks"] <= 1536 and stats["operations"] <= 8192
    proof = {"schema": "hepta.runtime.extract-line-verify-author.v1", "before_sha256": PIN,
        "source_sha256": sha(encoded), "source_bytes": len(encoded),
        "author_sha256": sha(Path(__file__).read_bytes()), "dispatcher_source": pseudo,
        "unchanged_graphs": {f["name"]: sha(canonical(f)) for f in retained},
        "legacy_entry_relocated": {"from": "f0", "to": "f22", "sha256": sha(canonical(restored))},
        "wide_validator": {"from": "f2", "to": "f23", "only_changed_constants": counts},
        "wide_entry": {"from": "f0", "to": "f24", "only_changed_call": "f2 -> f23"},
        "legacy_admission_unchanged": True, "result_abi": "HLINER01",
        "new_input_abi": "HLINE002", "native_executed": False,
        "original_compared": False, "whole_runtime_replaced": False, **stats}
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "line_verify.hepta").write_bytes(encoded)
    (args.output / "line_verify.proof.json").write_bytes(canonical(proof))
    print(json.dumps(proof, sort_keys=True))


if __name__ == "__main__":
    main()
