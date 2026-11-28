#!/usr/bin/env python3
"""Apply the three-function Batch edge to an explicitly pinned composed frontend.

All names come from the admitted composition aliases. The next three function
indices are derived from the current maximum, so authority and Bellman additions
are preserved. The caller owns mechanical child-table binding and final graph
rebinding; this source author does not assert integrated runtime qualification.
"""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent / "frontend-v3"))
from compile_delta import compile_delta

sha = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda row: (json.dumps(row, sort_keys=True, indent=2) + "\n").encode()
canonical = lambda row: json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
word = lambda text: int.from_bytes(text.encode(), "little")


def compose(baseline, hepta, baseline_sha256):
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    original = (baseline / "native/runtime_mcp.hepta").read_bytes()
    assert len(baseline_sha256) == 64 and sha(original) == baseline_sha256
    comp = json.loads((baseline / "native/runtime_mcp_composition.json").read_bytes())
    assert comp["source_sha256"] == baseline_sha256 and comp["source_bytes"] == len(original)
    before = assemble_program(original).as_dict()
    old = {function["name"]: function for function in before["functions"]}
    assert len(old) == len(before["functions"])
    assert comp["function_sha256"] == {name: sha(canonical(function)) for name, function in old.items()}
    names = dict(comp["functions"])
    for alias in ("tool_kind", "prepare", "prepare_text_editor", "entry"):
        assert names[alias] in old
    assert not any(alias in names for alias in ("retained_batch_tool_kind", "retained_batch_prepare", "prepare_batch"))
    indices = sorted(int(name.removeprefix("f")) for name in old)
    assert indices == list(range(len(old)))
    next_index = max(indices) + 1
    additions = {alias: "f" + str(next_index + offset) for offset, alias in enumerate(
        ("retained_batch_tool_kind", "retained_batch_prepare", "prepare_batch"))}
    aliases = {**names, **additions}
    seed = copy.deepcopy(before)
    relocated = {names["tool_kind"]: additions["retained_batch_tool_kind"],
        names["prepare"]: additions["retained_batch_prepare"]}
    for previous, current in relocated.items():
        function = copy.deepcopy(old[previous]); function["name"] = current
        seed["functions"].append(function)
    prepared = copy.deepcopy(old[names["prepare_text_editor"]])
    prepared["name"] = additions["prepare_batch"]
    changes = []
    for block in prepared["blocks"]:
        for op in block["ops"]:
            if op["op"] != "const":
                continue
            if op["attrs"]["value"] == word("HTEWGQ02"):
                changes.append((block["id"], op["out"][0]["name"], word("HTEWGQ02"), word("HBAWGQ02")))
                op["attrs"]["value"] = word("HBAWGQ02")
            elif block["id"] == "b16" and op["out"] == [{"name": "v177", "type": "u64"}]:
                assert op["attrs"]["value"] == 9
                changes.append((block["id"], "v177", 9, 13))
                op["attrs"]["value"] = 13
    assert len(changes) == 2
    seed["functions"].append(prepared)
    pseudo_path = Path(__file__).parent / "frontend-v3/batch_frontend.pseudo"
    pseudo = pseudo_path.read_text().replace("BATCH_NAME_HEAD", str(word("batch_ed")))
    raw, after, _ = compile_delta(hepta, render_assembly(seed).encode(), aliases, pseudo,
        {"tool_kind": names["tool_kind"], "prepare": names["prepare"]}, {})
    assert len(after) == len(old) + 3
    retained = {}
    for name, function in old.items():
        if name not in relocated:
            assert after[name] == function
            retained[name] = sha(canonical(function))
    assert after[additions["prepare_batch"]] == prepared
    for previous, current in relocated.items():
        function = copy.deepcopy(old[previous]); function["name"] = current
        assert after[current] == function
    inverse = copy.deepcopy(prepared); inverse["name"] = names["prepare_text_editor"]
    for block_id, variable, previous, current in changes:
        op = next(op for block in inverse["blocks"] if block["id"] == block_id for op in block["ops"]
            if op["out"] == [{"name": variable, "type": "u64"}])
        assert op["attrs"]["value"] == current
        op["attrs"]["value"] = previous
    assert inverse == old[names["prepare_text_editor"]]
    blocks = sum(len(function["blocks"]) for function in after.values())
    operations = sum(len(block["ops"]) for function in after.values() for block in function["blocks"])
    assert len(after) <= 128 and blocks <= 1536 and operations <= 8192
    proof = {"schema": "hepta.runtime.batch-public-dynamic-frontend.v1",
        "baseline_sha256": baseline_sha256, "source_sha256": sha(raw), "source_bytes": len(raw),
        "functions": len(after), "blocks": blocks, "operations": operations,
        "baseline_functions": len(old), "dynamic_next_index": next_index,
        "changed_original_functions": list(relocated), "relocated_original_functions": relocated,
        "retained_exact_functions": retained, "added_aliases": additions,
        "entry_ast_byte_exact": after[names["entry"]] == old[names["entry"]],
        "prepared_request_inverse_ast_exact": True, "prepared_request_constant_changes": changes,
        "fixed_child": 13, "global_gateway_slot": 47, "tool_kind": 10,
        "uses_existing_common_tool_completion_phase": 6, "uses_existing_growth_phase": 106,
        "other_phases_and_original_functions_unchanged": True,
        "catalog_remains_unchanged": True, "mechanical_table_binding_required": True,
        "public_batch_qualified": False, "full_async_cancellation_qualified": False,
        "whole_runtime_replaced": False, "author_sha256": sha(Path(__file__).read_bytes()),
        "pseudo_sha256": sha(pseudo_path.read_bytes())}
    comp.update(source_sha256=sha(raw), source_bytes=len(raw), functions=aliases,
        function_sha256={name: sha(canonical(function)) for name, function in after.items()},
        rebuilt_batch_extension=proof)
    return {"native/runtime_mcp.hepta": raw, "native/runtime_mcp_composition.json": encoded(comp),
        "native/runtime_mcp_batch_composition.json": encoded(proof)}, proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--baseline-sha256", required=True)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-output-sha256")
    args = parser.parse_args()
    outputs, proof = compose(args.baseline.resolve(strict=True), args.hepta.resolve(strict=True), args.baseline_sha256)
    if args.expected_output_sha256:
        assert proof["source_sha256"] == args.expected_output_sha256
    args.output.mkdir(parents=True, exist_ok=False)
    for name, data in outputs.items():
        path = args.output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    print(json.dumps({key: value for key, value in proof.items() if key != "retained_exact_functions"}, sort_keys=True))
