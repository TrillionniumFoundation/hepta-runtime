#!/usr/bin/env python3
"""Add the actual Batch gateway edge without changing shared admission/results.

Batch uses the existing phase 6 tool completion ABI, because its gateway emits
the same HRCFGM01 header. No new phase aliases 13/14, reserved for authority.
Local child 13 is fixed to global slot 47 by the installed mechanical graph.
"""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import sys

sys.dont_write_bytecode = True
from compile_delta import compile_delta


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def word(s):
    return int.from_bytes(s.encode(), "little")


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--hepta", type=Path, required=True)
    a = p.parse_args()
    sys.path.insert(0, str(a.hepta.resolve(strict=True)))
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    source, baseline = a.source.resolve(strict=True), a.baseline.resolve(strict=True)
    old_raw = (baseline / "native/runtime_mcp.hepta").read_bytes()
    assert sha(old_raw) == "311ccb1387c1d9f01e690fcda6b839d0dcd52514e6be6c63cd4a02f9c674c475"
    old = assemble_program(old_raw).as_dict()
    assert len(old["functions"]) == 60
    comp = json.loads((baseline / "native/runtime_mcp_composition.json").read_bytes())
    aliases = {**comp["functions"], "retained_batch_tool_kind": "f60", "retained_batch_prepare": "f61", "prepare_batch": "f62"}
    # Copy the checked Text gateway request construction. Only the private
    # request magic and the installed child index differ; the completion ABI
    # and phase, raw arguments, metadata and growth ownership are identical.
    prepared = copy.deepcopy(old["functions"][45])
    prepared["name"] = "f62"
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
    seed = copy.deepcopy(old)
    for index, name in ((29, "f60"), (8, "f61")):
        f = copy.deepcopy(old["functions"][index]);f["name"] = name;seed["functions"].append(f)
    seed["functions"].append(prepared)
    pseudo = (Path(__file__).parent / "batch_frontend.pseudo").read_text().replace("BATCH_NAME_HEAD", str(word("batch_ed")))
    raw, after, _ = compile_delta(a.hepta, render_assembly(seed).encode(), aliases, pseudo,
                                  {"tool_kind": "f29", "prepare": "f8"}, {})
    doc = assemble_program(raw).as_dict()
    assert len(doc["functions"]) == 63
    retained = {}
    for i, function in enumerate(old["functions"]):
        if i not in (8, 29):
            assert doc["functions"][i] == function
            retained[function["name"]] = sha(json.dumps(function,sort_keys=True,separators=(",",":")).encode())
    assert doc["functions"][62] == prepared
    inverse = copy.deepcopy(prepared);inverse["name"] = "f45"
    for bid, name, before, final in changes:
        op = next(o for b in inverse["blocks"] if b["id"] == bid for o in b["ops"] if o["out"] == [{"name": name, "type": "u64"}])
        assert op["attrs"]["value"] == final;op["attrs"]["value"] = before
    assert inverse == old["functions"][45]
    proof = {"schema": "hepta.runtime.rebuilt-batch-public-frontend-source.v1",
        "baseline_sha256": sha(old_raw), "source_sha256": sha(raw), "source_bytes": len(raw),
        "functions": 63, "blocks": sum(len(f["blocks"]) for f in doc["functions"]),
        "operations": sum(len(b["ops"]) for f in doc["functions"] for b in f["blocks"]),
        "retained_exact_functions": retained, "changed_original_functions": ["f8", "f29"],
        "relocated_original_functions": {"f29": "f60", "f8": "f61"},
        "prepared_request_inverse_ast_exact": True, "prepared_request_constant_changes": changes,
        "fixed_child": 13, "global_gateway_slot": 47, "tool_kind": 10,
        "uses_existing_common_tool_completion_phase": 6, "uses_existing_growth_phase": 106,
        "new_authority_phases_13_14_unmodified": True, "entry_ast_byte_exact": True,
        "actual_target_text_constructor_retained": True, "catalog_remains_nine": True,
        "public_batch_route_registered_in_candidate_source": True,
        "public_batch_qualified": False, "full_async_cancellation_qualified": False,
        "whole_runtime_replaced": False, "author_sha256": sha(Path(__file__).read_bytes()),
        "pseudo_sha256": sha((Path(__file__).parent / "batch_frontend.pseudo").read_bytes())}
    comp.update(source_sha256=sha(raw), source_bytes=len(raw), functions=aliases,
        function_sha256={f["name"]:sha(json.dumps(f,sort_keys=True,separators=(",",":")).encode()) for f in doc["functions"]},
        rebuilt_batch_extension=proof)
    for name, data in {"native/runtime_mcp.hepta": raw, "native/runtime_mcp_composition.json": encoded(comp),
                       "native/runtime_mcp_batch_composition.json": encoded(proof)}.items():
        (source / name).write_bytes(data)
    binding = json.loads((source / "native/runtime_mcp_sources.json").read_bytes())
    for name in ("native/runtime_mcp.hepta", "native/runtime_mcp_composition.json", "native/runtime_mcp_batch_composition.json"):
        data = (source / name).read_bytes();binding["sources"][name] = {"bytes":len(data),"sha256":sha(data)}
    binding["rebuilt_batch_extension"].update(public_batch_route_registered=True, catalog_remains_nine=True,
        frontend_composition=proof["source_sha256"])
    (source / "native/runtime_mcp_sources.json").write_bytes(encoded(binding))
    print(json.dumps({k:v for k,v in proof.items() if k != "retained_exact_functions"},sort_keys=True))


if __name__ == "__main__":
    main()
