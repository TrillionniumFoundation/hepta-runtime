#!/usr/bin/env python3
"""Expand only the checked internal SDK message projection's borrowed spans.

The external transport still admits at most 16 MiB including LF. A typed
HRCJR001 envelope contains additional full serialized spans; its total size is
not the original transport size. The direct HRQPR001 interface keeps its old
16 MiB input / 8 MiB parameter bounds. No parser/serializer function changes.
"""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import re
import sys

BASE = "ed335f8fae0ab751d6d1282fa62d7351f72b7ce622dd4efca4e2f6a62f5c5641"
sha = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def author(hepta, baseline, output):
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    raw = baseline.read_bytes()
    assert sha(raw) == BASE
    old = assemble_program(raw).as_dict()
    assert render_assembly(old).encode() == raw and len(old["functions"]) == 23
    program = copy.deepcopy(old)
    entry = program["functions"][0]
    next_value = max(int(x) for x in re.findall(r"\bv(\d+)\b", json.dumps(old["functions"][0]))) + 1

    def value():
        nonlocal next_value
        name = "v" + str(next_value)
        next_value += 1
        return name

    def const(ops, number):
        name = value()
        ops.append({"op": "const", "out": [{"name": name, "type": "u64"}], "args": [], "attrs": {"value": number}})
        return name

    def insert(block_name, old_name, old_number, operands):
        block = next(b for b in entry["blocks"] if b["id"] == block_name)
        index = next(i for i, op in enumerate(block["ops"]) if op["out"] == [{"name": old_name, "type": "u64"}])
        assert block["ops"][index] == {"op": "const", "out": [{"name": old_name, "type": "u64"}], "args": [], "attrs": {"value": old_number}}
        ops = []
        if block_name == "b1":
            zero = const(ops, 0)
            got = value()
            ops.append({"op": "call", "out": [{"name": got, "type": "u64"}], "args": [operands, zero], "attrs": {"function": "f8"}})
            expected = const(ops, int.from_bytes(b"HRCJR001", "little"))
            wide = 64 << 20
        else:
            got, expected = operands, const(ops, 1)
            wide = 16 << 20
        selected = value()
        ops.append({"op": "compare.eq", "out": [{"name": selected, "type": "bool"}], "args": [got, expected], "attrs": {}})
        extended, legacy = const(ops, wide), const(ops, old_number)
        ops.append({"op": "select", "out": [{"name": old_name, "type": "u64"}], "args": [selected, extended, legacy], "attrs": {}})
        block["ops"][index:index + 1] = ops

    insert("b1", "v17", 16 << 20, "v7")
    insert("b30", "v398", 8 << 20, "v391")
    after = render_assembly(program).encode()
    assert assemble_program(after).as_dict() == program
    assert program["functions"][1:] == old["functions"][1:]
    changed_blocks = [before["id"] for before, final in zip(old["functions"][0]["blocks"], entry["blocks"], strict=True) if before != final]
    assert changed_blocks == ["b1", "b30"]
    # Existing layout: control words below 64 KiB; copied params followed by
    # copied external metadata occupy at most 16 MiB (the unchanged b52 bound).
    # The unchanged serializer's 64 MiB region follows that exact input slab.
    copied_start, copied_size = 65536, 16 << 20
    rendered_start, rendered_size, minimum_workspace = 16842752, 64 << 20, 96 << 20
    assert copied_start + copied_size == rendered_start
    assert rendered_start + rendered_size <= minimum_workspace
    proof = {"schema": "hepta.runtime.sdk-request-internal-capacity.v1",
        "baseline_sha256": BASE, "source_sha256": sha(after), "source_bytes": len(after),
        "function_count": 23, "changed_function": "f0", "changed_blocks": changed_blocks,
        "retained_function_sha256": {f["name"]: sha(encoded(f)) for f in old["functions"][1:]},
        "legacy_direct_input_limit": 16 << 20, "legacy_direct_params_limit": 8 << 20,
        "typed_message_input_limit": 64 << 20, "typed_message_params_limit": 16 << 20,
        "external_transport_including_lf_limit_unchanged": 16 << 20,
        "existing_metadata_limit_unchanged": 8 << 20, "combined_copied_params_metadata_limit_unchanged": copied_size,
        "copied_input_region": [copied_start, rendered_start],
        "render_region": [rendered_start, rendered_start + rendered_size],
        "workspace_minimum_unchanged": minimum_workspace,
        "existing_checked_pair_and_all_type_validation_unchanged": True,
        "existing_output_capacity_and_atomicity_logic_unchanged": True,
        "author_sha256": sha(Path(__file__).read_bytes()),
        "native_executed": False, "fresh_original_compared": False, "public_batch_qualified": False}
    output.mkdir(parents=True, exist_ok=False)
    (output / "sdk_request_target.hepta").write_bytes(after)
    (output / "proof.json").write_bytes(encoded(proof))
    return proof


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hepta", type=Path, required=True)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(author(args.hepta.resolve(strict=True), args.baseline.resolve(strict=True), args.output.absolute()), sort_keys=True))
