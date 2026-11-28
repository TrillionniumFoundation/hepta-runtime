#!/usr/bin/env python3
"""Author only the Batch frame/controller seam; retain transport helper graphs."""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import json
import sys

PIN = "ca157b5bdeef65ce22590d9efb8677a8f3c5a26ea83352e5190b5f8e57f31b11"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def magic(value):
    assert len(value) == 8
    return int.from_bytes(value.encode("ascii"), "little")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    raw = (root / "retained/text_editor_local_body.hepta").read_bytes()
    assert sha(raw) == PIN
    old = assemble_program(raw).as_dict()
    oldmap = {f["name"]: f for f in old["functions"]}
    replacements = {"entry": "f0", "valid_input": "f1", "prepare_input": "f2",
        "prepare_body": "f14", "after_input": "f15", "after_body": "f16"}
    aliases = {"child": "f3", "region": "f4", "region_capacity": "f5",
        "reserve": "f6", "request_grow": "f7", "pending_grow": "f8",
        "admit_growth": "f9", "delivery_again": "f10", "load": "f11", "get": "f12", "put": "f13"}
    constants = {"INVALID": 0xffffffff, "CAPACITY": 0xfffffffe,
        "CANCELLED": 0xfffffff7, "FIRST_ERROR": 0xffff0000,
        "DELIVERY": 0xffffffcd, "MAXIMUM": (1 << 64) - 1,
        "PHASE": 8, "SEQUENCE": 16, "INPUT_LENGTH": 24,
        "OUTPUT_LENGTH": 32, "WORK_LENGTH": 40, "ACTION": 256,
        "STATE_MAGIC": magic("HBBADS01"), "ACTION_MAGIC": magic("HBBACA01"),
        "REQUEST_MAGIC": magic("HBBSPQ01"), "RESULT_MAGIC": magic("HBBSPR01"),
        "PARAMS_RESULT": magic("HBPRR002"), "INPUT_REQUEST": magic("HBPIQ002"),
        "INPUT_RESULT": magic("HBPIR002"), "PLAN_REQUEST": magic("HBPLAN01"),
        "BODY_REQUEST": magic("HFBWT001"), "BODY_RESULT": magic("HFBWR001")}

    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]), node)
            return node

    class BulkBuilder(Builder):
        def expr(self, node):
            if isinstance(node, ast.Call) and node.func.id == "copy_range":
                destination, source, at, start, count = [self.expr(a) for a in node.args]
                positions = [self.cast(v, "usize") for v in (at, start, count)]
                if destination == source:
                    self.op("buffer.move_within", [destination, *positions])
                elif source[1] == "mutbuf":
                    loan = self.op("borrow.read", [source], "readbuf")
                    self.op("buffer.copy_range", [destination, loan, *positions])
                    self.op("loan.end", [loan])
                else:
                    self.op("buffer.copy_range", [destination, source, *positions])
                return None
            return super().expr(node)

    pseudo = (root / "authoring/batch_body_adapter.pseudo").read_bytes()
    nodes = [Constants().visit(n) for n in ast.parse(pseudo).body]
    names = {**aliases, **replacements}
    signatures = {alias: ([p["type"] for p in oldmap[target]["params"]], oldmap[target]["returns"][0])
                  for alias, target in aliases.items()}
    signatures.update({node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes})
    total = total_scalar_functions(nodes)
    produced = []
    for node in nodes:
        builder = BulkBuilder(node, names, signatures, total)
        builder.statements(node.body)
        produced.append({"name": names[node.name], "params": [builder.param(v) for v in builder.params],
            "returns": [builder.returns], "effects": ["read", "write", "trap"], "entry": "b0", "blocks": builder.blocks})
    changed = set(replacements.values())
    functions = [copy.deepcopy(f) for f in old["functions"] if f["name"] not in changed]
    before_magic, after_magic = magic("HTLBCA01"), magic("HBBACA01")
    relocations = []
    for function in functions:
        for block in function["blocks"]:
            for operation in block["ops"]:
                if operation["op"] == "const" and operation["attrs"]["value"] == before_magic:
                    operation["attrs"]["value"] = after_magic
                    relocations.append(function["name"])
    complete = {"schema": old["schema"], "module": "batch_adapter_compaction", "functions": functions + produced}
    compact = compact_authoring_cfg(complete)["functions"]
    replacements_by_name = {f["name"]: f for f in compact if f["name"] in changed}
    combined = {f["name"]: f for f in functions}
    combined.update(replacements_by_name)
    functions = [combined["f" + str(n)] for n in range(17)]
    retained = {}
    for f in functions:
        if f["name"] in changed:
            continue
        check = copy.deepcopy(f)
        for block in check["blocks"]:
            for operation in block["ops"]:
                if operation["op"] == "const" and operation["attrs"]["value"] == after_magic:
                    operation["attrs"]["value"] = before_magic
        assert check == oldmap[f["name"]], f["name"]
        retained[f["name"]] = sha(canonical(check))
    document = {"schema": old["schema"], "module": "runtime_rebuilt_batch_body_adapter", "functions": functions}
    encoded = render_assembly(document).encode()
    assert assemble_program(encoded).as_dict() == document
    stats = {"functions": len(functions), "blocks": sum(len(f["blocks"]) for f in functions),
        "operations": sum(len(b["ops"]) for f in functions for b in f["blocks"])}
    assert stats["functions"] <= 128 and stats["blocks"] <= 1536 and stats["operations"] <= 8192
    proof = {"schema": "hepta.runtime.rebuilt-batch-body-adapter-author.v1", "source_bytes": len(encoded),
        "source_sha256": sha(encoded), "retained_source_sha256": sha(raw),
        "author_sha256": sha(Path(__file__).read_bytes()), "pseudo_sha256": sha(pseudo),
        "replacement_functions": replacements, "retained_function_sha256": retained,
        "action_magic_relocations": relocations, "observed_result_inputs": False,
        "filesystem_policy_owner": "existing native/batch_write.hepta", "new_version_not_lost_private91": True,
        "native_executed": False, "fresh_current_original_compared": False,
        "public_batch_qualified": False, "whole_runtime_replaced": False, **stats}
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "batch_body_adapter.hepta").write_bytes(encoded)
    (args.output / "body-adapter-author-proof.json").write_bytes(canonical(proof))
    print(json.dumps(proof, sort_keys=True))


if __name__ == "__main__":
    main()
