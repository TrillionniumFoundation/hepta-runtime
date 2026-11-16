#!/usr/bin/env python3
"""Compile the source-bound extract_lines data owner; never read oracle answers."""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import json
import sys

TEXT_PIN = "89df7b4320fdbd3525450e9446267ae3d54a5b62660d8904fe8f09be36a7fbf9"
IMPORTS = {"utf8": "f2", "line_hash": "f9", "load": "f14", "get": "f15", "put": "f16"}
LITERALS = (
    "Appended ", " lines (", ") from '", "' to '", "' at ",
    "beginning of file", "end of file", "after line ", ":\n",
    "\nshift: lines after ", " +", "[...", " lines more]",
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def magic(value):
    assert len(value) == 8
    return int.from_bytes(value.encode("ascii"), "little")


def literal_source():
    rows = ["def literal(o: mutbuf, w: mutbuf, ident: u64) -> u64:"]
    for index, value in enumerate(LITERALS):
        raw = value.encode()
        rows += [f"    if ident == {index}:", "        at = get(w, 0)",
                 f"        advance(w, {len(raw)})", "        if get(w, 8) != 0:"]
        offset = 0
        while offset + 8 <= len(raw):
            rows.append(f"            put(o, at + {offset}, {int.from_bytes(raw[offset:offset + 8], 'little')})")
            offset += 8
        while offset < len(raw):
            rows.append(f"            store(o, at + {offset}, {raw[offset]})")
            offset += 1
        rows.append("        return 1")
    rows.append("    return 0")
    return "\n".join(rows) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--text-owner", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly

    raw = args.text_owner.read_bytes()
    assert sha(raw) == TEXT_PIN
    old = assemble_program(raw).as_dict()
    oldmap = {f["name"]: f for f in old["functions"]}
    constants = {
        "INVALID": 0xffffffff, "CAPACITY": 0xfffffffe, "GROW": 0xffffffd0,
        "RESOURCE": 0xfffffffc, "FIRST_ERROR": 0xffff0000, "MAXIMUM": (1 << 64) - 1,
        "REQUEST": magic("HEXDATA1"), "GROW_MAGIC": magic("HGRWS002"),
        "VERIFY_MAGIC": magic("HLINE002"), "SELECT_MAGIC": magic("HEXSEL01"),
        "EDIT_MAGIC": magic("HEDIT001"),
    }

    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]), node)
            return node

    class BulkBuilder(Builder):
        def expr(self, node):
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.FloorDiv)):
                left, right = self.expr(node.left), self.expr(node.right)
                assert left[1] == right[1]
                name = "int.rem.checked" if isinstance(node.op, ast.Mod) else "int.div.checked"
                return self.op(name, [left, right], left[1])
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "copy_range":
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

    pseudo = Path(__file__).with_name("extract_data.pseudo").read_bytes()
    literal = literal_source().encode()
    parsed = ast.parse(pseudo + b"\n" + literal)
    assert all(isinstance(node, ast.FunctionDef) for node in parsed.body)
    nodes = [Constants().visit(node) for node in parsed.body]
    names = {node.name: "f" + str(index) for index, node in enumerate(nodes)}
    names.update({name: "f" + str(len(nodes) + index) for index, name in enumerate(IMPORTS)})
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    signatures.update({name: ([p["type"] for p in oldmap[ident]["params"]], oldmap[ident]["returns"][0])
                       for name, ident in IMPORTS.items()})
    total = total_scalar_functions(nodes)
    produced = []
    for node in nodes:
        builder = BulkBuilder(node, names, signatures, total)
        builder.statements(node.body)
        produced.append({"name": names[node.name], "params": [builder.param(v) for v in builder.params],
            "returns": [builder.returns], "effects": ["read", "write", "trap"], "entry": "b0", "blocks": builder.blocks})
    retained_functions = []
    imported = {}
    for alias, ident in IMPORTS.items():
        original = oldmap[ident]
        assert not any(o["op"] == "call" for b in original["blocks"] for o in b["ops"])
        copied = copy.deepcopy(original)
        copied["name"] = names[alias]
        retained_functions.append(copied)
        restored = copy.deepcopy(copied)
        restored["name"] = ident
        assert restored == original
        imported[alias] = {"from": ident, "to": names[alias], "complete_graph_sha256": sha(canonical(original))}
    document = {"schema": old["schema"], "module": "extract_data_new_graphs", "functions": produced + retained_functions}
    new_names = {f["name"] for f in produced}
    functions = [f for f in compact_authoring_cfg(document)["functions"] if f["name"] in new_names]
    functions += retained_functions
    document = {"schema": old["schema"], "module": "runtime_extract_lines_data", "functions": functions}
    encoded = render_assembly(document).encode()
    assert assemble_program(encoded).as_dict() == document
    counts = {"functions": len(functions), "blocks": sum(len(f["blocks"]) for f in functions),
              "operations": sum(len(b["ops"]) for f in functions for b in f["blocks"])}
    assert counts["functions"] <= 128 and counts["blocks"] <= 1536 and counts["operations"] <= 8192
    proof = {"schema": "hepta.runtime.extract-lines-data-author.v1", "source_bytes": len(encoded),
        "source_sha256": sha(encoded), "retained_text_owner_sha256": TEXT_PIN,
        "author_sha256": sha(Path(__file__).read_bytes()), "pseudo_sha256": sha(pseudo),
        "literal_source_sha256": sha(literal), "aliases": names, "imports": imported,
        "observed_result_inputs": False, "native_executed": False,
        "fresh_current_original_compared": False, "public_extract_qualified": False,
        "whole_runtime_replaced": False, **counts}
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "extract_data.hepta").write_bytes(encoded)
    (args.output / "extract_data.proof.json").write_bytes(canonical(proof))
    print(json.dumps(proof, sort_keys=True))


if __name__ == "__main__":
    main()
