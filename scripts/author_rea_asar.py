# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author native ASAR grammar and integrity; Python runs only in development."""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import json
import operator
import re
import sys
from rea_asar_author_tables import CONSTANTS, NAMES, LITERALS, ERRORS

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CANONICAL = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class ExactConstantArithmetic(ast.NodeTransformer):
    """Fold only nontrapping integer literals in this module's own author input."""

    operations = {
        ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
        ast.BitAnd: operator.and_, ast.BitOr: operator.or_, ast.BitXor: operator.xor,
        ast.LShift: operator.lshift, ast.RShift: operator.rshift,
        ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
    }

    def visit_BinOp(self, node):
        self.generic_visit(node)
        operation = self.operations.get(type(node.op))
        if operation is None or not all(isinstance(v, ast.Constant) and type(v.value) is int
                                        for v in (node.left, node.right)):
            return node
        left, right = node.left.value, node.right.value
        if not (0 <= left <= 0xffffffffffffffff and 0 <= right <= 0xffffffffffffffff):
            return node
        if isinstance(node.op, (ast.LShift, ast.RShift)) and right >= 64:
            return node
        if isinstance(node.op, (ast.FloorDiv, ast.Mod)) and right == 0:
            return node
        value = operation(left, right)
        if 0 <= value <= 0xffffffffffffffff:
            return ast.copy_location(ast.Constant(value=value), node)
        return node


def literal_function(name, values):
    source = f"\ndef {name}(w:mutbuf, at:u64, code:u64) -> u64:\n"
    for code, raw in values.items():
        source += f"    if code == {code}:\n"
        full = len(raw) // 8 * 8
        for offset in range(0, full, 8):
            value = int.from_bytes(raw[offset:offset + 8], "little")
            source += f"        at = word(w, at, {value})\n"
        tail = raw[full:]
        if len(tail) >= 3:
            source += f"        at = partial_word(w, at, {int.from_bytes(tail, 'little')}, {len(tail)})\n"
        else:
            for value in tail:
                source += f"        at = emit(w, at, {value})\n"
        source += "        return at\n"
    return source + "    return at\n"

def round_constant_function(values):
    assert len(values) == 64 and all(type(v) is int and 0 <= v < (1 << 32) for v in values)
    values = [(values[i] << 32) | values[i + 1] for i in range(0, 64, 2)]
    def tree(start, stop, indent):
        if stop - start == 1:
            return indent + f"return {values[start]}\n"
        middle = (start + stop) // 2
        return (indent + f"if index < {middle}:\n" + tree(start, middle, indent + "    ")
                + indent + "else:\n" + tree(middle, stop, indent + "    "))
    return "\ndef sha_round_constant(index:u64) -> u64:\n" + tree(0, 32, "    ")


def generated_source(root, rounds):
    constants = dict(CONSTANTS)
    literals, names = {}, {}
    for index, (name, raw) in enumerate(LITERALS.items(), 1):
        constants[name] = index
        literals[index] = raw
    for index, (name, raw) in enumerate(NAMES.items(), 1):
        constants[name] = index
        names[index] = raw
    source = (root / "scripts/rea_asar_parser_source.py.txt").read_text()
    source = re.sub(r"\b(" + "|".join(constants) + r")\b", lambda m: str(constants[m[0]]), source)
    source += literal_function("literal", literals)
    source += literal_function("error_text", {code: text.encode() for code, text in ERRORS.items()})
    source += round_constant_function(rounds)
    source += "\ndef matches(w:mutbuf, at:u64, n:u64, code:u64) -> u64:\n"
    for code, raw in names.items():
        source += f"    if code == {code}:\n        if n != {len(raw)}:\n            return 0\n"
        full = len(raw) // 8 * 8
        for offset in range(0, full, 8):
            value = int.from_bytes(raw[offset:offset + 8], "little")
            source += f"        if get(w, at + {offset}) != {value}:\n            return 0\n"
        tail = raw[full:]
        if tail:
            mask = (1 << (len(tail) * 8)) - 1
            value = int.from_bytes(tail, "little")
            source += f"        if (get(w, at + {full}) & {mask}) != {value}:\n            return 0\n"
        source += "        return 1\n"
    source += "    return 0\n"
    return source

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    options = parser.parse_args()
    root = options.runtime.resolve(strict=True)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(options.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from tools.generate_hia_sha256 import ROUND
    from hepta.hia_agent_assembly import assemble_program, render_assembly

    class Bulk(Builder):
        def expr(self, node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("private32", "private32be", "private64", "private64be", "private_store32"):
                args = [self.expr(item) for item in node.args]
                view, at = args[:2]
                offset = self.cast(at, "usize")
                if node.func.id == "private_store32":
                    value = args[2]
                    for index in range(4):
                        pos = offset if index == 0 else self.op("int.add.wrap", [offset, self.c(index, "usize")], "usize")
                        part = value if index == 0 else self.op("int.shr.checked", [value, self.c(index * 8, "u64")], "u64")
                        part = self.cast(part, "u8")
                        self.op("buffer.store", [view, pos, part])
                    return self.c(0, "u64")
                size = 8 if node.func.id in ("private64", "private64be") else 4
                result = self.c(0, "u64")
                for index in range(size):
                    pos = offset if index == 0 else self.op("int.add.wrap", [offset, self.c(index, "usize")], "usize")
                    part = self.cast(self.op("buffer.load", [view, pos], "u8"), "u64")
                    shift = (size - index - 1 if node.func.id in ("private32be", "private64be") else index) * 8
                    if shift:
                        part = self.op("int.shl.checked", [part, self.c(shift, "u64")], "u64")
                    result = self.op("bit.or", [result, part], "u64")
                return result
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.FloorDiv, ast.Mod)):
                args = [self.expr(node.left), self.expr(node.right)]
                return self.op("int.div.checked" if isinstance(node.op, ast.FloorDiv) else "int.rem.checked", args, args[0][1])
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "copy_range":
                args = [self.expr(item) for item in node.args]
                if args[0] == args[1]:
                    return self.op("buffer.move_within", [args[0], *(self.cast(x, "usize") for x in args[2:])])
                source = args[1]
                if source[1] == "mutbuf":
                    source = self.op("borrow.read", [source], "readbuf")
                result = self.op("buffer.copy_range", [args[0], source, *(self.cast(x, "usize") for x in args[2:])])
                if args[1][1] == "mutbuf":
                    self.op("loan.end", [source])
                return result
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in self.signatures:
                values = [self.expr(item) for item in node.args]
                signature = self.signatures[node.func.id]
                assert len(values) == len(signature[0])
                args, loans = [], []
                for value, kind in zip(values, signature[0]):
                    if value[1] == "mutbuf" and kind == "readbuf":
                        value = self.op("borrow.read", [value], "readbuf")
                        loans.append(value)
                    args.append(self.cast(value, kind) if value[1] != kind else value)
                result = self.op("call", args, signature[1], function=self.names[node.func.id])
                for value in loans:
                    self.op("loan.end", [value])
                return result
            return super().expr(node)

    source = generated_source(root, ROUND)
    nodes = ExactConstantArithmetic().visit(ast.parse(source)).body
    assert all(isinstance(node, ast.FunctionDef) for node in nodes)
    names = {node.name: "f" + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    specs = [
        ("native/binary_codec.hepta", {"sha_init": "f17", "sha_final": "f10"},
         "f58ab824ecb47545f19cd1d0daded9e41fca5457110693677d84e393e3098f23"),
        ("native/text_budget.hepta", {"utf8": "f2"},
         "89df7b4320fdbd3525450e9446267ae3d54a5b62660d8904fe8f09be36a7fbf9"),
        ("native/serde_json_span.hepta", {"classify_number": "f7"},
         "eb7bf96e7944d8d69fa0ee441ecbf3fc2a79daaa233a3f9706f0fc324eb39f7d"),
    ]
    imports, proof = [], []
    for relative, aliases, expected in specs:
        raw = (root / relative).read_bytes()
        assert SHA(raw) == expected
        original = {f["name"]: f for f in assemble_program(raw).as_dict()["functions"]}
        selected, pending = set(aliases.values()), list(aliases.values())
        while pending:
            for block in original[pending.pop()]["blocks"]:
                for op in block["ops"]:
                    if op["op"] == "call" and op["attrs"]["function"] not in selected:
                        selected.add(op["attrs"]["function"])
                        pending.append(op["attrs"]["function"])
        replaced = {}
        if relative == "native/binary_codec.hepta":
            assert "f19" in selected
            selected.remove("f19")
            replaced["f19"] = names["sha_compress"]
        relocation = {old: "f" + str(len(nodes) + len(imports) + index)
                      for index, old in enumerate(sorted(selected, key=lambda n: int(n[1:])))}
        relocation.update(replaced)
        for alias, old in aliases.items():
            names[alias] = relocation[old]
            signatures[alias] = ([p["type"] for p in original[old]["params"]], original[old]["returns"][0])
        for old, new in relocation.items():
            if old in replaced:
                continue
            item = copy.deepcopy(original[old])
            item["name"] = new
            for block in item["blocks"]:
                for op in block["ops"]:
                    if op["op"] == "call":
                        op["attrs"]["function"] = relocation[op["attrs"]["function"]]
            imports.append(item)
        proof.append({"source": relative, "sha256": expected, "relocation": relocation,
                      "functions": {old: SHA(CANONICAL(original[old])) for old in relocation},
                      "changes": "retained bodies differ only in names/direct targets; private canonical SHA compression explicitly replaced" if replaced else "function and direct-call target names only",
                      "private_replacements": replaced,
                      "private_sha_domain": "internal canonical 32-bit chaining/round words and disjoint block input, with complete original 1184-byte state" if replaced else None})
    functions = []
    total = total_scalar_functions(nodes)
    for node in nodes:
        builder = Bulk(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({"name": names[node.name], "params": [builder.param(p) for p in builder.params],
                          "returns": [builder.returns], "effects": ["read", "write", "trap"],
                          "entry": "b0", "blocks": builder.blocks})
    document = compact_authoring_cfg({"schema": "hepta.hia.program.v8", "module": "hepta_runtime_rea_asar", "functions": functions + imports})
    document["functions"] = document["functions"][:len(functions)] + imports
    operation_count = sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"])
    assert operation_count <= 8192, ("unchanged d3e2 instruction bound", operation_count)
    raw = render_assembly(document).encode()
    actual = {f["name"]: f for f in assemble_program(raw).as_dict()["functions"]}
    assert all(actual[f["name"]] == f for f in imports)
    target = root / "native/rea_asar_parser.hepta"
    target.write_bytes(raw)
    metadata = {
        "schema": "hepta.runtime.rea-asar-composition.v1",
        "source_sha256": SHA(raw), "source_bytes": len(raw), "imports": proof,
        "functions": names, "original_parser": "src/mcp/rea_asar_parser.rs",
        "original_parser_sha256": SHA((root / "src/mcp/rea_asar_parser.rs").read_bytes()),
        "original_parent_sha256": SHA((root / "src/mcp/rea_asar.rs").read_bytes()),
        "workspace_bytes": CONSTANTS["WORKSPACE"], "maximum_result_bytes": 4194304,
        "constants": CONSTANTS, "errors": ERRORS,
        "qualified": False, "public_route_qualified": False, "whole_runtime_qualified": False,
        "scope": "HIA canonical ASAR header and selected-member verification on one caller-admitted descriptor; public authority, isolation, cancellation and parent commitment checks are separate owners",
    }
    (root / "native/rea_asar_parser_composition.json").write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"source_bytes": len(raw), "sha256": SHA(raw), "functions": len(actual),
                      "instructions": sum(len(b["ops"]) for f in actual.values() for b in f["blocks"]),
                      "fits_existing_1MiB_compiler_input": len(raw) <= 1048576}, sort_keys=True))

if __name__ == "__main__":
    main()
