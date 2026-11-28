# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Development-only source author. Emitted production modules contain only HIA."""
from pathlib import Path
import ast
import copy
import hashlib
import json
import re
import sys

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CANONICAL = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

def compile_source(root, hepta, name, source, constants, imports):
    root, hepta = Path(root).resolve(strict=True), Path(hepta).resolve(strict=True)
    for key, module in tuple(sys.modules.items()):
        if key == "hepta" or key.startswith(("hepta.", "tools.")):
            location = getattr(module, "__file__", None)
            if location and not Path(location).resolve().is_relative_to(hepta):
                raise ValueError("foreign author package already loaded")
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    class Bulk(Builder):
        def expr(self, node):
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.FloorDiv, ast.Mod)):
                a, b = self.expr(node.left), self.expr(node.right)
                return self.op("int.div.checked" if isinstance(node.op, ast.FloorDiv) else "int.rem.checked", [a, b], a[1])
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "copy_range":
                    a = [self.expr(item) for item in node.args]
                    if a[0] == a[1]:
                        return self.op("buffer.move_within", [a[0], *(self.cast(x, "usize") for x in a[2:])])
                    original = a[1]
                    borrowed = self.op("borrow.read", [original], "readbuf") if original[1] == "mutbuf" else original
                    result = self.op("buffer.copy_range", [a[0], borrowed, *(self.cast(x, "usize") for x in a[2:])])
                    if borrowed != original:
                        self.op("loan.end", [borrowed])
                    return result
                if node.func.id in self.signatures:
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
    if constants:
        source = re.sub(r"\b(" + "|".join(map(re.escape, constants)) + r")\b",
                        lambda match: str(constants[match[0]]), source)
    nodes = ast.parse(source).body
    assert all(isinstance(node, ast.FunctionDef) for node in nodes)
    names = {node.name: "f" + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    imported, proof, expected_functions = [], [], {}
    for relative, expected, aliases in imports:
        raw = (root / relative).read_bytes()
        if SHA(raw) != expected:
            raise ValueError("exact imported source differs: " + relative)
        original = {f["name"]: f for f in assemble_program(raw).as_dict()["functions"]}
        selected, pending = set(aliases.values()), list(aliases.values())
        while pending:
            for block in original[pending.pop()]["blocks"]:
                for op in block["ops"]:
                    if op["op"] == "call" and op["attrs"]["function"] not in selected:
                        selected.add(op["attrs"]["function"])
                        pending.append(op["attrs"]["function"])
        relocation = {old: "f" + str(len(nodes) + len(imported) + i)
                      for i, old in enumerate(sorted(selected, key=lambda value: int(value[1:])))}
        for alias, old in aliases.items():
            names[alias] = relocation[old]
            signatures[alias] = ([p["type"] for p in original[old]["params"]], original[old]["returns"][0])
        for old, new in relocation.items():
            function = copy.deepcopy(original[old])
            function["name"] = new
            for block in function["blocks"]:
                for op in block["ops"]:
                    if op["op"] == "call":
                        op["attrs"]["function"] = relocation[op["attrs"]["function"]]
            imported.append(function)
            expected_functions[new] = function
        proof.append(dict(path=relative, sha256=SHA(raw), relocation=relocation,
                          complete_functions={old: SHA(CANONICAL(original[old])) for old in relocation}))
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Bulk(node, names, signatures, total)
        builder.statements(node.body)
        functions.append(dict(name=names[node.name], params=[builder.param(p) for p in builder.params],
                              returns=[builder.returns], effects=["read", "write", "trap"],
                              entry="b0", blocks=builder.blocks))
    document = compact_authoring_cfg(dict(schema="hepta.hia.program.v8", module=name,
                                         functions=functions + imported))
    document["functions"] = document["functions"][:len(functions)] + imported
    raw = render_assembly(document).encode()
    parsed = assemble_program(raw).as_dict()
    for function in parsed["functions"]:
        if function["name"] in expected_functions:
            assert function == expected_functions[function["name"]]
    target = root / "native" / (name + ".hepta")
    target.write_bytes(raw)
    record = dict(schema="hepta.runtime.durable-source-composition.v1",
                  module=name, source_sha256=SHA(raw), source_bytes=len(raw),
                  functions=names, imported_exact_functions=proof,
                  authored_sha256=SHA(source.encode()),
                  authored_functions=len(nodes), total_functions=len(parsed["functions"]),
                  total_blocks=sum(len(f["blocks"]) for f in parsed["functions"]),
                  production_routing_qualified=False)
    (root / "native" / (name + "_composition.json")).write_bytes(CANONICAL(record) + b"\n")
    return record
