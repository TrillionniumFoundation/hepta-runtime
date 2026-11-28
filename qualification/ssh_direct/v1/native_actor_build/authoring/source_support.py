"""Pinned HIA source authoring only; no runtime, loader, emitter or Rust execution."""
from __future__ import annotations
import ast
import copy
import hashlib
import json
import sys

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CANON = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
WORD = lambda value: int.from_bytes(value.encode(), "little")

def require(ok, message):
    if not ok:
        raise ValueError(message)

def identity(raw):
    return {"bytes": len(raw), "sha256": SHA(raw)}

def tools(hepta):
    sys.path.insert(0, str(hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    class NativeBuilder(Builder):
        def expr(self, node):
            if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.FloorDiv)):
                left, right = self.expr(node.left), self.expr(node.right)
                require(left[1] == right[1], "integer operation type differs")
                return self.op("int.rem.checked" if isinstance(node.op, ast.Mod) else "int.div.checked", [left, right], left[1])
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "copy_range":
                    destination, source, at, start, size = [self.expr(a) for a in node.args]
                    positions = [self.cast(v, "usize") for v in (at, start, size)]
                    if destination == source:
                        self.op("buffer.move_within", [destination, *positions])
                    elif source[1] == "mutbuf":
                        loan = self.op("borrow.read", [source], "readbuf")
                        self.op("buffer.copy_range", [destination, loan, *positions])
                        self.op("loan.end", [loan])
                    else:
                        self.op("buffer.copy_range", [destination, source, *positions])
                    return None
                if node.func.id in self.signatures:
                    signature = self.signatures[node.func.id]
                    values = [self.expr(a) for a in node.args]
                    converted, loans = [], []
                    for value, typ in zip(values, signature[0], strict=True):
                        if value[1] == "mutbuf" and typ == "readbuf":
                            value = self.op("borrow.read", [value], "readbuf")
                            loans.append(value)
                        else:
                            value = self.cast(value, typ)
                        converted.append(value)
                    returned = self.op("call", converted, signature[1], function=self.names[node.func.id])
                    for loan in reversed(loans):
                        self.op("loan.end", [loan])
                    return returned
            return super().expr(node)
    return NativeBuilder, compact_authoring_cfg, total_scalar_functions, assemble_program, render_assembly

def parsed_nodes(pseudo, constants):
    class Constants(ast.NodeTransformer):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]), node)
            return node
    nodes = [Constants().visit(node) for node in ast.parse(pseudo).body]
    require(all(isinstance(node, ast.FunctionDef) for node in nodes), "authoring contains a non-function")
    require(len({node.name for node in nodes}) == len(nodes), "duplicate authoring function")
    return nodes

def signature(function):
    return ([p["type"] for p in function["params"]], function["returns"][0])

def checked_program(api, document):
    _, _, _, assemble, render = api
    raw = render(document).encode()
    require(assemble(raw).as_dict() == document, "HIA roundtrip differs")
    fs = document["functions"]
    stats = {"functions": len(fs), "blocks": sum(len(f["blocks"]) for f in fs),
             "operations": sum(len(b["ops"]) for f in fs for b in f["blocks"])}
    require(stats["functions"] <= 128 and stats["blocks"] <= 1536 and stats["operations"] <= 8192,
            "compiler module budget differs: " + str(stats))
    for f in fs:
        require(len(f["blocks"]) <= 256, "function block budget differs: " + f["name"])
        require(max(len(b["params"]) for b in f["blocks"]) <= 16, "block argument budget differs: " + f["name"])
    return raw, stats

def compile_delta(api, original, aliases, pseudo, constants, module):
    Builder, compact, total_functions, assemble, _ = api
    before = assemble(original).as_dict()
    functions = copy.deepcopy(before["functions"])
    by_name = {f["name"]: f for f in functions}
    nodes = parsed_nodes(pseudo, constants)
    names = dict(aliases)
    signatures = {alias: signature(by_name[name]) for alias, name in names.items()}
    next_index = len(functions)
    require(sorted(int(name[1:]) for name in by_name) == list(range(next_index)), "function indices are not dense")
    for node in nodes:
        sig = ([p.annotation.id for p in node.args.args], node.returns.id)
        if node.name in signatures:
            require(signatures[node.name] == sig, "replaced function signature changed: " + node.name)
        else:
            names[node.name] = "f" + str(next_index)
            next_index += 1
        signatures[node.name] = sig
    total = total_functions(nodes)
    generated = {}
    for node in nodes:
        b = Builder(node, names, signatures, total)
        b.statements(node.body)
        generated[names[node.name]] = dict(name=names[node.name], params=[b.param(p) for p in b.params],
            returns=[b.returns], effects=["read", "write", "trap"], entry="b0", blocks=b.blocks)
    combined = [generated.get(f["name"], f) for f in functions]
    combined += [generated[name] for name in sorted(set(generated) - by_name.keys(), key=lambda n: int(n[1:]))]
    tmp = compact(dict(schema=before["schema"], module=module, functions=combined))
    compacted = {f["name"]: f for f in tmp["functions"]}
    final = [compacted[f["name"]] if f["name"] in generated else f for f in combined]
    document = dict(schema=before["schema"], module=module, functions=final)
    raw, stats = checked_program(api, document)
    after = {f["name"]: f for f in document["functions"]}
    retained = {}
    for name, function in by_name.items():
        if name not in generated:
            require(function == after[name], "retained function changed: " + name)
            retained[name] = SHA(CANON(function))
    return raw, names, {"source": identity(raw), **stats, "retained_exact_functions": retained,
        "generated_functions": sorted(generated, key=lambda n: int(n[1:]))}

def compile_new(api, source, roots, pseudo, constants, module):
    Builder, compact, total_functions, assemble, _ = api
    origin = assemble(source).as_dict()
    old = {f["name"]: f for f in origin["functions"]}
    nodes = parsed_nodes(pseudo, constants)
    require(not set(roots) & {node.name for node in nodes}, "import alias collides with generated function")
    closure, queue = set(), list(roots.values())
    while queue:
        name = queue.pop()
        if name in closure:
            continue
        require(name in old, "import function missing: " + name)
        closure.add(name)
        queue += [op["attrs"]["function"] for b in old[name]["blocks"] for op in b["ops"] if op["op"] == "call"]
    ordered = sorted(closure, key=lambda n: int(n[1:]))
    mapping = {name: "f" + str(len(nodes) + i) for i, name in enumerate(ordered)}
    names = {node.name: "f" + str(i) for i, node in enumerate(nodes)}
    names.update({alias: mapping[name] for alias, name in roots.items()})
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    signatures.update({alias: signature(old[name]) for alias, name in roots.items()})
    retained = []
    for name in ordered:
        f = copy.deepcopy(old[name])
        f["name"] = mapping[name]
        for b in f["blocks"]:
            for op in b["ops"]:
                if op["op"] == "call":
                    op["attrs"]["function"] = mapping[op["attrs"]["function"]]
        retained.append(f)
    total = total_functions(nodes)
    new = []
    for node in nodes:
        b = Builder(node, names, signatures, total)
        b.statements(node.body)
        new.append(dict(name=names[node.name], params=[b.param(p) for p in b.params],
            returns=[b.returns], effects=["read", "write", "trap"], entry="b0", blocks=b.blocks))
    tmp = compact(dict(schema=origin["schema"], module=module, functions=new + retained))
    generated = {f["name"] for f in new}
    final = [f for f in tmp["functions"] if f["name"] in generated] + retained
    document = dict(schema=origin["schema"], module=module, functions=final)
    raw, stats = checked_program(api, document)
    inverse = {v: k for k, v in mapping.items()}
    proofs = {}
    for f in retained:
        restored = copy.deepcopy(f)
        restored["name"] = inverse[f["name"]]
        for b in restored["blocks"]:
            for op in b["ops"]:
                if op["op"] == "call":
                    op["attrs"]["function"] = inverse[op["attrs"]["function"]]
        require(restored == old[restored["name"]], "import inverse AST differs")
        proofs[restored["name"]] = {"destination": f["name"], "ast_sha256": SHA(CANON(restored))}
    return raw, names, {"source": identity(raw), **stats, "source_import": identity(source),
        "imports_inverse_ast_exact": proofs, "import_aliases": roots}

def renamed(api, raw, labels, module):
    _, _, _, assemble, render = api
    before = assemble(raw).as_dict()
    doc = copy.deepcopy(before)
    changes = []
    numeric = {WORD(k): WORD(v) for k, v in labels.items()}
    found = set()
    for f in doc["functions"]:
        for block in f["blocks"]:
            for op in block["ops"]:
                if op["op"] == "const" and op["attrs"]["value"] in numeric:
                    previous = op["attrs"]["value"]
                    changes.append([f["name"], block["id"], op["out"], previous, numeric[previous]])
                    op["attrs"]["value"] = numeric[previous]
                    found.add(previous)
    require(found == set(numeric), "private magic source anchor missing")
    doc["module"] = module
    return render(doc).encode(), changes
