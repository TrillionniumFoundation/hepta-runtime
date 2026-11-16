from __future__ import annotations
import ast, copy, hashlib, sys
sha = lambda raw: hashlib.sha256(raw).hexdigest()
canon = lambda value: __import__("json").dumps(value,sort_keys=True,separators=(",",":")).encode()

def compile_delta(hepta, original, aliases, pseudo, replacements, additions, relocated=()):
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    class NativeBuilder(Builder):
        def expr(self, node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "copy_within":
                values = [self.expr(value) for value in node.args]
                return self.op("buffer.move_within", [values[0], *(self.cast(value, "usize") for value in values[1:])])
            return super().expr(node)
    old = assemble_program(original).as_dict()
    before = {f["name"]: copy.deepcopy(f) for f in old["functions"]}
    functions = copy.deepcopy(old["functions"])
    for old_name, new_name in relocated:
        f = copy.deepcopy(before[old_name]); f["name"] = new_name; functions.append(f)
    names = {**aliases, **replacements, **additions}
    by_name = {f["name"]: f for f in functions}
    signatures = {name: ([p["type"] for p in by_name[target]["params"]], by_name[target]["returns"][0])
        for name, target in aliases.items()}
    nodes = ast.parse(pseudo).body
    assert all(isinstance(node, ast.FunctionDef) for node in nodes)
    signatures.update({node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes})
    total = total_scalar_functions(nodes)
    generated = {}
    for node in nodes:
        b = NativeBuilder(node, names, signatures, total); b.statements(node.body)
        generated[names[node.name]] = dict(name=names[node.name],
            params=[b.param(p) for p in b.params], returns=[b.returns],
            effects=["read", "write", "trap"], entry="b0", blocks=b.blocks)
    combined = [generated.get(f["name"], f) for f in functions]
    seen = {f["name"] for f in combined}
    combined += [generated[name] for name in sorted(set(generated) - seen, key=lambda n: int(n[1:]))]
    compacted = compact_authoring_cfg(dict(schema="hepta.hia.program.v8", module="public_connection_delta",
        functions=combined))["functions"]
    compacted = {f["name"]: f for f in compacted}
    functions = [compacted[f["name"]] if f["name"] in generated else f for f in combined]
    raw = render_assembly({**old, "functions": functions}).encode()
    after = {f["name"]: f for f in assemble_program(raw).as_dict()["functions"]}
    retained = {}
    for name, function in before.items():
        if name not in replacements.values():
            assert after[name] == function, name
            retained[name] = sha(canon(function))
    for old_name, new_name in relocated:
        f = copy.deepcopy(before[old_name]); f["name"] = new_name
        assert after[new_name] == f
    for f in after.values():
        assert len(f["blocks"]) <= 256, f["name"]
        assert max(len(b["params"]) for b in f["blocks"]) <= 16, f["name"]
    return raw, after, retained
