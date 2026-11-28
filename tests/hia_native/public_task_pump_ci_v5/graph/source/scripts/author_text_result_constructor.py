"""Author the single HIA text CallToolResult constructor.

All imported helper ASTs remain exact except direct function/call relocation.
The new owner owns target constructor fields, policy projection and private ABI.
"""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import json
import re
import sys

sys.dont_write_bytecode = True

PINS = {
    "native/serde_json.hepta": "ef9dd3a567acf523257c4245c022b8cefa9b3ddb83075e826f129b1a1f341d18",
    "native/typed_result_json.hepta": "a9dfe2fec3f35b2ef2bcfaec56229007c75301cccb06a96a36691dc361aa0bec",
}
PREFIX = b'{"resultType":"complete","content":[{"type":"text","text":'
LEGACY_PREFIX = b'{"content":[{"type":"text","text":'
SUCCESS_SUFFIX = b'}],"isError":false}'
ERROR_SUFFIX = b'}],"isError":true}'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def literal(name, value):
    result = f"\ndef {name}(o:mutbuf,at:u64) -> u64:\n"
    last = len(value) // 8 * 8
    for i in range(0, last, 8):
        result += f"    put(o,at+{i},{int.from_bytes(value[i:i+8], 'little')})\n"
    for i in range(last, len(value)):
        result += f"    store(o,at+{i},{value[i]})\n"
    return result + f"    return at+{len(value)}\n"


def generate(hepta, source):
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly

    class NativeBuilder(Builder):
        def expr(self, node):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "copy_range":
                args = [self.expr(v) for v in node.args]
                assert args[0][1] == "mutbuf" and args[1][1] == "readbuf"
                return self.op("buffer.copy_range", [args[0], args[1],
                    *(self.cast(v, "usize") for v in args[2:])])
            return super().expr(node)

    documents = {}
    for path, expected in PINS.items():
        raw = (source / path).read_bytes()
        if sha(raw) != expected:
            raise ValueError(("source pin differs", path, sha(raw)))
        documents[path] = {fn["name"]: fn for fn in assemble_program(raw).as_dict()["functions"]}
    dsl = source / "scripts/text_result_constructor.pseudo"
    authored = dsl.read_text()
    for name, raw in {"current_prefix": PREFIX, "legacy_prefix": LEGACY_PREFIX,
                      "success_suffix": SUCCESS_SUFFIX, "error_suffix": ERROR_SUFFIX}.items():
        authored += literal(name, raw)
    constants = dict(INVALID=0xffffffff, CAPACITY=0xfffffffe, RESOURCE=0xfffffffc, GROW=0xffffffd0,
                     PREFIX_SIZE=len(PREFIX), LEGACY_PREFIX_SIZE=len(LEGACY_PREFIX),
                     SUCCESS_SUFFIX_SIZE=len(SUCCESS_SUFFIX), ERROR_SUFFIX_SIZE=len(ERROR_SUFFIX))
    for name, raw in dict(REQUEST=b"HRTCRQ01", RESPONSE=b"HRTCRS01", GROW_RESPONSE=b"HGRWS002").items():
        constants[name] = int.from_bytes(raw, "little")
    authored = re.sub(r"\b(" + "|".join(constants) + r")\b", lambda m: str(constants[m[0]]), authored)
    nodes = ast.parse(authored).body
    names = {node.name: "f" + str(i) for i, node in enumerate(nodes)}
    selected = {
        "native/serde_json.hepta": {"get": "f14", "put": "f15", "read64": "f21", "quote": "f39"},
        "native/typed_result_json.hepta": {"utf8": "f70"},
    }
    imports, aliases, proof = [], {}, {}
    for path, exposed in selected.items():
        old = documents[path]
        pending, closure = list(exposed.values()), set()
        while pending:
            current = pending.pop()
            if current in closure:
                continue
            closure.add(current)
            pending.extend(op["attrs"]["function"] for block in old[current]["blocks"]
                           for op in block["ops"] if op["op"] == "call")
        relocation = {name: "f" + str(len(nodes) + len(imports) + i)
                      for i, name in enumerate(sorted(closure, key=lambda n: int(n[1:])))}
        proof[path] = dict(source_sha256=PINS[path], relocation=relocation,
                           functions={n: sha(canonical(old[n])) for n in relocation})
        for alias, old_name in exposed.items():
            aliases[alias] = relocation[old_name]
        for old_name, new_name in relocation.items():
            function = copy.deepcopy(old[old_name])
            function["name"] = new_name
            for block in function["blocks"]:
                for operation in block["ops"]:
                    if operation["op"] == "call":
                        operation["attrs"]["function"] = relocation[operation["attrs"]["function"]]
            imports.append(function)
    names.update(aliases)
    imported = {f["name"]: f for f in imports}
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    signatures.update({alias: ([p["type"] for p in imported[name]["params"]], imported[name]["returns"][0])
                       for alias, name in aliases.items()})
    total = total_scalar_functions(nodes)
    generated = []
    for node in nodes:
        builder = NativeBuilder(node, names, signatures, total)
        builder.statements(node.body)
        generated.append(dict(name=names[node.name], params=[builder.param(v) for v in builder.params],
                              returns=[builder.returns], effects=["read", "write", "trap"],
                              entry="b0", blocks=builder.blocks))
    document = compact_authoring_cfg(dict(schema="hepta.hia.program.v8",
                                          module="text_result_constructor", functions=generated+imports))
    document["functions"] = [imported.get(f["name"], f) for f in document["functions"]]
    raw = render_assembly(document).encode()
    checked = assemble_program(raw).as_dict()
    for function in checked["functions"]:
        if function["name"] in imported:
            assert function == imported[function["name"]]
        assert len(function["blocks"]) <= 256, function["name"]
        assert max(len(b["params"]) for b in function["blocks"]) <= 16, function["name"]
    destination = source / "native/text_result_constructor.hepta"
    destination.write_bytes(raw)
    result = dict(schema="hepta.runtime.text-result-constructor-source.v2",
        source_sha256=sha(raw), source_bytes=len(raw), functions=len(checked["functions"]),
        blocks=sum(len(f["blocks"]) for f in checked["functions"]), function_names=names,
        dsl_sha256=sha(dsl.read_bytes()), author_sha256=sha(Path(__file__).read_bytes()),
        constants=constants, imports=proof, import_changes=["direct function/call relocation only"],
        target_application_commit="d3d75c30719db966b004756f610007a7c723729e",
        target_rmcp="3.9.0", target_rmcp_commit="5596a8a0bba2a1ec5519cc855cdadf23e4dcecdc",
        actual_target_constructor_compared=False, public_publish_qualified=False,
        whole_runtime_replaced=False, full_async_runtime_qualified=False)
    destination.with_suffix(".composition.json").write_text(json.dumps(result, sort_keys=True, indent=2)+"\n")
    print(json.dumps({k:result[k] for k in ("source_sha256","source_bytes","functions","blocks")},sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    generate(args.hepta.resolve(), args.source.resolve())

