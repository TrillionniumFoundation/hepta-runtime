"""Generate fixed get_info HIA from original source declarations.

No process output is opened here. JSON keys, nested objects, booleans and
source-derived strings are emitted individually by HIA functions.
"""
from pathlib import Path
import argparse, ast, copy, hashlib, json, re, sys
sys.dont_write_bytecode = True
CORE_SHA = "3a4c9b40136e0c3dbf3b580e475447e94fb79913f93416a0ec906da6d294996d"
def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value): return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
def put_json(path, value): path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
def plan(contract):
    experimental = ("object", [(contract["experimental_channel"], ("object", []))])
    enabled = {
        "experimental": experimental,
        "resources": ("object", [("subscribe", ("bool", contract["resources_subscribe"]))]),
        "tools": ("object", []),
    }
    capabilities = ("object", [(field, enabled[field])
                    for field in contract["capability_field_order"] if field in enabled])
    identity = {"name": ("string", contract["server_name"]),
                "version": ("string", contract["server_version"])}
    implementation = ("object", [(field, identity[field])
                      for field in contract["implementation_field_order"] if field in identity])
    fields = {
        "protocol_version": ("protocolVersion", ("string", contract["protocol_version"])),
        "capabilities": ("capabilities", capabilities),
        "server_info": ("serverInfo", implementation),
        "instructions": ("instructions", ("string", contract["instructions"])),
    }
    record = ("object", [fields[field] for field in contract["result_field_order"] if field in fields])
    pieces = []
    def emit(value):
        kind, data = value
        if kind == "object":
            pieces.append(("open_object", b"{"))
            for index, (key, child) in enumerate(data):
                if index: pieces.append(("comma", b","))
                pieces.append(("key_" + re.sub("[^A-Za-z0-9_]", "_", key),
                               json.dumps(key, ensure_ascii=False).encode() + b":"))
                emit(child)
            pieces.append(("close_object", b"}"))
        elif kind == "string":
            pieces.append(("string", json.dumps(data, ensure_ascii=False).encode()))
        elif kind == "bool":
            pieces.append(("boolean", b"true" if data else b"false"))
        else:
            raise ValueError("unsupported fixed field type")
    emit(record)
    return pieces
def literal(name, raw):
    lines = [f"def {name}(o:mutbuf,at:u64) -> u64:"]
    aligned = len(raw) // 8 * 8
    for at in range(0, aligned, 8):
        lines.append(f"    put(o,at+{at},{int.from_bytes(raw[at:at+8], 'little')})")
    for at in range(aligned, len(raw)):
        lines.append(f"    store(o,at+{at},{raw[at]})")
    lines.append(f"    return at+{len(raw)}")
    return "\n".join(lines) + "\n"
def generate(source, primary, hepta, output):
    sys.path.insert(0, str(source / "scripts"))
    from derive_contract import derive
    contract = derive(primary)
    output.mkdir(parents=True, exist_ok=False)
    (output / "native").mkdir()
    put_json(output / "derived-contract.json", contract)
    pieces = plan(contract)
    literals, steps, known = [], [], {}
    for label, raw in pieces:
        if raw not in known:
            name = "literal_" + str(len(literals)) + "_" + label
            known[raw] = name
            literals.append((name, raw))
        steps.append(known[raw])
    wire_bytes = sum(len(raw) for _, raw in pieces)
    authored = (source / "scripts/current_get_info.pseudo").read_text()
    authored += "\ndef emit_info(o:mutbuf,at:u64) -> u64:\n"
    for name in steps: authored += f"    at={name}(o,at)\n"
    authored += "    return at\n\n"
    authored += "\n".join(literal(name, raw) for name, raw in literals)
    constants = dict(INVALID=0xffffffff, CAPACITY=0xfffffffe, RESOURCE=0xfffffffc,
                     GROW=0xffffffd0, WIRE_BYTES=wire_bytes)
    for name, value in dict(REQUEST=b"HRTGIQ01", RESPONSE=b"HRTGIS01",
                            GROW_RESPONSE=b"HGRWS002").items():
        constants[name] = int.from_bytes(value, "little")
    authored = re.sub(r"\b(" + "|".join(constants) + r")\b",
                      lambda match: str(constants[match[0]]), authored)
    (output / "authored.pseudo").write_text(authored)
    put_json(output / "literal-plan.json", {
        "wire_bytes": wire_bytes, "steps": steps,
        "literals": [{"name": name, "bytes": len(raw), "sha256": sha(raw),
                      "utf8": raw.decode()} for name, raw in literals],
        "whole_expected_wire_read_or_embedded": False,
    })
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    support = (source / "support/text_result_constructor.hepta").read_bytes()
    if sha(support) != CORE_SHA: raise ValueError("retained binary ABI helper source differs")
    original = {fn["name"]: fn for fn in assemble_program(support).as_dict()["functions"]}
    nodes = ast.parse(authored).body
    names = {node.name: "f" + str(index) for index, node in enumerate(nodes)}
    exposed = {"put": "f7", "read64": "f8"}
    pending, closure = list(exposed.values()), set()
    while pending:
        name = pending.pop()
        if name in closure: continue
        closure.add(name)
        pending.extend(op["attrs"]["function"] for block in original[name]["blocks"]
                       for op in block["ops"] if op["op"] == "call")
    relocation = {old: "f" + str(len(nodes) + index)
                  for index, old in enumerate(sorted(closure, key=lambda n: int(n[1:])))}
    imported = {}
    for old, new in relocation.items():
        function = copy.deepcopy(original[old]); function["name"] = new
        for block in function["blocks"]:
            for operation in block["ops"]:
                if operation["op"] == "call":
                    operation["attrs"]["function"] = relocation[operation["attrs"]["function"]]
        imported[new] = function
    names.update({alias: relocation[old] for alias, old in exposed.items()})
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    signatures.update({alias: ([p["type"] for p in imported[names[alias]]["params"]],
                                imported[names[alias]]["returns"][0]) for alias in exposed})
    total = total_scalar_functions(nodes)
    generated = []
    for node in nodes:
        builder = Builder(node, names, signatures, total); builder.statements(node.body)
        generated.append(dict(name=names[node.name], params=[builder.param(v) for v in builder.params],
            returns=[builder.returns], effects=["read", "write", "trap"], entry="b0", blocks=builder.blocks))
    document = compact_authoring_cfg(dict(schema="hepta.hia.program.v8",
        module="current_get_info", functions=generated + list(imported.values())))
    document["functions"] = [imported.get(fn["name"], fn) for fn in document["functions"]]
    raw = render_assembly(document).encode()
    checked = assemble_program(raw).as_dict()
    for function in checked["functions"]:
        if function["name"] in imported: assert function == imported[function["name"]]
        assert len(function["blocks"]) <= 256
        assert max(len(block["params"]) for block in function["blocks"]) <= 16
    path = output / "native/current_get_info.hepta"; path.write_bytes(raw)
    result = {
        "schema": "hepta.current-get-info.hia-source.v1",
        "source_sha256": sha(raw), "source_bytes": len(raw),
        "functions": len(checked["functions"]), "function_names": names,
        "author_sha256": sha(Path(__file__).read_bytes()),
        "pseudo_sha256": sha((source / "scripts/current_get_info.pseudo").read_bytes()),
        "derived_contract_sha256": sha((output / "derived-contract.json").read_bytes()),
        "wire_bytes": wire_bytes, "complete_extent": 64 + wire_bytes,
        "helper_source_sha256": CORE_SHA, "helper_relocation": relocation,
        "helper_original_ast_sha256": {name: sha(canonical(original[name])) for name in relocation},
        "helper_changes": ["direct function and call relocation only"],
        "target_commit": contract["target_commit"], "rmcp_source_commit": contract["rmcp_source_commit"],
        "expected_output_or_process_stream_used_for_generation": False,
        "generic_initialize_result_serializer": False, "public_frontend_registered": False,
        "actual_target_comparison_complete": False, "full_sdk_qualified": False,
        "full_async_runtime_qualified": False, "production_activated": False, "old_path_removed": False,
    }
    put_json(output / "native/current_get_info.composition.json", result)
    return result
if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "primary", "hepta", "output"): p.add_argument("--" + name, required=True, type=Path)
    a = p.parse_args()
    print(json.dumps(generate(a.source.resolve(strict=True), a.primary.resolve(strict=True),
        a.hepta.resolve(strict=True), a.output.absolute()), sort_keys=True))
