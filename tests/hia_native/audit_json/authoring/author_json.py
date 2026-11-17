"""Author the audit codec; never execute HIA, emitted native code, or Rust."""
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import sys


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                git_blob=hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def generate(root, hepta):
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    inputs = json.loads((root / "INPUTS.json").read_bytes())
    for name, identity in inputs["files"].items():
        actual = pin((root / name).read_bytes())
        assert all(actual[key] == value for key, value in identity.items()), name
    original = (root / "reference/request_audit.rs.txt").read_bytes()
    record_begin = original.index(b"#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]\n#[serde(rename_all = \"snake_case\")]\nenum DurableState")
    record_end = original.index(b"\n/// The private owner", record_begin)
    assert original[record_begin:record_end].rstrip() + b"\n" == (root / "reference/record_types.rs.txt").read_bytes()
    anchor_begin = original.index(b"#[cfg(unix)]\n#[derive(Deserialize, Serialize)]\n#[serde(deny_unknown_fields)]\nstruct ArchiveAnchor")
    anchor_end = original.index(b"\n\n#[derive(Debug, Clone, Copy)]", anchor_begin)
    assert original[anchor_begin:anchor_end] == (root / "reference/anchor_type.rs.txt").read_bytes()

    literals = [b"request_id", b"owner", b"tool_name", b"state", b"accepted_unix_ms",
                b"elapsed_ms", b"root_device", b"root_inode", b"archive_device",
                b"archive_inode", b"unknown", b"completed", b"failed", b"null"]
    constants = dict(INVALID=0xffffffff, CAPACITY=0xfffffffe,
                     REQUEST=int.from_bytes(b"HAJRQ001", "little"),
                     PROJECTION=int.from_bytes(b"HAJPR001", "little"))
    pseudo = (root / "authoring/audit_json.pseudo").read_text()
    pseudo = re.sub(r"\b(" + "|".join(constants) + r")\b",
                    lambda match: str(constants[match[0]]), pseudo)
    pseudo += "\ndef literal_length(literal:u64) -> u64:\n"
    for index, raw in enumerate(literals):
        pseudo += f"    if literal=={index}:\n        return {len(raw)}\n"
    pseudo += "    return 0\n\ndef literal_byte(literal:u64,index:u64) -> u64:\n"
    for index, raw in enumerate(literals):
        pseudo += f"    if literal=={index}:\n        return literal_{index}(index)\n"
    pseudo += "    return 0\n"
    for index, raw in enumerate(literals):
        pseudo += f"\ndef literal_{index}(index:u64) -> u64:\n"
        for offset, byte in enumerate(raw):
            pseudo += f"    if index=={offset}:\n        return {byte}\n"
        pseudo += "    return 0\n"
    nodes = ast.parse(pseudo).body
    assert all(isinstance(node, ast.FunctionDef) for node in nodes)
    names = {node.name: "f" + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    imported, proofs = {}, []
    for source_name, aliases in [
        ("request_storage_json.hepta", dict(unsigned="f7", string_info="f22", copy_string="f23",
            whitespace="f25", decoded="f28", get="f29", put="f30", read64="f31")),
        ("request_retention.hepta", dict(decimal128="f14")),
    ]:
        source = (root / "imports" / source_name).read_bytes()
        functions = {fn["name"]: fn for fn in assemble_program(source).as_dict()["functions"]}
        pending, closure = list(aliases.values()), set()
        while pending:
            name = pending.pop()
            if name in closure:
                continue
            closure.add(name)
            pending.extend(op["attrs"]["function"] for block in functions[name]["blocks"]
                           for op in block["ops"] if op["op"] == "call")
        relocation = {name: "f" + str(len(nodes) + len(imported) + index)
                      for index, name in enumerate(sorted(closure, key=lambda value: int(value[1:])))}
        inverse = {value: key for key, value in relocation.items()}
        for name, relocated in relocation.items():
            function = copy.deepcopy(functions[name])
            function["name"] = relocated
            for block in function["blocks"]:
                for operation in block["ops"]:
                    if operation["op"] == "call":
                        operation["attrs"]["function"] = relocation[operation["attrs"]["function"]]
            restored = copy.deepcopy(function)
            restored["name"] = name
            for block in restored["blocks"]:
                for operation in block["ops"]:
                    if operation["op"] == "call":
                        operation["attrs"]["function"] = inverse[operation["attrs"]["function"]]
            assert restored == functions[name]
            imported[relocated] = function
        for alias, original_name in aliases.items():
            names[alias] = relocation[original_name]
            function = imported[names[alias]]
            signatures[alias] = ([parameter["type"] for parameter in function["params"]], function["returns"][0])
        proofs.append(dict(source="imports/" + source_name, source_identity=pin(source),
            relocation=relocation, aliases=aliases, inverse_full_ast_equal=True,
            original_functions={name: pin(canonical(functions[name])) for name in relocation}))
    total = total_scalar_functions(nodes)
    generated = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        generated.append(dict(name=names[node.name], params=[builder.param(v) for v in builder.params],
            returns=[builder.returns], effects=["read", "write", "trap"], entry="b0", blocks=builder.blocks))
    program = compact_authoring_cfg(dict(schema="hepta.hia.program.v8", module="audit_json",
                                        functions=generated + list(imported.values())))
    program["functions"] = [imported.get(fn["name"], fn) for fn in program["functions"]]
    raw = render_assembly(program).encode()
    checked = assemble_program(raw).as_dict()
    for function in checked["functions"]:
        if function["name"] in imported:
            assert function == imported[function["name"]]
        assert len(function["blocks"]) <= 256, function["name"]
        assert all(len(block["params"]) <= 16 for block in function["blocks"]), function["name"]
    shape = dict(functions=len(checked["functions"]),
                 blocks=sum(len(fn["blocks"]) for fn in checked["functions"]),
                 operations=sum(len(block["ops"]) for fn in checked["functions"] for block in fn["blocks"]))
    assert shape["operations"] <= 8192, shape
    native = root / "native"
    native.mkdir(exist_ok=False)
    (native / "audit_json.hepta").write_bytes(raw)
    proof = dict(schema="hepta.audit-json.source-composition.v1", target_commit=inputs["target"],
        compiler_commit=inputs["compiler"], source_identity=pin(raw), shape=shape,
        function_names=names, constants=constants, imports=proofs,
        original_types={name: pin((root / "reference" / name).read_bytes())
                        for name in ("record_types.rs.txt", "anchor_type.rs.txt")},
        author_identity=pin(Path(__file__).read_bytes()),
        pseudo_identity=pin((root / "authoring/audit_json.pseudo").read_bytes()),
        no_expected_output_used_for_generation=True, source_authoring_only=True,
        native_or_hia_or_rust_execution=0, actual_type_comparison_complete=False,
        public_handler_qualified=False, production_activated=False, whole_runtime_replaced=False)
    (native / "audit_json.composition.json").write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n")
    files = {}
    for path in sorted(native.iterdir()):
        name = path.relative_to(root).as_posix()
        content = path.read_bytes()
        files[name] = pin(content)
        print("GENERATED_FILE_BEGIN " + name)
        print(content.decode(), end="")
        print("GENERATED_FILE_END " + name)
    print("GENERATED_MANIFEST " + json.dumps(files, sort_keys=True))
    print(json.dumps(dict(status="PASS", source_authoring_only=True, shape=shape,
                         native_or_hia_or_rust_execution=0), sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--hepta", type=Path, required=True)
    args = parser.parse_args()
    generate(args.root.resolve(strict=True), args.hepta.resolve(strict=True))
