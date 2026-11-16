"""Author HIA audit lifetime policy and native atomic reference instructions.

Generated sources are frozen before later compilation and semantic qualification.
This authoring program never executes emitted HIA or native code.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import sys

COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
TARGET = "d3d75c30719db966b004756f610007a7c723729e"
TARGET_SHA = "b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da"

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                git_blob=hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())

def render(pseudo, module):
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    nodes = ast.parse(pseudo).body
    assert all(isinstance(node, ast.FunctionDef) for node in nodes)
    names = {node.name: "f" + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id)
                  for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append(dict(name=names[node.name], params=[builder.param(p) for p in builder.params],
                              returns=[builder.returns], effects=["read", "write", "trap"],
                              entry="b0", blocks=builder.blocks))
    program = compact_authoring_cfg(dict(schema="hepta.hia.program.v8", module=module,
                                        functions=functions))
    raw = render_assembly(program).encode()
    checked = assemble_program(raw).as_dict()
    assert all(len(f["blocks"]) <= 256 for f in checked["functions"])
    assert all(len(b["params"]) <= 16 for f in checked["functions"] for b in f["blocks"])
    return raw, dict(function_names=names, functions=len(checked["functions"]),
                     blocks=sum(len(f["blocks"]) for f in checked["functions"]),
                     operations=sum(len(b["ops"]) for f in checked["functions"] for b in f["blocks"]))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root, output = args.root.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.hepta.resolve()))
    sys.path.insert(0, str(root))
    from process import Recorder
    recorder = Recorder(root, output / "processes")
    native = root / "native"
    native.mkdir(exist_ok=True)
    original = (root / "reference/request_audit.rs.txt").read_bytes()
    assert hashlib.sha256(original).hexdigest() == TARGET_SHA
    begin = original.index(b"fn active_registry()")
    end = original.index(b"\n#[cfg(unix)]\nfn name(", begin)
    owner = original[begin:end]
    (root / "reference/registry.rs.txt").write_bytes(owner)
    constants = dict(INVALID=0xffffffff, CAPACITY=0xfffffffe, STATE_ERROR=0xfffffff9,
                     RESOURCE=0xfffffffa, MAXIMUM=(1 << 64) - 1, MASK8=(1 << 64) - 8,
                     LOCKED=10, FINAL_UNLOCK=11, ERROR_UNLOCK=12, QUERY_UNLOCK=13,
                     CLEAR_UNLOCK=14, PUBLISH_WEAK=20, REPLACE_DROP=21, PRUNE_COUNT=22,
                     PRUNE_DROP=23, QUERY_UPGRADE=24, QUERY_LOAD=25, QUERY_DROP=26,
                     CLEAR_DROP=27, GROWN=28, HELD=90, DONE=91)
    for name, value in dict(REQUEST=b"HARGQ001", ACTOR=b"HARGA001", MAP=b"HARMAP01",
                            SYNC_REQUEST=b"HASCMD01", SYNC_RESPONSE=b"HASYNR01",
                            REF_REQUEST=b"HARREF01", REF_RESPONSE=b"HARRES01").items():
        constants[name] = int.from_bytes(value, "little")
    source = root / "authoring/audit_lifetime.pseudo"
    pseudo = re.sub(r"\b(" + "|".join(constants) + r")\b",
                    lambda m: str(constants[m[0]]), source.read_text())
    policy, policy_shape = render(pseudo, "audit_lifetime")
    (native / "audit_lifetime.hepta").write_bytes(policy)
    asm = root / "authoring/audit_refs.S"
    commands = [
        ["/usr/bin/as", "--64", "-o", str(output / "refs.o"), str(asm)],
        ["/usr/bin/objcopy", "-O", "binary", "--only-section=.text",
         str(output / "refs.o"), str(output / "refs.bin")],
        ["/usr/bin/readelf", "--wide", "--relocs", "--symbols", str(output / "refs.o")],
    ]
    observed = []
    for index, command in enumerate(commands):
        raw, row = recorder.run("author-" + str(index), command, timeout=60)
        observed.append(row)
    symbols = raw.decode()
    assert "There are no relocations in this file." in symbols
    assert len([line for line in symbols.splitlines() if " UND " in line]) == 1
    code = (output / "refs.bin").read_bytes()
    positions = {}
    for name in ("entry", "end"):
        found = re.findall(r"\d+:\s+([0-9a-f]+)\s+\d+\s+\S+\s+GLOBAL\s+DEFAULT\s+1\s+audit_refs_" + name + r"\s*$", symbols, re.M)
        assert len(found) == 1
        positions[name] = int(found[0], 16)
    assert positions == dict(entry=0, end=len(code))
    magic = int.from_bytes(b"HAREMP01", "little")
    start = f"""def audit_refs_emitter(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=16 or read64(s,0)!={magic} or read64(s,8)!=1:
        return 4294967295
    if length(o)<{len(code)}:
        return 4294967294
"""
    chunks = []
    for at in range(0, len(code), 96):
        name = "emit_" + str(at)
        start += f"    {name}(o)\n"
        body = f"def {name}(o:mutbuf) -> u64:\n"
        body += "".join(f"    store(o,{i},{byte})\n" for i, byte in enumerate(code[at:at + 96], at))
        chunks.append(body + "    return 0\n")
    start += f"    return {len(code)}\n"
    read64 = """def read64(s:readbuf,at:u64) -> u64:
    return byte(s,at)|(byte(s,at+1)<<8)|(byte(s,at+2)<<16)|(byte(s,at+3)<<24)|(byte(s,at+4)<<32)|(byte(s,at+5)<<40)|(byte(s,at+6)<<48)|(byte(s,at+7)<<56)
"""
    emitter, emitter_shape = render("\n".join([start, *chunks, read64]), "audit_refs_emitter")
    (native / "audit_refs_emitter.hepta").write_bytes(emitter)
    proof = dict(schema="hepta.audit-lifetime.source-authoring.v1",
                 compiler_commit=COMPILER, target_commit=TARGET,
                 target_source=pin(original), exact_registry_owner=pin(owner),
                 controller=pin(policy), controller_shape=policy_shape,
                 controller_pseudo=pin(source.read_bytes()), constants=constants,
                 reference_emitter=pin(emitter), reference_emitter_shape=emitter_shape,
                 reference_instructions=pin(code), reference_hex=code.hex(),
                 reference_assembly=pin(asm.read_bytes()), author=pin(Path(__file__).read_bytes()),
                 commands=observed, native_or_hia_execution=0,
                 runtime_rust_required=False, runtime_python_required=False,
                 qualification_completed=False, production_activated=False,
                 public_handler_qualified=False, whole_runtime_replaced=False)
    (native / "audit_lifetime.composition.json").write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n")
    files = {}
    for path in sorted([*native.rglob("*"), root / "reference/registry.rs.txt"]):
        if path.is_file():
            name = path.relative_to(root).as_posix()
            raw = path.read_bytes()
            files[name] = pin(raw)
            print("GENERATED_FILE_BEGIN " + name)
            print(raw.decode(), end="")
            print("GENERATED_FILE_END " + name)
    (output / "AUTHORING.json").write_text(json.dumps(dict(source_files=files, native_or_hia_execution=0),
                                                     sort_keys=True, indent=2) + "\n")
    print("GENERATED_MANIFEST " + json.dumps(files, sort_keys=True))

if __name__ == "__main__":
    main()
