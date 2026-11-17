"""Author the fixed audit native adapter and its HIA composition packer.

This program runs only assembler/source authoring. It does not load or execute
the record owner, JSON owner, or composed callable. The complete source and
every assembler stdout/stderr is retained before a later native qualification.
"""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys

OWNER = dict(bytes=295103, sha256="3b290dab82a2c60982a7af947562a4cf7aa407e9399c0d877640354c13112664")
JSON_OWNER = dict(bytes=161260, sha256="76122331b305e654b6175a3d0a975d080815ee1cfcf542ea837d8aecdb83b2fc")


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def run(hepta, root, output):
    output.mkdir(parents=True, exist_ok=False)
    (output / "generated/native").mkdir(parents=True)
    (output / "generated/authoring").mkdir()
    source = root / "authoring/audit_record_callable.S"
    semantic_sources = {
        "imports/audit_record_io.hepta": dict(bytes=218029, sha256="6826f361511a1345b63a1604a92b89252f5405c549fe38337e88e3d8aa8338ea"),
        "imports/audit_json.hepta": dict(bytes=126320, sha256="5146e5c42028692933762ce68bd9c62d52f9760d8ce378124e3888edacb4255b"),
    }
    for name, expected in semantic_sources.items():
        assert pin((root / name).read_bytes()) == expected, name
    commands = [
        ["/usr/bin/as", "--64", "--fatal-warnings", "-o", str(output / "adapter.o"), str(source)],
        ["/usr/bin/objcopy", "-O", "binary", "--only-section=.text",
         str(output / "adapter.o"), str(output / "template.bin")],
        ["/usr/bin/readelf", "--wide", "--relocs", "--symbols", str(output / "adapter.o")],
        ["/usr/bin/objdump", "-d", "--no-show-raw-insn", str(output / "adapter.o")],
    ]
    receipts = []
    for index, command in enumerate(commands):
        completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=60,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"})
        (output / (str(index) + ".stdout")).write_bytes(completed.stdout)
        (output / (str(index) + ".stderr")).write_bytes(completed.stderr)
        receipts.append(dict(argv=command, timeout_seconds=60, exit_code=completed.returncode,
                             stdout=pin(completed.stdout), stderr=pin(completed.stderr)))
        (output / "ASSEMBLY-PROCESSES.json").write_bytes(encoded(receipts))
        if completed.returncode != 0 or completed.stderr:
            raise ValueError("fixed native adapter assembly failed: " + str(index))
    symbols = (output / "2.stdout").read_text()
    assert "There are no relocations in this file." in symbols
    assert len([line for line in symbols.splitlines() if " UND " in line]) == 1
    offsets = {}
    for name in ("entry", "initialize", "dispose", "owner", "json", "end"):
        found = re.findall(r"\d+:\s+([0-9a-f]+)\s+\d+\s+\S+\s+GLOBAL\s+DEFAULT\s+1\s+audit_record_callable_" +
                           name + r"\s*$", symbols, re.M)
        assert len(found) == 1, (name, symbols)
        offsets[name] = int(found[0], 16)
    raw = (output / "template.bin").read_bytes()
    assert offsets["entry"] == 0
    assert 0 < offsets["initialize"] < offsets["dispose"] < offsets["owner"]
    assert offsets["owner"] % 16 == 0
    assert offsets["json"] == offsets["owner"] + OWNER["bytes"]
    assert offsets["end"] == len(raw) == offsets["json"] + JSON_OWNER["bytes"]
    stub = raw[:offsets["owner"]]
    assert raw[len(stub):] == bytes(OWNER["bytes"] + JSON_OWNER["bytes"])
    (output / "adapter.bin").write_bytes(stub)

    request_bytes = 32 + OWNER["bytes"] + JSON_OWNER["bytes"]
    magic = int.from_bytes(b"HAIOPK01", "little")
    head = f"""def audit_record_callable(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!={request_bytes} or read64(s,0)!={magic} or read64(s,8)!=1 or read64(s,16)!={OWNER['bytes']} or read64(s,24)!={JSON_OWNER['bytes']}:
        return 4294967295
    if length(o)<{len(raw)}:
        return 4294967294
"""
    functions = []
    for start in range(0, len(stub), 512):
        name = "literal_" + str(start)
        head += "    " + name + "(o)\n"
        body = "def " + name + "(o:mutbuf) -> u64:\n"
        for at in range(start, min(start + 512, len(stub)), 8):
            word = int.from_bytes(stub[at:at + 8], "little")
            assert len(stub[at:at + 8]) == 8
            body += f"    put64(o,{at},{word})\n"
        functions.append(body + "    return 0\n")
    head += f"""    at=0
    while at<{OWNER['bytes']}:
        store(o,{offsets['owner']}+at,byte(s,32+at))
        at=at+1
    at=0
    while at<{JSON_OWNER['bytes']}:
        store(o,{offsets['json']}+at,byte(s,{32 + OWNER['bytes']}+at))
        at=at+1
    return {len(raw)}
"""
    functions.insert(0, head)
    functions.extend([
        "def read64(s:readbuf,at:u64) -> u64:\n"
        "    return byte(s,at)|(byte(s,at+1)<<8)|(byte(s,at+2)<<16)|(byte(s,at+3)<<24)|(byte(s,at+4)<<32)|(byte(s,at+5)<<40)|(byte(s,at+6)<<48)|(byte(s,at+7)<<56)\n",
        "def put64(o:mutbuf,at:u64,value:u64) -> u64:\n" +
        "".join(f"    store(o,at+{i},(value>>{8*i})&255)\n" for i in range(8)) +
        "    return 0\n",
    ])
    pseudo = "\n".join(functions)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    nodes = ast.parse(pseudo).body
    names = {node.name: "f" + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([p.annotation.id for p in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    rows = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        rows.append(dict(name=names[node.name], params=[builder.param(p) for p in builder.params],
            returns=[builder.returns], effects=["read", "write", "trap"], entry="b0", blocks=builder.blocks))
    program = compact_authoring_cfg(dict(schema="hepta.hia.program.v8",
        module="audit_record_callable", functions=rows))
    hia = render_assembly(program).encode()
    checked = assemble_program(hia).as_dict()
    assert all(len(f["blocks"]) <= 256 for f in checked["functions"])
    instructions = sum(len(b["ops"]) for f in checked["functions"] for b in f["blocks"])
    assert instructions <= 8192
    proof = dict(schema="hepta.audit-record-callable.source.v1",
        adapter_source=pin(source.read_bytes()), author=pin(Path(__file__).read_bytes()),
        semantic_sources=semantic_sources,
        adapter=pin(stub), adapter_hex=stub.hex(), owner=OWNER, json=JSON_OWNER,
        offsets=offsets, image_bytes=len(raw), context_bytes=98304,
        packer_source=pin(hia), pseudo=pin(pseudo.encode()), functions=len(checked["functions"]),
        instructions=instructions, relocations=0, unresolved_symbols=0,
        runtime_python_required=False, runtime_rust_required=False, observer_optional=True,
        audit_policy_in_adapter=False, semantic_execution=False, qualification_pending=True,
        public_handler_qualified=False, whole_runtime_replaced=False)
    targets = {
        "native/audit_record_callable.hepta": hia,
        "native/audit_record_callable.composition.json": encoded(proof),
        "authoring/audit_record_callable.pseudo": pseudo.encode(),
    }
    for name, data in targets.items():
        (output / "generated" / name).write_bytes(data)
    result = dict(schema="hepta.audit-record-callable.authoring.v1", status="SOURCE_ONLY_PASS",
        commands=receipts, source=proof, generated={name: pin(raw) for name, raw in targets.items()},
        native_or_rust_executions=0)
    (output / "AUTHORING.json").write_bytes(encoded(result))
    for name, raw in targets.items():
        print("GENERATED_FILE_BEGIN " + name)
        print(raw.decode(), end="")
        print("GENERATED_FILE_END " + name)
    print("GENERATED_MANIFEST " + json.dumps(result["generated"], sort_keys=True))
    print(encoded(result).decode(), end="")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hepta", type=Path, required=True)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    run(a.hepta.resolve(strict=True), a.root.resolve(strict=True), a.output.absolute())
