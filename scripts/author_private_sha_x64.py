# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author an explicitly pinned HIA scalar SHA native lowering stage.

Python is a development author only. The emitted HIA verifies the complete
base image, generates all new machine instructions, copies the base image,
and patches five explicitly bound private entries. It is not a change to B3.
"""
from pathlib import Path
import argparse
import ast
import copy
import hashlib
import json
import re
import sys

LITERALS = {
    # cmp qword [rdi+8],1184; jb rel32 (fixed after the full body is generated).
    1: bytes.fromhex("48817f08a00400000f8200000000"),
    # Save rbp,rbx,r12..r15,rsi; r15=[rdi]; copy 64 qwords state->schedule.
    2: bytes.fromhex("55534154415541564157564c8b3f4c89fe498dbf00020000b940000000f348a5"),
    # Pop result pointer, store u64 zero, restore six saved registers, xor eax,ret.
    3: bytes.fromhex("5e48c70600000000415f415e415d415c5b5d31c0c3"),
    # len >= 8 and index <= len - 8, otherwise the exact original prologue.
    4: bytes.fromhex("488b47084883f8080f82000000004883e808488b57104839c20f8700000000"),
    # Little-endian unaligned u64 load; write only the result cell's low u64.
    5: bytes.fromhex("488b0f488b0411488906c3"),
    # Little-endian unaligned u64 store; return exactly one u64 zero.
    6: bytes.fromhex("488b0f488b47204889041131c0488906c3"),
}
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CANONICAL = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def generated_source(body, binding, rounds):
    constants = {"IMAGE_BYTES": binding["image_bytes"],
        "FUNCTION_OFFSET": binding["function_offset"],
        "FRAME_MAGIC": int.from_bytes(b"HSHX6402", "little")}
    for key, function in zip(("WORD_GET_OFFSET", "WORD_PUT_OFFSET", "CODEC_GET_OFFSET", "CODEC_PUT_OFFSET"), binding["word_functions"]):
        constants[key] = function["function_offset"]
    source = re.sub(r"\b("+"|".join(constants)+r")\b", lambda m: str(constants[m[0]]), body)
    source += "\ndef image_digest_matches(w:mutbuf) -> u64:\n"
    digest = bytes.fromhex(binding["image_sha256"])
    for j in range(8):
        source += f"    if get(w, {1024+8*j}) != {int.from_bytes(digest[4*j:4*j+4], 'big')}:\n        return 0\n"
    source += "    return 1\n\ndef original_prologue_matches(i:readbuf) -> u64:\n"
    for target in [binding, *binding["word_functions"]]:
        prologue = bytes.fromhex(target["original_prologue_hex"])
        assert len(prologue) == 11
        for j, value in enumerate(prologue):
            source += f"    if byte(i, {16+target['function_offset']+j}) != {value}:\n        return 0\n"
    source += "    return 1\n\ndef literal(w:mutbuf, code:u64) -> u64:\n"
    for code, raw in LITERALS.items():
        source += f"    if code == {code}:\n"
        for j in range(0, len(raw), 8):
            part = raw[j:j+8]
            source += f"        emit_bytes(w, {int.from_bytes(part, 'little')}, {len(part)})\n"
        source += "        return 0\n"
    source += "    return 0\n\ndef round_constant(index:u64) -> u64:\n"
    def tree(start, stop, indent):
        if stop-start == 1:
            return indent+f"return {rounds[start]}\n"
        middle = (start+stop)//2
        return (indent+f"if index < {middle}:\n"+tree(start,middle,indent+"    ")
            +indent+"else:\n"+tree(middle,stop,indent+"    "))
    source += tree(0,64,"    ")
    return source


def main():
    ap = argparse.ArgumentParser()
    for name in ("hepta", "runtime", "binding", "input-image", "output"):
        ap.add_argument("--"+name, required=True, type=Path)
    args = ap.parse_args()
    args.output.mkdir(mode=0o700, exist_ok=False)
    sys.dont_write_bytecode = True
    sys.path.insert(0,str(args.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from tools.generate_hia_sha256 import ROUND
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    binding = json.loads(args.binding.read_bytes())
    image = args.input_image.read_bytes()
    assert len(image) == binding["image_bytes"] and SHA(image) == binding["image_sha256"]
    assert binding["image_sha256"] == "ab3e303b07aaab48a825627a6d743dfe8724eaf9b8d3c157127917c10be2775d"
    assert binding["compiler_commit"] == "d3e2c90173cf733e42b299d0c4274df4b593a12f"
    assert binding["compiler_sha256"] == "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
    assert binding["function"] == "f65" and binding["function_offset"] > 0
    offset, end = binding["function_offset"], binding["function_end"]
    assert 0 < offset < end <= len(image)
    assert SHA(image[offset:end]) == binding["function_image_sha256"]
    prologue = image[offset:offset+11]
    assert prologue.hex() == binding["original_prologue_hex"]
    # The copied prologue contains complete push/mov/sub instructions and no
    # PC-relative operand. Its continuation stays at the original address.
    assert prologue[:7] == bytes.fromhex("554889e54881ec")
    assert 0 < int.from_bytes(prologue[7:11],"little") <= 4096
    original_source = (args.runtime / "native/rea_asar_parser.hepta").read_bytes()
    assert SHA(original_source) == binding["source_sha256"]
    assert binding["source_sha256"] == "70c1de9a0f9511bed5379cb0ac4eb9495f53fb71b2999a6290cc0605c22d0ab6"
    original_program = assemble_program(original_source).as_dict()
    target = next(f for f in original_program["functions"] if f["name"] == binding["function"])
    assert SHA(CANONICAL(target)) == binding["function_ir_sha256"]
    assert [p["type"] for p in target["params"]] == ["mutbuf"] and target["returns"] == ["u64"]
    expected_words = [
        ("f63", "get", "ba559aa7fb5abac68a1a336071bfea4ebe7161267ad5deb3c84f68d96a38fdb0"),
        ("f64", "put", "c56087dfaf0788e5e8c22b87e73ad5ec51273cc7871bc2aac703c755d51271f1"),
        ("f75", "get", "bd0d23cbcd5136f56554be9782634f7b29cdf3b51768c2dd9039da114ee4c988"),
        ("f76", "put", "497d40a9be7c6377274846fb7b589efebb22d7ea2a80ed8311049dd747dc7310"),
    ]
    assert len(binding["word_functions"]) == len(expected_words)
    for record, (name, kind, ir_hash) in zip(binding["word_functions"], expected_words):
        assert record["function"] == name and record["kind"] == kind
        target = next(f for f in original_program["functions"] if f["name"] == name)
        assert SHA(CANONICAL(target)) == record["function_ir_sha256"] == ir_hash
        assert [p["type"] for p in target["params"]] == ["mutbuf", "u64"] + (["u64"] if kind == "put" else [])
        assert target["returns"] == ["u64"]
        offset, end = record["function_offset"], record["function_end"]
        assert 0 < offset < end <= len(image)
        assert SHA(image[offset:end]) == record["function_image_sha256"]
        prologue = image[offset:offset+11]
        assert prologue.hex() == record["original_prologue_hex"]
        assert prologue[:7] == bytes.fromhex("554889e54881ec")
        assert 0 < int.from_bytes(prologue[7:11], "little") <= 4096
    body_path = Path(__file__).with_name("private_sha_x64_source.py.txt")
    body = body_path.read_text()
    source = generated_source(body,binding,ROUND)
    nodes = ast.parse(source).body
    assert all(isinstance(n,ast.FunctionDef) for n in nodes)
    names = {node.name:"f"+str(j) for j,node in enumerate(nodes)}
    signatures = {node.name:([p.annotation.id for p in node.args.args],node.returns.id) for node in nodes}
    codec_path = args.runtime / "native/binary_codec.hepta"
    codec_raw = codec_path.read_bytes()
    assert SHA(codec_raw) == "f58ab824ecb47545f19cd1d0daded9e41fca5457110693677d84e393e3098f23"
    functions = {f["name"]:f for f in assemble_program(codec_raw).as_dict()["functions"]}
    aliases = {"sha_init":"f17","sha_compress":"f19","sha_final":"f10","get":"f21","put":"f22"}
    selected, pending = set(aliases.values()), list(aliases.values())
    while pending:
        for block in functions[pending.pop()]["blocks"]:
            for op in block["ops"]:
                if op["op"] == "call" and op["attrs"]["function"] not in selected:
                    selected.add(op["attrs"]["function"])
                    pending.append(op["attrs"]["function"])
    relocation = {name:"f"+str(len(nodes)+j) for j,name in enumerate(sorted(selected,key=lambda n:int(n[1:])))}
    imported = []
    for old,new in relocation.items():
        f = copy.deepcopy(functions[old]);f["name"] = new
        for block in f["blocks"]:
            for op in block["ops"]:
                if op["op"] == "call":
                    op["attrs"]["function"] = relocation[op["attrs"]["function"]]
        imported.append(f)
    for alias,old in aliases.items():
        names[alias] = relocation[old]
        signatures[alias] = ([p["type"] for p in functions[old]["params"]],functions[old]["returns"][0])

    class Bulk(Builder):
        def expr(self,node):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id == "copy_range":
                args = [self.expr(v) for v in node.args]
                view = args[1]
                if view[1] == "mutbuf":
                    view = self.op("borrow.read",[view],"readbuf")
                result = self.op("buffer.copy_range",[args[0],view,*(self.cast(v,"usize") for v in args[2:])])
                if args[1][1] == "mutbuf":
                    self.op("loan.end",[view])
                return result
            return super().expr(node)
    authored = []
    total = total_scalar_functions(nodes)
    for node in nodes:
        b = Bulk(node,names,signatures,total);b.statements(node.body)
        authored.append({"name":names[node.name],"params":[b.param(v) for v in b.params],
            "returns":[b.returns],"effects":["read","write","trap"],"entry":"b0","blocks":b.blocks})
    doc = compact_authoring_cfg({"schema":"hepta.hia.program.v8",
        "module":"hepta_runtime_private_sha256_scalar_x64_lowering","functions":authored+imported})
    doc["functions"] = doc["functions"][:len(authored)]+imported
    operation_count = sum(len(b["ops"]) for f in doc["functions"] for b in f["blocks"])
    assert operation_count <= 8192
    raw = render_assembly(doc).encode()
    assembled = assemble_program(raw).as_dict()
    assert assembled["functions"][len(authored):] == imported
    (args.output / "private_sha_x64_lowering.hepta").write_bytes(raw)
    (args.output / "author-input.py.txt").write_text(source)
    (args.output / "author.py").write_bytes(Path(__file__).read_bytes())
    (args.output / "source.py.txt").write_bytes(body_path.read_bytes())
    (args.output / "input-binding.json").write_bytes(args.binding.read_bytes())
    info = {"schema":"hepta.runtime.private-sha-scalar-x64-lowering.v2",
        "source_sha256":SHA(raw),"source_bytes":len(raw),"instructions":operation_count,
        "input_binding":binding,"imported_codec_sha256":SHA(codec_raw),
        "imported_relocation":relocation,"imported_original_functions":{n:SHA(CANONICAL(functions[n])) for n in selected},
        "compiler_changed":False,"base_b3_image_changed_in_place":False,
        "product_is_direct_b3_output":False,"maximum_code_bytes":32768,
        "private_abi":"One valid mutable view with disjoint argument and one-u64 result cells, as emitted by the pinned B3 callers. The view is exclusively owned during a call; arbitrary native pointers and concurrent observers are outside this private ABI.",
        "short_view_behavior":"Compression views below 1184 bytes and word accesses outside a complete in-view eight-byte range execute each function's original complete 11-byte prologue then jump to its unchanged continuation; no fast-path state access occurs first.",
        "patched_functions":[binding["function"], *[r["function"] for r in binding["word_functions"]]],
        "request_magic":"HSHX6402",
        "qualified":False,"public_route_qualified":False,"whole_runtime_qualified":False}
    (args.output / "composition.json").write_text(json.dumps(info,sort_keys=True,indent=2)+"\n")
    print(json.dumps({"source_sha256":SHA(raw),"source_bytes":len(raw),"instructions":operation_count,
        "functions":len(assembled["functions"]),"qualified":False},sort_keys=True))


if __name__ == "__main__":
    main()
