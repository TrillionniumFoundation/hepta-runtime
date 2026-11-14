"""Author HIA ELF packers for fixed Linux syscall transports.

This build-time authoring aid does not run in the compiled runtime. The emitted
.hepta files own ELF construction, relocation and complete image copying.
The fixed ISA bytes implement only descriptor IO, framing and memory allocation.
"""
from __future__ import annotations
import argparse
import ast
from pathlib import Path
import struct
import sys

WIRE = 8 << 20
OUTPUT = 8 << 20
WORKSPACE = 32 << 20
OUT_AT = WIRE + 4096
WORK_AT = OUT_AT + OUTPUT
MAP_BYTES = WORK_AT + WORKSPACE
MAGIC = int.from_bytes(b"HIAFLT01", "little")


def stdio_template():
    code = bytearray()
    labels = {}
    branches = []
    def emit(hexadecimal): code.extend(bytes.fromhex(hexadecimal))
    def word(value): code.extend(struct.pack("<I", value))
    def label(name): labels[name] = len(code)
    def jump(op, target):
        emit(op); branches.append((len(code), target)); word(0)
    # Preserve a 16-byte-aligned stack for every kernel call. A private LF and
    # EOF flag occupy this small frame. No system/environment path is opened.
    emit("48 83 3c 24 01"); jump("0f 85", "usage")
    emit("48 83 ec 10 48 c7 04 24 0a 00 00 00 c6 44 24 08 00")
    emit("31 ff be"); word(MAP_BYTES)
    emit("ba 03 00 00 00 41 ba 22 00 00 00 49 c7 c0 ff ff ff ff 45 31 c9 b8 09 00 00 00 0f 05")
    emit("48 3d 01 f0 ff ff"); jump("0f 83", "io")
    emit("49 89 c4 45 31 ed 45 31 f6 45 31 ff")
    label("read")
    emit("31 c0 31 ff 4b 8d 34 2c ba"); word(WIRE + 1)
    emit("4c 29 ea 0f 05 48 83 f8 fc"); jump("0f 84", "read")
    emit("48 85 c0"); jump("0f 88", "io"); jump("0f 84", "eof")
    emit("49 01 c5")
    label("scan")
    emit("4d 39 ee"); jump("0f 83", "compact")
    emit("43 0f b6 04 34 3c 0a"); jump("0f 84", "line")
    emit("49 ff c6"); jump("e9", "scan")
    label("line")
    emit("4b 8d 3c 3c 4c 89 f6 4c 29 fe")
    emit("49 8d 94 24"); word(OUT_AT)
    emit("b9"); word(OUTPUT)
    emit("4d 8d 84 24"); word(WORK_AT)
    emit("41 b9"); word(WORKSPACE)
    # Calls are source/image-relative. The actual HIA packer patches this hole.
    emit("e8"); call_hole = len(code); word(0)
    emit("83 f8 fe"); jump("0f 84", "space")
    emit("3d"); word(OUTPUT); jump("0f 87", "invalid")
    emit("85 c0"); jump("0f 84", "after_line")
    emit("89 c5 49 8d 9c 24"); word(OUT_AT)
    label("write")
    emit("b8 01 00 00 00 bf 01 00 00 00 48 89 de 48 89 ea 0f 05 48 83 f8 fc")
    jump("0f 84", "write")
    emit("48 85 c0"); jump("0f 8e", "io")
    emit("48 01 c3 48 29 c5"); jump("0f 85", "write")
    label("newline")
    emit("b8 01 00 00 00 bf 01 00 00 00 48 89 e6 ba 01 00 00 00 0f 05 48 83 f8 fc")
    jump("0f 84", "newline")
    emit("48 83 f8 01"); jump("0f 85", "io")
    label("after_line")
    emit("80 7c 24 08 00"); jump("0f 85", "success")
    emit("49 ff c6 4d 89 f7"); jump("e9", "scan")
    label("compact")
    emit("4d 29 fd 49 81 fd"); word(WIRE); jump("0f 87", "space")
    emit("4d 85 ff"); jump("0f 84", "read")
    emit("4c 89 e7 4b 8d 34 3c 4c 89 e9 fc f3 a4 45 31 ff 4d 89 ee")
    jump("e9", "read")
    label("eof")
    emit("4d 85 ed"); jump("0f 84", "success")
    emit("c6 44 24 08 01 4d 89 ee 45 31 ff"); jump("e9", "line")
    for name, status in (("success", 0), ("invalid", 2), ("space", 3), ("io", 4), ("usage", 64)):
        label(name); emit("bf"); word(status); jump("e9", "exit")
    label("exit"); emit("b8 3c 00 00 00 0f 05 0f 0b")
    for at, target in branches:
        struct.pack_into("<i", code, at, labels[target] - at - 4)
    header = (b"\x7fELF\x02\x01\x01" + bytes(9)
        + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        + struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
        + struct.pack("<IIQQQQQQ", 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    assert len(header) == 176
    return header + code, 176 + call_hole


def packer_source(prefix, hole):
    from tools.generate_hia_elf_linker import SOURCE as HELPERS
    source = f'''def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 17 or length(s) > 1048576:
        return 4294967295
    if uint(s, 0, 8) != {MAGIC}:
        return 4294967295
    image = uint(s, 8, 8)
    if image != length(s) - 16:
        return 4294967295
    size = {len(prefix)} + image
    if size > 1048576 or length(o) < size:
        return 4294967294
'''
    for at in range(0, len(prefix), 8):
        part = prefix[at:at+8]
        source += f'    write(o, {at}, {int.from_bytes(part,"little")}, {len(part)})\n'
    source += f'''    write(o, 96, size, 8)
    write(o, 104, size, 8)
    write(o, {hole}, {len(prefix)-hole-4}, 4)
    copy_bytes(s, o, 16, {len(prefix)}, image)
    return size
'''
    return source + HELPERS[HELPERS.index("\ndef uint("):]


def document(source, module):
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    nodes = ast.parse(source).body
    names = {node.name: "f" + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total_scalar_functions(nodes))
        builder.statements(node.body)
        functions.append({"name": names[node.name], "params": [builder.param(p) for p in builder.params],
            "returns": [builder.returns], "effects": ["read", "write", "trap"],
            "entry": "b0", "blocks": builder.blocks})
    return compact_authoring_cfg({"schema": "hepta.hia.program.v8", "module": module, "functions": functions})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "native")
    args = parser.parse_args()
    sys.path.insert(0, str(args.hepta.resolve()))
    sys.dont_write_bytecode = True
    from hepta.hia_agent_assembly import render_assembly
    from tools.generate_hia_native_filter import document as filter_document
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "filter_packer.hepta").write_text(render_assembly(filter_document(
        output_bytes=OUTPUT, workspace_bytes=WORKSPACE, module="runtime_filter_packer")))
    prefix, hole = stdio_template()
    (args.output / "stdio_packer.hepta").write_text(render_assembly(document(packer_source(prefix, hole), "runtime_stdio_packer")))
    print("Generated exact HIA filter and persistent stdio packer sources")


if __name__ == "__main__":
    main()
