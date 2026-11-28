#!/usr/bin/env python3
"""Reproduce a fixed ELF prefix and author its ordinary HIA packer."""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import subprocess
import sys
import time

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
PIN = lambda raw: {"bytes": len(raw), "sha256": SHA(raw)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = args.output.absolute()
    out.mkdir(parents=True, exist_ok=False)
    source = root / "native_boundary/local_batch_body_fixture.S"
    exported = (root / "native_boundary/local_batch_body_callable.S").read_bytes()
    raw = source.read_bytes()
    assert raw.count(exported) == 1
    processes = []

    def run(name, argv):
        begin = time.monotonic()
        result = subprocess.run(argv, cwd=out, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        (out / (name + ".stdout")).write_bytes(result.stdout)
        (out / (name + ".stderr")).write_bytes(result.stderr)
        processes.append({"name": name, "argv": argv, "cwd": str(out), "returncode": result.returncode,
            "timeout_seconds": 30, "elapsed_seconds": time.monotonic() - begin,
            "stdout": PIN(result.stdout), "stderr": PIN(result.stderr)})
        (out / "processes.json").write_text(json.dumps(processes, sort_keys=True, indent=2) + "\n")
        assert result.returncode == 0, (name, result.stderr.decode(errors="replace"))
        return result.stdout

    run("assemble", ["as", "--64", "-o", "fixture.o", str(source)])
    run("link", ["ld", "-nostdlib", "-Ttext=0", "-e", "_start", "-o", "fixture-code.elf", "fixture.o"])
    run("image", ["objcopy", "-O", "binary", "--only-section=.text", "fixture-code.elf", "fixture.bin"])
    relocation = run("relocations", ["readelf", "-rW", "fixture-code.elf"])
    assert b"There are no relocations in this file." in relocation
    symbol_bytes = run("symbols", ["nm", "-n", "--defined-only", "fixture-code.elf"])
    symbols = {line.split()[2]: int(line.split()[0], 16) for line in symbol_bytes.decode().splitlines()}
    assert symbols["_start"] == 0
    code = (out / "fixture.bin").read_bytes()
    assert symbols["images"] == len(code)
    assert symbols["image_table"] + 112 == len(code)
    header = (root / "retained/elf-header.bin").read_bytes()
    assert PIN(header) == {"bytes": 176, "sha256": "927f94d195b14ecd06706963656a95b543ac2da671ab450fbc34a8d6401b5938"}
    prefix = header + code
    table_at = 176 + symbols["image_table"]
    assert prefix[96:112] == bytes(16) and prefix[table_at:] == bytes(112)
    assert len(prefix) % 8 == 0
    (out / "batch_fixture_prefix.bin").write_bytes(prefix)
    chunk_names = []
    chunks = []
    for index, start in enumerate(range(0, len(prefix), 2048)):
        name = "emit_" + str(index)
        chunk_names.append(name)
        lines = [f"def {name}(o: mutbuf) -> u64:"]
        for offset in range(start, min(start + 2048, len(prefix)), 8):
            value = int.from_bytes(prefix[offset:offset + 8], "little")
            lines.append(f"    put(o, {offset}, {value})")
        lines.append("    return 0")
        chunks.append("\n".join(lines))
    magic = int.from_bytes(b"HLBBPX01", "little")
    body = f'''def pack(s: readbuf, o: mutbuf, w: mutbuf) -> u32:
    if length(s) < 134 or load(s, 0) != {magic}:
        return 4294967295
    total = 0
    i = 0
    while i < 14:
        n = load(s, 8 + i * 8)
        if n == 0 or n > 1048576:
            return 4294967295
        total = total + n
        i = i + 1
    if total != length(s) - 120:
        return 4294967295
    size = {len(prefix)} + total
    if length(o) < size:
        return 4294967294
'''
    body += "".join("    " + name + "(o)\n" for name in chunk_names)
    body += f'''    put(o, 96, size)
    put(o, 104, size)
    copy_range(o, s, {table_at}, 8, 112)
    copy_range(o, s, {len(prefix)}, 120, total)
    return size
'''
    body += "\n\n" + "\n\n".join(chunks)
    body += '''

def load(s: readbuf, at: u64) -> u64:
    value = 0
    i = 0
    while i < 8:
        value = value | (byte(s, at + i) << (i * 8))
        i = i + 1
    return value

def put(o: mutbuf, at: u64, value: u64) -> u64:
    i = 0
    while i < 8:
        store(o, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0
'''
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly

    class BulkBuilder(Builder):
        def expr(self, node):
            if isinstance(node, ast.Call) and node.func.id == "copy_range":
                dst, src, at, start, count = [self.expr(arg) for arg in node.args]
                self.op("buffer.copy_range", [dst, src, *[self.cast(n, "usize") for n in (at, start, count)]])
                return None
            return super().expr(node)

    nodes = ast.parse(body).body
    names = {node.name: "f" + str(i) for i, node in enumerate(nodes)}
    signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = BulkBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({"name": names[node.name], "params": [builder.param(v) for v in builder.params],
            "returns": [builder.returns], "effects": ["read", "write", "trap"], "entry": "b0", "blocks": builder.blocks})
    document = compact_authoring_cfg({"schema": "hepta.hia.program.v8", "module": "hepta_rebuilt_batch_callable_fixture_packer", "functions": functions})
    generated = render_assembly(document).encode()
    assert assemble_program(generated).as_dict() == document
    stats = {"functions": len(document["functions"]), "blocks": sum(len(f["blocks"]) for f in document["functions"]),
        "operations": sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"])}
    assert stats["functions"] <= 128 and stats["blocks"] <= 1536 and stats["operations"] <= 8192
    assert source.read_bytes() == raw
    (out / "batch_fixture_packer.hepta").write_bytes(generated)
    proof = {"schema": "hepta.runtime.rebuilt-batch-fixture-pack-author.v1", "fixture": PIN(raw),
        "callable": PIN(exported), "prefix": PIN(prefix), "table_offset": table_at,
        "packer": PIN(generated), "assembler_processes": processes, "stats": stats,
        "actual_fixed_images": 14, "entry_offset": 176, "external_relocations": 0,
        "native_packer_executed": False, "semantic_qualification": False}
    (out / "fixture-pack-proof.json").write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n")
    print(json.dumps({key: proof[key] for key in ("prefix", "table_offset", "packer", "stats")}, sort_keys=True))


if __name__ == "__main__":
    main()
