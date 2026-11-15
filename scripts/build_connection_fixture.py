#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Pack three fixed HIA images into an actual syscall-only SDK transport fixture.

The last image is explicitly a test implementation of unoverridden SDK methods.
This executable does not claim any original runtime tool handler migration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
MEMBERS = (
    ("message", "sdk_message", "serde-json.v1"),
    ("connection", "sdk_connection", "history.v1"),
    ("fixture", "sdk_default_fixture", "history.v1"),
)
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def make_packer(prefix: bytes, holes: list[int], helpers: str) -> str:
    source = "def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n"
    source += "    if length(s) < 35 or length(s) > 8388608:\n        return 4294967295\n"
    source += f"    if uint(s, 0, 8) != {int.from_bytes(b'HRCNPK01', 'little')}:\n        return 4294967295\n"
    for i in range(3):
        source += f"    n{i} = uint(s, {8 + i * 8}, 8)\n    if n{i} == 0 or n{i} > 1048576:\n        return 4294967295\n"
    source += "    total = n0 + n1 + n2\n    if length(s) != 32 + total:\n        return 4294967295\n"
    source += f"    size = {len(prefix)} + total\n    if size > 8388608 or length(o) < size:\n        return 4294967294\n"
    source += "    write_prefix(o)\n    write(o, 96, size, 8)\n    write(o, 104, size, 8)\n"
    source += f"    at = {len(prefix)}\n    pos = 32\n"
    for i, hole in enumerate(holes):
        source += f"    write(o, {hole}, at - {hole + 4}, 4)\n    copy_bytes(s, o, pos, at, n{i})\n    at = at + n{i}\n    pos = pos + n{i}\n"
    source += "    return size\n\ndef write_prefix(o:mutbuf) -> u64:\n"
    chunks = [list(range(at, min(at + 1024, len(prefix)), 8)) for at in range(0, len(prefix), 1024)]
    for i in range(len(chunks)):
        source += f"    prefix_chunk_{i}(o)\n"
    source += "    return 0\n"
    for i, chunk in enumerate(chunks):
        source += f"\ndef prefix_chunk_{i}(o:mutbuf) -> u64:\n"
        for at in chunk:
            raw = prefix[at:at + 8]
            source += f"    write(o, {at}, {int.from_bytes(raw, 'little')}, {len(raw)})\n"
        source += "    return 0\n"
    return source + helpers[helpers.index("\ndef uint("):]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, default=ROOT / "build")
    parser.add_argument("--name", required=True)
    parser.add_argument("--author-packer", action="store_true")
    for name, _, _ in MEMBERS:
        parser.add_argument("--" + name + "-manifest", type=Path, required=True)
    args = parser.parse_args()
    runtime = args.runtime.resolve(strict=True)
    sys.path.insert(0, str(runtime / "scripts"))
    sys.path.insert(1, str(args.hepta.resolve(strict=True)))
    from hia_native_build import NativeBuild
    from hia_native_loader import NativeModule
    from generate_hia_transport import document
    from hepta.hia_agent_assembly import render_assembly
    from tools.generate_hia_elf_linker import SOURCE as HELPERS

    build = NativeBuild(args.hepta, args.build_root)
    build.bootstrap()
    work = args.build_root / (args.name + "-elf")
    work.mkdir(mode=0o700)
    records: list[dict] = []

    def run(name: str, command: list[str]) -> bytes:
        begin = time.monotonic()
        try:
            process = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            out, err, code, timeout = process.stdout, process.stderr, process.returncode, False
        except subprocess.TimeoutExpired as error:
            out, err, code, timeout = error.stdout or b"", error.stderr or b"", None, True
        (work / (name + ".stdout")).write_bytes(out)
        (work / (name + ".stderr")).write_bytes(err)
        records.append(dict(name=name, command=command, cwd=str(ROOT), exit_code=code,
                            timed_out=timeout, timeout_seconds=30, elapsed_seconds=time.monotonic() - begin,
                            stdout_bytes=len(out), stdout_sha256=sha(out), stderr_bytes=len(err), stderr_sha256=sha(err)))
        (work / "processes.json").write_text(json.dumps(records, sort_keys=True, indent=2) + "\n")
        if timeout or code:
            raise RuntimeError("fixed adapter build command failed: " + name)
        return out

    members, images = [], []
    for index, (name, source_name, profile) in enumerate(MEMBERS):
        path = getattr(args, name + "_manifest").resolve(strict=True)
        metadata = json.loads(path.read_bytes())
        source = (path.parent / metadata["source"]).read_bytes()
        image = (path.parent / metadata["image"]).read_bytes()
        if (sha(source) != metadata["source_sha256"] or sha(image) != metadata["image_sha256"]
                or source != (ROOT / "native" / (source_name + ".hepta")).read_bytes()
                or metadata["compiler_commit"] != build.identity["commit"]
                or metadata["compiler_sha256"] != build.compiler_sha256
                or metadata.get("buffer_profile", "standard") != profile):
            raise ValueError("fixed member/source/profile changed: " + name)
        members.append(dict(id=index, name=name, source="native/" + source_name + ".hepta",
                            manifest=str(path), manifest_sha256=sha(path.read_bytes()), source_sha256=sha(source),
                            image_sha256=sha(image), image_bytes=len(image), buffer_profile=profile,
                            input_capacity=metadata["input_capacity"], output_capacity=metadata["output_capacity"],
                            workspace_capacity=metadata["workspace_capacity"]))
        images.append(image)
    assembly_path = ROOT / "scripts/sdk_connection_adapter.S"
    assembly = assembly_path.read_bytes()
    (work / "adapter.S").write_bytes(assembly)
    run("assemble", ["as", "--64", str(work / "adapter.S"), "-o", str(work / "adapter.o")])
    relocations = run("relocations", ["readelf", "-r", str(work / "adapter.o")])
    if b"There are no relocations" not in relocations:
        raise ValueError("unresolved adapter relocations")
    run("objcopy", ["objcopy", "-O", "binary", "--only-section=.text", str(work / "adapter.o"), str(work / "adapter.bin")])
    symbols = run("symbols", ["nm", "-n", str(work / "adapter.o")]).decode()
    holes = []
    for name, _, _ in MEMBERS:
        match = re.search(r"^([0-9a-f]+) T " + name + r"_call_displacement$", symbols, re.M)
        if match is None:
            raise ValueError("missing fixed call hole: " + name)
        holes.append(176 + int(match[1], 16))
    header = (b"\x7fELF\x02\x01\x01" + bytes(9)
              + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack("<IIQQQQQQ", 0x6474E551, 6, 0, 0, 0, 0, 0, 16))
    prefix = header + (work / "adapter.bin").read_bytes()
    if any(prefix[hole - 1:hole + 4] != b"\xe8\0\0\0\0" for hole in holes):
        raise ValueError("fixed call bytes differ")
    authoring = make_packer(prefix, holes, HELPERS)
    raw = render_assembly(document(authoring, "sdk_connection_fixture_packer")).encode()
    packer = ROOT / "native/sdk_connection_packer.hepta"
    if args.author_packer:
        if packer.exists():
            raise FileExistsError("authoring never overwrites a frozen packer")
        packer.write_bytes(raw)
        (ROOT / "scripts/sdk_connection_packer_authoring.txt").write_text(authoring)
    if packer.read_bytes() != raw:
        raise ValueError("frozen HIA packer differs from fixed adapter")
    packer_manifest = build.compile(args.name + "-packer", packer, standalone=None)
    frame = b"HRCNPK01" + b"".join(struct.pack("<Q", len(image)) for image in images) + b"".join(images)
    with NativeModule(packer_manifest, manifest_sha256=sha(packer_manifest.read_bytes())) as module:
        elf = module.invoke(frame, output_capacity=len(prefix) + sum(map(len, images)), workspace_capacity=4096)
    packing_receipt = {"schema": "hepta.sdk-connection.actual-packer-call.v1", "status": "returned",
                       "result_u32": len(elf), "input_bytes": len(frame), "input_sha256": sha(frame),
                       "output_bytes": len(elf), "output_sha256": sha(elf),
                       "packer_manifest_sha256": sha(packer_manifest.read_bytes()),
                       "source_and_canary_guards_checked": True}
    (work / "pack.result.json").write_text(json.dumps(packing_receipt, sort_keys=True, indent=2) + "\n")
    expected = bytearray(prefix)
    struct.pack_into("<QQ", expected, 96, len(elf), len(elf))
    at = len(prefix)
    for image, hole, member in zip(images, holes, members):
        if elf[at:at + len(image)] != image:
            raise ValueError("embedded native image differs")
        struct.pack_into("<i", expected, hole, at - hole - 4)
        member.update(offset=at, call_displacement_offset=hole)
        at += len(image)
    if at != len(elf) or elf[:len(prefix)] != expected:
        raise ValueError("fixed prefix or complete image binding differs")
    binary = work / "sdk-connection-fixture.elf"
    binary.write_bytes(elf)
    binary.chmod(0o700)
    (work / "pack.input.bin").write_bytes(frame)
    build._recheck()
    for member in members:
        path = Path(member["manifest"])
        metadata = json.loads(path.read_bytes())
        if (sha(path.read_bytes()) != member["manifest_sha256"]
                or sha((path.parent / metadata["image"]).read_bytes()) != member["image_sha256"]
                or sha((ROOT / member["source"]).read_bytes()) != member["source_sha256"]):
            raise ValueError("member changed during build")
    if assembly_path.read_bytes() != assembly:
        raise ValueError("adapter changed during build")
    result = dict(schema="hepta.sdk-connection.native-fixture.v1", members=members,
                  compiler_commit=build.identity["commit"], compiler_sha256=build.compiler_sha256,
                  executable=binary.name, elf_sha256=sha(elf), elf_bytes=len(elf),
                  adapter_source="scripts/sdk_connection_adapter.S", adapter_source_sha256=sha(assembly),
                  prefix_bytes=len(prefix), prefix_sha256=sha(prefix), pack_input_sha256=sha(frame),
                  packer_source="native/sdk_connection_packer.hepta", packer_source_sha256=sha(raw),
                  packer_manifest=str(packer_manifest.resolve()), packer_manifest_sha256=sha(packer_manifest.read_bytes()),
                  builder_source_sha256=sha(Path(__file__).read_bytes()),
                  generic_build_sha256=sha((runtime / "scripts/hia_native_build.py").read_bytes()),
                  generic_loader_sha256=sha((runtime / "scripts/hia_native_loader.py").read_bytes()),
                  call_order=["message", "connection", "fixture"], raw_frame_limit=8 << 20,
                  production_runtime_handlers=False, test_fixture_only=True, fresh_cold_qualified=False)
    manifest = work / "manifest.json"
    manifest.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(dict(manifest=str(manifest.resolve()), elf_sha256=sha(elf), elf_bytes=len(elf)), sort_keys=True))


if __name__ == "__main__":
    main()
