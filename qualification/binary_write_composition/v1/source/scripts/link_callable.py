#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual fixed HIA linker and image-packer composition of the parent owner."""
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "parent/dependency/scripts"))
from hia_native_loader import NativeModule

IMAGES = ("parent", "body", "metadata", "codec", "stat", "error", "publish", "read", "base64", "entropy", "adapter", "planner")
PATCHES = (("binary_parent_owner_body_call_displacement", "parent"),
           ("binary_write_body_body_call_displacement", "body"),
           ("binary_write_body_stat_call_displacement", "stat"),
           ("binary_write_body_codec_call_displacement", "codec"),
           ("binary_write_body_base64_call_displacement", "base64"),
           ("publish_at_body_call_displacement", "publish"),
           ("publish_at_stat_call_displacement", "stat"),
           ("binary_read_body_body_call_displacement", "read"),
           ("binary_read_body_codec_call_displacement", "codec"),
           ("binary_read_body_stat_call_displacement", "stat"),
           ("file_metadata_body_call_displacement", "metadata"),
           ("file_metadata_codec_call_displacement", "codec"),
           ("binary_entropy_body_call_displacement", "entropy"),
           ("binary_write_body_error_call_displacement", "error"),
           ("binary_write_composition_adapter_call_displacement", "adapter"),
           ("binary_write_composition_planner_call_displacement", "planner"))
ASM = tuple("parent/dependency/asm/" + name + ".S" for name in (
    "binary_write_body_callable", "publish_at_callable", "binary_read_body_callable",
    "file_metadata_callable", "binary_entropy_callable", "process_orphans")) + (
    "parent/asm/binary_parent_owner_callable.S", "asm/binary_write_composition_callable.S",
    "asm/binary_write_composition_fixture.S")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pin(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def flattened(source):
    original = "\n".join((source / name).read_text() for name in ASM)
    value = original
    names = re.findall(r"^\.global ([A-Za-z_][A-Za-z_0-9]*)$", value, re.M)
    require(len(names) == len(set(names)) and names.count("_start") == 1, "global declarations")
    for name in names:
        if name == "_start":
            continue
        alias = name + "_flat"
        require("\n" + alias + ":" not in value, "existing mechanical alias")
        value = value.replace("\n" + name + ":", "\n" + name + ":\n" + alias + ":")
        value = re.sub(r"\b(call|jmp) " + re.escape(name) + r"\b", lambda m: m[1] + " " + alias, value)
        value = value.replace("[rip + " + name + "]", "[rip + " + alias + "]")
    restored = value
    for name in reversed(names):
        if name == "_start":
            continue
        alias = name + "_flat"
        restored = restored.replace("\n" + alias + ":", "")
        restored = re.sub(r"\b(call|jmp) " + re.escape(alias) + r"\b", lambda m: m[1] + " " + name, restored)
        restored = restored.replace("[rip + " + alias + "]", "[rip + " + name + "]")
    require(restored == original, "complete mechanical label inverse")
    return value


def object_layout(raw):
    require(raw[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", raw, 16)[0] == 1, "ELF relocatable")
    at = struct.unpack_from("<Q", raw, 40)[0]
    count = struct.unpack_from("<H", raw, 60)[0]
    sections = [struct.unpack_from("<IIQQQQIIQQ", raw, at + i * 64) for i in range(count)]
    names = sections[struct.unpack_from("<H", raw, 62)[0]]
    strings = raw[names[4]:names[4] + names[5]]
    labels = [strings[h[0]:strings.index(0, h[0])].decode() for h in sections]
    index = labels.index(".text")
    section = sections[index]
    symbols = {}
    require(not any(h[2] & 2 and h[5] and i != index for i, h in enumerate(sections)), "extra allocated section")
    require(not any(h[1] in (4, 9) and h[5] for h in sections), "unresolved ELF relocation")
    for header in sections:
        if header[1] != 2:
            continue
        strings_section = sections[header[6]]
        names = raw[strings_section[4]:strings_section[4] + strings_section[5]]
        for offset in range(header[4], header[4] + header[5], 24):
            name, info, other, owner, value, size = struct.unpack_from("<IBBHQQ", raw, offset)
            if owner == index:
                symbols[names[name:names.index(0, name)].decode()] = value
    return raw[section[4]:section[4] + section[5]], symbols


def process(output, name, argv):
    start = time.monotonic_ns()
    record = dict(argv=[str(x) for x in argv], limit_seconds=30, timed_out=False,
                  locale={"LC_ALL": "C", "LANG": "C"})
    environment = dict(os.environ, **record["locale"])
    with (output / (name + ".stdout")).open("xb") as out, (output / (name + ".stderr")).open("xb") as err:
        try:
            child = subprocess.run(record["argv"], stdout=out, stderr=err, timeout=30, check=False, env=environment)
            record["returncode"] = child.returncode
        except subprocess.TimeoutExpired:
            record.update(returncode=None, timed_out=True)
    record["elapsed_ns"] = time.monotonic_ns() - start
    record["streams"] = {suffix: pin(output / (name + "." + suffix)) for suffix in ("stdout", "stderr")}
    (output / (name + ".json")).write_bytes(encoded(record))
    require(record["returncode"] == 0 and not record["timed_out"], "mechanical process failed: " + name)
    require((output / (name + ".stderr")).read_bytes() == b"", "mechanical process stderr: " + name)
    return record


def build(images_root, output):
    require(not output.exists(), "fresh link directory required")
    output.mkdir(parents=True)
    identities = {name: pin(ROOT / name) for name in ASM}
    images_record = json.loads((images_root / "IMAGES.json").read_bytes())
    members = images_record["members"]
    require(set(members) == set(IMAGES) | {"linker", "packer"}, "complete fourteen-member actual build")
    images = []
    for name in IMAGES:
        row = members[name]
        manifest = images_root / row["manifest"]
        metadata = json.loads(manifest.read_bytes())
        require(pin(manifest) == row["identity"] and pin(ROOT / row["source_path"]) == row["source"], "image source binding")
        path = manifest.parent / metadata["image"]
        require(pin(path) == row["image"], "actual immutable image binding")
        images.append(path.read_bytes())
    (output / "combined.S").write_text(flattened(ROOT))
    records = [process(output, "assemble", ["as", "--64", "-o", output / "bridge.o", output / "combined.S"]),
               process(output, "relocations", ["readelf", "-r", output / "bridge.o"])]
    obj = (output / "bridge.o").read_bytes()
    text, symbols = object_layout(obj)
    require(b"There are no relocations" in (output / "relocations.stdout").read_bytes(), "relocation report")
    frame = b"HIALNK01" + struct.pack("<3Q", 1, 6, 0) + b"_start" + struct.pack("<Q", len(obj)) + obj
    (output / "link.input.bin").write_bytes(frame)
    row = members["linker"]
    with NativeModule(images_root / row["manifest"], manifest_sha256=row["identity"]["sha256"]) as module:
        code, raw, workspace = module.invoke_raw(frame, output_capacity=8 << 20, workspace_capacity=32 << 20)
    (output / "link.output.bin").write_bytes(raw)
    (output / "link.workspace.bin").write_bytes(workspace)
    end = 256 + len(text)
    require(code == (end + 4095) & ~4095 and 256 < end <= code <= len(raw), "actual linked extent")
    prefix = raw[:code]
    require(prefix[256:end] == text and prefix[end:] == bytes(code - end) and raw[code:] == bytes(len(raw) - code), "complete linked text/padding")
    require(prefix[:4] == b"\x7fELF" and struct.unpack_from("<Q", prefix, 24)[0] == 4194304 + 232
            and prefix[238] == 0xe8 and 243 + struct.unpack_from("<i", prefix, 239)[0] == 256 + symbols["_start"], "actual linker entry")
    (output / "prefix.elf").write_bytes(prefix)
    patches = [(2, 256 + symbols[name], IMAGES.index(image)) for name, image in PATCHES]
    for _, at, _ in patches:
        require(prefix[at - 1:at + 4] == b"\xe9\0\0\0\0", "fixed HIA call displacement")
    frame = b"HIAIMG02" + struct.pack("<4Q", len(prefix), len(images), len(patches), 0) + prefix
    frame += b"".join(struct.pack("<Q", len(image)) for image in images)
    frame += b"".join(struct.pack("<3Q", *patch) for patch in patches) + b"".join(images)
    (output / "pack.input.bin").write_bytes(frame)
    expected = bytearray(prefix)
    positions = []
    for image in images:
        expected += bytes(-len(expected) % 16)
        positions.append(len(expected))
        expected += image
    text_end = len(expected)
    expected += bytes(-len(expected) % 4096)
    for _, at, index in patches:
        struct.pack_into("<i", expected, at, positions[index] - at - 4)
    struct.pack_into("<QQ", expected, 96, text_end, text_end)
    struct.pack_into("<QQQ", expected, 128, len(expected), 4194304 + len(expected), 4194304 + len(expected))
    row = members["packer"]
    with NativeModule(images_root / row["manifest"], manifest_sha256=row["identity"]["sha256"]) as module:
        pack_code, raw, workspace = module.invoke_raw(frame, output_capacity=32 + len(expected), workspace_capacity=4096,
                                                     output_fill=0xb3, workspace_fill=0xc7)
    (output / "pack.output.bin").write_bytes(raw)
    (output / "pack.workspace.bin").write_bytes(workspace)
    require(pack_code == 32 and raw == b"HIAIMR02" + struct.pack("<3Q", 0, len(expected), 0) + expected,
            "actual HIA image pack differs from independently derived fixed layout")
    elf = output / "binary-write-composition.elf"
    elf.write_bytes(raw[32:])
    elf.chmod(0o500)
    require({name: pin(ROOT / name) for name in ASM} == identities, "native sources changed during composition")
    record = dict(schema="hepta.runtime.binary-write-composition-callable-build.v1", status="ACTUAL_HIA_LINK_AND_PACK_PASS",
                  images_manifest=pin(images_root / "IMAGES.json"), images_directory=str(images_root),
                  native_sources=identities, image_order=list(IMAGES), patches=patches, image_offsets=positions,
                  symbols=symbols, processes=records, linked_return=code, packer_return=pack_code,
                  artifacts={name: pin(output / name) for name in ("combined.S", "bridge.o", "link.input.bin", "link.output.bin",
                      "link.workspace.bin", "prefix.elf", "pack.input.bin", "pack.output.bin", "pack.workspace.bin")},
                  executable=pin(elf), application_executions=0, runtime_python_required=False, runtime_libc_required=False,
                  public_binary_write_registered=False, whole_runtime_replaced=False)
    (output / "BUILD.json").write_bytes(encoded(record))
    print(json.dumps(dict(status=record["status"], executable=record["executable"], images=len(IMAGES)), sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.images.resolve(strict=True), args.output.absolute())


if __name__ == "__main__":
    main()
