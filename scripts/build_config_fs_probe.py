"""Development build of the actual HIA descriptor owner and static OS probe."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, default=ROOT / "build")
    parser.add_argument("--name", default="config-fs-v2")
    args = parser.parse_args()
    runtime = args.runtime.resolve(strict=True)
    sys.path.insert(0, str(runtime / "scripts"))
    sys.path.insert(1, str(args.hepta.resolve(strict=True)))
    from hia_native_build import NativeBuild
    from hia_native_loader import NativeModule
    build = NativeBuild(args.hepta, args.build_root)
    manifest = build.compile(args.name, ROOT / "native/config_fs.hepta", standalone=None)
    work = args.build_root / (args.name + "-elf")
    work.mkdir(mode=0o700)
    assembly = ROOT / "scripts/config_fs_adapter.S"
    subprocess.run(["as", "--64", str(assembly), "-o", str(work / "adapter.o")], check=True)
    relocs = subprocess.run(["readelf", "-r", str(work / "adapter.o")], check=True, capture_output=True).stdout
    if b"There are no relocations" not in relocs:
        raise ValueError("adapter contains external or unresolved relocations")
    subprocess.run(["objcopy", "-O", "binary", "--only-section=.text", str(work / "adapter.o"), str(work / "adapter.bin")], check=True)
    symbols = subprocess.run(["nm", "-n", str(work / "adapter.o")], check=True, capture_output=True, text=True).stdout
    match = re.search(r"^([0-9a-f]+) T native_call_displacement$", symbols, re.M)
    if match is None:
        raise ValueError("missing unique native call relocation")
    hole = 176 + int(match[1], 16)
    code = (work / "adapter.bin").read_bytes()
    header = (b"\x7fELF\x02\x01\x01" + bytes(9)
        + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
        + struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
        + struct.pack("<IIQQQQQQ", 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    assert len(header) == 176
    prefix = header + code
    if prefix[hole - 1:hole + 4] != b"\xe8\0\0\0\0":
        raise ValueError("adapter call hole differs")
    transport = load("fence_transport_authoring", runtime / "scripts/generate_hia_transport.py")
    from hepta.hia_agent_assembly import render_assembly
    packer_source = render_assembly(transport.document(transport.packer_source(prefix, hole), "config_fs_packer")).encode()
    packer_path = ROOT / "native/config_fs_packer.hepta"
    if packer_path.read_bytes()!=packer_source:
        raise ValueError("frozen HIA filesystem packer differs")
    packer_manifest = build.compile(args.name + "-packer", packer_path, standalone=None)
    module = json.loads(manifest.read_bytes())
    image = (manifest.parent / module["image"]).read_bytes()
    frame = b"HIAFLT01" + struct.pack("<Q", len(image)) + image
    with NativeModule(packer_manifest, manifest_sha256=SHA(packer_manifest.read_bytes())) as packer:
        elf = packer.invoke(frame, output_capacity=len(prefix) + len(image), workspace_capacity=4096)
    if (elf[len(prefix):] != image or len(elf) != len(prefix) + len(image)
        or int.from_bytes(elf[hole:hole + 4], "little", signed=True) != len(prefix) - hole - 4
        or struct.unpack_from("<QQ", elf, 96) != (len(elf), len(elf))):
        raise ValueError("actual HIA-packed ELF differs from exact source image")
    expected_prefix = bytearray(prefix)
    struct.pack_into("<QQ", expected_prefix, 96, len(elf), len(elf))
    struct.pack_into("<i", expected_prefix, hole, len(prefix) - hole - 4)
    if elf[:len(prefix)] != expected_prefix:
        raise ValueError("actual HIA-packed adapter differs")
    executable = work / "config-fs.elf"
    executable.write_bytes(elf)
    executable.chmod(0o700)
    build._recheck()
    result = {"schema": "hepta.runtime.config-fs-probe.v1", "compiler_commit": module["compiler_commit"],
              "compiler_sha256": module["compiler_sha256"], "module_manifest": str(manifest.resolve()),
              "module_manifest_sha256": SHA(manifest.read_bytes()), "source_sha256": module["source_sha256"],
              "image_sha256": module["image_sha256"], "packer_manifest": str(packer_manifest.resolve()),
              "packer_manifest_sha256": SHA(packer_manifest.read_bytes()), "packer_source_sha256": SHA(packer_source),
              "adapter_source_sha256": SHA(assembly.read_bytes()), "prefix_bytes": len(prefix),
              "prefix_sha256": SHA(prefix), "call_displacement_offset": hole,
              "pack_input_sha256": SHA(frame), "executable": executable.name,
              "elf_sha256": SHA(elf), "elf_bytes": len(elf),
              "complete_config_owner": False, "fresh_cold_qualified": False}
    (work / "manifest.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"manifest": str((work / "manifest.json").resolve()), **result}, sort_keys=True))


if __name__ == "__main__":
    main()
