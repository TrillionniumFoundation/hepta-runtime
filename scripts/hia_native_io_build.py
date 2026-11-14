"""Build the isolated native read-only OS boundary through the pinned HIA compiler.

This extension adds no effect implementation to the Python loader or stable
builder. The generated ELF requires only the Linux kernel at runtime.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from hia_native_build import NativeBuild, json_bytes, write_new

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def build_io(hepta: Path, build_root: Path, *, source_root: Path = ROOT) -> Path:
    build = NativeBuild(hepta, build_root)
    compiler = build.bootstrap()
    compiler_sha = sha(compiler.read_bytes())
    sources = {kind: (source_root / "native" / ("io_" + kind + ".hepta")).read_bytes() for kind in ("policy", "packer")}
    key = sha(sources["policy"] + sources["packer"])
    destination = Path(build_root).resolve() / "io" / key
    manifest_path = destination / "manifest.json"
    if manifest_path.exists():
        metadata = json.loads(manifest_path.read_bytes())
        if metadata.get("compiler_sha256") != compiler_sha:
            raise ValueError("native IO cached compiler differs")
        for member, expected in [("policy.hepta", sha(sources["policy"])), ("packer.hepta", sha(sources["packer"])),
                                 ("native-read.elf", metadata["executable_sha256"]),
                                 ("policy.json", metadata["policy_manifest_sha256"])]:
            if sha((destination / member).read_bytes()) != expected:
                raise ValueError("native IO cached member differs: " + member)
        policy = json.loads((destination / "policy.json").read_bytes())
        if (policy.get("source") != "policy.hepta" or policy.get("image") != "policy.image.bin"
            or policy.get("compiler_sha256") != compiler_sha
            or policy.get("source_sha256") != sha(sources["policy"])
            or sha((destination / "policy.image.bin").read_bytes()) != policy.get("image_sha256")):
            raise ValueError("native IO cached policy image differs")
        build._recheck()
        return manifest_path
    modules = {}
    for kind in ("policy", "packer"):
        name = "io-" + kind + "-" + sha(sources[kind])[:16]
        module_manifest = Path(build_root).resolve() / "modules" / name / "manifest.json"
        if not module_manifest.exists():
            module_manifest = build.compile(name, source_root / "native" / ("io_" + kind + ".hepta"), standalone=None)
        metadata = json.loads(module_manifest.read_bytes())
        image = module_manifest.parent / metadata["image"]
        if metadata["source_sha256"] != sha(sources[kind]) or metadata["compiler_sha256"] != compiler_sha or sha(image.read_bytes()) != metadata["image_sha256"]:
            raise ValueError("native IO module identity differs")
        modules[kind] = (metadata, image)
    destination.mkdir(parents=True, mode=0o700)
    owner, owner_image = modules["policy"]
    packer, packer_image = modules["packer"]
    frame = b"HIAIOP01" + struct.pack("<Q", owner_image.stat().st_size) + owner_image.read_bytes()
    from tools.qualify_hia_selfhost import invoke
    from tools.qualify_hia_selfhost_cli import inspect_executable
    receipt, output = invoke(destination, "pack", packer_image, frame)
    count = receipt.get("core_u32")
    if (receipt.get("status") != "returned" or type(receipt.get("abi_status")) is not int or receipt["abi_status"] != 0
            or type(count) is not int or not 0 < count <= min(1 << 20, len(output))
            or receipt.get("result_u64") != count or receipt.get("source_unchanged") is not True
            or receipt.get("input_sha256") != sha(frame) or receipt.get("input_bytes") != len(frame)
            or receipt.get("artifact_sha256") != sha(packer_image.read_bytes())
            or receipt.get("output_sha256") != sha(output) or receipt.get("forbidden_compiler_modules_loaded") != []):
        raise ValueError("HIA IO packer receipt differs")
    executable = output[:count]
    inspection = inspect_executable(executable)
    owner = dict(owner, source="policy.hepta", image="policy.image.bin")
    owner_raw = json_bytes(owner)
    write_new(destination / "policy.hepta", sources["policy"])
    write_new(destination / "policy.image.bin", owner_image.read_bytes())
    write_new(destination / "policy.json", owner_raw)
    write_new(destination / "packer.hepta", sources["packer"])
    write_new(destination / "native-read.elf", executable, 0o500)
    metadata = {"schema": "hepta.runtime.native-io.v1", "target": "linux-x86_64",
        "transport": "length-prefixed-binary", "executable": "native-read.elf", "executable_sha256": sha(executable),
        "policy_manifest": "policy.json", "policy_manifest_sha256": sha(owner_raw),
        "policy_source_sha256": sha(sources["policy"]), "packer_source_sha256": sha(sources["packer"]),
        "packer_image_sha256": packer["image_sha256"], "compiler_commit": owner["compiler_commit"],
        "compiler_sha256": compiler_sha, "runtime_python_required": False, "runtime_libc_required": False,
        "registered_mcp_tool": False, "whole_runtime_replaced": False, "inspection": inspection,
        "pack_receipt": receipt}
    if any((source_root / "native" / ("io_" + kind + ".hepta")).read_bytes() != raw for kind, raw in sources.items()):
        raise ValueError("native IO source changed during build")
    build._recheck()
    write_new(manifest_path, json_bytes(metadata))
    return manifest_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, default=os.environ.get("HIA_HEPTA_DIR"))
    parser.add_argument("--build-root", type=Path, default=os.environ.get("HIA_BUILD_ROOT"))
    args = parser.parse_args()
    if not args.hepta or not args.build_root:
        parser.error("--hepta and --build-root or their HIA environment variables are required")
    print(json.dumps({"manifest": str(build_io(args.hepta, args.build_root))}))
