"""Compile HIA entropy policy and its fixed syscall-only executable boundary.

Python drives compilation and verifies build evidence. It does not execute
entropy policy or supply entropy to the emitted native executable.
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
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_build import NativeBuild, json_bytes, write_new


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def build_entropy(hepta: Path, build_root: Path, *, source_root: Path = ROOT) -> Path:
    build = NativeBuild(hepta, build_root)
    compiler_sha = sha(build.bootstrap().read_bytes())
    sources = {kind: (source_root / "native" / ("entropy_" + kind + ".hepta")).read_bytes()
               for kind in ("policy", "packer")}
    destination = Path(build_root).resolve() / "entropy" / sha(sources["policy"] + sources["packer"])
    manifest_path = destination / "manifest.json"
    from tools.qualify_hia_selfhost_cli import inspect_executable

    def verify_completed() -> None:
        metadata = json.loads(manifest_path.read_bytes())
        expected = {"schema": "hepta.runtime.native-entropy.v2", "target": "linux-x86_64",
                    "transport": "fixed-24-byte-requests-u32-results", "compiler_sha256": compiler_sha,
                    "compiler_commit": build.identity["commit"],
                    "executable": "native-entropy.elf", "policy_manifest": "policy.json",
                    "packer_manifest": "packer.json", "request_bytes": 24,
                    "maximum_entropy_bytes": 128, "workspace_bytes": 1024,
                    "runtime_python_required": False, "runtime_libc_required": False,
                    "registered_mcp_tool": False, "production_activated": False,
                    "whole_runtime_replaced": False}
        if any(metadata.get(k) != v for k, v in expected.items()):
            raise ValueError("native entropy manifest contract differs")
        for kind in ("policy", "packer"):
            if metadata.get(kind + "_source_sha256") != sha(sources[kind]):
                raise ValueError("native entropy source identity differs: " + kind)
            source = destination / (kind + ".hepta")
            module_path = destination / (kind + ".json")
            module = json.loads(module_path.read_bytes())
            if (source.read_bytes() != sources[kind]
                    or sha(module_path.read_bytes()) != metadata.get(kind + "_manifest_sha256")
                    or module.get("source") != kind + ".hepta"
                    or module.get("image") != kind + ".image.bin"
                    or module.get("source_sha256") != sha(sources[kind])
                    or module.get("compiler_sha256") != compiler_sha
                    or module.get("compiler_commit") != build.identity["commit"]
                    or module.get("image_sha256") != metadata.get(kind + "_image_sha256")
                    or sha((destination / (kind + ".image.bin")).read_bytes()) != module.get("image_sha256")):
                raise ValueError("native entropy compiled source/image differs: " + kind)
        executable = (destination / metadata["executable"]).read_bytes()
        if (sha(executable) != metadata.get("executable_sha256")
                or inspect_executable(executable) != metadata.get("inspection")):
            raise ValueError("native entropy executable identity differs")
        policy_image = (destination / "policy.image.bin").read_bytes()
        frame = b"HIAENTP1" + struct.pack("<Q", len(policy_image)) + policy_image
        receipt = metadata.get("pack_receipt", {})
        count = receipt.get("core_u32")
        packed_output = (destination / "pack.output.bin").read_bytes()
        if (receipt.get("status") != "returned" or type(receipt.get("abi_status")) is not int
                or receipt["abi_status"] != 0 or type(count) is not int or count != len(executable)
                or type(receipt.get("result_u64")) is not int or receipt["result_u64"] != count
                or receipt.get("source_unchanged") is not True or receipt.get("input_bytes") != len(frame)
                or receipt.get("input_sha256") != sha(frame)
                or receipt.get("artifact_sha256") != metadata["packer_image_sha256"]
                or receipt.get("output_sha256") != sha(packed_output)
                or (destination / "pack.input.bin").read_bytes() != frame
                or packed_output[:count] != executable
                or receipt.get("forbidden_compiler_modules_loaded") != []):
            raise ValueError("native entropy complete packer receipt differs")
        if any((source_root / "native" / ("entropy_" + kind + ".hepta")).read_bytes() != raw
               for kind, raw in sources.items()):
            raise ValueError("native entropy source changed during build")
        build._recheck()

    if manifest_path.exists():
        verify_completed()
        return manifest_path
    modules = {}
    for kind in ("policy", "packer"):
        name = "entropy-" + kind + "-" + sha(sources[kind])[:16]
        path = Path(build_root).resolve() / "modules" / name / "manifest.json"
        if not path.exists():
            path = build.compile(name, source_root / "native" / ("entropy_" + kind + ".hepta"), standalone=None)
        metadata = json.loads(path.read_bytes())
        image = path.parent / metadata["image"]
        if (metadata.get("source_sha256") != sha(sources[kind])
                or metadata.get("compiler_sha256") != compiler_sha
                or metadata.get("compiler_commit") != build.identity["commit"]
                or (path.parent / metadata["source"]).read_bytes() != sources[kind]
                or sha(image.read_bytes()) != metadata.get("image_sha256")):
            raise ValueError("native entropy module identity differs: " + kind)
        modules[kind] = (metadata, image)
    destination.mkdir(parents=True, mode=0o700)
    policy, policy_image = modules["policy"]
    packer, packer_image = modules["packer"]
    frame = b"HIAENTP1" + struct.pack("<Q", policy_image.stat().st_size) + policy_image.read_bytes()
    from tools.qualify_hia_selfhost import invoke
    receipt, output = invoke(destination, "pack", packer_image, frame)
    count = receipt.get("core_u32")
    if (receipt.get("status") != "returned" or type(receipt.get("abi_status")) is not int
            or receipt["abi_status"] != 0 or type(count) is not int or not 0 < count <= min(1 << 20, len(output))
            or receipt.get("result_u64") != count or receipt.get("source_unchanged") is not True
            or receipt.get("input_sha256") != sha(frame) or receipt.get("input_bytes") != len(frame)
            or receipt.get("artifact_sha256") != sha(packer_image.read_bytes())
            or receipt.get("output_sha256") != sha(output)
            or receipt.get("forbidden_compiler_modules_loaded") != []):
        raise ValueError("native entropy packer execution differs")
    executable = output[:count]
    inspection = inspect_executable(executable)
    metadata = {"schema": "hepta.runtime.native-entropy.v2", "target": "linux-x86_64",
                "transport": "fixed-24-byte-requests-u32-results", "compiler_commit": build.identity["commit"],
                "compiler_sha256": compiler_sha, "executable": "native-entropy.elf",
                "executable_sha256": sha(executable), "request_bytes": 24,
                "maximum_entropy_bytes": 128, "workspace_bytes": 1024,
                "runtime_python_required": False, "runtime_libc_required": False,
                "registered_mcp_tool": False, "production_activated": False,
                "whole_runtime_replaced": False, "inspection": inspection, "pack_receipt": receipt}
    for kind, (module, image) in modules.items():
        module = dict(module, source=kind + ".hepta", image=kind + ".image.bin")
        raw = json_bytes(module)
        write_new(destination / (kind + ".hepta"), sources[kind])
        write_new(destination / (kind + ".image.bin"), image.read_bytes())
        write_new(destination / (kind + ".json"), raw)
        metadata.update({kind + "_manifest": kind + ".json", kind + "_manifest_sha256": sha(raw),
                         kind + "_source_sha256": sha(sources[kind]), kind + "_image_sha256": module["image_sha256"]})
    write_new(destination / "native-entropy.elf", executable, 0o500)
    write_new(manifest_path, json_bytes(metadata))
    verify_completed()
    return manifest_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, default=os.environ.get("HIA_HEPTA_DIR"))
    parser.add_argument("--build-root", type=Path, default=os.environ.get("HIA_BUILD_ROOT"))
    args = parser.parse_args()
    if not args.hepta or not args.build_root:
        parser.error("--hepta and --build-root or their HIA environment variables are required")
    print(json.dumps({"manifest": str(build_entropy(args.hepta, args.build_root))}))
