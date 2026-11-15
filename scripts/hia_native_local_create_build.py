"""Build the private exclusive-create owner and its fixed Linux syscall bridge.

The HIA owner decides filesystem policy, retries, chunking and descriptor
lifetime. This driver compiles and verifies artifacts; the produced ELF has
no Python, Rust, libc, dynamic-loader or host semantic fallback.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_build import ABI, HEPTA_COMMIT, NativeBuild, json_bytes, write_new

COMPONENT = "native/local_create_file_component.json"
SOURCES = {"owner": "native/local_create_file.hepta", "packer": "native/local_create_packer.hepta"}
SCOPE = {"production_activated": False, "whole_runtime_replaced": False,
         "old_stack_removal_qualified": False, "async_cancellation_qualified": False,
         "public_handler_qualified": False}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink() or path.resolve() != path.absolute():
        raise ValueError("local-create artifact must be an ordinary unaliased file: " + str(path))
    return path.read_bytes()


def source_evidence(root: Path = ROOT) -> dict:
    metadata = json.loads(read(root / COMPONENT))
    if (metadata.get("schema") != "hepta.runtime.local-create-component.v1"
            or metadata.get("compiler_commit") != HEPTA_COMMIT
            or any(metadata.get(key) is not value for key, value in SCOPE.items())):
        raise ValueError("local-create component scope or compiler differs")
    files = metadata.get("source_sha256")
    if not isinstance(files, dict) or set(files) != {*SOURCES.values(), "scripts/local_create_adapter.S"}:
        raise ValueError("local-create source closure differs")
    if any(digest(read(root / name)) != expected for name, expected in files.items()):
        raise ValueError("local-create source bytes differ")
    prefix = bytes.fromhex(metadata["prefix_hex"])
    if (len(prefix) != 5632 or prefix[96:112] != bytes(16)
            or digest(prefix) != metadata.get("prefix_sha256")):
        raise ValueError("local-create fixed prefix differs")
    return {"component_sha256": digest(read(root / COMPONENT)), **metadata}


def expected_executable(component: dict, image: bytes) -> bytes:
    raw = bytearray(bytes.fromhex(component["prefix_hex"]) + image)
    struct.pack_into("<QQ", raw, 96, len(raw), len(raw))
    if (len(raw) != component["executable_bytes"]
            or type(component["executable_bytes"]) is not int
            or digest(raw) != component["executable_sha256"]
            or raw[:16] != b"\x7fELF\x02\x01\x01" + bytes(9)
            or struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
            != (2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
            or struct.unpack_from("<IIQQQQQQ", raw, 64)
            != (1, 5, 0, 0x400000, 0x400000, len(raw), len(raw), 4096)
            or struct.unpack_from("<IIQQQQQQ", raw, 120)
            != (0x6474e551, 6, 0, 0, 0, 0, 0, 16)):
        raise ValueError("local-create complete static ELF identity differs")
    return bytes(raw)


def check_receipt(receipt: dict, frame: bytes, image: bytes, output: bytes, executable: bytes) -> None:
    expected = {"status": "returned", "abi_status": 0, "core_u32": len(executable),
                "result_u64": len(executable), "source_unchanged": True,
                "input_sha256": digest(frame), "input_bytes": len(frame),
                "artifact_sha256": digest(image), "format": "flat-x86-64",
                "output_sha256": digest(output), "forbidden_compiler_modules_loaded": []}
    if (not isinstance(receipt, dict) or any(receipt.get(key) != value for key, value in expected.items())
            or any(type(receipt.get(key)) is not int for key in ("abi_status", "core_u32", "result_u64", "input_bytes"))
            or receipt.get("source_unchanged") is not True
            or len(output) != 1 << 20 or output[:len(executable)] != executable
            or output[len(executable):] != bytes([0xa5]) * (len(output) - len(executable))):
        raise ValueError("local-create actual HIA packer receipt or complete output differs")


def verify_build(manifest_path: Path, *, source_root: Path = ROOT) -> dict:
    component = source_evidence(source_root)
    folder = manifest_path.parent
    metadata = json.loads(read(manifest_path))
    fixed = {"schema": "hepta.runtime.local-create-native.v1", "target": "linux-x86_64",
             "compiler_commit": component["compiler_commit"], "compiler_sha256": component["compiler_sha256"],
             "source_evidence": component, "executable": "local-create.elf",
             "runtime_python_required": False, "runtime_libc_required": False,
             "dynamic_loader": False, "transport": "one-u64-length-request-one-result", **SCOPE}
    if (any(metadata.get(key) != value for key, value in fixed.items())
            or any(metadata.get(key) is not False for key in
                   (*SCOPE, "runtime_python_required", "runtime_libc_required", "dynamic_loader"))):
        raise ValueError("local-create build manifest differs")
    images = {}
    for role, relative in SOURCES.items():
        child_path = folder / (role + ".json")
        child = json.loads(read(child_path))
        image = read(folder / (role + ".image.bin"))
        source = read(folder / (role + ".hepta"))
        profile = (134217728, 134217728, 268435456) if role == "owner" else (8388608, 8388608, 33554432)
        expected = {"schema": "hepta.runtime.native-module.v1", "abi": ABI, "target": "linux-x86_64",
                    "compiler_commit": component["compiler_commit"], "compiler_sha256": component["compiler_sha256"],
                    "source": role + ".hepta", "source_sha256": component["source_sha256"][relative],
                    "image": role + ".image.bin", "image_sha256": component[role + "_image_sha256"],
                    "standalone": None, "input_capacity": profile[0], "output_capacity": profile[1],
                    "workspace_capacity": profile[2]}
        if (any(child.get(key) != value for key, value in expected.items())
                or metadata.get(role + "_manifest_sha256") != digest(read(child_path))
                or source != read(source_root / relative)
                or digest(image) != component[role + "_image_sha256"]):
            raise ValueError("local-create compiled child differs: " + role)
        images[role] = image
    expected = expected_executable(component, images["owner"])
    if read(folder / "local-create.elf") != expected:
        raise ValueError("local-create executable bytes differ")
    frame = b"HLCREPK1" + struct.pack("<Q", len(images["owner"])) + images["owner"]
    if read(folder / "pack.input.bin") != frame:
        raise ValueError("local-create retained packer input differs")
    receipt = json.loads(read(folder / "pack.receipt.json"))
    check_receipt(receipt, frame, images["packer"], read(folder / "pack.output.bin"), expected)
    if metadata.get("pack_receipt") != receipt:
        raise ValueError("local-create packer receipt binding differs")
    return metadata


def build_local_create(hepta: Path, build_root: Path, *, source_root: Path = ROOT) -> Path:
    hepta, build_root, source_root = hepta.resolve(), build_root.resolve(), source_root.resolve()
    component = source_evidence(source_root)
    builder = NativeBuild(hepta, build_root)
    if digest(builder.bootstrap().read_bytes()) != component["compiler_sha256"]:
        raise ValueError("local-create compiler fixed point differs")
    folder = build_root / "local-create" / component["component_sha256"]
    manifest_path = folder / "manifest.json"
    if manifest_path.exists():
        verify_build(manifest_path, source_root=source_root)
        builder._recheck()
        return manifest_path
    children = {}
    for role, relative in SOURCES.items():
        name = "local-create-" + role + "-" + component["source_sha256"][relative][:16]
        built = build_root / "modules" / name / "manifest.json"
        if not built.exists():
            built = builder.compile(name, source_root / relative, standalone=None,
                                    buffer_profile="history.v1" if role == "owner" else "standard")
        child = json.loads(read(built))
        image = read(built.parent / child["image"])
        if (read(built.parent / child["source"]) != read(source_root / relative)
                or digest(image) != component[role + "_image_sha256"]
                or child.get("source_sha256") != component["source_sha256"][relative]
                or child.get("compiler_sha256") != component["compiler_sha256"]):
            raise ValueError("local-create newly compiled child differs: " + role)
        children[role] = (child, image, built.parent / child["image"])
    folder.mkdir(parents=True, exist_ok=False)
    from tools.qualify_hia_selfhost import invoke
    owner_image = children["owner"][1]
    frame = b"HLCREPK1" + struct.pack("<Q", len(owner_image)) + owner_image
    receipt, output = invoke(folder, "pack", children["packer"][2], frame)
    executable = expected_executable(component, owner_image)
    check_receipt(receipt, frame, children["packer"][1], output, executable)
    metadata = {"schema": "hepta.runtime.local-create-native.v1", "target": "linux-x86_64",
                "compiler_commit": component["compiler_commit"], "compiler_sha256": component["compiler_sha256"],
                "source_evidence": component, "executable": "local-create.elf",
                "runtime_python_required": False, "runtime_libc_required": False,
                "dynamic_loader": False, "transport": "one-u64-length-request-one-result",
                "pack_receipt": receipt, **SCOPE}
    for role, (child, image, _) in children.items():
        child = dict(child, source=role + ".hepta", image=role + ".image.bin")
        encoded = json_bytes(child)
        write_new(folder / (role + ".hepta"), read(source_root / SOURCES[role]))
        write_new(folder / (role + ".image.bin"), image)
        write_new(folder / (role + ".json"), encoded)
        metadata[role + "_manifest_sha256"] = digest(encoded)
    write_new(folder / "local-create.elf", executable, 0o500)
    write_new(manifest_path, json_bytes(metadata))
    verify_build(manifest_path, source_root=source_root)
    if source_evidence(source_root) != component:
        raise ValueError("local-create source changed during build")
    builder._recheck()
    return manifest_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    args = parser.parse_args()
    print(build_local_create(args.hepta, args.build_root, source_root=args.source_root))
