"""Compile and pack the exact serial caller-authority profile with pinned HIA.

The Python driver admits source and artifact identities; all runtime policy,
hashing, authority decisions and ELF construction execute native HIA code.
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
from hia_native_build import HEPTA_COMMIT, NativeBuild, json_bytes, write_new
from hia_native_loader import NativeModule
from hia_native_entropy_qualification import inspect_elf, native_receipt
from hia_native_authority_layout import validate_authority_layout

PROFILE_SHA = "927cb5e16d8c3fcb9f4d61dc00c4aa48ae09592fec8e28cb2ba3deb4b0950b92"
PACKER_SHA = "c54c54f664944b7a243d8e8e3d10e2ba623ab7e8e4f4189962542722617969d0"
PROVENANCE_SHA = "9683325f1ab64d1e675ab12b967959944d579fcc28a4a18bde0c602317a354e1"
ABI = "hepta.runtime.borrowed-bytes.linux-x86_64.v1"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError("authority build: " + message)


def read(path):
    path = Path(path).absolute()
    require(path.is_file() and not path.is_symlink() and path.resolve() == path,
            "source or artifact must be a regular non-aliased file")
    return path.read_bytes()


def same(actual, expected, message):
    require(json_bytes(actual) == json_bytes(expected), message)


def admitted_profile(source_root):
    source_root = Path(source_root).resolve(strict=True)
    profile_raw = read(source_root / "native/authority_profile.json")
    provenance_raw = read(source_root / "native/authority_packer_provenance.json")
    packer = read(source_root / "native/authority_packer.hepta")
    require(sha(profile_raw) == PROFILE_SHA and sha(provenance_raw) == PROVENANCE_SHA
            and sha(packer) == PACKER_SHA, "fixed HIA profile, packer or provenance differs")
    profile, provenance = json.loads(profile_raw), json.loads(provenance_raw)
    require(profile.get("compiler_commit") == HEPTA_COMMIT and len(profile.get("members", [])) == 9,
            "fixed compiler or member count differs")
    snapshots = {"native/authority_profile.json": profile_raw,
                 "native/authority_packer_provenance.json": provenance_raw,
                 "native/authority_packer.hepta": packer}
    for index, row in enumerate(profile["members"]):
        require(type(row.get("id")) is int and row["id"] == index, "profile member order differs")
        snapshots[row["source"]] = read(source_root / row["source"])
        require(sha(snapshots[row["source"]]) == row["source_sha256"],
                "current native member source differs")
    return profile, provenance, snapshots


def checked_flat(build, name, source_path, expected_image=None):
    compiler = read(build.bootstrap())
    source = read(source_path)
    path = build.root / "modules" / name / "manifest.json"
    if not path.exists():
        path = build.compile(name, source_path, standalone=None)
    metadata = json.loads(read(path))
    expected = {"schema": "hepta.runtime.native-module.v1", "name": name,
                "abi": ABI, "target": "linux-x86_64", "compiler_commit": HEPTA_COMMIT,
                "compiler_sha256": sha(compiler), "source": name + ".hepta",
                "source_sha256": sha(source), "image": "module.image.bin",
                "input_capacity": 8 << 20, "output_capacity": 8 << 20,
                "workspace_capacity": 32 << 20, "qualification": "development_fixed_point",
                "standalone": None}
    same({key: metadata.get(key) for key in expected}, expected, "cached flat compiler/ABI differs")
    image = read(path.parent / "module.image.bin")
    require(read(path.parent / metadata["source"]) == source and metadata.get("image_sha256") == sha(image)
            and (expected_image is None or sha(image) == expected_image), "cached flat source/image differs")
    receipt = json.loads(read(path.parent / "module.receipt.json"))
    native_receipt(receipt, image=compiler, source=source,
                   output=read(path.parent / "module.output.bin"), produced=image)
    record = json.loads(read(path.parent / "build.json"))
    require(read(path.parent / "module.input.bin") == source
            and receipt.get("produced_sha256") == sha(image)
            and receipt.get("produced_bytes") == len(image), "native compilation products differ")
    same(record.get("compile_receipt"), receipt, "native compilation receipts disagree")
    same(record.get("compiler_dependency"), build.identity, "compiler source closure differs")
    require(record.get("whole_runtime_replaced") is False, "cached scope claim differs")
    return path, metadata, image


def make_frame(profile, images):
    require(len(images) == len(profile["members"]) == 9, "fixed packer input count differs")
    result = bytearray(b"HIABND01" + struct.pack("<3Q", 9, 0, 0))
    for row, image in zip(profile["members"], images):
        require(len(image) == row["image_bytes"] and sha(image) == row["image_sha256"],
                "packer input actual image differs")
        result.extend(struct.pack("<8Q", len(image), row["input_capacity"], row["output_capacity"],
                                  row["workspace_capacity"], row["flags"], row["call_mask"], 0, 0))
        result.extend(bytes.fromhex(row["source_sha256"] + row["image_sha256"]))
        result.extend(image)
    return bytes(result)


def _copied(metadata, stem):
    return {**metadata, "source": stem + ".hepta", "image": stem + ".image.bin"}


def build_authority(hepta: Path, build_root: Path, *, source_root: Path = ROOT) -> Path:
    source_root = Path(source_root).resolve(strict=True)
    profile, provenance, snapshots = admitted_profile(source_root)
    build = NativeBuild(hepta, build_root)
    compiler = read(build.bootstrap())
    compiler_sha = sha(compiler)
    require(compiler_sha == profile["compiler_sha256"], "pinned compiler image differs")
    capability_table = [{key: row[key] for key in ("id", "name", "source_sha256", "flags", "call_mask",
                                                  "input_capacity", "output_capacity", "workspace_capacity")}
                        for row in profile["members"]]
    key = sha(json_bytes({"compiler": compiler_sha, "members": capability_table, "packer": PACKER_SHA}))
    destination = build.root / "composition" / key
    manifest_path = destination / "manifest.json"
    compiled = [checked_flat(build, "composition-" + PACKER_SHA[:24],
                             source_root / "native/authority_packer.hepta")]
    for row in profile["members"]:
        compiled.append(checked_flat(build, "composition-" + row["source_sha256"][:24],
                                     source_root / row["source"], row["image_sha256"]))
    frame = make_frame(profile, [entry[2] for entry in compiled[1:]])

    def verify():
        saved = json.loads(read(manifest_path))
        expected = {"schema": "hepta.runtime.native-composition.v1", "target": "linux-x86_64",
                    "transport": "newline-hex-typed-header-qualification", "key": key,
                    "compiler_commit": HEPTA_COMMIT, "compiler_sha256": compiler_sha,
                    "profile": capability_table, "frame_bytes": len(frame), "frame_sha256": sha(frame),
                    "executable": "native-authority.elf", "runtime_python_required": False,
                    "runtime_libc_required": False, "whole_runtime_replaced": False}
        same({k: saved.get(k) for k in expected}, expected, "cached top-level compiler/profile differs")
        require(type(saved.get("members")) is list and len(saved["members"]) == 9,
                "cached member inventory differs")
        for index, (_, original, image) in enumerate(compiled):
            stem = "packer" if index == 0 else f"module_{index - 1:02d}"
            row = saved.get("packer") if index == 0 else saved["members"][index - 1]
            copied_path = destination / (stem + ".json")
            copied = _copied(original, stem)
            same(json.loads(read(copied_path)), copied, "copied native module manifest differs")
            source_name = "native/authority_packer.hepta" if index == 0 else profile["members"][index - 1]["source"]
            require(read(destination / (stem + ".hepta")) == snapshots[source_name]
                    and read(destination / (stem + ".image.bin")) == image, "copied source/image bytes differ")
            same(row, {"manifest": stem + ".json", "manifest_sha256": sha(read(copied_path)),
                       "source_sha256": copied["source_sha256"], "image_sha256": sha(image)},
                 "copied member manifest custody differs")
        executable = read(destination / "native-authority.elf")
        layout = validate_authority_layout(executable, frame, profile, provenance)
        require(saved.get("executable_sha256") == sha(executable), "cached executable hash differs")
        same(saved.get("inspection"), inspect_elf(executable), "cached executable inspection differs")
        same(saved.get("packing"), {"owner": "HIA", "input_unchanged": True,
                                    "buffer_canaries_unchanged": True,
                                    "packer_image_sha256": sha(compiled[0][2])},
             "native packing ownership differs")
        if "layout" in saved:
            same(saved["layout"], layout, "cached exact layout observation differs")
        for name, raw in snapshots.items():
            require(read(source_root / name) == raw, "source changed during build")
        build._recheck()

    if manifest_path.exists():
        verify()
        return manifest_path
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination.mkdir(mode=0o700)
    with NativeModule(compiled[0][0], manifest_sha256=sha(read(compiled[0][0]))) as packer:
        executable = packer.invoke(frame, output_capacity=8 << 20, workspace_capacity=1 << 20)
    layout = validate_authority_layout(executable, frame, profile, provenance)
    copied_rows = []
    for index, (_, original, image) in enumerate(compiled):
        stem = "packer" if index == 0 else f"module_{index - 1:02d}"
        source_name = "native/authority_packer.hepta" if index == 0 else profile["members"][index - 1]["source"]
        write_new(destination / (stem + ".hepta"), snapshots[source_name])
        write_new(destination / (stem + ".image.bin"), image)
        copied_path = destination / (stem + ".json")
        write_new(copied_path, json_bytes(_copied(original, stem)))
        copied_rows.append({"manifest": stem + ".json", "manifest_sha256": sha(read(copied_path)),
                            "source_sha256": original["source_sha256"], "image_sha256": sha(image)})
    write_new(destination / "native-authority.elf", executable, 0o500)
    saved = {"schema": "hepta.runtime.native-composition.v1", "target": "linux-x86_64",
             "transport": "newline-hex-typed-header-qualification", "key": key,
             "compiler_commit": HEPTA_COMMIT, "compiler_sha256": compiler_sha,
             "profile": capability_table, "frame_bytes": len(frame), "frame_sha256": sha(frame),
             "packer": copied_rows[0], "members": copied_rows[1:],
             "executable": "native-authority.elf", "executable_sha256": sha(executable),
             "inspection": inspect_elf(executable), "layout": layout,
             "packing": {"owner": "HIA", "input_unchanged": True, "buffer_canaries_unchanged": True,
                         "packer_image_sha256": sha(compiled[0][2])},
             "runtime_python_required": False, "runtime_libc_required": False, "whole_runtime_replaced": False}
    write_new(manifest_path, json_bytes(saved))
    verify()
    return manifest_path


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, default=os.environ.get("HIA_HEPTA_DIR"))
    parser.add_argument("--build-root", type=Path, default=os.environ.get("HIA_BUILD_ROOT"))
    parser.add_argument("--source-root", type=Path, default=ROOT)
    args = parser.parse_args()
    if args.hepta is None or args.build_root is None:
        parser.error("--hepta and --build-root are required")
    print(build_authority(args.hepta, args.build_root, source_root=args.source_root))
