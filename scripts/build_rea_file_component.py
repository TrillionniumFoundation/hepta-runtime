# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Construct the pinned HIA REA file policies and HIA-emitted syscall owner.

This is a development custody driver. Every emitted policy and the engine
producer are native HIA programs. No assembler or Python semantic fallback
participates in the resulting components.
"""
from pathlib import Path
import argparse
import json
import struct

from hia_native_build import NativeBuild, digest, json_bytes, write_new
from hia_native_loader import NativeModule

SOURCES = {
    "rea-file-policy": "93c4841f65904ba025de02ee3bb0c79fdc9f014552c2b02f204eed6a17f39a8d",
    "rea-file-actor": "24182c6e5b12c5e47b415366956cd3c36f74cd1d6c357dc95cd2617aaeb569ee",
    "rea-descriptor-packer": "04764472d0557881c8740b722757c4550cb450690e7f3707fbcbb215a507146c",
}
IMAGES = {
    "rea-file-policy": "ffd1b9c3756c0904672dc7e819fa5261447fc3abdb764b60202c03e73fb29ea9",
    "rea-file-actor": "19ac750a7634a9ce6a37376d77d06b5b754cd7106d757b29a4d2956a152f7183",
    "rea-descriptor-packer": "9a0b9d5f8130b5cb4a1eb2f47a636859669133df8aca25427f99a360ddf0fe8d",
}
ENGINE_BYTES = 2115
ENGINE_SHA256 = "04398f038a64471a5b6dad3774ba03f469c5d8a3e41a4f8191d5c60dc7a8ea68"
FLAT_SHA256 = "14e65f19b70579d0f3d028687283209440dde7d52613385ed7038c8a8de39f2e"
EXPORTS = {"create": 0, "step": 154, "take": 1744, "destroy": 1831}


def build_component(builder: NativeBuild, runtime_root: Path) -> Path:
    runtime_root = runtime_root.resolve(strict=True)
    folder = builder.root / "rea-file-component"
    folder.mkdir(mode=0o700, exist_ok=False)
    inputs = {}
    manifests = {}
    compiled = {}
    for role, expected in SOURCES.items():
        path = runtime_root / "native" / (role.replace("-", "_") + ".hepta")
        raw = path.read_bytes()
        if digest(raw) != expected:
            raise ValueError("REA file component source differs: " + role)
        inputs[path] = raw
        manifest = builder.compile(role, path, standalone=None)
        manifest_raw = manifest.read_bytes()
        meta = json.loads(manifest_raw)
        image = (manifest.parent / meta["image"]).read_bytes()
        if (meta["source_sha256"] != expected or digest(image) != meta["image_sha256"]
                or role in IMAGES and digest(image) != IMAGES[role]):
            raise ValueError("REA actual component image differs: " + role)
        manifests[role] = manifest
        compiled[role] = {"manifest": str(manifest), "manifest_sha256": digest(manifest_raw),
                          "source_sha256": expected, "image_bytes": len(image),
                          "image_sha256": digest(image), "compiler_commit": meta["compiler_commit"],
                          "compiler_sha256": meta["compiler_sha256"]}
    compiler_ids = {(row["compiler_commit"], row["compiler_sha256"]) for row in compiled.values()}
    if compiler_ids != {("d3e2c90173cf733e42b299d0c4274df4b593a12f",
                         "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0")}:
        raise ValueError("REA component compilers differ")
    producer = manifests["rea-descriptor-packer"]
    request = b"HREAPQ01" + struct.pack("<QQ", 1, 0)
    with NativeModule(producer, manifest_sha256=compiled["rea-descriptor-packer"]["manifest_sha256"]) as module:
        actual = module.invoke(request, output_capacity=ENGINE_BYTES, workspace_capacity=0)
    if (len(actual) != ENGINE_BYTES or digest(actual) != ENGINE_SHA256
            or actual[:8] != b"HREAPK01"
            or struct.unpack_from("<7Q", actual, 8) != (2115, 2051, 0, 154, 1744, 1831, 0)
            or digest(actual[64:]) != FLAT_SHA256):
        raise ValueError("actual HIA-emitted descriptor owner differs")
    write_new(folder / "descriptor.engine", actual)
    write_new(folder / "producer-input.bin", request)
    for path, raw in inputs.items():
        if path.read_bytes() != raw:
            raise ValueError("REA source changed during native construction")
    builder._recheck()
    result = {
        "schema": "hepta.runtime.rea-file-component.v1", "modules": compiled,
        "engine": {"path": "descriptor.engine", "bytes": ENGINE_BYTES, "sha256": ENGINE_SHA256,
                   "flat_bytes": 2051, "flat_sha256": FLAT_SHA256, "exports": EXPORTS},
        "engine_producer_input_hex": request.hex(), "construction_assembler_required": False,
        "private_ownership": "one exclusive actor workspace and one descriptor context",
        "public_route_qualified": False, "whole_runtime_replaced": False,
    }
    path = folder / "component.json"
    write_new(path, json_bytes(result))
    return path


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("runtime", "hepta", "build-root"):
        ap.add_argument("--" + name, type=Path, required=True)
    a = ap.parse_args()
    path = build_component(NativeBuild(a.hepta, a.build_root), a.runtime)
    print(json.dumps({"component": str(path), "engine_sha256": ENGINE_SHA256,
                      "public_route_qualified": False}, sort_keys=True))


if __name__ == "__main__":
    main()
