# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Build the ASAR parser through its explicitly bound native HIA lowering stage.

This Python module is a development build driver. The emitted parser and
lowering stage are HIA-compiled native images; no Python runs in either image.
"""
from pathlib import Path
import argparse
import json
import struct

from hia_native_build import NativeBuild, digest, json_bytes, write_new

BASE_SOURCE = "70c1de9a0f9511bed5379cb0ac4eb9495f53fb71b2999a6290cc0605c22d0ab6"
BASE_IMAGE = "ab3e303b07aaab48a825627a6d743dfe8724eaf9b8d3c157127917c10be2775d"
STAGE_SOURCE = "641e1d1b460251283fccd8d8749b4dfd7ed8689951bb1f43ad918bbd18064af0"
FINAL_IMAGE = "d5b57ebd0fe6956464cc95b5712449d543e3af5850442ae67d57049f5ef6fbd5"
FINAL_BYTES = 549750

def build_component(builder: NativeBuild, runtime_root: Path) -> Path:
    runtime_root = runtime_root.resolve(strict=True)
    parser = runtime_root / "native/rea_asar_parser.hepta"
    stage_source = runtime_root / "native/rea_asar_private_lowering.hepta"
    composition_path = runtime_root / "native/rea_asar_private_lowering_composition.json"
    composition_raw = composition_path.read_bytes()
    composition = json.loads(composition_raw)
    binding = composition["input_binding"]
    parser_bytes, stage_bytes = parser.read_bytes(), stage_source.read_bytes()
    if (digest(parser_bytes) != BASE_SOURCE or digest(stage_bytes) != STAGE_SOURCE
        or composition["schema"] != "hepta.runtime.private-sha-scalar-x64-lowering.v2"
        or composition["source_sha256"] != STAGE_SOURCE
        or binding["source_sha256"] != BASE_SOURCE
        or binding["image_sha256"] != BASE_IMAGE
        or binding["image_bytes"] != 537735
        or composition["request_magic"] != "HSHX6402"
        or composition["patched_functions"] != ["f65", "f63", "f64", "f75", "f76"]
        or composition["product_is_direct_b3_output"] is not False):
        raise ValueError("ASAR native lowering source or closed binding differs")
    base_manifest = builder.compile("rea-asar-base", parser, standalone=None,
                                    buffer_profile="history.v1")
    base_meta = json.loads(base_manifest.read_bytes())
    base_image = base_manifest.parent / base_meta["image"]
    base_bytes = base_image.read_bytes()
    if (len(base_bytes) != binding["image_bytes"] or digest(base_bytes) != BASE_IMAGE
        or base_meta["source_sha256"] != BASE_SOURCE
        or base_meta["compiler_commit"] != binding["compiler_commit"]
        or base_meta["compiler_sha256"] != binding["compiler_sha256"]):
        raise ValueError("actual parser compile differs from the whole-image binding")
    stage_manifest = builder.compile("rea-asar-private-lowering", stage_source, standalone=None)
    stage_meta = json.loads(stage_manifest.read_bytes())
    stage_image = stage_manifest.parent / stage_meta["image"]
    if (stage_meta["source_sha256"] != STAGE_SOURCE
        or stage_meta["compiler_commit"] != binding["compiler_commit"]
        or stage_meta["compiler_sha256"] != binding["compiler_sha256"]):
        raise ValueError("actual lowering stage compiler differs")
    folder = builder.root / "modules/rea-asar-parser"
    folder.mkdir(mode=0o700, exist_ok=False)
    frame = b"HSHX6402" + struct.pack("<Q", len(base_bytes)) + base_bytes
    from tools.qualify_hia_selfhost import invoke
    record, output = invoke(folder, "private-lowering", stage_image, frame)
    if (record.get("status") != "returned" or type(record.get("abi_status")) is not int
        or record["abi_status"] != 0 or type(record.get("core_u32")) is not int
        or record["core_u32"] != FINAL_BYTES or len(output) < FINAL_BYTES
        or record.get("source_unchanged") is not True
        or record.get("input_sha256") != digest(frame)
        or record.get("artifact_sha256") != digest(stage_image.read_bytes())
        or type(record.get("result_u64")) is not int
        or record["result_u64"] != FINAL_BYTES
        or record.get("output_sha256") != digest(output)
        or type(record.get("input_bytes")) is not int
        or record["input_bytes"] != len(frame)
        or record.get("forbidden_compiler_modules_loaded") != []):
        raise ValueError("HIA lowering returned an incomplete or inconsistent native receipt")
    product = output[:FINAL_BYTES]
    if digest(product) != FINAL_IMAGE:
        raise ValueError("HIA lowering product differs from the qualified exact image")
    restored = bytearray(product[:len(base_bytes)])
    for item in [binding, *binding["word_functions"]]:
        offset = item["function_offset"]
        restored[offset:offset+11] = base_bytes[offset:offset+11]
    if bytes(restored) != base_bytes:
        raise ValueError("HIA lowering changed an unbound region of the base image")
    write_new(folder / "rea-asar-parser.hepta", parser_bytes)
    write_new(folder / "module.image.bin", product)
    meta = dict(base_meta, name="rea-asar-parser", source="rea-asar-parser.hepta",
        image="module.image.bin", image_sha256=FINAL_IMAGE,
        qualification="development_explicit_hia_native_lowering", standalone=None,
        lowering={"schema": composition["schema"], "request_magic": "HSHX6402",
            "stage_source_sha256": STAGE_SOURCE,
            "stage_manifest_sha256": digest(stage_manifest.read_bytes()),
            "stage_image_sha256": digest(stage_image.read_bytes()),
            "composition_sha256": digest(composition_raw),
            "base_manifest_sha256": digest(base_manifest.read_bytes()),
            "base_image_sha256": BASE_IMAGE, "base_source_sha256": BASE_SOURCE,
            "base_compiler_commit": binding["compiler_commit"],
            "base_compiler_sha256": binding["compiler_sha256"],
            "bound_functions": [{k: item[k] for k in
                ("function", "function_offset", "function_end", "function_ir_sha256",
                 "function_image_sha256", "original_prologue_hex")}
                for item in [binding, *binding["word_functions"]]],
            "product_is_direct_b3_output": False,
            "whole_cold_qualified": False})
    if (parser.read_bytes() != parser_bytes or stage_source.read_bytes() != stage_bytes
        or composition_path.read_bytes() != composition_raw
        or base_image.read_bytes() != base_bytes):
        raise ValueError("ASAR source or stage input changed during construction")
    builder._recheck()
    write_new(folder / "build.json", json_bytes({
        "schema": "hepta.runtime.explicit-asar-native-lowering-build.v2",
        "base_manifest": str(base_manifest), "stage_manifest": str(stage_manifest),
        "input_binding": binding, "native_stage_receipt": record,
        "final_bytes": FINAL_BYTES, "final_image_sha256": FINAL_IMAGE,
        "whole_runtime_replaced": False, "public_route_qualified": False}))
    manifest = folder / "manifest.json"
    write_new(manifest, json_bytes(meta))
    return manifest

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ("runtime", "hepta", "build-root"):
        ap.add_argument("--" + name, required=True, type=Path)
    args = ap.parse_args()
    builder = NativeBuild(args.hepta, args.build_root)
    manifest = build_component(builder, args.runtime)
    print(json.dumps({"manifest": str(manifest), "final_image_sha256": FINAL_IMAGE,
        "product_is_direct_b3_output": False, "whole_runtime_replaced": False}, sort_keys=True))

if __name__ == "__main__":
    main()
