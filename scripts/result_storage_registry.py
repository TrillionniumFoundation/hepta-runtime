# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fixed compilation domain for the private result-retention and storage graph."""
from pathlib import Path
import hashlib
import json

PROFILE = "native/result_storage_profile.json"
PROFILE_SHA = "f04a2f90cb8033526112c67194390dadef489d73811edef8087a87142d343dc9"
COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
COMPILER_IMAGE = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
ORIGINAL = "src/mcp/runtime/request_results.rs"
ORIGINAL_SHA = "f1003ad4de7448d601d0536d3a7c4f0d72790e732e8301d6c36349035ca3c439"
REF_ROOT = "tests/hia_native/result_storage_reference"
FIXTURE_ROOT = "tests/hia_native/fixtures/result_storage_reference"
sha = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def regular(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "not an owned regular input: " + str(path))
    return path.read_bytes()


def profile(root):
    raw = regular(Path(root) / PROFILE)
    require(sha(raw) == PROFILE_SHA, "fixed result storage profile changed")
    value = json.loads(raw)
    require(value["schema"] == "hepta.result-storage.fixed-profile.v1"
        and value["compiler_commit"] == COMPILER and value["compiler_sha256"] == COMPILER_IMAGE
        and len(value["modules"]) == 30 and len(value["owners"]) == 9
        and len(value["graphs"]) == 6, "unexpected result storage graph")
    return value


def build_sources(root):
    """Pin the whole compilation graph; test evidence supplies its separate closure."""
    root = Path(root)
    fixed = profile(root)
    names = {PROFILE, ORIGINAL, "native/config_result_composition.json",
        "native/result_storage_child_rebinding.json", "scripts/result_storage_registry.py",
        "scripts/build_result_storage.py", "scripts/hia_native_build.py",
        "scripts/hia_native_loader.py", "scripts/generate_hia_transport.py",
        "scripts/result_storage_pack_child.py", "native/filter_packer.hepta"}
    names.update(item["source"] for item in fixed["modules"].values())
    names.update(item["layout"] for item in fixed["graphs"].values())
    for stem in fixed["owners"].values():
        path = "native/" + stem + "_composition.json"
        names.add(path)
        names.add("native/" + stem + "_abi.md")
        proof = json.loads(regular(root / path))
        names.update(row["source"] for row in proof["imports"])
    require(sha(regular(root / ORIGINAL)) == ORIGINAL_SHA, "original storage owner changed")
    return {name: sha(regular(root / name)) for name in sorted(names)}


def manifest_image(path):
    path = Path(path)
    raw = regular(path)
    metadata = json.loads(raw)
    require(metadata["schema"] == "hepta.runtime.native-module.v1"
        and metadata["compiler_commit"] == COMPILER
        and metadata["compiler_sha256"] == COMPILER_IMAGE, "module compiler identity differs")
    image = regular(path.parent / metadata["image"])
    source = regular(path.parent / metadata["source"])
    require(sha(image) == metadata["image_sha256"] and sha(source) == metadata["source_sha256"],
        "module retained source or image changed")
    return metadata, image, sha(raw)
