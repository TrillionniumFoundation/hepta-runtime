# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Source-owned fixed graph for the bounded public installed-handler profile."""
from pathlib import Path
import hashlib
import json

COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
COMPILER_IMAGE = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
PROFILE_SHA = '7b0cc202216d6023b62909150e1be3e036a7a1c9e86c8746a9ebb35aeea669a9'
TESTS = ("run_public_registry_cases.py", "test_public_registry_controls.py", "test_public_registry_elf.py")
FOLDERS = ("cases", "controls", "elf")
REMOVED_ENVIRONMENT = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR",
    "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP")
OWN = [
    "native/public_tool_dispatch.hepta", "native/public_tool_dispatch_composition.json",
    "native/public_runtime_packer.hepta", "native/public_runtime_adapter_composition.json",
    "native/public_registry_profile.json", "native/public_registry_abi.md", "native/public_registry_scope.md",
    "scripts/public_registry_registry.py", "scripts/public_runtime_adapter.S",
    "scripts/public_router_source.py.txt", "scripts/public_emitter_source.py.txt",
    "scripts/public_connection_transport.S.txt", "scripts/public_tool_dispatch_authoring.txt",
    "scripts/author_public_router.py", "scripts/author_public_adapter.py",
    "scripts/build_public_registry.py", "scripts/public_registry_pack_child.py",
    "scripts/hia_native_public_registry_qualification.py", "scripts/hia_native_public_registry_reference.py",
    "tests/hia_native/public_registry_cases.py", "tests/hia_native/public_registry_catalog.json",
    *["tests/hia_native/" + name for name in TESTS],
    "tests/hia_native/compare_public_registry_original.py", "tests/hia_native/check_public_registry_evidence.py",
    *["tests/hia_native/public_registry_reference/" + name for name in
      ("oracle_mcp.rs", "source-identity.json", "rustfmt.toml")],
]
COMMON = [
    "scripts/hia_native_build.py", "scripts/hia_native_loader.py", "scripts/generate_hia_transport.py",
    "scripts/hia_native_config_reference.py", "scripts/config_mcp_adapter.S", "native/text_budget.hepta",
    "tests/hia_native/config_reference_sources.json", "tests/hia_native/config_reference.tar.gz",
]
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("not a regular source file: " + str(path))
    return path.read_bytes()


def profile(root):
    raw = regular(Path(root) / "native/public_registry_profile.json")
    if sha(raw) != PROFILE_SHA:
        raise ValueError("public registry fixed graph changed")
    value = json.loads(raw)
    if value["compiler_commit"] != COMPILER or value["compiler_sha256"] != COMPILER_IMAGE:
        raise ValueError("public registry compiler changed")
    return value


def source_pins(root):
    root = Path(root)
    graph = profile(root)
    reference = json.loads(regular(root / "tests/hia_native/config_reference_sources.json"))
    names = [*OWN, *COMMON, *[row["source"] for row in graph["members"]], *reference["original_sources"]]
    return {name: sha(regular(root / name)) for name in sorted(set(names))}
