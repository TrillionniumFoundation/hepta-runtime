# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fixed source and original-reference domains for private result byte owners."""
from pathlib import Path
import hashlib
import json

COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
COMPILER_IMAGE = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
REMOVED_ENVIRONMENT = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR",
    "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP", "RUSTUP_TOOLCHAIN",
    "CARGO_BUILD_RUSTFLAGS", "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER")
MODULES = {
    "binary32": ("native/binary32_json.hepta",
        "2f44dc27744129ce56a2ce5bb835594f48aaca02ab75615fefd84e860a31f4b1",
        "af6d396e1488ab56039bd2edffd5e8979f49ba2f7a0113299ec12026dccdbf13"),
    "typed": ("native/typed_result_json.hepta",
        "f238c612a77e9a697b457a68dada4b423a7d443a6b5e4c4890e360df7926024f",
        "6b5f83ad351d6fd613cf059dc42efb520c90ebd541dd75ffde62b29ce6347c3a"),
    "request": ("native/request_result.hepta",
        "1d990c3482c181b64c38027b6b424fbcad365ebc28938a9299fa7666fad4e0c7",
        "4f73723701dcc0f8a3a8382e0b0386819b13aa93f728031fcfc9a7aec68b4899"),
    "value": ("native/serde_json.hepta",
        "6c3afb7d322b3c42d89727651aaae7cc1907a7766773e0bff4fdac9b11567a96",
        "1a189af4822ae3f167138f3d90277ca028f891c3b34ff2e7ce0ac50ecc2ee7f2"),
    "bulk": ("tests/hia_native/binary32_bulk.hepta",
        "d54de644fa87f6794f7b4b0c941161b9a50cee668a0ccb7298030a8607223b0f",
        "72dfa07f8781d99c7f5bce23496a5316ba8588aed87c2db4c39f24891a3b09a5"),
}
KEYS = {"binary32_json": "binary32", "typed_result_json": "typed", "request_result": "request"}
TESTS = ("test_binary32_json.py", "test_typed_result_json.py", "test_request_result.py")
CONTROL_TEST = "test_result_value_evidence.py"
DOMAINS = ("binary32", "typed", "request")
COUNTS = {"binary32": {"main": 541693}, "typed": {"probes": 2, "cases": 5249},
          "request": {"probes": 44, "cases": 1926}}
BINS = {"binary32": "hia-binary32-reference", "typed": "hia-typed-json-reference",
        "request": "hia-request-result-reference"}
REFERENCE = "tests/hia_native/result_reference"
FIXTURES = "tests/hia_native/result_value_fixtures"
SDK_MANIFEST = "native/sdk_rmcp_source_manifest.json"
SDK_MANIFEST_SHA = "5ba12f2a865b7f336fe0d798bde8422821927a2b82dd71b72082866bdeeb7e23"
OWN = [
    "native/binary32_json.hepta", "native/binary32_json_composition.json", "native/binary32_json_abi.md",
    "native/typed_result_json.hepta", "native/typed_result_json_composition.json", "native/typed_result_json_abi.md",
    "native/request_result.hepta", "native/request_result_composition.json", "native/request_result_abi.md",
    "native/result_values_qualification.md",
    "scripts/result_value_registry.py", "scripts/build_result_values.py", "scripts/hia_native_result_qualification.py",
    "scripts/hia_native_result_reference.py", "tests/hia_native/binary32_bulk.hepta",
    "tests/hia_native/result_value_fixture.py", "tests/hia_native/result_value_cases.py",
    *["tests/hia_native/" + name for name in (*TESTS, CONTROL_TEST)],
    "tests/hia_native/compare_result_values_original.py", "tests/hia_native/check_result_value_evidence.py",
    *[REFERENCE + "/" + name for name in ("binary32.rs", "typed_result.rs", "request_result.rs", "json_size.rs",
        "Cargo.toml", "Cargo.lock", "original-runtime.lock", "rustfmt.toml", "crate-sources.json", "source-projection.json")],
    FIXTURES + "/manifest.json",
    *[FIXTURES + "/" + domain + "-" + name + ".jsonl.gz" for domain, values in COUNTS.items() for name in values],
]
COMMON = [
    "scripts/hia_native_build.py", "scripts/hia_native_loader.py", "scripts/generate_hia_transport.py",
    "scripts/hia_native_public_registry_qualification.py", "scripts/public_registry_registry.py",
    "native/text_budget.hepta", "native/client_context.hepta", "native/directory_caller.hepta",
    "native/serde_json.hepta", SDK_MANIFEST, "Cargo.lock",
    "src/mcp/runtime/request_results.rs", "src/mcp/runtime/request_audit.rs", "src/mcp/server.rs", "src/utils/json_size.rs",
]
sha = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda value: (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def regular(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "not a regular source file: " + str(path))
    return path.read_bytes()


def source_pins(root):
    root = Path(root)
    return {name: sha(regular(root / name)) for name in sorted(set(OWN + COMMON))}


def sdk_sources(root):
    raw = regular(Path(root) / SDK_MANIFEST)
    require(sha(raw) == SDK_MANIFEST_SHA, "complete SDK source inventory changed")
    value = json.loads(raw)
    require(value["crate"] == "rmcp" and value["version"] == "3.4.1" and len(value["files"]) == 175,
        "complete SDK domain changed")
    return value["files"]
