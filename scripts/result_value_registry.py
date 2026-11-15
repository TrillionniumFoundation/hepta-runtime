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
        "12c13ecc1cfa4bdfebf34fca69e990740f1a3c4d76e947d551f32e818fe7e341",
        "63ac7956f61f1df83014dd4bee7b750776ab21e79e05e32f38471e680b046457"),
    "typed": ("native/typed_result_json.hepta",
        "a9dfe2fec3f35b2ef2bcfaec56229007c75301cccb06a96a36691dc361aa0bec",
        "fdf581b95d1dfd7d73004807bbc43a797a5353555326ff809c4acd02b6207f68"),
    "request": ("native/request_result.hepta",
        "7bd290ed707687eb764603f62b6d9104b75154f7c6a1189512cf149a00ae2f73",
        "2b76e9668d2f426070b1b3891a460bfd8de3dc2425e2ab324dc19665dc8abddc"),
    "value": ("native/serde_json.hepta",
        "ef9dd3a567acf523257c4245c022b8cefa9b3ddb83075e826f129b1a1f341d18",
        "d57ad9ee16270929bbaac78219c7ac54e3ad2ab64de2e6a4fe3f29236706f22c"),
    "bulk": ("tests/hia_native/binary32_bulk.hepta",
        "df23c57ee37d75f7862fe8716f46d2dbb5f640301265486142fad38636aea3c0",
        "053e29dc4efaf7ffca382100fe4e950d4602b0d61151bc35eee9e321d45a5117"),
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
