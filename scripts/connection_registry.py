# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Frozen source and image identities for the bounded public SDK connection owner."""
from pathlib import Path
import hashlib

COMPILER = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
COMPILER_IMAGE = "bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0"
TESTS = ("test_sdk_message.py", "test_sdk_transport.py", "test_sdk_connection.py",
         "test_sdk_connection_elf.py", "test_sdk_connection_controls.py")
FOLDERS = ("message", "transport", "connection", "elf", "controls")
MODULES = {
    "message": ("sdk_message", "serde-json.v1", "d84d399a78e428a3505bd14258b0fb5a50cde46753551ff85703ac9094ba795d",
                "99237bf6998d9bdcc48de5209a4a9aa6d0b8b1149d4af3f13d3bc60937c9de31"),
    "connection": ("sdk_connection", "history.v1", "8bb5612e877d2dc8ad2e184d1cfff17f280a334e06b0e9e5d5dbffaca3b55f61",
                   "dbe1cfbba16e008cc8f607faf03d2b68252064f569c354a24545c1cb079b9b3f"),
    "fixture": ("sdk_default_fixture", "history.v1", "52548bf8b328389fdc3c76939e9bd974208042f0e75841bf4e5d939022428dad",
                "eaea40429f8b1a4f4200c62b70ee5331337445af7f92565e39b3e456903d08d9"),
    "packer": ("sdk_connection_packer", "standard", "27c7cdba8ca1dfd6a059e33d47807113cca90a31945fab3718d2785c0df3e11f",
               "957c8f4f6949d41751fa5dce5164d807f134c22cb6affda8390549aa625b2b96"),
}
ELF_SHA = "13fda11fb59719c8192a4509e1f1e7cd6a081e8f0f4f194ad7886b8bbfb1a5f0"
ELF_BYTES = 760766
PREFIX_SHA = "d4cbb017d55981de5bef9692a105c2ce2d1cadeea100cfb08b971145b0c72063"
PREFIX_BYTES = 1113
CALL_HOLES = (502, 646, 800)
ADAPTER_SHA = "9a2abaa8d89ed6cb44718c5e2e05bb3db1f3c4f5d159dbeae2499470c5759013"
OWN = [
    *["native/" + name + ".hepta" for name, _, _, _ in MODULES.values()],
    *["native/" + name + "_composition.json" for name in ("sdk_message", "sdk_connection", "sdk_default_fixture")],
    "native/sdk_connection_abi.md", "native/sdk_connection_scope.md",
    "scripts/connection_registry.py", "scripts/sdk_connection_adapter.S", "scripts/build_connection_fixture.py",
    "scripts/build_native_connection.py", "scripts/hia_native_connection_qualification.py", "scripts/hia_native_connection_reference.py",
    "tests/hia_native/connection_test_context.py", *["tests/hia_native/" + name for name in TESTS],
    "tests/hia_native/check_sdk_connection_evidence.py", "tests/hia_native/compare_sdk_connection_original.py",
    "tests/hia_native/connection_reference_cases.json", "tests/hia_native/connection_reference_cases.tar.gz",
    *["tests/hia_native/connection_reference/" + name for name in (
        "Cargo.toml", "Cargo.lock", "original-runtime.lock", "rustfmt.toml", "source-identity.json",
        "oracle_connection_context.rs", "oracle_message_decode.rs", "oracle_transport_decode.rs", "generated_get_info.rs")],
]
DEPENDENCIES = ["scripts/hia_native_build.py", "scripts/hia_native_loader.py", "scripts/generate_hia_transport.py",
                "native/serde_json.hepta", "native/text_budget.hepta", "Cargo.toml", "Cargo.lock", "src/mcp/server.rs"]


def source_pins(root):
    result = {}
    for name in OWN + DEPENDENCIES:
        path = Path(root) / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("connection source is not a regular file: " + name)
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result
