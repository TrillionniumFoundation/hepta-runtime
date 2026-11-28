#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Build a source-pinned standalone research crate; use real Rust dependencies."""

import argparse
import hashlib
import json
import shutil
import tomllib
from pathlib import Path


NATIVE_PINS = {
    "src/mcp/weight_norm.rs": "db63a69fa37768d6d55eb600a4b4dc8a2f1e46471ab2db077da98d5d50119084",
    "src/mcp/weight_norm_tests.rs": "ca09167591244fc16ae76b78e4165ed626d7b2774cfc9162ac2093407d0c11ed",
    "src/mcp/weight_tensor.rs": "318efe7eae126cc567457eaf42b9269bef5fcadbdebb52c988bd8bd437c6bad9",
    "Cargo.lock": "1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    repo = args.source_repo.resolve()
    study = repo / "qualification/weight_program_composition_20261120"
    out = args.out.resolve()
    if out.exists():
        raise SystemExit("standalone output must be absent; no existing build is overwritten")
    inputs = {}
    for path, expected in NATIVE_PINS.items():
        data = (repo / path).read_bytes()
        if digest(data) != expected:
            raise SystemExit(f"native source pin mismatch: {path}")
        inputs[path] = data
    # These are literal, unchanged source declarations and the real decoder.
    # No SDK shim, mock arithmetic, substituted macro or runtime owner is created.
    tensor = inputs["src/mcp/weight_tensor.rs"].decode()
    start = tensor.index("#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]")
    end = tensor.index("\n#[derive", start + 1)
    declaration = tensor[start:end]
    start = tensor.index("pub(super) fn unhex(text: &str)")
    end = tensor.index("\nfn width(", start)
    decoder = tensor[start:end]
    header = """// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact original ExactElementEdit declaration and unhex decoder extraction.
//! Uses the real schemars crate directly; rmcp only reexports that same crate.
//! File admission, artifact ownership and their tests are outside this crate.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

"""
    target = out / "src/mcp"
    target.mkdir(parents=True)
    (target / "weight_tensor.rs").write_text(header + declaration + "\n" + decoder)
    (target / "weight_norm.rs").write_bytes(inputs["src/mcp/weight_norm.rs"])
    shutil.copyfile(repo / "src/mcp/weight_norm_tests.rs", target / "weight_norm_tests.rs")
    for name in ("composition.rs", "composition_tests.rs"):
        shutil.copyfile(study / name, target / name)
    code_header = """// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
"""
    (out / "src/lib.rs").write_text(
        code_header + "//! Isolated executable research tests; no production library routes.\n\n"
        + "#[cfg(test)]\nmod mcp;\n"
    )
    (target / "mod.rs").write_text(
        code_header + "//! Reused native arithmetic and the pure composition study.\n\n"
        + "mod weight_norm;\n"
        + '#[path = "composition.rs"]\nmod weight_program_composition;\n'
        + "mod weight_tensor;\n"
    )
    lock = tomllib.loads(inputs["Cargo.lock"].decode())
    names = ("anyhow", "serde", "serde_json", "sha2", "schemars")
    packages = {p["name"]: p for p in lock["package"] if p["name"] in names}
    if set(packages) != set(names):
        raise SystemExit("reference lockfile does not contain the complete dependency set")
    lines = [
        "[package]", 'name = "hepta-weight-program-composition-study"',
        'version = "0.1.0"', 'edition = "2021"', 'rust-version = "1.95"',
        'license = "Apache-2.0"', "", "[dependencies]",
    ]
    for name in names:
        version = packages[name]["version"]
        if name == "serde":
            lines.append(f'{name} = {{ version = "={version}", features = ["derive"] }}')
        elif name == "serde_json":
            lines.append(f'{name} = {{ version = "={version}", features = ["float_roundtrip"] }}')
        else:
            lines.append(f'{name} = "={version}"')
    lines += ["", "[profile.dev]", "debug = 0", "opt-level = 1", "overflow-checks = true", ""]
    (out / "Cargo.toml").write_text("\n".join(lines))
    standalone_lock = (study / "Cargo.standalone.lock").read_bytes()
    standalone_packages = tomllib.loads(standalone_lock.decode())["package"]
    reference_packages = {
        (p["name"], p["version"], p.get("checksum")) for p in lock["package"]
    }
    for package in standalone_packages:
        if package.get("source") and (
            package["name"], package["version"], package.get("checksum")
        ) not in reference_packages:
            raise SystemExit("standalone dependency differs from the reference lockfile")
    (out / "Cargo.lock").write_bytes(standalone_lock)
    (out / "rustfmt.toml").write_text("hard_tabs = true\nmax_width = 100\n")
    receipt = {
        "schema": "hepta.weight.composition.standalone-source.v1",
        "base_commit": "d3d75c30719db966b004756f610007a7c723729e",
        "unchanged_native_norm_sha256": digest((target / "weight_norm.rs").read_bytes()),
        "exact_tensor_declaration_sha256": digest(declaration.encode()),
        "exact_decoder_sha256": digest(decoder.encode()),
        "dependencies_from_reference_lock": packages,
        "all_resolved_versions_and_checksums_match_reference": True,
        "standalone_lock_sha256": digest(standalone_lock),
        "sdk_or_arithmetic_shims": False,
        "full_runtime_compiled": False,
        "file_admission_or_ownership_tested": False,
        "rust_tests_executed": False,
    }
    (out / "SOURCE_EXTRACTION.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"prepared": str(out), "native_norm_byte_identical": True,
                      "dependency_resolution_or_tests_executed": False}))


if __name__ == "__main__":
    main()
