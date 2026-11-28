#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Check the research source and exact reused native helpers; execute no Rust."""

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    study = repo / "qualification/weight_program_composition_20261120"
    binding = json.loads((study / "SOURCE_BINDING.json").read_text())
    checked = []
    for entry in binding["native_sources"] + binding["research_sources"]:
        path = repo / entry["path"]
        observed = sha256(path)
        if observed != entry["sha256"]:
            raise SystemExit(f"source identity mismatch: {entry['path']}")
        checked.append({"path": entry["path"], "sha256": observed})
    module = repo / "src/mcp/mod.rs"
    observed = sha256(module)
    allowed = binding["test_registration"]
    if observed not in (allowed["original_sha256"], allowed["registered_sha256"]):
        raise SystemExit("MCP module differs from both the reference and exact test registration")
    result = {
        "schema": "hepta.weight.composition.source-readback.v1",
        "base_commit": binding["base_commit"],
        "checked_sources": checked,
        "test_module_registered": observed == allowed["registered_sha256"],
        "source_identity_verified": True,
        "rust_compilation_executed": False,
        "rust_tests_executed": False,
        "model_quality_evaluated": False,
        "production_eligible": False,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
