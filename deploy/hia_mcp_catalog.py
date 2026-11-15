#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Freeze the registered HIA contract and verify an actual native tools/list.

The HIA-only contract is an explicit 11-tool allowlist for consumers that select
this family. It does not replace the full-operator facade's whole-catalog pin or
publish additional tools through the separate public gateway policy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from mcp_tool_contract import ANNOTATIONS, ToolContract, canonical, make_contract

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "src/mcp/hia_tool_catalog.json"
TOOL_NAMES = frozenset({
    "hia_describe", "hia_artifact", "hia_read", "hia_context", "hia_inspect",
    "hia_candidate", "hia_verify", "hia_emit", "hia_evaluate", "hia_adopt", "hia_rollback",
})


def registered_tools():
    catalog = json.loads(CATALOG_PATH.read_bytes())
    tools = catalog["tools"]
    if len(tools) != len(TOOL_NAMES) or {tool["name"] for tool in tools} != TOOL_NAMES:
        raise ValueError("HIA registry and exact reviewed allowlist differ")
    result = []
    for tool in tools:
        definition = dict(tool)
        definition["title"] = tool["name"].replace("_", " ").upper()
        result.append(definition)
    return result


def native_tools(value):
    if isinstance(value, dict) and "result" in value:
        value = value["result"]
    if isinstance(value, dict):
        value = value.get("tools")
    if not isinstance(value, list):
        raise ValueError("An actual tools/list result is required")
    return value


def verify_native(value):
    actual = [tool for tool in native_tools(value) if str(tool.get("name", "")).startswith("hia_")]
    if len(actual) != len(TOOL_NAMES) or {tool.get("name") for tool in actual} != TOOL_NAMES:
        raise ValueError("Actual native HIA registration differs from the exact allowlist")
    expected = {tool["name"]: tool for tool in registered_tools()}
    for tool in actual:
        required = expected[tool["name"]]
        for key in ("name", "title", "description", "inputSchema", "outputSchema"):
            if tool.get(key) != required[key]:
                raise ValueError(f"Actual HIA {tool['name']} {key} differs from its reviewed definition")
        if any(tool.get("annotations", {}).get(key) != required["annotations"][key] for key in ANNOTATIONS):
            raise ValueError(f"Actual HIA {tool['name']} operation annotations differ")
    return actual


def freeze():
    result = make_contract(registered_tools())
    result["name"] = "Hepta HIA Agent Native Tools"
    result["execution_backend"] = "Pinned HIA worker through the existing native durable process owner"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-tools", type=Path, help="Actual tools/list JSON to verify before freezing")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.native_tools:
        verify_native(json.loads(args.native_tools.read_bytes()))
    contract = freeze()
    ToolContract(contract).verify_integrity()
    payload = json.dumps(contract, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(payload)
    print(json.dumps({"contract_file_sha256": hashlib.sha256(payload).hexdigest(),
                      "contract_catalog_sha256": contract["catalog_sha256"],
                      "hia_catalog_file_sha256": hashlib.sha256(CATALOG_PATH.read_bytes()).hexdigest(),
                      "tool_count": len(TOOL_NAMES),
                      "actual_native_catalog_verified": args.native_tools is not None}, sort_keys=True))


if __name__ == "__main__":
    main()
