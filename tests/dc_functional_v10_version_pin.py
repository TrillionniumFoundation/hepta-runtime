#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""V10 reviewed helper closure; no subprocess, network or controller effects."""
import hashlib
import pathlib

V10_SHA256 = "12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553"
V9_SHA256 = "3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761"
HELPER_PINS = {
    "tests/dc_successor_contract_v10.py": "4623c4da9493dccfc4bcef18c7267ba96ba7f5f1ddd799441214948c9da161fe",
    "tests/dc_successor_contract.py": "0b039e2d667314fec32bde7827fd0f9ad01d35b8d3199e73a1e036c7b1eb3dde",
    "deploy/mcp_tool_contract.py": "e2b29f987d3aaa863d7bf6879d0d6a835a807c133c5c355b6a4e69bce9c3e216",
    "tests/runtime_http_acceptance.py": "8b7ee206ccfc7978ac4abdf3eac3ddb8f7e7c36d053f601b5cfcb66f52fb8dba",
}


def verify_import_pins(root):
    for relative, pin in HELPER_PINS.items():
        path = pathlib.Path(root) / relative
        if not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != pin:
            raise ValueError("reviewed V10 helper closure differs: " + relative)
    return dict(HELPER_PINS)
