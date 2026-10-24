#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""V9-only explicit helper pins; no controller, subprocess or network execution."""
import hashlib
import pathlib
import re

V9_SHA256 = "3eb628812d0c70b9af8393ecf9d0ce47f69b1438a134148f75ae2dd3132e6761"
V8_SHA256 = "b64769210b9913fbdab28f7d0e95b7ef300d8710b3f1eeea74afcfac25b08318"

def digest(path):
    path = pathlib.Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("ordinary reviewed helper required")
    return hashlib.sha256(path.read_bytes()).hexdigest()

def add_helper_pins(parser, *, existing_loader=False, existing_tool_helper=False):
    if not existing_loader:
        parser.add_argument("--expected-loader-sha256", "--expected-approval-loader-sha256",
                            dest="expected_loader_sha256", required=True)
    if not existing_tool_helper:
        parser.add_argument("--expected-tool-helper-sha256", required=True)
    parser.add_argument("--expected-http-helper-sha256", required=True)
    parser.add_argument("--expected-version-helper-sha256", required=True)

def verify_helper_pins(args, root):
    paths = {
        "tests/dc_successor_contract.py": args.expected_loader_sha256,
        "deploy/mcp_tool_contract.py": args.expected_tool_helper_sha256,
        "tests/runtime_http_acceptance.py": args.expected_http_helper_sha256,
        "tests/dc_functional_v9_version_pin.py": args.expected_version_helper_sha256,
    }
    for relative, pin in paths.items():
        if not re.fullmatch("[0-9a-f]{64}", pin) or digest(root / relative) != pin:
            raise ValueError("explicit reviewed V9 helper pin differs: " + relative)
    return paths
