#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Verify an explicitly reviewed full successor before projecting frozen v4 tools.

The v7 credential metadata descriptions are approved by an exact file digest.
That branch never relaxes the historical v6 requirement that all v5 definitions
remain exact, nor accepts an unknown self-consistent catalog by its tool count.
"""
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
from mcp_tool_contract import ToolContract

ADDITIONS = {"host_health", "read_multiple_files", "search_start", "search_results", "search_list", "search_stop"}
AUDIT_CONFIG_ADDITIONS = {"effective_config", "request_history"}
V7_OWNERSHIP_CHANGED = {"request_history", "search_start", "search_results", "search_list", "search_stop"}
V4_SHA256 = "d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1"
V5_SHA256 = "f3fd365ae69e1189c550c4314c4fdfb12f4c80d8cc86d1bc0aca6bd1bf7c4cba"
V6_SHA256 = "de23cec290a0c22d248575c92b656d2a194a8306b85cc92b68aedea4fe0db3c8"
V7_SHA256 = "8ad53842e4aa41bbd1567ed99e956088baafea108b6fb0b9a8df979c72c794cc"
REVIEWED_SUCCESSORS = {V5_SHA256: 5, V6_SHA256: 6, V7_SHA256: 7}

def frozen(version, digest):
    return ToolContract.load(ROOT / f"deploy/contracts/hepta-runtime-full-operator-v{version}.json", digest)

def verify_successor(tools, path):
    successor = pathlib.Path(path)
    digest = hashlib.sha256(successor.read_bytes()).hexdigest()
    version = REVIEWED_SUCCESSORS.get(digest)
    if version is None:
        raise ValueError("Unreviewed successor contract digest; explicit version review required")
    contract = ToolContract.load(successor, digest)
    contract.verify(tools)
    baseline = frozen(4, V4_SHA256)
    expected = ADDITIONS if version == 5 else ADDITIONS | AUDIT_CONFIG_ADDITIONS
    assert set(contract.by_name) - set(baseline.by_name) == expected, "unexpected successor additions"
    assert len(contract.tools) == (56 if version == 5 else 58), "unexpected successor tool count"
    assert all(contract.by_name[name] == value for name, value in baseline.by_name.items()), "v4 definition drift"
    if version == 6:
        v5 = frozen(5, V5_SHA256)
        assert all(contract.by_name[name] == value for name, value in v5.by_name.items()), "v5 definition drift"
    elif version == 7:
        v6 = frozen(6, V6_SHA256)
        assert set(contract.by_name) == set(v6.by_name), "v7 name drift"
        assert all(contract.by_name[name] == value for name, value in v6.by_name.items()
                   if name not in V7_OWNERSHIP_CHANGED), "unreviewed v7 predecessor definition drift"
    return [tool for tool in tools if tool["name"] in baseline.by_name]
