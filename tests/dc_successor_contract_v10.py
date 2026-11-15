#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Reviewed V10 full catalog approval before any historical v4 projection.

The immutable legacy loader retains historical V5..V9 behavior. V10 approval
requires the independently reviewed exact file digest, all 62 V9 definitions,
and exactly four new operation definitions. Tool counts never approve a catalog.
Projection is returned only after full 66-tool verification, for old regression.
"""
import hashlib
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
LEGACY_LOADER_SHA256 = "0b039e2d667314fec32bde7827fd0f9ad01d35b8d3199e73a1e036c7b1eb3dde"
TOOL_HELPER_SHA256 = "e2b29f987d3aaa863d7bf6879d0d6a835a807c133c5c355b6a4e69bce9c3e216"
V10_SHA256 = "12994454084369fb31e44f0e1ceb7a7f2ace5bbed33057789399cf895e70d553"
V10_OPERATION_ADDITIONS = {"operation_start", "operation_status", "operation_result", "operation_cancel"}


def digest(path):
    path = pathlib.Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("ordinary reviewed input required")
    return hashlib.sha256(path.read_bytes()).hexdigest()


if digest(ROOT / "tests/dc_successor_contract.py") != LEGACY_LOADER_SHA256:
    raise ValueError("immutable legacy approval loader drift")
if digest(ROOT / "deploy/mcp_tool_contract.py") != TOOL_HELPER_SHA256:
    raise ValueError("reviewed tool helper drift")
sys.path.insert(0, str(ROOT / "deploy"))
from mcp_tool_contract import ToolContract

_spec = importlib.util.spec_from_file_location("_hepta_immutable_approval_v9", ROOT / "tests/dc_successor_contract.py")
_legacy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_legacy)
V4_SHA256 = _legacy.V4_SHA256
V5_SHA256 = _legacy.V5_SHA256
V6_SHA256 = _legacy.V6_SHA256
V7_SHA256 = _legacy.V7_SHA256
V8_SHA256 = _legacy.V8_SHA256
V9_SHA256 = _legacy.V9_SHA256
frozen = _legacy.frozen


def verify_successor(tools, path):
    if digest(path) != V10_SHA256:
        return _legacy.verify_successor(tools, path)
    reviewed = ToolContract.load(path, V10_SHA256)
    reviewed.verify(tools)  # Verify the entire actual catalog, never a projection.
    previous_path = ROOT / "deploy/contracts/hepta-runtime-full-operator-v9.json"
    previous = ToolContract.load(previous_path, V9_SHA256)
    _legacy.verify_successor(previous.tools, previous_path)
    assert set(reviewed.by_name) - set(previous.by_name) == V10_OPERATION_ADDITIONS
    assert set(previous.by_name) <= set(reviewed.by_name)
    assert all(reviewed.by_name[name] == definition for name, definition in previous.by_name.items())
    assert len(tools) == len(reviewed.by_name) == 66
    baseline = frozen(4, V4_SHA256)
    return [tool for tool in tools if tool["name"] in baseline.by_name]
