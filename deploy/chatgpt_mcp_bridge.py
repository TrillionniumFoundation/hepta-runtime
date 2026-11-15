#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Compatibility entry point for the read-only ChatGPT MCP bridge.

The self-contained deployment source lives in ``readonly-bridge/bridge.py``.
Keep imports and command-line use of this original repository path working
without maintaining a second copy of the implementation.
"""
from pathlib import Path as _Path

_implementation = _Path(__file__).resolve().parent / "readonly-bridge" / "bridge.py"
# Use this module's namespace so existing imports and patches of its globals
# keep the same behavior; the implementation owns the command-line entry point.
exec(compile(_implementation.read_bytes(), str(_implementation), "exec"), globals())
