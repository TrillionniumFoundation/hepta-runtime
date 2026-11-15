# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independent Desktop Commander compatibility handlers and MCP dispatch."""
from .registry import ToolError, ToolRegistry, text_result
from .processes import ProcessManager
from .server import CompatServer

__all__ = ['CompatServer', 'ProcessManager', 'ToolError', 'ToolRegistry', 'text_result']
