# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Server-assigned MCP session identity for accidental GUI interleaving guards.

This is cooperative input ownership, not an authorization boundary between
parties sharing the same full-operator credential and journal access.
"""
import contextvars

INPUT_CLIENT = contextvars.ContextVar('hepta_gui_input_client', default=None)
