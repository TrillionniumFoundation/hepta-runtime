# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Keep the administrator-supplied DC catalog exact and dispatch Python handlers."""
from __future__ import annotations
import copy
import inspect
import json
import pathlib

from jsonschema import Draft7Validator


class ToolError(ValueError):
    """An intentional tool-level refusal suitable for an MCP text result."""


def text_result(text, *, is_error=False, structured=None):
    result = {'content': [{'type': 'text', 'text': str(text)}]}
    if is_error:
        result['isError'] = True
    if structured is not None:
        result['structuredContent'] = structured
    return result


class ToolRegistry:
    def __init__(self, tools):
        if isinstance(tools, (str, pathlib.Path)):
            tools = json.loads(pathlib.Path(tools).read_bytes())
        if isinstance(tools, dict):
            tools = tools['tools']
        if not isinstance(tools, list) or not tools:
            raise ValueError('a nonempty exact tool catalog is required')
        self._tools = copy.deepcopy(tools)
        self._definitions, self._validators, self._handlers = {}, {}, {}
        for definition in self._tools:
            name = definition.get('name')
            if not isinstance(name, str) or not name or name in self._definitions:
                raise ValueError('invalid or duplicate tool name')
            schema = definition['inputSchema']
            Draft7Validator.check_schema(schema)
            self._definitions[name] = definition
            self._validators[name] = Draft7Validator(schema)

    def tools(self):
        return copy.deepcopy(self._tools)

    def add_handler(self, names, invoke):
        names = frozenset(names)
        if not callable(invoke) or names - self._definitions.keys() or names & self._handlers.keys():
            raise ValueError('unknown, duplicate or invalid tool handler')
        self._handlers.update({name: invoke for name in names})

    def add(self, handler):
        self.add_handler(handler.tool_names, handler.invoke)

    async def invoke(self, name, arguments):
        if name not in self._definitions:
            return text_result('Error: Unknown tool: ' + str(name), is_error=True)
        if not isinstance(arguments, dict):
            return text_result('Error: Arguments must be an object', is_error=True)
        errors = sorted(self._validators[name].iter_errors(arguments), key=lambda error: str(error.path))
        if errors:
            return text_result('Error: Invalid arguments for ' + name + ': ' + errors[0].message, is_error=True)
        handler = self._handlers.get(name)
        if handler is None:
            return text_result('Error: Compatibility handler is not configured for ' + name, is_error=True)
        try:
            value = handler(name, copy.deepcopy(arguments))
            result = await value if inspect.isawaitable(value) else value
            if not isinstance(result, dict) or not isinstance(result.get('content'), list):
                raise TypeError('handler did not return an MCP CallToolResult')
            return result
        except ToolError as error:
            return text_result('Error: ' + str(error), is_error=True)

    @property
    def implemented_tools(self):
        return frozenset(self._handlers)
