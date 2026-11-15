# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Transport-neutral MCP dispatcher with a newline-delimited stdio entry point."""
from __future__ import annotations
import asyncio
import json
import sys


class CompatServer:
    def __init__(self, registry, *, name='hepta-dc-compat', version='1'):
        self.registry, self.name, self.version = registry, name, version
        self._initialized = False

    async def invoke(self, name, arguments):
        return await self.registry.invoke(name, arguments)

    async def dispatch(self, request):
        identity = request.get('id') if isinstance(request, dict) else None
        def error(code, message):
            return {'jsonrpc': '2.0', 'id': identity, 'error': {'code': code, 'message': message}}
        if (not isinstance(request, dict) or request.get('jsonrpc') != '2.0'
                or not isinstance(request.get('method'), str)):
            return error(-32600, 'Invalid Request')
        notification = 'id' not in request
        method, params = request['method'], request.get('params', {})
        if notification:
            return None
        if type(identity) not in (int, str) or not isinstance(params, dict):
            return error(-32600, 'Invalid Request')
        if method == 'initialize':
            requested = params.get('protocolVersion')
            protocol = requested if requested in ('2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25') else '2025-06-18'
            self._initialized = True
            result = {'protocolVersion': protocol, 'capabilities': {'tools': {}},
                      'serverInfo': {'name': self.name, 'version': self.version}}
        elif not self._initialized:
            return error(-32000, 'Initialize this compatibility connection first')
        elif method == 'ping':
            result = {}
        elif method == 'tools/list':
            if params.get('cursor') is not None:
                return error(-32602, 'This catalog has no continuation cursor')
            result = {'tools': self.registry.tools()}
        elif method == 'tools/call':
            if not isinstance(params.get('name'), str):
                return error(-32602, 'Tool name is required')
            try:
                result = await self.invoke(params['name'], params.get('arguments', {}))
            except Exception as exc:
                return error(-32603, 'Compatibility handler failed: ' + type(exc).__name__)
        else:
            return error(-32601, 'Method not found')
        return {'jsonrpc': '2.0', 'id': identity, 'result': result}

    async def serve_stdio(self, reader=None, writer=None):
        reader, writer = reader or sys.stdin.buffer, writer or sys.stdout.buffer
        lock = asyncio.Lock()
        tasks, seen = set(), set()
        async def handle(request):
            identity = request.get('id') if isinstance(request, dict) else None
            if isinstance(request, dict) and 'id' in request:
                key = (type(identity).__name__, str(identity))
                if key in seen:
                    response = {'jsonrpc': '2.0', 'id': identity, 'error': {'code': -32600, 'message': 'Duplicate request id; no replay'}}
                else:
                    seen.add(key)
                    response = await self.dispatch(request)
            else:
                response = await self.dispatch(request)
            if response is not None:
                raw = (json.dumps(response, ensure_ascii=False, separators=(',', ':')) + '\n').encode()
                async with lock:
                    writer.write(raw)
                    writer.flush()
        while True:
            raw = await asyncio.to_thread(reader.readline, 16 * 1024 * 1024 + 1)
            if not raw:
                break
            if len(raw) > 16 * 1024 * 1024:
                raise ValueError('MCP input exceeds the configured message bound')
            try:
                request = json.loads(raw)
            except (ValueError, UnicodeError):
                async with lock:
                    writer.write(b'{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}\n')
                    writer.flush()
                continue
            # Initialization must complete before following pipelined tool calls.
            if isinstance(request, dict) and request.get('method') == 'initialize':
                await handle(request)
            else:
                task = asyncio.create_task(handle(request))
                tasks.add(task)
                task.add_done_callback(tasks.discard)
        if tasks:
            await asyncio.gather(*tasks)
