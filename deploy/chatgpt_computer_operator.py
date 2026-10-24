#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Compose retained Hepta controllers with an independent computer-use owner.

Existing definitions and routes remain exact. DC-compatible tools are namespaced
dc_ because read_multiple_files already has a different native Hepta schema.
Only the independent owner executes these tools; no DC process is contacted.
"""
from __future__ import annotations
import argparse
import copy
import json
import pathlib
import sys

from chatgpt_full_operator import (ActiveRequest, MAX_ACTIVE_REQUESTS, MODERN_VERSION,
    NativeProxy, error, private_token, request_era, valid_request)
from chatgpt_v11_layered_read import LayeredReadNativeProxy
from mcp_tool_contract import ToolContract, make_contract


COMPUTER_READS = frozenset(('computer_capabilities', 'computer_screenshot',
    'hepta_call_result_page', 'get_tool_result', 'list_devices',
    'list_remote_tool_calls', 'ping', 'who_am_i'))


def normalized_tools(tools):
    """Make conservative transport hints explicit without changing input schemas."""
    result = copy.deepcopy(tools)
    for tool in result:
        hints = tool.setdefault('annotations', {})
        read = hints.setdefault('readOnlyHint', tool['name'] in COMPUTER_READS)
        hints.setdefault('destructiveHint', not read)
        hints.setdefault('idempotentHint', read)
        hints.setdefault('openWorldHint', True)
    return result


class CompatibilityContract(ToolContract):
    def verify(self, tools):
        super().verify(normalized_tools(tools))


def combined_contract(native, compatibility):
    tools = copy.deepcopy(native.tools)
    for definition in compatibility.tools:
        tool = copy.deepcopy(definition)
        if not tool['name'].startswith('computer_') and tool['name'] != 'hepta_call_result_page':
            tool['name'] = 'dc_' + tool['name']
        tools.append(tool)
    return ToolContract(make_contract(tools))


class ComputerOperatorProxy(NativeProxy):
    def __init__(self, native, compatibility, contract):
        super().__init__('http://127.0.0.1:1/mcp', 'unused-composition-token', contract)
        expected = combined_contract(native.contract, compatibility.contract)
        if expected.catalog_sha256 != contract.catalog_sha256:
            raise ValueError('reviewed combined contract does not match both owners')
        self.native, self.compatibility = native, compatibility

    def _reserve(self, request, remember=False):
        # Modern IDs can be reused after completion. Legacy session IDs keep
        # lifetime digests without a 4096-request ceiling; durable owner call
        # records remain separate from these transport correlation IDs.
        remember = remember and request_era(request)[0] != 'modern'
        ident = request['id']; key = (type(ident), ident)
        with self._active_lock:
            if self._closing.is_set():
                return None, error(ident, -32603, 'Facade input is closing', outcome='not_submitted', automatic_retry=False)
            if key in self._active or (remember and self._identity_digest(ident) in self._retired):
                return None, error(ident, -32600, 'Request identity has already been used', outcome='not_submitted', automatic_retry=False)
            active_limit = getattr(self, 'active_request_limit', MAX_ACTIVE_REQUESTS)
            if active_limit is not None and len(self._active) >= active_limit:
                return None, error(ident, -32603, 'Facade active request limit reached', outcome='not_submitted', automatic_retry=False)
            context = ActiveRequest(request, self._owner, remember)
            self._active[key] = context
            return context, None

    def _schedule_cancel(self, context):
        with self._active_lock:
            child = getattr(context, 'child_request', None)
        if child is not None:
            proxy, request = child
            # A delayed parent cancellation must not target a newer child that
            # has legitimately reused the completed modern request's ID.
            with proxy._active_lock:
                if proxy._active.get(request.key) is request and not request.completed:
                    proxy._cancel_active({'requestId': request.ident})

    def _child(self, proxy, request, context):
        child, refused = proxy._reserve(request)
        if refused is not None:
            return refused
        try:
            if context is not None:
                with self._active_lock:
                    context.child_request = (proxy, child)
                    if context.cancel_requested or self._closing.is_set():
                        child.cancel_requested = True
                    # A parent EOF must never describe an outstanding child
                    # effect as definitely unsubmitted. Only its final reply
                    # can establish that result.
                    context.transmitting = True
            return proxy.dispatch(request, child)
        finally:
            proxy._finish(child)
            if context is not None:
                with self._active_lock:
                    context.child_request = None

    def _dispatch(self, request, context=None):
        invalid = valid_request(request, self.contract)
        if invalid is not None:
            return invalid
        method, ident = request['method'], request.get('id')
        era, version = request_era(request)
        if era == 'unsupported':
            return error(ident, -32022, 'Unsupported protocol version', supported=[MODERN_VERSION], requested=version)
        if era == 'invalid':
            return error(ident, -32602, 'Modern MCP request requires object clientCapabilities')
        if method.startswith('notifications/'):
            if method == 'notifications/cancelled':
                self._cancel_active(request['params'])
            return None
        if method == 'initialize' and era == 'modern':
            return error(ident, -32601, 'Modern MCP uses server/discover')
        if method == 'server/discover' and era != 'modern':
            return error(ident, -32601, 'Modern MCP discovery requires protocol metadata')
        if era == 'legacy' and method != 'initialize' and not self.legacy_ready:
            return error(ident, -32071, 'Legacy MCP initialization required before tool calls')
        if context is not None and (context.cancel_requested or self._closing.is_set()):
            return self._not_submitted(context, era)
        self.contract.verify_integrity()
        if method in ('initialize', 'server/discover', 'tools/list', 'ping'):
            for proxy in (self.native, self.compatibility):
                reply = self._child(proxy, request, context)
                if not isinstance(reply, dict) or 'error' in reply:
                    return reply
            if method == 'initialize':
                self.legacy_ready = True
                value = dict(reply['result'])
                value['serverInfo'] = {'name': 'hepta-runtime-full-operator', 'version': self.contract.catalog_sha256[:16]}
                value['capabilities'] = {'tools': {'listChanged': False}}
            elif method == 'server/discover':
                value = {'supportedVersions': [MODERN_VERSION], 'capabilities': {'tools': {'listChanged': False}}, 'cacheScope': 'private', 'ttlMs': 0}
            elif method == 'tools/list':
                value = {'tools': self.contract.tools, 'cacheScope': 'private', 'ttlMs': 0}
            else:
                value = {}
            return self._modern_result(ident, value) if era == 'modern' else {'jsonrpc': '2.0', 'id': ident, 'result': value}
        if method == 'tools/call':
            name = request['params']['name']
            routed = copy.deepcopy(request)
            if self.native.contract.allows(name):
                proxy = self.native
            else:
                proxy = self.compatibility
                if name.startswith('dc_'):
                    routed['params']['name'] = name[3:]
            reply = self._child(proxy, routed, context)
            if era == 'modern' and isinstance(reply, dict) and isinstance(reply.get('result'), dict):
                return self._modern_result(ident, reply['result'])
            return reply
        return error(ident, -32601, 'Unsupported method')

    def close(self, timeout=2.5):
        self.native.close(timeout=0)
        self.compatibility.close(timeout=0)
        super().close(timeout=timeout)


def add_proxy_arguments(parser, *, stdio=False):
    """Shared explicit custody arguments; HTTP adds its own listener/auth options."""
    if stdio:
        parser.add_argument('--stdio', required=True, action='store_true')
    for prefix in ('', 'legacy-', 'predecessor-', 'computer-'):
        for name in ('upstream', 'token-file', 'contract', 'contract-sha256'):
            parser.add_argument('--' + prefix + name, required=True)
    for name in ('legacy-state', 'predecessor-state', 'native-state', 'combined-contract', 'combined-contract-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--retained-backends-current', action='store_true')
    parser.add_argument('--legacy-route-contract')
    parser.add_argument('--legacy-route-contract-sha256')
    parser.add_argument('--acknowledge-full-operator', required=True, action='store_true')
    return parser


def build_proxy(args):
    """Create the same reviewed composition without starting any transport."""
    load = lambda p: ToolContract.load(getattr(args, p + 'contract'), getattr(args, p + 'contract_sha256'))
    current = getattr(args, 'retained_backends_current', False)
    route_path = getattr(args, 'legacy_route_contract', None)
    route_sha = getattr(args, 'legacy_route_contract_sha256', None)
    if bool(route_path) != bool(route_sha) or current != bool(route_path):
        raise ValueError('current retained backends require one explicitly pinned original routing contract')
    original_route = ToolContract.load(route_path, route_sha) if current else None
    native = LayeredReadNativeProxy(args.upstream, private_token(args.token_file), load(''),
        args.legacy_upstream, private_token(args.legacy_token_file), load('legacy_'), args.legacy_state,
        args.predecessor_upstream, private_token(args.predecessor_token_file), load('predecessor_'),
        args.predecessor_state, args.native_state, retained_backends_current=current,
        original_route_contract=original_route)
    compatibility = NativeProxy(args.computer_upstream, private_token(args.computer_token_file),
        CompatibilityContract.load(args.computer_contract, args.computer_contract_sha256), timeout=38)
    return ComputerOperatorProxy(native, compatibility,
        ToolContract.load(args.combined_contract, args.combined_contract_sha256))


def main():
    parser = add_proxy_arguments(argparse.ArgumentParser(description=__doc__), stdio=True)
    args = parser.parse_args()
    proxy = build_proxy(args)
    proxy.serve(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == '__main__':
    main()
