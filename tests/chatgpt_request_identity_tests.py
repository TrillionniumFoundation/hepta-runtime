#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Request IDs are live correlation keys for modern MCP, not effect deduplication.

The pipe tests use the real serve reader/writer and private fixture HTTP owners.
They never touch the desktop, installed services, or Desktop Commander.
"""
import copy
import json
import os
import pathlib
import select
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'deploy'))
import chatgpt_full_operator as F
from chatgpt_computer_operator import (CompatibilityContract, ComputerOperatorProxy,
    combined_contract, normalized_tools)
from dc_compat.engine import Operator
from dc_compat.http_server import OperatorHTTP
from dc_compat.registry import ToolRegistry, text_result
from mcp_tool_contract import ToolContract, canonical, make_contract


def definition(name):
    return {'name': name, 'description': 'Count one private fixture action.',
        'inputSchema': {'type': 'object', 'properties': {'marker': {'type': 'string'}},
                        'required': ['marker'], 'additionalProperties': False},
        'annotations': {'readOnlyHint': False, 'destructiveHint': True,
                        'idempotentHint': False, 'openWorldHint': False}}


def request(ident=1, *, modern=True, method='ping', params=None):
    value = copy.deepcopy(params or {})
    if modern:
        value['_meta'] = {F.VERSION_KEY: F.MODERN_VERSION, F.CAPABILITIES_KEY: {}}
    return {'jsonrpc': '2.0', 'id': ident, 'method': method, 'params': value}


class IdentityRules:
    """Exercise the remember=True path which only real serve used previously."""
    composed = False

    def setUp(self):
        contract = ToolContract(make_contract([definition('fixture_effect')]))
        self.native = F.NativeProxy('http://127.0.0.1:1/mcp', 'fixture', contract)
        self.compatibility = None
        if self.composed:
            compatibility = CompatibilityContract(make_contract(normalized_tools([
                definition('compat_effect')])))
            self.compatibility = F.NativeProxy('http://127.0.0.1:1/mcp', 'fixture', compatibility)
            self.proxy = ComputerOperatorProxy(self.native, self.compatibility,
                combined_contract(contract, compatibility))
        else:
            self.proxy = self.native

    def tearDown(self):
        self.proxy.close(timeout=0)

    def reserve(self, ident=1, modern=True):
        context, refused = self.proxy._reserve(request(ident, modern=modern), remember=True)
        self.assertIsNone(refused, refused)
        self.assertIsNotNone(context)
        return context

    def test_completed_modern_identity_can_be_reused(self):
        for _ in range(3):
            context = self.reserve('request-1')
            self.assertTrue(self.proxy._finish(context))

    def test_integer_and_string_identities_are_distinct_while_active_and_retired(self):
        integer = self.reserve(1, modern=False)
        string = self.reserve('1', modern=False)
        self.assertIsNot(integer, string)
        self.proxy._finish(integer)
        self.proxy._finish(string)
        self.assertEqual(len(self.proxy._retired), 2)
        for ident in (1, '1'):
            context, refused = self.proxy._reserve(request(ident, modern=False), remember=True)
            self.assertIsNone(context)
            self.assertIn('error', refused)

    def test_legacy_completed_identity_still_refuses_reuse(self):
        context = self.reserve('legacy', modern=False)
        self.proxy._finish(context)
        context, refused = self.proxy._reserve(request('legacy', modern=False), remember=True)
        self.assertIsNone(context)
        self.assertEqual(refused['error']['data']['outcome'], 'not_submitted')
        self.assertFalse(refused['error']['data']['automatic_retry'])

    def test_completed_modern_request_does_not_retire_a_legacy_identity(self):
        context = self.reserve('shared')
        self.proxy._finish(context)
        self.assertNotIn(self.proxy._identity_digest('shared'), self.proxy._retired)
        context = self.reserve('shared', modern=False)
        self.proxy._finish(context)

    def test_mixed_versions_do_not_confuse_retired_legacy_and_new_modern(self):
        context = self.reserve('shared', modern=False)
        self.proxy._finish(context)
        for _ in range(2):
            context = self.reserve('shared')
            self.proxy._finish(context)
        context, refused = self.proxy._reserve(request('shared', modern=False), remember=True)
        self.assertIsNone(context)
        self.assertIn('error', refused)

    def test_active_identity_still_refuses_duplicate_including_mixed_versions(self):
        for first_modern in (False, True):
            context = self.reserve(('modern' if first_modern else 'legacy'), first_modern)
            for next_modern in (False, True):
                duplicate, refused = self.proxy._reserve(
                    request(context.ident, modern=next_modern), remember=True)
                self.assertIsNone(duplicate)
                self.assertEqual(refused['error']['code'], -32600)
            self.proxy._finish(context)

    def test_cancellation_selects_the_exact_active_id_type_and_native_mapping(self):
        contexts = []
        child_contexts = []
        for ident in (1, '1'):
            value = request(ident, method='tools/call', params={
                'name': 'fixture_effect', 'arguments': {'marker': str(type(ident))}})
            context, refused = self.proxy._reserve(value, remember=True)
            self.assertIsNone(refused)
            contexts.append(context)
            if self.composed:
                child, refused = self.native._reserve(value)
                self.assertIsNone(refused)
                context.child_request = (self.native, child)
                child_contexts.append(child)
            else:
                child = context
            child.native_id = 'upstream-integer' if type(ident) is int else 'upstream-string'
            child.binding = ('fixture-session', '2025-11-25')
            child.posted = True
        forwarded = []
        def exchange(value, **kwargs):
            forwarded.append((value, kwargs['binding'], kwargs['cancellation']))
        with mock.patch.object(self.native, 'exchange', side_effect=exchange):
            self.proxy._cancel_active({'requestId': 1})
            deadline = time.monotonic() + 2
            while not forwarded and time.monotonic() < deadline:
                time.sleep(.005)
        self.assertEqual(len(forwarded), 1)
        self.assertEqual(forwarded[0][0]['params'], {'requestId': 'upstream-integer'})
        self.assertEqual(forwarded[0][1], ('fixture-session', '2025-11-25'))
        self.assertIs(forwarded[0][2], child_contexts[0] if self.composed else contexts[0])
        self.assertTrue(contexts[0].cancel_requested)
        self.assertFalse(contexts[1].cancel_requested)
        self.assertFalse((child_contexts if self.composed else contexts)[1].cancel_requested)
        for context in child_contexts:
            self.native._finish(context)
        for context in contexts:
            self.proxy._finish(context)


class NativeIdentityTests(IdentityRules, unittest.TestCase):
    pass


class ComputerIdentityTests(IdentityRules, unittest.TestCase):
    composed = True

    def test_stale_parent_child_mapping_cannot_cancel_reused_child_identity(self):
        value = request('reused-child', method='tools/call', params={
            'name': 'fixture_effect', 'arguments': {'marker': 'fixture'}})
        parent_a, refused = self.proxy._reserve(value, remember=True)
        self.assertIsNone(refused)
        child_a, refused = self.native._reserve(value)
        self.assertIsNone(refused)
        parent_a.child_request = (self.native, child_a)
        self.native._finish(child_a)
        self.proxy._finish(parent_a)
        parent_b, refused = self.proxy._reserve(value, remember=True)
        self.assertIsNone(refused)
        child_b, refused = self.native._reserve(value)
        self.assertIsNone(refused)
        parent_b.child_request = (self.native, child_b)
        with mock.patch.object(self.native, '_cancel_active', wraps=self.native._cancel_active) as cancel:
            self.proxy._schedule_cancel(parent_a)
            cancel.assert_not_called()
        self.assertFalse(parent_b.cancel_requested)
        self.assertFalse(child_b.cancel_requested)
        self.assertIs(self.native._active[child_b.key], child_b)
        self.native._finish(child_b)
        self.proxy._finish(parent_b)

    def test_current_parent_child_mapping_still_cancels_active_child_once(self):
        value = request('current-child', method='tools/call', params={
            'name': 'fixture_effect', 'arguments': {'marker': 'fixture'}})
        parent, refused = self.proxy._reserve(value, remember=True)
        self.assertIsNone(refused)
        child, refused = self.native._reserve(value)
        self.assertIsNone(refused)
        parent.child_request = (self.native, child)
        with mock.patch.object(self.native, '_cancel_active', wraps=self.native._cancel_active) as cancel:
            self.proxy._cancel_active({'requestId': parent.ident})
            cancel.assert_called_once_with({'requestId': child.ident})
        self.assertTrue(parent.cancel_requested)
        self.assertTrue(child.cancel_requested)
        self.native._finish(child)
        self.proxy._finish(parent)


class RecordingNativeProxy(F.NativeProxy):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tool_requests = []
        self.drop_next_result = False

    def exchange(self, value, *args, **kwargs):
        if value['method'] == 'tools/call':
            self.tool_requests.append(copy.deepcopy(value))
        result = super().exchange(value, *args, **kwargs)
        if value['method'] == 'tools/call' and self.drop_next_result:
            self.drop_next_result = False
            raise ConnectionError('Fixture result lost after exactly one durable action')
        return result


class LiveStdio:
    def __init__(self, proxy):
        incoming, self.writer = os.pipe()
        self.reader, outgoing = os.pipe()
        self.input_stream = os.fdopen(incoming, 'rb', buffering=0)
        self.output_stream = os.fdopen(outgoing, 'wb', buffering=0)
        self.worker = threading.Thread(target=proxy.serve,
            args=(self.input_stream, self.output_stream), daemon=True)
        self.worker.start()
        self.buffer = bytearray()

    def call(self, value):
        payload = canonical(value) + b'\n'
        self.assert_complete_write(payload)
        deadline = time.monotonic() + 5
        while b'\n' not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.reader], [], [], remaining)[0]:
                raise AssertionError('Real serve response deadline')
            raw = os.read(self.reader, 65536)
            if not raw:
                raise AssertionError('Real serve output closed before response')
            self.buffer.extend(raw)
        raw, _, rest = self.buffer.partition(b'\n')
        self.buffer = bytearray(rest)
        return json.loads(raw)

    def assert_complete_write(self, payload):
        if os.write(self.writer, payload) != len(payload):
            raise AssertionError('Incomplete fixture pipe request')

    def close(self):
        os.close(self.writer)
        self.worker.join(5)
        try:
            if self.worker.is_alive():
                raise AssertionError('Real serve did not shut down after input EOF')
        finally:
            self.input_stream.close()
            self.output_stream.close()
            os.close(self.reader)


class StdioIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.endpoints = []
        self.streams = []
        self.proxies = []

    def tearDown(self):
        for stream in reversed(self.streams):
            stream.close()
        for proxy in self.proxies:
            proxy.close(timeout=0)
        for engine, server in reversed(self.endpoints):
            server.close()
        self.tmp.cleanup()

    def endpoint(self, name, compatibility=False):
        root = pathlib.Path(self.tmp.name)
        engine = Operator(root / name, root, enable_computer=False, include_providers=False)
        tool = definition(name)
        engine.registry = ToolRegistry([tool])
        effects = []
        def effect(_name, args):
            effects.append(args['marker'])
            return text_result(json.dumps({'marker': args['marker'], 'sequence': len(effects)}))
        engine.registry.add_handler([name], effect)
        server = OperatorHTTP(engine, 'fixture-' + name)
        self.endpoints.append((engine, server))
        contract_type = CompatibilityContract if compatibility else ToolContract
        tools = normalized_tools([tool]) if compatibility else [tool]
        proxy = RecordingNativeProxy(f'http://127.0.0.1:{server.port}/mcp',
            'fixture-' + name, contract_type(make_contract(tools)), timeout=2)
        self.proxies.append(proxy)
        return engine, proxy, effects

    def stream(self, proxy):
        stream = LiveStdio(proxy)
        self.streams.append(stream)
        return stream

    def assert_call(self, stream, name, marker, sequence, ident='tool-call'):
        reply = stream.call(request(ident, method='tools/call', params={
            'name': name, 'arguments': {'marker': marker}}))
        self.assertNotIn('error', reply, reply)
        self.assertEqual(reply['id'], ident)
        self.assertEqual(json.loads(reply['result']['content'][0]['text']),
                         {'marker': marker, 'sequence': sequence})

    def assert_independent_records(self, engine, proxy, effects, expected):
        self.assertEqual(effects, expected)
        requests = proxy.tool_requests
        self.assertEqual(len(requests), len(expected))
        native_ids = [value['id'] for value in requests]
        self.assertEqual(len(set(native_ids)), len(expected))
        self.assertTrue(all(value.startswith('hepta-call-') for value in native_ids))
        with engine.journal.lock:
            rows = list(engine.journal.connection.execute('SELECT call_id,rpc_key,state FROM calls'))
        self.assertEqual(len(rows), len(expected))
        self.assertEqual(len({row['call_id'] for row in rows}), len(expected))
        self.assertTrue(all(row['state'] == 'completed' for row in rows))
        self.assertEqual({row['rpc_key'].rsplit(':', 1)[-1] for row in rows}, set(native_ids))

    def test_native_real_serve_reuses_completed_id_without_caching_the_old_action(self):
        engine, proxy, effects = self.endpoint('native_effect')
        stream = self.stream(proxy)
        self.assert_call(stream, 'native_effect', 'first', 1)
        self.assert_call(stream, 'native_effect', 'second', 2)
        self.assert_independent_records(engine, proxy, effects, ['first', 'second'])

    def test_composed_real_serve_reuses_one_id_for_native_and_compatibility_actions(self):
        native_engine, native, native_effects = self.endpoint('native_effect')
        compat_engine, compat, compat_effects = self.endpoint('compat_effect', compatibility=True)
        combined = ComputerOperatorProxy(native, compat, combined_contract(native.contract, compat.contract))
        self.proxies.append(combined)
        stream = self.stream(combined)
        self.assert_call(stream, 'native_effect', 'native-first', 1)
        self.assert_call(stream, 'native_effect', 'native-second', 2)
        self.assert_call(stream, 'dc_compat_effect', 'compat-first', 1)
        self.assert_call(stream, 'dc_compat_effect', 'compat-second', 2)
        self.assert_independent_records(native_engine, native, native_effects, ['native-first', 'native-second'])
        self.assert_independent_records(compat_engine, compat, compat_effects, ['compat-first', 'compat-second'])

    def test_real_serve_mixed_versions_preserve_legacy_retirement_and_modern_reuse(self):
        _, proxy, _ = self.endpoint('native_effect')
        stream = self.stream(proxy)
        for _ in range(2):
            self.assertIn('result', stream.call(request('shared', method='server/discover')))
        init = request('shared', modern=False, method='initialize', params={
            'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {}})
        self.assertIn('result', stream.call(init))
        refused = stream.call(init)
        self.assertEqual(refused['error']['data']['outcome'], 'not_submitted')
        self.assertIn('result', stream.call(request('shared', method='server/discover')))
        refused = stream.call(init)
        self.assertEqual(refused['error']['data']['outcome'], 'not_submitted')

    def test_unknown_native_effect_result_is_not_automatically_replayed(self):
        self._unknown_effect(composed=False)

    def test_unknown_composed_compat_effect_result_is_not_automatically_replayed(self):
        self._unknown_effect(composed=True)

    def _unknown_effect(self, composed):
        engine, target, effects = self.endpoint('compat_effect' if composed else 'native_effect',
                                                 compatibility=composed)
        proxy = target
        name = 'native_effect'
        if composed:
            _, native, _ = self.endpoint('native_effect')
            proxy = ComputerOperatorProxy(native, target, combined_contract(native.contract, target.contract))
            self.proxies.append(proxy)
            name = 'dc_compat_effect'
        target.drop_next_result = True
        stream = self.stream(proxy)
        reply = stream.call(request('uncertain', method='tools/call', params={
            'name': name, 'arguments': {'marker': 'exactly-once-unconfirmed'}}))
        self.assertEqual(reply['error']['data']['outcome'], 'unknown')
        self.assertFalse(reply['error']['data']['automatic_retry'])
        time.sleep(.05)
        self.assert_independent_records(engine, target, effects, ['exactly-once-unconfirmed'])
        self.assertFalse(select.select([stream.reader], [], [], .05)[0])


if __name__ == '__main__':
    unittest.main()
