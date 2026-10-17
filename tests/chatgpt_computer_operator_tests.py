import asyncio
import copy
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'deploy'))
from chatgpt_computer_operator import (CompatibilityContract, ComputerOperatorProxy,
    combined_contract, normalized_tools)
from chatgpt_full_operator import (NativeProxy, MODERN_VERSION, VERSION_KEY, CAPABILITIES_KEY)
from dc_compat.engine import Operator
from dc_compat.http_server import OperatorHTTP
from dc_compat.registry import ToolRegistry, text_result
from mcp_tool_contract import ToolContract, make_contract


class Composition(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.tmp.name)
        self.native_engine = Operator(root / 'old', root, enable_computer=False, include_providers=False)
        self.actions = []
        tool = {'name': 'native_effect', 'description': 'Fixture effect with exact original schema.',
                'inputSchema': {'type': 'object', 'properties': {'marker': {'type': 'string'}}, 'required': ['marker'], 'additionalProperties': False},
                'annotations': {'readOnlyHint': False, 'destructiveHint': True, 'idempotentHint': False, 'openWorldHint': False}}
        self.native_engine.registry = ToolRegistry([tool])
        self.native_engine.registry.add_handler(['native_effect'], lambda name, args: self.actions.append(args['marker']) or text_result(args['marker']))
        self.native_http = OperatorHTTP(self.native_engine, 'old-token')
        self.compat_engine = Operator(root / 'new', root, enable_computer=False, include_providers=False)
        self.compat_http = OperatorHTTP(self.compat_engine, 'new-token')
        native = NativeProxy(f'http://127.0.0.1:{self.native_http.port}/mcp', 'old-token', ToolContract(make_contract([tool])))
        compatibility = NativeProxy(f'http://127.0.0.1:{self.compat_http.port}/mcp', 'new-token', CompatibilityContract(make_contract(normalized_tools(self.compat_engine.registry.tools()))))
        self.proxy = ComputerOperatorProxy(native, compatibility, combined_contract(native.contract, compatibility.contract))
        self.counter = 0

    def tearDown(self):
        self.proxy.close(timeout=0)
        self.native_http.close()
        self.compat_http.close()
        self.tmp.cleanup()

    def request(self, method, params=None, modern=False):
        self.counter += 1
        params = copy.deepcopy(params or {})
        if modern:
            params['_meta'] = {VERSION_KEY: MODERN_VERSION, CAPABILITIES_KEY: {}}
        return self.proxy.dispatch({'jsonrpc': '2.0', 'id': self.counter, 'method': method, 'params': params})

    def test_legacy_combined_catalog_preserves_schema_and_namespaced_dispatch(self):
        self.assertIn('result', self.request('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {}}))
        tools = self.request('tools/list')['result']['tools']
        by_name = {row['name']: row for row in tools}
        self.assertEqual(by_name['native_effect'], self.proxy.native.contract.tools[0])
        original = self.compat_engine.registry._definitions['read_multiple_files']['inputSchema']
        self.assertEqual(by_name['dc_read_multiple_files']['inputSchema'], original)
        reply = self.request('tools/call', {'name': 'native_effect', 'arguments': {'marker': 'preserved'}})
        self.assertEqual(reply['result']['content'][0]['text'], 'preserved')
        self.assertEqual(self.actions, ['preserved'])
        reply = self.request('tools/call', {'name': 'dc_get_config', 'arguments': {}})
        self.assertIn('Current configuration:', reply['result']['content'][0]['text'])
        self.assertEqual(self.compat_engine.journal.stats()['totalToolCalls'], 1)

    def test_modern_discovery_and_server_identity_cover_all_owners(self):
        reply = self.request('server/discover', modern=True)
        self.assertEqual(reply['result']['resultType'], 'complete')
        self.assertEqual(len(self.request('tools/list', modern=True)['result']['tools']), 34)
        reply = self.request('tools/call', {'name': 'dc_ping', 'arguments': {}}, modern=True)
        self.assertIn('pong', reply['result']['content'][0]['text'])
        self.assertEqual(reply['result']['_meta']['io.modelcontextprotocol/serverInfo']['version'], self.proxy.contract.catalog_sha256[:16])

    def test_contract_drift_refuses_before_any_native_effect(self):
        self.request('server/discover', modern=True)
        self.native_engine.registry._tools[0]['description'] = 'unreviewed drift'
        reply = self.request('tools/call', {'name': 'native_effect', 'arguments': {'marker': 'must-not-run'}}, modern=True)
        self.assertIn('error', reply)
        self.assertEqual(self.actions, [])

    def test_long_connection_has_no_4096_lifetime_request_ceiling(self):
        for ident in range(4200):
            context, refused = self.proxy._reserve({'jsonrpc': '2.0', 'id': ident, 'method': 'ping'}, remember=True)
            self.assertIsNone(refused)
            self.proxy._finish(context)
        context, refused = self.proxy._reserve({'jsonrpc': '2.0', 'id': 4199, 'method': 'ping'}, remember=True)
        self.assertIsNone(context)
        self.assertEqual(refused['error']['data']['outcome'], 'not_submitted')

    def test_cancelled_before_child_submission_does_not_execute(self):
        self.request('server/discover', modern=True)
        request = {'jsonrpc': '2.0', 'id': 'cancel', 'method': 'tools/call', 'params': {'name': 'native_effect', 'arguments': {'marker': 'never'}, '_meta': {VERSION_KEY: MODERN_VERSION, CAPABILITIES_KEY: {}}}}
        context, refused = self.proxy._reserve(request)
        context.cancel_requested = True
        reply = self.proxy.dispatch(request, context)
        self.proxy._finish(context)
        self.assertEqual(reply['error']['data']['outcome'], 'not_submitted')
        self.assertEqual(self.actions, [])


if __name__ == '__main__':
    unittest.main()
