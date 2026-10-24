#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Latest binaries in retained namespaces: exact69 attestation, original custody."""
import copy
import types
import unittest
from unittest import mock

import chatgpt_v11_layered_read_tests as historic_routes
import chatgpt_v11_v4_session_binding_tests as historic_sessions
import chatgpt_computer_operator as C
from mcp_tool_contract import ToolContract, make_contract

L = historic_routes.L


class CurrentBackendRouting(historic_routes.LayeredRouting):
    """Run all23 historic custody/cancel/no-replay fixtures with upgraded catalogs."""
    def adapter(self, contract=None, *, legacy=None, predecessor=None, route=None):
        current = self.contracts['v11']
        return L.LayeredReadNativeProxy('http://127.0.0.1:8792/mcp', 'native-fixture', contract or current,
            'http://127.0.0.1:8790/mcp', 'v4-fixture', legacy or current, self.roots['v4'],
            'http://127.0.0.1:8791/mcp', 'predecessor-fixture', predecessor or current,
            self.roots['predecessor'], self.roots['native'], retained_backends_current=True,
            original_route_contract=route or self.contracts['v4'])

    def test_all_backend_catalogs_are_identical69(self):
        self.assertTrue(self.proxy.retained_backends_current)
        catalogs = [self.proxy.contract, self.proxy.legacy.contract, self.proxy.predecessor.contract]
        self.assertEqual([len(c.tools) for c in catalogs], [69, 69, 69])
        self.assertEqual(len({c.catalog_sha256 for c in catalogs}), 1)
        expected = {t['name'] for t in self.contracts['v4'].tools if not t['annotations']['readOnlyHint']}
        self.assertEqual(self.proxy._original_effect_names, expected)
        self.assertEqual(len(expected), 31)

    def test_old_catalogs_cannot_be_passed_as_current_backend(self):
        with self.assertRaises(L.UnsafeProvenance):
            self.adapter(legacy=self.contracts['v4'])
        with self.assertRaises(L.UnsafeProvenance):
            self.adapter(predecessor=self.contracts['v10'])

    def test_changed_route_policy_is_refused_even_with69_backend(self):
        tools = copy.deepcopy(self.contracts['v4'].tools)
        next(t for t in tools if t['name'] == 'view')['annotations'].update(
            readOnlyHint=False, destructiveHint=True)
        with self.assertRaises(L.UnsafeProvenance):
            self.adapter(route=ToolContract(make_contract(tools)))

    def test_mutating_new_workflow_does_not_become_original_effect(self):
        # Even if workflow admission is disabled later, the newly advertised
        # legacy backend tool cannot silently become one of its31 old effects.
        self.proxy.route_v10_read_workflows = False
        response = self.call('operation_start', {'operation': {'tool': 'file_info',
            'arguments': {'host': 'main', 'path': '/fixture'}}, 'idempotency_key': 'fixture'})
        self.assertIn('error', response)
        self.assertEqual(response['error']['data']['outcome'], 'not_submitted')
        self.assertEqual(self.calls, [])

    def test_explicit_original_policy_is_required(self):
        with self.assertRaises(L.UnsafeProvenance):
            L.LayeredReadNativeProxy('http://127.0.0.1:8792/mcp', 'n', self.contracts['v11'],
                'http://127.0.0.1:8790/mcp', 'l', self.contracts['v11'], self.roots['v4'],
                'http://127.0.0.1:8791/mcp', 'p', self.contracts['v11'],
                self.roots['predecessor'], self.roots['native'], retained_backends_current=True)

    def test_factory_selects_explicit_mode_without_other_release_paths(self):
        compatibility = C.CompatibilityContract(make_contract(C.normalized_tools([{
            'name': 'computer_capabilities', 'description': 'Private unrouted fixture',
            'inputSchema': {'type': 'object'}}])))
        combined = C.combined_contract(self.contracts['v11'], compatibility)
        values = {}
        for prefix in ('', 'legacy_', 'predecessor_', 'computer_'):
            values.update({prefix + 'upstream': 'http://127.0.0.1:' + {
                '': '8792', 'legacy_': '8790', 'predecessor_': '8791', 'computer_': '8794'}[prefix] + '/mcp',
                prefix + 'token_file': 'private-fixture-token', prefix + 'contract': prefix + 'catalog',
                prefix + 'contract_sha256': 'a' * 64})
        values.update(legacy_state=self.roots['v4'], predecessor_state=self.roots['predecessor'],
            native_state=self.roots['native'], combined_contract='combined',
            combined_contract_sha256='b' * 64, retained_backends_current=True,
            legacy_route_contract='route', legacy_route_contract_sha256='c' * 64)
        def load(path, digest):
            return (self.contracts['v4'] if path == 'route' else combined if path == 'combined'
                    else compatibility if path == 'computer_catalog' else self.contracts['v11'])
        with mock.patch.object(C.ToolContract, 'load', side_effect=load), \
                mock.patch.object(C, 'private_token', return_value='private-fixture'):
            proxy = C.build_proxy(types.SimpleNamespace(**values))
        self.addCleanup(proxy.close)
        self.assertTrue(proxy.native.retained_backends_current)
        self.assertEqual(len(proxy.native.legacy.contract.tools), 69)
        self.assertEqual(proxy.native._original_effect_names, self.proxy._original_effect_names)


class CurrentBackendSessionBinding(historic_sessions.SessionBinding):
    """Run real loopback session/workdir/undo/unknown-write fixtures with69×3."""
    def setUp(self):
        super().setUp()
        original_policy = self.v4.contract
        current = self.v11.contract
        roots = [self.base / name for name in ('v4-state', 'v10-state', 'v11-state')]
        self.proxy.close()
        for server in self.servers:
            server.contract = current
        def url(server):
            return 'http://127.0.0.1:' + str(server.server_port) + '/mcp'
        self.proxy = L.LayeredReadNativeProxy(url(self.v11), 'fixture-v11', current,
            url(self.v4), 'fixture-v4', current, roots[0], url(self.v10), 'fixture-v10', current,
            roots[1], roots[2], retained_backends_current=True, original_route_contract=original_policy)


if __name__ == '__main__':
    unittest.main()
