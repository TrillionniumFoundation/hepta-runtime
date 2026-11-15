# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independent core regression audit: fresh private state and loopback only."""
import asyncio
import http.client
import json
import math
import pathlib
import sqlite3
import sys
import tempfile
import contextlib
import time
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'deploy'))
from dc_compat.configuration import CompatConfig
from dc_compat.engine import Operator
from dc_compat.http_server import OperatorHTTP, strict_json
from dc_compat.journal import CallJournal, encode
from dc_compat.registry import ToolError, text_result
import chatgpt_full_operator as facade
import full_operator_cancel_tests as cancel_fixture
from chatgpt_computer_operator import ComputerOperatorProxy, combined_contract
from mcp_tool_contract import ToolContract, canonical


class PersistentAudit(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_missing_established_database_refuses_instead_of_rebinding_an_old_rpc(self):
        state = self.root / 'journal'
        journal = CallJournal(state)
        original, _ = journal.begin('write_file', {'path': 'own'}, 'same-rpc')
        journal.complete(original['call_id'], text_result('original bytes'))
        journal.close()
        (state / 'calls.sqlite3').unlink()
        replacement = None
        try:
            try:
                replacement = CallJournal(state)
            except (ToolError, FileNotFoundError):
                return
            row, reused = replacement.begin('write_file', {'path': 'own'}, 'same-rpc')
            self.fail(f'established history was silently reset: reused={reused}, same_id={row["call_id"] == original["call_id"]}')
        finally:
            if replacement is not None:
                replacement.close()

    def test_missing_required_table_refuses_instead_of_silently_creating_empty_history(self):
        state = self.root / 'journal'
        journal = CallJournal(state)
        journal.begin('write_file', {'path': 'own'}, 'same-rpc')
        journal.close()
        connection = sqlite3.connect(state / 'calls.sqlite3')
        connection.execute('DROP TABLE calls')
        connection.commit()
        connection.close()
        replacement = None
        try:
            try:
                replacement = CallJournal(state)
            except (ToolError, sqlite3.DatabaseError):
                return
            self.fail('an established database with missing calls table was accepted as empty')
        finally:
            if replacement is not None:
                replacement.close()

    def test_missing_established_settings_never_relaxes_restricted_roots_to_defaults(self):
        state = self.root / 'settings'
        inside = self.root / 'inside'
        inside.mkdir()
        configuration = CompatConfig(state, self.root)
        configuration.set('allowedDirectories', [str(inside)])
        configuration.close()
        (state / 'settings.json').unlink()
        replacement = None
        try:
            try:
                replacement = CompatConfig(state, self.root)
            except (ToolError, FileNotFoundError):
                return
            try:
                replacement.resolve_path('/etc')
            except ToolError:
                pass
            else:
                self.fail('deleted restricted settings were recreated with unrestricted path access')
            self.fail('established missing settings were silently repaired')
        finally:
            if replacement is not None:
                replacement.close()

    def test_history_never_returns_payload_that_fails_original_result_integrity(self):
        journal = CallJournal(self.root / 'journal')
        try:
            row, _ = journal.begin('write_file', {'path': 'own'}, 'same-rpc')
            journal.complete(row['call_id'], text_result('genuine original'))
            forged = text_result('changed bytes')
            with journal.connection:
                journal.connection.execute('UPDATE calls SET result=? WHERE call_id=?', (encode(forged), row['call_id']))
            with self.assertRaises(ToolError):
                journal.result(row['call_id'])
            try:
                history = journal.recent()
            except ToolError:
                return
            self.assertTrue(all(item.get('output') != forged for item in history),
                            'history returned changed result bytes despite failed original digest')
        finally:
            journal.close()


class LifecycleAudit(unittest.IsolatedAsyncioTestCase):
    async def test_repeated_close_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            engine = Operator(root / 'state', root, enable_computer=False, include_providers=False)
            await engine.close()
            await engine.close()

    async def test_concurrent_close_closes_each_provider_once_and_releases_journal_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            engine = Operator(root / 'state', root, enable_computer=False, include_providers=False)
            class Provider:
                calls = 0
                async def close(self):
                    self.calls += 1
                    await asyncio.sleep(0.03)
            provider = Provider()
            engine.providers.append(provider)
            result = await asyncio.gather(engine.close(), engine.close(), return_exceptions=True)
            self.assertEqual(provider.calls, 1, 'concurrent close invoked the same provider twice')
            self.assertTrue(all(item is None for item in result), 'concurrent close raised or double-closed journal descriptors')

    async def test_failed_gui_close_still_attempts_remaining_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            engine = Operator(root / 'state', root, enable_computer=False, include_providers=False)
            closed = []
            class Provider:
                async def close(self):
                    closed.append('earlier-owned-provider')
            class FailedGUI:
                async def close(self):
                    closed.append('gui-attempt')
                    raise RuntimeError('fixture: desktop session closed during shutdown')
            engine.providers += [Provider(), FailedGUI()]
            try:
                with contextlib.suppress(RuntimeError):
                    await engine.close()
                self.assertEqual(closed, ['gui-attempt', 'earlier-owned-provider'],
                    'one GUI close error skipped the other owned providers and their children')
            finally:
                # This fixture never starts a child. Explicit cleanup also
                # permits testing a daemon which memoizes its failed close.
                engine.processes.close()
                engine.journal.close()
                engine.config.close()


class HTTPAudit(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temporary.name)
        self.engine = Operator(root / 'state', root, enable_computer=False, include_providers=False)
        self.owner = OperatorHTTP(self.engine, 'private-audit-fixture-token')
        self.quiet_errors = mock.patch.object(self.owner.server, 'handle_error', lambda *_: None)
        self.quiet_errors.start()

    def tearDown(self):
        self.owner.close()
        self.quiet_errors.stop()
        self.temporary.cleanup()

    def request(self, payload, token='private-audit-fixture-token'):
        connection = http.client.HTTPConnection('127.0.0.1', self.owner.port, timeout=3)
        try:
            raw = json.dumps(payload).encode()
            connection.request('POST', '/mcp', raw, {'Content-Type': 'application/json',
                'X-Hepta-Runtime-Token': token, 'Accept': 'application/json'})
            response = connection.getresponse()
            body = response.read()
            return response.status, json.loads(body) if body else None
        finally:
            connection.close()

    def test_malformed_initialize_params_return_protocol_error_instead_of_aborting_connection(self):
        for malformed in (None, [], 'text', False, 42):
            with self.subTest(params_type=type(malformed).__name__):
                try:
                    status, body = self.request({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': malformed})
                except (http.client.RemoteDisconnected, ConnectionError, TimeoutError) as error:
                    self.fail('malformed initialize aborted HTTP connection: ' + type(error).__name__)
                self.assertIn(status, (200, 400))
                self.assertIn('error', body)
        self.assertEqual(self.engine.journal.stats()['totalToolCalls'], 0)

    def test_non_ascii_bad_credential_is_401_not_unhandled_compare_digest_typeerror(self):
        try:
            status, _ = self.request({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}}, token='\u00e9')
        except (http.client.RemoteDisconnected, ConnectionError) as error:
            self.fail('bad credential aborted HTTP connection: ' + type(error).__name__)
        self.assertEqual(status, 401)

    def test_json_numeric_overflow_is_refused_as_nonfinite(self):
        for raw in (b'{"x":1e309}', b'{"x":-1e309}'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    strict_json(raw)


class CombinedFacadeAudit(unittest.TestCase):
    """Exercise the actual threaded stdio owner over synthetic HTTP owners."""
    def setUp(self):
        self.native = cancel_fixture.CancellationTests()
        self.compatibility = cancel_fixture.CancellationTests()
        self.native.setUp()
        self.compatibility.setUp()
        self.proxy = ComputerOperatorProxy(self.native.proxy, self.compatibility.proxy,
            combined_contract(self.native.proxy.contract, self.compatibility.proxy.contract))
        self.stream = cancel_fixture.Stream(self.proxy)
        self.stream.send(cancel_fixture.request('init', 'initialize', {
            'protocolVersion': '2025-06-18', 'capabilities': {},
            'clientInfo': {'name': 'isolated-audit', 'version': '1'}}))
        self.assertIn('result', self.stream.output.wait('init'))

    def tearDown(self):
        self.native.server.release.set()
        self.compatibility.server.release.set()
        self.stream.close()
        self.proxy.close(timeout=0)
        self.native.tearDown()
        self.compatibility.tearDown()

    def _start(self, owner, name):
        self.stream.send(cancel_fixture.request('owned-effect', params={
            'name': name, 'arguments': {'command': 'synthetic-effect'}}))
        self.assertTrue(owner.server.started.wait(2), 'synthetic child POST was not received')

    def test_cancel_maps_native_owner_id_and_frozen_session_once(self):
        self._start(self.native, 'shell_start')
        self.stream.send(cancel_fixture.cancellation('owned-effect'))
        self.stream.send(cancel_fixture.cancellation('owned-effect'))
        self.native.backend_wait(lambda: len(self.native.server.cancels) == 1)
        self.assertIn('result', self.stream.output.wait('owned-effect'))
        call = self.native.server.calls[0]
        cancel = self.native.server.cancels[0]
        self.assertNotEqual(call['request']['id'], 'owned-effect')
        self.assertEqual(cancel['request']['params'], {'requestId': call['request']['id']})
        self.assertEqual((cancel['session'], cancel['protocol']), (call['session'], call['protocol']))
        self.assertEqual(len(self.native.server.calls), 1)
        self.assertEqual(self.compatibility.server.calls, [])

    def test_cancel_maps_namespaced_compatibility_owner_once(self):
        self._start(self.compatibility, 'dc_shell_start')
        self.stream.send(cancel_fixture.cancellation('owned-effect'))
        self.compatibility.backend_wait(lambda: len(self.compatibility.server.cancels) == 1)
        self.assertIn('result', self.stream.output.wait('owned-effect'))
        call = self.compatibility.server.calls[0]
        cancel = self.compatibility.server.cancels[0]
        self.assertEqual(call['request']['params']['name'], 'shell_start')
        self.assertEqual(cancel['request']['params'], {'requestId': call['request']['id']})
        self.assertEqual((cancel['session'], cancel['protocol']), (call['session'], call['protocol']))
        self.assertEqual(self.native.server.calls, [])
        self.assertEqual(len(self.compatibility.server.calls), 1)

    def test_eof_during_posted_effect_reports_unknown_with_no_second_submission(self):
        self.compatibility.server.release_on_cancel = False
        self._start(self.compatibility, 'dc_shell_start')
        with mock.patch.object(facade, 'SHUTDOWN_TIMEOUT', 0.4):
            started = time.monotonic()
            self.stream.writer.close()
            self.stream.thread.join(2)
            self.assertFalse(self.stream.thread.is_alive(), 'stdio EOF was not bounded')
            self.assertLess(time.monotonic() - started, 1.5)
        reply = self.stream.output.wait('owned-effect')
        self.assertEqual(reply['error']['data']['outcome'], 'unknown')
        self.assertFalse(reply['error']['data']['automatic_retry'])
        self.assertEqual(len(self.compatibility.server.calls), 1)
        self.assertEqual(self.native.server.calls, [])

    def test_all_69_native_definitions_remain_canonically_exact(self):
        path = pathlib.Path(__file__).resolve().parents[1] / 'deploy/contracts/hepta-runtime-full-operator-v11.json'
        native = ToolContract(json.loads(path.read_bytes()))
        self.assertEqual(len(native.tools), 69)
        combined = combined_contract(native, self.compatibility.proxy.contract)
        for tool in native.tools:
            self.assertEqual(canonical(combined.by_name[tool['name']]), canonical(tool))


class GUIRegistryAudit(unittest.IsolatedAsyncioTestCase):
    async def test_gui_config_snapshot_and_gnome_route_compose_without_desktop_actions(self):
        from dc_compat.computer import COMPUTER_TOOLS
        from dc_compat.gnome_window_provider import GNOME_WINDOW_TOOLS
        seen = []
        class Computer:
            tool_names = frozenset(row['name'] for row in COMPUTER_TOOLS)
            def __init__(self, configuration):
                if not isinstance(configuration, dict):
                    raise TypeError('GUI construction requires a snapshot dict')
                seen.append(('computer-config', configuration['backend']))
            async def invoke(self, name, arguments):
                seen.append(('computer', name))
                if name == 'computer_capabilities':
                    return text_result('fixture capabilities', structured={'result': {
                        'features': {'window_list': False, 'window_focus': False},
                        'limitations': ['global window support absent', 'fixture retained limitation']}})
                return text_result('computer-routed')
            async def close(self):
                seen.append(('computer-close', None))
        class Windows:
            tool_names = frozenset({'computer_window'})
            def __init__(self, configuration):
                seen.append(('windows-config', configuration['profile_id']))
            async def capabilities(self):
                return {'available': True, 'features': {'window_list': True, 'window_focus': True}}
            async def invoke(self, name, arguments):
                seen.append(('windows', name))
                return text_result('gnome-routed')
            async def close(self):
                seen.append(('windows-close', None))
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch('dc_compat.computer.ComputerManager', Computer), \
                mock.patch('dc_compat.gnome_window_provider.GnomeWindowManager', Windows):
            root = pathlib.Path(temporary)
            engine = Operator(root / 'state', root, initial={
                'backend': 'portal', 'windowBackend': 'gnome-extension', 'profile_id': 'fixture-profile'},
                enable_computer=True, include_providers=False)
            try:
                definition = engine.registry._definitions['computer_window']
                self.assertEqual(definition, GNOME_WINDOW_TOOLS[0])
                result = await engine.call('computer_capabilities', {}, 'caps-rpc')
                value = result['structuredContent']['result']
                self.assertTrue(value['features']['window_list'])
                self.assertTrue(value['features']['window_focus'])
                self.assertEqual(value['limitations'], ['fixture retained limitation'])
                self.assertIn(('computer-config', 'portal'), seen)
                self.assertIn(('windows-config', 'fixture-profile'), seen)
                window = await engine.call('computer_window', {'action': 'list'}, 'windows-rpc')
                self.assertEqual(window['content'][0]['text'], 'gnome-routed')
                mouse = await engine.call('computer_mouse', {'action': 'move', 'x': 1, 'y': 2}, 'mouse-rpc')
                self.assertEqual(mouse['content'][0]['text'], 'computer-routed')
                self.assertNotIn(('computer', 'computer_window'), seen)
                self.assertNotIn(('computer', 'computer_session'), seen)
            finally:
                await engine.close()


if __name__ == '__main__':
    unittest.main()
