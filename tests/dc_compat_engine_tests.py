# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real private journals/HTTP and owned effects; no DC service or package loads."""
import asyncio
import base64
import hashlib
import json
import os
import pathlib
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'deploy'))
from dc_compat.configuration import CompatConfig
from dc_compat.engine import Operator
from dc_compat.http_server import OperatorHTTP, strict_json
from dc_compat.journal import CallJournal
from dc_compat.registry import ToolError, text_result


class Journals(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.journal = CallJournal(self.root / 'journal')

    def tearDown(self):
        self.journal.close()
        self.temp.cleanup()

    def test_more_than_128_arbitrary_results_do_not_block_or_evict_and_restart_exact(self):
        originals = []
        for index in range(140):
            row, reused = self.journal.begin('write_file', {'path': f'own-{index}', 'content': '中文'}, str(index))
            self.assertFalse(reused)
            self.journal.executing(row['call_id'])
            self.journal.complete(row['call_id'], text_result('complete-' + str(index)))
            originals.append(self.journal.result(row['call_id']))
        self.assertEqual(self.journal.stats()['successfulCalls'], 140)
        self.journal.close()
        self.journal = CallJournal(self.root / 'journal')
        for original in originals:
            self.assertEqual(original, self.journal.result(original['call_id']))
        self.assertEqual(len(self.journal.recent(1000, 'write_file')), 140)

    def test_bound_rpc_never_reexecutes_or_changes_arguments_and_unknown_stays_unknown(self):
        row, _ = self.journal.begin('write_file', {'path': 'owned'}, 'same-rpc')
        self.journal.executing(row['call_id'])
        with self.assertRaises(ToolError):
            self.journal.begin('write_file', {'path': 'different'}, 'same-rpc')
        self.journal.close()
        self.journal = CallJournal(self.root / 'journal')
        current, reused = self.journal.begin('write_file', {'path': 'owned'}, 'same-rpc')
        self.assertTrue(reused)
        self.assertEqual(current['call_id'], row['call_id'])
        self.assertEqual(current['state'], 'unknown')

    def test_single_owner_lock_precedes_recovery_so_live_intent_is_not_changed(self):
        row, _ = self.journal.begin('write_file', {}, 'running')
        self.journal.executing(row['call_id'])
        with self.assertRaises(BlockingIOError):
            CallJournal(self.root / 'journal')
        self.assertEqual(self.journal.lookup(row['call_id'])['state'], 'executing')

    def test_full_original_binary_pages_and_large_history_preview_without_data_loss(self):
        row, _ = self.journal.begin('read_file', {'path': 'owned'}, 'large')
        original = text_result('中文' * 2500)
        self.journal.complete(row['call_id'], original)
        accumulated, offset = bytearray(), 0
        while True:
            page = self.journal.page(row['call_id'], offset, 73)
            accumulated.extend(base64.b64decode(page['data_base64'], validate=True))
            offset = page['next_offset']
            if page['eof']:
                break
        self.assertEqual(json.loads(accumulated), original)
        self.assertEqual(hashlib.sha256(accumulated).hexdigest(), page['sha256'])
        preview = self.journal.recent()[0]['output']
        self.assertTrue(preview['omitted'])
        self.assertEqual(self.journal.result(row['call_id'])['result'], original)

    def test_filter_since_history_order_and_self_exclusion(self):
        for number, name in enumerate(('read_file', 'write_file', 'get_recent_tool_calls', 'read_file')):
            row, _ = self.journal.begin(name, {'n': number}, str(number))
            self.journal.complete(row['call_id'], text_result(str(number)))
        self.assertEqual([r['args']['n'] for r in self.journal.recent(1000)], [0, 1, 3])
        self.assertEqual([r['args']['n'] for r in self.journal.recent(1, 'read_file')], [3])
        self.assertEqual(self.journal.recent(since='2999-01-01T00:00:00Z'), [])
        with self.assertRaises(ToolError): self.journal.recent(since='invalid date')

    def test_public_or_linked_state_refused(self):
        public = self.root / 'public'; public.mkdir(mode=0o755)
        with self.assertRaises(ToolError): CallJournal(public)
        linked = self.root / 'linked'; linked.mkdir(mode=0o700)
        (linked / 'calls.sqlite3').symlink_to(self.root / 'journal/calls.sqlite3')
        with self.assertRaises(ToolError): CallJournal(linked)


class Configurations(unittest.TestCase):
    def test_persistent_six_settings_allowed_roots_and_literal_command_argument(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / 'inside').mkdir()
            cfg = CompatConfig(root / 'settings', root)
            try:
                cfg.set('allowedDirectories', [str(root / 'inside')])
                self.assertEqual(cfg.resolve_path('inside/child'), root / 'inside/child')
                with self.assertRaises(ToolError): cfg.resolve_path('outside')
                (root / 'inside/link').symlink_to('/tmp')
                with self.assertRaises(ToolError): cfg.resolve_path('inside/link/escape')
                self.assertTrue(cfg.validate_command('printf "%s" sudo'))
                self.assertFalse(cfg.validate_command('/usr/bin/sudo true'))
                self.assertFalse(cfg.validate_command('echo safe; sudo true'))
                cfg.set('blockedCommands', [])
                cfg.set('fileReadLineLimit', 777)
                with self.assertRaises(ToolError): cfg.set('state_dir', '/tmp/other')
                with self.assertRaises(ToolError): cfg.set('fileWriteLineLimit', False)
            finally:
                cfg.close()
            cfg = CompatConfig(root / 'settings', root)
            self.assertEqual(cfg.get('fileReadLineLimit'), 777)
            self.assertEqual(cfg.get('blockedCommands'), [])
            cfg.close()


class Engine(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.engine = Operator(self.root / 'state', self.root, synchronous_wait=.01,
                               enable_computer=False, include_providers=False)

    async def asyncTearDown(self):
        await self.engine.close()
        self.temp.cleanup()

    async def test_any_effect_can_be_background_and_same_rpc_is_executed_once(self):
        calls = []
        async def delayed(name, arguments):
            calls.append(arguments)
            await asyncio.sleep(.04)
            (self.root / 'marker').write_text('once')
            return text_result('saved')
        self.engine.registry.add_handler({'write_file'}, delayed)
        arguments = {'path': str(self.root / 'marker'), 'content': 'once'}
        first = await self.engine.call('write_file', arguments, 'owned-rpc')
        identity = json.loads(first['content'][0]['text'])['call_id']
        self.assertEqual(json.loads((await self.engine.call('write_file', arguments, 'owned-rpc'))['content'][0]['text'])['call_id'], identity)
        await asyncio.sleep(.06)
        self.assertEqual((await self.engine.call('write_file', arguments, 'owned-rpc'))['content'][0]['text'], 'saved')
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.engine.journal.result(identity)['status'], 'completed')
        self.assertEqual(self.engine.journal.background()[0]['call_id'], identity)

    async def test_close_waits_for_real_worker_before_releasing_provider_and_journal(self):
        import threading
        entered, leave, finished = threading.Event(), threading.Event(), threading.Event()
        class Provider:
            closed = False
            def close(self):
                self.closed = True
        provider = Provider()
        self.engine.providers.append(provider)
        def slow(_name, _arguments):
            entered.set(); leave.wait(3)
            self.assertFalse(provider.closed)
            finished.set()
            return text_result('real effect finished')
        async def invoke(name, arguments):
            return await asyncio.to_thread(slow, name, arguments)
        self.engine.registry.add_handler({'write_file'}, invoke)
        await self.engine.call('write_file', {'path': 'owned', 'content': 'one'}, 'slow')
        self.assertTrue(entered.is_set())
        closing = asyncio.create_task(self.engine.close())
        await asyncio.sleep(.03)
        self.assertFalse(closing.done()); self.assertFalse(provider.closed)
        leave.set(); await closing
        self.assertTrue(finished.is_set()); self.assertTrue(provider.closed)
        # Test tearDown does not close the already released runtime a second time.
        self.engine.close = self._noop

    async def _noop(self):
        pass


class HTTP(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        engine = Operator(self.root / 'state', self.root, enable_computer=False, include_providers=False)
        self.owner = OperatorHTTP(engine, 'test-private-token')
        self.url = f'http://127.0.0.1:{self.owner.port}/mcp'
        self.session = None
        self.serial = 0
        self.rpc('initialize', {'protocolVersion': '2025-11-25', 'clientInfo': {'name': 'own-test', 'version': '1'}})

    def tearDown(self):
        self.owner.close()
        self.temp.cleanup()

    def rpc(self, method, params, identity=None, headers=None):
        self.serial += 1
        identity = identity if identity is not None else self.serial
        request = {'jsonrpc': '2.0', 'id': identity, 'method': method, 'params': params}
        values = {'Content-Type': 'application/json', 'Accept': 'application/json',
                  'X-Hepta-Runtime-Token': 'test-private-token', 'MCP-Protocol-Version': '2025-11-25'}
        if self.session: values['Mcp-Session-Id'] = self.session
        values.update(headers or {})
        with urllib.request.urlopen(urllib.request.Request(self.url, data=json.dumps(request).encode(), headers=values), timeout=5) as response:
            self.session = response.headers.get('Mcp-Session-Id', self.session)
            return json.loads(response.read())

    def test_native_proxy_real_http_pins_schema_and_serves_more_than_128_config_reads(self):
        self.assertEqual(len(self.rpc('tools/list', {})['result']['tools']), 33)
        for _ in range(135):
            result = self.rpc('tools/call', {'name': 'get_config', 'arguments': {}})['result']
            self.assertFalse(result.get('isError', False))
            self.assertEqual(result['structuredContent']['config']['provider'], 'Hepta Runtime')
        self.assertEqual(self.owner.engine.journal.stats()['successfulCalls'], 135)

    def test_auth_origin_unknown_session_and_strict_json_fail_before_effect(self):
        for headers, expected in [({'X-Hepta-Runtime-Token': 'wrong'}, 401),
                                  ({'Origin': 'https://untrusted.example'}, 403),
                                  ({'Mcp-Session-Id': 'unknown'}, 404)]:
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.rpc('tools/list', {}, headers=headers)
            self.assertEqual(error.exception.code, expected)
        with self.assertRaises(ValueError): strict_json(b'{"a":1,"a":2}')
        with self.assertRaises(ValueError): strict_json(b'{"a":NaN}')
        self.assertEqual(self.owner.engine.journal.stats()['totalToolCalls'], 0)


if __name__ == '__main__':
    unittest.main()
