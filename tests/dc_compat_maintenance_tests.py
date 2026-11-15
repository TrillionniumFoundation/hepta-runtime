# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real private HTTP maintenance fencing; no production owner or GUI calls."""
import asyncio
import base64
import concurrent.futures
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deploy'))
from dc_compat.engine import Operator
from dc_compat.http_server import OperatorHTTP
from dc_compat.journal import encode
from dc_compat.registry import text_result


def value(result):
    return json.loads(result['content'][0]['text'])


class Maintenance(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hepta-maintenance-private-')
        self.root = Path(self.temporary.name)
        self.engine = Operator(self.root / 'state', self.root, synchronous_wait=.01,
            enable_computer=False, include_providers=False)
        self.release, self.started = threading.Event(), threading.Event()
        self.dispatched = []
        async def write(name, arguments):
            self.dispatched.append(arguments)
            self.started.set()
            await asyncio.to_thread(self.release.wait)
            (self.root / Path(arguments['path']).name).write_text(arguments['content'])
            return text_result('原始完整结果:' + arguments['content'])
        self.engine.registry.add_handler({'write_file'}, write)
        self.token = secrets.token_hex(24)
        self.owner = OperatorHTTP(self.engine, self.token)
        self.session = self.initialize()

    def tearDown(self):
        self.release.set()
        self.owner.close()
        self.temporary.cleanup()

    def http(self, method, path, data=None, *, headers=None, raw=None):
        options = {'Content-Type': 'application/json', 'X-Hepta-Runtime-Token': self.token}
        if headers: options.update(headers)
        if raw is None and data is not None: raw = encode(data)
        connection = http.client.HTTPConnection('127.0.0.1', self.owner.port, timeout=5)
        try:
            connection.request(method, path, body=raw, headers=options)
            response = connection.getresponse()
            body = response.read()
            result = json.loads(body) if body else None
            return response.status, result, dict(response.getheaders())
        finally:
            connection.close()

    def initialize(self):
        status, body, headers = self.http('POST', '/mcp', {'jsonrpc': '2.0', 'id': 'initialize',
            'method': 'initialize', 'params': {'protocolVersion': '2025-06-18', 'capabilities': {},
                'clientInfo': {'name': 'isolated-maintenance-fixture', 'version': '1'}}})
        self.assertEqual(status, 200); self.assertIn('result', body)
        return headers['Mcp-Session-Id']

    def call(self, name, arguments, *, session=None, identity=None):
        status, body, _ = self.http('POST', '/mcp', {'jsonrpc': '2.0', 'id': identity or uuid.uuid4().hex,
            'method': 'tools/call', 'params': {'name': name, 'arguments': arguments}},
            headers={'Mcp-Session-Id': session or self.session, 'MCP-Protocol-Version': '2025-06-18'})
        self.assertEqual(status, 200); self.assertNotIn('error', body)
        return body['result']

    def journal_count(self):
        with self.engine.journal.lock:
            return self.engine.journal.connection.execute('SELECT count(*) FROM calls').fetchone()[0]

    def pause(self):
        status, body, _ = self.http('POST', '/maintenance', {'action': 'pause'})
        self.assertEqual(status, 200); self.assertTrue(body['admission_paused'])
        self.assertRegex(body['lease'], r'^[a-f0-9]{64}$')
        return body

    def resume(self, lease):
        status, body, _ = self.http('POST', '/maintenance', {'action': 'resume', 'lease': lease})
        self.assertEqual(status, 200); self.assertFalse(body['admission_paused'])

    def await_completed(self, identity):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            receipt = self.engine.journal.result(identity)
            if receipt['status'] == 'completed': return receipt
            time.sleep(.01)
        self.fail('Own accepted fixture did not finish')

    def test_accepted_worker_finishes_while_old_and_new_sessions_are_fenced_without_intents(self):
        arguments = {'path': str(self.root / 'original.txt'), 'content': '只执行一次'}
        original = self.call('write_file', arguments, identity='bound-effect')
        identity = value(original)['call_id']
        self.assertTrue(self.started.wait(2))
        paused = self.pause()
        self.assertEqual(paused['active'], 1)
        self.assertFalse(self.release.is_set())
        self.assertEqual(len(self.dispatched), 1)
        health = self.http('GET', '/health')[1]
        self.assertFalse(health['ready']); self.assertTrue(health['admission_paused'])
        self.assertNotIn('lease', health)
        count = self.journal_count()
        new_session = self.initialize()
        for session in (self.session, new_session):
            refused = self.call('write_file', {'path': str(self.root / 'forbidden.txt'), 'content': 'never'}, session=session)
            self.assertTrue(refused['isError']); self.assertIn('no new action submitted', refused['content'][0]['text'])
        self.assertEqual(self.journal_count(), count)
        self.assertEqual(len(self.dispatched), 1)
        self.assertFalse((self.root / 'forbidden.txt').exists())
        current = value(self.call('get_tool_result', {'call_id': identity}, session=new_session))
        self.assertEqual(current['call_id'], identity); self.assertEqual(current['status'], 'executing')
        self.release.set()
        retained = self.await_completed(identity)
        expected = text_result('原始完整结果:只执行一次')
        self.assertEqual(retained['result'], expected)
        self.assertEqual((self.root / 'original.txt').read_text(), '只执行一次')
        # Maintenance reads cross the same real HTTP/session boundary but do
        # not replay the original effect or alter its retained original bytes.
        self.assertEqual(value(self.call('get_tool_result', {'call_id': identity}))['result'], expected)
        page = value(self.call('hepta_call_result_page', {'call_id': identity, 'offset': 0, 'limit': 1048576}))
        raw = base64.b64decode(page['data_base64'], validate=True)
        self.assertTrue(page['eof']); self.assertEqual(json.loads(raw), expected)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), page['sha256'])
        self.assertEqual(self.engine.journal.result(identity), retained)
        self.assertEqual(len(self.dispatched), 1)
        self.assertFalse(self.http('GET', '/health')[1]['ready'])
        self.resume(paused['lease'])
        repeated = self.call('write_file', arguments, identity='bound-effect')
        self.assertEqual(repeated, expected); self.assertEqual(len(self.dispatched), 1)
        following = self.call('write_file', {'path': str(self.root / 'resumed.txt'), 'content': 'new'}, identity='new-effect')
        self.assertNotIn('isError', following)
        self.assertEqual((self.root / 'resumed.txt').read_text(), 'new')
        self.assertEqual(len(self.dispatched), 2)
        self.assertTrue(self.http('GET', '/health')[1]['ready'])

    def test_only_exact_matching_lease_resumes_and_other_read_tools_are_fenced(self):
        paused = self.pause(); lease = paused['lease']
        status, body, _ = self.http('POST', '/maintenance', {'action': 'pause'})
        self.assertEqual(status, 409); self.assertNotIn('lease', body)
        for wrong in ('0' * 63, lease + 'x', '\u4e2d\u6587', None, [], {}, 42):
            status, body, _ = self.http('POST', '/maintenance', {'action': 'resume', 'lease': wrong})
            self.assertEqual(status, 409); self.assertNotIn('lease', body)
            self.assertTrue(self.http('GET', '/health')[1]['admission_paused'])
        before = self.journal_count()
        for name in ('who_am_i', 'ping', 'get_config', 'list_sessions'):
            reply = self.call(name, {})
            self.assertTrue(reply['isError'])
        self.assertEqual(before, self.journal_count())
        self.assertEqual(self.dispatched, [])
        self.resume(lease)
        status, _, _ = self.http('POST', '/maintenance', {'action': 'resume', 'lease': lease})
        self.assertEqual(status, 409)
        new = self.pause()
        self.assertNotEqual(new['lease'], lease)
        status, _, _ = self.http('POST', '/maintenance', {'action': 'resume', 'lease': lease})
        self.assertEqual(status, 409)
        self.resume(new['lease'])

    def test_auth_origin_host_strict_json_and_route_boundaries_cannot_pause(self):
        for headers, expected in (
            ({'X-Hepta-Runtime-Token': 'wrong'}, 401),
            ({'Host': 'external.example'}, 403),
            ({'Origin': 'https://external.example'}, 403),
            ({'Content-Type': 'text/plain'}, 415)):
            status, _, _ = self.http('POST', '/maintenance', {'action': 'pause'}, headers=headers)
            self.assertEqual(status, expected)
            self.assertFalse(self.engine._admission_paused)
        for raw in (b'[]', b'{"action":"pause","action":"resume"}', b'{"action":"pause","x":1e309}', b'{bad'):
            self.assertEqual(self.http('POST', '/maintenance', raw=raw)[0], 400)
            self.assertFalse(self.engine._admission_paused)
        for body in ({}, {'action': 'pause', 'lease': 'unexpected'}, {'action': 'resume'}, {'action': ['pause']}):
            self.assertEqual(self.http('POST', '/maintenance', body)[0], 400)
        self.assertEqual(self.http('GET', '/maintenance')[0], 404)
        self.assertEqual(self.http('DELETE', '/maintenance')[0], 404)
        self.assertEqual(self.journal_count(), 0)
        self.assertFalse(self.engine._admission_paused)
        self.assertEqual(self.dispatched, [])

    def test_concurrent_pause_has_one_private_lease_and_post_ack_effects_never_enter_journal(self):
        barrier = threading.Barrier(6)
        def pause_once(_):
            barrier.wait(3)
            return self.http('POST', '/maintenance', {'action': 'pause'})[:2]
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as workers:
            replies = list(workers.map(pause_once, range(6)))
        successful = [body for status, body in replies if status == 200]
        self.assertEqual(len(successful), 1)
        self.assertEqual(sum(status == 409 for status, _ in replies), 5)
        self.assertTrue(all('lease' not in body for status, body in replies if status != 200))
        session = self.initialize()
        before = self.journal_count()
        def effect(index):
            return self.call('write_file', {'path': str(self.root / f'blocked-{index}'), 'content': str(index)},
                session=self.session if index % 2 else session)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as workers:
            replies = list(workers.map(effect, range(18)))
        self.assertTrue(all(reply.get('isError') is True for reply in replies))
        self.assertEqual(self.journal_count(), before)
        self.assertFalse(list(self.root.glob('blocked-*')))
        self.assertEqual(self.dispatched, [])
        self.resume(successful[0]['lease'])


if __name__ == '__main__': unittest.main()
