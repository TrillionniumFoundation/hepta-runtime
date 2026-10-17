#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Ephemeral loopback HTTP fixtures; no real controller, credential, GUI or host."""
import concurrent.futures
import copy
import errno
import http.client
import json
import pathlib
import subprocess
import socket
import struct
import sys
import threading
import time
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'deploy'))
import chatgpt_computer_http as HTTP
from chatgpt_computer_http import ComputerHTTPServer
from chatgpt_computer_operator import ComputerOperatorProxy, combined_contract
from chatgpt_full_operator import (CAPABILITIES_KEY, MODERN_VERSION, VERSION_KEY,
                                  NativeProxy, canonical, request_era)
from mcp_tool_contract import ToolContract, make_contract
from runtime_registry_page import RuntimeRegistryPager

TOKEN = 'private-fixture-token'


def tool(name):
    return {'name': name, 'description': 'isolated fixture',
            'inputSchema': {'type': 'object'},
            'annotations': {'readOnlyHint': True, 'destructiveHint': False,
                            'idempotentHint': True, 'openWorldHint': False}}


NATIVE = ToolContract(make_contract([tool('host_list')] + [tool('native_' + str(i)) for i in range(68)]))
COMPUTER = ToolContract(make_contract([tool('computer_capabilities')] + [tool('compat_' + str(i)) for i in range(40)]))
COMBINED = combined_contract(NATIVE, COMPUTER)


def request(method, identity=1, *, modern=False, params=None):
    value = {'jsonrpc': '2.0', 'method': method, 'params': copy.deepcopy(params or {})}
    if not method.startswith('notifications/'):
        value['id'] = identity
    if modern:
        value['params']['_meta'] = {VERSION_KEY: MODERN_VERSION, CAPABILITIES_KEY: {},
                                  'fixture:opaque': {'preserved': True}}
    return value


def call(identity, label, *, modern=False, barrier=None):
    return request('tools/call', identity, modern=modern,
                   params={'name': 'host_list', 'arguments': {'label': label, 'barrier': barrier}})


class Controller:
    def __init__(self):
        self.lock = threading.Lock()
        self.counts = {}
        self.started = {}
        self.releases = {}
        self.barriers = {}
        self.active = 0
        self.peak = 0
        self.proxies = []

    def run(self, context, params):
        args = params['arguments']
        label = args['label']
        with self.lock:
            self.counts[label] = self.counts.get(label, 0) + 1
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.started.setdefault(label, threading.Event()).set()
        cancelled = False
        try:
            barrier = self.barriers.get(args.get('barrier'))
            if barrier is not None:
                barrier.wait(timeout=12)
            release = self.releases.get(label)
            if release is not None:
                deadline = time.monotonic() + 12
                while not release.wait(.005):
                    if context.cancel_requested:
                        cancelled = True
                        break
                    if time.monotonic() > deadline:
                        raise TimeoutError('fixture_release_timeout')
            return {'content': [{'type': 'text', 'text': json.dumps({
                'label': label, 'cancel_intent_seen': cancelled,
                'seen_meta': params.get('_meta')})}], 'isError': False}
        finally:
            with self.lock:
                self.active -= 1

    def wait_started(self, label):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with self.lock:
                event = self.started.get(label)
            if event is not None and event.wait(.01):
                return
            time.sleep(.005)
        raise AssertionError('fixture_not_started')

    def factory(self):
        controller = self

        class Backend(NativeProxy):
            def _schedule_cancel(self, context):
                # The real facade's exact child object mapping is exercised;
                # this backend observes intent without any native HTTP call.
                return

            def _dispatch(self, value, context=None):
                method, ident = value['method'], value.get('id')
                era, _ = request_era(value)
                if method == 'initialize':
                    self.legacy_ready = True
                    result = {'protocolVersion': value['params'].get('protocolVersion', '2025-11-25'),
                              'serverInfo': {'name': 'fixture', 'version': '1'},
                              'capabilities': {'tools': {}}}
                elif method == 'server/discover':
                    result = {'supportedVersions': [MODERN_VERSION], 'capabilities': {'tools': {}},
                              'cacheScope': 'private', 'ttlMs': 0}
                elif method == 'tools/list':
                    result = {'tools': self.contract.tools, 'cacheScope': 'private', 'ttlMs': 0}
                elif method == 'ping':
                    result = {}
                elif method == 'tools/call':
                    result = controller.run(context, value['params'])
                else:
                    return None
                return self._modern_result(ident, result) if era == 'modern' else {
                    'jsonrpc': '2.0', 'id': ident, 'result': result}

        native = Backend('http://127.0.0.1:1/mcp', 'unused', NATIVE)
        native.legacy = Backend('http://127.0.0.1:1/mcp', 'unused', NATIVE)
        native.predecessor = Backend('http://127.0.0.1:1/mcp', 'unused', NATIVE)
        compatibility = Backend('http://127.0.0.1:1/mcp', 'unused', COMPUTER)
        proxy = ComputerOperatorProxy(native, compatibility, COMBINED)
        self.proxies.append(proxy)
        return proxy


class Fixture(unittest.TestCase):
    def setUp(self):
        self.control = Controller()
        self.server = ComputerHTTPServer(('127.0.0.1', 0), self.control.factory, TOKEN)
        self.worker = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01})
        self.worker.start()
        self.port = self.server.server_port

    def tearDown(self):
        for release in self.control.releases.values():
            release.set()
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=3)

    def http(self, value=None, *, sid=None, token=TOKEN, method='POST', path='/mcp', headers=None, raw=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=18)
        body = raw if raw is not None else (canonical(value) if value is not None else b'')
        selected = {'Content-Type': 'application/json'}
        if token is not None:
            selected['X-Hepta-Runtime-Token'] = token
        if sid is not None:
            selected['Mcp-Session-Id'] = sid
        selected.update(headers or {})
        try:
            connection.request(method, path, body, selected)
            response = connection.getresponse()
            data = response.read()
            result = json.loads(data) if data and response.getheader('Content-Type', '').startswith('application/json') else data
            return response.status, dict(response.getheaders()), result
        finally:
            connection.close()

    def initialize(self):
        status, headers, body = self.http(request('initialize', params={
            'protocolVersion': '2025-11-25', 'capabilities': {},
            'clientInfo': {'name': 'isolated-http-fixture', 'version': '1'}}))
        self.assertEqual(status, 200)
        self.assertIn('result', body)
        sid = headers['Mcp-Session-Id']
        self.assertEqual(self.http(request('notifications/initialized'), sid=sid)[0], 202)
        return sid

    def payload(self, reply):
        self.assertEqual(reply[0], 200, reply)
        return json.loads(reply[2]['result']['content'][0]['text'])

    def test_auth_401_and_origin_never_dispatch(self):
        for token in (None, 'wrong', 'é'):
            self.assertEqual(self.http(call(1, 'forbidden', modern=True), token=token)[0], 401)
        self.assertEqual(self.http(call(1, 'forbidden', modern=True),
                        headers={'Origin': 'https://untrusted.invalid'})[0], 403)
        self.assertEqual(self.control.counts, {})

    def test_address_reuse_keeps_the_live_listener_exclusive(self):
        other = None
        try:
            with self.assertRaises(OSError) as raised:
                other = ComputerHTTPServer(('127.0.0.1', self.port),
                                           self.control.factory, TOKEN)
            self.assertEqual(raised.exception.errno, errno.EADDRINUSE)
        finally:
            if other is not None:
                other.server_close()

    def test_closed_server_time_wait_allows_immediate_rebind(self):
        # Read through EOF so the server is the active closer. Merely reading
        # Content-Length and closing the client could leave TIME_WAIT only on
        # the client port and would not exercise the observed restart failure.
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as peer:
            peer.sendall((
                'GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n'
                'X-Hepta-Runtime-Token: ' + TOKEN + '\r\n'
                'Connection: close\r\n\r\n').encode('ascii'))
            response = bytearray()
            while block := peer.recv(65536):
                response.extend(block)
        self.assertTrue(response.startswith(b'HTTP/1.1 200 '), response[:128])
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=3)
        self.assertFalse(self.worker.is_alive())
        if sys.platform.startswith('linux'):
            # Observe the actual kernel state before attempting the new bind.
            port = ':' + format(self.port, '04X')
            deadline, time_wait = time.monotonic() + 1, False
            while time.monotonic() < deadline:
                with open('/proc/net/tcp', encoding='ascii') as table:
                    time_wait = any(len(parts := line.split()) > 3
                                    and parts[1].endswith(port) and parts[3] == '06'
                                    for line in table)
                if time_wait:
                    break
                time.sleep(.005)
            self.assertTrue(time_wait, 'closed server did not enter TIME_WAIT')
        replacement = ComputerHTTPServer(('127.0.0.1', self.port),
                                         self.control.factory, TOKEN)
        worker = threading.Thread(target=replacement.serve_forever,
                                  kwargs={'poll_interval': .01})
        worker.start()
        try:
            self.assertEqual(self.http(method='GET', path='/health')[0], 200)
        finally:
            replacement.shutdown()
            replacement.server_close()
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())

    def test_stateless_http_lanes_share_only_readonly_registry_snapshot(self):
        # A modern tool follow-up may run on a different HTTP worker lane.
        # Its frozen cursor must not depend on the original lane's proxy.
        with tempfile.TemporaryDirectory(prefix='hepta-http-shared-job-pages-') as folder:
            root = pathlib.Path(folder)
            old, predecessor = root/'v4', root/'v10'
            for item in (old, predecessor):
                item.mkdir(mode=0o700)
                (item/'jobs').mkdir(mode=0o700)
            for number, item in ((1,old),(2,predecessor)):
                identity=f'1a14-{number:x}-1'
                path=item/'jobs'/(identity+'.json')
                path.write_text(json.dumps({
                    'id':identity,'host':'main','created_unix_ms':number,
                    'execution_mode':'operator','launch_state':'launched',
                    'args':['PRIVATE_MUST_NOT_LEAK']}))
                path.chmod(0o600)
            def factory():
                proxy=self.control.factory()
                proxy.native.registry_pager=RuntimeRegistryPager(old,predecessor)
                return proxy
            isolated=ComputerHTTPServer(('127.0.0.1',0),factory,TOKEN)
            next_lane=None
            try:
                first=isolated._modern_idle[0].proxy
                next_lane=isolated._new_proxy()
                self.assertIsNot(first,next_lane)
                self.assertIsNot(first.native,next_lane.native)
                self.assertIsNot(first.native.legacy,next_lane.native.legacy)
                self.assertIs(first.native.registry_pager,
                              next_lane.native.registry_pager)
                first_page=first.native.registry_pager.page({'limit':1})
                next_page=next_lane.native.registry_pager.page({
                    'limit':1,'cursor':first_page['next_cursor']})
                self.assertEqual(first_page['snapshot_id'],next_page['snapshot_id'])
                self.assertEqual(first_page['total'],2)
                self.assertEqual(next_page['total'],2)
                self.assertTrue(next_page['inventory_complete'])
                self.assertNotIn('PRIVATE_MUST_NOT_LEAK',repr([first_page,next_page]))
            finally:
                if next_lane is not None:next_lane.close(timeout=0)
                isolated.server_close()

    def test_mixed_registry_state_roots_refuse_sharing_and_keep_first_cursor(self):
        with tempfile.TemporaryDirectory(prefix='hepta-http-mixed-owner-') as folder:
            root=pathlib.Path(folder)
            old,first_other,second_other=(root/x for x in ('v4','v10','v10drift'))
            for item in (old,first_other,second_other):
                item.mkdir(mode=0o700)
                (item/'jobs').mkdir(mode=0o700)
            count=[0]
            def factory():
                count[0]+=1
                proxy=self.control.factory()
                target=first_other if count[0]==1 else second_other
                proxy.native.registry_pager=RuntimeRegistryPager(old,target)
                return proxy
            isolated=ComputerHTTPServer(('127.0.0.1',0),factory,TOKEN)
            try:
                source=isolated._modern_idle[0].proxy.native.registry_pager
                first=source.page({})
                with self.assertRaisesRegex(ValueError,'readonly_registry_pager_root_mismatch'):
                    isolated._new_proxy()
                stable=source.page({})
                self.assertTrue(first['inventory_complete'])
                self.assertTrue(stable['inventory_complete'])
                self.assertEqual(count[0],2)
            finally:
                isolated.server_close()

    def test_legacy_session_110_exact_catalog_and_lifetime_ids(self):
        sid = self.initialize()
        result = self.http(request('tools/list', 2), sid=sid)
        self.assertEqual(result[2]['result']['tools'], COMBINED.tools)
        self.assertEqual(len(result[2]['result']['tools']), 110)
        self.payload(self.http(call(3, 'once'), sid=sid))
        repeat = self.http(call(3, 'never'), sid=sid)
        self.assertEqual(repeat[2]['error']['code'], -32600)
        self.assertNotIn('never', self.control.counts)
        self.assertEqual(self.http(call(4, 'no-session'))[0], 400)
        self.assertEqual(self.http(call(4, 'unknown'), sid='0' * 64)[0], 404)

    def test_different_sessions_same_id_and_modern_metadata_reuse(self):
        first, second = self.initialize(), self.initialize()
        self.assertNotEqual(first, second)
        self.payload(self.http(call(9, 'left'), sid=first))
        self.payload(self.http(call(9, 'right'), sid=second))
        modern = self.payload(self.http(call(9, 'modern-left', modern=True), sid=first))
        self.assertEqual(modern['seen_meta']['fixture:opaque'], {'preserved': True})
        self.payload(self.http(call(9, 'modern-reuse', modern=True), sid=first))

    def test_modern_discovery_catalog_and_completed_id_reuse_without_session(self):
        discover = self.http(request('server/discover', modern=True))
        self.assertEqual(discover[0], 200)
        self.assertEqual(discover[2]['result']['supportedVersions'], [MODERN_VERSION])
        result = self.http(request('tools/list', modern=True))
        self.assertEqual(result[2]['result']['tools'], COMBINED.tools)
        self.assertEqual(result[2]['result']['ttlMs'], 0)
        self.payload(self.http(call(1, 'first', modern=True)))
        self.payload(self.http(call(1, 'second', modern=True)))

    def test_same_session_64_concurrent_requests_are_not_capped_at_16(self):
        sid = self.initialize()
        self.control.barriers['parallel'] = threading.Barrier(64)
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
            results = list(pool.map(lambda n: self.http(call(100 + n, str(n), barrier='parallel'), sid=sid), range(64)))
        self.assertTrue(all(item[0] == 200 and 'result' in item[2] for item in results))
        self.assertGreaterEqual(self.control.peak, 64)
        proxy = self.control.proxies[-1]
        for item in (proxy, proxy.native, proxy.compatibility, proxy.native.legacy, proxy.native.predecessor):
            self.assertIsNone(item.active_request_limit)

    def test_32_stateless_same_ids_have_independent_concurrent_lanes(self):
        self.control.barriers['modern'] = threading.Barrier(32)
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
            results = list(pool.map(lambda n: self.http(call(1, str(n), modern=True, barrier='modern')), range(32)))
        self.assertTrue(all(item[0] == 200 and 'result' in item[2] for item in results))
        self.assertGreaterEqual(self.control.peak, 32)

    def test_active_duplicate_rejected_and_session_cancel_bound_to_exact_child(self):
        sid, other = self.initialize(), self.initialize()
        self.control.releases['cancel-me'] = threading.Event()
        self.control.releases['keep-me'] = threading.Event()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.http, call(77, 'cancel-me', modern=True), sid=sid)
            second = pool.submit(self.http, call(77, 'keep-me', modern=True), sid=other)
            self.control.wait_started('cancel-me')
            self.control.wait_started('keep-me')
            duplicate = self.http(call(77, 'must-not-run', modern=True), sid=sid)
            self.assertEqual(duplicate[2]['error']['code'], -32600)
            notification = request('notifications/cancelled', modern=True, params={'requestId': 77})
            self.assertEqual(self.http(notification, sid=sid)[0], 202)
            self.assertTrue(self.payload(first.result())['cancel_intent_seen'])
            self.assertFalse(second.done())
            self.control.releases['keep-me'].set()
            self.assertFalse(self.payload(second.result())['cancel_intent_seen'])
        self.assertNotIn('must-not-run', self.control.counts)

    def test_late_stateless_cancel_cannot_hit_reused_id(self):
        self.payload(self.http(call(5, 'old', modern=True)))
        self.control.releases['new'] = threading.Event()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.http, call(5, 'new', modern=True))
            self.control.wait_started('new')
            notify = request('notifications/cancelled', modern=True, params={'requestId': 5})
            self.assertEqual(self.http(notify)[0], 400)
            self.assertFalse(future.done())
            self.control.releases['new'].set()
            self.assertFalse(self.payload(future.result())['cancel_intent_seen'])

    def test_delete_drains_active_call_and_refuses_new_session_requests(self):
        sid = self.initialize()
        self.control.releases['active'] = threading.Event()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.http, call(2, 'active'), sid=sid)
            self.control.wait_started('active')
            self.assertEqual(self.http(method='DELETE', sid=sid, token='wrong')[0], 401)
            self.assertEqual(self.http(method='DELETE', sid=sid)[0], 200)
            self.assertEqual(self.http(call(3, 'new'), sid=sid)[0], 404)
            self.assertFalse(future.done())
            self.control.releases['active'].set()
            self.assertFalse(self.payload(future.result())['cancel_intent_seen'])
        self.assertEqual(self.control.counts['active'], 1)
        self.assertNotIn('new', self.control.counts)

    def test_shutdown_waits_for_active_modern_call_and_refuses_new_admission(self):
        self.control.releases['active'] = threading.Event()
        idle = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        idle.request('GET', '/health', headers={'X-Hepta-Runtime-Token': TOKEN})
        idle.getresponse().read()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.http, call(2, 'active', modern=True))
            self.control.wait_started('active')
            self.server.shutdown()
            close = threading.Thread(target=self.server.server_close)
            close.start()
            deadline = time.monotonic() + 3
            while not self.server.status()['closing'] and time.monotonic() < deadline:
                time.sleep(.005)
            self.assertTrue(close.is_alive())
            self.assertTrue(all(session.deleted for session, _ in self.server._modern_busy.values()))
            idle.request('POST', '/mcp', canonical(call(3, 'forbidden', modern=True)),
                         {'X-Hepta-Runtime-Token': TOKEN, 'Content-Type': 'application/json'})
            refused = idle.getresponse()
            value = json.loads(refused.read())
            self.assertEqual(refused.status, 503)
            self.assertEqual(value['error']['data']['outcome'], 'not_submitted')
            idle.close()
            self.control.releases['active'].set()
            self.assertFalse(self.payload(future.result())['cancel_intent_seen'])
            close.join(timeout=3)
            self.assertFalse(close.is_alive())
        self.assertEqual(self.control.counts['active'], 1)
        self.assertNotIn('forbidden', self.control.counts)

    def test_closed_response_does_not_replay_or_claim_effect_unsubmitted(self):
        self.control.releases['lost-response'] = threading.Event()
        raw = canonical(call(8, 'lost-response', modern=True))
        peer = socket.create_connection(('127.0.0.1', self.port), timeout=3)
        headers = ('POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n'
                   f'X-Hepta-Runtime-Token: {TOKEN}\r\nContent-Length: {len(raw)}\r\n\r\n').encode()
        peer.sendall(headers + raw)
        self.control.wait_started('lost-response')
        peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        peer.close()
        self.control.releases['lost-response'].set()
        deadline = time.monotonic() + 3
        while self.server.status()['active_requests'] and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertEqual(self.control.counts['lost-response'], 1)
        self.assertEqual(self.server.status()['response_delivery_failures'], 1)
        self.payload(self.http(call(8, 'new-independent-call', modern=True)))
        self.assertEqual(self.control.counts['lost-response'], 1)

    def test_strict_json_and_http_body_refuse_before_dispatch(self):
        for raw in (b'{"jsonrpc":"2.0","jsonrpc":"2.0"}', b'{"value":NaN}',
                    '{"x":1}'.encode('utf-16'), b'[]'):
            result = self.http(raw=raw)
            self.assertIn(result[0], (200, 400))
            self.assertIn('error', result[2])
        self.assertEqual(self.http(call(1, 'never', modern=True), headers={'Mcp-Session-Id': 'invalid'})[0], 400)
        self.assertEqual(self.control.counts, {})

    def test_response_bound_keeps_correlation_and_unknown_delivery_semantics(self):
        with mock.patch.object(HTTP, 'MAX_RESPONSE', 512):
            value = self.http(request('tools/list', 99, modern=True))
        self.assertEqual(value[0], 500)
        self.assertEqual(value[2]['id'], 99)
        self.assertEqual(value[2]['error']['data']['outcome'], 'unknown')
        self.assertFalse(value[2]['error']['data']['automatic_retry'])

    def test_legacy_protocol_header_mismatch_refuses_before_dispatch(self):
        sid = self.initialize()
        value = self.http(call(9, 'never'), sid=sid,
                          headers={'MCP-Protocol-Version': '2024-11-05'})
        self.assertEqual(value[0], 400)
        self.assertNotIn('never', self.control.counts)

    def test_real_sigterm_waits_for_once_only_effect_and_response(self):
        script = r'''
import json,pathlib,sys,time
sys.path.insert(0,sys.argv[2])
from test_computer_http import Controller,TOKEN
from chatgpt_computer_http import ComputerHTTPServer,serve
root=pathlib.Path(sys.argv[1]); control=Controller()
def run(context,params):
    with (root/'effects').open('a') as stream:stream.write('once\n')
    (root/'started').touch()
    until=time.monotonic()+10
    while not (root/'release').exists():
        if time.monotonic()>until:raise TimeoutError('fixture')
        time.sleep(.005)
    return {'content':[{'type':'text','text':'{"done":true}'}],'isError':False}
control.run=run
server=ComputerHTTPServer(('127.0.0.1',0),control.factory,TOKEN)
print(json.dumps({'port':server.server_port}),flush=True)
serve(server)
'''
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            process = subprocess.Popen([sys.executable, '-c', script, directory,
                str(pathlib.Path(__file__).resolve().parent)], stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True)
            connection = None
            try:
                port = json.loads(process.stdout.readline())['port']
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    def run():
                        nonlocal connection
                        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=12)
                        connection.request('POST', '/mcp', canonical(call(1, 'once', modern=True)),
                            {'X-Hepta-Runtime-Token': TOKEN, 'Content-Type': 'application/json'})
                        response = connection.getresponse()
                        return response.status, json.loads(response.read())
                    future = pool.submit(run)
                    deadline = time.monotonic() + 5
                    while not (root / 'started').exists() and time.monotonic() < deadline:
                        time.sleep(.01)
                    self.assertTrue((root / 'started').exists())
                    process.terminate()
                    time.sleep(.15)
                    self.assertIsNone(process.poll())
                    self.assertFalse(future.done())
                    (root / 'release').touch()
                    status, reply = future.result(timeout=5)
                    self.assertEqual(status, 200)
                    self.assertEqual(json.loads(reply['result']['content'][0]['text']), {'done': True})
                    connection.close()
                    self.assertEqual(process.wait(timeout=5), 0)
                    self.assertEqual((root / 'effects').read_text(), 'once\n')
            finally:
                (root / 'release').touch()
                if connection is not None:
                    connection.close()
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                process.stdout.close()
                process.stderr.close()


if __name__ == '__main__':
    unittest.main()
