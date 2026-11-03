# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Local capture contract tests; no real browser or external service is started."""
import base64
from collections import deque
from contextlib import contextmanager, nullcontext
import http.client
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deploy'))
from dc_compat import chromium_capture as capture
from dc_compat.chromium_pdf import ChromeProtocolError, _CDP, private_chrome
from dc_compat import chromium_pdf as pdf
from rea_browser_external import python_identity, replay_sentinels


class Connection:
    def __init__(self, messages):
        self.messages = deque(json.dumps(message) for message in messages)
        self.sent, self.closed = [], False
    def send(self, value): self.sent.append(json.loads(value))
    def recv(self): return self.messages.popleft()
    def settimeout(self, _value): pass
    def close(self, **_kwargs): self.closed = True


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def manifest(self, body=b'local before', after=b'local after', **changes):
        (self.root / 'before.bin').write_bytes(body)
        (self.root / 'after.bin').write_bytes(after)
        value = dict(schema=capture.SCHEMA, resources=[dict(url_path='/data', mime_type='application/octet-stream',
            before=dict(file='before.bin', sha256=capture.digest(body)),
            after=dict(file='after.bin', sha256=capture.digest(after)))], requests=['/data', '/data'])
        value.update(changes)
        path = self.root / 'fixture.json'
        raw = json.dumps(value).encode(); path.write_bytes(raw)
        return path, capture.digest(raw), value

    def test_bound_sources_are_captured_once_including_empty_and_binary(self):
        path, identity, _ = self.manifest(b'', b'\0\xff')
        value = capture.load_manifest(path, identity)
        (self.root / 'after.bin').write_bytes(b'changed after admission')
        self.assertEqual(value['resources']['/data']['before']['data'], b'')
        self.assertEqual(value['resources']['/data']['after']['data'], b'\0\xff')
        self.assertEqual(value['requests'], ['/data', '/data'])

    def test_wrong_manifest_and_resource_identity_refuse_before_browser(self):
        path, identity, _ = self.manifest()
        with self.assertRaisesRegex(ValueError, 'manifest SHA'):
            capture.load_manifest(path, '0' * 64)
        (self.root / 'before.bin').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'resource SHA'):
            capture.load_manifest(path, identity)

    def test_duplicate_members_symlinks_and_outside_paths_refuse(self):
        path, _, _ = self.manifest()
        raw = b'{"schema":"x","schema":"y"}'; path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            capture.load_manifest(path, capture.digest(raw))
        path, identity, _ = self.manifest()
        (self.root / 'before.bin').unlink()
        (self.root / 'before.bin').symlink_to(self.root / 'after.bin')
        with self.assertRaises(OSError): capture.load_manifest(path, identity)
        for name in ('../outside', '/outside', 'a//b', 'a/./b', 'a/../b'):
            with self.assertRaises(ValueError): capture._relative(name)

    def test_resource_request_and_encoded_output_budgets(self):
        path, identity, _ = self.manifest(b'x' * (capture.MAX_SOURCE_BYTES + 1))
        with self.assertRaisesRegex(ValueError, 'bounded regular'):
            capture.load_manifest(path, identity)
        path, identity, _ = self.manifest(requests=['/data'] * (capture.MAX_REQUESTS + 1))
        with self.assertRaisesRegex(ValueError, 'requests must'):
            capture.load_manifest(path, identity)
        with self.assertRaisesRegex(ValueError, 'encoded byte'):
            capture.encode({'text': '汉' * 10}, 20)
        path, identity, _ = self.manifest(url='http://external.invalid/')
        with self.assertRaisesRegex(ValueError, 'unsupported fields'):
            capture.load_manifest(path, identity)

    def test_two_owned_loopback_servers_and_identical_origin_for_phases(self):
        path, identity, _ = self.manifest()
        value = capture.load_manifest(path, identity)
        with capture.FixtureServers(value) as fixture:
            observation = capture.Capture(fixture.origin, value['resources'])
            with self.assertRaisesRegex(ValueError, 'outside'):
                observation.gate(fixture.probe_origin + capture.PROBE_PATH)
            observation.gate(fixture.origin + '/data')
            observed = []
            for phase in ('before', 'after'):
                fixture.phase = phase
                connection = http.client.HTTPConnection('127.0.0.1', fixture.servers[0].server_port, timeout=2)
                connection.request('GET', '/data')
                observed.append(connection.getresponse().read()); connection.close()
            self.assertEqual(observed, [b'local before', b'local after'])
            self.assertEqual(fixture.probe_requests(), 0)
            self.assertEqual(fixture.receipt()['negative_probe_control_requests'], 1)
            self.assertNotEqual(fixture.origin, fixture.probe_origin)

    def observation(self):
        observation = capture.Capture('http://127.0.0.1:1', ['/data'])
        for number in range(4):
            observation.event(dict(method='Network.requestWillBeSent', params=dict(requestId=str(number),
                timestamp=1, wallTime=1, request=dict(method='GET', url='http://127.0.0.1:1/data', headers={}))))
            if number < 3:
                observation.event(dict(method='Network.responseReceived', params=dict(requestId=str(number),
                    response=dict(status=200, statusText='OK', protocol='http/1.1', headers={}, mimeType='text/plain'))))
                observation.event(dict(method='Network.loadingFinished', params=dict(requestId=str(number), timestamp=2)))
            else:
                observation.event(dict(method='Network.loadingFailed', params=dict(requestId=str(number),
                    timestamp=2, errorText='net::ERR_CONTENT_LENGTH_MISMATCH')))
        return observation

    def test_text_empty_base64_and_missing_are_distinct_without_decoding_har(self):
        responses = [{'body': 'héllo', 'base64Encoded': False}, {'body': '', 'base64Encoded': False},
                     {'body': base64.b64encode(b'\xff\0').decode(), 'base64Encoded': True}]
        client = mock.Mock(); client.call.side_effect = responses
        har, coverage = self.observation().har(client)
        entries = har['log']['entries']
        self.assertEqual([entry['_hepta']['body_state'] for entry in entries], ['complete', 'empty', 'base64', 'missing'])
        self.assertEqual(entries[1]['response']['content']['text'], '')
        self.assertEqual(entries[2]['response']['content']['encoding'], 'base64')
        self.assertEqual(entries[2]['response']['content']['text'], '/wA=')
        self.assertNotIn('text', entries[3]['response']['content'])
        self.assertEqual(entries[2]['_hepta']['representation_sha256'], capture.digest(b'/wA='))
        self.assertFalse(coverage['every_response_body_recorded'])

    def test_protocol_body_unavailability_is_missing_but_budget_failure_is_not_swallowed(self):
        client = mock.Mock(); client.call.side_effect = ChromeProtocolError('No resource with given identifier')
        har, _ = self.observation().har(client)
        self.assertTrue(all('text' not in entry['response']['content'] for entry in har['log']['entries']))
        client.call.side_effect = ValueError('CDP observation exceeds budget')
        with self.assertRaisesRegex(ValueError, 'exceeds budget'):
            self.observation().har(client)
        client.call.side_effect = None
        client.call.return_value = {'body': 'x' * (capture.MAX_BODY_BYTES + 1), 'base64Encoded': False}
        with self.assertRaisesRegex(ValueError, 'byte budget'):
            self.observation().har(client)

    def test_request_event_and_cdp_message_budgets_are_failures(self):
        observation = capture.Capture('http://127.0.0.1:1', ['/data'])
        with mock.patch.object(capture, 'MAX_ENTRIES', 1):
            event = dict(method='Network.requestWillBeSent', params=dict(requestId='1', request=dict(method='GET', url='/data')))
            observation.event(event)
            event['params']['requestId'] = '2'
            with self.assertRaisesRegex(ValueError, 'request count'): observation.event(event)
        connection = Connection([{'method': 'Network.event', 'params': {'data': 'x' * 100}}, {'id': 1, 'result': {}}])
        client = _CDP(connection, None, lambda _url: None, max_message_bytes=64)
        with self.assertRaisesRegex(ValueError, 'message budget'): client.call('Page.enable')
        connection = Connection([{'method': 'Network.event'}, {'id': 1, 'result': {}}])
        client = _CDP(connection, None, lambda _url: None, max_messages=1)
        with self.assertRaisesRegex(ValueError, 'message budget'): client.call('Page.enable')

    def test_shared_cdp_keeps_events_and_denies_the_exact_paused_request(self):
        connection = Connection([{'method': 'Fetch.requestPaused', 'params': {'requestId': 'owned-denied',
            'request': {'url': 'http://127.0.0.1:2/denied'}}}, {'id': 1, 'result': {}}])
        events = []
        def gate(_url): raise ValueError('outside origin')
        client = _CDP(connection, None, gate, event_sink=events.append)
        client.call('Page.enable')
        self.assertEqual(connection.sent[1]['method'], 'Fetch.failRequest')
        self.assertEqual(connection.sent[1]['params']['requestId'], 'owned-denied')
        self.assertEqual(len(events), 1)

    def test_same_url_old_document_is_not_accepted_as_the_new_capture_phase(self):
        url = 'http://127.0.0.1:1/fixture'
        client = mock.Mock()
        client.call.side_effect = [
            {'result': {'value': {'url': url, 'generation': 'before', 'ready': True}}},
            {'result': {'value': {'url': url, 'generation': 'after', 'ready': True}}},
            {'result': {'value': {'generation': 'after', 'results': [], 'blocked': True}}}]
        with mock.patch.object(capture.time, 'sleep'):
            self.assertEqual(capture.completed_page(client, url, 'after')['generation'], 'after')
        self.assertEqual(client.call.call_count, 3)
        self.assertNotIn('awaitPromise', client.call.call_args_list[0].args[1])
        self.assertTrue(client.call.call_args_list[-1].args[1]['awaitPromise'])
        client.call.side_effect = [
            {'result': {'value': {'url': url, 'generation': 'after', 'ready': True}}},
            {'result': {'value': {'generation': 'before', 'results': [], 'blocked': True}}}]
        with self.assertRaisesRegex(ValueError, 'document generation'):
            capture.completed_page(client, url, 'after')
        capture.Capture('http://127.0.0.1:1', ['/data']).event({'id': 1, 'result': {}})

    def test_create_only_publication_preserves_existing_and_reports_failed_directory_sync(self):
        with capture._directory(self.root) as directory:
            capture.publish_file(directory, 'result.har', b'first')
            with self.assertRaises(FileExistsError): capture.publish_file(directory, 'result.har', b'second')
            self.assertEqual((self.root / 'result.har').read_bytes(), b'first')
            original = os.fsync
            def fail_parent(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError('parent fsync failed')
                original(fd)
            with mock.patch.object(capture.os, 'fsync', side_effect=fail_parent):
                with self.assertRaisesRegex(RuntimeError, 'unconfirmed'):
                    capture.publish_file(directory, 'uncertain.har', b'visible but unconfirmed')
            self.assertEqual((self.root / 'uncertain.har').read_bytes(), b'visible but unconfirmed')
            self.assertFalse(list(self.root.glob('.stage-*')))

    @contextmanager
    def fake_private_chrome(self, connection):
        process = mock.Mock(pid=424242, returncode=None)
        process.wait.return_value = -signal.SIGKILL
        status = types.SimpleNamespace(si_pid=process.pid, si_code=os.CLD_KILLED, si_status=signal.SIGKILL)
        def launch(arguments, **_kwargs):
            self.assertNotIn('--no-sandbox', arguments)
            profile = Path(next(value.split('=', 1)[1] for value in arguments if value.startswith('--user-data-dir=')))
            self.assertEqual(profile, self.root / 'profile')
            (profile / 'DevToolsActivePort').write_text('9222\n/devtools/browser/owned\n')
            return process
        fake_websocket = types.SimpleNamespace(create_connection=mock.Mock(return_value=connection))
        with mock.patch.dict(sys.modules, websocket=fake_websocket), \
                mock.patch.object(pdf, '_check_reaping_configuration'), \
                mock.patch.object(pdf.Path, 'is_file', return_value=True), \
                mock.patch.object(pdf.subprocess, 'Popen', side_effect=launch), \
                mock.patch.object(pdf.os, 'waitid', return_value=status), \
                mock.patch.object(pdf, '_live_group_members', return_value=[]), \
                mock.patch.object(pdf.os, 'killpg') as kill:
            yield process, kill
        process.poll.assert_not_called()
        process.kill.assert_not_called()
        process.terminate.assert_not_called()
        process.send_signal.assert_not_called()

    def test_shared_private_chrome_cleans_only_its_group_on_cancellation(self):
        connection = Connection([])
        with self.fake_private_chrome(connection) as (process, kill):
            with self.assertRaises(InterruptedError):
                with private_chrome(self.root, resource_check=lambda _url: None):
                    raise InterruptedError('owned job cancelled')
            kill.assert_called_once_with(process.pid, signal.SIGKILL)
            process.wait.assert_called_once()
            self.assertTrue(connection.closed)

    def test_first_sigterm_in_cleanup_is_deferred_until_group_cleanup_and_reap(self):
        connection = Connection([{'id': 1, 'result': {}}])
        with capture.cancellation_cleanup() as cancellation:
            def close(**_kwargs):
                self.assertGreater(cancellation.depth, 0)
                signal.raise_signal(signal.SIGTERM)
                self.assertTrue(cancellation.requested)
                self.assertFalse(cancellation.delivered)
                connection.closed = True
            connection.close = close
            with self.fake_private_chrome(connection) as (process, kill):
                with self.assertRaises(InterruptedError):
                    with private_chrome(self.root, resource_check=lambda _url: None, cleanup_guard=cancellation.defer):
                        pass
                self.assertTrue(connection.closed)
                kill.assert_called_once_with(process.pid, signal.SIGKILL)
                process.wait.assert_called_once()
                self.assertTrue(cancellation.delivered)

    def test_connection_close_error_still_cleans_and_reaps_the_owned_group(self):
        connection = Connection([{'id': 1, 'result': {}}])
        def close(**_kwargs): raise OSError('owned connection close failure')
        connection.close = close
        with self.fake_private_chrome(connection) as (process, kill):
            with self.assertRaisesRegex(OSError, 'connection close'):
                with private_chrome(self.root, resource_check=lambda _url: None):
                    pass
            kill.assert_called_once_with(process.pid, signal.SIGKILL)
            process.wait.assert_called_once()

    def test_cleanup_uncertainty_is_not_masked_by_a_first_cleanup_sigterm(self):
        connection = Connection([{'id': 1, 'result': {}}])
        with capture.cancellation_cleanup() as cancellation:
            def close(**_kwargs): signal.raise_signal(signal.SIGTERM)
            connection.close = close
            with self.fake_private_chrome(connection) as (process, kill):
                kill.side_effect = PermissionError('injected group failure')
                with self.assertRaisesRegex(pdf.ChromeOwnershipUnconfirmed, 'group signal'):
                    with private_chrome(self.root, resource_check=lambda _url: None, cleanup_guard=cancellation.defer):
                        pass
                process.wait.assert_not_called()
                self.assertTrue(cancellation.requested)
                self.assertFalse(cancellation.delivered)

    def test_foreign_reap_never_signals_a_remembered_numeric_group(self):
        for observed_returncode in (None, 0):
            with self.subTest(returncode=observed_returncode):
                process = mock.Mock(pid=424242, returncode=observed_returncode)
                with mock.patch.object(pdf.os, 'waitid', side_effect=ChildProcessError('foreign reap')) as peek, \
                        mock.patch.object(pdf.os, 'killpg') as kill:
                    with self.assertRaises(pdf.ChromeOwnershipUnconfirmed):
                        pdf._OwnedChromeProcess(process).cleanup()
                    kill.assert_not_called()
                    process.wait.assert_not_called()
                    if observed_returncode is not None: peek.assert_not_called()

    def test_signal_success_without_group_exit_remains_unconfirmed_and_unreaped(self):
        process = mock.Mock(pid=424242, returncode=None)
        status = types.SimpleNamespace(si_pid=process.pid, si_code=os.CLD_EXITED, si_status=0)
        with mock.patch.object(pdf.os, 'waitid', return_value=status), \
                mock.patch.object(pdf.os, 'killpg') as kill, \
                mock.patch.object(pdf, '_live_group_members', return_value=[424243]), \
                mock.patch.object(pdf.time, 'monotonic', side_effect=[0, 11]):
            with self.assertRaisesRegex(pdf.ChromeOwnershipUnconfirmed, 'termination is unconfirmed'):
                pdf._OwnedChromeProcess(process).cleanup()
            kill.assert_called_once_with(process.pid, signal.SIGKILL)
            process.wait.assert_not_called()

    def test_nondefault_sigchld_refuses_before_creating_a_child(self):
        for handler in (signal.SIG_IGN, lambda _number, _frame: None):
            with self.subTest(handler=handler):
                with mock.patch.object(pdf.signal, 'getsignal', return_value=handler), \
                        mock.patch.object(pdf.subprocess, 'Popen') as launch:
                    with self.assertRaisesRegex(pdf.ChromeOwnershipUnconfirmed, 'exclusive reaping'):
                        pdf._check_reaping_configuration(nullcontext)
                    launch.assert_not_called()

    @unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'WNOWAIT'), 'Linux child custody contract')
    def test_real_exited_leader_retains_custody_until_its_live_descendant_is_gone(self):
        # A finite child holds stdout open after its leader exits. EOF is actual
        # termination evidence; no Chrome, shared browser or external target runs.
        source = """import os, time
reader, writer = os.pipe()
child = os.fork()
if child == 0:
    os.close(reader)
    os.write(writer, b'ready')
    os.close(writer)
    time.sleep(8)
    os._exit(0)
os.close(writer)
os.read(reader, 5)
os.close(reader)
print(child, flush=True)
os._exit(0)
"""
        process = subprocess.Popen([sys.executable, '-B', '-c', source], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        owned = pdf._OwnedChromeProcess(process)
        try:
            self.assertEqual(owned.wait_exit(2), 0)
            self.assertIsNone(process.returncode)
            descendant = int(process.stdout.readline())
            self.assertIn(descendant, pdf._live_group_members(process.pid, time.monotonic() + 1))
            self.assertFalse(select.select([process.stdout], [], [], 0)[0])
            order = []
            original_peek, original_kill, original_wait = os.waitid, os.killpg, process.wait
            original_members = pdf._live_group_members
            def peek(*arguments):
                self.assertTrue(arguments[2] & os.WNOWAIT)
                order.append('non_reaping_observation')
                return original_peek(*arguments)
            def kill(*arguments):
                order.append('original_group_signal')
                return original_kill(*arguments)
            def members(*arguments):
                live = original_members(*arguments)
                if not live: order.append('no_live_group_members')
                return live
            def reap(*arguments, **keywords):
                self.assertIn('no_live_group_members', order)
                order.append('final_reap')
                return original_wait(*arguments, **keywords)
            with mock.patch.object(pdf.os, 'waitid', side_effect=peek), \
                    mock.patch.object(pdf.os, 'killpg', side_effect=kill), \
                    mock.patch.object(pdf, '_live_group_members', side_effect=members), \
                    mock.patch.object(process, 'wait', side_effect=reap) as waited:
                owned.cleanup()
                waited.assert_called_once()
            self.assertEqual(order[0], 'non_reaping_observation')
            self.assertEqual(order[-1], 'final_reap')
            self.assertEqual(process.returncode, 0)
            self.assertTrue(select.select([process.stdout], [], [], 1)[0])
            self.assertEqual(process.stdout.read(), b'')
        finally:
            try:
                if not owned.reaped: owned.cleanup()
            finally:
                process.stdout.close()

    @unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'WNOWAIT'), 'Linux child custody contract')
    def test_real_default_reaping_preflight_accepts_a_finite_owned_probe(self):
        pdf._check_reaping_configuration(nullcontext)

    def test_replay_sentinels_count_non_get_methods_and_bare_connections(self):
        origins = ['http://127.0.0.1:0', 'http://127.0.0.1:0']
        with replay_sentinels(origins) as empty:
            self.assertTrue(all(value == dict(accepted_connections=0, http_requests=0, methods={}) for value in empty.values()))
        methods = ('HEAD', 'POST', 'OPTIONS', 'CONNECT', 'UNSUPPORTED')
        with self.assertRaisesRegex(AssertionError, 'two known captured origins'):
            with replay_sentinels(origins) as counts:
                first, second = counts
                for method in methods:
                    connection = http.client.HTTPConnection('127.0.0.1', first, timeout=2)
                    try:
                        connection.request(method, '/owned-qualification', body=b'')
                        response = connection.getresponse()
                        self.assertEqual(response.status, 501)
                        response.read()
                    finally:
                        connection.close()
                with socket.create_connection(('127.0.0.1', second), timeout=2) as connection:
                    connection.sendall(b'bad\r\n\r\n')
                    connection.recv(1024)
        self.assertEqual(counts[first], dict(accepted_connections=len(methods), http_requests=len(methods),
                                            methods={method: 1 for method in methods}))
        self.assertEqual(counts[second], dict(accepted_connections=1, http_requests=0, methods={}))

    def test_python_invocation_keeps_venv_symlink_and_pins_target_separately(self):
        target = self.root / 'base-python'
        target.write_bytes(b'owned fake interpreter'); target.chmod(0o700)
        directory = self.root / 'venv' / 'bin'; directory.mkdir(parents=True)
        launcher = directory / 'python'; launcher.symlink_to(target)
        invocation, identity = python_identity(launcher)
        self.assertEqual(invocation, launcher)
        self.assertEqual(identity['invocation_path'], str(launcher))
        self.assertEqual(identity['realpath'], str(target))
        self.assertEqual(identity['sha256'], capture.digest(target.read_bytes()))
        self.assertNotEqual(identity['invocation_path'], identity['realpath'])


if __name__ == '__main__':
    unittest.main()
