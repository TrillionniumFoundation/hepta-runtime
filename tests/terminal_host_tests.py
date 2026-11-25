#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real disposable PTY tests, using a new RPC client process for every call."""
import hashlib
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock

HELPER = pathlib.Path(__file__).resolve().parents[1] / 'src/mcp/runtime/terminal_host.py'
SPEC = importlib.util.spec_from_file_location('terminal_host_under_test', HELPER)
TERMINAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TERMINAL)


class Terminals(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hepta-pty-test-')
        self.path = pathlib.Path(self.temp.name) / 'terminal'
        self.sid = 'dpty-test-' + uuid.uuid4().hex
        self.req = {'allow_detached_fallback': True, 'session_id': self.sid, 'executable': '/usr/bin/python3', 'args': [],
                    'env': {}, 'rows': 24, 'cols': 100, 'cwd': self.temp.name}

    def call(self, op, fail=False, **values):
        q = {'op': op, 'job_dir': str(self.path), 'session_id': self.sid, **values}
        p = subprocess.run([sys.executable, str(HELPER)], input=json.dumps(q), text=True, capture_output=True, timeout=30)
        if fail:
            self.assertNotEqual(p.returncode, 0)
            return p.stderr
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)

    def start(self, code):
        self.req['args'] = ['-c', code]
        return self.call('start', request=self.req)

    def until(self, marker):
        for _ in range(80):
            value = self.call('read')
            if marker in value['text']: return value
            time.sleep(.05)
        self.fail('terminal marker not seen: ' + marker)

    def ended(self):
        for _ in range(100):
            value = self.call('status')
            if value['state'] != 'running': return value
            time.sleep(.05)
        self.fail('terminal did not finish')

    def tearDown(self):
        if (self.path / 'request.json').exists():
            try:
                self.call('close'); self.ended()
            except (AssertionError, subprocess.SubprocessError): pass
        self.temp.cleanup()

    def test_archive_exceeds_ring_and_retains_exact_bytes(self):
        count = 6*1024*1024+11
        self.start(f"import os;os.write(1,b'x'*{count});os.write(1,b'END')")
        final = self.ended()
        self.assertTrue(final['output_complete'], final)
        self.assertEqual(final['bytes_stored'], count+3)
        self.assertEqual(self.call('read', offset=count)['text'], 'END')
        self.assertEqual(hashlib.sha256((self.path/'output.log').read_bytes()).hexdigest(), hashlib.sha256(b'x'*count+b'END').hexdigest())
        self.assertEqual(self.call('read', offset=0, limit=1)['text'], 'x')

    def test_terminal_survives_client_exit_and_duplicate_launch(self):
        initial = self.start("import os,time;print('PID='+str(os.getpid()),flush=True);print(input(),flush=True);time.sleep(.2)")
        pid = initial['status']['pid']
        self.until('PID=')
        again = self.call('start', request=self.req)
        self.assertTrue(again['reused'])
        self.assertEqual(again['status']['pid'], pid)
        self.call('write', data='RESUMED\n', request_id='first')
        self.until('RESUMED')
        self.assertTrue(self.ended()['output_complete'])
        self.assertIn('different request', self.call('start', fail=True, request={**self.req,'cwd':'/'}))

    def test_input_deduplication_does_not_repeat_and_rejects_different_data(self):
        self.start("import time;print('READY',flush=True);time.sleep(3)")
        self.until('READY')
        first = self.call('write', data='ONE\n', request_id='input-1')
        second = self.call('write', data='ONE\n', request_id='input-1')
        self.assertFalse(first['reused']); self.assertTrue(second['reused'])
        self.assertIn('different bytes', self.call('write', fail=True, data='TWO\n', request_id='input-1'))
        self.assertNotIn('ONE', (self.path/'request.json').read_text())

    def test_unicode_split_write_and_exact_binary_cursor(self):
        data = '中文α🦀'.encode()
        self.start(f'import os,time;b={data!r};os.write(1,b[:2]);time.sleep(.2);os.write(1,b[2:])')
        text, raw, cursor = '', b'', 0
        for _ in range(100):
            part = self.call('read', offset=cursor, limit=1)
            text += part['text']; raw += bytes.fromhex(part['bytes_hex']); cursor=part['next_offset']
            self.assertFalse(part['text_is_lossy'])
            if part['status']['state'] != 'running' and cursor == part['available_end']: break
            time.sleep(.02)
        self.assertEqual(text, '中文α🦀'); self.assertEqual(raw, data)
        self.assertEqual(self.call('read', offset=0, limit=1, raw_bytes=True)['bytes_hex'], data[:1].hex())
        self.call('read', fail=True, offset=999999)

    def test_password_style_echo_is_disabled_and_input_not_stored(self):
        self.start("import getpass;value=getpass.getpass('LOCAL_PROMPT:');print('ACCEPTED' if value=='test-fixture-only' else 'WRONG',flush=True)")
        self.until('LOCAL_PROMPT:')
        self.call('write', data='test-fixture-only\n', request_id='password-fixture')
        final = self.ended(); self.assertTrue(final['output_complete'])
        log = (self.path/'output.log').read_text()
        self.assertIn('ACCEPTED', log); self.assertNotIn('test-fixture-only', log)
        # This validates echo transport, not the system sudo/PAM password path.

    def test_reboot_identity_reports_lost_without_relaunch(self):
        self.start("import time;print('READY',flush=True);time.sleep(3)")
        self.until('READY')
        path = self.path/'started.json'; original = json.loads(path.read_text())
        different_boot = str(uuid.uuid4())
        if sys.platform == 'darwin': different_boot = TERMINAL.DARWIN_BOOT_PREFIX + different_boot
        path.write_text(json.dumps({**original,'boot':different_boot}))
        state = self.call('status')
        self.assertEqual(state['state'],'lost'); self.assertEqual(state['reason'],'target_reboot')
        path.write_text(json.dumps(original))


class DarwinBootIdentity(unittest.TestCase):
    UUID = '12345678-9ABC-4DEF-8123-456789ABCDEF'
    OTHER_UUID = '11111111-2222-4333-8444-555555555555'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hepta-boot-identity-test-')
        self.addCleanup(self.temp.cleanup)
        self.job = pathlib.Path(self.temp.name)
        self.started = {'pid': 42, 'boot': TERMINAL.DARWIN_BOOT_PREFIX + self.UUID.lower(),
                        'state': 'running', 'output_complete': False}
        (self.job / 'started.json').write_text(json.dumps(self.started))
        self.platform = mock.patch.object(TERMINAL.sys, 'platform', 'darwin')
        self.platform.start()
        self.addCleanup(self.platform.stop)

    def test_canonical_uuid_uses_exact_read_only_sysctl(self):
        with mock.patch.object(TERMINAL.subprocess, 'check_output', return_value=self.UUID + '\n') as query:
            self.assertEqual(TERMINAL.boot(), self.started['boot'])
        query.assert_called_once_with(
            ['/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid'], text=True, timeout=3)

    def test_nil_malformed_multiline_and_extra_text_are_rejected(self):
        for value in ('', '00000000-0000-0000-0000-000000000000',
                      '{' + self.UUID + '}', self.UUID.replace('-', ''),
                      self.UUID + '\nextra', self.UUID + '\n\n',
                      ' ' + self.UUID, self.UUID + ' ', self.UUID + '\x00',
                      'kern.bootsessionuuid: ' + self.UUID):
            with self.subTest(value=value), mock.patch.object(
                    TERMINAL.subprocess, 'check_output', return_value=value):
                with self.assertRaises(ValueError): TERMINAL.boot()

    def test_unavailable_uuid_has_no_boottime_or_pid_fallback(self):
        for error in (FileNotFoundError('sysctl missing'),
                      subprocess.CalledProcessError(1, 'sysctl'),
                      subprocess.TimeoutExpired('sysctl', 3)):
            with self.subTest(error=type(error).__name__), mock.patch.object(
                    TERMINAL.subprocess, 'check_output', side_effect=error) as query:
                with self.assertRaises(type(error)): TERMINAL.boot()
                self.assertEqual(query.call_count, 1)
                self.assertEqual(query.call_args.args[0][-1], 'kern.bootsessionuuid')

    def test_unknown_platform_does_not_query_darwin(self):
        with mock.patch.object(TERMINAL.sys, 'platform', 'unsupported-os'), mock.patch.object(
                TERMINAL.subprocess, 'check_output') as query:
            with self.assertRaisesRegex(RuntimeError, 'unavailable on this platform'):
                TERMINAL.boot()
        query.assert_not_called()

    def test_same_uuid_remains_valid_despite_timeval_changes(self):
        timeval = ['{ sec = 1, usec = 667910 }', '{ sec = 1, usec = 746448 }']
        def query(args, **kwargs):
            return self.UUID + '\n' if args[-1] == 'kern.bootsessionuuid' else timeval.pop(0)
        with mock.patch.object(TERMINAL.subprocess, 'check_output', side_effect=query), mock.patch.object(
                TERMINAL, 'request_daemon', return_value=self.started) as rpc:
            self.assertEqual(TERMINAL.status(self.job), self.started)
            self.assertEqual(TERMINAL.status(self.job), self.started)
        self.assertEqual(rpc.call_count, 2)
        self.assertEqual(len(timeval), 2)

    def test_changed_uuid_reports_reboot_without_owner_contact(self):
        with mock.patch.object(TERMINAL.subprocess, 'check_output', return_value=self.OTHER_UUID), mock.patch.object(
                TERMINAL, 'request_daemon') as rpc:
            state = TERMINAL.status(self.job)
        self.assertEqual(state, {'state': 'lost', 'output_complete': False,
                                 'reason': 'target_reboot', 'pid': 42})
        rpc.assert_not_called()

    def test_legacy_identity_is_unverifiable_but_archive_remains_readable(self):
        legacy = {**self.started, 'boot': '{ sec = 1, usec = 667910 }'}
        path = self.job / 'started.json'
        path.write_text(json.dumps(legacy))
        original = path.read_bytes()
        data = b'existing archive\n'
        (self.job / 'output.log').write_bytes(data)
        with mock.patch.object(TERMINAL.subprocess, 'check_output') as query, mock.patch.object(
                TERMINAL, 'request_daemon') as rpc:
            result = TERMINAL.read_page(self.job, {})
        self.assertEqual(bytes.fromhex(result['bytes_hex']), data)
        self.assertFalse(result['output_complete'])
        self.assertEqual(result['status']['reason'], 'boot_identity_unverifiable')
        self.assertEqual(path.read_bytes(), original)
        query.assert_not_called()
        rpc.assert_not_called()

    def test_current_uuid_failure_is_unavailable_not_reboot(self):
        with mock.patch.object(TERMINAL.subprocess, 'check_output', return_value='malformed'), mock.patch.object(
                TERMINAL, 'request_daemon') as rpc:
            state = TERMINAL.status(self.job)
        self.assertEqual(state['reason'], 'boot_identity_unavailable')
        self.assertFalse(state['output_complete'])
        rpc.assert_not_called()

    def test_mutation_rejects_legacy_changed_or_unavailable_boot_before_socket(self):
        for op in ('write', 'resize', 'close'):
            for recorded, current, reason in (
                    ('{ sec = 1, usec = 2 }', self.UUID, 'boot_identity_unverifiable'),
                    (TERMINAL.DARWIN_BOOT_PREFIX + 'invalid', self.UUID, 'boot_identity_unverifiable'),
                    (self.started['boot'], self.OTHER_UUID, 'target_reboot'),
                    (self.started['boot'], '', 'boot_identity_unavailable')):
                (self.job / 'started.json').write_text(json.dumps({**self.started, 'boot': recorded}))
                with self.subTest(op=op, reason=reason), mock.patch.object(
                        TERMINAL.subprocess, 'check_output', return_value=current), mock.patch.object(
                        TERMINAL.socket, 'socket') as connect:
                    with self.assertRaisesRegex(RuntimeError, reason):
                        TERMINAL.request_daemon(self.job, {'op': op})
                    connect.assert_not_called()

    def test_same_boot_mutations_reach_original_rpc_unchanged(self):
        for op in ('write', 'resize', 'close'):
            request = {'op': op, 'data': 'fixture input', 'rows': 24, 'cols': 100}
            with self.subTest(op=op), mock.patch.object(
                    TERMINAL.subprocess, 'check_output', return_value=self.UUID), mock.patch.object(
                    TERMINAL, 'socket_path', return_value=self.job / 'owner.sock'), mock.patch.object(
                    TERMINAL.socket, 'socket') as connect:
                conn = connect.return_value.__enter__.return_value
                conn.recv.return_value = b'{"fixture_reply":true}\n'
                self.assertEqual(TERMINAL.request_daemon(self.job, request), {'fixture_reply': True})
                conn.sendall.assert_called_once_with(json.dumps(request).encode() + b'\n')

    def test_new_start_rejects_identity_before_launch_or_request_publication(self):
        with mock.patch.object(TERMINAL.subprocess, 'check_output', return_value=''), mock.patch.object(
                TERMINAL.subprocess, 'Popen') as launch, mock.patch.object(TERMINAL.subprocess, 'run') as manager:
            with self.assertRaises(ValueError):
                TERMINAL.start(self.job, {'request': {'session_id': 'new-fixture'}}, 'fixture owner')
        launch.assert_not_called()
        manager.assert_not_called()
        self.assertFalse((self.job / 'request.json').exists())
        self.assertFalse((self.job / 'owner.py').exists())

    def test_daemon_rejects_identity_before_listener_or_pty_fork(self):
        with mock.patch.object(TERMINAL.subprocess, 'check_output', return_value=''), mock.patch.object(
                TERMINAL.pty, 'fork') as fork, mock.patch.object(TERMINAL.socket, 'socket') as listener:
            with self.assertRaises(ValueError): TERMINAL.daemon(self.job)
        fork.assert_not_called()
        listener.assert_not_called()
        self.assertFalse((self.job / 'output.log').exists())

    def test_final_receipt_remains_readable_without_current_boot(self):
        final = {'state': 'exited', 'output_complete': True, 'exit_code': 0}
        (self.job / 'exit.json').write_text(json.dumps(final))
        with mock.patch.object(TERMINAL, 'boot', side_effect=OSError('unavailable')) as query:
            self.assertEqual(TERMINAL.status(self.job), final)
        query.assert_not_called()

    def test_legacy_close_never_reaches_owner_or_rewrites_identity(self):
        path = self.job / 'started.json'
        path.write_text(json.dumps({**self.started, 'boot': '{ sec = 1, usec = 2 }'}))
        before = path.read_bytes()
        (self.job / 'request.json').write_text(json.dumps({'session_id': 'legacy-fixture'}))
        q = {'job_dir': str(self.job), 'session_id': 'legacy-fixture', 'op': 'close'}
        output = io.StringIO()
        with mock.patch.object(TERMINAL.sys, 'argv', ['owner.py']), mock.patch.object(
                TERMINAL.sys, 'stdin', io.StringIO(json.dumps(q))), mock.patch.object(
                TERMINAL.sys, 'stdout', output), mock.patch.object(TERMINAL, 'request_daemon') as rpc:
            TERMINAL.main()
        # Rust deliberately maps this existing ACK to unknown, never confirmed termination.
        self.assertEqual(json.loads(output.getvalue()), {'result': 'already_exited'})
        self.assertEqual(path.read_bytes(), before)
        rpc.assert_not_called()

    def test_legacy_partial_utf8_keeps_cursor_until_archive_completes_character(self):
        (self.job / 'started.json').write_text(json.dumps(
            {**self.started, 'boot': '{ sec = 1, usec = 2 }'}))
        output = self.job / 'output.log'
        output.write_bytes(b'\xce')
        pending = TERMINAL.read_page(self.job, {'limit': 1})
        self.assertEqual(pending['status']['reason'], 'boot_identity_unverifiable')
        self.assertEqual(pending['next_offset'], 0)
        self.assertEqual(pending['text'], '')
        self.assertTrue(pending['utf8_pending'])
        self.assertFalse(pending['text_is_lossy'])
        raw = TERMINAL.read_page(self.job, {'limit': 1, 'raw_bytes': True})
        self.assertEqual(raw['bytes_hex'], 'ce')
        self.assertEqual(raw['next_offset'], 1)
        with output.open('ab') as stream: stream.write(b'\xb1')
        complete = TERMINAL.read_page(self.job, {'offset': pending['next_offset'], 'limit': 1})
        self.assertEqual(complete['text'], 'α')
        self.assertEqual(complete['bytes_hex'], 'ceb1')
        self.assertEqual(complete['next_offset'], 2)
        self.assertFalse(complete['text_is_lossy'])
        self.assertFalse(complete['output_complete'])

    def test_explicit_final_receipt_allows_lossy_truncated_utf8_to_advance(self):
        (self.job / 'exit.json').write_text(json.dumps(
            {'state': 'exited', 'output_complete': False, 'exit_code': 0}))
        (self.job / 'output.log').write_bytes(b'\xce')
        final = TERMINAL.read_page(self.job, {'limit': 1})
        self.assertEqual(final['next_offset'], 1)
        self.assertEqual(final['bytes_hex'], 'ce')
        self.assertEqual(final['text'], '\ufffd')
        self.assertTrue(final['text_is_lossy'])
        self.assertFalse(final['utf8_pending'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
