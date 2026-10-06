#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real disposable PTY tests, using a new RPC client process for every call."""
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

HELPER = pathlib.Path(__file__).resolve().parents[1] / 'src/mcp/runtime/terminal_host.py'


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
        path.write_text(json.dumps({**original,'boot':'different-boot'}))
        state = self.call('status')
        self.assertEqual(state['state'],'lost'); self.assertEqual(state['reason'],'target_reboot')
        path.write_text(json.dumps(original))


if __name__ == '__main__':
    unittest.main(verbosity=2)
