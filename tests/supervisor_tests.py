#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Exercise the actual embedded detached supervisor on disposable local jobs.
This does not pretend to qualify macOS or systemd; those require SSH acceptance.
"""
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / 'src/mcp/runtime/jobs.rs').read_text()
CODE = {name: re.search(r'const ' + name + r': &str = r#"(.*?)"#;', SOURCE, re.S).group(1)
        for name in ['START_CODE', 'STATUS_CODE', 'READ_CODE', 'CANCEL_CODE']}


def rpc(name, value, success=True, timeout=25):
    p = subprocess.run([sys.executable, '-c', CODE[name]], input=json.dumps(value), text=True, capture_output=True, timeout=timeout)
    if success:
        if p.returncode:
            raise AssertionError((name, p.returncode, p.stdout, p.stderr))
        return json.loads(p.stdout)
    if p.returncode == 0:
        raise AssertionError('request unexpectedly accepted')
    return p.stderr


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hepta-supervisor-test-')
        self.q = {'job_id': uuid.uuid4().hex, 'job_dir': self.temp.name, 'unit': 'test',
                  'request_fingerprint': 'a'*64, 'platform': 'macos', 'execution_mode': 'operator',
                  'executable': sys.executable, 'args': [], 'cwd': self.temp.name, 'env': {},
                  'timeout_seconds': 20, 'allow_job_network': True, 'allow_detached_fallback': True}

    def tearDown(self):
        # Every workload has a bounded lifetime. Wait before deleting its state.
        exit_path = pathlib.Path(self.temp.name) / 'exit.json'
        started = pathlib.Path(self.temp.name) / 'launch.json'
        if started.exists() and not exit_path.exists():
            try:
                rpc('CANCEL_CODE', {**self.q, 'grace_seconds': 12})
            except (AssertionError, subprocess.SubprocessError):
                pass
        self.temp.cleanup()

    def wait(self):
        for _ in range(60):
            p = pathlib.Path(self.temp.name) / 'exit.json'
            if p.exists():
                return json.loads(p.read_text())
            time.sleep(.2)
        raise AssertionError('test supervisor failed to finish')

    def test_incremental_output_and_no_duplicate_relaunch(self):
        self.q['args'] = ['-c', "import time;print('BEGIN',flush=True);time.sleep(2);print('END')"]
        self.assertEqual(rpc('START_CODE', self.q)['backend'], 'detached')
        text = ''
        for _ in range(30):
            text = rpc('READ_CODE', self.q)['stdout']['text']
            if 'BEGIN' in text:
                break
            time.sleep(.05)
        self.assertIn('BEGIN', text)
        self.assertNotIn('END', text)
        self.assertTrue(rpc('START_CODE', self.q)['reused_remote'])
        self.assertIn('different request', rpc('START_CODE', {**self.q, 'request_fingerprint': 'b'*64}, success=False))
        ended = self.wait()
        self.assertEqual(ended['exit_code'], 0)
        self.assertTrue(ended['output_complete'])
        self.assertFalse(any(ended['log_errors'].values()))
        self.assertEqual(rpc('READ_CODE', self.q)['stdout']['text'].count('BEGIN'), 1)

    def test_log_cap_and_lossless_cursor_bound(self):
        self.q['args'] = ['-c', "import sys;sys.stdout.buffer.write(b'x'*(17*1024*1024));sys.stderr.write('DRAINED')"]
        rpc('START_CODE', self.q)
        status = self.wait()
        self.assertEqual(status['exit_code'], 0)
        self.assertTrue(status['log_truncated']['stdout'])
        self.assertFalse(status['output_complete'])
        self.assertEqual(status['log_bytes']['stdout']['seen'], 17*1024*1024)
        self.assertEqual(status['log_bytes']['stdout']['stored'], 16*1024*1024)
        page = rpc('READ_CODE', {**self.q, 'stdout_offset': 16*1024*1024})
        self.assertEqual(page['stdout']['size'], 16*1024*1024)
        self.assertTrue(page['stdout']['eof'])
        self.assertEqual(page['stderr']['text'], 'DRAINED')
        page = rpc('READ_CODE', {**self.q, 'limit': 1024*1024})
        self.assertEqual(page['stdout']['next_offset'], 16384)
        rpc('READ_CODE', {**self.q, 'stdout_offset': 17*1024*1024}, success=False)

    def test_cancel_escalates_own_term_ignoring_child(self):
        self.q['args'] = ['-c', "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('READY',flush=True);time.sleep(20)"]
        rpc('START_CODE', self.q)
        for _ in range(40):
            if 'READY' in rpc('READ_CODE', self.q)['stdout']['text']:
                break
            time.sleep(.1)
        result = rpc('CANCEL_CODE', {**self.q, 'grace_seconds': 12})
        self.assertIn(result['result'], ['term_sent', 'kill_sent'])
        ended = self.wait()
        self.assertTrue(ended['cancelled'])
        self.assertEqual(ended['exit_code'], -9)

    def test_detached_resource_limits_fail_instead_of_silently_dropping(self):
        self.q['cpu_quota_percent'] = 5
        self.assertIn('cannot enforce', rpc('START_CODE', self.q, success=False))


if __name__ == '__main__':
    unittest.main(verbosity=2)
