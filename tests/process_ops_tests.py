#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real OS tests; signal only disposable child processes created by this test."""
import errno
import importlib.util
import json
import pathlib
import signal
import subprocess
import sys
import unittest
from unittest import mock

PATH = pathlib.Path(__file__).resolve().parents[1] / 'src/mcp/runtime/process_ops.py'
spec = importlib.util.spec_from_file_location('process_ops', PATH)
ops = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ops)


class ProcessOperations(unittest.TestCase):
    def test_list_is_bounded_and_omits_arguments(self):
        page = ops.list_processes({'limit': 2})
        self.assertLessEqual(len(page['processes']), 2)
        for row in page['processes']:
            self.assertNotIn('args', row)
            self.assertIn('identity', row)
        next_page = ops.list_processes({'limit': 2, 'after_pid': page['next_after_pid']})
        self.assertTrue(all(p['pid'] > page['next_after_pid'] for p in next_page['processes']))

    def test_probe_stale_identity_and_real_child_termination(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        try:
            start = ops.identity(child.pid)
            request = {'pid': child.pid, 'signal': 0, 'expected_identity': start}
            self.assertEqual(ops.send_signal(request)['result'], 'probe_succeeded')
            refused = ops.send_signal({**request, 'signal': signal.SIGTERM, 'expected_identity': 'stale'})
            self.assertEqual(refused, {'pid': child.pid, 'signal': signal.SIGTERM,
                'result': 'signal_refused', 'signal_syscall_attempted': False, 'termination_confirmed': False})
            self.assertIsNone(child.poll())
            result = ops.send_signal({**request, 'signal': signal.SIGTERM})
            self.assertEqual(result['result'], 'signal_sent')
            self.assertFalse(result['termination_confirmed'])
            if sys.platform == 'linux':
                self.assertTrue(result['atomic_identity'])
            self.assertEqual(child.wait(timeout=5), -signal.SIGTERM)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux pidfd acknowledgement cleanup path')
    def test_cleanup_error_can_happen_after_real_signal_delivery(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        actual_close = ops.os.close
        def close_then_fail(fd):
            actual_close(fd)
            raise OSError('post-syscall acknowledgement cleanup failed')
        try:
            start = ops.identity(child.pid)
            with mock.patch.object(ops.os, 'close', side_effect=close_then_fail):
                with self.assertRaisesRegex(OSError, 'post-syscall'):
                    ops.send_signal({'pid': child.pid, 'signal': signal.SIGTERM, 'expected_identity': start})
            self.assertEqual(child.wait(timeout=5), -signal.SIGTERM)
        finally:
            if child.poll() is None:
                child.kill(); child.wait(timeout=5)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux kernel refusal acknowledgement')
    def test_kernel_permission_refusal_is_explicit_and_does_not_claim_a_sent_signal(self):
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        try:
            start = ops.identity(child.pid)
            with mock.patch.object(ops.signal, 'pidfd_send_signal', side_effect=PermissionError(errno.EPERM, 'PRIVATE')):
                ack = ops.send_signal({'pid': child.pid, 'signal': 0, 'expected_identity': start})
            self.assertEqual(ack['refusal_reason'], 'kernel_permission_denied')
            self.assertTrue(ack['signal_syscall_attempted'])
            self.assertFalse(ack['signal_delivery_confirmed'])
            self.assertEqual(ack['identity'], start)
            self.assertNotIn('PRIVATE', json.dumps(ack))
            self.assertIsNone(child.poll())
        finally:
            if child.poll() is None:
                child.kill(); child.wait(timeout=5)

    def test_group_and_wildcard_are_not_single_pids(self):
        for pid in [0, -1, -100, 2147483648]:
            with self.assertRaises(ValueError):
                ops.send_signal({'pid': pid, 'signal': 0})

    def test_json_transport_rejects_bad_operation(self):
        result = subprocess.run([sys.executable, str(PATH)], input=json.dumps({'op': 'invalid'}), text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('unknown process operation', result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
