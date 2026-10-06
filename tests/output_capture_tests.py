#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Fault injection against the actual embedded supervisor drain function."""
import ast
import io
import pathlib
import re
import unittest

SOURCE = (pathlib.Path(__file__).resolve().parents[1] / 'src/mcp/runtime/jobs.rs').read_text()
START = re.search(r'const START_CODE: &str = r#"(.*?)"#;', SOURCE, re.S).group(1)
TREE = ast.parse(START)
RUNNER = next(ast.literal_eval(n.value) for n in TREE.body if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == 'runner' for t in n.targets))
DRAIN = next(n for n in ast.parse(RUNNER).body if isinstance(n, ast.FunctionDef) and n.name == 'drain')
CODE = compile(ast.Module(body=[DRAIN], type_ignores=[]), '<embedded-runtime-drain>', 'exec')


class ShortWriter(io.BytesIO):
    def write(self, data):
        return super().write(data[:2])


class BrokenWriter:
    def write(self, data):
        raise OSError('injected storage failure')


class ZeroWriter:
    def write(self, data):
        return 0


class BrokenReader:
    def read1(self, limit):
        raise OSError('injected read failure')

    def close(self):
        pass


class Drain(unittest.TestCase):
    def run_drain(self, stream, sink):
        ns = {'log_truncated': {'stdout': False}, 'log_errors': {'stdout': None},
              'log_eof': {'stdout': False}, 'log_bytes': {'stdout': {'seen': 0, 'stored': 0}}}
        exec(CODE, ns)
        ns['drain'](stream, sink, 'stdout')
        return ns

    def test_short_writes_preserve_every_byte(self):
        data = '中文α\x00'.encode() * 100
        sink = ShortWriter()
        ns = self.run_drain(io.BytesIO(data), sink)
        self.assertEqual(sink.getvalue(), data)
        self.assertTrue(ns['log_eof']['stdout'])
        self.assertIsNone(ns['log_errors']['stdout'])
        self.assertEqual(ns['log_bytes']['stdout'], {'seen': len(data), 'stored': len(data)})

    def test_storage_failure_still_drains_producer_and_records_failure(self):
        data = b'x' * 200000
        ns = self.run_drain(io.BytesIO(data), BrokenWriter())
        self.assertTrue(ns['log_eof']['stdout'])
        self.assertIn('storage failure', ns['log_errors']['stdout'])
        self.assertEqual(ns['log_bytes']['stdout'], {'seen': len(data), 'stored': 0})

    def test_zero_write_is_failure_not_infinite_loop(self):
        ns = self.run_drain(io.BytesIO(b'bytes'), ZeroWriter())
        self.assertIn('invalid progress', ns['log_errors']['stdout'])
        self.assertTrue(ns['log_eof']['stdout'])

    def test_read_error_is_not_eof(self):
        ns = self.run_drain(BrokenReader(), io.BytesIO())
        self.assertFalse(ns['log_eof']['stdout'])
        self.assertIn('read failure', ns['log_errors']['stdout'])

    def test_capacity_loss_is_reported_and_counted(self):
        data = b'x' * (16 * 1024 * 1024 + 37)
        ns = self.run_drain(io.BytesIO(data), io.BytesIO())
        self.assertTrue(ns['log_truncated']['stdout'])
        self.assertTrue(ns['log_eof']['stdout'])
        self.assertEqual(ns['log_bytes']['stdout'], {'seen': len(data), 'stored': 16 * 1024 * 1024})


if __name__ == '__main__':
    unittest.main(verbosity=2)
