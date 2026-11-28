#!/usr/bin/env python3
"""Actual shared HIA Value RawValue parity, bounds and output-atomicity tests."""
from __future__ import annotations
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from json_native_cases import CAPACITY, INVALID, UNKNOWN, Corpus, value_frame
from raw_value_cases import raw_value_cases, wrap
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(os.environ.get('HIA_RUNTIME_ROOT', ROOT)) / 'scripts'))
from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError
from hia_native_json_qualification import check_module, source_inputs


class RawValueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = Path(os.environ['HIA_SERDE_JSON_MANIFEST']).resolve()
        cls.metadata = check_module(ROOT, 'serde_json', cls.manifest)
        cls.original = Path(os.environ.get('HIA_JSON_REFERENCE_ROOT', ROOT))
        cls.inputs = source_inputs(ROOT, cls.original)
        cls.extension = {name: hashlib.sha256((ROOT / 'tests/hia_native' / name).read_bytes()).hexdigest()
                         for name in ['raw_value_cases.py', 'test_serde_json_raw_value.py']}
        cls.module = NativeModule(cls.manifest, manifest_sha256=hashlib.sha256(cls.manifest.read_bytes()).hexdigest())
        cls.calls = 0
        cls.started = time.perf_counter()
        cls.temporary = tempfile.TemporaryDirectory(prefix='hia-rawvalue-')
        directory = os.environ.get('HIA_RAW_VALUE_CORPUS_DIR', str(Path(cls.temporary.name) / 'corpus'))
        cls.corpus = Corpus(Path(directory))

    @classmethod
    def tearDownClass(cls):
        if source_inputs(ROOT, cls.original) != cls.inputs:
            raise AssertionError('source identity changed during native RawValue execution')
        if any(hashlib.sha256((ROOT / 'tests/hia_native' / name).read_bytes()).hexdigest() != digest
               for name, digest in cls.extension.items()):
            raise AssertionError('RawValue domain changed during execution')
        result = cls.corpus.close({'schema': 'hepta.runtime.raw-value-native-corpus.v1',
            'status': 'NATIVE_COMPLETE_RUST_REPLAY_REQUIRED', 'actual_native_calls': cls.calls,
            'source_sha256': cls.metadata['source_sha256'], 'image_sha256': cls.metadata['image_sha256'],
            'qualification_inputs': cls.inputs, 'extension_inputs': cls.extension,
            'native_seconds': time.perf_counter() - cls.started})
        cls.module.close()
        cls.temporary.cleanup()
        print(json.dumps(result, sort_keys=True), flush=True)

    def call(self, session, wire):
        type(self).calls += 1
        try:
            result = session.invoke(wire)
            return len(result), result
        except (NativeRejected, NativeCapacityError) as exc:
            return exc.code, b''

    def test_01_complete_raw_value_domain(self):
        with self.module.session(output_capacity=1 << 20, workspace_capacity=16 << 20) as session:
            for index, (category, wire, expected) in enumerate(raw_value_cases()):
                code, result = self.call(session, wire)
                self.assertTrue(code == INVALID or code == len(result), (index, category, code))
                if expected is not UNKNOWN:
                    self.assertEqual((code, result), (INVALID, b'') if expected == INVALID else (len(expected), expected),
                                     (index, category, wire[:200]))
                self.corpus.record(category, wire, code, result)

    def test_02_full_input_bound_and_derived_depth(self):
        limit = 8 << 20
        with self.module.session(output_capacity=64 << 20, workspace_capacity=256 << 20) as session:
            raw = wrap(b'0')
            raw = raw[:-2] + b' ' * (limit - len(raw)) + raw[-2:]
            self.assertEqual(len(raw), limit)
            wire = value_frame(1, raw)
            code, result = self.call(session, wire)
            self.assertEqual((code, result), (1, b'0'))
            self.corpus.record('8MiB-raw-whitespace', wire, code, result)
            # Keep the complete 8 MiB domain; wrappers consume their actual bytes.
            overhead = len(wrap(b'[]')) - 2
            count = (limit - overhead - 1) // 2
            inner = b'[' + b'0,' * (count - 1) + b'0]'
            raw = wrap(inner)
            raw += b' ' * (limit - len(raw))
            self.assertEqual(len(raw), limit)
            wire = value_frame(1, raw)
            code, result = self.call(session, wire)
            self.assertEqual(result, inner)
            self.corpus.record('8MiB-raw-node-arena', wire, code, result)
            raw = b'0'
            depth = 0
            while len(wrap(raw)) <= limit:
                raw = wrap(raw)
                depth += 1
            self.assertGreater(depth, 14)
            wire = value_frame(1, raw)
            code, result = self.call(session, wire)
            self.assertEqual((code, result), (1, b'0'))
            self.corpus.record('maximum-representable-context-chain', wire, code, result)
            wire = value_frame(1, wrap(raw))
            code, result = self.call(session, wire)
            self.assertEqual((code, result), (INVALID, b''))
            self.corpus.record('raw-source-plus-one-context', wire, code, result)

    def test_03_refusal_atomicity_and_recovery(self):
        good = value_frame(1, wrap(b'{"b":-0,"a":1e15}'))
        expected = b'{"a":1000000000000000.0,"b":-0.0}'
        for capacity in [0, 1, len(expected) - 1, len(expected)]:
            type(self).calls += 1
            code, result, _ = self.module.invoke_raw(good, output_capacity=capacity, workspace_capacity=65536,
                                                     output_fill=0xCC, workspace_fill=0xA7)
            self.assertEqual((code, result), (CAPACITY, b'\xCC' * capacity) if capacity < len(expected) else (len(expected), expected))
        for capacity in [0, 1, 8191, 8192, 16511, 16512]:
            type(self).calls += 1
            code, result, _ = self.module.invoke_raw(good, output_capacity=256, workspace_capacity=capacity,
                                                     output_fill=0xCC, workspace_fill=0xA7)
            self.assertEqual((code, result), (CAPACITY, b'\xCC' * 256))
        bad = [wrap(b'1e9999'), wrap(b'1')[:-1] + b',"a":0}', wrap(b'[' * 128 + b'0' + b']' * 128)]
        with self.module.session(output_capacity=512, workspace_capacity=65536) as session:
            for _ in range(3):
                for raw in bad:
                    ctypes.memset(session._output, 0xCC, 512)
                    wire = value_frame(1, raw)
                    code, result = self.call(session, wire)
                    self.assertEqual((code, result), (INVALID, b''))
                    self.assertEqual(ctypes.string_at(session._output, 512), b'\xCC' * 512)
                    self.corpus.record('refusal-output-atomicity', wire, code, result)
                    code, result = self.call(session, good)
                    self.assertEqual(result, expected)
                    self.corpus.record('recovery-after-refusal', good, code, result)


if __name__ == '__main__':
    unittest.main(verbosity=2)
