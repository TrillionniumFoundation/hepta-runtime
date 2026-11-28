#!/usr/bin/env python3
"""Native typed serde projection and capacity controls; Rust replay is separate."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from json_native_cases import (CAPACITY, INVALID, UNKNOWN, Corpus, LEGACY, OWNER,
                               encode, fence_cases, fence_frame, typed_expected)

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = Path(os.environ.get('HIA_RUNTIME_ROOT', ROOT))
sys.path.insert(0, str(RUNTIME / 'scripts'))
from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError
from hia_native_json_qualification import check_module, source_inputs

MANIFEST = None
CORPUS_DIR = None


class FenceJSONTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = Path(MANIFEST or os.environ['HIA_FENCE_JSON_MANIFEST']).resolve()
        cls.metadata = check_module(ROOT, 'fence_json', cls.manifest)
        cls.original_root = Path(os.environ.get('HIA_JSON_REFERENCE_ROOT', ROOT))
        cls.qualification_inputs = source_inputs(ROOT, cls.original_root)
        cls.module = NativeModule(cls.manifest, manifest_sha256=hashlib.sha256(cls.manifest.read_bytes()).hexdigest())
        cls.calls = 0
        cls.standalone_runs = 0
        cls.elf_observations = []
        cls.started = time.perf_counter()
        cls.temp = tempfile.TemporaryDirectory(prefix='hia-fence-json-corpus-')
        location = CORPUS_DIR or os.environ.get('HIA_FENCE_JSON_CORPUS_DIR')
        cls.corpus = Corpus(Path(location) if location else Path(cls.temp.name) / 'corpus')

    @classmethod
    def tearDownClass(cls):
        if source_inputs(ROOT, cls.original_root) != cls.qualification_inputs:
            raise AssertionError('JSON source inputs changed during the native tests')
        result = cls.corpus.close({
            'schema': 'hepta.runtime.fence-json-native-corpus.v1',
            'status': 'NATIVE_COMPLETE_RUST_REPLAY_REQUIRED',
            'actual_native_calls': cls.calls, 'standalone_runs': cls.standalone_runs,
            'elf_observations': cls.elf_observations,
            'source_sha256': cls.metadata['source_sha256'],
            'image_sha256': cls.metadata['image_sha256'],
            'oracle_sha256': hashlib.sha256((ROOT / 'tests/hia_native/serde_json_oracle/oracle.rs').read_bytes()).hexdigest(),
            'qualification_inputs': cls.qualification_inputs,
            'native_seconds': time.perf_counter() - cls.started})
        cls.module.close()
        print(json.dumps(result, sort_keys=True), flush=True)
        cls.temp.cleanup()

    def invoke(self, session, wire):
        type(self).calls += 1
        try:
            output = session.invoke(wire)
            return len(output), output
        except (NativeRejected, NativeCapacityError) as exc:
            return exc.code, b''

    def test_01_original_typed_domain_and_mutations(self):
        with self.module.session(output_capacity=(1 << 20) + 128, workspace_capacity=(1 << 20) + 4096) as session:
            for index, (category, wire, expected) in enumerate(fence_cases()):
                code, output = self.invoke(session, wire)
                self.assertTrue(code == INVALID or code == len(output), (index, category, code))
                if expected is not UNKNOWN:
                    if expected == INVALID:
                        self.assertEqual(code, INVALID, (index, category, wire[:256]))
                    else:
                        self.assertEqual(output, expected, (index, category, wire[:256]))
                self.corpus.record(category, wire, code, output)

    def test_02_closed_frame(self):
        valid = fence_frame(2, encode(LEGACY))
        bad = [valid[:size] for size in range(24)]
        bad += [valid[:8] + struct.pack('<Q', kind) + valid[16:] for kind in [0, 3, 2**64 - 1]]
        bad += [valid[:16] + struct.pack('<Q', size) + valid[24:] for size in [0, 1, len(valid), 2**64 - 1]]
        bad += [bytes([valid[0] ^ 1]) + valid[1:], valid + b' ', valid[:-1]]
        with self.module.session(output_capacity=256, workspace_capacity=4096) as session:
            for wire in bad:
                code, output = self.invoke(session, wire)
                self.assertEqual((code, output), (INVALID, b''))
                self.corpus.record('closed-frame', wire, code, output)

    def test_03_output_shortage_is_atomic(self):
        samples = [(1, OWNER), (2, LEGACY), (2, dict(LEGACY, idempotency_key='', request_digest='\x00😀'))]
        for kind, value in samples:
            expected = typed_expected(kind, value)
            wire = fence_frame(kind, encode(value))
            for capacity in [0, 1, 127, len(expected) - 1, len(expected)]:
                code, output, _ = self.module.invoke_raw(wire, output_capacity=capacity,
                    workspace_capacity=4096, output_fill=0xCC, workspace_fill=0xA7)
                type(self).calls += 1
                if capacity < len(expected):
                    self.assertEqual(code, CAPACITY)
                    self.assertEqual(output, b'\xcc' * capacity)
                else:
                    self.assertEqual(code, len(expected))
                    self.assertEqual(output, expected)

    def test_04_workspace_bound_and_recovery(self):
        wire = fence_frame(2, encode(LEGACY))
        for capacity in [0, 1, 255, 256, 4095]:
            code, output, workspace = self.module.invoke_raw(wire, output_capacity=256,
                workspace_capacity=capacity, output_fill=0xCC, workspace_fill=0xA7)
            type(self).calls += 1
            self.assertEqual(code, CAPACITY)
            self.assertEqual(output, b'\xcc' * 256)
            self.assertEqual(workspace, b'\xa7' * capacity)
        deep = b'{"id":"job","host":"main","x":' + b'[' * 128 + b'0' + b']' * 128 + b'}'
        for capacity in [4096, 4097, 4098, 4351, 4352]:
            code, output, _ = self.module.invoke_raw(fence_frame(2, deep), output_capacity=256,
                workspace_capacity=capacity, output_fill=0xCC, workspace_fill=0xA7)
            type(self).calls += 1
            self.assertEqual(code, CAPACITY if capacity < 4352 else len(typed_expected(2, LEGACY)))
            if code == CAPACITY:
                self.assertEqual(output, b'\xcc' * 256)
        with self.module.session(output_capacity=256, workspace_capacity=4096) as session:
            for raw in [b'{"id":"job","host":"main","x":[0]}', encode(LEGACY), b'{}', encode(LEGACY)]:
                code, output = self.invoke(session, fence_frame(2, raw))
                if raw == encode(LEGACY):
                    self.assertEqual(output, typed_expected(2, LEGACY))
                else:
                    self.assertIn(code, [INVALID, CAPACITY])

    def test_05_refusal_does_not_publish_or_leak_previous_fields(self):
        with self.module.session(output_capacity=512, workspace_capacity=16384) as session:
            sequence = [dict(LEGACY, idempotency_key='secret', request_digest='hash'),
                        LEGACY, dict(LEGACY, idempotency_key=''), LEGACY]
            for value in sequence:
                code, output = self.invoke(session, fence_frame(2, encode(value)))
                self.assertEqual(output, typed_expected(2, value))
                ctypes.memset(session._output, 0xCC, session.output_capacity)
                code, output, _ = session.invoke_raw(fence_frame(2, b'{"id":"bad","host":null}'))
                type(self).calls += 1
                self.assertEqual(code, INVALID)
                self.assertEqual(output, b'\xcc' * 512)

    def test_06_real_standalone_without_runtime_interpreter(self):
        standalone = self.metadata.get('standalone')
        self.assertIsNotNone(standalone, 'qualification requires the actual syscall-only filter ELF')
        executable = self.manifest.parent / standalone['path']
        self.assertEqual(hashlib.sha256(executable.read_bytes()).hexdigest(), standalone['sha256'])
        samples = [(1, OWNER), (2, LEGACY), (2, dict(LEGACY, idempotency_key='\x00雪😀'))]
        for kind, value in samples:
            wire = fence_frame(kind, encode(value))
            result = subprocess.run([str(executable)], input=wire,
                capture_output=True, env={'PATH': ''}, timeout=10, check=False)
            type(self).standalone_runs += 1
            type(self).elf_observations.append({'exit_code': result.returncode,
                'input_bytes': len(wire), 'input_sha256': hashlib.sha256(wire).hexdigest(),
                'output_bytes': len(result.stdout), 'output_sha256': hashlib.sha256(result.stdout).hexdigest(),
                'stderr_sha256': hashlib.sha256(result.stderr).hexdigest(),
                'elf_sha256': standalone['sha256']})
            self.assertEqual((result.returncode, result.stderr), (0, b''))
            self.assertEqual(result.stdout, typed_expected(kind, value))

    def test_07_exact_locked_rust_corpus_identity(self):
        self.corpus.requests.flush()
        self.corpus.outputs.flush()
        expected = {'requests.hex': 'd279aad1aace9f809d5b0aa8990de8fc1262036b1eacd40be5e3d770080403b4',
                    'native-output.txt': 'd12faf42fa156b19015456e4e7aabe34a046bccda1264d9838929e1ff1ba762c'}
        self.assertEqual(self.corpus.count, 5087)
        for name, digest in expected.items():
            with (self.corpus.directory / name).open('rb') as source:
                self.assertEqual(hashlib.file_digest(source, 'sha256').hexdigest(), digest)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest')
    parser.add_argument('--corpus-dir')
    options, remaining = parser.parse_known_args()
    MANIFEST = options.manifest
    CORPUS_DIR = options.corpus_dir
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
