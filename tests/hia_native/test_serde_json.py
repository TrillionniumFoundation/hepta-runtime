#!/usr/bin/env python3
"""Actual native Value/number/serializer controls and locked-Rust corpus export."""
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

from json_native_cases import (CAPACITY, INVALID, UNKNOWN, Corpus, numeric_cases,
                               value_cases, value_frame)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(os.environ.get('HIA_RUNTIME_ROOT', ROOT)) / 'scripts'))
from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError
from hia_native_json_qualification import check_module, source_inputs

MANIFEST = None
CORPUS_DIR = None


class SerdeJSONTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = Path(MANIFEST or os.environ['HIA_SERDE_JSON_MANIFEST']).resolve()
        cls.metadata = check_module(ROOT, 'serde_json', cls.manifest)
        cls.original_root = Path(os.environ.get('HIA_JSON_REFERENCE_ROOT', ROOT))
        cls.qualification_inputs = source_inputs(ROOT, cls.original_root)
        cls.module = NativeModule(cls.manifest, manifest_sha256=hashlib.sha256(cls.manifest.read_bytes()).hexdigest())
        cls.calls = 0
        cls.standalone_runs = 0
        cls.elf_observations = []
        cls.started = time.perf_counter()
        cls.temp = tempfile.TemporaryDirectory(prefix='hia-serde-json-corpus-')
        location = CORPUS_DIR or os.environ.get('HIA_SERDE_JSON_CORPUS_DIR')
        cls.corpus = Corpus(Path(location) if location else Path(cls.temp.name) / 'corpus')

    @classmethod
    def tearDownClass(cls):
        if source_inputs(ROOT, cls.original_root) != cls.qualification_inputs:
            raise AssertionError('JSON source inputs changed during the native tests')
        result = cls.corpus.close({
            'schema': 'hepta.runtime.serde-json-native-corpus.v1',
            'status': 'NATIVE_COMPLETE_RUST_REPLAY_REQUIRED',
            'actual_native_calls': cls.calls, 'standalone_runs': cls.standalone_runs,
            'elf_observations': cls.elf_observations,
            'source_sha256': cls.metadata['source_sha256'], 'image_sha256': cls.metadata['image_sha256'],
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

    def test_01_value_order_duplicates_unicode_and_mutations(self):
        with self.module.session(output_capacity=1 << 20, workspace_capacity=4 << 20) as session:
            for index, (category, wire, expected) in enumerate(value_cases()):
                code, output = self.invoke(session, wire)
                self.assertTrue(code == INVALID or code == len(output), (index, category, code))
                if expected is not UNKNOWN:
                    if expected == INVALID:
                        self.assertEqual(code, INVALID, (index, category, wire[:256]))
                    else:
                        self.assertEqual(output, expected, (index, category, wire[:256]))
                self.corpus.record(category, wire, code, output)

    def test_02_numeric_classification_and_exact_binary64_text(self):
        requests = hashlib.sha256()
        outputs = hashlib.sha256()
        count = 0
        with self.module.session(output_capacity=64, workspace_capacity=8192) as session:
            for category, wire in numeric_cases():
                code, output = self.invoke(session, wire)
                self.assertTrue(code == INVALID or code == len(output))
                self.corpus.record(category, wire, code, output)
                requests.update(wire.hex().encode() + b'\n')
                outputs.update(f'{code:08x}:'.encode() + output.hex().encode() + b'\n')
                count += 1
        # This exact corpus was executed by locked serde_json/zmij, not Python floats.
        self.assertEqual(count, 14456)
        self.assertEqual(requests.hexdigest(), 'aac35fadf7244bf9890f509a35a3945f96fc5381c76df13d446d8bed5577faca')
        self.assertEqual(outputs.hexdigest(), 'c8a620c83e9bc573b9b61af69090f29f4820c1f4359b99dda119410a41f04ee7')

    def test_03_full_source_bound_and_node_arena(self):
        limit = 8 << 20
        with self.module.session(output_capacity=64 << 20, workspace_capacity=256 << 20) as session:
            raw = b'"' + b'x' * (limit - 2) + b'"'
            code, output = self.invoke(session, value_frame(1, raw))
            self.assertEqual(output, raw)
            self.corpus.record('8MiB-string', value_frame(1, raw), code, output)
            # 4,194,303 scalar slots plus the root: no former one-million-node cap.
            count = (limit - 2) // 2
            raw = b'[' + b'0,' * count + b'0]'
            self.assertEqual(len(raw), limit + 1)
            raw = raw[:-3] + b']'
            self.assertEqual(len(raw), limit - 1)
            raw += b' '
            code, output = self.invoke(session, value_frame(1, raw))
            self.assertEqual(output, raw[:-1])
            self.corpus.record('8MiB-max-nodes', value_frame(1, raw), code, output)
            # Valid short exponent spellings can exceed a 16 MiB output buffer.
            count = (limit - 1) // 5
            raw = b'[' + b'1e15,' * (count - 1) + b'1e15]'
            raw += b' ' * (limit - len(raw))
            expected = b'[' + b'1000000000000000.0,' * (count - 1) + b'1000000000000000.0]'
            self.assertGreater(len(expected), 16 << 20)
            code, output = self.invoke(session, value_frame(1, raw))
            self.assertEqual(output, expected)
            self.corpus.record('8MiB-exponent-expansion', value_frame(1, raw), code, output)
            raw = b'0' + b' ' * limit
            code, output = self.invoke(session, value_frame(1, raw))
            self.assertEqual((code, output), (INVALID, b''))
            self.corpus.record('8MiB-plus-one-refusal', value_frame(1, raw), code, output)

    def test_04_closed_frame_and_atomic_capacities(self):
        valid = value_frame(1, b'{"b":-0,"a":1e15}')
        bad = [valid[:size] for size in range(24)]
        bad += [valid[:8] + struct.pack('<Q', operation) + valid[16:] for operation in [0, 4, 2**64 - 1]]
        bad += [valid[:16] + struct.pack('<Q', size) + valid[24:] for size in [0, 1, len(valid), 2**64 - 1]]
        bad += [bytes([valid[0] ^ 1]) + valid[1:], valid + b' ', valid[:-1]]
        with self.module.session(output_capacity=256, workspace_capacity=65536) as session:
            for wire in bad:
                code, output = self.invoke(session, wire)
                self.assertEqual((code, output), (INVALID, b''))
                self.corpus.record('value-closed-frame', wire, code, output)
        expected = b'{"a":1000000000000000.0,"b":-0.0}'
        for capacity in [0, 1, len(expected) - 1, len(expected)]:
            code, output, _ = self.module.invoke_raw(valid, output_capacity=capacity,
                workspace_capacity=65536, output_fill=0xCC, workspace_fill=0xA7)
            type(self).calls += 1
            if capacity < len(expected):
                self.assertEqual(code, CAPACITY)
                self.assertEqual(output, b'\xcc' * capacity)
            else:
                self.assertEqual((code, output), (len(expected), expected))
        for operation, raw in [(1, b'[]'), (2, b'1'), (3, struct.pack('<Q', 0))]:
            for capacity in [0, 1, 8191]:
                code, output, workspace = self.module.invoke_raw(value_frame(operation, raw),
                    output_capacity=256, workspace_capacity=capacity, output_fill=0xCC, workspace_fill=0xA7)
                type(self).calls += 1
                self.assertEqual((code, output, workspace), (CAPACITY, b'\xcc' * 256, b'\xa7' * capacity))
        for capacity in [8192, 16511, 16512]:
            code, output, _ = self.module.invoke_raw(value_frame(1, b'[1,2,3]'),
                output_capacity=256, workspace_capacity=capacity, output_fill=0xCC, workspace_fill=0xA7)
            type(self).calls += 1
            self.assertEqual((code, output), (CAPACITY, b'\xcc' * 256))

    def test_05_persistent_scratch_and_scalar_reuse_preserve_errors(self):
        values = [(b'[1e15,1e15,1e15]', b'[1000000000000000.0,1000000000000000.0,1000000000000000.0]'),
                  (b'[-0,0,-0.0,0.0,-0]', b'[-0.0,0,-0.0,0.0,-0.0]'),
                  (b'[1.0,1e0,1.00,1.000]', b'[1.0,1.0,1.0,1.0]'),
                  (b'{"z":1e15,"a":1e15,"z":0}', b'{"a":1000000000000000.0,"z":0}'),
                  (b'{"a":1e9999,"a":1e15}', INVALID),
                  (b'{"a":1e15,"a":1e9999}', INVALID),
                  (b'[1e15,1e9999,1e15]', INVALID),
                  (b'[1e15,"1e15",1e15]', b'[1000000000000000.0,"1e15",1000000000000000.0]')]
        with self.module.session(output_capacity=512, workspace_capacity=65536) as session:
            for raw, expected in values * 3:
                ctypes.memset(session._output, 0xCC, 512)
                wire = value_frame(1, raw)
                code, output = self.invoke(session, wire)
                if expected == INVALID:
                    self.assertEqual(code, INVALID)
                    self.assertEqual(ctypes.string_at(session._output, 512), b'\xcc' * 512)
                else:
                    self.assertEqual(output, expected)
                self.corpus.record('scalar-reuse-state', wire, code, output)

    def test_06_real_filter_source_and_image_binding(self):
        standalone = self.metadata.get('standalone')
        self.assertIsNotNone(standalone)
        executable = self.manifest.parent / standalone['path']
        elf = executable.read_bytes()
        image = (self.manifest.parent / self.metadata['image']).read_bytes()
        self.assertEqual(hashlib.sha256(elf).hexdigest(), standalone['sha256'])
        self.assertTrue(elf.endswith(image))
        self.assertEqual(elf[:7], b'\x7fELF\x02\x01\x01')
        self.assertEqual(struct.unpack_from('<HH', elf, 16), (2, 62))
        phoff = struct.unpack_from('<Q', elf, 32)[0]
        entsize, count = struct.unpack_from('<HH', elf, 54)
        for i in range(count):
            kind, flags = struct.unpack_from('<II', elf, phoff + i * entsize)
            self.assertNotIn(kind, [2, 3], 'no dynamic or interpreter program header')
            self.assertFalse(flags & 1 and flags & 2, 'no writable executable segment')
        cases = [(value_frame(1, b'{"b":1e15,"a":-0,"a":2}'), b'{"a":2,"b":1000000000000000.0}'),
                 (value_frame(2, b'-9223372036854775808'), struct.pack('<QQ', 4, 1 << 63)),
                 (value_frame(3, struct.pack('<Q', 1)), b'5e-324')]
        for wire, expected in cases:
            p = subprocess.run([str(executable)], input=wire, capture_output=True,
                               env={'PATH': ''}, timeout=10, check=False)
            type(self).standalone_runs += 1
            type(self).elf_observations.append({'exit_code': p.returncode,
                'input_bytes': len(wire), 'input_sha256': hashlib.sha256(wire).hexdigest(),
                'output_bytes': len(p.stdout), 'output_sha256': hashlib.sha256(p.stdout).hexdigest(),
                'stderr_sha256': hashlib.sha256(p.stderr).hexdigest(),
                'elf_sha256': standalone['sha256']})
            self.assertEqual((p.returncode, p.stderr, p.stdout), (0, b'', expected))

    def test_07_exact_locked_rust_corpus_identity(self):
        self.corpus.requests.flush()
        self.corpus.outputs.flush()
        expected = {'requests.hex': 'f656bcdac70022f54971ee55446b3af8b8119e7061afd8f3bd17f346ccd9c23c',
                    'native-output.txt': '49bb94f284686a0f65c6b212b83b4223c7d9226289666abde197cb925e017809'}
        self.assertEqual(self.corpus.count, 17778)
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
