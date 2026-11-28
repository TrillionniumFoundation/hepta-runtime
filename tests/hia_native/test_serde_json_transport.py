#!/usr/bin/env python3
"""Execute the named large-buffer filter profile at its actual OS boundary."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(os.environ.get('HIA_RUNTIME_ROOT', ROOT)) / 'scripts'))
from hia_native_json_qualification import check_module, source_inputs
from json_native_cases import value_frame

MANIFEST = None


class SerdeFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = Path(MANIFEST or os.environ['HIA_SERDE_JSON_MANIFEST']).resolve()
        cls.metadata = check_module(ROOT, 'serde_json', cls.manifest)
        cls.original_root = Path(os.environ.get('HIA_JSON_REFERENCE_ROOT', ROOT))
        cls.inputs = source_inputs(ROOT, cls.original_root)
        cls.executable = cls.manifest.parent / cls.metadata['standalone']['path']
        cls.records = []

    @classmethod
    def tearDownClass(cls):
        if source_inputs(ROOT, cls.original_root) != cls.inputs:
            raise AssertionError('serde filter source inputs changed during OS tests')
        result = {'schema': 'hepta.runtime.serde-filter-observation.v1',
                  'source_sha256': cls.metadata['source_sha256'],
                  'image_sha256': cls.metadata['image_sha256'],
                  'elf_sha256': cls.metadata['standalone']['sha256'],
                  'packer_sha256': cls.metadata['standalone']['packer_source_sha256'],
                  'qualification_inputs': cls.inputs, 'actual_elf_runs': len(cls.records),
                  'runs': cls.records}
        destination = os.environ.get('HIA_SERDE_JSON_TRANSPORT_REPORT')
        if destination:
            path = Path(destination)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('x') as output:
                output.write(json.dumps(result, indent=2, sort_keys=True) + '\n')
        print(json.dumps(result, sort_keys=True), flush=True)

    def execute(self, label, wire, expected_code, expected, args=()):
        start = time.perf_counter()
        result = subprocess.run([str(self.executable), *args], input=wire, capture_output=True,
                                env={'PATH': ''}, timeout=90, check=False)
        self.records.append({'case': label, 'elapsed': time.perf_counter() - start,
                             'input_bytes': len(wire), 'input_sha256': hashlib.sha256(wire).hexdigest(),
                             'output_bytes': len(result.stdout), 'output_sha256': hashlib.sha256(result.stdout).hexdigest(),
                             'stderr_sha256': hashlib.sha256(result.stderr).hexdigest(), 'exit_code': result.returncode})
        self.assertEqual((result.returncode, result.stderr, result.stdout), (expected_code, b'', expected))

    def test_01_result_exceeds_old_sixteen_mib_capacity(self):
        limit = 8 << 20
        count = (limit - 1) // 5
        raw = b'[' + b'1e15,' * (count - 1) + b'1e15]'
        raw += b' ' * (limit - len(raw))
        expected = b'[' + b'1000000000000000.0,' * (count - 1) + b'1000000000000000.0]'
        self.assertGreater(len(expected), 16 << 20)
        self.execute('8MiB-input-31876700-byte-result', value_frame(1, raw), 0, expected)

    def test_02_frame_and_transport_limits(self):
        self.execute('malformed-frame', b'HSJVAL01', 2, b'')
        self.execute('module-eight-mib-limit', value_frame(1, b'0' + b' ' * (8 << 20)), 2, b'')
        self.execute('transport-sixteen-mib-plus-one', b' ' * ((16 << 20) + 1), 3, b'')
        self.execute('closed-cli', value_frame(1, b'null'), 64, b'', args=('unexpected',))

    def test_03_typed_failure_and_fresh_process_recovery(self):
        self.execute('nonfinite-f64-refusal', value_frame(3, struct.pack('<Q', 0x7FF0000000000000)), 2, b'')
        self.execute('fresh-success', value_frame(1, b'{"a":0,"a":1}'), 0, b'{"a":1}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest')
    options, remaining = parser.parse_known_args()
    MANIFEST = options.manifest
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
