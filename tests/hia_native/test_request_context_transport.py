#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual persistent HIA scopes, process isolation and native response composition.

The fixed-slot hex controller is a test fixture, not a public task-selection API.
Original Tokio scheduling and cache capabilities remain independent caller owners.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_build import HEPTA_COMMIT
from hia_native_loader import NativeModule
from hia_native_scope_qualification import embedded_images
from hia_native_request_context_build import members

INVALID, STATE = 0xFFFFFFFF, 0xFFFFFFFD
UNIT = b'HRCXR001' + struct.pack('<QQQ', 0, 0, 0)
EMPTY = b'HRCXR001' + struct.pack('<QQQ', 1, 0, 0)
NONE = b'HRCXR001' + struct.pack('<QQQ', 3, 0, 0)
RECORDS = {}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def packet(op, payload=b''):
    return b'HRCXQ001' + struct.pack('<QQQ', op, len(payload), 0) + payload


def hints(*values):
    payload = b''.join(struct.pack('<Q', len(v)) + v for v in values)
    return b'HRCXR001' + struct.pack('<QQQ', 1, len(values), len(payload)) + payload


def cache(value):
    return b'HRCXR001' + struct.pack('<QQQ', 3, 1, 8) + struct.pack('<Q', value)


def retain(name, command, raw, completed, *, context_requests=0):
    data = {'input': raw, 'stdout': completed.stdout, 'stderr': completed.stderr}
    RECORDS[name] = {'command': command, 'exit_code': completed.returncode,
                     'context_requests': context_requests,
                     'streams': {k: {'bytes': len(v), 'sha256': sha(v)} for k, v in data.items()}}
    destination = os.environ.get('HIA_REQUEST_CONTEXT_TRANSPORT_DIR')
    if destination:
        folder = Path(destination)
        folder.mkdir(parents=True, exist_ok=True)
        for suffix, content in data.items():
            with (folder / (name + '.' + suffix)).open('xb') as stream:
                stream.write(content)


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path(os.environ['HIA_REQUEST_CONTEXT_ELF_MANIFEST'])
        raw = cls.path.read_bytes()
        cls.metadata = meta = json.loads(raw)
        direct = Path(os.environ['HIA_REQUEST_CONTEXT_MANIFEST'])
        direct_meta = json.loads(direct.read_bytes())
        cls.executable = cls.path.parent / meta['executable']
        cls.response_path = Path(os.environ['HIA_RESPONSE_HINTS_MANIFEST'])
        response = json.loads(cls.response_path.read_bytes())
        cls.response_executable = cls.response_path.parent / response['standalone']['path']
        for path in (direct, cls.response_path):
            owner = NativeModule(path, manifest_sha256=sha(path.read_bytes()))
            owner.close()
        expected = [{'id': i, 'name': spec.name, 'flags': spec.flags,
                     'call_mask': spec.call_mask, 'input_capacity': spec.input_capacity,
                     'output_capacity': spec.output_capacity, 'workspace_capacity': spec.workspace_capacity,
                     'source_sha256': sha(spec.source.read_bytes())} for i, spec in enumerate(members(ROOT))]
        if meta['profile'] != expected or len(meta['members']) != 2:
            raise ValueError('context fixed private image table differs')
        images = []
        for i, row in enumerate(meta['members']):
            if row['manifest'] != f'module_{i:02d}.json':
                raise ValueError('context child manifest name differs')
            path = cls.path.parent / row['manifest']
            child_raw = path.read_bytes()
            child = json.loads(child_raw)
            if (sha(child_raw) != row['manifest_sha256'] or child['compiler_commit'] != HEPTA_COMMIT
                    or child['compiler_sha256'] != direct_meta['compiler_sha256']
                    or child['source_sha256'] != expected[i]['source_sha256']):
                raise ValueError('context child source or compiler differs')
            owner = NativeModule(path, manifest_sha256=sha(child_raw))
            owner.close()
            image = (path.parent / child['image']).read_bytes()
            if sha(image) != child['image_sha256'] or sha(image) != row['image_sha256']:
                raise ValueError('context child image differs')
            images.append(image)
        if sha(images[1]) != direct_meta['image_sha256']:
            raise ValueError('persistent process does not use the directly qualified image')
        elf = cls.executable.read_bytes()
        if sha(elf) != meta['executable_sha256']:
            raise ValueError('context executable differs')
        cls.binding = {'manifest_sha256': sha(raw), 'executable_sha256': sha(elf), 'profile': expected,
                       'embedded_images': embedded_images(elf, expected, images)}
        if (response['source_sha256'] != sha((ROOT / 'native/response_hints.hepta').read_bytes())
                or sha(cls.response_executable.read_bytes()) != response['standalone']['sha256']):
            raise ValueError('response executable source differs')

    def execute(self, label, requests):
        raw = b''.join(v.hex().encode('ascii') + b'\n' for v in requests)
        command = [str(self.executable), '--local-read-profile', '/request-context-fixture']
        result = subprocess.run(command, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=30, env={'PATH': '', 'LANG': 'C'})
        retain(label, command, raw, result, context_requests=len(requests))
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual(result.stderr, b'')
        lines = result.stdout.splitlines()
        self.assertEqual(len(lines), len(requests))
        outputs = []
        for line in lines:
            code, data = line.split(b':', 1)
            status, output = int(code, 16), bytes.fromhex(data.decode('ascii'))
            self.assertEqual(len(output), status if status < 0xFFFF0000 else 0)
            outputs.append((status, output))
        return outputs

    def good(self, label, requests, expected):
        result = self.execute(label, requests)
        self.assertEqual(result, [(len(v), v) for v in expected])
        return result

    def test_nested_scopes_and_ordered_drain(self):
        self.good('nested', [packet(1), packet(7), packet(4, b'dropped'), packet(5),
            packet(2, struct.pack('<Q', 42)), packet(4, b'parent'), packet(4, b'parent'),
            packet(2, struct.pack('<Q', 43)), packet(4, b'child'), packet(7), packet(6),
            packet(5), packet(5), packet(3), packet(7), packet(5), packet(3), packet(7), packet(8)],
            [UNIT, NONE, UNIT, EMPTY, UNIT, UNIT, UNIT, UNIT, UNIT, cache(43), hints(b'child'),
             hints(b'child'), EMPTY, UNIT, cache(42), hints(b'parent'), UNIT, NONE, UNIT])

    def test_scope_failure_and_reinitialization(self):
        self.good('discard', [packet(1), packet(2, struct.pack('<Q', 7)), packet(4, b'discard on error'),
            packet(3), packet(2, struct.pack('<Q', 7)), packet(5), packet(4, b'cancelled'), packet(8),
            packet(1), packet(2, struct.pack('<Q', 7)), packet(5), packet(8)],
            [UNIT, UNIT, UNIT, UNIT, UNIT, EMPTY, UNIT, UNIT, UNIT, UNIT, EMPTY, UNIT])

    def test_refusals_preserve_active_context(self):
        changed = bytearray(packet(4, b'invalid header'))
        struct.pack_into('<Q', changed, 24, 1)
        result = self.execute('refusals', [packet(1), packet(3), packet(2, struct.pack('<Q', 10)),
            packet(4, b'keep'), packet(9), bytes(changed), packet(4, b'\xc0\x80'), packet(5), packet(8)])
        self.assertEqual(result, [(len(UNIT), UNIT), (STATE, b''), (len(UNIT), UNIT), (len(UNIT), UNIT),
            (INVALID, b''), (INVALID, b''), (INVALID, b''), (len(hints(b'keep')), hints(b'keep')), (len(UNIT), UNIT)])

    def test_two_private_processes(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = []
            for index, alias in enumerate((21, 22)):
                label = ('task-' + str(index)).encode()
                requests = [packet(1), packet(2, struct.pack('<Q', alias)), packet(4, label),
                            packet(4, label), packet(7), packet(5), packet(8)]
                expected = [UNIT, UNIT, UNIT, UNIT, cache(alias), hints(label), UNIT]
                futures.append(pool.submit(self.good, 'isolation-' + str(index), requests, expected))
            for future in futures:
                future.result()

    def test_native_drain_to_native_response(self):
        hint = '请使用文件工具\nsecond line\0tail'.encode()
        result = self.good('join', [packet(1), packet(2, struct.pack('<Q', 99)), packet(4, hint),
            packet(4, hint), packet(4, b''), packet(5), packet(8)],
            [UNIT, UNIT, UNIT, UNIT, UNIT, hints(hint, b''), UNIT])
        drained, base = result[-2][1], '完整结果\r\n'.encode()
        wire = b'HRHAQ001' + struct.pack('<QQQ', len(base), len(drained), 0) + base + drained
        command = [str(self.response_executable)]
        actual = subprocess.run(command, input=wire, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=30, env={'PATH': '', 'LANG': 'C'})
        retain('join-response', command, wire, actual)
        self.assertEqual(actual.returncode, 0, actual.stderr.decode(errors='replace'))
        self.assertEqual(actual.stderr, b'')
        self.assertEqual(actual.stdout, base + b'\n\n' + '⚠️ '.encode() + hint + b'\n' + '⚠️ \n'.encode())


def main():
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(TransportTests))
    counts = {'native_context_processes': sum(v['context_requests'] > 0 for v in RECORDS.values()),
              'native_response_processes': sum(v['context_requests'] == 0 for v in RECORDS.values()),
              'context_requests': sum(v['context_requests'] for v in RECORDS.values()),
              'physical_isolation_processes': sum(k.startswith('isolation-') for k in RECORDS),
              'joined_responses': int('join-response' in RECORDS)}
    qualified = (result.wasSuccessful() and result.testsRun == 5 and not result.skipped
                 and not result.expectedFailures and not result.unexpectedSuccesses)
    report = {'schema': 'hepta.runtime.request-context-transport.v1',
              'status': 'PASS' if qualified else 'FAIL', 'test_groups': result.testsRun,
              'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
              'expected_failures': len(result.expectedFailures), 'unexpected_successes': len(result.unexpectedSuccesses),
              'counts': counts, 'processes': RECORDS, 'test_sha256': sha(Path(__file__).read_bytes()),
              'whole_runtime_replaced': False, 'production_scheduler_replaced': False}
    if hasattr(TransportTests, 'binding'):
        report['composition'] = TransportTests.binding
    if destination := os.environ.get('HIA_REQUEST_CONTEXT_TRANSPORT_DIR'):
        folder = Path(destination)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / 'transport.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report, sort_keys=True))
    return 0 if qualified else 1


if __name__ == '__main__':
    raise SystemExit(main())
