# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual HIA diagnostics; every semantic row is retained for locked Rust replay."""
from pathlib import Path
import argparse
import collections
import gzip
import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import sys
import time
import unittest

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'native/serde_error.hepta').is_file())
HERE = Path(__file__).resolve().parent
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
MODULE = SESSION = CORPUS = OPTIONS = None
CALLS = CONTROLS = 0
ELF_RECEIPTS = []
EXPECTED_GROUPS = 8
EXPECTED_CASES = 98699
DOMAIN_COUNTS = dict(unicode=67664, mutation=16318, number=12968, raw_value=378, wide=10)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def frame(raw):
    return b'HSJERQ01' + struct.pack('<QQ', 1, len(raw)) + raw


def expected_observation(row):
    if row['valid']:
        return b'HSJERR01' + bytes(56)
    raw = row['message'].encode()
    return b'HSJERR01' + struct.pack('<7Q', 1, row['category'], row['line'], row['column'], len(raw), 0, 0) + raw


class Corpus:
    def __init__(self, path):
        self.path = path
        path.mkdir()
        self.inputs = gzip.open(path / 'cases.bin.gz', 'wb', compresslevel=1)
        self.outputs = gzip.open(path / 'native-output.bin.gz', 'wb', compresslevel=1)
        self.index = gzip.open(path / 'cases.jsonl.gz', 'wb', compresslevel=1)
        self.count = self.input_bytes = self.output_bytes = 0
        self.input_hash = hashlib.sha256()
        self.output_hash = hashlib.sha256()
        self.domains = collections.Counter()

    def add(self, domain, wire, result):
        incoming = struct.pack('<Q', len(wire)) + wire
        outgoing = struct.pack('<IQ', len(result), len(result)) + result
        self.inputs.write(incoming)
        self.outputs.write(outgoing)
        self.input_hash.update(incoming)
        self.output_hash.update(outgoing)
        self.input_bytes += len(incoming)
        self.output_bytes += len(outgoing)
        row = dict(ordinal=self.count, domain=domain, input_bytes=len(wire), input_sha256=SHA(wire),
            output_bytes=len(result), output_sha256=SHA(result))
        self.index.write((json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode())
        self.domains[domain] += 1
        self.count += 1

    def close(self):
        for stream in (self.inputs, self.outputs, self.index):
            stream.close()
        return dict(cases=self.count, domains=dict(self.domains), input_bytes=self.input_bytes,
            input_sha256=self.input_hash.hexdigest(), output_bytes=self.output_bytes,
            output_sha256=self.output_hash.hexdigest(), files={name: pin(self.path / name)
                for name in ('cases.bin.gz', 'native-output.bin.gz', 'cases.jsonl.gz')})


def pin(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=SHA(raw))


def observe(domain, raw, expected=None):
    global CALLS
    wire = frame(raw)
    result = SESSION.invoke(wire)
    CALLS += 1
    assert len(result) >= 64 and result[:8] == b'HSJERR01'
    status, category, line, column, count, reserved1, reserved2 = struct.unpack('<7Q', result[8:64])
    assert count == len(result) - 64 and reserved1 == reserved2 == 0
    if status == 0:
        assert result == b'HSJERR01' + bytes(56)
    else:
        assert status == 1 and category in (1, 2, 3) and line >= 1 and count > 0
        result[64:].decode('utf8')
    if expected is not None:
        assert result == expected, (domain, raw[:150], result, expected)
    CORPUS.add(domain, wire, result)
    return result


def control(wire, expected_code, *, output=512, workspace=2097152, expected=None):
    global CALLS, CONTROLS
    code, result, _ = MODULE.invoke_raw(wire, output_capacity=output,
        workspace_capacity=workspace, output_fill=0xA5, workspace_fill=0x5A)
    CALLS += 1
    CONTROLS += 1
    assert code == expected_code, (hex(code), hex(expected_code), len(wire), output, workspace)
    if code >= 0xFFFF0000:
        assert result == b'\xa5' * output
    else:
        assert result[:code] == expected and result[code:] == b'\xa5' * (output - code)


class Diagnostics(unittest.TestCase):
    def test_01_original_probe(self):
        rows = [json.loads(x) for x in gzip.decompress((HERE / 'fixtures/original_probe.jsonl.gz').read_bytes()).splitlines()]
        self.assertEqual(len(rows), 1361)
        before = CORPUS.count
        for row in rows:
            case, original = row['case'], row['observation']
            self.assertEqual(case['ordinal'], original['ordinal'])
            observe('original-probe-' + case['domain'], bytes.fromhex(case['input_hex']), expected_observation(original))
        self.assertEqual(CORPUS.count - before, 1361)

    def generated(self, name):
        before = CORPUS.count
        cases = load('serde_error_cases_' + name, HERE / 'error_cases.py')
        for domain, raw in cases.GENERATORS[name]():
            self.assertLessEqual(len(raw), 8388608)
            observe(domain, raw)
        self.assertEqual(CORPUS.count - before, DOMAIN_COUNTS[name])

    def test_02_unicode(self):
        self.generated('unicode')

    def test_03_mutation(self):
        self.generated('mutation')

    def test_04_number(self):
        self.generated('number')

    def test_05_raw_value(self):
        self.generated('raw_value')

    def test_06_wide(self):
        self.generated('wide')

    def test_07_abi_capacity(self):
        before = CONTROLS
        for raw in (b'', b'x', bytes(23), bytes(24), frame(b'null')[:-1],
                frame(b'null')+b' ', b'HSJERQ01'+struct.pack('<QQ', 2, 0),
                b'HSJERQ01'+struct.pack('<QQ', 1, (1<<64)-1), frame(b' ' * 8388609)):
            control(raw, 0xFFFFFFFF)
        for raw in (b'', b'null', b'"x"', b'[1,]', b'{"$serde_json::private::RawValue":"["}'):
            expected = SESSION.invoke(frame(raw))
            global CALLS
            CALLS += 1
            for output in (0, 63, len(expected)-1):
                control(frame(raw), 0xFFFFFFFE, output=output)
            for output in (len(expected), len(expected)+1):
                control(frame(raw), len(expected), output=output, expected=expected)
            control(frame(raw), 0xFFFFFFFE, workspace=1048576+len(raw)-1)
        raw = b'{"$serde_json::private::RawValue":"123"}'
        control(frame(raw), 0xFFFFFFFE, workspace=1048576+len(raw))
        control(frame(raw), 0xFFFFFFFE, workspace=1048576+len(raw)+2)
        self.assertEqual(CONTROLS-before, 41)

    def test_08_static_elf(self):
        metadata = MODULE.metadata['standalone']
        self.assertEqual(metadata['transport'], 'filter')
        executable = OPTIONS.manifest.parent / metadata['path']
        raw = executable.read_bytes()
        self.assertEqual(SHA(raw), metadata['sha256'])
        self.assertEqual(raw[:7], b'\x7fELF\x02\x01\x01')
        phoff = struct.unpack_from('<Q', raw, 32)[0]
        phsize, phcount = struct.unpack_from('<HH', raw, 54)
        for index in range(phcount):
            kind, flags = struct.unpack_from('<II', raw, phoff + index * phsize)
            self.assertNotEqual(kind, 3)
            self.assertNotEqual(flags & 3, 3)
        for index, payload in enumerate((b'', b'null', b'"\xff\\x"', b'{"$serde_json::private::RawValue":"["}')):
            expected = SESSION.invoke(frame(payload))
            global CALLS
            CALLS += 1
            start = time.monotonic()
            process = subprocess.run([str(executable.resolve())], input=frame(payload), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env={'PATH':'', 'LC_ALL':'C'}, timeout=20)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(process.stdout, expected)
            self.assertEqual(process.stderr, b'')
            stem = OPTIONS.output / f'elf-{index}'
            stem.with_suffix('.input').write_bytes(frame(payload))
            stem.with_suffix('.stdout').write_bytes(process.stdout)
            stem.with_suffix('.stderr').write_bytes(process.stderr)
            ELF_RECEIPTS.append(dict(ordinal=index, exit_code=process.returncode,
                timeout_seconds=20, timed_out=False, process_reaped=True, empty_path=True,
                elapsed_seconds=time.monotonic()-start, input=pin(stem.with_suffix('.input')),
                stdout=pin(stem.with_suffix('.stdout')), stderr=pin(stem.with_suffix('.stderr')),
                executable_sha256=metadata['sha256']))


def main():
    global OPTIONS, MODULE, SESSION, CORPUS
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, default=os.environ.get('HIA_SERDE_ERROR_MANIFEST'))
    parser.add_argument('--runtime', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, required=True)
    OPTIONS = parser.parse_args()
    assert OPTIONS.manifest is not None
    OPTIONS.manifest = OPTIONS.manifest.resolve(strict=True)
    OPTIONS.output = OPTIONS.output.resolve()
    OPTIONS.output.mkdir()
    loader = load('serde_error_native_loader', OPTIONS.runtime / 'scripts/hia_native_loader.py')
    MODULE = loader.NativeModule(OPTIONS.manifest, manifest_sha256=SHA(OPTIONS.manifest.read_bytes()))
    assert MODULE.metadata['source_sha256'] == SHA((ROOT / 'native/serde_error.hepta').read_bytes())
    assert MODULE.metadata['compiler_commit'] == 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
    sources = {str(path.relative_to(ROOT)): pin(path) for path in (ROOT / 'native/serde_error.hepta',
        HERE / 'test_serde_error.py', HERE / 'error_cases.py', HERE / 'fixtures/original_probe.jsonl.gz',
        HERE / 'fixtures/original_probe_provenance.json')}
    loader_pin = pin(OPTIONS.runtime / 'scripts/hia_native_loader.py')
    CORPUS = Corpus(OPTIONS.output / 'corpus')
    SESSION = MODULE.session(output_capacity=1024, workspace_capacity=33554432)
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Diagnostics))
    corpus = CORPUS.close()
    summary = dict(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors),
        skipped=len(result.skipped), expected_failures=len(result.expectedFailures), unexpected_successes=len(result.unexpectedSuccesses))
    unchanged = all(pin(ROOT / name)==expected for name,expected in sources.items()) and pin(OPTIONS.runtime/'scripts/hia_native_loader.py')==loader_pin
    passed = result.wasSuccessful() and summary==dict(tests_run=8, failures=0, errors=0, skipped=0, expected_failures=0, unexpected_successes=0)
    passed = passed and corpus['cases']==EXPECTED_CASES and CONTROLS==41 and CALLS==EXPECTED_CASES+50 and len(ELF_RECEIPTS)==4 and unchanged
    report = dict(schema='hepta.runtime.serde-error-native.v1', status='PASS' if passed else 'FAIL',
        summary=summary, expected_groups=EXPECTED_GROUPS, native_calls=CALLS, controls=CONTROLS,
        semantic_cases=corpus['cases'], actual_elf_processes=len(ELF_RECEIPTS), elf=ELF_RECEIPTS,
        elapsed_seconds=time.monotonic()-started, source_unchanged=unchanged, source_files=sources,
        loader=loader_pin, manifest=pin(OPTIONS.manifest), module=MODULE.metadata, corpus=corpus,
        original_executions_in_this_suite=0, original_complete_replay_required=True,
        whole_runtime_closed=False, typed_derive_diagnostics_closed=False)
    (OPTIONS.output/'native-report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    SESSION.close()
    MODULE.close()
    print(json.dumps(dict(status=report['status'],summary=summary,native_calls=CALLS,semantic_cases=corpus['cases'],
        controls=CONTROLS,actual_elf_processes=len(ELF_RECEIPTS),elapsed_seconds=report['elapsed_seconds']),sort_keys=True))
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
