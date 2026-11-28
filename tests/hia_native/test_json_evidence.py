"""Reject altered completed JSON receipts without counting new native execution."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from hia_native_json_qualification import (COMPONENTS, EVIDENCE_COUNTS, EVIDENCE_REPORT,
    TRANSPORT_REPORT, native_evidence, source_inputs)
from qualify_hia_runtime_native import completed_test_summary

COUNTS = {key: 0 for key in EVIDENCE_COUNTS}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def replace(path, raw):
    path.unlink()
    path.write_bytes(raw)


def replace_json(path, value):
    replace(path, (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())


class JSONEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = Path(os.environ['HIA_JSON_QUALIFICATION_OUTPUT']).resolve()
        cls.report = json.loads((cls.output / 'result.json').read_bytes())
        cls.actual = native_evidence(ROOT, cls.output, cls.report, completed_test_summary)
        cls.pins = source_inputs(ROOT)

    @classmethod
    def tearDownClass(cls):
        if source_inputs(ROOT) != cls.pins:
            raise AssertionError('JSON qualification inputs changed during mutation controls')
        result = {'schema': 'hepta.runtime.json-evidence-controls.v1', 'status': 'PASS',
                  'synthetic_receipt_controls': True, 'new_native_calls': 0,
                  'source_inputs': cls.pins, 'counts': COUNTS}
        with (cls.output / EVIDENCE_REPORT).open('x') as stream:
            stream.write(json.dumps(result, indent=2, sort_keys=True) + '\n')
        print(json.dumps(result, sort_keys=True), flush=True)

    def snapshot(self, *, with_sources=False):
        temporary = tempfile.TemporaryDirectory(prefix='json-evidence-', dir=self.output.parent)
        self.addCleanup(temporary.cleanup)
        folder = Path(temporary.name)
        output = folder / 'capture'
        output.mkdir()
        for name in {**self.actual['artifact_sha256'], **self.actual['corpus_sha256']}:
            target = output / name
            target.parent.mkdir(parents=True, exist_ok=True)
            os.link(self.output / name, target)
        report = copy.deepcopy(self.report)
        root = ROOT
        if with_sources:
            root = folder / 'source'
            for name in self.pins['files']:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            for row in report['checks']:
                if row['name'] in self.actual['tests']:
                    row['command'] = [row['command'][0], '-I', '-B', str(root / 'tests/hia_native' / row['name'])]
        return root, output, report

    def refuses(self, root, output, report, category):
        with self.assertRaises((ValueError, KeyError, FileNotFoundError, AssertionError)):
            native_evidence(root, output, report, completed_test_summary)
        COUNTS[category] += 1

    @staticmethod
    def row(report, name):
        return next(row for row in report['checks'] if row['name'] == name)

    def refresh_stdout(self, output, report, name, summary):
        raw = (json.dumps(summary, sort_keys=True) + '\n').encode()
        replace(output / (name + '.stdout'), raw)
        self.row(report, name).update(summary=summary, stdout_sha256=sha(raw), stdout_bytes=len(raw))

    def refresh_manifest(self, output, report, component, module):
        path = output / report['modules'][component]['manifest']
        replace_json(path, module)
        report['modules'][component]['sha256'] = sha(path.read_bytes())

    def test_01_actual_three_suites_are_bound_without_new_execution(self):
        self.assertEqual(self.actual['actual_native_calls'], 22918)
        self.assertEqual(self.actual['actual_elf_runs'], 13)
        self.assertEqual(self.actual['captured_reference_cases'], 22865)
        self.assertFalse(self.actual['production_activated'])
        self.assertFalse(self.actual['whole_runtime_replaced'])
        COUNTS['actual_capture'] += 1

    def test_02_incomplete_or_counterfeit_test_processes_refuse(self):
        changes = ('missing', 'duplicate', 'exit', 'boolean-exit', 'timeout', 'start', 'command', 'stdout', 'stderr', 'summary')
        for name in self.actual['tests']:
            for change in changes:
                with self.subTest(name=name, change=change):
                    root, output, report = self.snapshot()
                    row = self.row(report, name)
                    if change == 'missing':
                        report['checks'].remove(row)
                    elif change == 'duplicate':
                        report['checks'].append(copy.deepcopy(row))
                    elif change == 'exit':
                        row['exit_code'] = 1
                    elif change == 'boolean-exit':
                        row['exit_code'] = False
                    elif change == 'timeout':
                        row['timed_out'] = True
                    elif change == 'start':
                        row['start_error'] = 'synthetic failed launch'
                    elif change == 'command':
                        row['command'].remove('-I')
                    elif change in ('stdout', 'stderr'):
                        path = output / (name + '.' + change)
                        replace(path, path.read_bytes() + b'changed\n')
                    else:
                        row['summary']['synthetic_forgery'] = True
                    self.refuses(root, output, report, 'completion_refusals')

    def test_03_changed_current_sources_and_reference_lock_refuse(self):
        names = ('native/fence_json.hepta', 'native/serde_filter_packer.hepta',
                 'tests/hia_native/serde_json_oracle/oracle.rs', 'tests/hia_native/serde_json_oracle/Cargo.lock',
                 'tests/hia_native/test_serde_json.py', 'scripts/hia_native_json_qualification.py')
        for name in names:
            with self.subTest(name=name):
                root, output, report = self.snapshot(with_sources=True)
                path = root / name
                replace(path, path.read_bytes() + b'\n')
                self.refuses(root, output, report, 'source_refusals')

    def test_04_compilation_packing_and_rehashed_elf_changes_refuse(self):
        changes = ('image', 'elf-header', 'elf-entry', 'compiled-source', 'compile-receipt',
                   'compile-output', 'pack-input', 'pack-receipt', 'packer-image', 'packer-source')
        for change in changes:
            with self.subTest(change=change):
                root, output, report = self.snapshot()
                path = output / report['modules']['serde_json']['manifest']
                module = json.loads(path.read_bytes())
                folder = path.parent
                cache = output / 'build/packers' / module['standalone']['packer_source_sha256']
                if change in ('elf-header', 'elf-entry'):
                    target = folder / module['standalone']['path']
                    raw = bytearray(target.read_bytes())
                    raw[200 if change == 'elf-header' else 338] ^= 1
                    replace(target, raw)
                    module['standalone']['sha256'] = sha(raw)
                    module['standalone']['inspection']['sha256'] = sha(raw)
                    self.refresh_manifest(output, report, 'serde_json', module)
                elif change in ('compile-receipt', 'pack-receipt'):
                    target = folder / ('module.receipt.json' if change == 'compile-receipt' else 'pack.receipt.json')
                    receipt = json.loads(target.read_bytes())
                    receipt['source_unchanged'] = False
                    replace_json(target, receipt)
                    if change == 'pack-receipt':
                        module['standalone']['pack_receipt'] = receipt
                        self.refresh_manifest(output, report, 'serde_json', module)
                else:
                    target = {'image': folder / module['image'], 'compiled-source': folder / module['source'],
                        'compile-output': folder / 'module.output.bin', 'pack-input': folder / 'pack.input.bin',
                        'packer-image': cache / 'packer.image.bin', 'packer-source': cache / 'source.hepta'}[change]
                    raw = bytearray(target.read_bytes())
                    raw[-1] ^= 1
                    replace(target, raw)
                self.refuses(root, output, report, 'artifact_refusals')

    def test_05_incomplete_or_rehashed_corpus_and_elf_receipts_refuse(self):
        changes = ('request-byte', 'output-byte', 'metadata-only', 'case-count', 'call-count',
                   'categories', 'boolean-category', 'source-claim', 'missing-elf', 'elf-output', 'corpus-digest')
        for change in changes:
            with self.subTest(change=change):
                root, output, report = self.snapshot()
                folder = output / COMPONENTS['fence_json']['folder']
                metadata = json.loads((folder / 'native-corpus.json').read_bytes())
                if change in ('request-byte', 'output-byte'):
                    target = folder / ('requests.hex' if change == 'request-byte' else 'native-output.txt')
                    raw = bytearray(target.read_bytes())
                    raw[0] = ord('0') if raw[0] != ord('0') else ord('1')
                    replace(target, raw)
                else:
                    if change == 'metadata-only': metadata['actual_native_calls'] -= 1
                    elif change == 'case-count': metadata['cases'] -= 1
                    elif change == 'call-count': metadata['actual_native_calls'] -= 1
                    elif change == 'categories': metadata['categories'].pop('duplicate-known')
                    elif change == 'boolean-category': metadata['categories']['unknown-duplicate'] = True
                    elif change == 'source-claim': metadata['qualification_inputs']['files']['scripts/hia_native_loader.py'] = '0' * 64
                    elif change == 'missing-elf': metadata['elf_observations'].pop()
                    elif change == 'elf-output': metadata['elf_observations'][0]['output_sha256'] = '0' * 64
                    elif change == 'corpus-digest': metadata['requests_sha256'] = '0' * 64
                    replace_json(folder / 'native-corpus.json', metadata)
                    if change != 'metadata-only':
                        self.refresh_stdout(output, report, 'test_fence_json.py', metadata)
                self.refuses(root, output, report, 'corpus_refusals')

    def test_06_counterfeit_transport_results_refuse_and_counts_close(self):
        changes = ('count', 'missing-case', 'exit', 'input', 'output', 'elapsed', 'elf', 'packer')
        for change in changes:
            with self.subTest(change=change):
                root, output, report = self.snapshot()
                transport = json.loads((output / TRANSPORT_REPORT).read_bytes())
                if change == 'count': transport['actual_elf_runs'] -= 1
                elif change == 'missing-case': transport['runs'].pop()
                elif change == 'exit': transport['runs'][1]['exit_code'] = 0
                elif change == 'input': transport['runs'][0]['input_sha256'] = '0' * 64
                elif change == 'output': transport['runs'][0]['output_bytes'] = 0
                elif change == 'elapsed': transport['runs'][0]['elapsed'] = float('nan')
                elif change == 'elf': transport['elf_sha256'] = '0' * 64
                elif change == 'packer': transport['packer_sha256'] = '0' * 64
                replace_json(output / TRANSPORT_REPORT, transport)
                self.refresh_stdout(output, report, 'test_serde_json_transport.py', transport)
                self.refuses(root, output, report, 'transport_refusals')
        self.assertEqual(COUNTS, EVIDENCE_COUNTS)


if __name__ == '__main__':
    unittest.main(verbosity=2)
