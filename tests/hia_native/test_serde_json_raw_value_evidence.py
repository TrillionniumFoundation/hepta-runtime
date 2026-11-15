"""Refuse altered completed RawValue execution and its additive full corpus."""
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
from hia_native_json_qualification import source_inputs
from hia_native_raw_value_qualification import (CALLS, CASES, CONTROL_COUNTS, EVIDENCE_REPORT,
                                               FOLDER, TEST, native_evidence)
from qualify_hia_runtime_native import completed_test_summary

COUNTS = {key: 0 for key in CONTROL_COUNTS}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def replace(path, raw):
    path.unlink()
    path.write_bytes(raw)


def replace_json(path, value):
    replace(path, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())


class RawValueEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = Path(os.environ['HIA_JSON_QUALIFICATION_OUTPUT']).resolve()
        cls.report = json.loads((cls.output / 'result.json').read_bytes())
        cls.actual = native_evidence(ROOT, cls.output, cls.report, completed_test_summary)
        cls.pins = source_inputs(ROOT)

    @classmethod
    def tearDownClass(cls):
        if source_inputs(ROOT) != cls.pins:
            raise AssertionError('RawValue sources changed during strict evidence controls')
        result = {'schema': 'hepta.runtime.raw-value-evidence-controls.v1', 'status': 'PASS',
                  'synthetic_receipt_controls': True, 'new_native_calls': 0,
                  'source_inputs': cls.pins, 'counts': COUNTS}
        with (cls.output / EVIDENCE_REPORT).open('x') as stream:
            stream.write(json.dumps(result, indent=2, sort_keys=True) + '\n')
        print(json.dumps(result, sort_keys=True), flush=True)

    def snapshot(self, *, with_sources=False):
        temporary = tempfile.TemporaryDirectory(prefix='raw-value-evidence-', dir=self.output.parent)
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
                if row['name'] == TEST:
                    row['command'] = [row['command'][0], '-I', '-B', str(root / 'tests/hia_native' / TEST)]
        return root, output, report

    def refuses(self, root, output, report, category):
        with self.assertRaises((ValueError, KeyError, FileNotFoundError, AssertionError)):
            native_evidence(root, output, report, completed_test_summary)
        COUNTS[category] += 1

    @staticmethod
    def row(report):
        return next(row for row in report['checks'] if row['name'] == TEST)

    def refresh_stdout(self, output, report, summary):
        raw = (json.dumps(summary, sort_keys=True) + '\n').encode()
        replace(output / (TEST + '.stdout'), raw)
        self.row(report).update(summary=summary, stdout_sha256=sha(raw), stdout_bytes=len(raw))

    def test_01_completed_shared_owner_and_domain_are_bound(self):
        self.assertEqual(self.actual['actual_native_calls'], CALLS)
        self.assertEqual(self.actual['captured_reference_cases'], CASES)
        self.assertEqual(self.actual['actual_elf_runs'], 0)
        self.assertFalse(self.actual['production_activated'])
        self.assertFalse(self.actual['whole_runtime_replaced'])
        COUNTS['actual_capture'] += 1

    def test_02_incomplete_or_counterfeit_processes_refuse(self):
        for change in ('missing', 'duplicate', 'exit', 'boolean-exit', 'timeout', 'start',
                       'command', 'stdout', 'stderr', 'summary'):
            with self.subTest(change=change):
                root, output, report = self.snapshot()
                row = self.row(report)
                if change == 'missing': report['checks'].remove(row)
                elif change == 'duplicate': report['checks'].append(copy.deepcopy(row))
                elif change == 'exit': row['exit_code'] = 1
                elif change == 'boolean-exit': row['exit_code'] = False
                elif change == 'timeout': row['timed_out'] = True
                elif change == 'start': row['start_error'] = 'synthetic failed launch'
                elif change == 'command': row['command'].remove('-I')
                elif change in ('stdout', 'stderr'):
                    path = output / (TEST + '.' + change)
                    replace(path, path.read_bytes() + b'changed\n')
                else: row['summary']['synthetic_forgery'] = True
                self.refuses(root, output, report, 'completion_refusals')

    def test_03_changed_domain_or_shared_owner_sources_refuse(self):
        for name in ('native/serde_json.hepta', 'tests/hia_native/raw_value_cases.py',
                     'tests/hia_native/test_serde_json_raw_value.py',
                     'scripts/hia_native_raw_value_qualification.py'):
            with self.subTest(name=name):
                root, output, report = self.snapshot(with_sources=True)
                path = root / name
                replace(path, path.read_bytes() + b'\n')
                self.refuses(root, output, report, 'source_refusals')

    def test_04_incomplete_or_rehashed_full_corpus_refuses(self):
        for change in ('request-byte', 'output-byte', 'metadata-only', 'case-count', 'boolean-case',
                       'call-count', 'boolean-category', 'categories', 'source-claim', 'image-claim',
                       'extension-claim', 'request-digest', 'member-path', 'elapsed'):
            with self.subTest(change=change):
                root, output, report = self.snapshot()
                folder = output / FOLDER
                metadata = json.loads((folder / 'native-corpus.json').read_bytes())
                if change in ('request-byte', 'output-byte'):
                    target = folder / ('requests.hex' if change == 'request-byte' else 'native-output.txt')
                    raw = bytearray(target.read_bytes())
                    raw[0] = ord('0') if raw[0] != ord('0') else ord('1')
                    replace(target, raw)
                else:
                    if change == 'metadata-only': metadata['actual_native_calls'] -= 1
                    elif change == 'case-count': metadata['cases'] -= 1
                    elif change == 'boolean-case': metadata['cases'] = True
                    elif change == 'call-count': metadata['actual_native_calls'] -= 1
                    elif change == 'boolean-category': metadata['categories']['8MiB-raw-node-arena'] = True
                    elif change == 'categories': metadata['categories'].pop('8MiB-raw-node-arena')
                    elif change == 'source-claim': metadata['qualification_inputs']['files']['scripts/hia_native_loader.py'] = '0' * 64
                    elif change == 'image-claim': metadata['image_sha256'] = '0' * 64
                    elif change == 'extension-claim': metadata['extension_inputs']['raw_value_cases.py'] = '0' * 64
                    elif change == 'request-digest': metadata['requests_sha256'] = '0' * 64
                    elif change == 'member-path': metadata['requests_file'] = '../requests.hex'
                    elif change == 'elapsed': metadata['native_seconds'] = float('nan')
                    replace_json(folder / 'native-corpus.json', metadata)
                    if change != 'metadata-only': self.refresh_stdout(output, report, metadata)
                self.refuses(root, output, report, 'corpus_refusals')
        self.assertEqual(COUNTS, CONTROL_COUNTS)


if __name__ == '__main__':
    unittest.main(verbosity=2)
