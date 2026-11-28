"""Re-read actual render-growth evidence; reject changed physical captures."""
from __future__ import annotations
from contextlib import contextmanager
import copy
import gzip
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_view_growth_qualification as q
from qualify_hia_runtime_native import completed_test_summary

CONTROLS = []

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def replace(path, raw):
    path.unlink()
    path.write_bytes(raw)

class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = Path(os.environ['HIA_VIEW_GROWTH_QUALIFICATION_OUTPUT']).resolve(strict=True)
        cls.report = q.decode((cls.output / 'result.json').read_bytes())
        cls.actual = q.native_evidence(ROOT, cls.output, cls.report, completed_test_summary)
        cls.summary = q.decode((cls.output / q.FOLDER / 'result.json').read_bytes())
        cls.module = q.decode((cls.output / cls.report['modules']['view_render_growth']['manifest']).read_bytes())

    def refuses(self, label, invoke):
        with self.assertRaises((ValueError, KeyError, IndexError, OSError, EOFError)):
            invoke()
        self.assertNotIn(label, CONTROLS)
        CONTROLS.append(label)

    def admit(self, output, report):
        return q.native_evidence(ROOT, output, report, completed_test_summary)

    @contextmanager
    def snapshot(self):
        with tempfile.TemporaryDirectory(prefix='view-growth-evidence-', dir=self.output.parent) as directory:
            target = Path(directory) / 'capture'
            target.mkdir()
            for relative in self.actual['artifact_sha256']:
                destination = target / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.link(q.owned(self.output, relative), destination)
            yield target, copy.deepcopy(self.report)

    def change_summary(self, output, report, summary):
        raw = encoded(summary)
        replace(output / (q.SUITE + '.stdout'), raw)
        replace(output / q.FOLDER / 'result.json', raw)
        row = next(row for row in report['checks'] if row['name'] == q.SUITE)
        row.update(stdout_bytes=len(raw), stdout_sha256=q.sha(raw), summary=copy.deepcopy(summary))

    def test_01_actual_admission(self):
        self.assertEqual((self.actual['semantic_cases'], self.actual['native_calls']), (2705, 2707))
        self.assertFalse(self.actual['original_rust_replay'])
        with self.snapshot() as (output, report):
            self.assertEqual(self.admit(output, report), self.actual)

    def test_02_process_identity(self):
        changes = {'missing': None, 'duplicate': None, 'boolean-exit': ('exit_code', False),
            'failed-exit': ('exit_code', 1), 'timeout': ('timed_out', True),
            'deadline': ('timeout_seconds', 181), 'float-deadline': ('timeout_seconds', 180.0),
            'command': ('command', ['/bin/true']), 'stdout-size': ('stdout_bytes', 0),
            'stderr-digest': ('stderr_sha256', '0' * 64), 'zero-elapsed': ('elapsed_seconds', 0),
            'over-deadline': ('elapsed_seconds', 180)}
        for label, mutation in changes.items():
            with self.subTest(label=label):
                report = copy.deepcopy(self.report)
                row = next(row for row in report['checks'] if row['name'] == q.SUITE)
                if label == 'missing': report['checks'].remove(row)
                elif label == 'duplicate': report['checks'].append(copy.deepcopy(row))
                else: row[mutation[0]] = mutation[1]
                self.refuses('process-' + label, lambda: self.admit(self.output, report))

    def test_03_compiled_and_corpus_files(self):
        labels = ('image', 'source', 'manifest-path', 'missing-requests', 'symlink-requests',
                  'corrupt-requests', 'corrupt-output')
        for label in labels:
            with self.subTest(label=label), self.snapshot() as (output, report):
                if label == 'manifest-path':
                    report['modules']['view_render_growth']['manifest'] = '../outside.json'
                elif label in ('image', 'source'):
                    parent = Path(report['modules']['view_render_growth']['manifest']).parent
                    path = output / parent / self.module[label]
                    raw = bytearray(path.read_bytes()); raw[-1] ^= 1; replace(path, raw)
                else:
                    name = 'native-output.txt.gz' if label == 'corrupt-output' else 'requests.hex.gz'
                    path = output / q.FOLDER / name
                    if label == 'missing-requests': path.unlink()
                    elif label == 'symlink-requests':
                        path.unlink(); path.symlink_to(self.output / q.FOLDER / name)
                    else:
                        raw = bytearray(path.read_bytes()); raw[-1] ^= 1; replace(path, raw)
                self.refuses('artifact-' + label, lambda: self.admit(output, report))

    def test_04_rebound_false_accounting(self):
        changes = {'native-calls': ('native_calls', 2705), 'false-rust': ('fresh_rust_processes', 1),
            'false-elf': ('actual_elf_processes', 1), 'source-hash': ('source_sha256', '0' * 64),
            'boolean-count': ('native_semantic_cases', True), 'growth-control': None, 'categories': None}
        for label, mutation in changes.items():
            with self.subTest(label=label), self.snapshot() as (output, report):
                summary = copy.deepcopy(self.summary)
                if label == 'growth-control': summary['growth_cases'][0]['short_output_unchanged'] = False
                elif label == 'categories': summary['categories']['whole'] -= 1
                else: summary[mutation[0]] = mutation[1]
                self.change_summary(output, report, summary)
                self.refuses('summary-' + label, lambda: self.admit(output, report))

    def test_05_rebound_physical_content(self):
        for label in ('duplicate-json', 'nonfinite-json', 'rehashed-short-requests', 'rehashed-short-output'):
            with self.subTest(label=label), self.snapshot() as (output, report):
                summary = copy.deepcopy(self.summary)
                if label in ('duplicate-json', 'nonfinite-json'):
                    path = output / q.FOLDER / 'native-corpus.json'
                    raw = path.read_bytes()
                    if label == 'duplicate-json': raw = b'{"cases":2705,' + raw[1:]
                    else: raw = raw.replace(b'"cases": 2705', b'"cases": NaN', 1)
                    replace(path, raw)
                    summary['corpus_metadata_sha256'] = q.sha(raw)
                else:
                    field = 'requests' if label.endswith('requests') else 'native_output'
                    name = summary[field]['file']
                    raw = gzip.compress(b'00\n' if field == 'requests' else b'OK 00\n', mtime=0)
                    replace(output / q.FOLDER / name, raw)
                    summary[field].update(gzip_bytes=len(raw), gzip_sha256=q.sha(raw))
                self.change_summary(output, report, summary)
                self.refuses('physical-' + label, lambda: self.admit(output, report))

def main():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    success = result.wasSuccessful() and result.testsRun == 5 and len(CONTROLS) == 30
    print(json.dumps({'status': 'PASS' if success else 'FAIL', 'test_groups': result.testsRun,
        'refusal_controls': len(CONTROLS), 'controls': CONTROLS,
        'skipped': len(result.skipped), 'failures': len(result.failures), 'errors': len(result.errors),
        'native_calls_added': 0, 'rust_processes_added': 0,
        'test_sha256': q.sha(Path(__file__).read_bytes()),
        'reader_sha256': q.sha((ROOT / 'scripts/hia_native_view_growth_qualification.py').read_bytes())},
        sort_keys=True), flush=True)
    raise SystemExit(0 if success else 1)

if __name__ == '__main__': main()
