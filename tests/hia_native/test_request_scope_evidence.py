#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Physical admission refusals; no new native or original semantic execution."""
from __future__ import annotations
import copy
from contextlib import contextmanager
import gzip
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'tests/hia_native'))
from evidence_snapshot import copy_evidence_files, unrelated_fixture_guard
import hia_native_request_scope_qualification as q
from qualify_hia_runtime_native import completed_test_summary

CONTROLS = []


@contextmanager
def snapshot(source, expected):
    with tempfile.TemporaryDirectory(prefix='hia-request-scope-evidence-', dir=source.parent) as directory:
        destination = Path(directory) / 'snapshot'
        with unrelated_fixture_guard(source):
            copy_evidence_files(source, destination, expected)
        yield destination


@contextmanager
def source_snapshot():
    with tempfile.TemporaryDirectory(prefix='hia-request-scope-source-', dir=ROOT.parent) as directory:
        destination = Path(directory) / 'source'
        copy_evidence_files(ROOT, destination, q.source_identity(ROOT))
        yield destination


@contextmanager
def changed(path, replacement):
    before = path.read_bytes()
    path.unlink()
    path.write_bytes(replacement)
    try:
        yield
    finally:
        path.unlink()
        path.write_bytes(before)


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = Path(os.environ['HIA_REQUEST_SCOPE_QUALIFICATION_OUTPUT']).resolve()
        report_path = Path(os.environ.get('HIA_REQUEST_SCOPE_QUALIFICATION_REPORT',
                                         str(cls.output / 'result.json')))
        cls.report = q.decode(report_path.read_bytes())
        cls.baseline = q.native_evidence(ROOT, cls.output, cls.report, completed_test_summary)
        cls.native = q.decode((cls.output / q.FOLDER / 'native-corpus.json').read_bytes())
        cls.boundary = q.decode((cls.output / q.BOUNDARY_FOLDER / 'native-boundary-corpus.json').read_bytes())
        manifest = cls.output / cls.report[q.FIXTURE_KEY]['manifest']
        cls.manifest = q.decode(manifest.read_bytes())
        cls.executable = manifest.parent / cls.manifest['executable']

    def reject(self, name, callback):
        self.assertNotIn(name, CONTROLS)
        with self.assertRaises((ValueError, OSError), msg=name):
            callback()
        CONTROLS.append(name)

    @contextmanager
    def snapshot(self):
        with snapshot(self.output, self.baseline['artifact_sha256']) as output:
            # Replay process argv still names the actual original executable.
            # Admit copied build bytes without inventing a relocated execution.
            binding, _ = q.build_evidence(ROOT, output, self.report, q.Evidence(output))
            self.assertEqual(binding, self.baseline['composition'])
            yield output

    def test_01_complete_unchanged_evidence_is_admitted(self):
        self.assertEqual(self.baseline['status'], 'PASS')
        self.assertEqual(self.baseline['counts']['native_cases_added_by_validation'], 0)
        with source_snapshot() as root:
            self.assertEqual(q.source_identity(root), self.baseline['source_pins'])
        with self.snapshot() as output:
            binding, _ = q.build_evidence(ROOT, output, self.report, q.Evidence(output))
            self.assertEqual(binding, self.baseline['composition'])

    def test_02_actual_process_identity_and_deadline(self):
        cases = [
            ('foreign-command', lambda row: row['command'].__setitem__(0, '/unqualified-python')),
            ('missing-isolation', lambda row: row['command'].__setitem__(1, '-B')),
            ('float-deadline', lambda row: row.__setitem__('timeout_seconds', 180.0)),
            ('enlarged-deadline', lambda row: row.__setitem__('timeout_seconds', 181)),
            ('elapsed-at-deadline', lambda row: row.__setitem__('elapsed_seconds', 180)),
            ('negative-elapsed', lambda row: row.__setitem__('elapsed_seconds', -1)),
            ('boolean-exit', lambda row: row.__setitem__('exit_code', False)),
            ('timed-out-process', lambda row: row.__setitem__('timed_out', True)),
            ('stdout-byte-count', lambda row: row.__setitem__('stdout_bytes', row['stdout_bytes'] + 1)),
            ('stdout-receipt-hash', lambda row: row.__setitem__('stdout_sha256', '0' * 64)),
        ]
        for name, mutate in cases:
            report = copy.deepcopy(self.report)
            row = next(row for row in report['checks'] if row['name'] == q.NATIVE_SUITE)
            mutate(row)
            self.reject(name, lambda: q.completed_suite(ROOT, self.output, report,
                        completed_test_summary, q.NATIVE_SUITE, q.NATIVE_GROUPS))
        report = copy.deepcopy(self.report)
        report['checks'].append(copy.deepcopy(next(row for row in report['checks'] if row['name'] == q.NATIVE_SUITE)))
        self.reject('duplicate-process', lambda: q.completed_suite(ROOT, self.output, report,
                    completed_test_summary, q.NATIVE_SUITE, q.NATIVE_GROUPS))
        report = copy.deepcopy(self.report)
        report['checks'] = [row for row in report['checks'] if row['name'] != q.NATIVE_SUITE]
        self.reject('missing-process', lambda: q.completed_suite(ROOT, self.output, report,
                    completed_test_summary, q.NATIVE_SUITE, q.NATIVE_GROUPS))

    def test_03_source_identity_and_owned_paths(self):
        with source_snapshot() as root:
            for label, name in [('changed-owner-source', 'native/request_scope_lifecycle.hepta'),
                                ('changed-imported-helper', 'native/text_budget.hepta')]:
                path = root / name
                with changed(path, path.read_bytes() + b'\n'):
                    self.reject(label, lambda: q.source_identity(root))
            path = root / 'native/request_scope_lifecycle_composition.json'
            proof = q.decode(path.read_bytes())
            proof['whole_runtime_replaced'] = True
            with changed(path, q.json_bytes(proof)):
                self.reject('changed-source-scope-claim', lambda: q.source_identity(root))
            path = root / 'native/request_scope_lifecycle.hepta'
            path.unlink()
            path.symlink_to(ROOT / 'native/request_scope_lifecycle.hepta')
            self.reject('symlinked-source', lambda: q.owned(root, 'native/request_scope_lifecycle.hepta'))
        self.reject('duplicate-json-key', lambda: q.decode(b'{"a":1,"a":2}'))
        self.reject('nonfinite-json-number', lambda: q.decode(b'{"a":NaN}'))
        self.reject('parent-path-escape', lambda: q.owned(self.output, '../result.json'))
        self.reject('absolute-artifact-path', lambda: q.owned(self.output, str(self.output / 'result.json')))

    def test_04_actual_compiler_images_and_private_table(self):
        with self.snapshot() as output:
            def check(report=None):
                return q.build_evidence(ROOT, output, self.report if report is None else report, q.Evidence(output))

            report = copy.deepcopy(self.report)
            report['compiler_image_sha256'] = '0' * 64
            self.reject('changed-compiler-identity', lambda: check(report))
            manifest_path = output / self.report[q.FIXTURE_KEY]['manifest']
            with changed(manifest_path, manifest_path.read_bytes() + b'\n'):
                self.reject('changed-composition-manifest', check)
            meta = copy.deepcopy(self.manifest)
            meta['profile'][0]['call_mask'] ^= 64
            raw = q.json_bytes(meta)
            report = copy.deepcopy(self.report)
            report[q.FIXTURE_KEY]['sha256'] = q.sha(raw)
            with changed(manifest_path, raw):
                self.reject('changed-private-child-privileges', lambda: check(report))
            for label, name in [('changed-native-source-bytes', 'module_01.hepta'),
                                ('changed-native-image-bytes', 'module_01.image.bin'),
                                ('changed-native-elf-prefix', 'native-local-read.elf')]:
                path = manifest_path.parent / name
                raw = path.read_bytes()
                with changed(path, bytes([raw[0] ^ 1]) + raw[1:]):
                    self.reject(label, check)
            source_hash = self.manifest['members'][1]['source_sha256']
            receipt_path = output / 'build/modules' / ('composition-' + source_hash[:24]) / 'module.receipt.json'
            receipt = q.decode(receipt_path.read_bytes())
            receipt['produced_sha256'] = '0' * 64
            with changed(receipt_path, q.json_bytes(receipt)):
                self.reject('changed-actual-compile-receipt', check)

    def test_05_complete_captures_and_refusal_snapshots(self):
        name = 'interleaved'
        record = copy.deepcopy(self.native['runs'][name])
        record['streams']['input']['bytes'] += 1
        self.reject('changed-frozen-input-domain', lambda: q.native_run(name, record, self.executable, q.Evidence(self.output)))
        with self.snapshot() as output:
            original = self.native['runs'][name]
            stdout_path = output / q.FOLDER / original['streams']['stdout']['path']
            packed = stdout_path.read_bytes()
            with changed(stdout_path, bytes([packed[0] ^ 1]) + packed[1:]):
                self.reject('changed-compressed-native-capture', lambda: q.native_run(name, original, self.executable, q.Evidence(output)))
            plain = gzip.decompress(packed)
            altered = gzip.compress(plain[:-1] + b'x', mtime=0)
            record = copy.deepcopy(original)
            record['streams']['stdout'].update(gzip_bytes=len(altered), gzip_sha256=q.sha(altered))
            with changed(stdout_path, altered):
                self.reject('changed-full-native-output-with-new-envelope',
                            lambda: q.native_run(name, record, self.executable, q.Evidence(output)))
            record = copy.deepcopy(original)
            record['streams']['domains']['sha256'] = '0' * 64
            self.reject('changed-native-row-accounting', lambda: q.native_run(name, record, self.executable, q.Evidence(output)))
            stdout_path.unlink()
            self.reject('missing-native-capture', lambda: q.native_run(name, original, self.executable, q.Evidence(output)))
            stdout_path.write_bytes(packed)
            extra = output / q.FOLDER / 'unreported.gz'
            extra.write_bytes(b'extra')
            expected = {'native-corpus.json'} | {stream['path'] for row in self.native['runs'].values() for stream in row['streams'].values()}
            self.reject('unreported-corpus-file', lambda: q.Evidence(output).inventory(q.FOLDER, expected))
            extra.unlink()
            row = copy.deepcopy(self.boundary['records'][0])
            path = output / q.BOUNDARY_FOLDER / row['streams']['workspace-after']['path']
            plain = gzip.decompress(path.read_bytes())
            altered = gzip.compress(plain[:-1] + bytes([plain[-1] ^ 1]), mtime=0)
            row['streams']['workspace-after'].update(gzip_bytes=len(altered), gzip_sha256=q.sha(altered))
            with changed(path, altered):
                self.reject('changed-refusal-workspace-tail-with-new-envelope',
                            lambda: q.boundary_row(0, row, q.Evidence(output)))
            row = copy.deepcopy(self.boundary['records'][0])
            row['actual_code'] = False
            self.reject('boolean-refusal-result', lambda: q.boundary_row(0, row, q.Evidence(output)))

    def test_06_native_reference_and_scope_domains_remain_distinct(self):
        for name, field, value in [
            ('invented-original-process', 'original_rust_processes', 1),
            ('invented-production-dispatch', 'production_dispatcher_installed', True),
            ('invented-caller-replacement', 'legacy_callers_replaced', True),
            ('invented-unbounded-cache', 'unbounded_cache_storage_closed', True),
            ('missing-native-request', 'native_elf_requests', self.native['native_elf_requests'] - 1),
        ]:
            summary = copy.deepcopy(self.native)
            summary[field] = value
            self.reject(name, lambda: q.native_header(summary))
        for name, field in [('invented-boundary-child-execution', 'executed_native_children'),
                            ('invented-original-refusal-operation', 'original_operations')]:
            summary = copy.deepcopy(self.boundary)
            summary[field] = 1
            self.reject(name, lambda: q.boundary_header(summary))


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {'schema': 'hepta.runtime.request-scope-evidence-tests.v1',
               'status': 'PASS' if result.wasSuccessful() else 'FAIL',
               'groups': result.testsRun, 'refusal_controls': len(CONTROLS),
               'failures': len(result.failures), 'errors': len(result.errors),
               'skipped': len(result.skipped), 'controls': sorted(CONTROLS),
               'new_native_calls': 0, 'new_original_processes': 0,
               'production_dispatcher_installed': False, 'legacy_callers_replaced': False,
               'whole_runtime_replaced': False,
               'native_evidence_sha256': q.sha(q.json_bytes(getattr(EvidenceTests, 'baseline', None))),
               'reader_sha256': q.sha((ROOT / 'scripts/hia_native_request_scope_qualification.py').read_bytes()),
               'test_sha256': q.sha(Path(__file__).read_bytes())}
    sys.stdout.buffer.write(q.json_bytes(summary))
    raise SystemExit(0 if result.wasSuccessful() else 1)
