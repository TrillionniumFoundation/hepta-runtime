"""Refuse altered full Local receipts and fully rehashed semantic evidence."""
import copy
import os
from pathlib import Path
import sys
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts')); sys.path.insert(0, str(ROOT / 'tests/hia_native'))
import hia_native_local_create_spec_qualification as q
c = q.driver('controls.py')
OUTPUT = Path(os.environ['HIA_LOCAL_CREATE_SPEC_OUTPUT']).resolve().parent
COUNTS = {name: 0 for name in q.CONTROL_COUNTS}


class LocalCreateSpecEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = q.decode((OUTPUT / 'result.json').read_bytes())
        with c.no_execution(): cls.actual = q.core_native_evidence(OUTPUT, cls.report, source_root=ROOT)
        cls.sources = q.source_evidence(ROOT)

    def refuses(self, root, output, report, *, raw=False):
        with c.no_execution():
            with self.assertRaises((ValueError, KeyError, TypeError, AssertionError, OSError, zlib.error)):
                if raw:
                    q.reader().capture(output / q.FOLDER / 'native', root / q.DRIVERS, 'native',
                        binary_identity=self.actual['module']['executable_identity'],
                        execution=q.capture_origin(self.actual['execution'], 'native',
                            Path(self.actual['execution']['manifest']).parent / 'local-create-spec.elf'),
                        fixtures=output / q.FOLDER / 'fixtures')
                else: q.core_native_evidence(output, report, source_root=root)

    def test_01_actual_and_relocated_complete_capture(self):
        self.assertEqual(self.actual['status'], 'PASS'); COUNTS['actual_captures'] += 1
        with c.snapshot(OUTPUT, self.actual['artifact_sha256'], ROOT, self.sources['files']) as (root, output):
            with c.no_execution(), c.forbid_producer_reads(OUTPUT):
                self.assertEqual(q.core_native_evidence(output, self.report, source_root=root), self.actual)
        COUNTS['actual_captures'] += 1

    def test_02_actual_process_custody_refusals(self):
        for change in ('missing', 'duplicate', 'exit', 'boolean-exit', 'timeout', 'start', 'command', 'stdout', 'stderr', 'summary'):
            with self.subTest(change=change), c.snapshot(OUTPUT, self.actual['artifact_sha256'], ROOT) as (root, output):
                report = copy.deepcopy(self.report); row = next(row for row in report['checks'] if row['name'] == q.TESTS[0])
                if change == 'missing': report['checks'].remove(row)
                elif change == 'duplicate': report['checks'].append(copy.deepcopy(row))
                elif change == 'exit': row['exit_code'] = 1
                elif change == 'boolean-exit': row['exit_code'] = False
                elif change == 'timeout': row['timed_out'] = True
                elif change == 'start': row['start_error'] = 'synthetic missing process launch'
                elif change == 'command': row['command'].remove('-I')
                elif change in ('stdout', 'stderr'):
                    path = output / (q.TESTS[0] + '.' + change); c.replace(path, path.read_bytes() + b'changed\n')
                else: row['summary']['scope']['whole_runtime_replaced'] = True
                self.refuses(root, output, report); COUNTS['process_refusals'] += 1

    def test_03_source_and_exact_target_refusals(self):
        names = ('native/local_create_spec.hepta', 'scripts/hia_native_local_create_spec_build.py',
            'scripts/hia_native_local_create_spec_qualification.py', q.DRIVERS + '/evidence.py',
            q.DRIVERS + '/run_held.py', q.REFERENCE + '/src/original_file_ops.rs',
            q.REFERENCE + '/src/original_remote.rs', q.REFERENCE + '/Cargo.lock')
        for name in names:
            with self.subTest(name=name), c.snapshot(OUTPUT, self.actual['artifact_sha256'], ROOT, self.sources['files']) as (root, output):
                path = root / name; c.replace(path, path.read_bytes() + b'\n')
                self.refuses(root, output, self.report); COUNTS['source_refusals'] += 1

    def test_04_rehashed_stream_files_and_owned_boundary_refusals(self):
        self.assertEqual(len(c.ARTIFACT_CHANGES), 30)
        for change in c.ARTIFACT_CHANGES:
            with self.subTest(change=change), c.snapshot(OUTPUT, self.actual['artifact_sha256'], ROOT) as (root, output):
                c.mutate_artifact(output, change, q)
                self.refuses(root, output, self.report, raw=True); COUNTS['artifact_refusals'] += 1

    def test_05_atomic_journal_commit_attribution(self):
        observed = [dict(tid=20, raw_hex='aa'), dict(tid=20, raw_hex='bb'),
                    dict(tid=21, raw_hex='cc'), dict(tid=21, raw_hex='dd')]
        for pipe in (['aa', 'bb', 'cc', 'dd'], ['cc', 'aa', 'dd', 'bb'], ['aa', 'cc', 'bb', 'dd']):
            q.reader().journal_interleaving(observed, pipe); COUNTS['journal_admissions'] += 1
        for pipe in (['aa', 'cc', 'dd'], ['aa', 'bb', 'cc', 'dd', 'dd'], ['aa', 'bb', 'cc', 'ff'],
                     ['bb', 'aa', 'cc', 'dd'], ['aa', 'dd', 'cc', 'bb']):
            with self.assertRaises(ValueError): q.reader().journal_interleaving(observed, pipe)
            COUNTS['journal_refusals'] += 1


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LocalCreateSpecEvidenceTests))
    passed = result.wasSuccessful() and result.testsRun == 5 and not (result.skipped or result.expectedFailures or result.unexpectedSuccesses)
    passed = passed and COUNTS == q.CONTROL_COUNTS
    summary = dict(schema='hepta.runtime.local-create-spec-evidence-controls.v1', status='PASS' if passed else 'FAIL',
        tests_run=result.testsRun, expected_tests=5, failures=len(result.failures), errors=len(result.errors),
        skipped=len(result.skipped), expected_failures=len(result.expectedFailures), unexpected_successes=len(result.unexpectedSuccesses),
        counts=COUNTS, source_inputs=q.source_evidence(ROOT),
        native_evidence_sha256=q.sha(q.compact(getattr(LocalCreateSpecEvidenceTests, 'actual', None))),
        new_native_or_rust_processes=0, synthetic_receipt_controls=True, scope=q.SCOPE)
    (OUTPUT / q.FOLDER / 'evidence-controls.json').write_bytes(q.compact(summary) + b'\n')
    print(q.compact(summary).decode(), flush=True)
    raise SystemExit(0 if passed else 1)
