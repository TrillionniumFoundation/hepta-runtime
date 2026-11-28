"""Shared runner for the two complete native Local Create capture suites."""
import contextlib
import io
import os
from pathlib import Path
import sys
import traceback
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_local_create_spec_qualification as qualification


def run(domain):
    q = qualification
    assert domain in ('ordinary', 'held')
    base = Path(os.environ['HIA_LOCAL_CREATE_SPEC_OUTPUT']).resolve()
    assert base.name == q.FOLDER
    output = base.parent
    manifest = Path(os.environ['HIA_LOCAL_CREATE_SPEC_MANIFEST']).resolve()

    class LocalCreateSpecTests(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            base.mkdir(parents=True, exist_ok=True)
            (base / 'native').mkdir(exist_ok=True)
            (base / 'fixtures').mkdir(exist_ok=True)
            cls.sources = q.source_evidence(ROOT)
            q.verify_build(manifest, source_root=ROOT)
            cls.origin = q.execution(output, manifest, ROOT)

        def test_complete_fixed_native_domain(self):
            captured = io.StringIO()
            try:
                with contextlib.redirect_stdout(captured):
                    arguments = [manifest.parent / 'local-create-spec.elf', base / 'native' / domain,
                                 base / 'fixtures' / domain]
                    if domain == 'held': arguments.append(ROOT / q.LEAF)
                    arguments.append('native')
                    q.driver('run_' + domain + '.py').run(*arguments)
            finally:
                (base / (domain + '.driver.stdout')).write_text(captured.getvalue())
            self.assertFalse(any((base / 'fixtures' / domain).iterdir()))

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LocalCreateSpecTests))
    passed = result.wasSuccessful() and result.testsRun == 1 and not (result.skipped or result.expectedFailures or result.unexpectedSuccesses)
    admission = None; error = None; unchanged = False
    if passed:
        try:
            admission = q.native_capture(output, manifest, source_root=ROOT, origin=LocalCreateSpecTests.origin, domain=domain)
            unchanged = q.source_evidence(ROOT) == LocalCreateSpecTests.sources
            if not unchanged: raise ValueError('full Local native source closure changed during actual execution')
        except BaseException as caught:
            passed = False; error = repr(caught); traceback.print_exc()
    if passed:
        summary = q.suite_summary(domain, LocalCreateSpecTests.sources, LocalCreateSpecTests.origin,
                                  q.sha(manifest.read_bytes()), admission)
    else:
        summary = dict(schema='hepta.runtime.local-create-spec-' + domain + '-suite.v1', status='FAIL',
            tests_run=result.testsRun, expected_tests=1, failures=len(result.failures), errors=len(result.errors),
            skipped=len(result.skipped), expected_failures=len(result.expectedFailures), unexpected_successes=len(result.unexpectedSuccesses),
            counts={}, source_inputs=getattr(LocalCreateSpecTests, 'sources', None),
            execution=getattr(LocalCreateSpecTests, 'origin', None), sources_unchanged=unchanged, capture_error=error, scope=q.SCOPE)
    (base / (domain + '-suite.json')).write_bytes(q.compact(summary) + b'\n')
    print(q.compact(summary).decode(), flush=True)
    raise SystemExit(0 if passed else 1)
