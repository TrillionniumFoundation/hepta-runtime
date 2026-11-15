"""Capture every actual native held-syscall and held-poll case."""
from __future__ import annotations
import contextlib
import io
import os
from pathlib import Path
import sys
import traceback
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_local_create_build import verify_build
from hia_native_local_create_async_qualification import (COUNTS,FOLDER,SCOPE,compact,driver,
    execution,native_capture,sha,source_evidence)

OUTPUT=Path(os.environ['HIA_LOCAL_CREATE_QUALIFICATION_OUTPUT']).resolve()
MANIFEST=Path(os.environ['HIA_LOCAL_CREATE_MANIFEST']).resolve()
BASE=OUTPUT/FOLDER


class LocalCreateHeldTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        BASE.mkdir(parents=True,exist_ok=False)
        cls.sources=source_evidence(ROOT)
        verify_build(MANIFEST,source_root=ROOT)
        cls.binary=MANIFEST.parent/'local-create.elf'
        cls.execution=execution(OUTPUT,MANIFEST,ROOT)

    def test_all_43_actual_held_boundaries(self):
        captured=io.StringIO()
        try:
            with contextlib.redirect_stdout(captured):
                result=driver('run_held.py').execute(self.binary,BASE/'native','native')
        finally:(BASE/'native.driver.stdout').write_text(captured.getvalue())
        self.assertEqual(result['status'],'PASS')
        self.assertEqual(result['actual_root_processes'],43)
        self.assertEqual(result['retired_fixture_directories'],43)


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LocalCreateHeldTests))
    passed=result.wasSuccessful()and result.testsRun==1 and not(result.skipped or result.expectedFailures or result.unexpectedSuccesses)
    captured=None;error=None;unchanged=False
    if passed:
        try:
            captured=native_capture(OUTPUT,MANIFEST,source_root=ROOT,origin=LocalCreateHeldTests.execution)
            unchanged=source_evidence(ROOT)==LocalCreateHeldTests.sources
            if not unchanged:raise ValueError('held native source closure changed during actual execution')
        except BaseException as caught:
            passed=False;error=repr(caught);traceback.print_exc()
    summary=dict(schema='hepta.runtime.local-create-held-native-suite.v1',status='PASS'if passed else'FAIL',
        tests_run=result.testsRun,expected_tests=1,failures=len(result.failures),errors=len(result.errors),
        skipped=len(result.skipped),expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses),
        counts=COUNTS if captured else{},source_inputs=getattr(LocalCreateHeldTests,'sources',None),
        execution=getattr(LocalCreateHeldTests,'execution',None),sources_unchanged=unchanged,
        manifest_sha256=sha(MANIFEST.read_bytes()),capture_sha256=sha(compact(captured))if captured else None,scope=SCOPE)
    if error:summary['capture_error']=error
    if BASE.is_dir():(BASE/'native-suite.json').write_bytes(compact(summary)+b'\n')
    print(compact(summary).decode(),flush=True)
    raise SystemExit(0 if passed else 1)
