"""Run every retained exclusive-create native state and filesystem case."""
from __future__ import annotations
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import traceback
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_local_create_build import verify_build
from hia_native_local_create_qualification import (COUNTS,FOLDER,SCOPE,capture_native,compact,
    driver,retire_fixtures,sha,source_evidence)
OUTPUT=Path(os.environ['HIA_LOCAL_CREATE_OUTPUT']).resolve()
QUALIFICATION=Path(os.environ['HIA_LOCAL_CREATE_QUALIFICATION_OUTPUT']).resolve()
MANIFEST=Path(os.environ['HIA_LOCAL_CREATE_MANIFEST']).resolve()
BASE=OUTPUT/'native'


class LocalCreateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert OUTPUT==QUALIFICATION/FOLDER
        BASE.mkdir(parents=True,exist_ok=False)
        cls.sources=source_evidence(ROOT)
        cls.metadata=verify_build(MANIFEST,source_root=ROOT)
        cls.binary=MANIFEST.parent/'local-create.elf'
        cls.execution=dict(source_root=str(ROOT),output=str(QUALIFICATION),manifest=str(MANIFEST))

    def call(self,label,callback):
        captured=io.StringIO()
        try:
            with contextlib.redirect_stdout(captured):return callback()
        finally:(BASE/(label+'.driver.stdout')).write_text(captured.getvalue())

    def test_01_all_native_state_controls(self):
        result=self.call('state',lambda:driver(ROOT,'state_controls.py').run_state_controls(MANIFEST.parent/'owner.json',BASE/'state'))
        self.assertEqual(result['counts']['actual_native_calls'],54030)
        self.assertEqual(result['status'],'PASS')

    def test_02_all_actual_kernel_cases(self):
        rows,summary=self.call('kernel',lambda:driver(ROOT,'kernel_cases.py').run_corpus(self.binary,BASE/'kernel',native=True))
        self.assertEqual(len(rows),285);self.assertEqual(summary['status'],'PASS')

    def test_03_two_actual_creators_race(self):
        self.call('race',lambda:driver(ROOT,'race_cases.py').run_races(self.binary,BASE/'race',False))
        result=json.loads((BASE/'race/result.json').read_bytes())
        self.assertEqual(result['pairs'],32);self.assertEqual(result['status'],'PASS')

    def test_04_actual_partial_writes_and_efbig(self):
        result=self.call('fault',lambda:driver(ROOT,'fault_cases.py').run_faults(self.binary,BASE/'fault',native=True))
        self.assertEqual(result['cases'],8);self.assertEqual(result['status'],'PASS')


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LocalCreateTests))
    passed=result.wasSuccessful() and result.testsRun==4 and not(result.skipped or result.expectedFailures or result.unexpectedSuccesses)
    capture=None;error=None;unchanged=False
    if passed:
        try:
            capture=capture_native(QUALIFICATION,MANIFEST,source_root=ROOT,execution=LocalCreateTests.execution)
            unchanged=source_evidence(ROOT)==LocalCreateTests.sources
            if not unchanged:raise ValueError('native sources changed during execution')
            retire_fixtures(QUALIFICATION,FOLDER+'/native',capture,create=True)
        except BaseException as caught:
            passed=False;error=repr(caught);traceback.print_exc()
    summary=dict(schema='hepta.runtime.local-create-native-suite.v1',status='PASS' if passed else 'FAIL',
        tests_run=result.testsRun,expected_tests=4,failures=len(result.failures),errors=len(result.errors),
        skipped=len(result.skipped),expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses),
        counts=COUNTS if capture else {},source_inputs=getattr(LocalCreateTests,'sources',None),
        execution=getattr(LocalCreateTests,'execution',None),manifest_sha256=sha(MANIFEST.read_bytes()),
        capture_sha256=sha(compact(capture)) if capture else None,sources_unchanged=unchanged,**SCOPE)
    if error:summary['capture_error']=error
    if BASE.is_dir():(BASE/'summary.json').write_bytes(compact(summary)+b'\n')
    print(compact(summary).decode(),flush=True)
    raise SystemExit(0 if passed else 1)
