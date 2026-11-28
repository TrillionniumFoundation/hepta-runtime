"""Run the complete segmented borrowed and real-kernel domains on one owner."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import hia_native_local_create_segments_qualification as leaf
from hia_native_local_create_build import verify_build

OUTPUT=Path(os.environ['HIA_LOCAL_CREATE_QUALIFICATION_OUTPUT']).resolve()
MANIFEST=Path(os.environ['HIA_LOCAL_CREATE_MANIFEST']).resolve()


class LocalCreateSegmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources=leaf.source_evidence(ROOT)
        verify_build(MANIFEST,source_root=ROOT)
        cls.base=OUTPUT/leaf.FOLDER/'native';cls.base.mkdir(parents=True,exist_ok=False)
        cls.execution=dict(source_root=str(ROOT),output=str(OUTPUT),manifest=str(MANIFEST),python=sys.executable)

    def run_driver(self,label,name):
        command=[sys.executable,'-I','-B',str(ROOT/leaf.DRIVERS/name)]
        if label=='state':command+=['--manifest',str(MANIFEST.parent/'owner.json')]
        else:command+=['--binary',str(MANIFEST.parent/'local-create.elf')]
        command+=['--output',str(self.base/label)]
        started=time.monotonic();timed_out=False
        child=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:stdout,stderr=child.communicate(timeout=180)
        except subprocess.TimeoutExpired:
            timed_out=True;child.kill();stdout,stderr=child.communicate(timeout=10)
        (self.base/(label+'.driver.stdout')).write_bytes(stdout)
        (self.base/(label+'.driver.stderr')).write_bytes(stderr)
        receipt=dict(command=command,timeout_seconds=180,exit_code=child.returncode,timed_out=timed_out,
            elapsed_seconds=time.monotonic()-started,stdout=leaf.pin(stdout),stderr=leaf.pin(stderr))
        (self.base/(label+'.driver.process.json')).write_bytes(leaf.compact(receipt)+b'\n')
        self.assertFalse(timed_out);self.assertEqual(child.returncode,0,(label,stderr[-4096:]));self.assertEqual(stderr,b'')

    def test_01_complete_borrowed_segment_domain(self):
        self.run_driver('state','segment_cases.py')

    def test_02_complete_ordinary_kernel_race_fault_domain(self):
        self.run_driver('ordinary','segment_native_cases.py')

    def test_03_initial_frame_fences_and_complete_capture(self):
        self.run_driver('admission','segment_admission_cases.py')
        captured=leaf.capture_native(OUTPUT,MANIFEST,source_root=ROOT,execution=self.execution)
        leaf.retire_fixtures(OUTPUT,captured,create=True)
        self.assertEqual(leaf.source_evidence(ROOT),self.sources)
        type(self).capture=captured


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LocalCreateSegmentTests))
    cls=LocalCreateSegmentTests
    passed=result.wasSuccessful()and result.testsRun==3 and not(result.skipped or result.expectedFailures or result.unexpectedSuccesses)
    passed=passed and hasattr(cls,'capture') and leaf.source_evidence(ROOT)==cls.sources
    summary=dict(schema='hepta.runtime.local-create-segments-native-suite.v1',status='PASS'if passed else'FAIL',
        tests_run=result.testsRun,expected_tests=3,failures=len(result.failures),errors=len(result.errors),
        skipped=len(result.skipped),expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses),
        counts=leaf.COUNTS,source_inputs=getattr(cls,'sources',None),execution=getattr(cls,'execution',None),
        manifest_sha256=leaf.sha(MANIFEST.read_bytes()),capture_sha256=leaf.sha(leaf.compact(cls.capture))if hasattr(cls,'capture')else None,
        sources_unchanged=hasattr(cls,'sources')and leaf.source_evidence(ROOT)==cls.sources,**leaf.SCOPE)
    folder=OUTPUT/leaf.FOLDER/'native';folder.mkdir(parents=True,exist_ok=True)
    (folder/'summary.json').write_bytes(leaf.compact(summary)+b'\n')
    print(leaf.compact(summary).decode(),flush=True)
    raise SystemExit(0 if passed else 1)
