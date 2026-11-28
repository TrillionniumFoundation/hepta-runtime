"""Run the complete caller/cache/parent and mkdir-await borrowed domains."""
from pathlib import Path
import os,subprocess,sys,time,unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import hia_native_local_create_spec_state_qualification as leaf
from hia_native_local_create_spec_build import verify_build
OUTPUT=Path(os.environ['HIA_LOCAL_CREATE_SPEC_OUTPUT']).resolve()
MANIFEST=Path(os.environ['HIA_LOCAL_CREATE_SPEC_MANIFEST']).resolve()

class StateControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources=leaf.source_evidence(ROOT);verify_build(MANIFEST,source_root=ROOT)
        cls.folder=OUTPUT/'state';cls.folder.mkdir(parents=True,exist_ok=False)
        cls.execution=dict(source_root=str(ROOT),manifest=str(MANIFEST),output=str(OUTPUT.parent),python=sys.executable)

    def run_driver(self,label):
        command=[sys.executable,'-I','-B',str(ROOT/leaf.DRIVERS/('state_'+label+'.py')),
            '--manifest',str(MANIFEST.parent/'caller.json'),'--output',str(self.folder/label)]
        started=time.monotonic();timed_out=False
        child=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:stdout,stderr=child.communicate(timeout=180)
        except subprocess.TimeoutExpired:
            timed_out=True;child.kill();stdout,stderr=child.communicate(timeout=10)
        (self.folder/(label+'.stdout')).write_bytes(stdout);(self.folder/(label+'.stderr')).write_bytes(stderr)
        receipt=dict(command=command,timeout_seconds=180,exit_code=child.returncode,timed_out=timed_out,
            elapsed_seconds=time.monotonic()-started,stdout=leaf.pin(stdout),stderr=leaf.pin(stderr))
        (self.folder/(label+'.process.json')).write_bytes(leaf.compact(receipt)+b'\n')
        self.assertFalse(timed_out);self.assertEqual(child.returncode,0,stderr[-4096:]);self.assertEqual(stderr,b'')

    def test_01_complete_caller_cache_and_parent_domain(self):
        self.run_driver('caller')

    def test_02_complete_awaiter_and_exact_readback(self):
        self.run_driver('await')
        type(self).capture=leaf.capture_state(OUTPUT.parent,MANIFEST,source_root=ROOT,execution=self.execution)
        self.assertEqual(leaf.source_evidence(ROOT),self.sources)

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(StateControls))
    cls=StateControls
    passed=result.wasSuccessful()and result.testsRun==2 and not(result.skipped or result.expectedFailures or result.unexpectedSuccesses)
    passed=passed and hasattr(cls,'capture')and leaf.source_evidence(ROOT)==cls.sources
    summary=dict(schema='hepta.runtime.local-create-spec-state-suite.v1',status='PASS'if passed else'FAIL',
        tests_run=result.testsRun,expected_tests=2,failures=len(result.failures),errors=len(result.errors),
        skipped=len(result.skipped),expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses),
        counts=leaf.STATE_COUNTS,source_inputs=getattr(cls,'sources',None),execution=getattr(cls,'execution',None),
        manifest_sha256=leaf.sha(MANIFEST.read_bytes()),capture_sha256=leaf.sha(leaf.compact(cls.capture))if hasattr(cls,'capture')else None,
        sources_unchanged=hasattr(cls,'sources')and leaf.source_evidence(ROOT)==cls.sources,**leaf.SCOPE)
    (OUTPUT/'state').mkdir(parents=True,exist_ok=True)
    (OUTPUT/'state'/'summary.json').write_bytes(leaf.compact(summary)+b'\n')
    print(leaf.compact(summary).decode(),flush=True)
    raise SystemExit(0 if passed else 1)
