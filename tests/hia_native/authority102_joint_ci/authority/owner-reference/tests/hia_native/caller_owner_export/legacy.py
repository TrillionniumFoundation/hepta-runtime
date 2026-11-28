"""Execute all eight unchanged authority groups against the new root image.

Only module admission selects the new explicitly pinned graph. Observation
wrappers add current-target reference custody without changing test methods or
the existing Harness implementation.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import unittest

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from native_support import Modules, Harness, bound, encoded, sha
from cases import LEGACY_COUNTS as EXPECTED

def run(args):
    if args.source_pins_sha256 is not None:
        from common import source_evidence
        source_evidence(args.source_root,args.source_pins_sha256)
    args.output.mkdir(parents=True,exist_ok=False)
    observations=[]
    class Observer(Harness):
        def save(self,operation):
            if getattr(self,'reference_export',False):
                observations.append({'context':self.reference_context,'operation':operation,'binding':bound(self)})
        def startup(self,path=b''):
            result=super().startup(path)
            self.reference_config['direct_missing_extension_fixture']=self.mode==3
            if self.mode==1:
                self.reference_config.update(stdio_fallback_source='native-os-observation',
                    observed_stdio_fallback=self.bytes(0,320,32).hex() if self.get(0,64)==1 else None)
            self.save('start');return result
        def request(self,wire,capacity=None):
            result=super().request(wire,capacity);self.save('request');return result
        def reconnect(self):
            result=super().reconnect();self.save('reconnect');return result
        def shutdown(self):
            result=super().shutdown();self.save('shutdown');return result
    path=args.source_root/'tests/hia_native/test_caller_authority.py'
    spec=importlib.util.spec_from_file_location('unchanged_legacy_authority_tests',path)
    test=importlib.util.module_from_spec(spec);spec.loader.exec_module(test)
    test.Modules=lambda *unused:Modules(args.manifest,args.fixture_manifest,source_root=args.source_root)
    test.Harness=Observer
    os.environ.update(HIA_AUTHORITY_MANIFEST=str(args.manifest),
        HIA_AUTHORITY_LOADER_MANIFEST=str(args.manifest),HIA_SCOPE_MANIFEST=str(args.manifest))
    start=time.monotonic_ns()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(test.AuthorityTests))
    good=result.wasSuccessful() and result.testsRun==8 and not any((result.failures,result.errors,
        result.skipped,result.expectedFailures,result.unexpectedSuccesses)) and test.COUNTS==EXPECTED and len(test.CORPUS)==122
    if not good:raise ValueError('unchanged eight-group authority domain failed')
    expected=[];binding={};at=0
    for row in test.CORPUS:
        if row['operation'] in ('replace_verified_extension','restore_verified_extension'):
            state=binding.get(row['context'])
        else:
            observed=observations[at];at+=1
            if (observed['context'],observed['operation'])!=(row['context'],row['operation']):
                raise ValueError('legacy observer order differs')
            state=observed['binding'];binding[row['context']]=state
        expected.append({'context':row['context'],'code':row['code'],'output_hex':row['output_hex'],'binding':state})
    if at!=len(observations):raise ValueError('unclaimed legacy observation')
    (args.output/'original-input.jsonl').write_bytes(b''.join(encoded(r) for r in test.CORPUS))
    (args.output/'expected-original.jsonl').write_bytes(b''.join(encoded(r) for r in expected))
    (args.output/'private-observations.json').write_bytes(encoded(observations))
    report={'schema':'hepta.runtime.owner-export.legacy.v2','status':'PASS','pid':os.getpid(),
        'ppid':os.getppid(),'pgid':os.getpgid(0),'tests_run':8,'counts':test.COUNTS,
        'original_rows':122,'native_test_source_sha256':sha(path.read_bytes()),
        'harness_source_sha256':sha((args.source_root/'tests/hia_native/authority_native_harness.py').read_bytes()),
        'loaded':test.AuthorityTests.modules.loaded_artifacts,'elapsed_ns':time.monotonic_ns()-start}
    if args.source_pins_sha256 is not None:source_evidence(args.source_root,args.source_pins_sha256)
    (args.output/'summary.json').write_bytes(encoded(report));print(encoded(report).decode(),end='')

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('source-root','manifest','fixture-manifest','output'):p.add_argument('--'+name,required=True,type=Path)
    p.add_argument('--source-pins-sha256')
    run(p.parse_args())
