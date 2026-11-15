"""Refuse changed sources, incomplete executions and rehashed create captures."""
from __future__ import annotations
import copy
import gzip
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import zlib

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(ROOT/'tests/hia_native'))
from evidence_snapshot import copy_evidence_files,unrelated_fixture_guard
from hia_native_local_create_qualification import (CONTROL_COUNTS,FOLDER,SCOPE,TESTS,compact,core_evidence,
    decode,pin,sha,source_evidence)
OUTPUT=Path(os.environ['HIA_LOCAL_CREATE_QUALIFICATION_OUTPUT']).resolve()
COUNTS={key:0 for key in CONTROL_COUNTS}


def replace(path,data):
    path.unlink();path.write_bytes(data)
def replace_json(path,data):replace(path,compact(data)+b'\n')


class LocalCreateEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report=decode((OUTPUT/'result.json').read_bytes())
        cls.actual=core_evidence(OUTPUT,cls.report,source_root=ROOT)
        cls.sources=source_evidence(ROOT)

    def snapshot(self,with_sources=False):
        temporary=tempfile.TemporaryDirectory(prefix='local-create-evidence-',dir=OUTPUT.parent)
        self.addCleanup(temporary.cleanup);target=Path(temporary.name);output=target/'capture'
        with unrelated_fixture_guard(OUTPUT):
            copy_evidence_files(OUTPUT,output,self.actual['artifact_sha256'])
        root=ROOT
        if with_sources:
            root=target/'source'
            copy_evidence_files(ROOT,root,{name:value['sha256'] for name,value in self.sources['files'].items()})
        return root,output,copy.deepcopy(self.report)

    @staticmethod
    def receipt(report):return next(row for row in report['checks'] if row['name']==TESTS[0])

    def refuses(self,root,output,report,kind):
        with self.assertRaises((ValueError,KeyError,TypeError,AssertionError,OSError,zlib.error)):
            core_evidence(output,report,source_root=root)
        COUNTS[kind]+=1

    def test_01_actual_and_relocated_complete_capture(self):
        self.assertEqual(self.actual['status'],'PASS');COUNTS['actual_captures']+=1
        root,output,report=self.snapshot(True)
        self.assertEqual(core_evidence(output,report,source_root=root),self.actual)
        COUNTS['actual_captures']+=1

    def test_02_failed_or_counterfeit_process_completion(self):
        for change in ('missing','duplicate','exit','boolean-exit','timeout','start','command','stdout','stderr','summary'):
            with self.subTest(change=change):
                root,output,report=self.snapshot();row=self.receipt(report)
                if change=='missing':report['checks'].remove(row)
                elif change=='duplicate':report['checks'].append(copy.deepcopy(row))
                elif change=='exit':row['exit_code']=1
                elif change=='boolean-exit':row['exit_code']=False
                elif change=='timeout':row['timed_out']=True
                elif change=='start':row['start_error']='synthetic launch refusal'
                elif change=='command':row['command'].remove('-I')
                elif change in ('stdout','stderr'):
                    p=output/(TESTS[0]+'.'+change);replace(p,p.read_bytes()+b'changed\n')
                else:row['summary']['whole_runtime_replaced']=True
                self.refuses(root,output,report,'process_refusals')

    def test_03_admitted_source_changes(self):
        for relative in ('native/local_create_file.hepta','tests/hia_native/local_create/corpus_pins.json',
                         'tests/hia_native/local_create/reference/src/main.rs','scripts/hia_native_local_create_qualification.py'):
            with self.subTest(relative=relative):
                root,output,report=self.snapshot(True);p=root/relative;replace(p,p.read_bytes()+b'\n')
                self.refuses(root,output,report,'source_refusals')

    def test_04_complete_bytes_and_rehashed_claims(self):
        for change in ('state-arrays','state-declaration','state-count','kernel-input','kernel-file','kernel-receipt',
                       'race-file','race-winner','fault-file','fault-limit','retirement','build-array'):
            with self.subTest(change=change):
                root,output,report=self.snapshot();base=output/FOLDER/'native'
                if change=='state-arrays':
                    p=base/'state/complete-arrays.bin.gz';raw=p.read_bytes();replace(p,raw[:-1]+bytes([raw[-1]^1]))
                elif change=='state-declaration':
                    p=base/'state/entries.jsonl.gz';lines=gzip.decompress(p.read_bytes()).splitlines();row=decode(lines[0]);row['category']='changed'
                    lines[0]=compact(row);replace(p,gzip.compress(b'\n'.join(lines)+b'\n',mtime=0))
                elif change=='state-count':
                    p=base/'state/summary.json';row=decode(p.read_bytes());row['counts']['actual_native_calls']-=1;replace_json(p,row)
                elif change=='kernel-input':
                    p=base/'kernel/0/stdin.bin.gz';raw=bytearray(gzip.decompress(p.read_bytes()));raw[-1]^=1;replace(p,gzip.compress(raw,mtime=0))
                    result=base/'kernel/0/result.json';row=decode(result.read_bytes());row['execution']['stdin']=pin(raw);replace_json(result,row)
                    replace_json(base/'kernel/0/execution.json',row['execution'])
                elif change=='kernel-file':
                    p=base/'kernel/0/after/file-0.bin.gz';raw=gzip.decompress(p.read_bytes())+b'changed';replace(p,gzip.compress(raw,mtime=0))
                    result=base/'kernel/0/result.json';row=decode(result.read_bytes());row['after'][0].update(pin(raw));replace_json(result,row)
                elif change=='kernel-receipt':
                    p=base/'kernel/0/result.json';row=decode(p.read_bytes());row['execution']['exit_code']=False;replace_json(p,row)
                    replace_json(base/'kernel/0/execution.json',row['execution'])
                elif change=='race-file':
                    p=base/'race/0/created.bin';raw=p.read_bytes()+b'changed';replace(p,raw)
                    result=base/'race/0/result.json';row=decode(result.read_bytes());row['final_file']=pin(raw);replace_json(result,row)
                elif change=='race-winner':
                    p=base/'race/0/result.json';row=decode(p.read_bytes());row['winner']=bool(row['winner']);replace_json(p,row)
                elif change=='fault-file':
                    p=base/'fault/4/created.bin';raw=p.read_bytes()+b'changed';replace(p,raw)
                    result=base/'fault/4/result.json';row=decode(result.read_bytes());row['file'].update(pin(raw));replace_json(result,row)
                elif change=='fault-limit':
                    p=base/'fault/4/result.json';row=decode(p.read_bytes());row['rlimit_fsize']=[2,2];replace_json(p,row)
                elif change=='retirement':
                    p=base/'retirement.json';row=decode(p.read_bytes());row['retired_directories']-=1;replace_json(p,row)
                else:
                    p=output/FOLDER/'build-controls/tail/after1.bin';raw=p.read_bytes();replace(p,raw[:-17]+bytes([raw[-17]^1])+raw[-16:])
                self.refuses(root,output,report,'artifact_refusals')


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LocalCreateEvidenceTests))
    unchanged=hasattr(LocalCreateEvidenceTests,'sources') and source_evidence(ROOT)==LocalCreateEvidenceTests.sources
    passed=result.wasSuccessful() and result.testsRun==4 and not(result.skipped or result.expectedFailures or result.unexpectedSuccesses)
    passed=passed and unchanged and COUNTS==CONTROL_COUNTS
    summary=dict(schema='hepta.runtime.local-create-evidence-controls.v1',status='PASS'if passed else'FAIL',
        tests_run=result.testsRun,expected_tests=4,failures=len(result.failures),errors=len(result.errors),
        skipped=len(result.skipped),expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses),
        counts=COUNTS,source_inputs=getattr(LocalCreateEvidenceTests,'sources',None),
        native_evidence_sha256=sha(compact(LocalCreateEvidenceTests.actual)) if hasattr(LocalCreateEvidenceTests,'actual')else None,
        new_native_calls=0,synthetic_receipt_controls=True,**SCOPE)
    (OUTPUT/FOLDER/'evidence-controls.json').write_bytes(compact(summary)+b'\n')
    print(compact(summary).decode(),flush=True)
    raise SystemExit(0 if passed else 1)
