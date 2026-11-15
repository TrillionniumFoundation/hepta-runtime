"""Refuse incomplete segmented processes and changed complete captures."""
from __future__ import annotations
import copy
import gzip
import os
from pathlib import Path
import sys
import tempfile
import unittest
import zlib

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(ROOT/'tests/hia_native'))
from evidence_snapshot import copy_evidence_files,unrelated_fixture_guard
import hia_native_local_create_segments_qualification as leaf

OUTPUT=Path(os.environ['HIA_LOCAL_CREATE_QUALIFICATION_OUTPUT']).resolve()
COUNTS={key:0 for key in leaf.CONTROL_COUNTS}


def replace(path,raw):
    path.unlink();path.write_bytes(raw)


def replace_json(path,value):replace(path,leaf.compact(value)+b'\n')


class LocalCreateSegmentEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report=leaf.core.decode((OUTPUT/'result.json').read_bytes())
        cls.actual=leaf.core_evidence(OUTPUT,cls.report,source_root=ROOT)
        cls.sources=leaf.source_evidence(ROOT)

    def snapshot(self,with_sources=False):
        temporary=tempfile.TemporaryDirectory(prefix='local-create-segments-evidence-',dir=OUTPUT.parent)
        self.addCleanup(temporary.cleanup);target=Path(temporary.name);output=target/'capture'
        with unrelated_fixture_guard(OUTPUT):
            copy_evidence_files(OUTPUT,output,self.actual['artifact_sha256'])
        root=ROOT
        if with_sources:
            root=target/'source'
            copy_evidence_files(ROOT,root,{name:row['sha256'] for name,row in self.sources['files'].items()})
        return root,output,copy.deepcopy(self.report)

    @staticmethod
    def receipt(report):return next(row for row in report['checks']if row['name']==leaf.TESTS[0])

    def refuses(self,root,output,report,kind):
        with self.assertRaises((ValueError,KeyError,TypeError,AssertionError,OSError,EOFError,zlib.error)):
            leaf.core_evidence(output,report,source_root=root)
        COUNTS[kind]+=1

    def test_01_actual_and_relocated_complete_capture(self):
        self.assertEqual(self.actual['status'],'PASS');COUNTS['actual_captures']+=1
        root,output,report=self.snapshot(True)
        self.assertEqual(leaf.core_evidence(output,report,source_root=root),self.actual)
        COUNTS['actual_captures']+=1

    def test_02_actual_process_completion_custody(self):
        for change in('missing','duplicate','boolean-exit','timeout','command','stdout'):
            with self.subTest(change=change):
                root,output,report=self.snapshot();row=self.receipt(report)
                if change=='missing':report['checks'].remove(row)
                elif change=='duplicate':report['checks'].append(copy.deepcopy(row))
                elif change=='boolean-exit':row['exit_code']=False
                elif change=='timeout':row['timed_out']=True
                elif change=='command':row['command'].remove('-I')
                else:
                    path=output/(leaf.TESTS[0]+'.stdout');replace(path,path.read_bytes()+b'changed\n')
                self.refuses(root,output,report,'process_refusals')

    def test_03_exact_admitted_source_closure(self):
        for relative in('native/local_create_file.hepta',
                         leaf.DRIVERS+'/segment_corpus_pins.json',
                         'scripts/hia_native_local_create_segments_qualification.py'):
            with self.subTest(relative=relative):
                root,output,report=self.snapshot(True);path=root/relative
                replace(path,path.read_bytes()+b'\n')
                self.refuses(root,output,report,'source_refusals')

    def test_04_full_arrays_files_and_rehashed_claims(self):
        for change in('owner-image','packer-output','typed-rows','typed-array-tail',
                       'ordinary-file','ordinary-completion','admission-frame','retirement'):
            with self.subTest(change=change):
                root,output,report=self.snapshot();base=output/leaf.FOLDER/'native'
                module=output/Path(self.actual['module']['manifest']).parent
                if change=='owner-image':
                    path=module/'owner.image.bin';raw=path.read_bytes();replace(path,raw[:-1]+bytes([raw[-1]^1]))
                elif change=='packer-output':
                    path=module/'pack.output.bin';raw=path.read_bytes();replace(path,raw[:-1]+bytes([raw[-1]^1]))
                elif change=='typed-rows':
                    path=base/'state/rows.json';rows=leaf.core.decode(path.read_bytes());rows[0]['number']=False
                    replace_json(path,rows)
                elif change=='typed-array-tail':
                    path=base/'state/arrays.bin.gz';raw=path.read_bytes();replace(path,raw[:-1]+bytes([raw[-1]^1]))
                elif change=='ordinary-file':
                    folder=base/'ordinary/kernel/0';path=folder/'after/file-0.bin.gz'
                    raw=gzip.decompress(path.read_bytes())+b'changed';replace(path,gzip.compress(raw,mtime=0))
                    record=folder/'result.json';row=leaf.core.decode(record.read_bytes());row['after'][0].update(leaf.pin(raw))
                    replace_json(record,row)
                elif change=='ordinary-completion':
                    folder=base/'ordinary/kernel/0';record=folder/'result.json';row=leaf.core.decode(record.read_bytes())
                    row['execution']['exit_code']=False;replace_json(record,row)
                    replace_json(folder/'execution.json',row['execution'])
                elif change=='admission-frame':
                    path=base/'admission/0/stdin.bin';raw=path.read_bytes();replace(path,raw+bytes([0]))
                    record=base/'admission/0/execution.json';row=leaf.core.decode(record.read_bytes());row['stdin']=leaf.pin(raw+bytes([0]))
                    replace_json(record,row)
                else:
                    path=base/'retirement.json';row=leaf.core.decode(path.read_bytes());row['retired_directories']-=1
                    replace_json(path,row)
                self.refuses(root,output,report,'artifact_refusals')


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LocalCreateSegmentEvidenceTests))
    cls=LocalCreateSegmentEvidenceTests
    unchanged=hasattr(cls,'sources')and leaf.source_evidence(ROOT)==cls.sources
    passed=result.wasSuccessful()and result.testsRun==4 and not(result.skipped or result.expectedFailures or result.unexpectedSuccesses)
    passed=passed and unchanged and COUNTS==leaf.CONTROL_COUNTS
    summary=dict(schema='hepta.runtime.local-create-segments-evidence-controls.v1',status='PASS'if passed else'FAIL',
        tests_run=result.testsRun,expected_tests=4,failures=len(result.failures),errors=len(result.errors),
        skipped=len(result.skipped),expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses),
        counts=COUNTS,source_inputs=getattr(cls,'sources',None),
        native_evidence_sha256=leaf.sha(leaf.compact(cls.actual))if hasattr(cls,'actual')else None,
        new_native_calls=0,synthetic_receipt_controls=True,**leaf.SCOPE)
    destination=OUTPUT/leaf.FOLDER/'evidence-controls.json';destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_bytes(leaf.compact(summary)+b'\n');print(leaf.compact(summary).decode(),flush=True)
    raise SystemExit(0 if passed else 1)
