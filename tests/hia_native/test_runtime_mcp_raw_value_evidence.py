"""Reject altered receipts, domains, complete streams and typed-boundary claims."""
from __future__ import annotations
import copy,gzip,json,os,sys,tempfile,unittest
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(os.environ.get('HIA_RUNTIME_ROOT',Path(__file__).resolve().parents[2])).resolve()
sys.path.insert(0,str(ROOT/'scripts'));sys.path.insert(0,str(ROOT/'tests/hia_native'))
from evidence_snapshot import copy_evidence_files,unrelated_fixture_guard
from hia_native_span_raw_value_qualification import (
    FOLDER,TEST,CONTROL_REPORT,CONTROL_COUNTS,COUNTS,SOURCE_FILES,
    compact,decode,native_evidence,pin,sha,sources)
from qualify_hia_runtime_native import completed_test_summary
COUNTERS={name:0 for name in CONTROL_COUNTS}

def replace(path,data):
    path.unlink();path.write_bytes(data)
def replace_json(path,data):replace(path,compact(data)+b'\n')

class SpanRawValueEvidenceTests(unittest.TestCase):
    def run(self,result=None):
        result=super().run(result)
        type(self)._suite_failed=not result.wasSuccessful() or bool(result.skipped)
        return result

    @classmethod
    def setUpClass(cls):
        cls._suite_failed=False
        cls.output=Path(os.environ['HIA_RUNTIME_MCP_QUALIFICATION_OUTPUT']).resolve()
        cls.report=decode((cls.output/'result.json').read_bytes())
        cls.inputs=sources(ROOT);cls.actual=native_evidence(ROOT,cls.output,cls.report,completed_test_summary)

    @classmethod
    def tearDownClass(cls):
        unchanged=sources(ROOT)==cls.inputs
        passed=not cls._suite_failed and unchanged and COUNTERS==CONTROL_COUNTS
        result=dict(schema='hepta.runtime.span-raw-value.evidence-controls.v1',status='PASS' if passed else 'FAIL',
            counts=COUNTERS,source_inputs=cls.inputs,native_evidence_sha256=sha(compact(cls.actual)),
            synthetic_receipt_controls=True,new_native_calls=0)
        with (cls.output/CONTROL_REPORT).open('xb') as stream:stream.write(compact(result)+b'\n')
        print(compact(result).decode(),flush=True)
        assert unchanged,'span evidence source changed'

    def snapshot(self,with_sources=False):
        temporary=tempfile.TemporaryDirectory(prefix='span-rawvalue-evidence-',dir=self.output.parent)
        self.addCleanup(temporary.cleanup);directory=Path(temporary.name);output=directory/'capture'
        with unrelated_fixture_guard(self.output):
            copy_evidence_files(self.output,output,
                {**self.actual['artifact_sha256'],**self.actual['public_owner_artifacts']})
        root=ROOT
        if with_sources:
            root=directory/'source'
            admitted={name:row['sha256'] for name,row in self.inputs['public_source_binding']['files'].items()}
            admitted.update({name:row['sha256'] for name,row in self.inputs['files'].items()})
            admitted['native/runtime_mcp_sources.json']=self.inputs['public_source_binding']['manifest_sha256']
            copy_evidence_files(ROOT,root,admitted)
        return root,output,copy.deepcopy(self.report)

    @staticmethod
    def receipt(report):return next(row for row in report['checks'] if row['name']==TEST)

    def refuses(self,root,output,report,kind):
        with self.assertRaises((ValueError,KeyError,AssertionError,FileNotFoundError)):
            native_evidence(root,output,report,completed_test_summary)
        COUNTERS[kind]+=1

    def replace_capture(self,output,report,capture):
        raw=compact(capture)+b'\n';replace(output/FOLDER/'result.json',raw)
        replace(output/(TEST+'.stdout'),raw)
        self.receipt(report).update(summary=capture,stdout_bytes=len(raw),stdout_sha256=sha(raw))

    def test_01_actual_complete_capture_and_relocated_sources(self):
        self.assertEqual(self.actual['counts'],COUNTS);self.assertFalse(self.actual['whole_runtime_replaced'])
        COUNTERS['actual_capture']+=1
        root,output,report=self.snapshot(True)
        self.assertEqual(native_evidence(root,output,report,completed_test_summary),self.actual)
        COUNTERS['actual_capture']+=1

    def test_02_failed_or_counterfeit_completion_refuses(self):
        for change in ('missing','duplicate','exit','boolean-exit','timeout','start','command','stdout','stderr','summary'):
            with self.subTest(change=change):
                root,output,report=self.snapshot();row=self.receipt(report)
                if change=='missing':report['checks'].remove(row)
                elif change=='duplicate':report['checks'].append(copy.deepcopy(row))
                elif change=='exit':row['exit_code']=1
                elif change=='boolean-exit':row['exit_code']=False
                elif change=='timeout':row['timed_out']=True
                elif change=='start':row['start_error']='synthetic failed launch'
                elif change=='command':row['command'].remove('-I')
                elif change in ('stdout','stderr'):
                    path=output/(TEST+'.'+change);replace(path,path.read_bytes()+b'changed\n')
                else:row['summary']['synthetic_forgery']=True
                self.refuses(root,output,report,'process_refusals')

    def test_03_changed_source_or_typed_domain_refuses(self):
        for name in ('native/serde_json_span.hepta','tests/hia_native/span_raw_value_cases.py',
                     'tests/hia_native/span_sdk_cases.json','scripts/hia_native_span_raw_value_qualification.py'):
            with self.subTest(name=name):
                root,output,report=self.snapshot(True);path=root/name;replace(path,path.read_bytes()+b'\n')
                self.refuses(root,output,report,'source_refusals')

    def test_04_rehashed_or_incomplete_native_bytes_refuse(self):
        changes=('request-byte','output-byte','calls-header','capacity-rehashed','capacity-path','public-wire',
                 'sdk-request','metadata-only','native-count','boolean-count','category','source-claim',
                 'manifest-claim','elapsed','whole-runtime','fixture-claim')
        for change in changes:
            with self.subTest(change=change):
                root,output,report=self.snapshot();folder=output/FOLDER
                capture=decode((folder/'result.json').read_bytes())
                if change in ('request-byte','output-byte','sdk-request'):
                    name={'request-byte':'requests.hex','output-byte':'native-output.txt','sdk-request':'sdk-requests.hex'}[change]
                    path=folder/name;raw=bytearray(path.read_bytes());raw[0]=48 if raw[0]!=48 else 49;replace(path,raw)
                elif change=='calls-header':
                    path=folder/'calls.jsonl';rows=[decode(line) for line in path.read_bytes().splitlines()]
                    rows[0]['header_hex']='00'*32;replace(path,b''.join(compact(row)+b'\n' for row in rows))
                elif change in ('capacity-rehashed','capacity-path'):
                    path=folder/'capacity.jsonl';rows=[decode(line) for line in path.read_bytes().splitlines()]
                    if change=='capacity-path':rows[0]['output']['path']='../escape.bin.gz'
                    else:
                        target=folder/rows[0]['output']['path'];raw=bytearray(gzip.decompress(target.read_bytes()));raw[-1]^=1
                        replace(target,gzip.compress(raw,mtime=0));rows[0]['output'].update(pin(raw))
                    replace(path,b''.join(compact(row)+b'\n' for row in rows))
                elif change=='public-wire':
                    path=folder/'sessions/1/stdout.bin.gz';raw=gzip.decompress(path.read_bytes());replace(path,gzip.compress(raw+b'{}\n',mtime=0))
                else:
                    if change in ('metadata-only','native-count'):capture['counts']['actual_native_calls']-=1
                    elif change=='boolean-count':capture['counts']['actual_sdk_input_cases']=True
                    elif change=='category':capture['leaf_categories']['root']=True
                    elif change=='source-claim':capture['source_inputs']['files']['tests/hia_native/span_raw_value_cases.py']['sha256']='0'*64
                    elif change=='manifest-claim':capture['manifest_sha256']='0'*64
                    elif change=='elapsed':capture['elapsed_seconds']=0
                    elif change=='whole-runtime':capture['whole_runtime_replaced']=True
                    elif change=='fixture-claim':capture['original_view_body_compared']=True
                    if change=='metadata-only':replace_json(folder/'result.json',capture)
                    else:self.replace_capture(output,report,capture)
                self.refuses(root,output,report,'corpus_refusals')
        self.assertEqual(COUNTERS,CONTROL_COUNTS)

if __name__=='__main__':unittest.main(verbosity=2)
