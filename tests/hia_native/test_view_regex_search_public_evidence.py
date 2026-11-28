"""Reject physical edits of actual public regex evidence; no HIA/Rust execution."""
from __future__ import annotations
import copy,gzip,json,os,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import hia_native_view_regex_search_public_qualification as q
CONTROLS=[]
class PublicEvidenceControls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.actual=Path(os.environ['HIA_VIEW_REGEX_SEARCH_PUBLIC_QUALIFICATION_OUTPUT']).resolve()
  report_path=Path(os.environ.get('HIA_VIEW_REGEX_SEARCH_PUBLIC_QUALIFICATION_REPORT',str(cls.actual/'result.json')))
  cls.report=q.decode(report_path.read_bytes())
  cls.baseline=q.public_native_evidence(ROOT,cls.actual,cls.report,None)
  cls.temporary=tempfile.TemporaryDirectory(prefix='view-regex-public-evidence-',dir=cls.actual.parent)
  cls.output=Path(cls.temporary.name)/'output';cls.output.mkdir()
  cls.source=Path(cls.temporary.name)/'runtime';cls.source.mkdir()
  for name,digest in cls.baseline['artifact_sha256'].items():
   original=cls.actual/name;assert q.identity(original)['sha256']==digest
   target=cls.output/name;target.parent.mkdir(parents=True,exist_ok=True);os.link(original,target)
  for name,digest in cls.baseline['source_sha256'].items():
   original=ROOT/name;assert q.identity(original)['sha256']==digest
   target=cls.source/name;target.parent.mkdir(parents=True,exist_ok=True);os.link(original,target)
  cls.report_path=cls.output/'actual-report.json';cls.report_path.write_bytes(q.compact(cls.report)+b'\n')
  assert all(not(cls.output/name).exists()for name in cls.baseline['transient_fixture_directories'])
  q.exact(q.public_native_evidence(cls.source,cls.output,cls.load(),None),cls.baseline,'same public evidence after source/output relocation without live fixtures')
  cls.folder=cls.report['view_regex_search_public']['corpus']
  cls.manifest_path=Path(cls.report['view_regex_search_public']['manifest'])
  cls.manifest=q.decode((cls.output/cls.manifest_path).read_bytes())
  cls.capture=q.decode((cls.output/cls.folder/'result.json').read_bytes())
  cls.rows=[q.decode(line)for line in(cls.output/cls.folder/'public-cases.jsonl').read_bytes().splitlines()]
 @classmethod
 def tearDownClass(cls):cls.temporary.cleanup()
 @classmethod
 def load(cls):return q.decode(cls.report_path.read_bytes())
 def check(self,label,changes):
  originals=[]
  try:
   for name,raw in changes:
    assert not Path(name).is_absolute() and '..' not in Path(name).parts
    path=self.output/name;originals.append((path,path.read_bytes()))
    private=path.with_name(path.name+'.private-edit');private.write_bytes(raw);private.replace(path)
   with self.assertRaises((ValueError,KeyError,TypeError,AssertionError,EOFError,OSError,UnicodeError,IndexError)):
    q.public_native_evidence(self.source,self.output,self.load(),None)
   CONTROLS.append(label)
  finally:
   for path,raw in reversed(originals):
    private=path.with_name(path.name+'.private-restore');private.write_bytes(raw);private.replace(path)
 def report_change(self,label,operation):
  report=copy.deepcopy(self.report);operation(report)
  self.check(label,[('actual-report.json',json.dumps(report,sort_keys=True,allow_nan=True).encode()+b'\n')])
 def test_01_actual_process_receipts(self):
  def row(report):return next(value for value in report['checks']if value['name']==q.NATIVE_SUITE)
  self.report_change('public-command',lambda report:row(report)['command'].remove('-I'))
  self.report_change('public-bool-exit',lambda report:row(report).__setitem__('exit_code',False))
  self.report_change('public-timeout-budget',lambda report:row(report).__setitem__('timeout_seconds',181))
  self.report_change('public-timed-out',lambda report:row(report).__setitem__('timed_out',True))
  self.report_change('public-nonfinite-elapsed',lambda report:row(report).__setitem__('elapsed_seconds',float('inf')))
  self.report_change('public-duplicate',lambda report:report['checks'].append(copy.deepcopy(row(report))))
 def test_02_complete_sources_and_streams(self):
  member=self.manifest['members'][0]
  path=q.mcp.mapped_manifest(self.output/self.manifest_path.parent.parent,member['manifest'],Path(self.capture['execution']['manifest_path']).parent.parent).relative_to(self.output)
  metadata=q.decode((self.output/path).read_bytes())
  for label,filename in [('public-module-image',metadata['image']),('public-compiler-output','module.output.bin')]:
   name=path.parent/filename;raw=bytearray((self.output/name).read_bytes());raw[-1]^=1
   self.check(label,[(str(name),bytes(raw))])
  process=self.capture['processes'][0];name=Path(self.folder)/process['stdin']['path']
  raw=bytearray((self.output/name).read_bytes());raw[-1]^=1
  self.check('public-process-stdin',[(str(name),bytes(raw))])
  for label,key in [('public-body-byte','actual_body'),('public-response-byte','actual_response')]:
   row=next(row for row in self.rows if row[key]['bytes'])
   name=Path(self.folder)/row[key]['path'];raw=bytearray(gzip.decompress((self.output/name).read_bytes()));raw[0]^=1
   self.check(label,[(str(name),gzip.compress(raw,mtime=0))])
  name=str(Path(self.folder)/'public-cases.jsonl')
  self.check('public-case-omitted',[(name,b''.join(q.compact(value)+b'\n'for value in self.rows[:-1]))])
def main():
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(PublicEvidenceControls))
 baseline=getattr(PublicEvidenceControls,'baseline',{})
 success=result.wasSuccessful()and result.testsRun==2 and sorted(CONTROLS)==list(q.PUBLIC_CONTROLS)
 summary=dict(schema='hepta.runtime.view-regex-search-public-evidence-tests.v1',status='PASS'if success else'FAIL',
  groups=result.testsRun,test_groups=result.testsRun,refusal_controls=len(CONTROLS),failures=len(result.failures),
  errors=len(result.errors),skipped=len(result.skipped),controls=sorted(CONTROLS),
  native_evidence_sha256=q.sha(q.compact(baseline)),reader_sha256=q.identity(ROOT/q.READER)['sha256'],
  test_sha256=q.identity(Path(__file__))['sha256'],new_native_calls=0,new_rust_processes=0,native_cases_added_by_replay=0,
  relocated_source_and_output_replay=True,live_fixture_directories_required=False,process_receipts_rewritten=False,
  whole_view_replaced=False,whole_runtime_replaced=False)
 print(json.dumps(summary,sort_keys=True,allow_nan=False),flush=True)
 return 0 if success else 1
if __name__=='__main__':raise SystemExit(main())
