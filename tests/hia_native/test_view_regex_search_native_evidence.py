"""Two groups of physical refusals for retained native search evidence.

The positive control moves all admitted source and output bytes to new roots
without rewriting absolute process/manifest receipts or copying live fixtures.
Only private hard links are replaced; the actual execution remains unchanged.
No HIA owner or Rust process is executed by this suite.
"""
from __future__ import annotations
import copy,gzip,json,os,shutil,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import hia_native_view_regex_search_qualification as q
CONTROLS=[]
class EvidenceControls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.actual=Path(os.environ['HIA_VIEW_REGEX_SEARCH_QUALIFICATION_OUTPUT']).resolve()
  cls.report=q.json_value((cls.actual/'result.json').read_bytes())
  cls.baseline=q.native_evidence(ROOT,cls.actual,cls.report)
  cls.temporary=tempfile.TemporaryDirectory(prefix='view-regex-search-native-evidence-',dir=cls.actual.parent)
  cls.output=Path(cls.temporary.name)/'output';cls.output.mkdir()
  cls.source=Path(cls.temporary.name)/'runtime';cls.source.mkdir()
  for name,digest in cls.baseline['artifact_sha256'].items():
   original=cls.actual/name;assert q.digest(original.read_bytes())==digest
   target=cls.output/name;target.parent.mkdir(parents=True,exist_ok=True);os.link(original,target)
  for name,digest in cls.baseline['source_sha256'].items():
   original=ROOT/name;assert q.digest(original.read_bytes())==digest
   target=cls.source/name;target.parent.mkdir(parents=True,exist_ok=True);os.link(original,target)
  cls.report_path=cls.output/'actual-report.json'
  cls.report_path.write_bytes(q.canonical(cls.report))
  assert all(not (cls.output/name).exists() for name in cls.baseline['transient_fixture_directories'])
  moved=q.native_evidence(cls.source,cls.output,cls.load())
  q.same(moved,cls.baseline,'same complete evidence after moving source/output and retiring all fixtures')
  cls.folder=cls.report['view_regex_search']['corpus']
  cls.manifest=q.json_value((cls.output/cls.report['view_regex_search']['manifest']).read_bytes())
  cls.build=Path(cls.report['view_regex_search']['manifest']).parent.parent
  cls.rows=q.json_value(b'['+b','.join((cls.output/cls.folder/'native-cases.jsonl').read_bytes().splitlines())+b']')
  cls.processes=q.json_value((cls.output/cls.folder/'processes.json').read_bytes())
 @classmethod
 def tearDownClass(cls):cls.temporary.cleanup()
 @classmethod
 def load(cls):return q.json_value(cls.report_path.read_bytes())
 def check(self,label,changes):
  originals=[]
  try:
   for name,raw in changes:
    path=self.output/name;originals.append((path,path.read_bytes()))
    pending=path.with_name(path.name+'.private-edit');pending.write_bytes(raw);pending.replace(path)
   with self.assertRaises((ValueError,KeyError,TypeError,AssertionError,EOFError,OSError,UnicodeError,IndexError)):
    q.native_evidence(self.source,self.output,self.load())
   CONTROLS.append(label)
  finally:
   for path,raw in reversed(originals):
    pending=path.with_name(path.name+'.private-restore');pending.write_bytes(raw);pending.replace(path)
 def report_change(self,label,change):
  value=copy.deepcopy(self.report);change(value)
  raw=json.dumps(value,sort_keys=True,allow_nan=True).encode()+b'\n'
  self.check(label,[('actual-report.json',raw)])
 def test_01_actual_receipts(self):
  def row(report):return next(value for value in report['checks'] if value['name']==q.NATIVE_SUITE)
  self.report_change('check-command',lambda report:row(report)['command'].remove('-I'))
  self.report_change('check-bool-exit',lambda report:row(report).__setitem__('exit_code',False))
  self.report_change('check-timeout-budget',lambda report:row(report).__setitem__('timeout_seconds',181))
  self.report_change('check-timed-out',lambda report:row(report).__setitem__('timed_out',True))
  self.report_change('check-nonfinite-elapsed',lambda report:row(report).__setitem__('elapsed_seconds',float('inf')))
  self.report_change('check-duplicate',lambda report:report['checks'].append(copy.deepcopy(row(report))))
 def test_02_complete_source_and_stream_artifacts(self):
  member=self.manifest['members'][0];path=self.build/member['manifest']
  metadata=q.json_value((self.output/path).read_bytes())
  name=path.parent/metadata['image'];raw=bytearray((self.output/name).read_bytes());raw[0]^=1
  self.check('module-image',[(str(name),bytes(raw))])
  name=path.parent/'module.output.bin';raw=bytearray((self.output/name).read_bytes());raw[-1]^=1
  self.check('compiler-output',[(str(name),bytes(raw))])
  name=Path(self.folder)/self.processes[0]['streams']['input']['path']
  raw=bytearray((self.output/name).read_bytes());raw[-1]^=1
  self.check('process-stdin-gzip',[(str(name),bytes(raw))])
  values=copy.deepcopy(self.rows)
  value=next(item for case in values for item in case['io'] if item['operation']==5)
  value['operation']=2
  name=str(Path(self.folder)/'native-cases.jsonl')
  self.check('logical-operation',[(name,b''.join(q.canonical(value) for value in values))])
  case=next(case for case in self.rows if case['events'])
  name=str(Path(self.folder)/case['events'][0]['ack_path'])
  raw=bytearray(gzip.decompress((self.output/name).read_bytes()));raw[16]^=1
  self.check('event-ack-gzip',[(name,gzip.compress(raw,mtime=0))])
  name=str(Path(self.folder)/'native-cases.jsonl')
  self.check('native-case-omitted',[(name,b''.join(q.canonical(value) for value in self.rows[:-1]))])

def main():
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceControls))
 baseline=getattr(EvidenceControls,'baseline',{})
 success=result.wasSuccessful() and result.testsRun==2 and sorted(CONTROLS)==list(q.CONTROLS)
 summary=dict(schema='hepta.runtime.view-regex-search-evidence-tests.v1',status='PASS' if success else 'FAIL',
  groups=result.testsRun,test_groups=result.testsRun,refusal_controls=len(CONTROLS),
  failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),
  controls=sorted(CONTROLS),native_evidence_sha256=q.digest(q.canonical(baseline)),
  reader_sha256=q.digest((ROOT/'scripts/hia_native_view_regex_search_qualification.py').read_bytes()),
  test_sha256=q.digest(Path(__file__).read_bytes()),new_native_calls=0,new_rust_processes=0,
  native_cases_added_by_replay=0,relocated_source_and_output_replay=True,
  live_fixture_directories_required=False,process_receipts_rewritten=False,
  whole_view_replaced=False,whole_runtime_replaced=False)
 print(json.dumps(summary,sort_keys=True,allow_nan=False),flush=True)
 return 0 if success else 1
if __name__=='__main__':raise SystemExit(main())
