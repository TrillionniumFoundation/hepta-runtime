"""Physical original-evidence refusals and portable full-byte public comparison.

This starts no Rust/native process. The two-root positive copies retained
artifacts only; it never copies or reads the live native fixture subtree.
"""
from pathlib import Path
import contextlib,errno,gzip,hashlib,io,json,os,shutil,struct,sys,tempfile,time,unittest
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_runtime_mcp_evidence import Evidence,compact,decode,exact,qualification_evidence,source_identity
from hia_native_runtime_mcp_reference import compare_reference,workdir_records
from hia_native_runtime_mcp_original import module
SOURCE_FILES=('scripts/hia_native_runtime_mcp_evidence.py','scripts/hia_native_runtime_mcp_reference.py',
 'scripts/hia_native_runtime_mcp_original.py','scripts/hia_native_workdir_reference.py',
 'tests/hia_native/runtime_mcp_oracle/run.py','tests/hia_native/test_runtime_mcp_original_evidence.py',
 'tests/hia_native/test_runtime_mcp_evidence.py','native/runtime_mcp_sources.json')
COUNTS={'groups':4,'physical_refusals':0,'two_new_roots_positive':0,'no_live_fixture_copied':False,
        'new_rust_processes':0,'new_native_processes':0}
sha=lambda value:hashlib.sha256(value).hexdigest()

def completed(output,report,name):
 return next(row for row in report['checks'] if row['name']==name),decode((output/(name+'.stdout')).read_bytes())

class OriginalEvidence(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.output=Path(os.environ['HIA_RUNTIME_MCP_QUALIFICATION_OUTPUT']).resolve()
  cls.before={name:sha((ROOT/name).read_bytes()) for name in SOURCE_FILES}
  report=decode((cls.output/'result.json').read_bytes())
  native=qualification_evidence(ROOT,cls.output,report,completed)
  cls.baseline=compare_reference(ROOT,cls.output/'runtime-mcp',cls.output/'view-call-original')
  cls.temp=tempfile.TemporaryDirectory(prefix='hia-runtime-mcp-original-evidence-')
  cls.copy=Path(cls.temp.name)/'output';cls.source=Path(cls.temp.name)/'source';cls.copy.mkdir();cls.source.mkdir()
  names=set(native['artifact_sha256'])|set(cls.baseline['artifact_sha256'])|{'result.json'}
  for name in names:
   target=cls.copy/name;target.parent.mkdir(parents=True,exist_ok=True)
   try:os.link(cls.output/name,target)
   except OSError as error:
    if error.errno!=errno.EXDEV:raise
    shutil.copyfile(cls.output/name,target)
  source_names=set(source_identity(ROOT)['files'])|set(SOURCE_FILES)
  for oracle in ('view_call_oracle','workdir_oracle'):
   source=module(oracle+'_source',ROOT/'tests/hia_native'/oracle/'verify_sources.py')
   source_names.update(source.SOURCE_FILES)
   for path in (ROOT/'tests/hia_native'/oracle).rglob('*'):
    if path.is_file() and '__pycache__' not in path.parts:source_names.add(str(path.relative_to(ROOT)))
  for name in source_names:
   target=cls.source/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
  assert not (cls.copy/'runtime-mcp/files').exists()
  moved_native=qualification_evidence(cls.source,cls.copy,report,completed)
  assert moved_native==native
  moved=compare_reference(cls.source,cls.copy/'runtime-mcp',cls.copy/'view-call-original')
  assert moved==cls.baseline
  COUNTS.update(two_new_roots_positive=1,no_live_fixture_copied=True,
                portable_artifacts=len(names),portable_source_files=len(source_names))
  cls.original_folder=cls.copy/'runtime-mcp-original'
  cls.records=decode((cls.original_folder/'process-receipts.json').read_bytes())
  cls.workdir_name=next(row['name'] for row in cls.records if row['name'].startswith('workdir-'))

 @classmethod
 def tearDownClass(cls):
  assert cls.before=={name:sha((ROOT/name).read_bytes()) for name in SOURCE_FILES}
  cls.temp.cleanup()

 @contextlib.contextmanager
 def edits(self):
  saved={}
  def write(path,raw):
   path=Path(path)
   if path not in saved:saved[path]=(path.read_bytes(),path.stat().st_mode & 0o777)
   path.unlink();path.write_bytes(raw);path.chmod(saved[path][1])
  # Receipts retain raw Unix paths through surrogateescape. JSON metadata must
  # escape those code units; the original byte streams are changed separately.
  def object_write(path,value):
   write(path,json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n')
  try:yield write,object_write
  finally:
   for path,(raw,mode) in reversed(list(saved.items())):
    path.unlink();path.write_bytes(raw);path.chmod(mode)

 def reject(self,label):
  with self.assertRaises((ValueError,AssertionError,EOFError,OSError),msg=label):
   compare_reference(self.source,self.copy/'runtime-mcp',self.copy/'view-call-original')
  COUNTS['physical_refusals']+=1

 def update_process(self,name,change,write):
  base=self.original_folder;path=base/name/'process.json';row=decode(path.read_bytes());change(row);write(path,row)
  records=decode((base/'process-receipts.json').read_bytes())
  for index,old in enumerate(records):
   if old['name']==name:records[index]=row;break
  write(base/'process-receipts.json',records)
  result=decode((base/'result.json').read_bytes());result['processes']=records;write(base/'result.json',result)

 def test_01_shared_compiler_source_and_binary(self):
  controls=[('actual Rust version','view-call-original/rustc-version.stdout',lambda raw:raw.replace(b'1.95.0',b'1.99.0')),
            ('exact lock bytes','view-call-original/crate/Cargo.lock',lambda raw:raw+b'\n'),
            ('actual unchanged Workdir binary','workdir-original/target/release/hepta-workdir-original-oracle',lambda raw:b'X'+raw[1:])]
  if not (self.copy/controls[0][1]).exists():controls[0]=(controls[0][0],'view-call-original/rust-version.stdout',controls[0][2])
  for label,name,change in controls:
   with self.subTest(label=label),self.edits() as (write,_):
    path=self.copy/name;write(path,change(path.read_bytes()));self.reject(label)

 def test_02_actual_replay_command_types_and_deadline(self):
  for label,change in [('wrong executable',lambda row:row['command'].__setitem__(0,row['command'][0]+'-other')),
      ('boolean elapsed',lambda row:row.__setitem__('elapsed_seconds',True)),
      ('extended actual deadline',lambda row:row.__setitem__('timeout_seconds',61))]:
   with self.subTest(label=label),self.edits() as (_,write):
    self.update_process(self.workdir_name,change,write);self.reject(label)

 def test_03_full_streams_beyond_self_hashes(self):
  for kind in ('input','workdir-body','over64-body'):
   with self.subTest(kind=kind),self.edits() as (write,write_object):
    name='over64' if kind in ('input','over64-body') else self.workdir_name
    stream='stdin' if kind=='input' else 'stdout';path=self.original_folder/name/(stream+'.bin.gz')
    raw=gzip.decompress(path.read_bytes())
    if kind=='input':
     changed=raw.replace(b'public-string-endpoint-over-64MiB',b'public-string-endpoint-over-64MiX',1)
     assert changed!=raw;raw=changed
    elif kind=='workdir-body':
     rows=list(workdir_records(raw));changed=False
     for metadata,blobs in rows:
      if metadata.get('kind')!='case' or 'response_blob' not in metadata.get('result',{}):continue
      reply=decode(blobs[metadata['result']['response_blob']])
      if 'result' not in reply:continue
      reply['result']['content'][0]['text']+='!';value=compact(reply)+b'\n'
      blobs[metadata['result']['response_blob']]=value;metadata['result']['response_bytes']=len(value);changed=True;break
     assert changed
     raw=b'HWDRO001'+b''.join(struct.pack('<QQ',len(compact(metadata)),len(blobs))+compact(metadata)+
         b''.join(struct.pack('<Q',len(blob))+blob for blob in blobs) for metadata,blobs in rows)
    else:
     cases=module('control_view_cases',self.source/'tests/hia_native/view_call_oracle/cases.py')
     rows=list(cases.read_records(io.BytesIO(raw),cases.OUTPUT_MAGIC));assert len(rows)==1
     row=rows[0];index=row['metadata']['outcome']['blob'];old=row['blobs'][index]
     row['blobs'][index]=old[:-1]+(b'!' if old[-1:]!=b'!' else b'?')
     raw=cases.OUTPUT_MAGIC+struct.pack('<Q',1)+cases.blob_record(row['metadata'],row['blobs'])
    write(path,gzip.compress(raw,mtime=0))
    def change(row):row[stream].update(bytes=len(raw),sha256=sha(raw))
    self.update_process(name,change,write_object);self.reject(kind)

 def test_04_exact_origin_and_fixture_restoration(self):
  for label,field,value in [('unrestored fixture','original_tree_restored',False),
                            ('wrong fixture owner','fixture','/tmp/unrelated-workdir'),
                            ('temporary original tree retained','temporary_tree_removed',False)]:
   with self.subTest(label=label),self.edits() as (_,write):
    path=self.original_folder/'fixture-journal.json';value_object=decode(path.read_bytes());value_object[field]=value
    write(path,value_object);self.reject(label)


def main():
 started=time.monotonic();result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(OriginalEvidence))
 summary=dict(schema='hepta.runtime.mcp-original-evidence-tests.v1',status='PASS' if result.wasSuccessful() else 'FAIL',
     elapsed_seconds=time.monotonic()-started,groups=result.testsRun,counts=COUNTS)
 if result.wasSuccessful():assert COUNTS['physical_refusals']==12 and COUNTS['two_new_roots_positive']==1
 print(json.dumps(summary,sort_keys=True),flush=True);raise SystemExit(0 if result.wasSuccessful() else 1)
if __name__=='__main__':main()
