"""Physical and re-signed refusal controls over exact retained artifacts."""
from pathlib import Path
import gzip,hashlib,io,json,os,shutil,struct,sys,tempfile,time
ROOT=Path(__file__).resolve().parents[3]
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'scripts'))
import hia_native_request_registry_pipeline as p
import hia_native_request_registry_qualification as q
NATIVE_NAMES=('empty-compiler-stdout','missing-hia','same-bytes-source-symlink','native-image-byte','compiler-b3-byte',
 'resigned-compile-return','frozen-schedule-source','native-process-failure','native-process-timeout','native-journal-pid',
 'resigned-grow-required-size','resigned-output-tail','resigned-workspace-cancel-bit','resigned-input-corpus','missing-native-chunk',
 'native-projected-context','resigned-unexecuted-origin','private-journal-pid','resigned-private-refusal-output')
ORIGINAL_NAMES=('missing-original-executable-pin','resigned-original-tool-hash','resigned-cargo-inode','resigned-original-toolchain',
 'original-sdk-crate-byte','resigned-original-context','resigned-original-id-type')
GUARDS={'empty-compiler-stdout': 'complete compiler stdout fields differ', 'missing-hia': 'FileNotFoundError', 'same-bytes-source-symlink': 'evidence must be an unsymlinked regular file', 'native-image-byte': 'native executable image differs', 'compiler-b3-byte': 'compiler generation differs', 'resigned-compile-return': 'native compiler did not return exact image', 'frozen-schedule-source': 'unchanged qualified source', 'native-process-failure': 'native invocation did not complete', 'native-process-timeout': 'native invocation did not complete', 'native-journal-pid': 'native process/order binding differs', 'resigned-grow-required-size': 'retained expected response differs', 'resigned-output-tail': 'complete native response/tail differs', 'resigned-workspace-cancel-bit': 'complete native arena differs', 'resigned-input-corpus': 'full native input corpus differs from frozen source', 'missing-native-chunk': 'FileNotFoundError', 'native-projected-context': 'full HIA snapshot differs from raw native journal', 'resigned-unexecuted-origin': 'recorded origin bound to actual main invocation', 'private-journal-pid': 'private raw call process/order', 'resigned-private-refusal-output': 'AssertionError', 'missing-original-executable-pin': 'complete original executable pin differs', 'resigned-original-tool-hash': 'fixed original tool executable bytes differ', 'resigned-cargo-inode': 'original cargo executable identity changed between processes', 'resigned-original-toolchain': 'fixed original process argv differs', 'original-sdk-crate-byte': 'unchanged SDK crate checksum differs', 'resigned-original-context': 'full comparison differs', 'resigned-original-id-type': 'full comparison differs'}
JOURNAL='request-registry/sdk/native/calls.jsonl.gz'
PRIVATE_JOURNAL='request-registry/private/calls.jsonl.gz'

class Controls:
 def __init__(self,source,output,kind,baseline,folder,working):
  self.source,self.output,self.kind=source,output,kind;self.baseline,self.folder,self.working=baseline,folder,working
  self.s=working/'source';self.o=working/'output';self.changed={};self.rows=[]
  for origin,target,table in [(source,self.s,baseline['source_sha256']),(output,self.o,baseline['artifact_sha256'])]:
   for name,sha in table.items():
    src=p.regular(origin/name);dst=target/name;dst.parent.mkdir(parents=True,exist_ok=True);os.link(src,dst)
  for name in ['result.json']:
   dst=self.o/name;dst.parent.mkdir(parents=True,exist_ok=True)
   if not dst.exists():os.link(output/name,dst)
 def mark(self,path):
  if path not in self.changed:
   base=self.source/path.relative_to(self.s)if path.is_relative_to(self.s)else self.output/path.relative_to(self.o)
   self.changed[path]=base
 def replace(self,path,raw):
  self.mark(path)
  if path.exists()or path.is_symlink():path.unlink()
  path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
 def change(self,path,edit):
  value=p.read(path);edit(value);self.replace(path,p.encoded(value))
 def missing(self,path):self.mark(path);path.unlink()
 def flip(self,path,at=0):raw=bytearray(path.read_bytes());raw[at]^=1;self.replace(path,raw)
 def restore(self):
  for path,base in self.changed.items():
   if path.exists()or path.is_symlink():path.unlink()
   if base.exists():os.link(base,path)
  self.changed.clear()
 def rows_read(self,name):
  with gzip.open(self.o/name,'rb')as src:return [p.decode(row)for row in src]
 def rows_write(self,name,rows):
  raw=io.BytesIO()
  with gzip.GzipFile(fileobj=raw,mode='wb',mtime=0)as out:
   for row in rows:out.write(q.canonical(row)+b'\n')
  self.replace(self.o/name,raw.getvalue())
 def journal_pid(self,name):
  rows=self.rows_read(name);rows[0]['pid']+=1;self.rows_write(name,rows)
 def chunks(self,kind):
  name=PRIVATE_JOURNAL if kind=='private-refusal'else JOURNAL
  rows=self.rows_read(name);blobs=self.o/Path(name).parent/'blobs'
  if kind=='tail':chosen=rows[0];fields=['output_after']
  elif kind=='grow':chosen=next(r for r in rows if r['domain'].endswith('/growth'));fields=['expected','output_after']
  elif kind=='private-refusal':chosen=next(r for r in rows if r['actual_code']==0xffffffff and r['output_after']['bytes']);fields=['output_after']
  else:chosen=next(r for r in rows if r['workspace_after']['bytes']>64 and struct.unpack_from('<Q',(blobs/r['request']['chunks'][0]).read_bytes(),8)[0]==1 and not r['domain'].endswith('/growth'));fields=['workspace_after']
  replacements={}
  for field in fields:
   ref=chosen[field];assert len(ref['chunks'])==1
   old=ref['chunks'][0];raw=bytearray((blobs/old).read_bytes())
   if kind=='tail':raw[80]^=1
   elif kind=='grow':struct.pack_into('<Q',raw,32,struct.unpack_from('<Q',raw,32)[0]+1)
   elif kind=='private-refusal':raw[0]^=1
   else:raw[96]^=1
   new=q.digest(raw);replacements[old]=(new,bytes(raw));assert not(blobs/new).exists();self.replace(blobs/new,raw)
  if kind=='private-refusal':
   field='output_after';old=chosen[field]['chunks'][0];new,raw=replacements[old]
   chosen[field]={'bytes':len(raw),'sha256':new,'chunks':[new]}
  else:
   for row in rows:
    for field in ('request','expected','output_before','output_after','workspace_before','workspace_after'):
     ref=row[field]
     if not any(s in replacements for s in ref['chunks']):continue
     ref['chunks']=[replacements[s][0]if s in replacements else s for s in ref['chunks']]
     whole=b''.join((blobs/s).read_bytes()for s in ref['chunks']);ref['sha256']=q.digest(whole);assert len(whole)==ref['bytes']
   for old in replacements:self.missing(blobs/old)
  self.rows_write(name,rows)
 def compile_return(self):
  folder=self.o/'build/modules/request-registry'
  self.change(folder/'module.receipt.json',lambda v:v.__setitem__('core_u32',89775))
  self.change(folder/'build.json',lambda v:v['compile_receipt'].__setitem__('core_u32',89775))
  self.change(folder/'module.stdout.log',lambda v:v.__setitem__('core_u32',89775))
 def projection(self):
  name='request-registry/sdk/native-observations.jsonl.gz';rows=self.rows_read(name)
  chosen=next(r for r in rows if r['event']=='step'and r['records']);chosen['records'][0]['cancelled']=not chosen['records'][0]['cancelled'];self.rows_write(name,rows)
 def input_corpus(self):
  path=self.o/'request-registry/sdk/sdk-cases.jsonl';first,rest=path.read_bytes().split(b'\n',1);value=p.decode(first);value['name']+='-altered'
  self.replace(path,q.canonical(value)+b'\n'+rest);changed=p.pin(path)
  self.change(self.o/'request-registry/sdk/RESULT.json',lambda v:v.__setitem__('cases',changed))
  self.change(self.o/'request-registry/sdk.stdout',lambda v:v.__setitem__('cases',changed))
  self.change(self.o/'request-registry/sdk.process.json',lambda v:v.__setitem__('stdout',p.pin(self.o/'request-registry/sdk.stdout')))
 def original_record(self,name,edit):
  self.change(self.o/'request-registry/original'/f'{name}.process.json',edit)
  self.change(self.o/'request-registry/original/RESULT.json',lambda v:edit(next(r['record']for r in v['processes']if r['record']['name']==name)))
 def original_stream(self,kind):
  path=self.o/'request-registry/original/original.stdout';self.mark(path);path.unlink();changed=False
  with (self.output/'request-registry/original/original.stdout').open('rb')as src,path.open('xb')as out:
   for raw in src:
    if not changed:
     value=p.decode(raw)
     if kind=='context'and value['event']=='step'and value['records']:
      value['records'][0]['cancelled']=not value['records'][0]['cancelled'];changed=True
     elif kind=='id'and value['event']=='end':
      for i,text in enumerate(value['responses']):
       response=p.decode(text)
       if type(response.get('id'))is int:
        response['id']=str(response['id']);value['responses'][i]=q.canonical(response).decode()+'\n';changed=True;break
     if changed:raw=q.canonical(value)+b'\n'
    out.write(raw)
  assert changed;identity=p.pin(path);self.original_record('original',lambda v:v.__setitem__('stdout',identity))
 def origin(self):
  old=p.read(self.o/'request-registry/execution.json')['source_root'];new='/unexecuted/registry-source'
  def changed(value):
   if isinstance(value,str):return value.replace(old,new)
   if isinstance(value,list):return [changed(x)for x in value]
   if isinstance(value,dict):return {k:changed(v)for k,v in value.items()}
   return value
  for name in ['request-registry/execution.json','request-registry/private.process.json','request-registry/sdk.process.json']:
   path=self.o/name;self.replace(path,p.encoded(changed(p.read(path))))
  execution=p.pin(self.o/'request-registry/execution.json')
  for domain in ('private','sdk'):
   self.change(self.o/'request-registry'/domain/'RESULT.json',lambda v:v.__setitem__('execution',execution))
   self.change(self.o/'request-registry'/(domain+'.stdout'),lambda v:v.__setitem__('execution',execution))
   self.change(self.o/'request-registry'/(domain+'.process.json'),lambda v:v.__setitem__('stdout',p.pin(self.o/'request-registry'/(domain+'.stdout'))))
 def records(self,folder):
  rows=[]
  for i,(path,base)in enumerate(sorted(self.changed.items())):
   row={'relative':path.relative_to(self.working).as_posix(),'before':p.pin(base)if base.is_file()else None}
   if path.is_symlink():row.update(kind='symlink',target=os.readlink(path))
   elif not path.exists():row['kind']='missing'
   else:
    row.update(kind='file',after=p.pin(path));retained=folder/(str(i)+'.bytes.gz')
    with path.open('rb')as src,retained.open('xb')as dst,gzip.GzipFile(fileobj=dst,mode='wb',mtime=0)as zipped:shutil.copyfileobj(src,zipped,1<<20)
    row.update(retained=retained.relative_to(self.output).as_posix(),retained_pin=p.pin(retained))
   rows.append(row)
  return rows
 def control(self,name,mutation,guard):
  folder=self.folder/'controls'/name;folder.mkdir(parents=True)
  mutation();mutations=self.records(folder)
  argv=[sys.executable,'-I','-B',str(self.source/'tests/hia_native/request_registry_sdk/read_evidence.py'),
        '--source',str(self.s),'--output',str(self.o),'--kind',self.kind,'--result',str(folder/'unexpected.json')]
  if self.kind=='original':argv+=['--native-baseline',str(self.folder/'native-baseline.json')]
  try:p.record(folder,'read',argv,cwd=self.source,timeout=180)
  except ValueError:pass
  row=p.read(folder/'read.process.json');stderr=(folder/'read.stderr').read_text()
  assert row['exit_code']!=0 and type(row['exit_code'])is int and row['timed_out']is False and row['start_error']is None and not(folder/'unexpected.json').exists(),row
  assert guard in stderr,(name,guard,stderr[-2500:])
  self.rows.append({'name':name,'status':'REJECTED','guard':guard,'process':row,'mutations':mutations})
  self.restore()
 def execute(self):
  s,o=self.s,self.o
  if self.kind=='native':
   self.control('empty-compiler-stdout',lambda:self.replace(o/'build/modules/request-registry/module.stdout.log',b'{}\n'),'complete compiler stdout fields differ')
   self.control('missing-hia',lambda:self.missing(s/'native/request_registry.hepta'),'FileNotFoundError')
   def symlink():
    path=s/'native/request_registry.hepta';self.missing(path);path.symlink_to(self.source/'native/request_registry.hepta')
   self.control('same-bytes-source-symlink',symlink,'evidence must be an unsymlinked regular file')
   self.control('native-image-byte',lambda:self.flip(o/'build/modules/request-registry/module.image.bin',100),'native executable image differs')
   self.control('compiler-b3-byte',lambda:self.flip(o/'build/bootstrap/B3.image.bin',100),'compiler generation differs')
   self.control('resigned-compile-return',self.compile_return,'native compiler did not return exact image')
   self.control('frozen-schedule-source',lambda:self.flip(s/'tests/hia_native/request_registry_sdk/cases.py',10),'unchanged qualified source')
   self.control('native-process-failure',lambda:self.change(o/'request-registry/sdk.process.json',lambda v:v.__setitem__('exit_code',1)),'native invocation did not complete')
   self.control('native-process-timeout',lambda:self.change(o/'request-registry/sdk.process.json',lambda v:v.__setitem__('timed_out',True)),'native invocation did not complete')
   self.control('native-journal-pid',lambda:self.journal_pid(JOURNAL),'native process/order binding differs')
   self.control('resigned-grow-required-size',lambda:self.chunks('grow'),'retained expected response differs')
   self.control('resigned-output-tail',lambda:self.chunks('tail'),'complete native response/tail differs')
   self.control('resigned-workspace-cancel-bit',lambda:self.chunks('workspace'),'complete native arena differs')
   self.control('resigned-input-corpus',self.input_corpus,'full native input corpus differs from frozen source')
   def chunk():
    row=self.rows_read(JOURNAL)[0];self.missing(o/'request-registry/sdk/native/blobs'/row['request']['chunks'][0])
   self.control('missing-native-chunk',chunk,'FileNotFoundError')
   self.control('native-projected-context',self.projection,'full HIA snapshot differs from raw native journal')
   self.control('resigned-unexecuted-origin',self.origin,'recorded origin bound to actual main invocation')
   self.control('private-journal-pid',lambda:self.journal_pid(PRIVATE_JOURNAL),'private raw call process/order')
   self.control('resigned-private-refusal-output',lambda:self.chunks('private-refusal'),'AssertionError')
  else:
   self.control('missing-original-executable-pin',lambda:self.original_record('build',lambda v:v.__setitem__('executable',{})),'complete original executable pin differs')
   self.control('resigned-original-tool-hash',lambda:self.original_record('build',lambda v:v['executable'].__setitem__('sha256','0'*64)),'fixed original tool executable bytes differ')
   self.control('resigned-cargo-inode',lambda:self.original_record('build',lambda v:v['executable_identity'].__setitem__('ino',999999999)),'original cargo executable identity changed between processes')
   self.control('resigned-original-toolchain',lambda:self.original_record('build',lambda v:v['argv'].__setitem__(0,'/wrong/toolchain/cargo')),'fixed original process argv differs')
   self.control('original-sdk-crate-byte',lambda:self.flip(o/'request-registry/original/rmcp-3.4.1.crate',100),'unchanged SDK crate checksum differs')
   self.control('resigned-original-context',lambda:self.original_stream('context'),'full comparison differs')
   self.control('resigned-original-id-type',lambda:self.original_stream('id'),'full comparison differs')

def run(kind):
 root=ROOT;output=Path(os.environ['HIA_REQUEST_REGISTRY_OUTPUT']).absolute();report=p.read(output/'result.json')
 started=time.monotonic_ns();folder=output/p.FOLDER/(kind+'-controls');folder.mkdir()
 native=p.native_evidence(root,output,report,with_controls=kind=='original')
 if kind=='native':baseline=native
 else:
  import hia_native_request_registry_reference as reference
  baseline=reference.read_original(root,output,report,native);p.write_new(folder/'native-baseline.json',native)
 p.write_new(folder/'baseline.json',baseline)
 with tempfile.TemporaryDirectory(prefix='request-registry-controls-',dir=output.parent)as temporary:
  working=Path(temporary);control=Controls(root,output,kind,baseline,folder,working)
  try:control.execute()
  finally:control.restore()
  require_names=NATIVE_NAMES if kind=='native'else ORIGINAL_NAMES
  assert tuple(r['name']for r in control.rows)==require_names
  result={'schema':'hepta.runtime.request-registry-controls.v1','status':'PASS','kind':kind,'pid':os.getpid(),
   'started_monotonic_ns':started,'finished_monotonic_ns':time.monotonic_ns(),'working_root':str(working),
   'source_root':str(root),'output_root':str(output),'python':sys.executable,
   'python_executable':p.pin(Path(sys.executable).resolve(strict=True)),'python_identity':p.executable_identity(sys.executable),
   'baseline':p.pin(folder/'baseline.json'),'rows':control.rows,'controls':len(control.rows),'test_groups':2,
   'source_files':p.source_table(root),'new_native_calls':0,'new_original_processes':0}
 p.write_new(folder/'RESULT.json',result)
 summary={'status':'PASS','test_groups':2,'skipped':0,'errors':0,'failures':0,'controls':len(control.rows),
          'native_cases_added_by_replay':0,'new_original_processes':0,'whole_runtime_replaced':False}
 p.write_new(folder/'summary.json',summary);print(json.dumps(summary,sort_keys=True),flush=True)
