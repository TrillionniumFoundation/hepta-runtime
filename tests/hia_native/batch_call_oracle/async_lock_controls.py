"""Two actual Linux cancellation controls; zero new original semantic cases."""
from pathlib import Path
import argparse,gzip,hashlib,importlib.util,json,os,select,struct,sys,time,traceback
parser=argparse.ArgumentParser()
for option in ('source','native-run','output'):parser.add_argument('--'+option,type=Path,required=True)
selected=parser.parse_args()
SOURCE=selected.source.resolve(strict=True)
NATIVE=selected.native_run.resolve(strict=True)
OUT=selected.output.absolute()
OUT.mkdir(exist_ok=False)
began=time.monotonic_ns()
(OUT/'remote-process.json').write_text(json.dumps({'pid':os.getpid(),'argv':sys.argv,'cwd':os.getcwd(),'cgroup':Path('/proc/self/cgroup').read_text(),'started_monotonic_ns':began}))
os.umask(0o077)
sys.path.insert(0,str(SOURCE/'tests/hia_native'))
from batch_call_capture import Session,Fixtures,Blobs,canonical,word,sha
spec=importlib.util.spec_from_file_location('control_case_input',SOURCE/'tests/hia_native/batch_call_oracle/cases.py')
cases=importlib.util.module_from_spec(spec);spec.loader.exec_module(cases)
manifest=NATIVE/'graph-v1/native/manifest.json';build=json.loads(manifest.read_bytes());elf=manifest.parent/build['elf']
def pin(path):
 with Path(path).open('rb')as f:return {'bytes':os.fstat(f.fileno()).st_size,'sha256':hashlib.file_digest(f,'sha256').hexdigest()}
sources=[Path(__file__),manifest,elf,SOURCE/'tests/hia_native/batch_call_capture.py',Path(cases.__file__),NATIVE/'output-async/native-cases.jsonl']
before={str(p):pin(p)for p in sources}
(OUT/'SOURCE.json').write_bytes(canonical(before))
native_rows={r['case_id']:r for r in map(json.loads,(NATIVE/'output-async/native-cases.jsonl').read_bytes().splitlines())}
blobs=Blobs(OUT);fixtures=Fixtures();(OUT/'sessions').mkdir();(OUT/'files').mkdir()
results=[]
def fd_snapshot(pid):
 answer=[]
 for n in sorted(os.listdir(f'/proc/{pid}/fd'),key=int):
  p=f'/proc/{pid}/fd/{n}'
  try:target=os.readlink(p);mode=os.stat(p).st_mode
  except FileNotFoundError:continue
  answer.append({'fd':int(n),'target_hex':os.fsencode(target).hex(),'mode':mode})
 return answer
def blocked(session,pid=None):
 limit=min(session.deadline,time.monotonic()+15)
 while time.monotonic()<limit:
  children=Path(f'/proc/{session.p.pid}/task/{session.p.pid}/children').read_text().split()
  if len(children)==1 and (pid is None or children==[str(pid)]):
   child=int(children[0]);wchan=Path(f'/proc/{child}/wchan').read_bytes()
   if b'wait_for_partner' in wchan:
    syscall=Path(f'/proc/{child}/syscall').read_bytes()
    assert syscall.split()[0]==b'257'
    return {'pid':child,'parent':session.p.pid,'observed_monotonic_ns':time.monotonic_ns(),
      'children':blobs.add((' '.join(children)+'\n').encode()),'wchan':blobs.add(wchan),
      'syscall':blobs.add(syscall),'status':blobs.add(Path(f'/proc/{child}/status').read_bytes()),
      'fd':fd_snapshot(child)}
  time.sleep(.002)
 raise AssertionError('actual worker was not blocked at FIFO open')
def result(session):
 kind,body,record=session.message()
 assert kind in(2,3) and len(body)>=72 and body[8:16]==b'HBCAR002'
 ret=word(body,0);status,gen,seq,target,n,aux,z=struct.unpack_from('<7Q',body,16)
 assert z==0 and n==len(body)-72 and ret in(64,0xfffffff0)
 return {'kind':kind,'return':ret,'status':status,'generation':gen,'sequence':seq,'target':target,
         'aux':aux,'body':blobs.add(body),'wire':record}
def lock(session,op,lease=0,key=b''):
 frame=b'HRFLOCK1'+struct.pack('<7Q',op,lease,len(key),0,0,0,0)+key
 ret,raw,wire=session.owner(18,frame)
 assert ret==64 and len(raw)==64 and raw[:8]==b'HRFLKR01'
 q=struct.unpack_from('<7Q',raw,8);assert q[0]==op
 return {'op':op,'request':blobs.add(frame),'response':blobs.add(raw),'decoded':list(q),'wire':wire}
def dump(session):
 ret,raw,wire=session.owner(18,b'');assert ret==0
 return {'body':blobs.add(raw),'wire':wire}
def write_fifo(path,data,deadline):
 fd=os.open(path,os.O_WRONLY|os.O_NONBLOCK);at=0
 try:
  while at<len(data):
   try:n=os.write(fd,memoryview(data)[at:at+65536]);assert n>0;at+=n
   except BlockingIOError:
    assert time.monotonic()<deadline
    select.select([],[fd],[],max(.001,deadline-time.monotonic()))
 finally:os.close(fd)
 return at
def read_fifo(path,pid,deadline):
 fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK);parts=[]
 try:
  while True:
   assert time.monotonic()<deadline
   try:raw=os.read(fd,65536)
   except BlockingIOError:raw=None
   if raw:parts.append(raw);continue
   state=Path(f'/proc/{pid}/stat').read_text().split(') ',1)[1].split()[0]
   if raw==b'' and state=='Z':break
   select.select([fd],[],[],.002)
 finally:os.close(fd)
 return b''.join(parts)
try:
 for case in cases.iter_cases():
  meta=case['metadata'];case_id=meta['case_id']
  if case_id not in(213,214):continue
  own=OUT/'files'/('case-'+str(case_id));own.mkdir();root=os.fsencode(own)
  fixtures.actions(root,meta['initial'],case['blobs'])
  descriptor=native_rows[case_id]['typed'];typed_path=NATIVE/'output-async'/descriptor['artifact']
  typed=gzip.decompress(typed_path.read_bytes())
  assert {'bytes':len(typed),'sha256':sha(typed)}=={k:descriptor[k]for k in('bytes','sha256')}
  before[str(typed_path)]=pin(typed_path)
  path=typed[64:64+word(typed,16)];resolved=root+b'/'+path
  assert not path.startswith(b'/') and b'..'not in path.split(b'/')
  session=Session(OUT/'sessions',str(case_id),elf,'--async')
  record={'case_id':case_id,'domain':'actual-Linux-cancel-before-late-lock-control','input_metadata':meta,
          'input_blobs':[blobs.add(x)for x in case['blobs']],'typed':blobs.add(typed),
          'fixture_root_hex':root.hex(),'before':fixtures.tree(root,blobs)}
  try:
   key,key_wire=session.key(resolved);record['key']={'bytes':blobs.add(key),'wire':key_wire}
   frame=b'HBCALQ02'+struct.pack('<7Q',1,0,0,len(typed),len(resolved),0,0)+typed+resolved
   session.deadline=time.monotonic()+60
   record['start']={'frame':blobs.add(frame),'wire':session.send(frame)}
   pending=[result(session)]
   target=2 if meta['cancel']['stage']=='first_read' else 19
   while pending[-1]['kind']==3 and pending[-1]['target']!=target:
    session.send(b'HBCACTL2'+struct.pack('<Q',3));pending.append(result(session))
   assert pending[-1]['kind']==3 and pending[-1]['target']==target
   record['pending']=pending;record['blocked_before_cancel']=blocked(session)
   record['lock_before_cancel']=lock(session,7);record['arena_before_cancel']=dump(session)
   session.send(b'HBCACTL2'+struct.pack('<Q',2));record['cancel']=result(session)
   assert record['cancel']['kind']==2 and record['cancel']['status']==4
   record['blocked_after_cancel']=blocked(session,record['blocked_before_cancel']['pid'])
   record['lock_after_cancel']=lock(session,7);record['arena_after_cancel']=dump(session)
   record['after_cancel']=fixtures.tree(root,blobs)
   acquired=lock(session,1,key=key);assert acquired['decoded'][1]==0 and acquired['decoded'][2]>0
   lease=acquired['decoded'][2]
   polled=lock(session,3,lease);assert polled['decoded'][1:3]==[0,lease]
   record['reacquire_before_late']=[acquired,polled]
   record['blocked_while_reacquired']=blocked(session,record['blocked_before_cancel']['pid'])
   released=lock(session,5,lease);dropped=lock(session,6,lease)
   assert released['decoded'][1:3]==dropped['decoded'][1:3]==[0,lease]
   record['new_lease_retirement']=[released,dropped]
   record['blocked_before_transfer']=blocked(session,record['blocked_before_cancel']['pid'])
   record['lock_before_transfer']=lock(session,7)
   if target==2:
    transferred=case['blobs'][meta['cancel']['transfer_blob']]
    assert write_fifo(resolved,transferred,session.deadline)==len(transferred)
   else:transferred=read_fifo(root+b'/.octofs_tmp_file.tmp',record['blocked_before_cancel']['pid'],session.deadline)
   record['transfer']=blobs.add(transferred)
   session.send(b'HBCACTL2'+struct.pack('<Q',3));record['late']=result(session)
   assert record['late']['kind']==2 and record['late']['status']==7
   record['lock_after_late']=lock(session,7);record['arena_after_late']=dump(session)
   record['after_late']=fixtures.tree(root,blobs);record['final_descriptors']=fd_snapshot(session.p.pid)
   assert [r['fd']for r in record['final_descriptors']]==[0,1,2]
   session.finish();record['status']='PASS'
  except BaseException:
   session.abort();record['status']='FAIL';record['traceback']=traceback.format_exc();raise
  finally:
   results.append(record);(OUT/'CONTROLS.json').write_bytes(canonical(results))
 fixtures.close()
 assert before=={p:pin(p)for p in before}
 (OUT/'SOURCE.json').write_bytes(canonical(before))
 summary={'status':'PASS','controls':2,'actual_elf_processes':2,'new_original_processes':0,'new_original_semantic_cases':0,
  'original_215_capture_changed':False,'scope_context_wire_observation':False,
  'elapsed_seconds':(time.monotonic_ns()-began)/1e9,'control_capture':pin(OUT/'CONTROLS.json')}
except BaseException:
 fixtures.close()
 summary={'status':'FAIL','error':traceback.format_exc(),'completed_controls':len(results),'elapsed_seconds':(time.monotonic_ns()-began)/1e9}
(OUT/'RESULT.json').write_bytes(canonical(summary));print(json.dumps(summary,sort_keys=True))
if summary['status']!='PASS':raise SystemExit(1)
