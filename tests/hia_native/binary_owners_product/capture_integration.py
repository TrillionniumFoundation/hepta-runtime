"""Actual installed HIA graph versus frozen qualified native component calls.

Every source domain, full transport byte stream, native mutable buffer and
failure is retained. No Rust result stream is read and no public writer is
registered by this integration qualification.
"""
from pathlib import Path
from read_resource_capture import read_trace, read_memory
import argparse, collections, ctypes, gzip, hashlib, importlib.util, json, os
import queue, re, struct, subprocess, sys, threading, time
sys.dont_write_bytecode=True
PACK=lambda *v:struct.pack('<'+'Q'*len(v),*v)
word=lambda b,o:struct.unpack_from('<Q',b,o)[0]
sha=lambda b:hashlib.sha256(b).hexdigest()
pin=lambda b:{'bytes':len(b),'sha256':sha(b)}
INVALID=0xffffffff

def save(p,v):p.write_text(json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False)+'\n')
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec)
 sys.modules[name]=m;spec.loader.exec_module(m);return m
def exact(stream,n):
 result=bytearray()
 while len(result)<n:
  b=stream.read(n-len(result))
  if not b:raise EOFError(('short private response',len(result),n))
  result.extend(b)
 return bytes(result)

class Fixture:
 def __init__(self,out,binary,cwd,config=None,budget=60,trace=False):
  self.out=out;out.mkdir();self.budget=budget;self.start=time.monotonic();self.closed=False
  self.errors=[];self.q=queue.Queue();self.rows=[];self.buffers={};self.hashes={};self.sizes={}
  from runtime_mcp_public_capture import Stream
  self.streams={n:Stream(out/(n+'.bin.gz')) for n in ('stdin','stdout','stderr')}
  self.command=[str(binary)]+([]if config is None else['--runtime-config',str(config)])
  if trace:self.command=['/usr/bin/strace','-f','-qq','-e','trace=mmap,mprotect,munmap,mremap,clone,clone3,exit,exit_group,wait4','-o',str(out/'memory.strace')]+self.command
  self.cwd=str(cwd)
  self.p=subprocess.Popen(self.command,cwd=cwd,env={'PATH':'','LC_ALL':'C'},stdin=subprocess.PIPE,
      stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
  def receive():
   try:
    while True:
     tag=self.p.stdout.read(8)
     if not tag:break
     tag+=exact(self.p.stdout,8-len(tag))
     if tag==b'HFSFXR02':
      h=tag+exact(self.p.stdout,96);size=word(h,32);assert size<1<<30
      b=exact(self.p.stdout,size);raw=h+b;kind='leaf'
     elif tag==b'HFSJPR03':
      h=tag+exact(self.p.stdout,88);status=word(h,16)
      b=b'' if status in(0,4) else self.p.stdout.readline();raw=h+b;kind='public'
      if status not in(0,4):assert b.endswith(b'\n')
     else:raise AssertionError(('unknown fixture response',tag.hex()))
     self.streams['stdout'].write(raw);self.q.put((kind,h,b))
   except BaseException as e:self.errors.append(repr(e));self.q.put(e)
  def stderr():
   try:
    while b:=self.p.stderr.read(65536):self.streams['stderr'].write(b)
   except BaseException as e:self.errors.append(repr(e))
  self.threads=[threading.Thread(target=receive),threading.Thread(target=stderr)]
  for t in self.threads:t.start()
 def query(self,slot,wire,session=0,label=''):
  started=time.monotonic();frame=b'HFSFXQ02'+PACK(session,slot,len(wire))+wire
  self.streams['stdin'].write(frame)
  left=memoryview(frame)
  while left:
   n=self.p.stdin.write(left);assert n and n>0;left=left[n:]
  remaining=self.budget-(time.monotonic()-self.start)
  if remaining<=0:raise TimeoutError('original private process budget')
  item=self.q.get(timeout=remaining)
  if isinstance(item,BaseException):raise item
  kind,head,body=item
  assert word(head,8)==session
  if kind=='leaf':
   assert word(head,16)==slot and len(body)==word(head,32)<=word(head,96)
   code=word(head,24)
  else:assert slot==34;code=word(head,16)
  self.rows.append({'sequence':len(self.rows)+1,'slot':slot,'session':session,'label':label,
      'input':pin(wire),'header_hex':head.hex(),'body':pin(body),'elapsed_seconds':time.monotonic()-started})
  return code,body,head
 def close(self,failed=False):
  if self.closed:return
  self.closed=True
  try:self.p.stdin.close()
  except (OSError,BrokenPipeError):pass
  if failed and self.p.poll() is None:self.p.kill()
  timed=False
  try:self.p.wait(timeout=max(.001,self.budget-(time.monotonic()-self.start)))
  except subprocess.TimeoutExpired:timed=True;self.p.kill();self.p.wait()
  for t in self.threads:t.join(timeout=5)
  assert all(not t.is_alive() for t in self.threads)
  streams={n:s.close() for n,s in self.streams.items()}
  save(self.out/'responses.json',self.rows)
  save(self.out/'process.json',{'command':self.command,'cwd':self.cwd,'environment':{'PATH':'','LC_ALL':'C'},
      'pid':self.p.pid,'exit_code':self.p.returncode,'timed_out':timed,'timeout_seconds':self.budget,
      'elapsed_seconds':time.monotonic()-self.start,'failure_cleanup_requested':failed,'errors':self.errors,**streams})
  if not failed:assert not timed and self.p.returncode==0 and not self.errors,(self.out,self.p.returncode,self.errors)

def main():
 p=argparse.ArgumentParser()
 for n in ('source','params-source','plan-source','references','product','fixture','baseline','baseline-fixture','output'):
  p.add_argument('--'+n,required=True,type=Path)
 a=p.parse_args();out=a.output.absolute();out.mkdir(parents=True,exist_ok=False)
 sys.path[:0]=[str(a.source/'scripts'),str(a.source/'tests/hia_native')]
 from hia_native_loader import NativeModule
 from public_nine_build import source_check
 frozen=source_check(a.source)
 sys.path.insert(0,str(a.params_source/'scripts'))
 typed=load('qualified_typed_capture',a.params_source/'scripts/native_capture.py')
 cases=typed.params_cases
 # Both exact packages have the same byte-only canonical/owned helpers. Load
 # the planner's full source under its own package-specific names.
 sys.path.insert(0,str(a.plan_source/'scripts'))
 sys.modules.pop('common',None)
 planner=load('qualified_plan_capture',a.plan_source/'scripts/native_capture.py')
 plan_cases=planner.plan_cases
 typed_source=typed.source_evidence(a.params_source)
 plan_source=planner.source_evidence(a.plan_source)
 oldtest=load('retained_root_product_verifier',a.source/'tests/hia_native/binary_root_product/verify_runtime.py')
 def binary(path,count):
  md=json.loads(path.read_bytes());b=path.parent/md['elf']
  assert pin(b.read_bytes())=={'bytes':md['elf_bytes'],'sha256':md['elf_sha256']}
  assert md['runtime_hia_images']==count and len(md['members'])==count-8
  return b,md
 product,pmd=binary(a.product,126);fixture,fmd=binary(a.fixture,126)
 base,bmd=binary(a.baseline,124);basefix,bfmd=binary(a.baseline_fixture,124)
 assert len(pmd['extra_table'])==len(fmd['extra_table'])==71
 assert pmd['extra_table'][:69]==bmd['extra_table'] and pmd['extra_table'][69:]==['binary_write_params','binary_call_plan']
 assert [r['name'] for r in pmd['members'] if r['name'] not in ('binary_write_params','binary_call_plan')]==[r['name']for r in bmd['members']]
 for before in bmd['members']:
  current=next(r for r in pmd['members']if r['name']==before['name'])
  assert all(current[k]==before[k]for k in ('source_sha256','image_sha256','image_bytes'))
 refs=json.loads(a.references.read_bytes())
 class Reference:
  invoke=typed.Recorder.invoke
  complete=typed.Recorder.complete
  plan=planner.Recorder.plan
  def __init__(self,folder):
   folder.mkdir();self.out=folder;self.modules={int(k):NativeModule(v['manifest'],manifest_sha256=v['sha256'])for k,v in refs.items()}
   self.stream=gzip.open(folder/'calls.bin.gz','wb',compresslevel=1);self.index=[];self.rows=[];self.controls=[];self.offset=0;self.first_plan=None
  def close(self):
   self.stream.close()
   for m in self.modules.values():m.close()
   for name,rows in [('calls',self.index),('cases',self.rows),('controls',self.controls)]:
    (self.out/(name+'.jsonl')).write_bytes(b''.join((json.dumps(r,sort_keys=True,separators=(',',':'))+'\n').encode()for r in rows))
   save(self.out/'capture.json',{'calls':len(self.index),'controls':len(self.controls),'logical_bytes':self.offset})
 report={'status':'RUNNING','original_rust_executed':False,'remote_body_executed':False,
     'public_binary_write_registered':False,'whole_runtime_qualified':False,'old_path_removed':False,
     'source':frozen,'qualified_sources':{'params':typed_source,'plan':plan_source},'binaries':{}}
 for n,b in [('product',product),('fixture',fixture),('baseline',base),('baseline_fixture',basefix)]:report['binaries'][n]=pin(b.read_bytes())
 started=time.monotonic();ref=None
 try:
  report['public']=oldtest.public_regression(out,base,product)
  print(json.dumps({'stage':'public','responses':report['public']['response_pairs'],'status':'PASS'}),flush=True)
  rootarea=out/'root';rootarea.mkdir();rootgroups=[]
  for name,hosts,rows in oldtest.root_domains():
   folder=rootarea/name;folder.mkdir();cwd=folder/'workspace';cwd.mkdir()
   cfg=None if hosts is None else oldtest.config(folder/'config.json',cwd,hosts)
   save(folder/'inputs.json',[{'name':r[0],'wire_hex':r[1].hex()}for r in rows])
   old,_=oldtest.fixture_run(folder/'baseline',basefix,cwd,cfg,rows)
   new,traces=oldtest.fixture_run(folder/'candidate',fixture,cwd,cfg,rows)
   assert old==new,(name,'root response/counter/capacity changed')
   rootgroups.append({'name':name,'queries':len(rows),'trace_records':len(traces)})
  report['root']={'status':'PASS','groups':rootgroups,'queries':sum(r['queries']for r in rootgroups)}
  print(json.dumps({'stage':'root','queries':report['root']['queries'],'status':'PASS'}),flush=True)
  ref=Reference(out/'reference')
  allcases=cases.cases();assert len(allcases)==1388
  typedarea=out/'typed';typedarea.mkdir();(typedarea/'input.jsonl').write_bytes(cases.encoded())
  typedrows=[]
  for kind in range(1,6):
   cwd=typedarea/('kind'+str(kind));cwd.mkdir();client=Fixture(cwd/'installed',fixture,cwd)
   success=False
   try:
    for row in [r for r in allcases if r['kind']==kind]:
     cid=row['case_id'];raw=row['raw_json'].encode();wire=b'HJSMS002'+PACK(1,len(raw))+raw
     expected,calls=ref.complete(1,cid,wire)
     code,observed,head=client.query(10,wire,cid%2,row['name'])
     assert code==32 and observed==expected,('Map',row['name'],code)
     admitted=word(observed,8)==0;ok=False;tframe=None;tcalls=[]
     if admitted:
      twire=typed.wire_for(kind,observed[32:]);tframe,tcalls=ref.complete(kind+1,cid,twire)
      if kind==3:
       tcode,actual,thead=client.query(69,twire,cid%2,row['name'])
       assert tcode==256 and actual==tframe,('typed-write',row['name'],tcode,actual[:256].hex())
      ok=word(tframe,8)==0
     result={'case_id':cid,'kind':kind,'name':row['name'],'input_sha256':sha(raw),
         'value_calls':calls,'params_calls':tcalls,'admitted':admitted,'typed_success':ok,
         'typed_frame_hex':None if tframe is None else tframe.hex(),'installed_write_owner':kind==3 and admitted}
     typedrows.append(result)
    success=True
   finally:client.close(not success)
  save(typedarea/'results.json',typedrows)
  typed.Recorder.boundary_controls(ref)
  assert len(ref.controls)==170
  report['typed']={'status':'PASS','all_input_cases':len(typedrows),'installed_write_cases':sum(r['kind']==3 for r in typedrows),
      'original_abi_controls':len(ref.controls),'admitted':sum(r['admitted']for r in typedrows),
      'success':sum(r['typed_success']for r in typedrows),'other_four_types_are_reference_fixtures':True}
  print(json.dumps({'stage':'typed',**report['typed']}),flush=True)
  planarea=out/'planner';planarea.mkdir();groups=plan_cases.groups(planarea);planrows=[];configcalls=0
  assert len(groups)==24 and sum(len(g['cases'])for g in groups)==433
  first_good_write=None
  for group in groups:
   folder=planarea/group['name'];folder.mkdir();cwd=folder/'workspace';cwd.mkdir()
   cfg=None
   if group['config']is not None:
    cfg=folder/'config.json';save(cfg,group['config'])
   (folder/'input.json').write_bytes(plan_cases.encoded(group))
   oldcfg=None
   if cfg is not None:
    oldvalue=json.loads(cfg.read_bytes());oldvalue['state_dir']=str(folder/'prior-state')
    oldcfg=folder/'prior-config.json';save(oldcfg,oldvalue)
    assert {k:v for k,v in oldvalue.items()if k!='state_dir'}=={k:v for k,v in group['config'].items()if k!='state_dir'}
   client=Fixture(folder/'installed',fixture,cwd,cfg,45)
   baseline=Fixture(folder/'prior-root',basefix,cwd,oldcfg,45)
   success=False
   try:
    for row in group['cases']:
     cid=row['case_id'];kind=row['kind'];raw=row['raw_json'].encode()
     vwire=b'HJSMS002'+PACK(1,len(raw))+raw
     value,vcalls=ref.complete(1,cid,vwire)
     code,actual,_=client.query(10,vwire,cid%2,row['name']);assert code==32 and actual==value and word(value,8)==0
     twire=typed.wire_for(kind,value[32:]);typedframe,tcalls=ref.complete(kind+1,cid,twire)
     if kind==3:
      code,actual,_=client.query(69,twire,cid%2,row['name']);assert code==256 and actual==typedframe
     stages=[];terminal=None;phase=0;feedback=b''
     if word(typedframe,8)==0:
      for _ in range(4):
       pwire=b'HBPLQ001'+PACK(phase,int(row['pool']),len(typedframe),len(feedback),0)+typedframe+feedback
       expected,pcalls=ref.plan(cid,pwire)
       code,actual,_=client.query(70,pwire,cid%2,row['name'])
       assert code==len(expected) and actual==expected,('plan',group['name'],row['name'],phase,code,actual[:64].hex())
       if ref.first_plan is None:ref.first_plan=(pwire,expected)
       if kind==3 and first_good_write is None:first_good_write=(twire,typedframe,pwire,expected)
       stage={'phase':phase,'plan_calls':pcalls,'frame_hex':actual.hex(),'root_hex':None}
       stages.append(stage)
       if word(actual,8)==2:
        phase=word(actual,24);qwire=actual[64:]
        bcode,old,_=baseline.query(11,qwire,cid%2,row['name'])
        code,feedback,_=client.query(11,qwire,cid%2,row['name'])
        assert code==bcode==len(feedback) and old==feedback
        stage['root_hex']=feedback.hex();configcalls+=1
       else:
        assert word(actual,8)in(1,3);terminal=actual;break
      assert terminal is not None
     planrows.append({'case_id':cid,'kind':kind,'name':row['name'],'group':group['name'],
         'value_calls':vcalls,'params_calls':tcalls,'typed_frame_hex':typedframe.hex(),'stages':stages,
         'terminal_hex':None if terminal is None else terminal.hex()})
    success=True
   finally:client.close(not success);baseline.close(not success)
   print(json.dumps({'stage':'planner-group','name':group['name'],'cases':len(group['cases']),'status':'PASS'}),flush=True)
  save(planarea/'results.json',planrows)
  prior_controls=len(ref.controls);planner.Recorder.boundary_controls(ref)
  # The immutable FINAL_HANDOFF preserves the original counter defect:
  # producer 27 / malformed 12; the old README incorrectly declared 28 / 13.
  handoff=json.loads((a.plan_source.parent/'FINAL_HANDOFF.json').read_bytes())
  assert handoff['actual_capture']['actual_boundary_controls']==27
  assert collections.Counter(r['kind']for r in ref.controls[prior_controls:])=={
      'bound-reference':1,'short-output':4,'output-boundary':4,'workspace-growth':3,
      'invalid-frame':12,'dirty-workspace':3}
  assert len(ref.controls)-prior_controls==27
  report['planner']={'status':'PASS','groups':24,'cases':len(planrows),'config_exchanges':configcalls,
      'original_abi_controls':27,'original_stale_declared_controls':28,
      'terminals':dict(collections.Counter('typed-error'if r['terminal_hex']is None else str(word(bytes.fromhex(r['terminal_hex']),8))for r in planrows))}
  # Actual installed invalid frames use the same frozen ABI mutations. They
  # must still reject after prior successful calls dirty both owner workspaces.
  controls=out/'installed-controls';controls.mkdir();cwd=controls/'workspace';cwd.mkdir()
  (cwd/'occupied.txt').write_bytes(b'occupied\n')
  cfg=oldtest.config(controls/'config.json',cwd,{'h':oldtest.host()})
  client=Fixture(controls/'installed',fixture,cwd,cfg,60,trace=True);success=False
  twire,tframe,pwire,pframe=first_good_write
  try:
   for session in(0,1):
    code,b,_=client.query(69,twire,session,'before-publication');assert(code,b)==(256,tframe)
    code,b,_=client.query(70,pwire,session,'before-publication');assert(code,b)==(len(pframe),pframe)
    for obj in [
      {'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'binary-owner-layout','version':'1'}}},
      {'jsonrpc':'2.0','method':'notifications/initialized'},
      {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'text_file_write','arguments':{'path':'occupied.txt','mode':'create','content':'new','expected_sha256':'absent'}}}]:
     raw=json.dumps(obj,separators=(',',':')).encode();code,b,_=client.query(34,raw,session,'existing-publication-route')
     if obj.get('id')is not None:assert json.loads(b)['id']==obj['id']
    code,b,_=client.query(69,twire,session,'after-publication');assert(code,b)==(256,tframe)
    code,b,_=client.query(70,pwire,session,'after-publication');assert(code,b)==(len(pframe),pframe)
   bad_typed=[b'',twire[:7],twire[:24],b'XXXXXXXX'+twire[8:],twire[:8]+PACK(len(twire)-23)+twire[16:],twire[:16]+PACK(4)+twire[24:]]
   bad_plan=[b'',pwire[:47],b'XXXXXXXX'+pwire[8:]]
   for at,v in((8,3),(16,2),(24,0),(32,1),(40,1),(48,0),(56,1),(64,0),(200,1)):
    raw=bytearray(pwire);struct.pack_into('<Q',raw,at,v);bad_plan.append(bytes(raw))
   bad_plan.append(pwire+b'\0') # additional complete-frame trailing-byte control
   for slot,domain in((69,bad_typed),(70,bad_plan)):
    for i,wire in enumerate(domain):
     code,b,_=client.query(slot,wire,i%2,'invalid-'+str(i));assert code==INVALID and b==b''
   for session in(1,0):
    code,b,_=client.query(69,twire,session,'after-invalid');assert(code,b)==(256,tframe)
    code,b,_=client.query(70,pwire,session,'after-invalid');assert(code,b)==(len(pframe),pframe)
   success=True
  finally:client.close(not success)
  assert(cwd/'occupied.txt').read_bytes()==b'occupied\n'
  trace=gzip.decompress((controls/'installed/stderr.bin.gz').read_bytes())
  # Canonical path depth changes ACK counts across reproduction directories.
  # Every byte is parsed; the exact frozen ROG DATA reader also pins its counts.
  trace_read=read_trace(trace,expected_counts=None);slots=set(trace_read['slots'])
  memory_read=read_memory((controls/'installed/memory.strace').read_text(),expected_counts=None)
  freed=memory_read['explicit_graph_unmaps']
  rejected=[]
  for slot in(71,72,(1<<64)-1):
   folder=controls/('slot-'+str(slot));folder.mkdir();wire=b'HFSFXQ02'+PACK(0,slot,0)
   child=subprocess.run([str(fixture)],input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=cwd,env={'PATH':'','LC_ALL':'C'},timeout=60)
   for name,raw in [('stdin',wire),('stdout',child.stdout),('stderr',child.stderr)]:
    (folder/(name+'.bin.gz')).write_bytes(gzip.compress(raw,mtime=0))
   assert child.returncode!=0 and child.stdout==b''
   save(folder/'process.json',{'exit_code':child.returncode,'timeout_seconds':60,'timed_out':False,'slot':slot})
   rejected.append(slot)
  report['installed_controls']={'status':'PASS','typed_invalid':6,'planner_invalid':13,'rejected_slots':rejected,
      'actual_slots_observed':sorted(slots),'freed_native_allocations':freed,'remaining_graph_allocations_before_exit':0,'process_owned_mapping_released_by_exit_bytes':3707834368,
      'two_sessions_interleaved_with_publication':True,'engine_bytes':16384,'slots':71,'high_bitmap_offsets':[12736,12744]}
  assert source_check(a.source)==frozen
  assert typed.source_evidence(a.params_source)==typed_source and planner.source_evidence(a.plan_source)==plan_source
  report['status']='PASS'
 except BaseException as e:report.update(status='FAIL',error=repr(e));raise
 finally:
  if ref is not None:ref.close()
  report['elapsed_seconds']=time.monotonic()-started;save(out/'RESULT.json',report)
 print(json.dumps({k:v for k,v in report.items()if k not in('source','qualified_sources')},sort_keys=True),flush=True)
if __name__=='__main__':main()
