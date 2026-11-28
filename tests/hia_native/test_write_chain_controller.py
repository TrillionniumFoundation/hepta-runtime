"""Actual HIA continuation/leaf tests; synthetic filesystem replies are explicit."""
from pathlib import Path
import argparse,ctypes,gzip,hashlib,json,struct,sys,time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_loader import NativeModule
from hia_native_write_chain_build import expected_image, filename

CALL,WAIT,GROW,GROW_OUTPUT=0xffffffe0,0xffffffe1,0xffffffef,0xffffffee
INVALID,CAPACITY,STATE,CANCELED=0xffffffff,0xfffffffe,0xfffffff9,0xfffffff7
Q=lambda *values:struct.pack('<'+'Q'*len(values),*values)

def frame(magic,words,body=b''):
 return magic+Q(*words)+body

class Buffer:
 def __init__(self,size,fill=0,guard=0x5a):
  self.size=size;self.raw=ctypes.create_string_buffer(size+16);self.address=ctypes.addressof(self.raw);self.guard=guard
  ctypes.memset(self.address,fill,size);ctypes.memset(self.address+size,guard,16)
 def read(self,at,count):
  assert 0<=at<=self.size and 0<=count<=self.size-at
  return ctypes.string_at(self.address+at,count)
 def write(self,at,data):
  assert 0<=at<=self.size and len(data)<=self.size-at
  ctypes.memmove(self.address+at,data,len(data))
 def word(self,at):return struct.unpack('<Q',self.read(at,8))[0]
 def put(self,at,value):self.write(at,Q(value))
 def check(self):assert ctypes.string_at(self.address+self.size,16)==bytes([self.guard])*16
 def grow(self,size):
  new=Buffer(size,guard=self.guard);new.write(0,self.read(0,self.size));return new

class World:
 def __init__(self,modules,report):
  self.modules=modules;self.report=report;self.state=Buffer(65536);self.history=Buffer(65536);self.cache=Buffer(65536)
  self.invoke('file_lock_state',frame(b'HRFLOCK1',[0]*7),self.state)
  self.invoke('history',frame(b'HHISTQ01',[0]*7),self.history)
  self.invoke('view_cache',frame(b'HVCACH01',[0]*5),self.cache)
  self.events=[];self.io={};self.keys=[];self.key=b'local:/fixture';self.pending_action=None
 def invoke(self,name,wire,work=None):
  source=Buffer(len(wire),guard=0x7c);source.write(0,wire)
  output=Buffer(131072,fill=0xa5,guard=0xa5);work=work or Buffer(131072)
  before=work.read(0,work.size)
  code=self.modules[name]._entry(source.raw,len(wire),output.raw,output.size,work.raw,work.size)
  self.report['native_leaf_calls']+=1
  observe(self.report,name,wire,code,output,before,work)
  assert source.read(0,len(wire))==wire
  source.check();output.check();work.check()
  if code>=0xffff0000:return code,b''
  assert code<=output.size and output.read(code,output.size-code)==b'\xa5'*(output.size-code)
  return code,output.read(0,code)
 def key_result(self):
  key=self.keys.pop(0) if self.keys else self.key
  self.events.append(('canonical',key.hex()))
  return frame(b'HRLKY001',[1,len(key),0],key)
 def lock(self,wire):
  work=Buffer(max(131072,len(wire)+512));out=Buffer(64,fill=0xa5,guard=0xa5);source=Buffer(len(wire),guard=0x7c);source.write(0,wire)
  while True:
   before=work.read(0,work.size)
   code=self.modules['file_lock_service']._entry(source.raw,len(wire),out.raw,64,work.raw,work.size)
   self.report['native_leaf_calls']+=1;source.check();out.check();work.check();assert source.read(0,len(wire))==wire
   observe(self.report,'file_lock_service',wire,code,out,before,work)
   if code!=0xfffffff0:
    assert code==64,code
    return out.read(0,code)
   child,at,count,reply=work.word(80),work.word(88),work.word(96),work.word(104)
   if child==1:data=self.key_result()
   else:
    assert child==2
    c,data=self.invoke('file_lock_state',work.read(at,count),self.state);assert c==64
   work.write(reply,data);work.put(120,len(data));work.put(128,len(data));work.put(136,1)
 def child(self,child,wire):
  self.events.append(('child',child,struct.unpack_from('<Q',wire,8)[0]))
  if child==1:return self.lock(wire)
  if child==2:return self.key_result()
  if child==3:return self.invoke('history',wire,self.history)[1]
  if child==5:return self.invoke('view_cache',wire,self.cache)[1]
  self.report['synthetic_filesystem_completions']+=1
  if child==6:
   op=struct.unpack_from('<Q',wire,8)[0]
   if op==1:return frame(b'HFLRO001',[1,0,8],Q(self.io.get('exists',1)))
   assert op==2
   if self.io.get('read_cancel'):return CANCELED
   data=self.io.get('read_error',self.io.get('content',b'before'))
   return frame(b'HFLRO001',[2,int('read_error' in self.io),len(data)],data)
  assert child==4
  assert wire[:8]==b'HRAWI001'
  plen,n=struct.unpack_from('<QQ',wire,16)
  assert wire[64+plen:]==self.io.get('expected_undo',b'before') and n==len(wire)-64-plen
  if self.io.get('write_cancel'):return CANCELED
  if 'write_error' in self.io:
   data=self.io['write_error'];return frame(b'HRAWR001',[1,4,len(data)],data)
  return frame(b'HRAWR001',[0,0,0])
 def root(self,op=1,path=b'target',context=1,cancel=0):
  wire=frame(b'HFWRT001',[op,context,len(path),0,0,0,0],path)
  source=Buffer(len(wire),guard=0x7c);source.write(0,wire);output=Buffer(32,fill=0xa5,guard=0xa5);work=Buffer(4608);work.put(112,cancel)
  start=len(self.events)
  for step in range(100):
   before=work.read(0,work.size)
   code=self.modules['write_chain']._entry(source.raw,len(wire),output.raw,output.size,work.raw,work.size)
   self.report['native_controller_calls']+=1
   observe(self.report,'write_chain',wire,code,output,before,work)
   source.check();output.check();work.check();assert source.read(0,len(wire))==wire
   if code in (GROW,GROW_OUTPUT):
    n=work.word(120)
    if code==GROW:assert n>work.size;work=work.grow(n)
    else:assert n>output.size;output=Buffer(n,fill=0xa5,guard=0xa5)
    self.report['trusted_buffer_growths']+=1
    continue
   if code==WAIT:
    assert self.pending_action is not None
    action=self.pending_action;self.pending_action=None;action(work)
    work.put(328,1);continue
   if code==CALL:
    effect=struct.unpack('<16Q',work.read(256,128));assert effect[0]==int.from_bytes(b'HFWRCALL','little') and effect[7:]==(0,)*9
    child,at,count,reply=effect[2:6];request=work.read(at,count)
    data=self.child(child,request)
    if isinstance(data,int):work.put(312,data);work.put(320,0)
    else:
     if reply+len(data)>work.size:work=work.grow(reply+len(data));self.report['trusted_buffer_growths']+=1
     work.write(reply,data);work.put(312,len(data));work.put(320,len(data))
    work.put(328,1);continue
   assert work.word(40)==0 and work.word(48)==0,(code,self.events[start:])
   if code>=0xffff0000:
    assert output.read(0,output.size)==b'\xa5'*output.size
    return code,b'',self.events[start:]
   data=output.read(0,code)
   assert output.read(code,output.size-code)==b'\xa5'*(output.size-code)
   assert data[:8]==b'HFWTR001' and struct.unpack_from('<Q',data,8)[0]==op
   assert struct.unpack_from('<Q',data,24)[0]==len(data)-32
   self.report['completed_requests']+=1
   return code,data,self.events[start:]
  raise AssertionError('unbounded continuation')

def observe(report,name,wire,code,output,before,work):
 row=dict(module=name,input_hex=wire.hex(),code=code,output_capacity=output.size,
  output_hex=output.read(0,code).hex() if code<0xffff0000 else '',
  output_sha256=hashlib.sha256(output.read(0,output.size)).hexdigest(),
  workspace_before_hex=before.hex(),workspace_after_hex=work.read(0,work.size).hex())
 raw=json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n'
 report['_trace'].write(raw);report['_digest'].update(raw)
 report['trace_bytes']+=len(raw);report['trace_calls']+=1

def run(registry,destination):
 destination=Path(destination);destination.mkdir(parents=True)
 registry=Path(registry).resolve(strict=True);index=json.loads(registry.read_bytes());modules={}
 report={'schema':'hepta.runtime.local-write-controller-test.v1','status':'RUNNING','native_controller_calls':0,'native_leaf_calls':0,'synthetic_filesystem_completions':0,'trusted_buffer_growths':0,'completed_requests':0,'actual_filesystem_effects':0,'original_rust_execution':'PENDING','trace_calls':0,'trace_bytes':0,'loaded_modules':{},'registry_sha256':hashlib.sha256(registry.read_bytes()).hexdigest(),'test_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'loader_sha256':hashlib.sha256((ROOT/'scripts/hia_native_loader.py').read_bytes()).hexdigest()}
 report['_trace']=gzip.open(destination/'calls.jsonl.gz','xb',compresslevel=1);report['_digest']=hashlib.sha256()
 started=time.monotonic()
 try:
  for name in ('write_chain','file_lock_service','file_lock_state','history','view_cache'):
   path=Path(index[name]['manifest'])
   if not path.is_absolute():path=registry.parent/path
   meta=json.loads(path.read_bytes())
   assert meta['image_sha256']==expected_image(name,ROOT)==index[name]['image_sha256']
   assert meta['source_sha256']==hashlib.sha256((ROOT/filename(name)).read_bytes()).hexdigest()==index[name]['source_sha256']
   modules[name]=NativeModule(path,manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
   report['loaded_modules'][name]=dict(manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),source_sha256=meta['source_sha256'],image_sha256=meta['image_sha256'])
  w=World(modules,report);w.io['exists']=0
  assert w.root()[1]==frame(b'HFWTR001',[1,0,0])
  assert w.events==[('child',6,1)]
  for content in (b'',b'abc',b'\x00\r\n',b'\xf0\x9f\x99\x82'*1024,b'x'*10000):
   w=World(modules,report);w.io.update(content=content,expected_undo=content)
   assert w.root()[1]==frame(b'HFWTR001',[1,0,0])
   _,result,events=w.root(2,path=b'bad\xff')
   assert result[32:]==b'Successfully undid the last edit to bad\xef\xbf\xbd'
   assert [e[:2] for e in events if e[0]=='child']==[('child',1),('child',1),('child',2),('child',3),('child',4),('child',2),('child',5),('child',1),('child',1)]
   _,missing,events=w.root(2)
   assert missing[32:]==b'No more undo history for this file (up to 10 levels are stored per file).'
   assert not any(e[:2]==('child',4) for e in events)
  for which in ('read_error','write_error','read_cancel','write_cancel'):
   w=World(modules,report)
   if which.startswith('write'):assert w.root()[0]==32
   w.io[which]=b'exact original error' if which.endswith('error') else True
   code,data,events=w.root(2 if which.startswith('write') else 1)
   if which.endswith('cancel'):assert code==CANCELED
   else:assert data[32:]==b'exact original error' and struct.unpack_from('<Q',data,16)[0]==1
   if which.startswith('write'):
    assert w.root(2)[1][32:]==b'No more undo history for this file (up to 10 levels are stored per file).'
  w=World(modules,report)
  w.invoke('history',frame(b'HHISTQ01',[3,0,0,0,0,0,0]),w.history)
  assert w.root()[1][32:]==b'Failed to acquire lock on file history'
  assert w.root(2)[1][32:]==b'Failed to acquire lock on file history'
  w=World(modules,report);assert w.root()[0]==32
  held=w.lock(frame(b'HRLKSRV1',[1,0,1,6,0,0,0],b'target'))
  lease=struct.unpack_from('<Q',held,24)[0]
  assert struct.unpack_from('<Q',w.lock(frame(b'HRLKSRV1',[3,lease,0,0,0,0,0])),16)[0]==0
  w.pending_action=lambda work:work.put(112,1)
  assert w.root(2)[0]==CANCELED
  w.lock(frame(b'HRLKSRV1',[5,lease,0,0,0,0,0]));w.lock(frame(b'HRLKSRV1',[6,lease,0,0,0,0,0]))
  assert w.root(2)[1][32:]==b'Successfully undid the last edit to target'
  w=World(modules,report);assert w.root(cancel=1)[0]==CANCELED and not w.events
  report['status']='PASS'
 except BaseException as error:report.update(status='FAIL',failure=repr(error));raise
 finally:
  for m in modules.values():m.close()
  report.pop('_trace').close();report['trace_sha256']=report.pop('_digest').hexdigest()
  assert report['trace_calls']==report['native_controller_calls']+report['native_leaf_calls']
  report['trace_gzip_sha256']=hashlib.sha256((destination/'calls.jsonl.gz').read_bytes()).hexdigest()
  report['elapsed']=time.monotonic()-started
  (destination/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 return report

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--registry',required=True);p.add_argument('--output',required=True);a=p.parse_args()
 print(json.dumps(run(a.registry,a.output),sort_keys=True))
