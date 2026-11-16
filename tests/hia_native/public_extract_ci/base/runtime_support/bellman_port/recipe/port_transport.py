"""Owned native export transport; records complete private buffers and journals."""
import ctypes,hashlib,json,mmap,os,pathlib,signal,struct,time

INVALID=0xffffffff
BUSY=0xfffffff8
CAPACITY=0xfffffffe
WORKER_MAGICS={b'HBWPL001',b'HBCLOCK1',b'HBPWHLD1',b'HBWPEND1',b'HBWPROC1'}
PORT_MAGICS={b'HBPWIN01',b'HBPMSR01',b'HBPAC001',b'HBPAA001'}
_LIVE_FAILURES=[]
def sha(b):return hashlib.sha256(b).hexdigest()
def get(b,o):return struct.unpack_from('<Q',b,o)[0]
def pack(m,*w):return m+struct.pack('<'+'Q'*len(w),*w)
def put(p,x):p.write_bytes(x if isinstance(x,bytes) else (json.dumps(x,sort_keys=True,indent=2)+'\n').encode())

def journal_records(path,*,complete=False):
 size=path.stat().st_size;at=0
 with path.open('rb') as stream:
  while at<size:
   prefix=stream.read(16)
   if len(prefix)<16:
    assert not complete,('partial journal header',at);break
   magic=prefix[:8];extent=get(prefix,8)
   assert magic in WORKER_MAGICS|PORT_MAGICS and 16<=extent<=128<<20,(magic,extent)
   tail=stream.read(extent-16)
   if len(tail)!=extent-16:
    assert not complete,('partial journal body',at,extent);break
   if magic==b'HBWPL001':assert extent==256
   if magic==b'HBCLOCK1':assert extent==192
   if magic in {b'HBPWHLD1',b'HBWPROC1'}:assert extent==64
   if magic in {b'HBPAC001',b'HBPAA001'}:assert extent==144
   yield at,magic,prefix+tail;at+=extent
  if complete:assert at==size and stream.read(1)==b''

class Port:
 def __init__(self,build,output):
  self.output=output;output.mkdir();self.blobs=output/'blobs';self.blobs.mkdir()
  self.log=(output/'calls.jsonl').open('x');self.journal=(output/'journal.bin').open('xb',buffering=0)
  self.component=json.loads((build/'component.json').read_bytes());self.pack_receipt=json.loads((build/'pack.receipt.json').read_bytes())
  raw=(build/'bellman-port-packed.elf').read_bytes();assert sha(raw)==self.component['executable_sha256']==self.pack_receipt['executable_sha256']
  assert self.pack_receipt['status']=='ACTUAL_HIA_PORT_PACK_PASS' and self.pack_receipt['code']==len(raw)
  self.mapping=mmap.mmap(-1,len(raw),prot=mmap.PROT_READ|mmap.PROT_WRITE);self.mapping.write(raw)
  address=ctypes.addressof(ctypes.c_char.from_buffer(self.mapping));libc=ctypes.CDLL(None,use_errno=True)
  libc.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];assert libc.mprotect(address,len(raw),5)==0
  counts={'create':1,'attach':2,'invoke':3,'service':1,'wake_fd':1,'ready_receive':3,'ready_release':2,'detach':2,'shutdown':1,'destroy':1}
  self.fn={k:ctypes.CFUNCTYPE(ctypes.c_uint64,*([ctypes.c_uint64]*n))(address+self.component['exports'][k]) for k,n in counts.items()}
  self.ctx=0;self.engines=[];self.events=[];self.stopped=set();self.calls=0;self.started=time.monotonic_ns()
  self.emit({'phase':'identity','pid':os.getpid(),'pgid':os.getpgid(0),'parent_pid':os.getppid(),'component':self.blob((build/'component.json').read_bytes()),'pack_receipt':self.blob((build/'pack.receipt.json').read_bytes()),'executable_sha256':sha(raw)})
 def blob(self,b):
  digest=sha(b);p=self.blobs/digest
  if not p.exists():p.write_bytes(b)
  return {'bytes':len(b),'sha256':digest}
 def emit(self,row):self.log.write(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n');self.log.flush()
 def snapshot(self):
  if not self.ctx:return {'context':None,'engines':[self.blob(e.raw) for e in self.engines],'rows':[],'ready':[]}
  data=ctypes.string_at(self.ctx,4096);result={'context':self.blob(data),'engines':[self.blob(e.raw) for e in self.engines],'rows':[],'ready':[]}
  ptr=get(data,48);seen=set()
  while ptr:
   assert ptr not in seen and len(seen)<100;seen.add(ptr);r=ctypes.string_at(ptr,4096);row={'address':ptr,'state':self.blob(r),'buffers':{}}
   for offset in [48,72,88,120,136,152,168]:
    pointer,size=get(r,offset),get(r,offset+8);assert size<=256<<20 and bool(pointer)==bool(size)
    row['buffers'][str(offset)]=self.blob(ctypes.string_at(pointer,size)) if pointer else None
   result['rows'].append(row);ptr=get(r,8)
  ptr=get(data,64);seen=set()
  while ptr:
   assert ptr not in seen and len(seen)<100;seen.add(ptr);r=ctypes.string_at(ptr,4096);result['ready'].append({'address':ptr,'state':self.blob(r)});ptr=get(r,0)
  return result
 def call(self,name,args,*,label=None):
  index=self.calls;self.calls+=1;before=self.snapshot()
  self.emit({'phase':'begin','call':index,'name':name,'arguments':args,'label':label,'before':before,'journal_bytes':self.journal.tell()})
  r=self.fn[name](*args)
  if name=='create' and r>0xffffffff:self.ctx=r
  if name=='destroy' and r==0:self.ctx=0
  after=self.snapshot();self.emit({'phase':'end','call':index,'name':name,'return':r,'after':after,'journal_bytes':self.journal.tell()});return r
 def create(self):assert self.call('create',[self.journal.fileno()])>0xffffffff
 def engine(self):
  e=ctypes.create_string_buffer(16384);struct.pack_into('<Q',e,8,ctypes.addressof(e)+8192);e[40:48]=b'HRGENG02';self.engines.append(e)
  self.emit({'phase':'engine','index':len(self.engines)-1,'address':ctypes.addressof(e),'before':self.blob(e.raw)})
  assert self.call('attach',[self.ctx,ctypes.addressof(e)])==0;return e
 def invoke(self,e,wire,*,label=None):
  source=ctypes.create_string_buffer(wire+b'\xd6'*8,len(wire)+8);before=source.raw;index=self.calls
  r=self.call('invoke',[ctypes.addressof(e),ctypes.addressof(source),len(wire)],label=label)
  assert source.raw==before
  d=e.raw[8192+57*64:8192+58*64];data=b''
  if r in (32,64):
   assert get(d,48)==r;pointer,capacity,size=get(d,32),get(d,40),get(d,56);assert size<=capacity<=64<<20
   data=ctypes.string_at(pointer,size)
  self.emit({'phase':'wire','call':index,'engine':self.engines.index(e),'input':self.blob(wire),'input_full_before':self.blob(before),'input_full_after':self.blob(source.raw),'output':self.blob(data),'descriptor':self.blob(d),'code':r})
  return r,data
 def allocate(self,e):
  r,d=self.invoke(e,pack(b'HBLTAG01',1,0,0,0,0,0,0),label='allocate');assert r==32 and d[:8]==b'HBLTGR01' and d[16:]==bytes(16);return get(d,8)
 def retire(self,e,tag,expected=32):
  r,d=self.invoke(e,pack(b'HBLRET01',1,tag,0,0,0,0,0),label='retire');assert r==expected
  if r==32:assert d==pack(b'HBLRTR01',tag,0,0)
  return r
 def command(self,e,op,tag,payload=b'',*,expected=64,label=None):
  r,d=self.invoke(e,pack(b'HBLCLQ01',op,tag,len(payload),0,0,0,0)+payload,label=label);assert r==expected,(label,r,expected)
  if r==64:assert d[:8]==b'HBLCLR01' and get(d,16)==tag and len(d)==64+get(d,32) and d[40:64]==bytes(24)
  return d
 def receive(self,capacity=32,*,expected=None):
  out=ctypes.create_string_buffer(bytes([0xa5])*40,40);index=self.calls
  r=self.call('ready_receive',[self.ctx,ctypes.addressof(out),capacity]);event=b'';token=0
  if expected is not None:assert r==expected,(r,expected)
  if r==32:
   assert out.raw[:8]==b'HBRPBR01' and out.raw[32:]==bytes([0xa5])*8
   ptr,size,token=struct.unpack_from('<3Q',out.raw,8);event=ctypes.string_at(ptr,size);assert size==192 and event[:8]==b'HBPMSR01' and get(event,16)==2
   self.events.append(event)
  else:assert out.raw==bytes([0xa5])*40
  self.emit({'phase':'ready','call':index,'capacity':capacity,'code':r,'before':self.blob(bytes([0xa5])*40),'after':self.blob(out.raw),'event':self.blob(event),'token':token})
  return r,event,token
 def release(self,token,expected=0):assert self.call('ready_release',[self.ctx,token])==expected
 def service(self):
  r=self.call('service',[self.ctx]);assert r in (0,1);return r
 def wait_ready(self,job,*,borrow=False):
  deadline=time.monotonic()+30
  while time.monotonic()<deadline:
   self.service()
   while True:
    r,event,token=self.receive()
    if not r:break
    if get(event,32)==job and borrow:return event,token
    self.release(token)
    if get(event,32)==job:return event,None
   time.sleep(.001)
  raise AssertionError(('actual READY deadline',job))
 def stop_after_clock(self,job):
  deadline=time.monotonic()+10;pid=None;clock=False
  while time.monotonic()<deadline:
   for _,magic,row in journal_records(self.output/'journal.bin'):
    if magic==b'HBWPROC1' and get(row,24)==job and get(row,40)==1:pid=get(row,32)
    if magic==b'HBCLOCK1' and get(row,16)==job:clock=True
    assert not (magic==b'HBWPL001' and get(row,24)==5 and get(row,48)==job),('completed before stop',job)
   if pid and clock:break
   time.sleep(.001)
  assert pid and clock and os.getpgid(pid)==os.getpgid(0)
  self.stopped.add(pid);os.kill(pid,signal.SIGSTOP)
  while time.monotonic()<deadline:
   raw=(pathlib.Path('/proc')/str(pid)/'status').read_bytes()
   if any(line.startswith(b'State:') and b'T' in line for line in raw.splitlines()):
    for _,magic,row in journal_records(self.output/'journal.bin'):
     assert not (magic==b'HBWPL001' and get(row,24)==5 and get(row,48)==job),('completed while stopping',job)
    result={'job':job,'pid':pid,'pgid':os.getpgid(pid),'signal':int(signal.SIGSTOP),'actual_status':self.blob(raw),'first_clock_observed':True}
    self.emit({'phase':'stop',**result});return pid,result
   time.sleep(.001)
  raise AssertionError(('stop not observed',job))
 def resume(self,pid):
  assert pid in self.stopped;os.kill(pid,signal.SIGCONT);self.stopped.remove(pid);self.emit({'phase':'resume','pid':pid,'signal':int(signal.SIGCONT)})
 def last_control(self):
  result=None
  for _,magic,row in journal_records(self.output/'journal.bin'):
   if magic==b'HBPMSR01' and get(row,16)==1:result=row
  assert result is not None;return result
 def close(self):
  for pid in list(self.stopped):
   try:os.kill(pid,signal.SIGCONT)
   except ProcessLookupError:pass
   finally:self.stopped.discard(pid)
  self.log.close()
  if self.ctx:
   # A failed assertion cannot unmap code still used by an admitted worker.
   # The owned supervisor kills and waits its entire process group on failure.
   _LIVE_FAILURES.append(self);return
  self.journal.close();self.fn.clear();self.mapping.close()
