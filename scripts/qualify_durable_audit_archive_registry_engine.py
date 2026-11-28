# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual shared HIA registry through its sealed native mutex/storage capability."""
from pathlib import Path
import argparse,ctypes,errno,fcntl,hashlib,json,os,stat,struct,threading,time,types
SELF=Path(__file__).resolve(strict=True);EXECUTED=SELF.read_bytes();SHA=lambda v:hashlib.sha256(v).hexdigest()
OWN=("scripts/qualify_durable_audit_archive_registry_engine.py","scripts/durable_audit_archive_registry_engine.S",
"scripts/durable_audit_archive_registry_code.json","scripts/author_durable_audit_archive_registry_packer.py",
"scripts/durable_audit_archive_registry_packer_source.py.txt","native/durable_audit_archive_registry_packer.hepta",
"native/durable_audit_archive_registry_packer_composition.json","scripts/author_durable_audit_archive_registry.py",
"scripts/durable_audit_archive_registry_source.py.txt","native/durable_audit_archive_registry.hepta",
"native/durable_audit_archive_registry_composition.json","scripts/author_durable_common.py",
"native/durable_audit_record_io.hepta","scripts/hia_native_build.py","scripts/hia_native_loader.py")
U=lambda b,n:struct.unpack_from("<Q",b,n)[0]
def wire(op,key=(0,0,0,0),token=0,argument=0):
 return b"HRAARQ01"+struct.pack("<11Q",op,*key,token,argument,0,0,0,0)
def response(raw):
 assert len(raw)==112 and raw[:8]==b"HRAARR01"and raw[96:]==bytes(16),raw.hex()
 return dict(zip(("status","token","refs","created","destroyed","needed","live","weak","pending","poisoned","serial"),struct.unpack_from("<11Q",raw,8)))
def bound(path):
 a=path.lstat();assert stat.S_ISREG(a.st_mode)and not path.is_symlink()
 with path.open("rb")as f:x=os.fstat(f.fileno());raw=f.read();y=os.fstat(f.fileno())
 z=path.lstat();sig=lambda t:[t.st_dev,t.st_ino,t.st_mode,t.st_uid,t.st_gid,t.st_nlink,t.st_size,t.st_mtime_ns,t.st_ctime_ns]
 assert sig(a)==sig(x)==sig(y)==sig(z)
 return dict(bytes=len(raw),sha256=SHA(raw),physical=sig(a))
class Engine:
 def __init__(self,raw,record):
  assert raw[:8]==b"HRARPK01"and len(raw)==U(raw,8)==64+U(raw,16)
  self.flat=raw[64:];assert SHA(self.flat)==record["flat_sha256"]and len(self.flat)==record["flat_bytes"]
  self.exports=dict(zip(("create","apply","sequence","wait","destroy"),struct.unpack_from("<5Q",raw,24)));assert self.exports==record["exports"]
  self.fd=os.memfd_create("hia-audit-archive-registry-capability",os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
  self.libc=ctypes.CDLL(None,use_errno=True)
  self.libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long];self.libc.mmap.restype=ctypes.c_void_p
  self.libc.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];self.libc.munmap.restype=ctypes.c_int
  self.address=None
  try:
   at=0
   while at<len(self.flat):
    n=os.write(self.fd,self.flat[at:]);assert n>0;at+=n
   fcntl.fcntl(self.fd,fcntl.F_ADD_SEALS,15);assert fcntl.fcntl(self.fd,fcntl.F_GET_SEALS)==15
   assert os.pread(self.fd,len(self.flat),0)==self.flat
   self.address=self.libc.mmap(None,len(self.flat),5,2,self.fd,0);assert self.address not in(None,ctypes.c_void_p(-1).value)
   P=ctypes.c_void_p;Q=ctypes.c_uint64
   for name,args in[("create",[P,Q]),("apply",[P,P,Q,P,Q]),("sequence",[P]),("wait",[P,Q,Q]),("destroy",[P])]:
    setattr(self,name,ctypes.CFUNCTYPE(ctypes.c_int64,*args)(self.address+self.exports[name]))
  except BaseException:
   self.close();raise
 def close(self):
  if self.fd is not None:
   assert os.pread(self.fd,len(self.flat),0)==self.flat and fcntl.fcntl(self.fd,fcntl.F_GET_SEALS)==15
   if self.address not in(None,ctypes.c_void_p(-1).value):assert self.libc.munmap(self.address,len(self.flat))==0
   os.close(self.fd);self.fd=None
 def __enter__(self):return self
 def __exit__(self,*args):self.close()
def main():
 p=argparse.ArgumentParser()
 for n in("source","policy","packer","output"):p.add_argument("--"+n,type=Path,required=True)
 a=p.parse_args();s=a.source.resolve(strict=True);q=a.output;q.mkdir(parents=True,exist_ok=False)
 assert(s/OWN[0]).read_bytes()==EXECUTED
 paths={n:s/n for n in OWN}
 for label,path in[("policy",a.policy),("packer",a.packer)]:
  m=json.loads(path.read_bytes());paths[label+"/manifest"]=path
  for n in("source","image"):assert Path(m[n]).name==m[n];paths[label+"/"+n]=path.parent/m[n]
 before={n:bound(path)for n,path in paths.items()}
 (q/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
 raw=(s/"scripts/hia_native_loader.py").read_bytes();loader=types.ModuleType("_captured_registry_engine_loader");loader.__file__=str(s/"scripts/hia_native_loader.py");exec(compile(raw,loader.__file__,"exec"),loader.__dict__)
 record=json.loads((s/"scripts/durable_audit_archive_registry_code.json").read_bytes())
 assert record["source_sha256"]==before["scripts/durable_audit_archive_registry_engine.S"]["sha256"]
 controls=[];calls=[];record_lock=threading.Lock();start=time.monotonic();passed=False
 def check(name,condition,**extra):
  assert condition,(name,extra);controls.append(dict(name=name,passed=True,**extra))
 try:
  with loader.NativeModule(a.policy,manifest_sha256=before["policy/manifest"]["sha256"])as policy,loader.NativeModule(a.packer,manifest_sha256=before["packer/manifest"]["sha256"])as packer:
   request=b"HRARPQ01"+struct.pack("<QQ",1,0)
   size=64+record["flat_bytes"]
   raw=packer.invoke(request,output_capacity=size,workspace_capacity=4096)
   expected=b"HRARPK01"+struct.pack("<7Q",size,record["flat_bytes"],*(record["exports"][n]for n in("create","apply","sequence","wait","destroy")))+bytes.fromhex(record["flat_hex"])
   check("actual HIA emitter matches independently extracted complete code",raw==expected,bytes=len(raw),sha256=SHA(raw));(q/"actual-capability.bin").write_bytes(raw)
   for label,value in[("empty",b""),("short",request[:-1]),("tail",request+b"\0"),("magic",b"X"+request[1:]),("version",request[:8]+struct.pack("<QQ",2,0)),("reserved",request[:16]+struct.pack("<Q",1))]:
    code,out,work=packer.invoke_raw(value,output_capacity=size,workspace_capacity=4096,output_fill=0xa7,workspace_fill=0x39)
    check("packer rejects "+label,code==0xffffffff and out==bytes([0xa7])*size and work==bytes([0x39])*4096)
   code,out,work=packer.invoke_raw(request,output_capacity=size-1,workspace_capacity=4096,output_fill=0xa7,workspace_fill=0x39)
   check("packer refuses short output without partial writes",code==0xfffffffe and out==bytes([0xa7])*(size-1)and work==bytes([0x39])*4096)
   with Engine(raw,record)as engine:
    contexts=set()
    def create(cap=128):
     c=engine.create(policy._address,cap);assert c>0;contexts.add(c);return c
    def call(c,label,value,expected_code=112):
     source=ctypes.create_string_buffer(value+b"\xC3"*16);output=ctypes.create_string_buffer(b"\xA7"*112+b"\xD2"*16)
     started=time.monotonic_ns();code=engine.apply(c,source,len(value),output,112);ended=time.monotonic_ns()
     assert source.raw==value+b"\xC3"*16+b"\0"and output.raw[112:128]==b"\xD2"*16
     out=output.raw[:112]
     with record_lock:calls.append(dict(label=label,thread=threading.get_native_id(),started_ns=started,ended_ns=ended,return_code=code,input_hex=value.hex(),output_hex=out.hex()))
     assert code==expected_code,(label,code,expected_code,out.hex())
     return response(out)if code==112 else dict(code=code)
    def finish(c,t,accepted=True):return call(c,"finish",wire(2,token=t,argument=int(accepted)))
    def drop(c,t):return call(c,"drop",wire(4,token=t))
    def destroy(c):
     assert engine.destroy(c)==0;contexts.remove(c)
    c=create()
    check("new shared capability owns initialized HIA state",call(c,"initial",wire(5))["live"]==0)
    first=call(c,"new",wire(1,key=(1,2,3,4)));token=first["token"]
    check("native storage grows under the same mutex before reserving identity",first["created"]==1 and first["pending"]==token and first["refs"]==1)
    check("unfinished reservation prevents context destruction",engine.destroy(c)==-errno.EBUSY)
    blocked=call(c,"blocked",wire(1,key=(5,6,7,8)));check("a second open observes the original pending owner",blocked["status"]==1)
    generation=engine.sequence(c);assert generation>=0
    entered=threading.Event();waits=[];waiter_ids=[]
    def waiting():
     waiter_ids.append(threading.get_native_id());entered.set();waits.append(engine.wait(c,generation,2_000_000_000))
    thread=threading.Thread(target=waiting);thread.start();assert entered.wait(2)
    until=time.monotonic()+2;actual_wait=None
    while time.monotonic()<until and thread.is_alive():
     observation=(Path("/proc/self/task")/str(waiter_ids[0])/"syscall").read_text().split()
     if len(observation)>=3 and observation[0]=="202" and int(observation[1],16)==c+28 and int(observation[2],16)==128:
      actual_wait=observation;break
    assert actual_wait is not None,("waiter did not reach the actual native futex",waits)
    finish(c,token);thread.join(3);assert not thread.is_alive()
    check("real blocked futex waiter observes completion without a lost wake",waits==[0]and engine.sequence(c)!=generation,actual_kernel_wait=actual_wait)
    check("late waiter returns EAGAIN for the already advanced generation",engine.wait(c,generation,1_000_000)==-errno.EAGAIN)
    now=engine.sequence(c);check("bounded empty wake wait returns its real timeout",engine.wait(c,now,1_000_000)==-errno.ETIMEDOUT)
    check("invalid wait generation is refused",engine.wait(c,2**32,1_000_000)==-errno.EINVAL)
    check("live strong owner prevents destroy",engine.destroy(c)==-errno.EBUSY)
    count=32;start_barrier=threading.Barrier(count+1);cloned_barrier=threading.Barrier(count+1);release=threading.Event();errors=[]
    def clone_worker(index):
     try:
      start_barrier.wait(timeout=5)
      row=call(c,"thread-clone-"+str(index),wire(3,token=token));assert row["status"]==0
      cloned_barrier.wait(timeout=5)
      assert release.wait(5);row=drop(c,token);assert row["destroyed"]==0
     except BaseException as e:
      with record_lock:errors.append(repr(e))
      start_barrier.abort();cloned_barrier.abort()
    workers=[threading.Thread(target=clone_worker,args=(i,))for i in range(count)]
    for t in workers:t.start()
    try:
     start_barrier.wait(timeout=5);cloned_barrier.wait(timeout=5)
     row=call(c,"all-thread-clones-held",wire(5,token=token))
     check("32 actual OS threads retain the same HIA owner",row["refs"]==33 and row["live"]==1 and row["weak"]==1)
    finally:
     release.set()
     for t in workers:t.join(5)
    check("actual concurrent drops preserve the original holder",not errors and all(not t.is_alive()for t in workers)and call(c,"after-thread-drops",wire(5,token=token))["refs"]==1,errors=errors,actual_threads=32)
    check("last actual strong drop returns one retirement",drop(c,token)["destroyed"]==1)
    check("dead weak record does not own runtime storage",call(c,"dead-only",wire(5))["live"]==0)
    destroy(c)
    c=create(128);tokens=[]
    for i in range(260):
     row=call(c,"grow-open-"+str(i),wire(1,key=(7,i+1,9,i+1001)));assert row["status"]==0
     tokens.append(row["token"]);finish(c,row["token"])
    row=call(c,"grown-state",wire(5));header=ctypes.string_at(c,304)
    check("native mmap growth supports 260 simultaneous identities",row["live"]==260 and row["weak"]==260 and U(header,40)>=128+260*64,workspace_bytes=U(header,40))
    for t in tokens:drop(c,t)
    row=call(c,"all-dead",wire(5));check("260 last drops leave only non-owning weak entries",row["live"]==0 and row["weak"]==260)
    new=call(c,"prune",wire(1,key=(101,102,103,104)));check("next begin prunes all expired entries",new["weak"]==1 and new["created"]==1 and new["serial"]==261)
    finish(c,new["token"],False);check("failed first open can retire its sole physical-owner reservation",call(c,"failed-open-state",wire(5))["live"]==0);destroy(c)
    c=create();one=call(c,"poison-new",wire(1,key=(201,202,203,204)));finish(c,one["token"])
    call(c,"poison",wire(6));row=call(c,"poison-refusal",wire(1,key=(301,302,303,304)))
    check("mutex poison classification remains actual HIA authority",row["status"]==2 and row["live"]==1)
    drop(c,one["token"]);destroy(c)
    for cap in(0,1,64,127,129,2**63):
     check("bad initial storage "+str(cap),engine.create(policy._address,cap)==-errno.EINVAL)
    check("missing actual HIA entry is refused",engine.create(0,128)==-errno.EINVAL)
    c=create();before_state=call(c,"before-negative",wire(5))
    call(c,"bad-native-wire-length",wire(5)[:-1],-errno.EINVAL)
    call(c,"unknown-HIA-op",wire(7),0xffffffff)
    src=ctypes.create_string_buffer(wire(5));out=ctypes.create_string_buffer(112)
    check("output capacity checked before native mutation",engine.apply(c,src,96,out,111)==-errno.EINVAL)
    check("owned context cannot be used as caller input",engine.apply(c,c+64,96,out,112)==-errno.EINVAL)
    check("owned context cannot be used as caller output",engine.apply(c,src,96,c+160,112)==-errno.EINVAL)
    work=U(ctypes.string_at(c,48),32)
    check("mutable policy workspace cannot alias input",engine.apply(c,work,96,out,112)==-errno.EINVAL)
    check("mutable policy workspace cannot alias output",engine.apply(c,src,96,work,112)==-errno.EINVAL)
    check("mechanical rejections preserve actual HIA state",call(c,"after-negative",wire(5))==before_state)
    child=os.fork()
    if child==0:os._exit(0 if engine.sequence(c)==-errno.EINVAL else 43)
    waited,status=os.waitpid(child,0);check("forked process cannot reuse the original runtime capability",waited==child and os.WIFEXITED(status)and os.WEXITSTATUS(status)==0)
    destroy(c);check("all owned registry contexts retired after actual users ended",not contexts)
   passed=True
 finally:
  (q/"calls.jsonl").write_text("".join(json.dumps(v,sort_keys=True)+"\n"for v in calls))
  after={n:bound(path)for n,path in paths.items()};same=before==after
  (q/"source-after.json").write_text(json.dumps(after,sort_keys=True,indent=2)+"\n")
  result=dict(schema="hepta.runtime.durable-archive-registry-native-engine-controls.v1",passed=passed and same,source_unchanged=same,
   elapsed_seconds=time.monotonic()-start,control_count=len(controls),controls=controls,native_calls=len(calls),
   real_os_mutex_and_storage=True,actual_physical_archive_owner_qualified=False,default_public_router_qualified=False)
  (q/"report.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
  print(json.dumps({k:result[k]for k in("passed","source_unchanged","elapsed_seconds","control_count","native_calls")}),flush=True);assert same
if __name__=="__main__":main()
