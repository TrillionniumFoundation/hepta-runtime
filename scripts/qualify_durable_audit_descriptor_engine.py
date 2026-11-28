# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""QA only: unchanged full Rust comparisons through the actual syscall engine.

The Python code below transports captured private action frames and fixed HIA
child results. It makes no root, record, staging, retention or ordering decision.
The installed public gateway is a separate qualification domain.
"""
from pathlib import Path
from contextlib import ExitStack
import argparse,ctypes,errno,fcntl,hashlib,json,os,struct,subprocess,sys,time
import qualify_durable_audit_record_io as io_qa
import qualify_durable_audit_root as root_qa
import qualify_durable_audit_hot as hot_qa
from hia_native_loader import NativeModule
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
U=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
YIELD=0xffffffe0
ENGINE=None

class Engine:
 def __init__(self,path,*,expected_sha256):
  self.path=path;raw=path.read_bytes();self.sha256=SHA(raw)
  assert self.sha256==expected_sha256 and raw[:7]==b"\x7fELF\x02\x01\x01"
  assert struct.unpack_from("<HH",raw,16)==(3,62)
  shoff=U(raw,40);entsize,number,strings=struct.unpack_from("<HHH",raw,58)
  assert entsize==64 and 0<number<=128 and strings<number and shoff+number*64<=len(raw)
  sections=[struct.unpack_from("<IIQQQQIIQQ",raw,shoff+i*64)for i in range(number)]
  def content(index):
   section=sections[index];at,count=section[4:6];assert at+count<=len(raw)
   return raw[at:at+count]
  names=content(strings)
  def name(table,offset):
   assert offset<len(table);end=table.find(b"\0",offset);assert end>=offset
   return table[offset:end].decode("ascii")
  text_indices=[i for i,s in enumerate(sections)if name(names,s[0])==".text"]
  assert len(text_indices)==1
  text_index=text_indices[0];section=sections[text_index]
  assert section[1]==1 and section[2]==6
  self.flat=content(text_index);self.flat_sha256=SHA(self.flat);self.exports={}
  assert self.flat and all(s[5]==0 for s in sections if s[1]in(4,9))
  for index,section in enumerate(sections):
   if section[1]!=2:continue
   assert section[9]==24 and section[5]%24==0 and section[6]<number
   symbols=content(index);strings_table=content(section[6])
   for at in range(0,len(symbols),24):
    symbol,info,other,owner,value,size=struct.unpack_from("<IBBHQQ",symbols,at)
    label=name(strings_table,symbol)
    if label.startswith("durable_audit_descriptor_"):
     assert owner==text_index and label not in self.exports
     offset=value-sections[text_index][3];assert 0<=offset<len(self.flat)
     self.exports[label.removeprefix("durable_audit_descriptor_")]=offset
  assert set(self.exports)=={"create","step","child_ack","take","destroy"}
  self.descriptor=os.memfd_create("hia-audit-descriptor-engine",os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
  self.mapping=None;self.system=ctypes.CDLL(None,use_errno=True)
  self.system.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
  self.system.mmap.restype=ctypes.c_void_p
  self.system.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];self.system.munmap.restype=ctypes.c_int
  try:
   at=0
   while at<len(self.flat):
    written=os.write(self.descriptor,self.flat[at:]);assert written>0;at+=written
   fcntl.fcntl(self.descriptor,fcntl.F_ADD_SEALS,fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE)
   assert fcntl.fcntl(self.descriptor,fcntl.F_GET_SEALS)==15
   assert os.pread(self.descriptor,len(self.flat),0)==self.flat
   self.mapping=self.system.mmap(None,len(self.flat),5,2,self.descriptor,0)
   assert self.mapping not in(None,ctypes.c_void_p(-1).value),ctypes.get_errno()
   for method,args in (
    ("create",[ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_int64]),
    ("step",[ctypes.c_void_p]),
    ("child_ack",[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64]),
    ("take",[ctypes.c_void_p,ctypes.c_uint64]),
    ("destroy",[ctypes.c_void_p])):
    fn=ctypes.CFUNCTYPE(ctypes.c_int64,*args)(self.mapping+self.exports[method]);setattr(self,method,fn)
  except BaseException:
   if self.mapping not in(None,ctypes.c_void_p(-1).value):self.system.munmap(self.mapping,len(self.flat))
   os.close(self.descriptor);self.descriptor=None;raise
 def close(self):
  if self.descriptor is not None:
   assert self.system.munmap(self.mapping,len(self.flat))==0
   self.mapping=None;os.close(self.descriptor);self.descriptor=None
 def open(self,mode,session,capacity,borrowed):
  result=self.create(mode,ctypes.addressof(session._workspace),capacity,borrowed)
  assert result>0,("private descriptor context creation",result);return result
 def state(self,context):
  raw=ctypes.string_at(context,144)
  assert raw[:8]==b"HRAENG01"
  return dict(mode=U(raw,8),sequence=U(raw,32),pending=U(raw,40),owned_mask=U(raw,56),
              descriptors=list(struct.unpack_from("<6q",raw,64)),temporary=U(raw,120))
 def cleanup(self,context):
  # Synchronous QA child invocations have returned or were never started at
  # this point. Explicitly cancel only that known pending child, never replay
  # any kernel action. An unknown external effect has no such cleanup path.
  state=self.state(context)
  if state["pending"]==2:
   assert self.child_ack(context,0,errno.ECANCELED)==0
  result=self.destroy(context)
  if result!=0:
   error=RuntimeError("native descriptor cleanup returned "+str(result))
   active=sys.exception()
   if active is not None:active.add_note(str(error))
   else:raise error

def preseek(fd):
 chunk=ctypes.create_string_buffer(32768)
 while True:
  n=io_qa.LIBC.syscall(217,fd,ctypes.c_void_p(ctypes.addressof(chunk)),len(chunk))
  if n==0:return
  if n<0:raise OSError(ctypes.get_errno(),"original preseek")

def fds(context):
 state=ENGINE.state(context)
 return {i:fd for i,fd in enumerate(state["descriptors"])if fd>=0}

def effect(context,session,w,trace,child=None,mutate=None):
 action=struct.unpack_from("<12Q",w,256)
 magic,sequence,kind,slot,span,count,arg,capacity,ack,result,error,reserved=action
 assert ack==result==error==reserved==0
 row=dict(sequence=sequence,kind=kind,slot=slot,span=span,count=count,arg=arg,
          capacity=capacity,action_hex=w[256:352].hex())
 if kind in (1,4):row["name_hex"]=w[span:span+count].hex()
 if mutate:mutate(row,fds(context),session,w)
 result=ENGINE.step(context)
 assert result in (0,1),("private descriptor action refused",result,row,ENGINE.state(context))
 child_result=None
 if result==1:
  assert kind==100 and child is not None
  # step commits exactly one pending call. A second step is rejected before
  # any descriptor/child effect; these calls are observations, not retries.
  before=ctypes.string_at(context,144)
  assert ENGINE.step(context)==-errno.EBUSY
  assert ctypes.string_at(context,144)==before
  request=w[span:span+count]
  payload,child_result=child(request)
  assert type(payload)is bytes and len(payload)<=capacity
  ctypes.memmove(ctypes.addressof(session._workspace)+arg,payload,len(payload))
  assert ENGINE.child_ack(context,len(payload),0)==0
  if child_result is not None:row["child"]=child_result
  row["child_request_hex"]=request.hex()
  payload_at=arg;payload_len=len(payload)
 else:
  current=ctypes.string_at(ctypes.addressof(session._workspace)+256,96)
  payload_at=span;payload_len=0
  if U(current,80)==0:
   if kind==2:payload_len=88
   elif kind in (3,8):payload_len=U(current,72)
 current=ctypes.string_at(ctypes.addressof(session._workspace)+256,96)
 assert U(current,64)==sequence and U(current,88)==0
 payload=ctypes.string_at(ctypes.addressof(session._workspace)+payload_at,payload_len)
 row.update(result=U(current,72),errno=U(current,80),payload_hex=payload.hex())
 trace.append(row)

class EngineIO:
 def __init__(self,native,record):self.native=native;self.record=record
 def _frame(self,frame,root,*,mutate=None):
  trace=[]
  with self.native.session(output_capacity=4096,workspace_capacity=65536)as session:
   context=ENGINE.open(1,session,65536,root)
   try:
    while True:
     code,out,w=session.invoke_raw(frame)
     if code!=YIELD:
      if code>=0xffff0000:return dict(code=code,raw=out.hex(),trace=trace,owned_after=sorted(fds(context)))
      assert 192<=code<=512 and out[:8]==b"HRADIO01"and U(out,32)==code
      result=dict(diagnostic=U(out,8),errno=U(out,16),record=None,raw=out[:code].hex())
      count=U(out,24)
      if count:
       r=out[192:code];assert r[:8]==b"HRAJR001"and U(r,8)==0 and U(r,56)==count
       fields=[r[U(r,64+i*16):U(r,64+i*16)+U(r,72+i*16)].decode()for i in range(3)]
       result["record"]=dict(request_id=fields[0],owner=fields[1],tool_name=fields[2],
        state=("unknown","completed","failed")[U(r,16)],accepted_unix_ms=U(r,24)+(U(r,32)<<64),
        elapsed_ms=U(r,48)if U(r,40)else None)
      assert ENGINE.state(context)["owned_mask"]==0
      replay,out2,w2=session.invoke_raw(frame);assert replay==0xffffffff and out2==out and w2==w
      return dict(result,trace=trace,owned_after=[0],terminal_replay_refused=True)
     def child(request):
      return self.record.invoke(request,output_capacity=4096,workspace_capacity=16384),None
     effect(context,session,w,trace,child=child,mutate=mutate)
   finally:ENGINE.cleanup(context)
 def run(self,directory,operation,filename,*,preseek=False,mutate=None):
  frame=b"HRAIO001"+struct.pack("<QQQ",operation,len(filename),0)+filename
  root=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   if preseek:globals()["preseek"](root)
   return self._frame(frame,root,mutate=mutate)
  finally:os.close(root)

class EngineRoot:
 def __init__(self,native):self.native=native
 def retained(self,root_bytes,operation,*,mutate=None):
  frame=b"HRAROOT1"+struct.pack("<QQQ",operation,len(root_bytes),0)+root_bytes
  capacity=max(4096,len(frame)+1024);trace=[];retained=None
  with self.native.session(output_capacity=160,workspace_capacity=capacity)as session:
   context=ENGINE.open(0,session,capacity,-1)
   try:
    while True:
     code,out,w=session.invoke_raw(frame)
     if code!=YIELD:
      assert code==160 and out[:8]==b"HRAROOT1"and U(out,32)==160,(code,trace)
      exported=U(out,24)
      assert ENGINE.state(context)["owned_mask"]==((1<<exported)if exported else 0)
      metadata=list(struct.unpack_from("<11Q",out,64))if exported else None
      if exported:
       assert 1<=exported<=3
       st=os.fstat(fds(context)[exported]);actual=[st.st_mode,st.st_uid,os.geteuid(),st.st_nlink,st.st_size,
        st.st_dev,st.st_ino,st.st_mtime_ns//10**9,st.st_mtime_ns%10**9,st.st_ctime_ns//10**9,st.st_ctime_ns%10**9]
       assert metadata==actual
      replay,out2,w2=session.invoke_raw(frame);assert replay==0xffffffff and out2==out and w2==w
      if exported:
       retained=ENGINE.take(context,exported);assert retained>=0
       assert ENGINE.state(context)["owned_mask"]==0
      return dict(diagnostic=U(out,8),errno=U(out,16),present=bool(exported),metadata=metadata,
       raw=out[:code].hex(),trace=trace,owned_export=[exported]if exported else [],
       terminal_replay_refused=True),retained
     effect(context,session,w,trace,mutate=mutate)
   except BaseException:
    if retained is not None:os.close(retained)
    raise
   finally:ENGINE.cleanup(context)
 def run(self,root_bytes,operation,*,mutate=None):
  result,fd=self.retained(root_bytes,operation,mutate=mutate)
  try:return result
  finally:
   if fd is not None:os.close(fd)

class EngineHot:
 def __init__(self,native,io,record):self.native=native;self.io=EngineIO(io,record)
 def held(self,root,*,mutate=None):
  frame=b"HRAHOT01"+struct.pack("<QQ",512,0);trace=[]
  with self.native.session(output_capacity=131136,workspace_capacity=532480)as session:
   context=ENGINE.open(2,session,532480,root)
   try:
    while True:
     code,out,w=session.invoke_raw(frame)
     if code!=YIELD:
      assert 64<=code<=131136 and out[:8]==b"HRAHOTR1"and U(out,32)==code,(code,trace)
      count=U(out,24);assert code==64+count*256 and ENGINE.state(context)["owned_mask"]==0
      records=[]
      for i in range(count):
       r=out[64+i*256:64+(i+1)*256];tool_len=U(r,192)
       assert 1<=tool_len<=64 and not any(r[128+tool_len:192])and U(r,240)==U(r,248)==0
       records.append(dict(request_id=r[:64].decode(),owner=r[64:128].decode(),tool_name=r[128:128+tool_len].decode(),
        state=("unknown","completed","failed")[U(r,200)],accepted_unix_ms=U(r,208)+(U(r,216)<<64),
        elapsed_ms=U(r,232)if U(r,224)else None))
      replay,out2,w2=session.invoke_raw(frame);assert replay==0xffffffff and out2==out and w2==w
      return dict(diagnostic=U(out,8),errno=U(out,16),records=records,raw=out[:code].hex(),
       trace=trace,owned_after=[0],terminal_replay_refused=True)
     def child(request):
      assert request[:8]==b"HRAIO001"and U(request,16)==len(request)-32 and U(request,24)==0
      result=self.io._frame(request,root);assert "code"not in result
      return bytes.fromhex(result["raw"]),result
     effect(context,session,w,trace,child=child,mutate=mutate)
   finally:ENGINE.cleanup(context)
 def run(self,directory,*,preseek=False,mutate=None):
  root=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   if preseek:globals()["preseek"](root)
   return self.held(root,mutate=mutate)
  finally:os.close(root)

def main():
 global ENGINE
 p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--build",type=Path,required=True)
 p.add_argument("--original-directory",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
 q=a.output;q.mkdir(parents=True,exist_ok=False)
 manifests={
  "root":a.build/"modules/durable-audit-root-v1/manifest.json",
  "io":a.build/"modules/durable-audit-record-io-v2/manifest.json",
  "hot":a.build/"modules/durable-audit-hot-v1/manifest.json",
  "record":a.build/"modules/durable-audit-record/manifest.json"}
 originals={k:a.original_directory/("hia-durable-audit-"+v+"-original")for k,v in (("root","root"),("io","record-io"),("hot","hot"))}
 bound=[Path(__file__),Path(io_qa.__file__),Path(root_qa.__file__),Path(hot_qa.__file__),
        a.source/"scripts/durable_audit_descriptor_engine.S",a.source/"scripts/hia_native_loader.py",
        *manifests.values(),*originals.values()]
 for path in manifests.values():
  value=json.loads(path.read_bytes());bound.extend(path.parent/value[k]for k in("source","image"))
 before={str(p):SHA(p.read_bytes())for p in bound};start=time.monotonic()
 commands=[
  ["/usr/bin/as","--64","-o",str(q/"engine.o"),str(a.source/"scripts/durable_audit_descriptor_engine.S")],
  ["/usr/bin/ld","-shared","-z","noexecstack","-z","relro","-z","now","-o",str(q/"engine.so"),str(q/"engine.o")],
  ["/usr/bin/readelf","-h","-l","-d","-r","-W",str(q/"engine.so")]]
 for index,argv in enumerate(commands):
  r=subprocess.run(argv,capture_output=True,timeout=30,env={**os.environ,"LANG":"C","LC_ALL":"C"})
  (q/f"build-{index}.stdout").write_bytes(r.stdout);(q/f"build-{index}.stderr").write_bytes(r.stderr)
  assert r.returncode==0,(argv,r.stderr.decode())
 assert b"NEEDED"not in r.stdout and b"There are no relocations in this file."in r.stdout
 ENGINE=Engine(q/"engine.so",expected_sha256=SHA((q/"engine.so").read_bytes()))
 original_classes=(io_qa.Broker,root_qa.RootBroker,hot_qa.HotBroker)
 old_argv=sys.argv
 try:
  io_qa.Broker=EngineIO;root_qa.RootBroker=EngineRoot;hot_qa.HotBroker=EngineHot
  calls=[
   (io_qa,["--manifest",str(manifests["io"]),"--record-manifest",str(manifests["record"]),"--original",str(originals["io"]),"--output",str(q/"io")]),
   (root_qa,["--manifest",str(manifests["root"]),"--original",str(originals["root"]),"--output",str(q/"root")]),
   (hot_qa,["--manifest",str(manifests["hot"]),"--io-manifest",str(manifests["io"]),"--record-manifest",str(manifests["record"]),
            "--original",str(originals["hot"]),"--output",str(q/"hot")])]
  for module,args in calls:
   sys.argv=[module.__file__,*args];module.main()
 finally:
  sys.argv=old_argv;io_qa.Broker,root_qa.RootBroker,hot_qa.HotBroker=original_classes
 reports={key:json.loads((q/key/"report.json").read_bytes())for key in("io","root","hot")}
 assert {key:r["cases"]for key,r in reports.items()}==dict(io=63,root=92,hot=40)
 assert all(r["state"]=="PASS"and r["source_unchanged"]is True for r in reports.values())
 after={str(p):SHA(p.read_bytes())for p in bound};assert before==after
 assert SHA((q/"engine.so").read_bytes())==ENGINE.sha256
 result=dict(schema="hepta.runtime.audit-native-descriptor-engine.v1",state="PASS",cases=195,
  groups={key:dict(cases=r["cases"],elapsed_seconds=r["elapsed_seconds"])for key,r in reports.items()},
  engine_source_sha256=before[str(a.source/"scripts/durable_audit_descriptor_engine.S")],
  engine_elf_sha256=ENGINE.sha256,engine_flat_sha256=ENGINE.flat_sha256,engine_exports=ENGINE.exports,executed_sealed_engine=True,source_before=before,source_after=after,
  source_unchanged=True,original_whole_methods_unchanged=True,mechanical_kernel_effects_native=True,
  public_routing_qualified=False,elapsed_seconds=time.monotonic()-start)
 (q/"report.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n");print(json.dumps(result,sort_keys=True))
 ENGINE.close()
if __name__=="__main__":main()
