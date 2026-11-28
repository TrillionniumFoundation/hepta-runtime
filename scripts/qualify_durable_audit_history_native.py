# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""QA transport for actual HIA History, native kernel effects and shared state.

Only private capabilities are transported here. HIA owns root/record/ordering,
activity and FIFO admission. Python Condition/Lock are real QA synchronization;
their final native-runtime mechanical replacement is a separate gate.
"""
from pathlib import Path
from contextlib import ExitStack
import argparse,ctypes,errno,fcntl,hashlib,json,os,resource,signal,struct,subprocess,threading,time
import qualify_durable_audit_descriptor_engine as engine_qa
import qualify_durable_audit_record_io as io_qa
import qualify_durable_audit_root as root_qa
import qualify_durable_audit_hot as hot_qa
from hia_native_loader import NativeModule
SHA=lambda b:hashlib.sha256(b).hexdigest()
U=lambda b,at:struct.unpack_from("<Q",b,at)[0]
YIELD=0xffffffe0
BINARY_SHA="3ed1de3bf2e7c1a33b461e547b18c6896da6ad222777835c4fa3910dd006ab49"

class PackedEngine(engine_qa.Engine):
 def __init__(self,raw):
  assert type(raw)is bytes and len(raw)==3487 and SHA(raw)=="0420003cb2777ee6ca733d792aa9c9197dbc0d0330a79c1cdfaf1f7208a4951a"
  assert raw[:8]==b"HRAEPK01"and struct.unpack_from("<7Q",raw,8)==(3487,3423,0,245,2874,3066,3184)
  self.path=None;self.sha256=SHA(raw);self.flat=raw[64:];self.flat_sha256=SHA(self.flat)
  assert self.flat_sha256=="d8aafa16374d1ba86085b84c3e54496a6d8bace2d06099a8b18e04255727914b"
  self.exports=dict(zip(("create","step","child_ack","take","destroy"),struct.unpack_from("<5Q",raw,24)))
  self.descriptor=os.memfd_create("hia-emitted-audit-engine",os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
  self.mapping=None;self.system=ctypes.CDLL(None,use_errno=True)
  self.system.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
  self.system.mmap.restype=ctypes.c_void_p
  self.system.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t];self.system.munmap.restype=ctypes.c_int
  try:
   at=0
   while at<len(self.flat):
    n=os.write(self.descriptor,self.flat[at:]);assert n>0;at+=n
   fcntl.fcntl(self.descriptor,fcntl.F_ADD_SEALS,15)
   assert fcntl.fcntl(self.descriptor,fcntl.F_GET_SEALS)==15 and os.pread(self.descriptor,len(self.flat),0)==self.flat
   self.mapping=self.system.mmap(None,len(self.flat),5,2,self.descriptor,0)
   assert self.mapping not in(None,ctypes.c_void_p(-1).value)
   for name,args in(("create",[ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64,ctypes.c_int64]),
    ("step",[ctypes.c_void_p]),("child_ack",[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64]),
    ("take",[ctypes.c_void_p,ctypes.c_uint64]),("destroy",[ctypes.c_void_p])):
    setattr(self,name,ctypes.CFUNCTYPE(ctypes.c_int64,*args)(self.mapping+self.exports[name]))
  except BaseException:
   if self.mapping not in(None,ctypes.c_void_p(-1).value):self.system.munmap(self.mapping,len(self.flat))
   os.close(self.descriptor);self.descriptor=None;raise

class State:
 def __init__(self,module,magic,capacity):
  self.module=module;self.magic=magic;self.capacity=capacity;self.manager=None;self.session=None;self.trace=[]
  self.replace(capacity,b"")
 def replace(self,capacity,prior):
  old=self.manager;manager=self.module.session(output_capacity=64,workspace_capacity=capacity)
  session=manager.__enter__()
  try:
   if prior:ctypes.memmove(ctypes.addressof(session._workspace),prior,len(prior))
  except BaseException:manager.__exit__(*__import__("sys").exc_info());raise
  self.manager=manager;self.session=session;self.capacity=capacity
  if old is not None:old.__exit__(None,None,None)
 def close(self):
  if self.manager is not None:self.manager.__exit__(None,None,None);self.manager=None
 def raw(self):return ctypes.string_at(ctypes.addressof(self.session._workspace),self.capacity)
 def call(self,frame,growth):
  while True:
   code,out,w=self.session.invoke_raw(frame)
   assert code==64 and out[:8]==self.magic and not any(out[56:64]),(code,out.hex())
   status=U(out,8);self.trace.append(dict(request=frame.hex(),response=out.hex()))
   if status!=growth:return out
   needed=U(out,24 if self.magic==b"HRAFO001"else 32)
   assert needed>self.capacity and needed>=len(w)
   # A requested arena extension is not a retry of an admitted effect: HIA
   # returned before inserting any new ticket/entry. Keep its complete state.
   self.replace(needed,w)

class Activity:
 def __init__(self,module):
  self.state=State(module,b"HRAACTR1",128);self.mutex=threading.Lock()
  assert U(self.call(0),8)==0
 def call(self,op,token=0,value=0,id=None):
  frame=b"HRAACTQ1"+struct.pack("<QQQ",op,token,value)+bytes(32)+(id.encode()if id is not None else bytes(64))
  assert len(frame)==128
  with self.mutex:return self.state.call(frame,1)
 def initialize(self,items):
  for item in items:
   out=self.call(1,id=item["id"]);assert U(out,8)==0;token=U(out,16)
   assert U(self.call(3,token,int(item["value"])),8)==0
   if not item["alive"]:assert U(self.call(4,token),8)==0
 def query(self,id):
  out=self.call(5,id=id.decode());assert U(out,8)==0
  return U(out,24)
 def remaining(self):
  raw=self.state.raw();return sorted([[raw[at:at+64].decode(),U(raw,at+72)]for at in range(128,len(raw),128)if U(raw,at+88)])
 def close(self):self.state.close()

class Domain:
 def __init__(self,fifo,activity):
  self.fifo=State(fifo,b"HRAFO001",128);self.condition=threading.Condition(threading.Lock())
  self.inner=threading.Lock();self.activity=Activity(activity)
  out=self.fifo.call(b"HRAFL001"+bytes(56),7);assert U(out,8)==0
  self.leases=set()
 def operation(self,op,ticket=0,flags=0):
  frame=b"HRAFL001"+struct.pack("<7Q",op,time.monotonic_ns(),0,0,ticket,flags,0)
  return self.fifo.call(frame,7)
 def acquire(self):
  with self.condition:
   out=self.operation(1);assert U(out,8)==1;ticket=U(out,16)
   while True:
    out=self.operation(3,ticket);status=U(out,8)
    if status==2:break
    assert status==1
    self.condition.wait()
   out=self.operation(4,ticket);assert U(out,8)==8
  locked=self.inner.acquire(blocking=False)
  with self.condition:
   out=self.operation(5,ticket,0 if locked else 4)
   if U(out,8)!=3:
    if locked:self.inner.release()
    assert U(self.operation(6,ticket),8)==0;self.condition.notify_all()
    raise RuntimeError("original FIFO inner admission refused")
   assert ticket not in self.leases;self.leases.add(ticket)
  return ticket
 def release(self,ticket):
  # Match the original writer guard: actual inner mutex drops before the
  # queue's writer flag clears and its waiters receive notify_all.
  self.inner.release()
  with self.condition:
   assert ticket in self.leases;out=self.operation(6,ticket)
   assert U(out,8)==0 and U(out,32)==1
   self.leases.remove(ticket);self.condition.notify_all()
 def close(self):
  assert not self.leases and not self.inner.locked()
  assert U(self.fifo.raw(),48)==0
  self.activity.close();self.fifo.close()

class History:
 def __init__(self,modules,domain):
  self.modules=modules;self.domain=domain
  self.root=engine_qa.EngineRoot(modules["root"])
  self.hot=engine_qa.EngineHot(modules["hot"],modules["io"],modules["record"])
 def run(self,root,owner,params,*,before_effect=None):
  limit=params.get("limit");limit=32 if limit is None else limit;cursor=params.get("after_id")
  frame=b"HRAHIS01"+struct.pack("<QQQ",limit,int(cursor is not None),len(root))+bytes(32)+owner.encode()+(cursor.encode()if cursor is not None else bytes(64))+root
  assert len(owner)==64 and(cursor is None or len(cursor)==64)
  capacity=1048608+2*len(frame);trace=[];lease=None;descriptor=None;seq=0
  before_fds=len(os.listdir("/proc/self/fd"))
  try:
   with self.modules["history"].session(output_capacity=65568,workspace_capacity=capacity)as session:
    while True:
     code,out,w=session.invoke_raw(frame)
     if code!=YIELD:
      assert 32<=code<=65568 and out[:8]==b"HRAHYR01"and U(out,24)==code and U(out,16)==code-32
      assert descriptor is None and lease is None
      replay,out2,w2=session.invoke_raw(frame);assert replay==0xffffffff and out2==out and w2==w
      return dict(result=dict(diagnostic=U(out,8),output=out[32:code].decode()if code>32 else None),
       remaining_active_entries=self.domain.activity.remaining(),trace=trace,
       fd_count_before=before_fds,fd_count_after=len(os.listdir("/proc/self/fd")),
       private_reason=U(w,160),terminal_replay_refused=True)
     magic,current,kind,slot,span,count,target,cap,ack,value,error,reserved=struct.unpack_from("<12Q",w,256)
     assert magic==int.from_bytes(b"HRAHYA01","little")and current==seq+1 and slot==ack==value==error==reserved==0
     assert w[256:320]==w[384:448];seq=current
     row=dict(sequence=seq,kind=kind,request_hex=w[span:span+count].hex(),action_hex=w[256:352].hex())
     if before_effect is not None:before_effect(kind,descriptor,self.domain)
     payload=b"";result=0;err=0
     if kind==110:
      assert lease is None and descriptor is None and span==count==target==cap==0
      lease=self.domain.acquire()
     elif kind==101:
      assert lease is not None and descriptor is None and target==4096 and cap==160
      request=w[span:span+count];assert request[:8]==b"HRAROOT1"and U(request,8)==2 and U(request,16)==len(request)-32 and U(request,24)==0
      child,descriptor=self.root.retained(request[32:],2);payload=bytes.fromhex(child["raw"]);row["child"]=child
     elif kind==102:
      assert lease is not None and descriptor is not None and w[span:span+count]==b"HRAHOT01"+struct.pack("<QQ",512,0)and target==8192 and cap==131136
      child=self.hot.held(descriptor);payload=bytes.fromhex(child["raw"]);row["child"]=child
     elif kind==103:
      assert lease is not None and descriptor is not None and count==64 and target==cap==0
      result=self.domain.activity.query(w[span:span+count])
     elif kind==104:
      assert lease is not None and descriptor is not None and target==300000 and cap==65568
      payload=self.modules["page"].invoke(w[span:span+count],output_capacity=65568,workspace_capacity=16384)
     elif kind==105:
      assert lease is not None and descriptor is not None and span==count==target==cap==0
      fd=descriptor;descriptor=None
      try:os.close(fd)
      except OSError as error:err=error.errno
     elif kind==111:
      assert lease is not None and descriptor is None and span==count==target==cap==0
      ticket=lease;lease=None;self.domain.release(ticket)
     else:raise AssertionError(("unknown closed History action",kind))
     if payload:
      assert len(payload)<=cap;result=len(payload);ctypes.memmove(ctypes.addressof(session._workspace)+target,payload,len(payload))
     assert ctypes.string_at(ctypes.addressof(session._workspace)+256,64)==w[256:320]
     ctypes.memmove(ctypes.addressof(session._workspace)+320,struct.pack("<4Q",seq,result,err,0),32)
     row.update(result=result,errno=err,response_hex=payload.hex());trace.append(row)
  finally:
   if descriptor is not None:os.close(descriptor)
   if lease is not None:self.domain.release(lease)

def scenarios():
 rows=[]
 def add(label,**kw):rows.append(dict(label=label,owner="b"*64,params=dict(after_id=None,limit=32),active=[],**kw))
 for count in(0,1,3,33,128,512,513):add("records-"+str(count),hot=dict(count=count,order="descending"))
 for variant in("same-time-id-sort","mixed-owners-and-states","malformed-json","wrong-identity","wide-record","symlink-record","hardlink-record","fifo-record","unexpected-extension","bad-json-name","invalid-utf8-member","orphan-stage","linked-stage","bad-stage","wide-stage","oversized-stage","wrong-linked-stage","cleanup-before-bad-record"):
  add(variant,hot=dict(count=3,variant=variant))
 for variant in("root-mode-755","root-mode-500","root-mode-1700","root-missing","root-file","root-fifo","root-symlink","ancestor-symlink","hot-755","hot-file","hot-fifo","hot-symlink","dot","dotdot","repeated-slashes","relative","nul"):
  add(variant,root_variant=variant)
 for state in("unknown","completed","failed"):
  for stamp in(2**64-1,2**64,2**128-1):
   add(state+"-u128-"+str(stamp),records=[dict(request_id="a"*64,owner="b"*64,tool_name="host_list",state=state,accepted_unix_ms=stamp,elapsed_ms=None)])
 for selected in(False,True):
  add("owner-u128-"+str(selected),records=[dict(request_id="a"*64,owner=("b"if selected else"c")*64,tool_name="host_list",state="unknown",accepted_unix_ms=2**128-1,elapsed_ms=None)])
 for alive in(False,True):
  for value in(False,True):
   add("active-"+str(alive)+"-"+str(value),hot=dict(count=3,order="ascending"))
   rows[-1]["active"]=[dict(id=f"{3:064x}",alive=alive,value=value),dict(id="d"*64,alive=False,value=True)]
 for mode in("known-skips-registry","cursor-before-active","unselected-skips-registry","replace-live-map"):
  add(mode,hot=dict(count=3));rows[-1]["active"]=[dict(id=f"{3:064x}",alive=True,value=True),dict(id="d"*64,alive=False,value=True)]
  if mode=="known-skips-registry":rows[-1]["params"]["limit"]=2
  if mode=="cursor-before-active":rows[-1]["params"]["after_id"]="e"*64
  if mode=="unselected-skips-registry":rows[-1]["owner"]="e"*64
  if mode=="replace-live-map":rows[-1]["active"].append(dict(id=f"{3:064x}",alive=False,value=True))
 for limit,cursor,owner,label in((0,None,"b","limit-zero"),(33,None,"b","limit-large"),(32,"Z"*64,"b","cursor-invalid"),(32,None,"B","owner-invalid"),(1,None,"b","first-page"),(1,f"{1:064x}","b","second-page"),(1,f"{3:064x}","b","last-page"),(1,f"{1:064x}","c","foreign-cursor"),(32,"f"*64,"b","missing-cursor")):
  add(label,hot=dict(count=3));rows[-1]["params"]=dict(after_id=cursor,limit=limit);rows[-1]["owner"]=owner*64
 return rows

def materialize(base,case):
 variant=case.get("root_variant","private");root=root_qa.materialize(base,dict(variant=variant,operation=2))
 if variant=="private":
  hot=Path(os.fsdecode(root))/"request-audit"
  if "records"in case:
   hot.mkdir(mode=0o700)
   for item in case["records"]:
    p=hot/(item["request_id"]+".json");p.write_text(json.dumps(item,separators=(",",":")));p.chmod(0o600)
  else:hot_qa.materialize(hot,case.get("hot",dict(count=0)))
 return root

def main():
 p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--build",type=Path,required=True)
 p.add_argument("--original",type=Path,required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--history-manifest",type=Path)
 a=p.parse_args();q=a.output;q.mkdir(parents=True,exist_ok=False);resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 names=dict(root="root-v1",hot="hot-v1",io="record-io-v2",record="record",page="page",fifo="fifo-v3",activity="activity-v1",history="history-v1",packer="descriptor-packer-v1")
 manifests={key:a.build/("modules/durable-audit-"+name+"/manifest.json")for key,name in names.items()}
 if a.history_manifest:manifests["history"]=a.history_manifest
 paths=[Path(__file__),Path(engine_qa.__file__),Path(io_qa.__file__),Path(root_qa.__file__),Path(hot_qa.__file__),Path(__file__).parent/"hia_native_loader.py",a.original,a.original.parent/"provenance.json",a.original.parent/"build-source-relation.json",a.original.parent/"original-Cargo.lock",a.original.parent/"original-request_audit.rs"]
 for key,path in manifests.items():
  m=json.loads(path.read_bytes());paths.extend([path,path.parent/m["source"],path.parent/m["image"]])
  relative="native/durable_audit_"+dict(io="record_io",packer="descriptor_packer").get(key,key)+".hepta"
  assert(path.parent/m["source"]).read_bytes()==(a.source/relative).read_bytes(),relative
  paths.append(a.source/relative)
 before={str(path):dict(bytes=path.stat().st_size,sha256=SHA(path.read_bytes()))for path in dict.fromkeys(paths)}
 assert before[str(a.original)]["sha256"]==BINARY_SHA
 provenance=json.loads((a.original.parent/"provenance.json").read_bytes())
 assert provenance["state"]=="PASS"and provenance["locked_registry_archives"]==360 and provenance["binary_record"]["sha256"]==BINARY_SHA
 (q/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
 rows=[];start=time.monotonic()
 with ExitStack()as stack:
  modules={key:stack.enter_context(NativeModule(path,manifest_sha256=before[str(path)]["sha256"]))for key,path in manifests.items()}
  emitted=modules["packer"].invoke(b"HRAEPQ01"+struct.pack("<QQ",1,0),output_capacity=4096,workspace_capacity=4096)
  (q/"actual-hia-emitted.engine").write_bytes(emitted);engine=PackedEngine(emitted);stack.callback(engine.close);engine_qa.ENGINE=engine
  for index,case in enumerate(scenarios()):
   d=q/(f"{index:03d}-"+case["label"]);d.mkdir();oldroot=materialize(d/"original",case);newroot=materialize(d/"native",case)
   (d/"case.json").write_text(json.dumps(case,sort_keys=True,indent=2)+"\n")
   oldbefore=root_qa.snapshot(d/"original");newbefore=root_qa.snapshot(d/"native");assert oldbefore==newbefore
   request=dict(root_hex=oldroot.hex(),owner=case["owner"],params=case["params"],active=case["active"])
   (d/"original-input.json").write_text(json.dumps(request,sort_keys=True)+"\n")
   result=subprocess.run([str(a.original)],input=(json.dumps(request)+"\n").encode(),capture_output=True,timeout=10)
   (d/"original.stdout").write_bytes(result.stdout);(d/"original.stderr").write_bytes(result.stderr)
   domain=Domain(modules["fifo"],modules["activity"])
   try:
    domain.activity.initialize(case["active"]);new=History(modules,domain).run(newroot,case["owner"],case["params"])
    new["fifo_trace"]=domain.fifo.trace;new["activity_trace"]=domain.activity.state.trace
    (d/"native.json").write_text(json.dumps(new,sort_keys=True,indent=2)+"\n")
   finally:domain.close()
   assert new["fd_count_before"]==new["fd_count_after"]
   if result.returncode==0:
    old=json.loads(result.stdout);assert old["fd_count_before"]==old["fd_count_after"]
    observed=dict(diagnostic=old["result"]["diagnostic"],output=old["result"]["output"])
    same=observed==new["result"]and old["remaining_active_entries"]==new["remaining_active_entries"]
   else:
    assert result.returncode==-signal.SIGABRT and b"request_audit.rs:2221"in result.stderr and b"number out of range"in result.stderr
    old=dict(release_process_aborted=True,exit_code=result.returncode)
    same=new["result"]==dict(diagnostic=3,output=None)
   oldafter=root_qa.snapshot(d/"original");newafter=root_qa.snapshot(d/"native")
   (d/"original-after.json").write_text(json.dumps(oldafter,sort_keys=True,indent=2)+"\n");(d/"native-after.json").write_text(json.dumps(newafter,sort_keys=True,indent=2)+"\n")
   row=dict(index=index,label=case["label"],passed=same and oldafter==newafter,original_exit_code=result.returncode,native_diagnostic=new["result"]["diagnostic"],private_reason=new["private_reason"],filesystem_equal=oldafter==newafter,actions=[r["kind"]for r in new["trace"]])
   rows.append(row);(q/"progress.json").write_text(json.dumps(rows,sort_keys=True,indent=2)+"\n")
   print(json.dumps(row,sort_keys=True),flush=True)
 after={str(path):dict(bytes=path.stat().st_size,sha256=SHA(path.read_bytes()))for path in dict.fromkeys(paths)}
 assert before==after
 report=dict(schema="hepta.runtime.durable-history-full-graph-comparison.v1",state="PASS"if all(r["passed"]for r in rows)else"FAIL",
  cases=len(rows),passed=sum(r["passed"]for r in rows),rows=rows,source_before=before,source_after=after,source_unchanged=True,
  complete_original_graph=True,original_commit="abc9ecb95ee9538518ec3f36c47b881974107021",original_binary_sha256=BINARY_SHA,
  hia_emitted_engine_sha256=SHA(emitted),actual_native_filesystem=True,actual_hia_activity_fifo=True,qa_kernel_mutex=True,
  original_panic_outcome_is_distinct=True,public_routing_qualified=False,elapsed_seconds=time.monotonic()-start)
 (q/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 print(json.dumps({k:v for k,v in report.items()if k not in("source_before","source_after","rows")},sort_keys=True),flush=True)
 assert report["state"]=="PASS"
if __name__=="__main__":main()
