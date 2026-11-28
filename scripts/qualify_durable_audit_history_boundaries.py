# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual shared-context, held-directory and private-ACK History controls."""
from pathlib import Path
from contextlib import ExitStack
import argparse,ctypes,hashlib,json,os,struct,threading,time
import qualify_durable_audit_history_native as h
from hia_native_loader import NativeModule
SHA=h.SHA;U=h.U
def main():
 p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--build",type=Path,required=True)
 p.add_argument("--history-manifest",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
 q=a.output;q.mkdir(parents=True,exist_ok=False);start=time.monotonic();rows=[]
 names=dict(root="root-v1",hot="hot-v1",io="record-io-v2",record="record",page="page",fifo="fifo-v3",activity="activity-v1",packer="descriptor-packer-v1")
 manifests={key:a.build/("modules/durable-audit-"+name+"/manifest.json")for key,name in names.items()};manifests["history"]=a.history_manifest
 paths=[Path(__file__),Path(h.__file__),Path(h.engine_qa.__file__),Path(h.io_qa.__file__),Path(h.root_qa.__file__),Path(h.hot_qa.__file__),Path(__file__).parent/"hia_native_loader.py"]
 for path in manifests.values():
  m=json.loads(path.read_bytes());paths.extend([path,path.parent/m["source"],path.parent/m["image"]])
 before={str(path):SHA(path.read_bytes())for path in dict.fromkeys(paths)}
 def note(label,**values):rows.append(dict(label=label,passed=True,**values))
 with ExitStack()as stack:
  modules={key:stack.enter_context(NativeModule(path,manifest_sha256=before[str(path)]))for key,path in manifests.items()}
  emitted=modules["packer"].invoke(b"HRAEPQ01"+struct.pack("<QQ",1,0),output_capacity=4096,workspace_capacity=4096)
  engine=h.PackedEngine(emitted);stack.callback(engine.close);h.engine_qa.ENGINE=engine
  # After the actual Root owner exports a captured directory FD, replace its
  # pathname. History must consume the original inode; the new path is bait.
  case=dict(label="held-directory",hot=dict(count=3),owner="b"*64,params=dict(after_id=None,limit=32),active=[])
  rawroot=h.materialize(q/"held-directory",case);root=Path(os.fsdecode(rawroot));domain=h.Domain(modules["fifo"],modules["activity"]);identity=[]
  try:
   def replaced(kind,fd,context):
    if kind!=102:return
    st=os.fstat(fd);identity.append((st.st_dev,st.st_ino))
    (root/"request-audit").rename(root/"held-original")
    h.hot_qa.materialize(root/"request-audit",dict(count=1))
    fake=root/"request-audit"/(f"{1:064x}"+".json");value=json.loads(fake.read_bytes());value["tool_name"]="replacement_bait";fake.write_text(json.dumps(value));fake.chmod(0o600)
    after=os.fstat(fd);assert identity[-1]==(after.st_dev,after.st_ino)
    assert (root/"request-audit").stat().st_ino!=st.st_ino
   result=h.History(modules,domain).run(rawroot,case["owner"],case["params"],before_effect=replaced)
   assert result["result"]["diagnostic"]==0
   records=json.loads(result["result"]["output"])["requests"];assert len(records)==3 and all(x["tool_name"]=="host_list"for x in records)
   assert result["fd_count_before"]==result["fd_count_after"]
   (q/"held-directory-native.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
   note("root-hot-io-use-same-retained-inode-after-path-replacement",identity=identity,records=len(records))
  finally:domain.close()
  # Two real calling threads, same FIFO and activity arena, distinct sessions.
  # The queued observation comes from native ticket insertion, never a sleep.
  first_inside=threading.Event();second_queued=threading.Event();allow_first=threading.Event();second_inside=threading.Event()
  class ObservedDomain(h.Domain):
   def operation(self,op,ticket=0,flags=0):
    out=super().operation(op,ticket,flags)
    if op==1 and threading.current_thread().name=="second-history":second_queued.set()
    return out
  domain=ObservedDomain(modules["fifo"],modules["activity"]);answers={};errors={};threads=[]
  roots=[h.materialize(q/("shared-"+str(i)),dict(hot=dict(count=3)))for i in range(2)]
  def worker(index):
   try:
    def boundary(kind,fd,ctx):
     if kind!=101:return
     if index==0:
      first_inside.set();assert allow_first.wait(10),"QA coordinator failed to release the actual admitted writer"
     else:second_inside.set()
    answers[index]=h.History(modules,domain).run(roots[index],"b"*64,dict(after_id=None,limit=32),before_effect=boundary)
   except BaseException as error:errors[index]=repr(error)
  try:
   threads=[threading.Thread(target=worker,args=(0,),name="first-history"),threading.Thread(target=worker,args=(1,),name="second-history")]
   threads[0].start();assert first_inside.wait(10)
   threads[1].start();assert second_queued.wait(10)
   with domain.condition:
    raw=domain.fifo.raw()
    assert U(raw,16)==1 and U(raw,48)==2 and not second_inside.is_set()
    (q/"two-session-queued-workspace.bin").write_bytes(raw)
   allow_first.set()
   for thread in threads:thread.join(10);assert not thread.is_alive()
   assert not errors and len(answers)==2 and second_inside.is_set(),errors
   assert all(value["result"]["diagnostic"]==0 for value in answers.values())
   assert answers[0]["result"]==answers[1]["result"]
   assert U(domain.fifo.raw(),48)==0 and not domain.leases
   (q/"two-session-native.json").write_text(json.dumps(dict(answers=answers,fifo_trace=domain.fifo.trace),sort_keys=True,indent=2)+"\n")
   note("two-sessions-share-one-native-FIFO-and-real-critical-section",tickets=2)
  finally:
   allow_first.set()
   for thread in threads:
    if thread.is_alive():thread.join(10)
   assert all(not thread.is_alive()for thread in threads)
   domain.close()
  # Cancellation at an observed synchronous boundary owns no unknown effect.
  # The frame and retained FD are disposed exactly once, then a new call works.
  class Cancelled(Exception):pass
  for cancellation in(110,101,102,103,104,105,111):
   d=q/("cancel-"+str(cancellation));root=h.materialize(d,dict(hot=dict(count=3)));domain=h.Domain(modules["fifo"],modules["activity"])
   beforefd=len(os.listdir("/proc/self/fd"))
   try:
    seen=[]
    def cancel(kind,fd,ctx):
     seen.append(kind)
     if kind==cancellation:raise Cancelled()
    try:h.History(modules,domain).run(root,"b"*64,dict(after_id=None,limit=32),before_effect=cancel)
    except Cancelled:pass
    else:raise AssertionError(("cancellation boundary not reached",cancellation))
    assert cancellation==seen[-1]and U(domain.fifo.raw(),48)==0 and not domain.leases
    assert len(os.listdir("/proc/self/fd"))==beforefd
    result=h.History(modules,domain).run(root,"b"*64,dict(after_id=None,limit=32));assert result["result"]["diagnostic"]==0
    assert len(os.listdir("/proc/self/fd"))==beforefd
    note("known-synchronous-cancel-"+str(cancellation),actions=seen)
   finally:domain.close()
  root=b"/unused-history-private-root";frame=b"HRAHIS01"+struct.pack("<3Q",32,0,len(root))+bytes(32)+b"b"*64+bytes(64)+root
  capacity=1048608+2*len(frame)
  # No root filesystem action is dispatched in these malformed-ACK controls.
  for index,offset in enumerate((0,8,16,24,32,40,48,56,64,72,80,88)):
   with modules["history"].session(output_capacity=65568,workspace_capacity=capacity)as session:
    code,out,w=session.invoke_raw(frame);assert code==h.YIELD and U(w,272)==110
    action=bytearray(w[256:352]);struct.pack_into("<4Q",action,64,U(w,264),0,0,0)
    if offset<64:struct.pack_into("<Q",action,offset,U(action,offset)^1)
    elif offset==64:struct.pack_into("<Q",action,offset,U(action,offset)+1)
    elif offset==72:struct.pack_into("<Q",action,offset,1)
    elif offset==80:struct.pack_into("<Q",action,offset,4096)
    else:struct.pack_into("<Q",action,offset,1)
    ctypes.memmove(ctypes.addressof(session._workspace)+256,bytes(action),96)
    rejected,out2,w2=session.invoke_raw(frame);assert rejected==0xffffffff and out2==out
    note("private-ack-field-"+str(offset)+"-refused",code=rejected)
  # Frozen public arguments cannot change between an HIA yield and its ACK.
  with modules["history"].session(output_capacity=65568,workspace_capacity=capacity)as session:
   code,out,w=session.invoke_raw(frame);assert code==h.YIELD
   ctypes.memmove(ctypes.addressof(session._workspace)+320,struct.pack("<4Q",U(w,264),0,0,0),32)
   changed=bytearray(frame);changed[64]=ord("c")
   rejected,out2,w2=session.invoke_raw(bytes(changed));assert rejected==0xffffffff and out2==out
   note("public-request-late-change-refused",code=rejected)
 after={str(path):SHA(path.read_bytes())for path in dict.fromkeys(paths)};assert before==after
 report=dict(state="PASS",controls=len(rows),rows=rows,source_before=before,source_after=after,source_unchanged=True,
  hia_emitted_engine=True,real_descriptor_effects=True,real_threads=2,qa_condition_and_mutex=True,
  public_routing_qualified=False,unknown_external_effect_not_replayed=True,elapsed_seconds=time.monotonic()-start)
 (q/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 print(json.dumps({k:v for k,v in report.items()if k not in("rows","source_before","source_after")},sort_keys=True),flush=True)
if __name__=="__main__":main()
