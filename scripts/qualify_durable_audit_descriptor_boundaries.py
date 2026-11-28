# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Real native descriptor ownership and private-action refusal controls."""
from pathlib import Path
from types import SimpleNamespace
import argparse,ctypes,errno,hashlib,json,os,stat,struct,time
from qualify_durable_audit_descriptor_engine import Engine
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
WORD=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
def frame(work,magic,sequence,kind,slot=0,span=0,count=0,arg=0,capacity=0):
 raw=struct.pack("<12Q",int.from_bytes(magic,"little"),sequence,kind,slot,span,count,arg,capacity,0,0,0,0)
 ctypes.memmove(ctypes.addressof(work)+256,raw,len(raw));return raw
def main():
 p=argparse.ArgumentParser();p.add_argument("--old-engine",type=Path,required=True);p.add_argument("--old-report",type=Path,required=True)
 p.add_argument("--engine",type=Path,required=True);p.add_argument("--report",type=Path,required=True)
 p.add_argument("--output",type=Path,required=True);a=p.parse_args();q=a.output;q.mkdir(parents=True,exist_ok=False)
 old_report=json.loads(a.old_report.read_bytes());report=json.loads(a.report.read_bytes())
 assert old_report["state"]==report["state"]=="PASS"and old_report["cases"]==report["cases"]==195
 assert old_report["engine_source_sha256"]=="b90d378db289b7511607e62708b6416e69ad3e06a6b9b226c2183cf06aec6e35"
 assert report["engine_source_sha256"]=="990a1dbd3a90d6a0a6154e9d0031b860b58b178b12201e7d382b8196ca715a8c"
 inputs=[Path(__file__),Path(__file__).parent/"qualify_durable_audit_descriptor_engine.py",a.old_engine,a.old_report,a.engine,a.report]
 before={str(p):SHA(p.read_bytes())for p in inputs};start=time.monotonic();rows=[]
 root=q/"actual-directory";root.mkdir(mode=0o700);leaf=root/"retained";leaf.write_bytes(b"actual native descriptor");leaf.chmod(0o600)
 borrowed=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
 old=Engine(a.old_engine,expected_sha256=old_report["engine_elf_sha256"])
 current=Engine(a.engine,expected_sha256=report["engine_elf_sha256"])
 def workspace(n=65536):return ctypes.create_string_buffer(n)
 def context(engine,mode,work,fd):
  return engine.open(mode,SimpleNamespace(_workspace=work),len(work),fd)
 def snapshot(ctx):return ctypes.string_at(ctx,4096)
 def note(name,**fields):
  rows.append(dict(name=name,passed=True,**fields))
  (q/"progress.json").write_text(json.dumps(rows,sort_keys=True,indent=2)+"\n")
 def cleanup(engine,ctx):engine.cleanup(ctx)
 try:
  # This old private-ACK counterexample does not claim a full actor false-PASS:
  # the separately captured HIA action shadow still rejected such a mutation.
  work=workspace();ctx=context(old,1,work,borrowed)
  try:
   raw=frame(work,b"HRADAS01",1,100,0,44000,101,48000,4096)
   assert old.step(ctx)==1
   ctypes.memmove(ctypes.addressof(work)+312,struct.pack("<Q",8192),8)
   admitted=old.child_ack(ctx,0,0);assert admitted==0
   old_observation=dict(schema="hepta.runtime.audit-old-private-ack-counterexample.v1",
    old_engine_sha256=old.sha256,original_action_hex=raw.hex(),
    changed_action_hex=ctypes.string_at(ctypes.addressof(work)+256,96).hex(),
    changed_field="capacity",old_ack_result=admitted,
    full_hia_actor_false_pass=False,scope="mechanical child ACK admitted changed capacity; HIA shadow remained a separate refusal")
   (q/"original-private-ack-observation.json").write_text(json.dumps(old_observation,sort_keys=True,indent=2)+"\n")
  finally:cleanup(old,ctx)
  for index,label in enumerate(("magic","sequence","kind","slot","span","count","target","capacity")):
   work=workspace();ctx=context(current,1,work,borrowed)
   try:
    raw=frame(work,b"HRADAS01",1,100,0,44000,101,48000,4096);assert current.step(ctx)==1
    base=snapshot(ctx)
    n=WORD(raw,index*8)^1;ctypes.memmove(ctypes.addressof(work)+256+index*8,struct.pack("<Q",n),8)
    changed=ctypes.string_at(ctypes.addressof(work)+256,96)
    assert current.child_ack(ctx,0,0)==-errno.EINVAL and snapshot(ctx)==base
    assert ctypes.string_at(ctypes.addressof(work)+256,96)==changed
    ctypes.memmove(ctypes.addressof(work)+256,raw,96)
    assert current.child_ack(ctx,0,errno.ECANCELED)==0
    note("child-action-"+label+"-late-change-refused")
   finally:cleanup(current,ctx)
  for label,result,error in(("oversized-result",4097,0),("invalid-errno",0,4096),("value-with-error",1,errno.EIO)):
   work=workspace();ctx=context(current,1,work,borrowed)
   try:
    raw=frame(work,b"HRADAS01",1,100,0,44000,101,48000,4096);assert current.step(ctx)==1
    base=snapshot(ctx)
    assert current.child_ack(ctx,result,error)==-errno.EINVAL and snapshot(ctx)==base
    assert ctypes.string_at(ctypes.addressof(work)+256,96)==raw
    assert current.child_ack(ctx,0,errno.ECANCELED)==0
    note("child-"+label+"-refused")
   finally:cleanup(current,ctx)
  work=workspace();ctx=context(current,1,work,borrowed)
  try:
   raw=frame(work,b"HRADAS01",1,100,0,44000,101,48000,4096);assert current.step(ctx)==1
   base=snapshot(ctx)
   assert current.step(ctx)==-errno.EBUSY and current.destroy(ctx)==-errno.EBUSY and snapshot(ctx)==base
   assert current.child_ack(ctx,0,errno.ECANCELED)==0
   after=snapshot(ctx)
   assert current.child_ack(ctx,0,0)==-errno.EINVAL and current.step(ctx)==-errno.EINVAL and snapshot(ctx)==after
   note("pending-child-no-replay-no-early-destroy")
  finally:cleanup(current,ctx)
  invalid_actions=[
   ("wrong-domain",b"HRARDS01",1,1,1,640,8,0xa0800,0),
   ("wrong-sequence",b"HRADAS01",2,1,1,640,8,0xa0800,0),
   ("unknown-op",b"HRADAS01",1,99,1,640,8,0xa0800,0),
   ("borrowed-slot-overwrite",b"HRADAS01",1,1,0,640,8,0xa0800,0),
   ("nonexistent-slot",b"HRADAS01",1,1,6,640,8,0xa0800,0),
   ("span-overflow",b"HRADAS01",1,1,1,(1<<64)-1,8,0xa0800,0),
   ("span-outside-workspace",b"HRADAS01",1,1,1,65536,8,0xa0800,0),
   ("write-flags",b"HRADAS01",1,1,1,640,8,0xa0801,0),
   ("parent-injection",b"HRADAS01",1,1,1,640,8,0xa0800,1),
   ("empty-component",b"HRADAS01",1,1,1,640,0,0xa0800,0)]
  for label,*args in invalid_actions:
   work=workspace();ctypes.memmove(ctypes.addressof(work)+640,b"retained",8);ctx=context(current,1,work,borrowed)
   try:
    raw=frame(work,*args);base=snapshot(ctx)
    assert current.step(ctx)==-errno.EINVAL and snapshot(ctx)==base
    assert ctypes.string_at(ctypes.addressof(work)+256,96)==raw
    note("kernel-"+label+"-refused")
   finally:cleanup(current,ctx)
  for label,name in(("embedded-nul",b"ret\0ined"),("embedded-separator",b"ret/ined")):
   work=workspace();ctypes.memmove(ctypes.addressof(work)+640,name,len(name));ctx=context(current,1,work,borrowed)
   try:
    frame(work,b"HRADAS01",1,1,1,640,len(name),0xa0800,0);base=snapshot(ctx)
    assert current.step(ctx)==-errno.EINVAL and snapshot(ctx)==base
    note("kernel-"+label+"-refused")
   finally:cleanup(current,ctx)
  for mode,magic in((0,b"HRARDS01"),(1,b"HRADAS01"),(2,b"HRAHAS01")):
   work=workspace(532480);ctx=context(current,mode,work,-1 if mode==0 else borrowed)
   try:
    base=snapshot(ctx)
    assert current.take(ctx,0)==-errno.EINVAL and current.take(ctx,1)==-errno.EINVAL and snapshot(ctx)==base
    note("mode-"+str(mode)+"-cannot-transfer-borrowed-or-empty-slot")
   finally:cleanup(current,ctx)
  # The new mechanical layer itself executes actual openat/read/close. It
  # never returns an OS descriptor number through the private HIA reply.
  work=workspace();ctypes.memmove(ctypes.addressof(work)+640,b"retained",8);ctx=context(current,1,work,borrowed)
  try:
   frame(work,b"HRADAS01",1,1,1,640,8,0xa0800,0);assert current.step(ctx)==0
   action=ctypes.string_at(ctypes.addressof(work)+256,96);assert WORD(action,64)==1 and WORD(action,72)==WORD(action,80)==0
   fd=current.state(ctx)["descriptors"][1];assert fd>=0
   assert os.fstat(fd).st_ino==leaf.stat().st_ino
   initial=snapshot(ctx)
   assert current.step(ctx)==-errno.EINVAL and snapshot(ctx)==initial
   frame(work,b"HRADAS01",2,3,1,40000,2049,0,0);assert current.step(ctx)==0
   action=ctypes.string_at(ctypes.addressof(work)+256,96);count=WORD(action,72)
   assert WORD(action,80)==0 and ctypes.string_at(ctypes.addressof(work)+40000,count)==leaf.read_bytes()
   frame(work,b"HRADAS01",3,6,1);assert current.step(ctx)==0
   try:os.fstat(fd)
   except OSError as error:assert error.errno==errno.EBADF
   else:raise AssertionError("native close did not close actual owned descriptor")
   frame(work,b"HRADAS01",4,6,1);initial=snapshot(ctx)
   assert current.step(ctx)==-errno.EINVAL and snapshot(ctx)==initial
   assert os.fstat(borrowed).st_ino==root.stat().st_ino
   note("actual-open-read-close-once-borrow-retained")
  finally:cleanup(current,ctx)
  work=workspace();ctypes.memmove(ctypes.addressof(work)+640,b"retained",8);ctx=context(current,1,work,borrowed)
  frame(work,b"HRADAS01",1,1,1,640,8,0xa0800,0);assert current.step(ctx)==0
  fd=current.state(ctx)["descriptors"][1];cleanup(current,ctx)
  try:os.fstat(fd)
  except OSError as error:assert error.errno==errno.EBADF
  else:raise AssertionError("native cancellation cleanup retained an owned descriptor")
  assert os.fstat(borrowed).st_ino==root.stat().st_ino
  note("actual-known-cancellation-closes-only-owned")
  work=workspace(4096);ctypes.memmove(ctypes.addressof(work)+768,b"/",1);ctx=context(current,0,work,-1)
  frame(work,b"HRARDS01",1,11,1,768,1,0x2b0000,0);assert current.step(ctx)==0
  fd=current.take(ctx,1);assert fd>=0 and current.state(ctx)["owned_mask"]==0
  cleanup(current,ctx)
  try:assert stat.S_ISDIR(os.fstat(fd).st_mode)
  finally:os.close(fd)
  note("actual-private-lease-survives-context-transfer")
  # Two immutable flat mappings retain separate image identities; there is
  # no dlopen pathname cache or recycled /proc/self/fd name in execution.
  assert old.mapping!=current.mapping and old.flat_sha256!=current.flat_sha256
  assert ctypes.string_at(old.mapping,len(old.flat))==old.flat
  assert ctypes.string_at(current.mapping,len(current.flat))==current.flat
  note("distinct-sealed-flat-code-and-export-binding")
 finally:
  old.close();current.close();os.close(borrowed)
 after={str(p):SHA(p.read_bytes())for p in inputs};assert before==after
 result=dict(schema="hepta.runtime.audit-native-descriptor-boundaries.v1",state="PASS",controls=len(rows),rows=rows,
  old_private_ack_counterexample_preserved=True,public_false_pass_claim=False,
  source_before=before,source_after=after,source_unchanged=True,elapsed_seconds=time.monotonic()-start)
 (q/"report.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n");print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
