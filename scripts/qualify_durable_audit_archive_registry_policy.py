# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual native registry policy controls; physical owner integration is separate."""
from pathlib import Path
import argparse,ctypes,hashlib,json,stat,struct,time,types
SELF=Path(__file__).resolve(strict=True);EXECUTED=SELF.read_bytes();SHA=lambda v:hashlib.sha256(v).hexdigest()
REQUEST=b"HRAARQ01";RESPONSE=b"HRAARR01";INVALID=0xffffffff;CAPACITY=0xfffffffe;FATAL=0xfffffffd
MAX_REFS=2**63-1;MAXWORD=2**64-1
OWN=("scripts/qualify_durable_audit_archive_registry_policy.py","scripts/author_durable_audit_archive_registry.py",
"scripts/durable_audit_archive_registry_source.py.txt","native/durable_audit_archive_registry.hepta",
"native/durable_audit_archive_registry_composition.json","scripts/prepare_durable_audit_archive_registry_reference.py",
"scripts/author_durable_common.py","native/durable_audit_record_io.hepta","src/mcp/runtime/request_archive_store.rs",
"src/mcp/runtime/request_audit.rs","scripts/hia_native_loader.py","scripts/hia_native_build.py")
def request(op,key=(0,0,0,0),token=0,argument=0):
 return REQUEST+struct.pack("<11Q",op,*key,token,argument,0,0,0,0)
def pin(path):
 raw=path.read_bytes();return dict(bytes=len(raw),sha256=SHA(raw),mode=stat.S_IMODE(path.stat().st_mode))
def fields(raw):
 assert len(raw)==112 and raw[:8]==RESPONSE and raw[96:]==bytes(16),raw.hex()
 v=struct.unpack("<13Q",raw[8:])
 return dict(zip(("status","token","refs","created","destroyed","needed","live","weak","pending","poisoned","serial","reserved0","reserved1"),v))
class Actual:
 def __init__(self,module,log,capacity=128,initial=None):
  self.module=module;self.log=log;self.session=module.session(output_capacity=112,workspace_capacity=capacity);self.calls=0
  if initial is None:
   self.call("initial",request(0))
  else:
   assert len(initial)==capacity;ctypes.memmove(ctypes.addressof(self.session._workspace),initial,capacity)
 def bytes(self):return self.session._workspace.raw[:self.session.workspace_capacity]
 def close(self):self.session.close()
 def call(self,label,wire,expected_code=112):
  before=self.bytes();code,out,after=self.session.invoke_raw(wire);self.calls+=1
  row=dict(label=label,input_hex=wire.hex(),return_code=code,output_hex=out.hex(),workspace_before_hex=before.hex(),workspace_after_hex=after.hex())
  self.log.write(json.dumps(row,sort_keys=True)+"\n");self.log.flush()
  assert code==expected_code,(label,code,expected_code,out.hex())
  return fields(out)if code==112 else dict(code=code)
 def begin(self,key):
  while True:
   result=self.call("begin",request(1,key=key))
   if result["status"]!=7:return result
   needed=result["needed"];old=self.bytes()
   assert needed==len(old)+64
   new=self.module.session(output_capacity=112,workspace_capacity=needed)
   ctypes.memmove(ctypes.addressof(new._workspace),old,len(old));self.session.close();self.session=new
 def finish(self,token,accepted=True):return self.call("complete",request(2,token=token,argument=int(accepted)))
 def __enter__(self):return self
 def __exit__(self,*args):self.close()
def main():
 parser=argparse.ArgumentParser()
 for n in("source","manifest","output"):parser.add_argument("--"+n,type=Path,required=True)
 a=parser.parse_args();s=a.source.resolve(strict=True);q=a.output;q.mkdir(parents=True,exist_ok=False)
 assert(s/OWN[0]).read_bytes()==EXECUTED
 paths={n:s/n for n in OWN};m=json.loads(a.manifest.read_bytes());paths["module/manifest"]=a.manifest
 for name in("source","image"):
  assert Path(m[name]).name==m[name];paths["module/"+name]=a.manifest.parent/m[name]
 before={n:pin(p)for n,p in paths.items()}
 assert m["source_sha256"]==before["native/durable_audit_archive_registry.hepta"]["sha256"]
 loader_raw=(s/"scripts/hia_native_loader.py").read_bytes();module=types.ModuleType("_actual_registry_loader");module.__file__=str(s/"scripts/hia_native_loader.py")
 exec(compile(loader_raw,module.__file__,"exec"),module.__dict__)
 (q/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
 controls=[];start=time.monotonic();passed=False
 def check(name,condition,**detail):
  assert condition,(name,detail);controls.append(dict(name=name,passed=True,**detail))
 try:
  with module.NativeModule(a.manifest,manifest_sha256=before["module/manifest"]["sha256"])as native,(q/"calls.jsonl").open("x")as log:
   with Actual(native,log)as r:
    initial=r.bytes();needed=r.call("first-capacity",request(1,key=(1,2,3,4)))
    check("capacity is a storage request without a new identity",needed["status"]==7 and needed["needed"]==192 and needed["serial"]==0 and r.bytes()==initial)
    first=r.begin((1,2,3,4));t=first["token"]
    check("fresh open reserves one strong reference",first["created"]==1 and first["refs"]==1 and first["pending"]==t and first["weak"]==1)
    original=r.bytes();blocked=r.begin((5,6,7,8))
    check("another open waits behind the held registry gate",blocked["status"]==1 and r.bytes()==original)
    for op in(3,4):
     result=r.call("cannot-use-open-reservation",request(op,token=t))
     check("reserved-only token is not a published handle "+str(op),result["status"]==3 and r.bytes()==original)
    bad=r.call("wrong-open-receipt",request(2,token=t+1,argument=1))
    check("wrong completion preserves the original reservation",bad["status"]==3 and r.bytes()==original)
    r.call("non-boolean-open-receipt",request(2,token=t,argument=2),INVALID)
    check("nonboolean completion leaves all state intact",r.bytes()==original)
    done=r.finish(t);check("successful completion publishes one strong handle",done["refs"]==1 and done["pending"]==0)
    existing=r.begin((1,2,3,4))
    check("same physical key upgrades the live weak entry",existing["token"]==t and existing["created"]==0 and existing["refs"]==2)
    cloned=r.call("clone-during-existing-open",request(3,token=t));check("an existing caller may clone while open is pending",cloned["refs"]==3)
    released=r.call("drop-during-existing-open",request(4,token=t));check("existing caller drop preserves the open reservation",released["refs"]==2 and released["destroyed"]==0)
    failed=r.finish(t,False);check("failed existing open releases only its reservation",failed["refs"]==1 and failed["destroyed"]==0 and failed["pending"]==0)
    dead=r.call("last-handle-drop",request(4,token=t))
    check("last strong drop retires exactly its owner",dead["refs"]==0 and dead["destroyed"]==1 and dead["weak"]==1 and dead["live"]==0)
    old=r.bytes();stale=r.call("dead-upgrade-refused",request(3,token=t));check("dead strong handle cannot be reused",stale["status"]==3 and r.bytes()==old)
    second=r.begin((5,6,7,8));check("later open prunes expired weak entry and allocates a fresh identity",second["token"]!=t and second["weak"]==1 and second["created"]==1)
    r.finish(second["token"])
    gone=r.call("old-token-after-prune",request(5,token=t));check("pruned identity is no longer addressable",gone["status"]==3)
   with Actual(native,log)as r:
    tokens=[]
    for index in range(260):
     row=r.begin((11,index+1,13,index+1024));tokens.append(row["token"]);r.finish(row["token"])
    row=r.call("many-live-archives",request(5))
    check("registry grows past 256 live scopes without an application cap",row["live"]==260 and row["weak"]==260 and row["serial"]==260,actual_live_scopes=260,workspace_bytes=len(r.bytes()))
    for token in tokens[::2]:r.call("drop-alternate-scope",request(4,token=token))
    reused=r.begin((11,2,13,1025))
    check("pruning interior dead entries preserves every live identity",reused["token"]==tokens[1] and reused["weak"]==130 and reused["live"]==130)
    r.finish(reused["token"])
    for index,token in enumerate(tokens[1::2]):
     row=r.call("inspect-retained-scope",request(5,token=token))
     assert row["status"]==0 and row["refs"]==(2 if index==0 else 1)
    check("all compacted live handles remain independently valid",True,handles=130)
   with Actual(native,log)as r:
    a1=r.begin((21,22,23,24));r.finish(a1["token"])
    pending=r.begin((31,32,33,34));poison=r.call("explicit-poison-event",request(6))
    check("poison while creating releases the exact pending owner",poison["token"]==pending["token"] and poison["destroyed"]==1 and poison["pending"]==0 and poison["poisoned"]==1,scope="explicit native mutex-poison protocol; no Rust panic-profile change")
    state=r.bytes();refused=r.begin((41,42,43,44));check("poisoned registry refuses before pruning or new allocation",refused["status"]==2 and r.bytes()==state)
    cloned=r.call("arc-clone-after-poison",request(3,token=a1["token"]))
    check("existing Arc holder remains clonable after registry poison",cloned["status"]==0 and cloned["refs"]==2)
    r.call("arc-drop-after-poison",request(4,token=a1["token"]))
    last=r.call("arc-last-drop-after-poison",request(4,token=a1["token"]))
    check("existing strong lifetime still terminates after poison",last["destroyed"]==1 and last["live"]==0 and last["weak"]==2)
   with Actual(native,log)as r:
    old=r.begin((1,1,1,1));r.finish(old["token"]);r.begin((1,1,1,1))
    poisoned=r.call("poison-existing-reservation",request(6))
    check("poison during upgrade keeps the preexisting holder",poisoned["refs"]==1 and poisoned["destroyed"]==0)
   with Actual(native,log,capacity=256)as base:
    first=base.begin((61,62,63,64));base.finish(first["token"]);valid=base.bytes();t=first["token"]
    for label,wire in[
     *[("request-length-"+str(n),request(5)[:n])for n in(0,1,7,8,16,63,64,95)],
     ("request-tail",request(5)+b"\0"),("bad-magic",b"X"+request(5)[1:]),
     ("unknown-operation",request(7)),("init-token",request(0,token=1)),("init-argument",request(0,argument=1)),
     ("open-token",request(1,key=(1,2,3,4),token=1)),("open-argument",request(1,key=(1,2,3,4),argument=1)),
     ("complete-missing-token",request(2,argument=1)),("complete-bool",request(2,token=t,argument=2)),
     ("clone-missing-token",request(3)),("drop-missing-token",request(4)),("inspect-argument",request(5,argument=1)),
     ("poison-token",request(6,token=t)),("unexpected-key",request(5,key=(1,0,0,0))),
     ("reserved-word",request(5)[:64]+struct.pack("<Q",1)+bytes(24))]:
     with Actual(native,log,capacity=len(valid),initial=valid)as r:
      r.call(label,wire,INVALID);check(label,r.bytes()==valid)
    for label,offset,value in[
     ("state-magic",0,0),("state-count",8,MAXWORD),("state-serial",16,0),("state-poison",24,2),
     ("state-pending",32,99),("state-new-flag",40,2),("state-reserved",48,1),("cell-zero-token",128,0),
     ("cell-ref-overflow",168,MAX_REFS+2),("cell-reserved",176,1),("unused-tail",248,1)]:
     changed=bytearray(valid);struct.pack_into("<Q",changed,offset,value);changed=bytes(changed)
     with Actual(native,log,capacity=len(changed),initial=changed)as r:
      r.call(label,request(5),INVALID);check(label,r.bytes()==changed)
    with native.session(output_capacity=111,workspace_capacity=len(valid))as session:
     ctypes.memmove(ctypes.addressof(session._workspace),valid,len(valid));code,out,after=session.invoke_raw(request(5))
     check("short-output-preserves-full-state",code==CAPACITY and after==valid)
    for capacity in(0,64,127,129,191):
     with native.session(output_capacity=112,workspace_capacity=capacity)as session:
      code,out,after=session.invoke_raw(request(0));check("workspace-capacity-"+str(capacity),code==CAPACITY and after==bytes(capacity))
    changed=bytearray(valid);struct.pack_into("<Q",changed,168,MAX_REFS)
    with Actual(native,log,capacity=len(changed),initial=bytes(changed))as r:
     edge=r.call("strong-reference-last-nonfatal",request(3,token=t));check("declared strong-reference edge is exact",edge["refs"]==MAX_REFS+1)
     before_fatal=r.bytes();r.call("strong-reference-overflow-fatal",request(3,token=t),FATAL)
     check("reference overflow is explicitly fatal rather than unavailable",r.bytes()==before_fatal,scope="native fatal classification control")
     dropped=r.call("strong-reference-drop-at-edge",request(4,token=t));check("edge holder may drop without reset",dropped["refs"]==MAX_REFS)
    changed=bytearray(valid);struct.pack_into("<Q",changed,16,MAXWORD)
    with Actual(native,log,capacity=len(changed),initial=bytes(changed))as r:
     before_fatal=r.bytes();r.call("fresh-identity-exhaustion",request(1,key=(71,72,73,74)),FATAL)
     check("identity exhaustion cannot wrap to an earlier owner",r.bytes()==before_fatal)
     upgraded=r.begin((61,62,63,64));check("exhausted fresh identities do not prevent live weak upgrade",upgraded["status"]==0 and upgraded["token"]==t and upgraded["created"]==0)
    with Actual(native,log,capacity=len(valid),initial=valid)as r:
     second=r.begin((71,72,73,74));r.finish(second["token"]);changed=bytearray(r.bytes());struct.pack_into("<Q",changed,192,t)
     with Actual(native,log,capacity=len(changed),initial=bytes(changed))as bad:
      bad.call("duplicate-token-state",request(5),INVALID);check("token order refuses reused native identities",bad.bytes()==bytes(changed))
  passed=True
 finally:
  after={n:pin(p)for n,p in paths.items()};same=before==after
  (q/"source-after.json").write_text(json.dumps(after,sort_keys=True,indent=2)+"\n")
  report=dict(schema="hepta.runtime.durable-archive-registry-native-policy-controls.v1",passed=passed and same,source_unchanged=same,
   elapsed_seconds=time.monotonic()-start,controls=controls,control_count=len(controls),
   identity_inputs="synthetic trusted identity words for isolated registry policy; no filesystem admission claim",
   physical_owner_integration_qualified=False,original_arc_weak_differential_qualified=False,public_archive_qualified=False)
  (q/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
  print(json.dumps({k:report[k]for k in("passed","source_unchanged","elapsed_seconds","control_count")}),flush=True);assert same
if __name__=="__main__":main()
