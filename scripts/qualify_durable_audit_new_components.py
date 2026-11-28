# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual HIA compilation and private ABI controls, before public history routing."""
from pathlib import Path
import argparse,ctypes,hashlib,json,struct,time
from hia_native_build import NativeBuild
from hia_native_loader import NativeModule
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
U=lambda b,at:struct.unpack_from("<Q",b,at)[0]
def main():
 p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--hepta",type=Path,required=True)
 p.add_argument("--build",type=Path,required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--reuse-packer-manifest",type=Path);a=p.parse_args()
 q=a.output;q.mkdir(parents=True,exist_ok=False);start=time.monotonic()
 names=["descriptor_packer","activity","history"]
 paths=[Path(__file__),Path(__file__).parent/"hia_native_build.py",Path(__file__).parent/"hia_native_loader.py"]
 for name in names:paths.extend([a.source/("native/durable_audit_"+name+".hepta"),a.source/("native/durable_audit_"+name+"_composition.json")])
 paths.extend(a.source/n for n in("scripts/durable_audit_descriptor_code.json","scripts/durable_audit_descriptor_engine.S"))
 before={str(path):SHA(path.read_bytes())for path in paths}
 build=NativeBuild(a.hepta,a.build);modules={};manifests={}
 for name in names:
  if name=="descriptor_packer"and a.reuse_packer_manifest is not None:
   manifest=a.reuse_packer_manifest
   assert manifest==a.build/"modules/durable-audit-descriptor-packer-v1/manifest.json"
   raw=manifest.read_bytes();assert SHA(raw)=="0dfb841e126dbe7970577f24c75442805739e24794a71604940f026747fce301"
   metadata=json.loads(raw);build.bootstrap()
   assert metadata["compiler_sha256"]==build.compiler_sha256
   assert (manifest.parent/metadata["source"]).read_bytes()==(a.source/"native/durable_audit_descriptor_packer.hepta").read_bytes()
  else:
   manifest=build.compile("durable-audit-"+name.replace("_","-")+"-v1",a.source/("native/durable_audit_"+name+".hepta"),standalone=None)
  manifests[name]=str(manifest);modules[name]=NativeModule(manifest,manifest_sha256=SHA(manifest.read_bytes()))
  print(json.dumps(dict(phase="native-compiled",module=name,manifest=str(manifest)),sort_keys=True),flush=True)
 rows=[]
 def call(module,frame,output=4096,workspace=4096):
  with module.session(output_capacity=output,workspace_capacity=workspace)as session:return session.invoke_raw(frame)
 def note(name,**fields):rows.append(dict(name=name,passed=True,**fields))
 module=modules["descriptor_packer"];composition=json.loads((a.source/"native/durable_audit_descriptor_packer_composition.json").read_bytes())
 request=bytes.fromhex(composition["request_hex"]);code,out,w=call(module,request)
 assert code==composition["expected_output_bytes"]==3487
 blob=out[:code];assert SHA(blob)==composition["expected_output_sha256"]
 assert blob[:8]==b"HRAEPK01"and U(blob,8)==len(blob)and U(blob,16)==len(blob)-64
 expected=json.loads((a.source/"scripts/durable_audit_descriptor_code.json").read_bytes())
 assert blob[64:]==bytes.fromhex(expected["flat_hex"])and SHA(blob[64:])==expected["flat_sha256"]
 assert list(struct.unpack_from("<5Q",blob,24))==[expected["exports"][n]for n in("create","step","child_ack","take","destroy")]
 (q/"descriptor.engine").write_bytes(blob);note("actual-hia-emits-complete-mechanical-engine",bytes=len(blob),sha256=SHA(blob))
 invalid=[request[:i]for i in range(24)]+[request+b"\0"]
 for index in range(8):
  value=bytearray(request);value[index]^=1;invalid.append(bytes(value))
 for value in(0,2,2**64-1):invalid.append(request[:8]+struct.pack("<Q",value)+request[16:])
 for value in(1,2**64-1):invalid.append(request[:16]+struct.pack("<Q",value))
 for index,frame in enumerate(invalid):
  code,out,w=call(module,frame);assert code==0xffffffff and not any(out)
  note("packer-invalid-frame-"+str(index),input_hex=frame.hex(),code=code)
 for cap in(1,63,3486):
  code,out,w=call(module,request,output=cap);assert code==0xfffffffe and not any(out)
  note("packer-capacity-"+str(cap),code=code)
 code,out,w=call(module,request,output=3487);assert code==3487 and out==blob
 note("packer-exact-output-boundary")
 activity=modules["activity"]
 def action(op,token=0,value=0,id=b""):
  return b"HRAACTQ1"+struct.pack("<QQQ",op,token,value)+bytes(32)+(id if id else bytes(64))
 def invoke(session,frame,label,status=0):
  code,out,w=session.invoke_raw(frame);assert code==64 and out[:8]==b"HRAACTR1"and U(out,8)==status,(label,code,out.hex())
  assert U(out,56)==0;note(label,status=status,token=U(out,16),active=U(out,24),mapped=U(out,40),allocated=U(out,48))
  return out,w
 ident=b"a"*64
 with activity.session(output_capacity=64,workspace_capacity=128)as zero:
  invoke(zero,action(0),"activity-empty-arena-init")
  before_empty=ctypes.string_at(ctypes.addressof(zero._workspace),128)
  out,w=invoke(zero,action(1,id=ident),"activity-explicit-growth-before-insert",1)
  assert U(out,32)==256 and w==before_empty
 with activity.session(output_capacity=64,workspace_capacity=512)as session:
  ctypes.memmove(ctypes.addressof(session._workspace),before_empty,128)
  out,w=invoke(session,action(1,id=ident),"activity-grow-and-begin");first=U(out,16);assert first==1 and U(out,24)==1
  out,w=invoke(session,action(5,id=ident),"activity-query-live");assert U(out,24)==1
  invoke(session,action(3,first,0),"activity-finish-store-false")
  out,w=invoke(session,action(5,id=ident),"activity-query-finished-held");assert U(out,24)==0 and U(out,40)==1
  invoke(session,action(4,first),"activity-drop-last-holder")
  out,w=invoke(session,action(5,id=ident),"activity-query-removes-dead-weak");assert U(out,40)==U(out,48)==0
  out,w=invoke(session,action(1,id=ident),"activity-new-generation");second=U(out,16);assert second>first
  invoke(session,action(3,first,1),"activity-rejects-retired-token",3)
  out,w=invoke(session,action(1,id=ident),"activity-replace-map-retain-old-holder");third=U(out,16);assert third>second and U(out,40)==1 and U(out,48)==2
  invoke(session,action(3,second,0),"activity-old-holder-independent")
  out,w=invoke(session,action(5,id=ident),"activity-query-current-map");assert U(out,24)==1
  invoke(session,action(4,second),"activity-drop-unmapped-old-holder")
  invoke(session,action(2,third),"activity-clone-strong-holder")
  invoke(session,action(4,third),"activity-drop-one-clone")
  out,w=invoke(session,action(5,id=ident),"activity-remaining-clone-live");assert U(out,24)==1
  invoke(session,action(6),"activity-lock-poison")
  out,w=invoke(session,action(5,id=ident),"activity-poison-refuses-query",2)
  invoke(session,action(3,third,0),"activity-atomic-store-independent-of-registry-poison")
  invoke(session,action(4,third),"activity-last-drop-independent-of-registry-poison")
 history=modules["history"]
 for label,owner,cursor,limit in(
  ("invalid-owner",b"Z"*64,bytes(64),32),
  ("zero-limit",b"a"*64,bytes(64),0),
  ("oversized-limit",b"a"*64,bytes(64),33),
  ("invalid-cursor",b"a"*64,b"Z"*64,32)):
  flag=int(any(cursor));path=b"/unexecuted-private-root"
  frame=b"HRAHIS01"+struct.pack("<QQQ",limit,flag,len(path))+bytes(32)+owner+cursor+path
  code,out,w=call(history,frame,output=65568,workspace=1048608+2*len(frame))
  assert code==32 and out[:8]==b"HRAHYR01"and U(out,8)==1 and U(out,16)==0 and U(out,24)==32
  assert U(w,8)==0 and U(w,48)==U(w,56)==0
  note("history-"+label+"-before-effects")
 after={str(path):SHA(path.read_bytes())for path in paths};assert before==after
 report=dict(schema="hepta.runtime.audit-new-native-components.v1",state="PASS",rows=rows,controls=len(rows),manifests=manifests,
  source_before=before,source_after=after,source_unchanged=True,descriptor_output_sha256=SHA(blob),
  descriptor_flat_sha256=SHA(blob[64:]),actual_hia_packer=True,installed_assembler_required=False,
  activity_sequential_abi_only=True,public_history_qualified=False,elapsed_seconds=time.monotonic()-start)
 (q/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 print(json.dumps({k:v for k,v in report.items()if k not in("rows","source_before","source_after")},sort_keys=True),flush=True)
if __name__=="__main__":main()
