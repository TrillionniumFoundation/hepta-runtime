# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Real native refusals and boundary states, supplemental to nine unchanged thread tests."""
from pathlib import Path
import argparse,ctypes,hashlib,json,struct,sys
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def request(op,now=0,deadline=None,ticket=0,flags=0):
 return b"HRAFL001"+struct.pack("<7Q",op,now,int(deadline is not None),deadline or 0,ticket,flags,0)
def word(raw,at,value):
 out=bytearray(raw);struct.pack_into("<Q",out,at,value);return bytes(out)
def main():
 p=argparse.ArgumentParser();p.add_argument("--manifest",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
 a.output.mkdir(exist_ok=False,parents=True);manifest=a.manifest.read_bytes()
 sys.path.insert(0,str(Path(__file__).resolve().parent));from hia_native_loader import NativeModule
 results=[];complete=[]
 with NativeModule(a.manifest,manifest_sha256=SHA(manifest))as native:
  with native.session(output_capacity=64,workspace_capacity=512)as session:
   def invoke(raw):
    code,out,state=session.invoke_raw(raw);complete.append(dict(input_hex=raw.hex(),code=code,output_hex=out.hex(),state_hex=state.hex()));return code,out,state
   assert invoke(request(0))[0]==64
   clean=bytes(session._workspace.raw[:512])
   inputs=[b"",request(0)[:63],b"BADFRAME"+request(0)[8:],request(11),request(1,flags=16),request(1,deadline=None)+b"x",word(request(1),24,2),word(request(1),32,1),word(request(1),56,1),request(3,ticket=999)]
   mutations=[(0,0),(16,2),(32,1),(40,2),(48,2**64-1),(56,1),(120,1)]
   cases=[("frame-"+str(i),raw,clean)for i,raw in enumerate(inputs)]
   cases.extend(("state-"+str(at),request(1),word(clean,at,value))for at,value in mutations)
   for label,raw,state in cases:
    ctypes.memmove(session._workspace,state,len(state));ctypes.memset(session._output,0x6d,64)
    code,out,after=invoke(raw)
    assert code==0xffffffff and out==b"m"*64 and after==state,(label,code)
    results.append(dict(name=label,refused=True,unchanged=True))
   ctypes.memmove(session._workspace,clean,len(clean))
   code,out,state=invoke(request(2,now=1,deadline=10));assert code==64 and struct.unpack_from("<Q",out,8)[0]==1
   assert struct.unpack_from("<Q",out,16)[0]==0
   assert struct.unpack_from("<Q",invoke(request(3,now=2,deadline=10))[1],8)[0]==2
   assert struct.unpack_from("<Q",invoke(request(4,now=3,deadline=10))[1],8)[0]==3
   held=bytes(session._workspace.raw[:512]);assert struct.unpack_from("<Q",held,32)[0]==1
   for label,raw in (("reticket",request(7,now=20,deadline=10,ticket=1)),("altered-deadline",request(7,now=20,deadline=11)),("writer-release-reader",request(6,now=20,deadline=10)),("double-admit",request(3,now=4,deadline=10))):
    ctypes.memset(session._output,0x6d,64);code,out,state=invoke(raw)
    assert code==0xffffffff and state==held and out==b"m"*64
    results.append(dict(name=label,refused=True,unchanged=True))
   # Merely passing the deadline cannot release an actual reader's custody.
   assert bytes(session._workspace.raw[:512])==held
   code,out,state=invoke(request(7,now=20,deadline=10));assert code==64 and struct.unpack_from("<Q",out,8)[0]==4 and struct.unpack_from("<Q",state,32)[0]==0
   results.append(dict(name="expired-owner-held-until-finish",passed=True))
   snapshot=state;ctypes.memset(session._output,0x6d,64);code,out,state=invoke(request(7,now=21,deadline=10));assert code==0xffffffff and state==snapshot and out==b"m"*64
   results.append(dict(name="finished-guard-not-replayed",refused=True,unchanged=True))
   ctypes.memmove(session._workspace,clean,len(clean))
   exhausted=word(clean,8,2**64-1);ctypes.memmove(session._workspace,exhausted,len(exhausted))
   code,out,state=invoke(request(1));assert code==64 and struct.unpack_from("<Q",out,8)[0]==5 and state==exhausted
   results.append(dict(name="ticket-exhaustion-no-wrap",refused=True,unchanged=True))
  with native.session(output_capacity=64,workspace_capacity=128)as small:
   assert small.invoke_raw(request(0))[0]==64;before=small._workspace.raw[:128]
   code,out,after=small.invoke_raw(request(1));assert code==64 and struct.unpack_from("<Q",out,8)[0]==7 and struct.unpack_from("<Q",out,24)[0]==192 and before==after
   results.append(dict(name="growth-is-capacity-not-admission-ceiling",passed=True,required=192,unchanged=True))
  code,out,state=native.invoke_raw(request(1),output_capacity=63,workspace_capacity=128,output_fill=109,workspace_fill=60)
  assert code==0xfffffffe and out==b"m"*63 and state==b"<"*128
  results.append(dict(name="short-output-no-state-effects",refused=True,unchanged=True))
 if a.manifest.read_bytes()!=manifest:raise ValueError("native manifest changed")
 (a.output/"complete-observations.json").write_text(json.dumps(complete,sort_keys=True,indent=2)+"\n")
 report=dict(state="PASS",controls=len(results),results=results,manifest_sha256=SHA(manifest),scope="native protocol/state refusals; original nine unchanged threaded methods retained separately")
 (a.output/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n");print(json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
