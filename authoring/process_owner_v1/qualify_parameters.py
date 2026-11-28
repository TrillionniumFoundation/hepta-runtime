"""Actual native process parameter capture and independent fixed Rust readback."""
from pathlib import Path
import argparse,ctypes,gzip,hashlib,json,struct,sys,traceback
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
U=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
def encoded(v):return (json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(",",":"))+"\n").encode()
def main():
 p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--qualification",type=Path,required=True);a=p.parse_args()
 s=a.source.resolve(strict=True);q=a.qualification.resolve(strict=True)
 sys.path.insert(0,str(s/"scripts"))
 from hia_native_loader import NativeModule
 spec=json.loads((q/"compiled.json").read_bytes())
 modules={}
 frozen={}
 for row in spec["modules"]:
  m=Path(row["manifest"]);raw=m.read_bytes();assert SHA(raw)==row["manifest_sha256"]
  data=json.loads(raw)
  for path in (m,m.parent/data["image"],m.parent/data["source"]):frozen[str(path)]=path.read_bytes()
  modules[row["name"]]=NativeModule(m,manifest_sha256=SHA(raw))
 d=q/"native";d.mkdir(mode=0o700)
 capture=gzip.open(d/"calls.bin.gz","wb",compresslevel=1);index=[];results=[];offset=0;controls=[]
 def call(name,cid,label,wire,before,cap):
  nonlocal offset
  mod=modules[name]
  with mod.session(output_capacity=cap,workspace_capacity=len(before)) as session:
   if before:ctypes.memmove(session._workspace,before,len(before))
   if cap:ctypes.memset(session._output,165,cap)
   code,out,after=session.invoke_raw(wire)
  number=len(index)+1;owner=1 if name=="serde_json_span" else 2
  head=struct.pack("<8Q",number,owner,cid,code,len(wire),cap,len(before),0)
  digest=hashlib.sha256();total=0
  for raw in (head,wire,before,bytes([165])*cap,out,after):
   capture.write(raw);digest.update(raw);total+=len(raw)
  index.append(dict(call=number,owner=owner,case_id=cid,label=label,offset=offset,bytes=total,
   return_code=code,input_bytes=len(wire),output_capacity=cap,workspace_capacity=len(before),
   record_sha256=digest.hexdigest(),input_sha256=SHA(wire),before_sha256=SHA(before),output_sha256=SHA(out),after_sha256=SHA(after)))
  offset+=total
  return code,out,after,number
 def complete(name,cid,wire,*,before=None,cap=None,label="semantic"):
  parser=name=="serde_json_span";header=32 if parser else 640;needed_at=24 if parser else 48
  magic=b"HJSVR002" if parser else b"HPRPAR01"
  before=bytes(16512 if parser else 65536) if before is None else before
  cap=header if cap is None else cap;calls=[]
  for _ in range(12):
   code,out,after,number=call(name,cid,label,wire,before,cap);calls.append(number)
   assert code==header and out[:8]==magic,(name,cid,code,out[:64].hex())
   status=U(out,8);needed=U(out,needed_at)
   if status in (2,3):
    assert out[header:]==bytes([165])*(cap-header)
    if status==2:
     assert len(before)<needed<=modules[name].metadata["workspace_capacity"]
     before=after+bytes(needed-len(after))
    else:
     assert cap<needed<=modules[name].metadata["output_capacity"]
     cap=needed;before=after
    continue
   assert needed==0 and status in ((0,1,5) if parser else (0,1)),(name,cid,status)
   size=header+(U(out,16) if parser else U(out,32) if status==0 else U(out,40))
   assert size<=cap and out[size:]==bytes([165])*(cap-size)
   return out[:size],calls
  raise AssertionError("capacity negotiation did not terminate")
 passed=False;failure=None;minimum={}
 try:
  rows=[json.loads(line) for line in (q/"cases.jsonl").read_text().splitlines()]
  for row in rows:
   cid=row["case_id"];kind=row["kind"];raw=row["raw_json"].encode()
   value,first=complete("serde_json_span",cid,b"HJSMS002"+struct.pack("<2Q",1,len(raw))+raw)
   result={"value_admitted":U(value,8)==0};second=[]
   if result["value_admitted"]:
    canonical=value[32:];wire=b"HPRPAQ01"+struct.pack("<2Q",len(canonical),kind)+canonical
    typed,second=complete("process_params",cid,wire)
    result.update(canonical=canonical.decode(),ok=U(typed,8)==0,frame_hex=typed.hex())
    if row["name"]=="minimum":minimum[kind]=(wire,typed)
   results.append({"case_id":cid,"kind":kind,"name":row["name"],"result":result,"value_calls":first,"parameter_calls":second})
  for kind,(wire,full) in minimum.items():
   size=max(len(wire),1024)+65536
   for cap in (0,1,639):
    before=bytes([123])*size;code,out,after,n=call("process_params",100000+kind,"short-output",wire,before,cap)
    assert (code,out,after)==(0xfffffffe,bytes([165])*cap,before)
    controls.append({"kind":kind,"label":"short-output","call":n})
   for cap in sorted(set((640,len(full)-1,len(full),len(full)+17))):
    if cap<640:continue
    code,out,after,n=call("process_params",110000+kind,"output-extent",wire,bytes([123])*size,cap)
    assert code==640
    if cap<len(full):assert U(out,8)==3 and U(out,48)==len(full) and out[640:]==bytes([165])*(cap-640)
    else:assert out==full+bytes([165])*(cap-len(full))
    controls.append({"kind":kind,"label":"output-extent","call":n})
   for work in (0,1,size-1):
    before=bytes([123])*work;code,out,after,n=call("process_params",120000+kind,"work-growth",wire,before,len(full)+11)
    assert code==640 and U(out,8)==2 and U(out,48)==size and before==after
    restored,calls=complete("process_params",121000+kind,wire,before=after+bytes(size-work),cap=len(full),label="growth-resume")
    assert restored==full
    controls.append({"kind":kind,"label":"work-growth","call":n,"resume":calls})
   dirty=bytes([123])*size
   for repeat in range(3):
    code,out,dirty,n=call("process_params",130000+kind,"ordinary-state-reuse",wire,dirty,len(full)+7)
    assert code==640 and out==full+bytes([165])*7
    controls.append({"kind":kind,"label":"ordinary-state-reuse","call":n})
  passed=True
 except BaseException:
  failure=traceback.format_exc();(d/"failure.txt").write_text(failure)
 finally:
  capture.close()
  for m in modules.values():m.close()
  assert all(Path(p).read_bytes()==raw for p,raw in frozen.items())
  (d/"calls.jsonl").write_bytes(b"".join(encoded(x) for x in index))
  (d/"native-results.jsonl").write_bytes(b"".join(encoded(x) for x in results))
  (d/"controls.jsonl").write_bytes(b"".join(encoded(x) for x in controls))
  report={"passed":passed,"cases":len(results),"native_calls":len(index),"controls":len(controls),
   "raw_capture_bytes":offset,"source_image_manifest_terminal_stable":True,"original_results_read_during_capture":False,
   "scope":"typed parameter and canonical JSON owner; no process effects or installed routing qualification","failure":failure}
  (d/"capture.json").write_bytes(encoded(report));print(json.dumps(report),flush=True)
 if not passed:raise SystemExit(1)
 # Reference results are opened only after the complete native stream is closed.
 reference=[json.loads(line) for line in (q/"reference.jsonl").read_text().splitlines()]
 assert len(reference)==len(results)
 differences=[]
 for actual,expected in zip(results,reference):
  assert (actual["case_id"],actual["kind"],actual["name"])==(expected["case_id"],expected["kind"],expected["name"])
  aa=actual["result"];ee=expected["result"]
  keys=["value_admitted"]+(["canonical","ok","frame_hex"] if ee["value_admitted"] else [])
  for key in keys:
   if aa.get(key)!=ee.get(key):differences.append({"case_id":actual["case_id"],"name":actual["name"],"key":key,"actual":aa.get(key),"expected":ee.get(key)})
 readback={"passed":not differences,"cases":len(results),"differences":differences,"native_capture_closed_before_reference_read":True}
 (d/"readback.json").write_bytes(encoded(readback))
 print(json.dumps({**readback,"differences":differences[:8]}),flush=True)
 raise SystemExit(0 if not differences else 1)
if __name__=="__main__":main()
