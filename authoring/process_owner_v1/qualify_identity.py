"""Capture native process request identity before reading the original Rust oracle."""
from pathlib import Path
import argparse,ctypes,gzip,hashlib,json,struct,sys,traceback
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
U=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
def encoded(value):return (json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"))+"\n").encode()
def lines(path):return [json.loads(row) for row in path.read_bytes().split(b"\n") if row]
def main():
 p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--qualification",type=Path,required=True);a=p.parse_args()
 s=a.source.resolve(strict=True);q=a.qualification.resolve(strict=True);sys.path.insert(0,str(s/"scripts"))
 from hia_native_loader import NativeModule
 modules={};frozen={}
 for row in json.loads((q/"compiled.json").read_bytes())["modules"]:
  path=Path(row["manifest"]);raw=path.read_bytes();assert SHA(raw)==row["manifest_sha256"];meta=json.loads(raw)
  for item in (path,path.parent/meta["image"],path.parent/meta["source"]):frozen[str(item)]=item.read_bytes()
  modules[row["name"]]=NativeModule(path,manifest_sha256=SHA(raw))
 d=q/"native";d.mkdir(mode=0o700)
 capture=gzip.open(d/"calls.bin.gz","wb",compresslevel=1);index=[];results=[];controls=[];offset=0
 identifiers={"serde_json_span":1,"process_params":2,"process_identity":3}
 def call(name,cid,label,wire,before,cap):
  nonlocal offset
  with modules[name].session(output_capacity=cap,workspace_capacity=len(before)) as session:
   if before:ctypes.memmove(session._workspace,before,len(before))
   if cap:ctypes.memset(session._output,165,cap)
   code,out,after=session.invoke_raw(wire)
  ordinal=len(index)+1;header=struct.pack("<8Q",ordinal,identifiers[name],cid,code,len(wire),cap,len(before),0)
  h=hashlib.sha256();size=0
  for raw in (header,wire,before,bytes([165])*cap,out,after):capture.write(raw);h.update(raw);size+=len(raw)
  index.append(dict(call=ordinal,owner=identifiers[name],case_id=cid,label=label,offset=offset,bytes=size,sha256=h.hexdigest(),return_code=code,input_sha256=SHA(wire),output_sha256=SHA(out),workspace_after_sha256=SHA(after),input_bytes=len(wire),output_capacity=cap,workspace_capacity=len(before)))
  offset+=size;return code,out,after,ordinal
 def complete(name,cid,wire,*,before=None,cap=None,label="semantic"):
  header,magic,needed_at={"serde_json_span":(32,b"HJSVR002",24),"process_params":(640,b"HPRPAR01",48),"process_identity":(64,b"HPRIDR01",40)}[name]
  if before is None:before=bytes(16512 if name=="serde_json_span" else 65536)
  if cap is None:cap=header
  calls=[]
  for _ in range(12):
   code,out,after,n=call(name,cid,label,wire,before,cap);calls.append(n)
   assert code==header and out[:8]==magic,(name,cid,code,out[:80].hex())
   status=U(out,8);needed=U(out,needed_at)
   if status in (2,3):
    assert out[header:]==bytes([165])*(cap-header)
    if status==2:
     assert len(before)<needed<=modules[name].metadata["workspace_capacity"];before=after+bytes(needed-len(after))
    else:
     assert cap<needed<=modules[name].metadata["output_capacity"];cap=needed;before=after
    continue
   assert needed==0 and status in ((0,1,5) if name=="serde_json_span" else (0,1))
   payload=(U(out,16) if name=="serde_json_span" else
            64+U(out,16) if name=="process_identity" else
            U(out,32) if status==0 else U(out,40))
   size=header+payload
   assert size<=cap and out[size:]==bytes([165])*(cap-size)
   return out[:size],calls
  raise AssertionError("capacity negotiation exhausted")
 passed=False;failure=None;representatives=[];keys=[]
 try:
  for row in lines(q/"cases.jsonl"):
   cid=row["case_id"];raw=row["raw_json"].encode()
   value,first=complete("serde_json_span",cid,b"HJSMS002"+struct.pack("<2Q",1,len(raw))+raw)
   assert U(value,8)==0,(cid,"identity JSON fixture was not admitted")
   canonical=value[32:]
   typed,second=complete("process_params",cid,b"HPRPAQ01"+struct.pack("<2Q",len(canonical),3)+canonical)
   assert U(typed,8)==0,(cid,"identity typed fixture was not admitted")
   wire=b"HPRIDQ01"+struct.pack("<5Q",1,len(typed),0,0,0)+typed
   out,third=complete("process_identity",cid,wire)
   assert U(out,8)==0 and U(out,24)==64 and U(out,48)==0 and U(out,56)==0
   binding=out[128:];digest=out[64:128].decode("ascii")
   assert len(binding)==U(out,16) and SHA(binding)==digest
   assert U(out,32)==int(digest[:16],16)
   results.append({"case_id":cid,"name":row["name"],"typed_hex":typed.hex(),"request_hex":wire.hex(),"expected_hex":out.hex(),"expected_code":64,"canonical":binding.decode(),"digest":digest,"fingerprint":U(out,32),"calls":first+second+third})
   if row["name"] in ("minimum","env-3","stdin-5","combined-191"):representatives.append((cid,wire,out))
   if row["name"]=="minimum" or row["name"].startswith("idempotency_key-"):keys.append(out)
  assert len(representatives)==4 and len(set(keys))==1
  for number,(cid,wire,full) in enumerate(representatives):
   need=133120+8*(len(wire)-48)
   for cap in (0,1,63):
    before=bytes([123])*need;code,out,after,n=call("process_identity",100000+number,"short-output",wire,before,cap)
    assert (code,out,after)==(0xfffffffe,bytes([165])*cap,before)
    controls.append({"label":"short-output","call":n,"fixture_case":cid})
   for cap in (64,len(full)-1,len(full),len(full)+17):
    code,out,after,n=call("process_identity",110000+number,"exact-extent",wire,bytes([123])*need,cap)
    assert code==64
    if cap<len(full):assert U(out,8)==3 and U(out,40)==len(full) and out[64:]==bytes([165])*(cap-64)
    else:assert out==full+bytes([165])*(cap-len(full))
    controls.append({"label":"exact-extent","call":n,"fixture_case":cid})
   for size in (0,1,need-1):
    before=bytes([123])*size;code,out,after,n=call("process_identity",120000+number,"work-growth",wire,before,len(full)+13)
    assert code==64 and U(out,8)==2 and U(out,40)==need and before==after
    resumed,calls=complete("process_identity",121000+number,wire,before=after+bytes(need-size),cap=len(full),label="growth-resume")
    assert resumed==full
    controls.append({"label":"work-growth","call":n,"resume":calls,"fixture_case":cid})
   before=bytes([123])*need
   for _ in range(3):
    code,out,before,n=call("process_identity",130000+number,"fresh-request-reused-workspace",wire,before,len(full)+9)
    assert code==64 and out==full+bytes([165])*9
    controls.append({"label":"workspace-reuse","call":n,"fixture_case":cid})
  wire=representatives[0][1];bad=[wire[:7],wire[:687],wire+b"x"]
  for at,value in [(0,0),(8,2),(16,len(wire)),(24,1),(32,1),(40,1),(48,0),(56,1),(64,1)]:
   raw=bytearray(wire);struct.pack_into("<Q",raw,at,value);bad.append(bytes(raw))
  for i,raw in enumerate(bad):
   code,out,after,n=call("process_identity",140000+i,"malformed-closed-frame",raw,bytes(133120+8*len(raw)),512)
   assert code==0xffffffff,(i,code,out[:64].hex())
   controls.append({"label":"malformed-closed-frame","call":n})
  passed=True
 except BaseException:
  failure=traceback.format_exc();(d/"failure.txt").write_text(failure)
 finally:
  capture.close()
  for module in modules.values():module.close()
  assert all(Path(path).read_bytes()==raw for path,raw in frozen.items())
  for name,rows in [("calls.jsonl",index),("native-results.jsonl",results),("controls.jsonl",controls)]:(d/name).write_bytes(b"".join(encoded(row) for row in rows))
  report={"passed":passed,"cases":len(results),"native_calls":len(index),"controls":len(controls),"raw_capture_bytes":offset,"source_image_manifest_terminal_stable":True,"original_results_read_during_capture":False,"scope":"complete original process request canonical binding, SHA256 and legacy fingerprint; no process effect or public routing qualification","failure":failure}
  (d/"capture.json").write_bytes(encoded(report));print(json.dumps(report),flush=True)
 if not passed:raise SystemExit(1)
 with gzip.open(d/"calls.bin.gz","rb") as f:
  for row in index:
   raw=f.read(row["bytes"]);assert len(raw)==row["bytes"] and SHA(raw)==row["sha256"]
  assert f.read(1)==b""
 reference=lines(q/"reference.jsonl");assert len(reference)==len(results);differences=[]
 for actual,expected in zip(results,reference):
  assert (actual["case_id"],actual["name"])==(expected["case_id"],expected["name"])
  for key in ("typed_hex","request_hex","expected_hex","expected_code","canonical","digest","fingerprint"):
   if actual[key]!=expected[key]:differences.append({"case_id":actual["case_id"],"name":actual["name"],"key":key,"actual":actual[key],"expected":expected[key]})
 report={"passed":not differences,"cases":len(results),"differences":differences,"every_native_binary_record_readback":True,"native_capture_closed_before_original_read":True}
 (d/"readback.json").write_bytes(encoded(report));print(json.dumps({**report,"differences":differences[:6]}),flush=True)
 raise SystemExit(0 if not differences else 1)
if __name__=="__main__":main()
