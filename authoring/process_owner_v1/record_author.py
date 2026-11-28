"""Generate an independent raw JobRecord decoder with complete u128 integers."""
from pathlib import Path
import argparse,copy,hashlib,json,re,stat,types
SHA=lambda x:hashlib.sha256(x).hexdigest()
CANON=lambda x:json.dumps(x,sort_keys=True,separators=(",",":")).encode()
ORIGINAL_SHA="2a2758e62ba30773c91a9709bba5d1a2efb133b9c4edc4f49b330630af1aa0fd"
FIELDS=(
 ("execution_mode",11,False),("system_jobctl",2,False),
 ("id",1,True),("host",1,True),("ssh_target",1,True),("unit",1,True),
 ("remote_job_dir",1,True),("executable",1,True),("args",201,True),
 ("cwd",1001,False),("env_keys",201,True),("created_unix_ms",8,True),
 ("idempotency_key",1001,False),("request_fingerprint",3,True),
 ("request_digest",1001,False),("launch_state",1,False),("launch_error",1001,False))
def module(name,path,captured):
 out=types.ModuleType(name);out.__file__=str(path);out.__package__=""
 exec(compile(captured,str(path),"exec"),out.__dict__);return out
def schema():
 out=["def record_schema(w:mutbuf) -> u64:"]
 def put(at,v):out.append(f"    put(w,{at},{v})")
 mask=sum(1<<i for i,(_,_,required) in enumerate(FIELDS) if required)
 for at,v in ((9024,18432),(9032,len(FIELDS)),(9040,mask),(9048,0)):put(at,v)
 cursor=19600
 for i,(name,kind,required) in enumerate(FIELDS):
  at=18432+i*40
  for position,v in ((at,cursor),(at+8,len(name)),(at+16,kind),(at+24,0),(at+32,int(required))):put(position,v)
  raw=name.encode()
  for j in range(0,len(raw),8):put(cursor+j,int.from_bytes(raw[j:j+8].ljust(8,b"\0"),"little"))
  cursor+=((len(raw)+7)//8)*8
 assert cursor<21000
 out.append("    return 0")
 return "\n".join(out)+"\n"
def main():
 p=argparse.ArgumentParser();p.add_argument("--hepta",type=Path,required=True);p.add_argument("--source",type=Path,default=Path(__file__).resolve().parents[2]);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
 root=a.source.resolve(strict=True);out=a.output.absolute()
 assert not out.exists()
 names=["authoring/process_owner_v1/record_author.py","authoring/process_owner_v1/record.pseudo","authoring/public_publication_v1/source_support.py","native/config_json_span.hepta","src/mcp/runtime/jobs.rs","src/mcp/runtime/config.rs"]
 def take(name):
  p=root/name;st=p.lstat();raw=p.read_bytes();end=p.lstat()
  assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and p.resolve()==p
  assert all(getattr(st,k)==getattr(end,k) for k in ("st_dev","st_ino","st_mode","st_size","st_mtime_ns","st_ctime_ns"))
  return raw
 before={n:take(n) for n in names}
 assert SHA(before[names[3]])==ORIGINAL_SHA
 schema_text=before[names[4]].decode().split("macro_rules! job_record_schema {",1)[1].split("job_record_schema!(JobRecord, String);",1)[0]
 actual=re.findall(r"^\s*([a-z_]+):",schema_text,re.M)
 assert actual==[n for n,_,_ in FIELDS],actual
 support=module("_process_record_support",root/names[2],before[names[2]]);api=support.tools(a.hepta);assemble,render=api[3:]
 original=assemble(before[names[3]]).as_dict();patched=copy.deepcopy(original)
 # Only the protocol constants of the two complete request readers and the
 # complete arena emitter change; their entire remaining function AST is retained.
 changed_constants={}
 for index,old,new in ((0,b"HRCFGJ01",b"HPRJRQ01"),(40,b"HRCFGJ01",b"HPRJRQ01"),(41,b"HRCFGA01",b"HPRJRA01")):
  count=0
  for block in patched["functions"][index]["blocks"]:
   for op in block["ops"]:
    if op["op"]=="const" and op["attrs"].get("value")==int.from_bytes(old,"little"):
     op["attrs"]["value"]=int.from_bytes(new,"little");count+=1
  assert count==1,(index,count)
  changed_constants[f"f{index}"]={"old":old.decode(),"new":new.decode(),"count":count}
 # Mode 3 is a new explicit JobRecord pretty renderer.  Keep the entire
 # original parser except this fixed three-value admission expression.
 mode_fn=patched["functions"][40]
 mode_block=next(b for b in mode_fn["blocks"] if b["id"]=="b4")
 expected={"args":["v34","v36"],"attrs":{},"op":"bool.and","out":[{"name":"v37","type":"bool"}]}
 assert mode_block["ops"][-1]==expected
 new_names=("v2201","v2202","v2203")
 existing={x["name"] for b in mode_fn["blocks"] for x in b["params"]}
 existing.update(x["name"] for b in mode_fn["blocks"] for op in b["ops"] for x in op["out"])
 assert not (set(new_names)&existing)
 mode_block["ops"][-1:]=[
  {"args":["v34","v36"],"attrs":{},"op":"bool.and","out":[{"name":"v2201","type":"bool"}]},
  {"args":[],"attrs":{"value":3},"op":"const","out":[{"name":"v2202","type":"u64"}]},
  {"args":["v26","v2202"],"attrs":{},"op":"compare.ne","out":[{"name":"v2203","type":"bool"}]},
  {"args":["v2201","v2203"],"attrs":{},"op":"bool.and","out":[{"name":"v37","type":"bool"}]}]
 aliases={"read":"f39","get":"f37","put":"f38","node_get":"f6","node_put":"f7","allocate":"f4","number_span":"f34","emit_byte":"f14"}
 clones={}
 for index,name in ((0,"entry"),(1,"value"),(2,"initialize"),(12,"emit_document"),(13,"scalar"),(14,"emit_byte"),(19,"schema_init"),(24,"type_map"),(41,"output_finish")):
  fn=copy.deepcopy(patched["functions"][index]);target=f"f{len(patched['functions'])}";fn["name"]=target
  patched["functions"].append(fn);aliases["retained_"+name]=target;aliases[name]=f"f{index}";clones[target]=index
 aliases["raw_emit"]=aliases["retained_emit_byte"]
 constants={"REQUEST":int.from_bytes(b"HPRJRQ01","little"),"LAUNCHED":int.from_bytes(b"launched","little"),"INVALID":0xffffffff,"CAPACITY":0xfffffffe,"INVALID_EDGE":0xfffffffc}
 raw,names_out,proof=support.compile_delta(api,render(patched).encode(),aliases,before[names[1]].decode()+"\n"+schema(),constants,"runtime_process_record")
 after=assemble(raw).as_dict();lookup={f["name"]:f for f in after["functions"]}
 retained={}
 replaced={0,1,2,12,13,14,19,24,41}
 for index,fn in enumerate(original["functions"]):
  if index in replaced:continue
  expect=patched["functions"][index]
  assert lookup[fn["name"]]==expect,(index,"full retained AST")
  retained[fn["name"]]=SHA(CANON(expect))
 for target,index in clones.items():
  fn=copy.deepcopy(lookup[target]);fn["name"]=f"f{index}"
  assert fn==patched["functions"][index],(target,index)
 assert len(raw)<=1048576
 assert all(take(n)==v for n,v in before.items())
 out.mkdir()
 report={"schema":"hepta.runtime.process-record-author.v1",**proof,"aliases":names_out,"input_files":{n:{"bytes":len(v),"sha256":SHA(v)} for n,v in before.items()},"original_parser_sha256":ORIGINAL_SHA,"fixed_protocol_constant_changes":changed_constants,"relocated_exact_functions":clones,"retained_exact_original_functions":retained,"field_order":[x[0] for x in FIELDS],"raw_limit":4194304,"durable_pretty_limit":4194304,"explicit_modes":[1,2,3],"fixed_mode_extension":{"function":"f40","block":"b4","old":[1,2],"new":[1,2,3],"after_sha256":SHA(CANON(mode_fn))},"pretty_private_header_words":[224,232,240,248],"created_unix_ms_bits":128,"duplicate_known_fields":"reject","unknown_fields":"retained original raw skip","source_bytes":len(raw),"source_sha256":SHA(raw),"native_compiled":False,"public_handler_qualified":False}
 (out/"process_record.hepta").write_bytes(raw);(out/"process_record_composition.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
 (out/"record.pseudo").write_text(before[names[1]].decode()+"\n"+schema())
 assert all(take(n)==v for n,v in before.items())
 print(json.dumps({k:report[k] for k in ("source_bytes","source_sha256","functions","blocks","operations")}),flush=True)
if __name__=="__main__":main()
