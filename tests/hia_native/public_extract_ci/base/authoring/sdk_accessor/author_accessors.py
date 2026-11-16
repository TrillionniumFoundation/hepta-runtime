"""Contract fixed accessor calls without changing parsing or byte accesses.

Copyright 2026 Muvon Un Limited.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
from pathlib import Path
import argparse,copy,hashlib,json,re,shutil,sys
sys.dont_write_bytecode=True
SPECS={
 "native/sdk_message_target.hepta":{"helpers":["f50","f51","f57"],
  "inline":["f42","f56","f61","f62","f63","f64","f65","f66","f71","f73"],
  "before":"4346674242b7f00cd97cee2b04e958a7552923623a79a1355d469c251add2968",
  "after":"3246ce5e5975851c71a4f487408f8ea5a69983f711614ea7d49d58c720be4961"},
 "native/serde_json_span.hepta":{"helpers":["f18","f19","f25"],
  "inline":["f10","f24","f32","f33","f34","f35","f36","f37","f42","f44","f66","f67","f68"],
  "before":"7a9355792f5044c9887c4194df5bc169664cf08fa8d084e8480c941fa2416a41",
  "after":"eb7bf96e7944d8d69fa0ee441ecbf3fc2a79daaa233a3f9706f0fc324eb39f7d"}}
def sha(b):return hashlib.sha256(b).hexdigest()
def canon(v):return json.dumps(v,sort_keys=True,separators=(",",":")).encode()
def op(line):
 m=re.fullmatch(r"  (v\d+):([A-Za-z0-9_]+) = ([A-Za-z0-9_.]+)\(([^)]*)\)(?: (.*))?",line)
 if not m:return None
 return dict(out=m[1],type=m[2],op=m[3],args=m[4].split(",") if m[4] else [],attrs=json.loads(m[5]) if m[5] else {})
def tokens(text,aliases,recursive=True):
 def sub(m):
  n=m[0];seen=set()
  if not recursive:return aliases.get(n,n)
  while n in aliases:
   assert n not in seen;seen.add(n);n=aliases[n]
  return n
 return re.sub(r"\bv\d+\b",sub,text)
def fid(text):return re.match(r"fn (f\d+)\(",text)[1]
def shorten(text):
 lines=text.split("\n");rawops=[v for l in lines if (v:=op(l))]
 aliases={};constants={};result=[]
 for line in lines:
  p=op(tokens(line,aliases))
  if p is None:result.append(tokens(line,aliases));continue
  if p["op"]=="const":constants[p["out"]]=p["attrs"]["value"]
  a,b=(p["args"]+[None,None])[:2];to=None
  if p["op"]=="int.add.wrap" and constants.get(b)==0:to=a
  if p["op"]=="int.add.wrap" and constants.get(a)==0:to=b
  if p["op"]=="int.shl.checked" and constants.get(b)==0:to=a
  if p["op"]=="bit.or" and constants.get(a)==0:to=b
  if p["op"]=="bit.or" and constants.get(b)==0:to=a
  if p["op"]=="bit.and" and constants.get(b)==255:
   uses=[q for q in rawops if p["out"] in q["args"]]
   if uses and all(q["op"]=="int.cast" and q["type"]=="u8" and q["attrs"].get("mode")=="wrap" for q in uses):to=a
  if to is not None:aliases[p["out"]]=to
  else:result.append(tokens(line,aliases))
 result=[tokens(l,aliases) for l in result]
 while True:
  uses=set()
  for line in result:
   body=line.split(" = ",1)[1] if op(line) else line
   uses.update(re.findall(r"\bv\d+\b",body))
  changed=False;kept=[]
  for line in result:
   p=op(line)
   safe=p is not None and (p["op"]=="const" or (p["op"]=="int.shr.checked" and len(p["args"])==2 and 0<=constants.get(p["args"][1],-1)<64))
   if safe and p["out"] not in uses:changed=True
   else:kept.append(line)
  result=kept
  if not changed:break
 result="\n".join(result);assert result!=text
 return result
def inline(text,wrappers,patches):
 name=fid(text);next_id=max(map(int,re.findall(r"\bv(\d+)\b",text)))+1;out=[]
 for line in text.split("\n"):
  p=op(line);callee=p["attrs"].get("function") if p and p["op"]=="call" else None
  if callee not in wrappers:out.append(line);continue
  w=wrappers[callee];params=re.search(r"\(([^)]*)\)",w.split("\n")[0])[1]
  params=[x.split(":")[0] for x in params.split(",") if x]
  assert len(params)==len(p["args"]) and p["type"]=="u64"
  body=[l for l in w.split("\n")[2:] if l.startswith("  ")]
  ret=re.fullmatch(r"  ret\((v\d+)\)",body[-1]);assert ret and ret[1] not in params
  mapping=dict(zip(params,p["args"]))
  for l in body[:-1]:
   q=op(l)
   if q:
    mapping[q["out"]]=p["out"] if q["out"]==ret[1] else "v"+str(next_id)
    if q["out"]!=ret[1]:next_id+=1
  generated=[tokens(l,mapping,False) for l in body[:-1]]
  out.extend(generated);patches.append(dict(function=name,callee=callee,original=line,replacement=generated))
 return "\n".join(out)
def helper_trace(text):
 """Exact 64-bit symbolic values and ordered checked-byte events; no execution."""
 mask=(1<<64)-1
 def c(n):return ("const",n&mask)
 def bits(x,width=64):
  if x[0]=="const":return tuple((x[1]>>i)&1 for i in range(width))
  assert x[0]=="bits";return x[1][:width]+(0,)*max(0,width-len(x[1]))
 def addr(x):
  if x[0]=="const":return x
  assert x[0]=="address";return x
 values={"v0":("buffer","v0"),"v1":("address",0),"v2":("bits",tuple("input:"+str(i) for i in range(64)))}
 events=[];answer=None
 for line in text.split("\n")[2:]:
  if line.startswith("  ret("):answer=bits(values[re.fullmatch(r"  ret\((v\d+)\)",line)[1]]);continue
  store=re.fullmatch(r"  _ = buffer.store\((v\d+),(v\d+),(v\d+)\)",line)
  if store:
   events.append(("store",values[store[1]],addr(values[store[2]]),bits(values[store[3]],8)));continue
  p=op(line)
  if p is None:assert line in ("end","");continue
  a=[values[x] for x in p["args"]];kind=p["op"]
  if kind=="const":v=c(p["attrs"]["value"])
  elif kind=="int.add.wrap":
   if a[0][0]=="address" and a[1][0]=="const":v=("address",(a[0][1]+a[1][1])&mask)
   elif a[1][0]=="address" and a[0][0]=="const":v=("address",(a[1][1]+a[0][1])&mask)
   else:assert a[0][0]==a[1][0]=="const";v=c(a[0][1]+a[1][1])
  elif kind=="int.cast":
   assert p["attrs"]=={"mode":"wrap"}
   if p["type"]=="usize":v=addr(a[0])
   else:
    width=int(p["type"][1:]);v=("bits",bits(a[0],width))
  elif kind=="buffer.load":
   assert a[0]==("buffer","v0")
   at=addr(a[1]);idx=len(events);events.append(("load",a[0],at))
   v=("bits",tuple("load:"+str(idx)+":"+str(i) for i in range(8)))
  elif kind in ("int.shl.checked","int.shr.checked"):
   assert a[1][0]=="const" and 0<=a[1][1]<64
   b=bits(a[0]);n=a[1][1]
   v=("bits",((0,)*n+b[:64-n]) if kind=="int.shl.checked" else b[n:]+(0,)*n)
  elif kind in ("bit.and","bit.or"):
   def bit(x,y):
    if kind=="bit.and":
     if x==0 or y==0:return 0
     if x==1:return y
     if y==1 or x==y:return x
    else:
     if x==1 or y==1:return 1
     if x==0:return y
     if y==0 or x==y:return x
    return (kind,x,y)
   v=("bits",tuple(bit(x,y) for x,y in zip(bits(a[0]),bits(a[1]))))
  else:raise AssertionError(kind)
  values[p["out"]]=v
 assert answer is not None and len(events)==8
 assert [e[2] for e in events]==[("address",i) for i in range(8)]
 return dict(events=events,return_bits=answer)
def generate(text,spec):
 parts=re.split(r"(?m)(?=^fn )",text);head=parts.pop(0);before={fid(f):f for f in parts}
 wrappers={}
 for name in spec["inline"]:
  f=before[name]
  assert len(re.findall(r"(?m)^block ",f))==1
  assert not re.search(r"\b(?:borrow|loan|owner|buffer\.new|buffer\.try_new|chain)\b",f)
  wrappers[name]=f
 patches=[];helpers={};after=[]
 for f in parts:
  name=fid(f)
  if name in spec["helpers"]:
   new=shorten(f);assert helper_trace(f)==helper_trace(new)
   helpers[name]=dict(before=f,after=new,ordered_symbolic_byte_trace_sha256=sha(canon(helper_trace(f))))
   f=new
  after.append(inline(f,wrappers,patches))
 result=head+"".join(after);restored=result
 for p in reversed(patches):
  f=next(f for f in re.split(r"(?m)(?=^fn )",restored) if f.startswith("fn "+p["function"]+"("))
  needle="\n".join(p["replacement"]);assert f.count(needle)==1
  back=f.replace(needle,p["original"],1);assert restored.count(f)==1;restored=restored.replace(f,back,1)
 for p in helpers.values():
  assert restored.count(p["after"])==1;restored=restored.replace(p["after"],p["before"],1)
 assert restored==text
 return result,patches,helpers
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for key in ("baseline","expected","output","hepta"):p.add_argument("--"+key,type=Path,required=True)
 a=p.parse_args();baseline=a.baseline.resolve(strict=True);expected=a.expected.resolve(strict=True);out=a.output.resolve()
 assert not out.exists()
 sys.path.insert(0,str(a.hepta.resolve(strict=True)))
 from hepta.hia_agent_assembly import assemble_program
 changes={};generated={}
 for name,spec in SPECS.items():
  old=(baseline/name).read_bytes();assert sha(old)==spec["before"]
  text,patches,helpers=generate(old.decode(),spec);raw=text.encode()
  assert sha(raw)==spec["after"] and raw==(expected/name).read_bytes()
  before=assemble_program(old).as_dict();after=assemble_program(raw).as_dict()
  assert before["module"]==after["module"] and before["schema"]==after["schema"]
  b={f["name"]:f for f in before["functions"]};c={f["name"]:f for f in after["functions"]};assert b.keys()==c.keys()
  for fn in b:
   assert b[fn]["params"]==c[fn]["params"] and b[fn]["returns"]==c[fn]["returns"] and b[fn]["effects"]==c[fn]["effects"] and b[fn]["entry"]==c[fn]["entry"]
   assert len(b[fn]["blocks"])==len(c[fn]["blocks"])
   for x,y in zip(b[fn]["blocks"],c[fn]["blocks"]):
    assert x["id"]==y["id"] and x["params"]==y["params"]
    if fn not in helpers:assert x["term"]==y["term"]
  changes[name]=dict(before_sha256=sha(old),after_sha256=sha(raw),after_bytes=len(raw),
   wrappers=spec["inline"],contracted_call_sites=len(patches),inverse_recovers_full_source=True,
   all_function_signatures_and_cfg_edges_retained=True,
   helper_proofs={k:{"before_sha256":sha(v["before"].encode()),"after_sha256":sha(v["after"].encode()),"ordered_symbolic_byte_trace_sha256":v["ordered_symbolic_byte_trace_sha256"]} for k,v in helpers.items()},
   changed_functions={n:{"before_ast_sha256":sha(canon(b[n])),"after_ast_sha256":sha(canon(c[n]))} for n in b if b[n]!=c[n]},
   exact_retained_functions={n:sha(canon(b[n])) for n in b if b[n]==c[n]},
   patches_sha256=sha(canon(patches)),ordinary_input_predicates_added=False,parser_or_formatter_algorithm_changed=False)
  generated[name]=raw
 shutil.copytree(baseline,out)
 for name,raw in generated.items():(out/name).write_bytes(raw)
 proof=dict(schema="hepta.runtime.fixed-accessor-call-contraction.v1",author_sha256=sha(Path(__file__).read_bytes()),
  changes=changes,all_eight_checked_byte_accesses_in_original_order=True,
  u64_wrapping_addresses_and_first_bounds_trap_preserved=True,put_partial_write_prefix_preserved=True,
  no_native_or_rust_executions=True,full_public_domain_qualified=False,fresh_ci_qualified=False)
 (out/"native/fixed_accessor_contraction.json").write_text(json.dumps(proof,sort_keys=True,indent=2)+"\n")
 binding=json.loads((baseline/"native/runtime_mcp_sources.json").read_bytes())
 binding["sources"]={q.relative_to(out).as_posix():{"bytes":q.stat().st_size,"sha256":sha(q.read_bytes())} for q in sorted(out.rglob("*")) if q.is_file() and q!=out/"native/runtime_mcp_sources.json"}
 (out/"native/runtime_mcp_sources.json").write_text(json.dumps(binding,sort_keys=True,indent=2)+"\n")
 print(json.dumps(proof,sort_keys=True))
if __name__=="__main__":main()
