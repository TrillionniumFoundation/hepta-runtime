# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual native policy comparison against complete original audit page functions."""
from pathlib import Path
import argparse, hashlib, json, random, struct, subprocess, time, sys
SHA=lambda b:hashlib.sha256(b).hexdigest()
NAMES=("scripts/author_durable_common.py","scripts/author_durable_audit_page.py",
 "scripts/durable_audit_page_source.py.txt","native/durable_audit_page.hepta",
 "native/durable_audit_page_composition.json","native/request_storage_json.hepta",
 "scripts/hia_native_build.py","scripts/hia_native_loader.py",
 "scripts/prepare_durable_audit_page_reference.py","scripts/qualify_durable_audit_page.py",
 "src/mcp/runtime/request_audit.rs")
def files(root):
 return {n:{"bytes":len(raw),"sha256":SHA(raw)}for n in NAMES for raw in [(root/n).read_bytes()]}
def word(raw,at,value):struct.pack_into("<Q",raw,at,value)
def make_row(identity,owner="a"*64,tool="read_file",state=0,accepted=0,elapsed=None,live=False):
 raw=bytearray(256);identity=f"{identity:064x}"if type(identity)is int else identity
 raw[:64]=identity.encode();raw[64:128]=owner.encode();raw[128:128+len(tool)]=tool.encode()
 for at,value in ((192,len(tool)),(200,state),(208,accepted&((1<<64)-1)),(216,accepted>>64),(224,int(elapsed is not None)),(232,elapsed or 0),(240,int(live))):word(raw,at,value)
 return bytes(raw)
def frame(rows,owner="a"*64,limit=32,cursor=None,op=1,total=None,expired=False):
 raw=bytearray(192);raw[:8]=b"HRAQP001"
 for at,value in ((8,op),(16,len(rows)),(24,limit),(32,int(cursor is not None)),(40,0 if op==1 else len(rows)if total is None else total),(48,0 if op==1 else 1),(56,0 if op==1 else 1 if expired else 3_000_000_001)):word(raw,at,value)
 raw[64:128]=owner.encode()
 if cursor is not None:raw[128:192]=cursor.encode()
 return bytes(raw)+b"".join(rows)
def row_key(row):return (int.from_bytes(row[216:224],"little"),int.from_bytes(row[208:216],"little"),row[:64])
def corpus():
 all_cases=[]
 def add(name,raw):all_cases.append((name,raw))
 add("empty-hot",frame([]));add("empty-archive",frame([],op=2))
 for owner in ("A"*64,"g"*64,"_"*64,"0"*63+"Z"):
  add("owner-invalid",frame([],owner))
 for limit in (0,33,65535):add("history-limit-invalid",frame([],limit=limit))
 for cursor in ("g"*64,"0"*63+"Z"):add("cursor-invalid",frame([],cursor=cursor))
 add("cursor-missing",frame([],cursor="0"*64))
 for n in (1,2,3,31,32,33,127,128,129,511,512):
  rows=[make_row(i+1,owner=("a"*64 if i%3!=1 else "b"*64),tool=("z"*64 if i%5==0 else "read_file"),state=i%3,accepted=(i*13)%17,elapsed=(None if i%4==0 else (1<<64)-1 if i%4==1 else i),live=i%2==0)for i in range(n)]
  for order in (rows,list(reversed(rows))):
   for limit in (1,2,31,32):add(f"hot-{n}-{limit}",frame(order,limit=limit))
  sorted_own=sorted((r for r in rows if r[64:128]==b"a"*64),key=row_key)
  for at in sorted(set((0,len(sorted_own)//2,max(0,len(sorted_own)-1)))):
   for limit in (1,32):add(f"cursor-{n}-{at}",frame(list(reversed(rows)),limit=limit,cursor=sorted_own[at][:64].decode()))
  other=next((r for r in rows if r[64:128]==b"b"*64),None)
  if other:add("foreign-cursor",frame(rows,cursor=other[:64].decode()))
 for size in (0,1,2,31,32,33):
  for limit in (1,2,31,32):
   if size>limit+1:continue
   rows=[make_row(i+1,state=i%3,accepted=i//3,elapsed=None if i%2 else (1<<64)-1,live=bool(i%2))for i in range(size)]
   for total in (size,size+100000,(1<<64)-1):
    add(f"archive-{size}-{limit}-{total}",frame(rows,limit=limit,op=2,total=total))
   add(f"archive-deadline-{size}-{limit}",frame(rows,limit=limit,op=2,expired=True))
 for value in (0,1,(1<<32)-1,1<<32,(1<<53)+1,(1<<63)-1,1<<63,(1<<64)-1,1<<64,(1<<127)+13,(1<<128)-1):
  for state in range(3):
   for active in (False,True):
    row=make_row(1,accepted=value,state=state,elapsed=(1<<64)-1,live=active)
    add("u128-history",frame([row]));add("u128-archive",frame([row],op=2))
    add("u128-foreign-unselected",frame([make_row(1,owner="b"*64,accepted=value)],owner="a"*64))
 rng=random.Random(0x4852415150303031)
 for iteration in range(700):
  n=rng.randrange(0,40);rows=[]
  for i in range(n):
   rows.append(make_row(iteration*100+i+1,owner=rng.choice(("a"*64,"b"*64,"c"*64)),tool=rng.choice(("read_file","effective_config","_","z"*64)),state=rng.randrange(3),accepted=rng.randrange(0,20),elapsed=rng.choice((None,0,1,(1<<64)-1,rng.getrandbits(64))),live=rng.choice((False,True))))
  rng.shuffle(rows);owner=rng.choice(("a"*64,"b"*64,"c"*64));limit=rng.randrange(1,33)
  own=sorted((r for r in rows if r[64:128]==owner.encode()),key=row_key)
  cursor=rng.choice(own)[:64].decode()if own and iteration%3==0 else None
  add("seeded-history",frame(rows,owner,limit,cursor))
  got=own[:limit+1];add("seeded-archive",frame(got,owner,limit,op=2,total=len(own)))
 return all_cases
def frames(raw):
 result=[];at=0
 while at<len(raw):
  if len(raw)-at<4:raise ValueError("truncated original frame")
  size=int.from_bytes(raw[at:at+4],"little");at+=4
  if size>len(raw)-at:raise ValueError("truncated original body")
  result.append(raw[at:at+size]);at+=size
 return result
def main():
 p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--manifest",type=Path,required=True);p.add_argument("--oracle",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
 a.output.mkdir(parents=True,exist_ok=False);before=files(a.source);(a.output/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
 if Path(__file__).resolve()!=a.source.resolve()/"scripts/qualify_durable_audit_page.py":raise ValueError("qualification source root differs")
 manifest=a.manifest.read_bytes();oracle=a.oracle.read_bytes();cases=corpus()
 payload=b"".join(struct.pack("<I",len(raw))+raw for _,raw in cases);(a.output/"input.bin").write_bytes(payload)
 (a.output/"cases.json").write_text(json.dumps([{"name":name,"bytes":len(raw),"sha256":SHA(raw)}for name,raw in cases],sort_keys=True,indent=2)+"\n")
 t=time.monotonic();p=subprocess.run([str(a.oracle)],input=payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 (a.output/"original.stdout").write_bytes(p.stdout);(a.output/"original.stderr").write_bytes(p.stderr)
 if p.returncode:raise RuntimeError("original oracle failed")
 original=frames(p.stdout)
 if len(original)!=len(cases):raise ValueError("original case count differs")
 sys.path.insert(0,str(a.source/"scripts"));from hia_native_loader import NativeModule
 actual=[];controls=[];start=time.monotonic()
 with NativeModule(a.manifest,manifest_sha256=SHA(manifest))as native:
  with native.session(output_capacity=65536,workspace_capacity=16384)as session:
   for index,((name,raw),expected)in enumerate(zip(cases,original)):
    got=session.invoke(raw);actual.append(got)
    if got!=expected:
     (a.output/"first-difference.json").write_text(json.dumps(dict(index=index,name=name,expected_hex=expected.hex(),actual_hex=got.hex()),sort_keys=True,indent=2)+"\n")
     raise AssertionError(f"original page mismatch {index} {name}")
  valid=frame([make_row(1)])
  negative=[b"",valid[:191],b"badmagic"+valid[8:],valid+b"x"]
  for at,value in ((8,0),(8,3),(16,2),(40,1),(48,1),(56,1),(128,1)):
   raw=bytearray(valid);word(raw,at,value);negative.append(bytes(raw))
  for at,value in ((192+192,0),(192+192,65),(192+200,3),(192+224,2),(192+232,1),(192+240,2),(192+248,1)):
   raw=bytearray(valid);word(raw,at,value);negative.append(bytes(raw))
  negative += [frame([make_row(1),make_row(1)]),frame([make_row(1,owner="b"*64)],op=2),
               frame([make_row(2,accepted=2),make_row(1,accepted=1)],op=2),
               frame([make_row(1)],op=2,total=0)]
  for index,raw in enumerate(negative):
   code,out,_=native.invoke_raw(raw,output_capacity=65536,workspace_capacity=16384,output_fill=0x6d,workspace_fill=0x3c)
   if code!=0xffffffff or out!=bytes([0x6d])*len(out):raise AssertionError(f"private frame control {index}: {code}")
   controls.append({"kind":"private-frame","index":index,"return":code})
  for output_capacity,workspace_capacity in ((0,16384),(31,16384),(32,16384),(512,16383)):
   code,out,_=native.invoke_raw(valid,output_capacity=output_capacity,workspace_capacity=workspace_capacity,output_fill=0x6d,workspace_fill=0x3c)
   if code!=0xfffffffe or out!=bytes([0x6d])*len(out):raise AssertionError("capacity no-output control")
   controls.append({"kind":"capacity","out":output_capacity,"workspace":workspace_capacity,"return":code})
 elapsed=time.monotonic()-start
 output=b"".join(struct.pack("<I",len(raw))+raw for raw in actual);(a.output/"native.stdout").write_bytes(output)
 after=files(a.source);(a.output/"source-after.json").write_text(json.dumps(after,sort_keys=True,indent=2)+"\n")
 if after!=before or a.manifest.read_bytes()!=manifest or a.oracle.read_bytes()!=oracle:raise ValueError("source or actual implementation changed")
 report=dict(schema="hepta.runtime.durable-audit-page-qualification.v1",state="PASS",scope="private validated-row history policy and archive rendering; filesystem/public routing remain separate",original_cases=len(cases),native_calls=len(cases)+len(controls),controls=controls,source_unchanged=True,original_sha256=SHA(p.stdout),native_sha256=SHA(output),input_sha256=SHA(payload),oracle_sha256=SHA(oracle),manifest_sha256=SHA(manifest),native_seconds=elapsed,total_seconds=time.monotonic()-t)
 if output!=p.stdout:raise AssertionError("whole output differs")
 (a.output/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n");print(json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
