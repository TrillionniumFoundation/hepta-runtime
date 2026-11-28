# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Raw typed comparisons against original derives in the complete abc9 Cargo graph."""
from pathlib import Path
import argparse,hashlib,itertools,json,random,struct,subprocess,time,sys
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
PATHS=("scripts/author_durable_common.py","scripts/author_durable_audit_archive_records.py",
 "scripts/durable_audit_archive_records_source.py.txt","native/durable_audit_archive_records.hepta",
 "native/durable_audit_archive_records_composition.json","native/request_storage_json.hepta",
 "src/mcp/runtime/request_audit.rs","src/mcp/runtime/request_archive_store.rs",
 "scripts/prepare_durable_audit_archive_records_reference.py","scripts/qualify_durable_audit_archive_records.py",
 "scripts/hia_native_build.py","scripts/hia_native_loader.py")
def pins(root):return{n:dict(bytes=len(raw),sha256=SHA(raw))for n in PATHS for raw in[(root/n).read_bytes()]}
def packet(kind,raw):return b"HRAATQ01"+struct.pack("<QQQ",kind,len(raw),0)+raw
def cases():
 canonical=lambda v:json.dumps(v,ensure_ascii=True,separators=(",",":")).encode()
 bases={1:dict(root_device=0,root_inode=1,archive_device=2,archive_inode=3),
  2:dict(format=1,root=[0,1],legacy=[2,3],archive=[4,5],shards=[[6,7],[8,9]]),
  3:dict(format=1,root=[0,1],legacy=[2,3],archive=None,shards=[])}
 rows=[];seen=set()
 def add(kind,label,raw):
  key=(kind,raw)
  if key not in seen:rows.append((kind,label,raw));seen.add(key)
 tokens=[b"0",b"1",b"4294967295",b"4294967296",b"18446744073709551615",b"18446744073709551616",
  b"340282366920938463463374607431768211455",b"-0",b"-1",b"00",b"01",b"+1",b"1.0",b"1e0",b"-0.0",
  b"1e999",b"NaN",b"Infinity",b"null",b"true",b"false",b'"0"',b"[]",b"{}"]
 rng=random.Random(0xA0D1712)
 for kind,base in bases.items():
  raw=canonical(base)
  add(kind,"base",raw);add(kind,"struct-sequence",canonical(list(base.values())))
  for order in itertools.permutations(base):
   add(kind,"field-order",canonical({n:base[n]for n in order}))
  for name in base:
   row=dict(base);del row[name];add(kind,"missing-"+name,canonical(row))
   escaped="".join("\\u%04x"%ord(ch)for ch in name)
   add(kind,"escaped-key-"+name,raw.replace(canonical(name),('"'+escaped+'"').encode()))
   for spelling in(name,escaped):
    for value in(b"null",canonical(base[name])):
     add(kind,"duplicate-"+name,raw[:-1]+b',"' +spelling.encode()+b'":'+value+b"}")
   for v in(None,False,True,0,-1,0.0,1.5,"",{},[],[0],[0,1,2],{"0":0}):
    add(kind,"wrong-type-"+name,canonical(dict(base,**{name:v})))
  for v in("",None,0,[],{},False):
   add(kind,"unknown-field",canonical(dict(base,unknown=v)))
  add(kind,"unknown-unicode-key",raw[:-1]+b',"\\ud800":0}')
  for count in range(len(base)+3):
   add(kind,"sequence-length-"+str(count),canonical(list(base.values())[:count]+[None]*max(0,count-len(base))))
  for suffix in(b"",b" ",b"\t\r\n",b"null",b"\x00",b"{}",b"[]",b"\xff"):
   add(kind,"trailing",raw+suffix)
  bound=2048 if kind==1 else 65536
  for size in(0,1,17,bound-1-len(raw),bound-len(raw),bound+1-len(raw)):
   add(kind,"raw-bound-"+str(size),b" "*size+raw)
  for i in range(len(raw)+1):
   add(kind,"truncated-"+str(i),raw[:i])
   if i<len(raw):
    for ch in(0,255,34,58,44):
     add(kind,"byte-mutation",raw[:i]+bytes([ch])+raw[i+1:])
  if kind==1:
   for name in base:
    needle=canonical(name)+b":"+canonical(base[name])
    for token in tokens:add(kind,"scalar-"+name,raw.replace(needle,canonical(name)+b":"+token))
   for i in range(128):
    row={n:rng.getrandbits(64)for n in base}
    add(kind,"u64-random",canonical(row));add(kind,"u64-random-sequence",canonical(list(row.values())))
  else:
   for token in tokens:add(kind,"format",raw.replace(b'"format":1',b'"format":'+token))
   for field in("root","legacy","archive"):
    original=canonical(base[field]);needle=canonical(field)+b":"+original
    for token in tokens:
     for pair in(b"["+token+b",0]",b"[0,"+token+b"]"):
      add(kind,"identity-number-"+field,raw.replace(needle,canonical(field)+b":"+pair))
    for v in([0,0],[(1<<64)-1,0],[0,(1<<64)-1],None,[],[0],[0,1,2],{"0":0,"1":1}):
     add(kind,"identity-shape-"+field,canonical(dict(base,**{field:v})))
   for value in(None,{},0,"",[None],[[0]],[[0,1,2]],[{}],[[0,1],None],[[0,1],[2,-1]],[[0,1],[]]):
    add(kind,"shards-type",canonical(dict(base,shards=value)))
   for count in(0,1,2,255,256,257,512,1024,4096,10900,10922):
    add(kind,"no-shard-policy-cap-"+str(count),canonical(dict(base,shards=[[0,0]]*count)))
   for i in range(128):
    row=dict(format=rng.getrandbits(32),root=[rng.getrandbits(64),rng.getrandbits(64)],
     legacy=[rng.getrandbits(64),rng.getrandbits(64)],
     archive=None if kind==3 and i%2 else[rng.getrandbits(64),rng.getrandbits(64)],
     shards=[[rng.getrandbits(64),rng.getrandbits(64)]for _ in range(i%9)])
    add(kind,"random-numbers",canonical(row));add(kind,"random-sequence",canonical(list(row.values())))
  for outer in(b"",b" ",b"\n\t"):
   add(kind,"leading",outer+raw)
 return rows
def main():
 p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--manifest",type=Path,required=True);p.add_argument("--oracle",type=Path,required=True);p.add_argument("--provenance",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
 q=a.output;q.mkdir(parents=True,exist_ok=False);before=pins(a.source);manifest=a.manifest.read_bytes();oracle=a.oracle.read_bytes();provenance=a.provenance.read_bytes()
 proof=json.loads(provenance);assert proof["state"]=="PASS"and proof["original_release_profile"]is True and proof["original_default_features"]is True
 assert proof["binary_record"]["sha256"]==SHA(oracle)and proof["binary_record"]["bytes"]==len(oracle)
 assert proof["lock_sha256"]=="b868d2529f17dfb78ba390e078eb281a98d9850e4eaa12245739fec43ec97823"
 assert proof["locked_registry_archives"]==360 and proof["current_full_registry_sources_rechecked"]is True
 rows=cases();commands=b"".join(json.dumps(dict(kind=k,raw_hex=raw.hex()),separators=(",",":")).encode()+b"\n"for k,label,raw in rows)
 (q/"original-input.jsonl").write_bytes(commands)
 (q/"cases.json").write_text(json.dumps([dict(ordinal=i,kind=k,label=l,raw_bytes=len(raw),raw_sha256=SHA(raw))for i,(k,l,raw)in enumerate(rows)],sort_keys=True,indent=2)+"\n")
 (q/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
 start=time.monotonic();original=subprocess.run([str(a.oracle)],input=commands,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
 original_seconds=time.monotonic()-start;(q/"original.stdout").write_bytes(original.stdout);(q/"original.stderr").write_bytes(original.stderr)
 terminal=dict(exit_code=original.returncode,elapsed_seconds=original_seconds,binary_sha256=SHA(oracle),input_sha256=SHA(commands),stdout_sha256=SHA(original.stdout),provenance_sha256=SHA(provenance))
 (q/"original-terminal.json").write_text(json.dumps(terminal,sort_keys=True,indent=2)+"\n")
 assert original.returncode==0 and not original.stderr
 expected=[json.loads(line)for line in original.stdout.splitlines()];assert len(expected)==len(rows)
 sys.path.insert(0,str(a.source/"scripts"))
 from hia_native_loader import NativeModule
 failures=[];actual=[];counts={};controls=[];start=time.monotonic()
 with NativeModule(a.manifest,manifest_sha256=SHA(manifest))as native:
  with native.session(output_capacity=262272,workspace_capacity=262656)as session:
   for i,((kind,label,raw),original_row)in enumerate(zip(rows,expected)):
    got=session.invoke(packet(kind,raw));want=bytes.fromhex(original_row["wire_hex"])
    actual.append(struct.pack("<I",len(got))+got)
    key=str(kind)+":"+str(struct.unpack_from("<Q",got,8)[0]);counts[key]=counts.get(key,0)+1
    if got!=want:failures.append(dict(ordinal=i,kind=kind,label=label,input_sha256=SHA(raw),expected_sha256=SHA(want),actual_sha256=SHA(got),expected_hex=want.hex(),actual_hex=got.hex(),original_error=original_row.get("original_error")))
  valid=packet(rows[0][0],rows[0][2]);required=512+len(rows[0][2])*4
  bad=[valid[:i]for i in range(32)]+[b"X"+valid[1:],valid+b"x"]
  for kind in(0,4,2**64-1):bad.append(valid[:8]+struct.pack("<Q",kind)+valid[16:])
  bad.append(valid[:24]+struct.pack("<Q",1)+valid[32:])
  bad.append(valid[:16]+struct.pack("<Q",2**64-1)+valid[24:])
  for i,wire in enumerate(bad):
   code,out,w=native.invoke_raw(wire,output_capacity=262272,workspace_capacity=262656,output_fill=0x6d,workspace_fill=0x3c)
   assert code==0xffffffff and out==bytes([0x6d])*len(out),(i,code)
   controls.append(dict(kind="invalid-frame",input_sha256=SHA(wire),code=code))
  for oc,wc in[(0,required),(31,required),(127,required),(128,0),(128,required-1)]:
   code,out,w=native.invoke_raw(valid,output_capacity=oc,workspace_capacity=wc,output_fill=0x6d,workspace_fill=0x3c)
   assert code==0xfffffffe and out==bytes([0x6d])*oc,(oc,wc,code)
   controls.append(dict(kind="capacity",output=oc,workspace=wc,code=code))
  code,out,w=native.invoke_raw(valid,output_capacity=128,workspace_capacity=required,output_fill=0x6d,workspace_fill=0x3c)
  assert code==128 and out==bytes.fromhex(expected[0]["wire_hex"]);controls.append(dict(kind="exact-capacity",code=code))
 actual_bytes=b"".join(actual);(q/"native.stdout").write_bytes(actual_bytes)
 after=pins(a.source);(q/"source-after.json").write_text(json.dumps(after,sort_keys=True,indent=2)+"\n")
 result=dict(schema="hepta.runtime.durable-archive-records-qualification.v1",passed=not failures and before==after,cases=len(rows),
  controls=controls,failures=failures,categories=counts,native_elapsed_seconds=time.monotonic()-start,
  original=terminal,manifest_sha256=SHA(manifest),source_before=before,source_after=after,source_unchanged=before==after,
  original_graph="abc9ecb95ee9538518ec3f36c47b881974107021",native_stdout_sha256=SHA(actual_bytes),
  original_derive_macros=True,shard_vector_not_limited_to_256=True,filesystem_qualified=False,redb_qualified=False,public_qualified=False)
 assert a.oracle.read_bytes()==oracle and a.manifest.read_bytes()==manifest and a.provenance.read_bytes()==provenance
 (q/"report.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 print(json.dumps({k:v for k,v in result.items()if k not in("source_before","source_after","controls","failures")},sort_keys=True),flush=True)
 if not result["passed"]:raise SystemExit(1)
if __name__=="__main__":main()
