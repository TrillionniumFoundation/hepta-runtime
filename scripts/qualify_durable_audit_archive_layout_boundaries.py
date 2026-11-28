# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual filesystem refusals and private capability boundaries for v12 layout."""
from pathlib import Path
from contextlib import ExitStack
import argparse,ctypes,errno,hashlib,json,os,stat,struct,sys,time,types
SELF=Path(__file__).resolve(strict=True);EXECUTED=SELF.read_bytes()
SHA=lambda b:hashlib.sha256(b).hexdigest()
U=lambda b,n:struct.unpack_from("<Q",b,n)[0]
ROLES=("layout","layout-packer","anchor","anchor-packer","metadata","metadata-packer","publication","publication-packer","records")
STEMS={"layout":"durable_audit_archive_layout","layout-packer":"durable_audit_archive_layout_packer",
 "anchor":"durable_audit_anchor","anchor-packer":"durable_audit_anchor_packer",
 "metadata":"durable_audit_archive_metadata","metadata-packer":"durable_audit_archive_metadata_packer",
 "publication":"durable_audit_archive_publication","publication-packer":"durable_audit_archive_publication_packer","records":"durable_audit_archive_records"}
BASE="scripts/qualify_durable_audit_archive_layout.py"
BASE_PIN="7c07b44e8b68d47fed33dff57f5cad2910cf88321006db3edbaf34d13913e4ad"
OWN="scripts/qualify_durable_audit_archive_layout_boundaries.py"
def captured(path,expected=None):
 raw=path.read_bytes()
 if expected is not None:assert SHA(raw)==expected,(str(path),SHA(raw))
 module=types.ModuleType("_actual_"+path.stem);module.__file__=str(path)
 exec(compile(raw,str(path),"exec"),module.__dict__)
 assert path.read_bytes()==raw
 if hasattr(module,"EXECUTED"):assert module.EXECUTED==raw
 return module,raw
def file_record(path):
 st=path.lstat();assert stat.S_ISREG(st.st_mode)
 raw=path.read_bytes();end=path.lstat()
 fields=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
 assert fields(st)==fields(end)and len(raw)==st.st_size
 return dict(bytes=len(raw),sha256=SHA(raw),mode=stat.S_IMODE(st.st_mode))
def make_intent(b,root,count=1,archive=True):
 path=root/b.ROOT
 if archive:
  path.mkdir(mode=0o700)
  for i in range(count):(path/format(i,"02x")).mkdir(mode=0o700)
 record=dict(format=12,root=b.identity(root),legacy=b.identity(root/b.LEGACY),
  archive=b.identity(path)if archive else None,
  shards=[b.identity(path/format(i,"02x"))for i in range(count)])
 b.put_file(root/b.INTENT,b.canonical(record))
 return record
def update_json(b,path,key,value):
 record=json.loads(path.read_bytes());record[key]=value;b.put_file(path,b.canonical(record))
def change(b,root,tag):
 ar=root/b.ROOT;an=root/b.ANCHOR;it=root/b.INTENT;la=root/b.LEGACY_ANCHOR
 if tag=="unanchored-root":ar.mkdir(mode=0o700)
 elif tag=="anchor-format":update_json(b,an,"format",13)
 elif tag=="anchor-root":update_json(b,an,"root",[0,0])
 elif tag=="anchor-legacy":update_json(b,an,"legacy",[0,0])
 elif tag=="anchor-count":update_json(b,an,"shards",json.loads(an.read_bytes())["shards"][:-1])
 elif tag in("archive-missing","archive-replaced"):
  ar.rename(root/"held-shards")
  if tag=="archive-replaced":ar.mkdir(mode=0o700)
 elif tag=="archive-mode":ar.chmod(0o755)
 elif tag in("shard-missing","shard-replaced","shard-symlink"):
  (ar/"78").rename(root/"held-shard")
  if tag=="shard-replaced":(ar/"78").mkdir(mode=0o700)
  if tag=="shard-symlink":os.symlink("../held-shard",ar/"78")
 elif tag=="shard-mode":(ar/"78").chmod(0o755)
 elif tag=="namespace-extra":(ar/"unexpected").mkdir(mode=0o700)
 elif tag=="namespace-invalid-utf8":os.mkdir(os.fsencode(ar)+b"/\xff",0o700)
 elif tag=="anchor-partial":b.put_file(an,b"{partial")
 elif tag=="anchor-unknown-alias":os.link(an,root/"unknown-anchor-alias")
 elif tag=="anchor-partial-known-alias":
  b.put_file(an,b"{partial");os.link(an,root/(".archive-v12-anchor-"+"d"*64+".tmp"))
 elif tag=="completed-intent-mismatch":
  record=json.loads(an.read_bytes());record["shards"]=[];b.put_file(it,b.canonical(record))
 elif tag.startswith("intent-") and tag!="intent-reappeared":
  if tag=="intent-unbound-payload":
   make_intent(b,root,0,False);ar.mkdir(mode=0o700);b.put_file(ar/"unexpected-original.json",b"original data must be preserved")
  else:
   record=make_intent(b,root)
   if tag=="intent-recorded-replaced":
    (ar/"00").rename(root/"held-init-shard");(ar/"00").mkdir(mode=0o700)
   elif tag=="intent-recorded-payload":b.put_file(ar/"00/unexpected-original.json",b"original data must be preserved")
   elif tag=="intent-recorded-missing":(ar/"00").rename(root/"held-init-shard")
   elif tag=="intent-next-payload":
    (ar/"01").mkdir(mode=0o700);b.put_file(ar/"01/unexpected-original.json",b"unbound payload must be preserved")
   elif tag=="intent-skipped-shard":(ar/"02").mkdir(mode=0o700)
   elif tag=="intent-extra-name":(ar/"GG").mkdir(mode=0o700)
   elif tag=="intent-next-symlink":os.symlink("00",ar/"01")
   elif tag=="intent-root-replaced":ar.rename(root/"held-init-root");ar.mkdir(mode=0o700)
   elif tag=="intent-no-archive-with-shards":record["archive"]=None;b.put_file(it,b.canonical(record))
   elif tag=="intent-root-binding":record["root"]=[0,0];b.put_file(it,b.canonical(record))
   elif tag=="intent-format":record["format"]=13;b.put_file(it,b.canonical(record))
   else:raise AssertionError(tag)
 elif tag=="legacy-directory-replaced":
  (root/b.LEGACY).rename(root/"held-legacy");(root/b.LEGACY).mkdir(mode=0o700)
 elif tag in("legacy-anchor-replaced","anchor-replaced"):
  path=la if tag.startswith("legacy-")else an
  raw=path.read_bytes();path.rename(root/("held-"+path.name));b.put_file(path,raw)
 elif tag in("legacy-anchor-edit-restored-mtime","anchor-edit-restored-mtime"):
  path=la if tag.startswith("legacy-")else an;st=path.stat();raw=bytearray(path.read_bytes())
  if tag.startswith("legacy-"):
   at=max(i for i,x in enumerate(raw)if 48<=x<=57);raw[at]=48+(raw[at]-48+1)%10
  else:
   old=bytes(raw);assert b'"format":12'in old;raw=bytearray(old.replace(b'"format":12',b'"format":13',1))
  b.put_file(path,bytes(raw));os.utime(path,ns=(st.st_atime_ns,st.st_mtime_ns))
 elif tag=="root-mode":root.chmod(0o755)
 elif tag=="intent-reappeared":
  if an.exists():record=json.loads(an.read_bytes())
  else:record=dict(format=12,root=b.identity(root),legacy=b.identity(root/b.LEGACY),archive=None,shards=[])
  b.put_file(it,b.canonical(record))
 elif tag=="flat-anchor":b.put_file(an,b"{}")
 elif tag=="known-anchor-alias":os.link(an,root/(".archive-v12-anchor-"+"c"*64+".tmp"))
 elif tag=="known-intent-alias":
  make_intent(b,root,0,False);os.link(it,root/(".archive-v12-init-"+"a"*64+".tmp"))
 elif tag=="complete-matching-intent":b.put_file(it,an.read_bytes())
 elif tag=="resume-next-empty":make_intent(b,root);(ar/"01").mkdir(mode=0o700)
 else:raise AssertionError(tag)
def cases():
 initial_complete=("anchor-format","anchor-root","anchor-legacy","anchor-count","archive-missing","archive-replaced","archive-mode",
  "shard-missing","shard-replaced","shard-symlink","shard-mode","namespace-extra","namespace-invalid-utf8",
  "anchor-partial","anchor-unknown-alias","anchor-partial-known-alias","completed-intent-mismatch")
 initial_flat=("unanchored-root","intent-recorded-replaced","intent-recorded-payload","intent-recorded-missing","intent-next-payload",
  "intent-skipped-shard","intent-extra-name","intent-next-symlink","intent-root-replaced","intent-no-archive-with-shards",
  "intent-root-binding","intent-format","intent-unbound-payload")
 rows=[dict(label="initial-"+tag,complete=True,when="before",op=1,tag=tag,accepted=False)for tag in initial_complete]
 rows += [dict(label="initial-"+tag,complete=False,when="before",op=1,tag=tag,accepted=False)for tag in initial_flat]
 for tag in("archive-missing","archive-replaced","archive-mode","anchor-replaced","anchor-edit-restored-mtime",
  "legacy-directory-replaced","legacy-anchor-replaced","legacy-anchor-edit-restored-mtime","root-mode","intent-reappeared"):
  rows.append(dict(label="loaded-"+tag,complete=True,when="after",op=3,tag=tag,accepted=False))
 for tag in("shard-missing","shard-replaced","shard-mode","shard-symlink","namespace-extra","namespace-invalid-utf8"):
  rows.append(dict(label="loaded-full-"+tag,complete=True,when="after",op=4,tag=tag,accepted=False))
 for tag in("unanchored-root","flat-anchor","intent-reappeared"):
  rows.append(dict(label="flat-epoch-"+tag,complete=False,when="after",op=3,tag=tag,accepted=False))
 for tag,complete in(("known-anchor-alias",True),("known-intent-alias",False),("complete-matching-intent",True),("resume-next-empty",False)):
  rows.append(dict(label="recover-"+tag,complete=complete,when="before",op=1,tag=tag,accepted=True))
 return rows
def pair_case(b,c,oracle,q,fixtures,spec):
 label=spec["label"];cq=q/label;cq.mkdir();fq=fixtures/label;fq.mkdir(mode=0o700)
 ro=fq/"original";rn=fq/"native";b.create_root(ro,spec["complete"]);b.create_root(rn,spec["complete"])
 legacy_name=b.LEGACY+"/"+"1"*64+".json"
 initial_legacy={key:b.snapshot(root)[legacy_name]for key,root in(("original",ro),("native",rn))}
 if spec["when"]=="before":
  for root in(ro,rn):change(b,root,spec["tag"])
 before=None;result=None
 with b.Original(oracle,cq/"oracle")as old,b.Layout(c,rn,cq/"native-trace.jsonl")as new:
  if spec["when"]=="after":
   first=old.step("open",root=str(ro));actual=new.drive(1)
   assert first["accepted"]is True and actual["diagnostic"]==0
   b.native_topology(actual,rn);b.verify_success(first,actual,ro)
   for root in(ro,rn):change(b,root,spec["tag"])
  before={key:b.snapshot(root)for key,root in(("original",ro),("native",rn))}
  (cq/"physical-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
  op=spec["op"];ref=old.step("open",root=str(ro))if op==1 else old.step({3:"fence",4:"full_layout"}[op])
  native=new.drive(op)
  accepted=spec["accepted"]
  assert ref["accepted"]is accepted,(label,ref)
  assert (native["diagnostic"]==0)is accepted,(label,ref,native)
  if not accepted:
   assert native["diagnostic"]==1
   if ref["error"]["io_errno"]is not None:assert native["errno"]==ref["error"]["io_errno"],(label,ref,native)
  after={key:b.snapshot(root)for key,root in(("original",ro),("native",rn))}
  if accepted:
   assert b.normalized(after["original"])==b.normalized(after["native"]),(label,"physical results")
   b.native_topology(native,rn);b.verify_success(ref,native,ro)
  else:assert before==after,(label,"refusal changed original evidence")
  expected_legacy=("held-legacy/"+"1"*64+".json")if spec["tag"]=="legacy-directory-replaced"else legacy_name
  for key in("original","native"):assert after[key][expected_legacy]==initial_legacy[key],(label,key,"legacy original changed")
  result=dict(specification=spec,passed=True,original=ref,native=native,physical_after=after,
   refusal_unchanged=before==after,legacy_complete_stamp_and_bytes_unchanged=True,native_effect_calls=new.steps)
  (cq/"result.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
 assert after=={key:b.snapshot(root)for key,root in(("original",ro),("native",rn))},(label,"close changed files")
 return dict(label=label,passed=True,accepted=accepted,effect_calls=result["native_effect_calls"],original_error=None if accepted else ref["error"])
def write_memory(base,at,raw):ctypes.memmove(base+at,raw,len(raw))
def actor_boundaries(b,c,q,fixtures):
 q.mkdir();results=[];good=b"HRAALQ01"+struct.pack("<QQQ",1,1,0)
 inputs=[("short",good[:-1]),("long",good+b"\0"),("magic",b"X"+good[1:]),("operation-zero",good[:8]+struct.pack("<Q",0)+good[16:]),
  ("operation-six",good[:8]+struct.pack("<Q",6)+good[16:]),("sequence-zero",good[:16]+struct.pack("<Q",0)+good[24:]),
  ("sequence-two",good[:16]+struct.pack("<Q",2)+good[24:]),("reserved",good[:24]+struct.pack("<Q",1)),
  ("uninitialized-initialize",good[:8]+struct.pack("<Q",2)+good[16:])]
 for name,wire in inputs:
  with c["layout"].session(output_capacity=4480,workspace_capacity=1048576)as session:
   code,out,w=session.invoke_raw(wire);assert code==0xffffffff,(name,code)
   results.append(dict(label=name,code=code,output_sha256=SHA(out),workspace_sha256=SHA(w),effects_dispatched=0))
 for name,oc,wc in[("output-bound",4479,1048576),("workspace-bound",4480,1048575)]:
  with c["layout"].session(output_capacity=oc,workspace_capacity=wc)as session:
   code,out,w=session.invoke_raw(good);assert code==0xfffffffe,(name,code)
   results.append(dict(label=name,code=code,output_sha256=SHA(out),workspace_sha256=SHA(w),effects_dispatched=0))
 with c["layout"].session(output_capacity=4480,workspace_capacity=1048576)as session:
  session._workspace[600000]=b"\1";code,out,w=session.invoke_raw(good);assert code==0xffffffff
  results.append(dict(label="dirty-fresh-workspace",code=code,effects_dispatched=0))
 root=fixtures/"actor-ack";b.create_root(root)
 with b.Layout(c,root,q/"actual-ack-trace.jsonl")as layout:
  code,out,w=layout.session.invoke_raw(good);assert code==b.YIELD
  assert layout.engine.step(layout.ctx)==0
  base=ctypes.addressof(layout.session._workspace);snapshot=ctypes.string_at(base,1048576);ctx=layout.engine.state(layout.ctx)
  assert U(snapshot,320)==1
  mutations=[("ack-sequence",320,struct.pack("<Q",2)),("ack-reserved",344,struct.pack("<Q",1)),
   ("ack-errno-range",336,struct.pack("<Q",4096)),("ack-effect-value",328,struct.pack("<Q",1)),
   ("ack-action-kind",272,struct.pack("<Q",11)),("ack-outer-input",None,good[:16]+struct.pack("<Q",2)+good[24:])]
  for name,offset,value in mutations:
   write_memory(base,0,snapshot);wire=good
   if offset is None:wire=value
   else:write_memory(base,offset,value)
   before=ctypes.string_at(base,1048576)
   code,out,w=layout.session.invoke_raw(wire)
   assert code==0xffffffff and w==before and layout.engine.state(layout.ctx)==ctx,(name,code)
   results.append(dict(label=name,code=code,workspace_sha256=SHA(w),engine_unchanged=True))
  write_memory(base,0,snapshot)
  code,out,w=layout.session.invoke_raw(good);assert code==b.YIELD
  results.append(dict(label="original-ack-remains-usable",code=code))
 (q/"results.json").write_text(json.dumps(results,sort_keys=True,indent=2)+"\n");return results
def capability_boundaries(b,c,q,fixtures):
 q.mkdir();root=fixtures/"capability-ack";b.create_root(root);results=[]
 with b.Layout(c,root,q/"trace.jsonl")as layout:
  wire=b"HRAALQ01"+struct.pack("<QQQ",1,1,0)
  for count in range(32):
   code,out,w=layout.session.invoke_raw(wire);assert code==b.YIELD
   kind=U(w,272);ret=layout.engine.step(layout.ctx)
   if ret==1:
    assert kind==100;break
   assert ret==0
  else:raise AssertionError("actual metadata child was not reached")
  base=ctypes.addressof(layout.session._workspace);snapshot=ctypes.string_at(base,1048576);ctx=layout.engine.state(layout.ctx)
  assert ctx["pending"]==1 and ctx["owned"]==[]
  for name,call,expected in[("pending-step",lambda:layout.engine.step(layout.ctx),-errno.EBUSY),
   ("pending-destroy",lambda:layout.engine.destroy(layout.ctx),-errno.EBUSY),
   ("borrowed-root-take",lambda:layout.engine.take(layout.ctx,0),-errno.EPERM),
   ("borrowed-legacy-take",lambda:layout.engine.take(layout.ctx,1),-errno.EPERM),
   ("owned-slot-take",lambda:layout.engine.take(layout.ctx,8),-errno.EPERM)]:
   value=call();assert value==expected and layout.engine.state(layout.ctx)==ctx
   assert ctypes.string_at(base,1048576)==snapshot
   results.append(dict(label=name,return_code=value,pending_retained=True))
  tests=[("query-changed",1536,b"X",0,errno.ECANCELED),("request-changed",131072,b"X",0,errno.ECANCELED),
   ("action-changed",272,struct.pack("<Q",101),0,errno.ECANCELED),("ack-already-written",320,struct.pack("<Q",1),0,errno.ECANCELED),
   ("response-overflow",None,b"",U(snapshot,312)+1,0),("errno-overflow",None,b"",0,4096),("error-with-response",None,b"",1,errno.EIO)]
  for name,offset,raw,length,error in tests:
   write_memory(base,0,snapshot)
   if offset is not None:write_memory(base,offset,raw)
   before=ctypes.string_at(base,1048576)
   value=layout.engine.child_ack(layout.ctx,length,error)
   assert value==-errno.EINVAL and layout.engine.state(layout.ctx)==ctx
   assert ctypes.string_at(base,1048576)==before
   results.append(dict(label=name,return_code=value,pending_retained=True))
  write_memory(base,0,snapshot)
  row=dict(kind=100,span=U(snapshot,288),count=U(snapshot,296),arg=U(snapshot,304),capacity=U(snapshot,312))
  request=ctypes.string_at(base+row["span"],row["count"])
  payload,actual=layout.child(row,request);assert len(payload)<=row["capacity"]
  write_memory(base,row["arg"],payload);assert layout.engine.child_ack(layout.ctx,len(payload),0)==0
  committed=layout.engine.state(layout.ctx);committed_w=ctypes.string_at(base,1048576)
  assert committed["pending"]==0
  assert layout.engine.child_ack(layout.ctx,len(payload),0)==-errno.EINVAL
  assert layout.engine.state(layout.ctx)==committed and ctypes.string_at(base,1048576)==committed_w
  os.fstat(layout.root);os.fstat(layout.legacy)
  results.append(dict(label="actual-child-one-ack-only",request_hex=request.hex(),response_hex=payload.hex(),actual=actual,pending=False))
 (q/"results.json").write_text(json.dumps(results,sort_keys=True,indent=2)+"\n");return results
def child_response_boundaries(b,c,q,fixtures):
 q.mkdir();results=[]
 for kind,op in[(100,2),(101,3),(102,2)]:
  cq=q/str(kind);cq.mkdir();root=fixtures/("child-response-"+str(kind));b.create_root(root)
  class Damaged(b.Layout):
   enabled=False
   delivered=0
   physical_after_child=None
   def child(self,row,request):
    raw,actual=super().child(row,request)
    if self.enabled and row["kind"]==kind:
     self.delivered+=1;assert self.delivered==1
     self.physical_after_child=b.snapshot(root)
     (cq/"actual-child.json").write_text(json.dumps(dict(request=request.hex(),response=raw.hex(),detail=actual),sort_keys=True,indent=2)+"\n")
     raw=bytes([raw[0]^1])+raw[1:]
    return raw,actual
  with Damaged(c,root,cq/"native-trace.jsonl")as layout:
   initial=layout.drive(1);assert initial["diagnostic"]==0
   layout.enabled=True;rejected=None
   try:layout.drive(op)
   except AssertionError as error:
    assert len(error.args)==1 and isinstance(error.args[0],dict)and error.args[0].get("code")==0xffffffff,error
    rejected=error.args[0]
   assert rejected is not None and layout.delivered==1
   assert layout.physical_after_child==b.snapshot(root)
   if kind==102:assert(root/b.INTENT).is_file()
   results.append(dict(child_kind=kind,rejected=rejected,actual_child_calls=1,completed_child_effects_preserved=True))
 (q/"results.json").write_text(json.dumps(results,sort_keys=True,indent=2)+"\n");return results
def main():
 parser=argparse.ArgumentParser()
 for name in("source","modules","oracle","provenance","output","fixtures"):parser.add_argument("--"+name,type=Path,required=True)
 a=parser.parse_args();s=a.source.resolve(strict=True);q=a.output;q.mkdir(parents=True,exist_ok=False)
 assert(s/OWN).read_bytes()==EXECUTED
 assert a.fixtures.is_absolute();a.fixtures.parent.resolve(strict=True);a.fixtures.mkdir(mode=0o700,exist_ok=False)
 b,base_raw=captured(s/BASE,BASE_PIN)
 pub,pubraw=b.captured(s,"scripts/qualify_durable_audit_archive_publication.py","dca32d7674518ac0a3ffef164459a56aa076239f475eb964767f1b9cf0c710e2")
 anchor,anchorraw=b.captured(s,"scripts/qualify_durable_audit_anchor.py","efdf5180ee7bac264e4cf561bf3ecbd82c8c61ffbb6777a909fc1929258ac012")
 metadata,metaraw=pub.captured_metadata_module(s)
 names=tuple(dict.fromkeys((OWN,*b.OWN,*pub.OWN,*metadata.PATHS,*anchor.PATHS)))
 paths={name:s/name for name in names}
 manifests={role:a.modules/role/"manifest.json"for role in ROLES}
 for role,p in manifests.items():
  m=json.loads(p.read_bytes());assert m["source_sha256"]==SHA((s/("native/"+STEMS[role]+".hepta")).read_bytes())
  for k in("source","image"):
   assert Path(m[k]).name==m[k]
   paths["module/"+role+"/"+k]=p.parent/m[k]
  paths["module/"+role+"/manifest"]=p
 paths["original/oracle"]=a.oracle;paths["original/provenance"]=a.provenance
 before={n:file_record(p)for n,p in paths.items()}
 proof=json.loads(a.provenance.read_bytes())
 assert proof["state"]=="PASS"and proof["locked_registry_archives"]==360 and proof["original_archive_store_methods"]==29
 assert proof["original_release_profile"]is True and proof["original_default_features"]is True
 assert proof["binary_record"]["sha256"]==before["original/oracle"]["sha256"]
 loader,loader_raw=captured(s/"scripts/hia_native_loader.py",before["scripts/hia_native_loader.py"]["sha256"])
 (q/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
 start=time.monotonic();report=dict(passed=False,physical=[],actor=[],capability=[],children=[])
 try:
  with ExitStack()as stack:
   c={role:stack.enter_context(loader.NativeModule(p,manifest_sha256=before["module/"+role+"/manifest"]["sha256"]))for role,p in manifests.items()}
   for key,magic,stem,cls in[("layout","HRALPQ01","durable_audit_archive_layout",b.Engine),("anchor","HRAAPQ01","durable_audit_anchor",anchor.Engine),
    ("metadata","HRAMPQ01","durable_audit_archive_metadata",metadata.Engine),("publication","HRAWPQ01","durable_audit_archive_publication",pub.Engine)]:
    record=json.loads((s/("scripts/"+stem+"_code.json")).read_bytes())
    assert record["source_sha256"]==SHA((s/("scripts/"+stem+"_engine.S")).read_bytes())
    out=c[key+"-packer"].invoke(magic.encode()+struct.pack("<QQ",1,0),output_capacity=64+record["flat_bytes"],workspace_capacity=16)
    (q/("actual-"+key+"-engine.pack")).write_bytes(out);c[key+"_engine"]=stack.enter_context(cls(out,record))
   c["anchor_type"]=b.borrowed_anchor_type(anchor);c["metadata_type"]=pub.borrowed_reader_type(metadata);c["publication_type"]=b.borrowed_publication_type(pub)
   physical=q/"physical";physical.mkdir();specs=cases()
   (q/"physical-cases.json").write_text(json.dumps(specs,sort_keys=True,indent=2)+"\n")
   for spec in specs:
    result=pair_case(b,c,a.oracle,physical,a.fixtures,spec);report["physical"].append(result);print(json.dumps(result),flush=True)
   report["actor"]=actor_boundaries(b,c,q/"actor",a.fixtures)
   report["capability"]=capability_boundaries(b,c,q/"capability",a.fixtures)
   report["children"]=child_response_boundaries(b,c,q/"children",a.fixtures)
  report["passed"]=True
 finally:
  after={n:file_record(p)for n,p in paths.items()};same=before==after
  (q/"source-after.json").write_text(json.dumps(after,sort_keys=True,indent=2)+"\n")
  report.update(schema="hepta.runtime.durable-layout-boundaries.v1",source_unchanged=same,elapsed_seconds=time.monotonic()-start,
   fixture_root=str(a.fixtures),original_binary_sha256=before["original/oracle"]["sha256"],public_archive_qualified=False,
   shared_registry_qualified=False,redb_qualified=False)
  if not same:report["passed"]=False
  (q/"report.json").write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
  print(json.dumps({k:report[k]for k in("passed","source_unchanged","elapsed_seconds")}|{k:len(report[k])for k in("physical","actor","capability","children")}),flush=True)
  assert same
if __name__=="__main__":main()
