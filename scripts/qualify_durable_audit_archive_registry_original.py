# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Physical original Archive registry observations in the unchanged full graph."""
from pathlib import Path
import argparse,hashlib,json,os,selectors,stat,subprocess,time
SELF=Path(__file__).resolve(strict=True);EXECUTED=SELF.read_bytes();SHA=lambda v:hashlib.sha256(v).hexdigest()
BINARY="d175ef7a8cee48991c8d552f8da2d1cc83a8bb416ecd62bc0b87b562b139009c"
LEGACY="request-archive-v11";ANCHOR=".request-archive-v11-anchor.json";V12=".request-archive-v12-anchor.json"
def pin(path):
 a=path.lstat();raw=path.read_bytes();b=path.lstat()
 sig=lambda t:[t.st_dev,t.st_ino,t.st_mode,t.st_uid,t.st_gid,t.st_nlink,t.st_size,t.st_mtime_ns,t.st_ctime_ns]
 assert stat.S_ISREG(a.st_mode)and not path.is_symlink()and sig(a)==sig(b)
 return dict(bytes=len(raw),sha256=SHA(raw),physical=sig(a))
def identity(path):x=path.stat();return[x.st_dev,x.st_ino]
def write(path,raw):
 with path.open("xb")as f:f.write(raw)
 path.chmod(0o600)
def create(root):
 root.mkdir(mode=0o700);root.chmod(0o700);legacy=root/LEGACY;legacy.mkdir(mode=0o700);legacy.chmod(0o700)
 r=identity(root);l=identity(legacy)
 write(root/ANCHOR,json.dumps(dict(root_device=r[0],root_inode=r[1],archive_device=l[0],archive_inode=l[1]),separators=(",",":")).encode())
 write(legacy/("a"*64+".json"),b'{"qualification":"retained original payload"}')
 return r+l
class Original:
 def __init__(self,path,q):
  self.q=q;self.err=(q/"oracle.stderr").open("xb");self.input=(q/"oracle.stdin.jsonl").open("xb");self.output=(q/"oracle.stdout.jsonl").open("xb")
  self.p=subprocess.Popen([str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.err,bufsize=0,start_new_session=True)
  self.selector=selectors.DefaultSelector();self.selector.register(self.p.stdout,selectors.EVENT_READ);self.buffer=b""
 def step(self,operation,**kw):
  raw=json.dumps(dict(operation=operation,**kw),separators=(",",":")).encode()+b"\n";self.input.write(raw);self.input.flush();self.p.stdin.write(raw);self.p.stdin.flush()
  deadline=time.monotonic()+10
  while b"\n"not in self.buffer:
   remaining=deadline-time.monotonic();assert remaining>0 and self.selector.select(remaining),"original command exceeded the existing qualification 10-second ceiling"
   part=os.read(self.p.stdout.fileno(),65536);assert part,"original ended without a response";self.buffer+=part
  raw,self.buffer=self.buffer.split(b"\n",1);self.output.write(raw+b"\n");self.output.flush()
  return json.loads(raw)
 def close(self):
  self.p.stdin.close()
  try:code=self.p.wait(timeout=3)
  except subprocess.TimeoutExpired:self.p.kill();self.p.wait();raise
  finally:self.selector.close();self.p.stdout.close();self.err.close();self.input.close();self.output.close()
  assert code==0 and not self.buffer and not(self.q/"oracle.stderr").read_bytes()
 def __enter__(self):return self
 def __exit__(self,*args):self.close()
def main():
 p=argparse.ArgumentParser()
 for n in("project","oracle","fixtures","output"):p.add_argument("--"+n,type=Path,required=True)
 a=p.parse_args();q=a.output;q.mkdir(parents=True,exist_ok=False);a.fixtures.mkdir(parents=True,mode=0o700,exist_ok=False);a.fixtures.chmod(0o700)
 paths={"executed":SELF,"oracle":a.oracle,**{n:a.project/n for n in("Cargo.toml","Cargo.lock","src/mcp/runtime/request_audit.rs","src/mcp/runtime/request_archive_store.rs","src/mcp/runtime/request_archive_store_tests.rs","audit_archive_registry/oracle.rs","audit_archive_registry/source-relation.json")}}
 before={n:pin(path)for n,path in paths.items()};assert before["oracle"]["sha256"]==BINARY and before["oracle"]["bytes"]==607568
 relation=json.loads((a.project/"audit_archive_registry/source-relation.json").read_bytes())
 assert relation["original_functions_whole_bytes_preserved"]and relation["original_test_methods_whole_bytes_preserved"]and relation["graph_default_features_release_profile_unchanged"]
 for n,row in relation["after"].items():assert before[n]["bytes"]==row["bytes"]and before[n]["sha256"]==row["sha256"],n
 (q/"source-before.json").write_text(json.dumps(before,sort_keys=True,indent=2)+"\n")
 keys={};controls=[];observations=[];start=time.monotonic();passed=False
 for name in("shared","failed","other"):keys[name]=create(a.fixtures/name)
 def check(name,condition,**detail):assert condition,(name,detail);controls.append(dict(name=name,passed=True,**detail))
 def observed(op,**kw):
  row=original.step(op,**kw);observations.append(dict(operation=op,arguments=kw,response=row));return row
 def ok(op,**kw):
  row=observed(op,**kw);assert row["accepted"],row;return row
 def refs(row,label):
  matching=[entry["strong"]for entry in row["registry"]["entries"]if entry["key"]==keys[label]]
  assert len(matching)<=1
  return matching[0]if matching else None
 try:
  with Original(a.oracle,q)as original:
   first=ok("open",handle=1,root=str(a.fixtures/"shared"))
   check("first actual open retains one shared owner",first["value"]["key"]==keys["shared"]and first["value"]["strong"]==1 and not first["value"]["loaded"]and refs(first,"shared")==1)
   rejected_alias=observed("open",handle=2,root=str(a.fixtures/"shared")+"/.")
   check("original root admission rejects a dot-suffix before the registry",not rejected_alias["accepted"]and refs(rejected_alias,"shared")==1 and rejected_alias["error"]["text"]=="invalid request audit root")
   second=ok("open",handle=2,root=str(a.fixtures/"shared"))
   check("two admitted opens retain the same actual physical key",second["value"]["key"]==keys["shared"]and second["value"]["strong"]==2)
   check("two opens share the real Arc",ok("same",handle=1,other=2)["value"]["same"])
   third=ok("clone",handle=1,target=3)
   check("try_clone adds one reference to the actual same Inner",third["value"]["strong"]==3 and ok("same",handle=1,other=3)["value"]["same"])
   dropped=ok("drop",handle=2);check("dropping one holder preserves the other two",refs(dropped,"shared")==2)
   initialized=ok("initialize",handle=3)
   older=ok("state",handle=1)
   check("preexisting ticket observes later activation of the exact shared OnceLock",initialized["value"]["loaded"]and older["value"]["loaded"]and older["value"]["layout"]==initialized["value"]["layout"])
   check("activated owner retains all 256 original physical shards",len(older["value"]["layout"]["shards"])==256 and older["value"]["layout"]["archive"]==identity(a.fixtures/"shared"/"request-archive-v12"))
   fourth=ok("open",handle=4,root=str(a.fixtures/"shared"))
   check("reopen reuses the already activated owner",fourth["value"]["strong"]==3 and fourth["value"]["layout"]==older["value"]["layout"])
   check("already active shared reader needs no initialization",ok("exclusive",handle=1)["value"]["exclusive"]is False)
   anchor=a.fixtures/"shared"/ANCHOR;saved=a.fixtures/"shared"/".original-anchor-retained"
   original_bytes=anchor.read_bytes();old_identity=identity(anchor);anchor.rename(saved);write(anchor,original_bytes)
   check("fixture replaces the named anchor with identical bytes and a different inode",anchor.read_bytes()==saved.read_bytes()and identity(anchor)!=old_identity)
   refusal=observed("open",handle=5,root=str(a.fixtures/"shared"))
   check("existing Inner cannot rebind to a freshly opened replacement anchor",not refusal["accepted"]and refs(refusal,"shared")==3,error=refusal.get("error"))
   check("failed reopen publishes no caller handle",not observed("state",handle=5)["accepted"])
   for handle in(1,3,4):last=ok("drop",handle=handle)
   check("last Arc drop leaves only an expired weak entry",refs(last,"shared")==0)
   fresh=ok("open",handle=6,root=str(a.fixtures/"shared"))
   check("after all old holders retire a new owner may bind the current anchor",fresh["value"]["strong"]==1 and fresh["value"]["loaded"]and refs(fresh,"shared")==1)
   write(a.fixtures/"failed"/V12,b"{")
   refused=observed("open",handle=7,root=str(a.fixtures/"failed"))
   check("failed first layout load leaves an expired weak entry",not refused["accepted"]and refs(refused,"failed")==0 and refs(refused,"shared")==1,error=refused.get("error"))
   (a.fixtures/"failed"/V12).unlink()
   other=ok("open",handle=8,root=str(a.fixtures/"other"))
   check("later open prunes dead weak entries and keeps unrelated live owners",refs(other,"failed")is None and refs(other,"shared")==1 and refs(other,"other")==1)
   check("different retained physical roots have different actual Arcs",ok("same",handle=6,other=8)["value"]["same"]is False)
   recovered=ok("open",handle=9,root=str(a.fixtures/"failed"))
   check("recovery after removing invalid first-load bytes gets a new live owner",recovered["value"]["strong"]==1 and refs(recovered,"failed")==1)
   copy=ok("clone",handle=9,target=10);check("separate live owner has independent strong accounting",copy["value"]["strong"]==2 and refs(copy,"shared")==1 and refs(copy,"other")==1)
   for handle in(6,8,9,10):last=ok("drop",handle=handle)
   check("all last references leave no owned strong entry",all(row["strong"]==0 for row in last["registry"]["entries"])and not last["registry"]["poisoned"])
  passed=True
 finally:
  after={n:pin(path)for n,path in paths.items()};same=before==after
  (q/"source-after.json").write_text(json.dumps(after,sort_keys=True,indent=2)+"\n")
  (q/"observations.json").write_text(json.dumps(observations,sort_keys=True,indent=2)+"\n")
  result=dict(schema="hepta.runtime.durable-archive-registry-original-physical.v1",passed=passed and same,source_unchanged=same,
   elapsed_seconds=time.monotonic()-start,control_count=len(controls),controls=controls,actual_original_calls=len(observations),
   actual_identity_keys=keys,original_full_graph_only=True,hia_equivalence_qualified=False,public_archive_qualified=False)
  (q/"report.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
  print(json.dumps({k:result[k]for k in("passed","source_unchanged","elapsed_seconds","control_count","actual_original_calls")}),flush=True);assert same
if __name__=="__main__":main()
