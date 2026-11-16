from pathlib import Path
import hashlib,json,os,stat,sys,tarfile,time,zipfile
root=Path("/workspace/scratch/6780eb0cbcc3/audit-store-lock-work-v1/controller-final-evidence")
keeper=root/"complete.zip"
v3=Path("/tmp/hia-audit-controller-6780-readback-v3")
v2=Path("/workspace/scratch/6780eb0cbcc3/audit-store-lock-work-v1/controller-readback-local-v2")
def identity(p):
 s=p.lstat();return (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def pin(p):
 with p.open("rb") as f:digest=hashlib.file_digest(f,"sha256").hexdigest()
 return {"bytes":p.stat().st_size,"sha256":digest,"mode":stat.S_IMODE(p.stat().st_mode)}
def inventory(r):
 out={}
 for p in r.rglob("*"):
  s=p.lstat();assert stat.S_ISREG(s.st_mode) or stat.S_ISDIR(s.st_mode)
  assert p.absolute()==p.resolve()
  if stat.S_ISREG(s.st_mode):out[p.relative_to(r).as_posix()]=identity(p)
 return out
def compare(stream,path,size,mode):
 before=identity(path);assert before[3]==size and stat.S_IMODE(before[2])==mode
 h=hashlib.sha256();n=0
 with path.open("rb") as f:
  while b:=stream.read(1048576):
   assert f.read(len(b))==b;h.update(b);n+=len(b)
  assert f.read(1)==b""
 assert n==size and identity(path)==before
 return {"bytes":n,"sha256":h.hexdigest(),"mode":mode,"identity":before}
own=Path(__file__).read_bytes()
assert hashlib.sha1(b"blob "+str(len(own)).encode()+b"\0"+own).hexdigest()==sys.argv[1]
assert pin(keeper)=={"bytes":335213267,"sha256":"89084d8d0e2b8a08e50cbd463816ed4b6717e38fe5c0f1163fb18d8d018954ec","mode":420}
keep_id=identity(keeper);start=time.monotonic();compared={}
with keeper.open("rb") as f:compared[str(v3/"complete.zip")]=compare(f,v3/"complete.zip",335213267,420)
expanded=v3/"expanded";actual=inventory(expanded);seen=set()
with zipfile.ZipFile(keeper) as z:
 names=[m.filename for m in z.infolist() if not m.is_dir()]
 assert len(names)==len(set(names))
 for local in [v3/"zip",v2/"zip"]:
  assert set(inventory(local))==set(names)
  for name in names:
   m=z.getinfo(name)
   with z.open(m) as f:compared[str(local/name)]=compare(f,local/name,m.file_size,(m.external_attr>>16)&0o777)
 with z.open("audit-store-controller.tar.gz") as compressed:
  with tarfile.open(fileobj=compressed,mode="r|gz") as t:
   while m:=t.next():
    assert not Path(m.name).is_absolute() and ".." not in Path(m.name).parts
    if m.isfile():
     assert m.name in actual and m.name not in seen
     path=expanded/m.name;assert identity(path)==actual[m.name]
     with t.extractfile(m) as f:compared[str(path)]=compare(f,path,m.size,m.mode)
     seen.add(m.name)
    else:assert m.isdir()
    t.members.clear()
assert seen==set(actual) and len(seen)==18126
assert sum(compared[str(expanded/n)]["bytes"] for n in seen)==2054555731
assert identity(keeper)==keep_id
# Every independent proof and process log is already copied outside retired roots.
for sub in ["reader-processes","outer-processes","first-failure-processes"]:
 assert (root/sub/"processes.json").is_file()
assert pin(root/"reader-processes/independent-reader.stdout")["sha256"]=="2487b15f12ee5a14d89f605b294900abf42b3190053f3ccf50cbfd570664238f"
assert pin(root/"READBACK.json")["sha256"]=="eb8936e395089df8fcacbfcbf29d4dca258232e6febe87f7620c8b28b0f197e1"
for name,record in compared.items():assert identity(Path(name))==tuple(record["identity"])
for name,record in compared.items():
 p=Path(name);assert identity(p)==tuple(record["identity"]);p.unlink()
for directory in [expanded,v3/"zip",v2/"zip"]:
 for p in sorted(directory.rglob("*"),key=lambda p:len(p.parts),reverse=True):
  assert p.is_dir() and not p.is_symlink();p.rmdir()
 directory.rmdir()
assert identity(keeper)==keep_id
receipt={"schema":"hepta.audit-controller.complete-duplicate-retirement.v1","keeper":str(keeper),
 "keeper_pin":pin(keeper),"full_bytes_and_modes_compared":True,"files":compared,
 "file_count":len(compared),"logical_bytes":sum(r["bytes"] for r in compared.values()),
 "native_or_rust_executions":0,"failed_v2_processes_preserved":True,"successful_v3_processes_and_full_proof_preserved":True,
 "elapsed_seconds":time.monotonic()-start,"driver_git_blob":sys.argv[1]}
(root/"DUPLICATE_RETIREMENT.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
spaces={}
for p in [root,Path("/tmp"),Path("/dev/shm")]:
 s=os.statvfs(p);spaces[str(p)]=s.f_bavail*s.f_frsize
print(json.dumps({"file_count":receipt["file_count"],"logical_bytes":receipt["logical_bytes"],"elapsed_seconds":receipt["elapsed_seconds"],"available_bytes":spaces,"retained_complete_zip":str(keeper),"semantic_executions":0}))
