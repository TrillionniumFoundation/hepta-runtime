#!/usr/bin/env python3
import pathlib,os,stat,json,hashlib,subprocess,shutil,sys
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
T=R/"target/debug/incremental"
Q=R/"docs/qualification/dc-functional-v9-integrated-evidence-20261013/r31-root-inactive-cache-cleanup"
sys.path.insert(0,"/home/qian-qi/hepta-successor-preflight-checker-3791c11-20261013-r3/deploy")
import preflight_dc_successor as P
import stage_dc_successor as S
def compilers():
 rows=[]
 for p in pathlib.Path("/proc").iterdir():
  if not p.name.isdigit():continue
  try:
   if p.stat().st_uid!=os.getuid() or (p/"comm").read_text().strip() not in ("cargo","rustc","clippy-driver","cargo-clippy","sccache"):continue
   cwd=os.readlink(p/"cwd")
   if cwd==str(R) or cwd.startswith(str(R)+"/"):rows.append(int(p.name))
  except (OSError,ValueError):continue
 return rows
def artifact(path):
 parent,name=S.open_parent(path)
 try:
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
  try:
   a=os.fstat(fd);assert stat.S_ISREG(a.st_mode) and a.st_uid==os.getuid() and not a.st_mode&0o022 and 0<a.st_size<=S.MAX_NATIVE_BYTES
   h=hashlib.sha256();count=0
   while True:
    raw=os.read(fd,1048576)
    if not raw:break
    count+=len(raw);assert count<=S.MAX_NATIVE_BYTES;h.update(raw)
   b=os.fstat(fd);linked=os.stat(name,dir_fd=parent,follow_symlinks=False)
   fields=("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns","st_nlink","st_uid","st_mode")
   assert all(getattr(a,f)==getattr(b,f)==getattr(linked,f) for f in fields) and count==a.st_size
   return dict(path=str(path),bytes=count,sha256=h.hexdigest(),mode=oct(stat.S_IMODE(a.st_mode)),nlink=a.st_nlink,inode=a.st_ino,dev=a.st_dev)
  finally:os.close(fd)
 finally:os.close(parent)
assert not compilers()
assert R.stat().st_uid==os.getuid() and stat.S_IMODE(R.stat().st_mode)==0o700 and (R/".git").exists()
head=subprocess.check_output(["git","rev-parse","HEAD"],cwd=R,text=True).strip()
assert head=="97764573fafe03d2167ee7c36a52efe57107d7aa"
artifacts=[R/"target/debug/hepta-runtime",R/"target/release/hepta-runtime",pathlib.Path("/home/qian-qi/hepta-runtime-v9-pinned-native-92c3ae-20261013")]
pins={str(p):artifact(p) for p in artifacts}
assert pins[str(artifacts[0])]["sha256"]=="9b36496eb1a695de04e5c41e3f1ffcebe5587089709d5c7a4361a9db18173de2"
assert pins[str(artifacts[1])]["sha256"]==pins[str(artifacts[2])]["sha256"]=="92c3ae0eb64e8d2213e4938312ae636a2ab6d18ef417b2167086d0737d7664ce"
services=P.service_observation("/home/qian-qi/.config/hepta-runtime-operator/token")
process=P.process_observation(int(services["units"][P.UNITS[0]]["MainPID"]))
parent,name=S.open_parent(T)
try:
 a=os.stat(name,dir_fd=parent,follow_symlinks=False)
 assert stat.S_ISDIR(a.st_mode) and a.st_uid==os.getuid()
finally:os.close(parent)
entries=0;size=0
for p in T.rglob("*"):
 s=p.lstat()
 assert s.st_uid==os.getuid() and (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode))
 entries+=1
 if stat.S_ISREG(s.st_mode):size+=s.st_size
assert not Q.exists();Q.mkdir(mode=0o700)
(Q/"driver.py").write_bytes(pathlib.Path(__file__).read_bytes())
intent={"head":head,"only_target":str(T),"target_inode":a.st_ino,"target_dev":a.st_dev,"entries":entries,"logical_bytes":size,"preserved_artifacts":pins,"services_before":services,"process_before":process,"scope":"unlink only inactive owned Cargo incremental cache names behind owner-only worktree; no linked file content changes"}
(Q/"intent.json").write_text(json.dumps(intent,sort_keys=True,indent=2)+"\n")
assert not compilers()
parent,name=S.open_parent(T)
try:
 b=os.stat(name,dir_fd=parent,follow_symlinks=False)
 assert (a.st_dev,a.st_ino,a.st_uid)==(b.st_dev,b.st_ino,b.st_uid)
 moved=name+".retired-dc-owned-20261013-r31"
 try:os.stat(moved,dir_fd=parent,follow_symlinks=False)
 except FileNotFoundError:pass
 else:raise FileExistsError("owned retired destination exists")
 os.rename(name,moved,src_dir_fd=parent,dst_dir_fd=parent)
 c=os.stat(moved,dir_fd=parent,follow_symlinks=False)
 assert (c.st_dev,c.st_ino)==(a.st_dev,a.st_ino)
finally:os.close(parent)
retired=T.parent/moved
shutil.rmtree(retired)
assert not retired.exists() and not T.exists()
after={str(p):artifact(p) for p in artifacts}
assert after==pins and P.service_observation("/home/qian-qi/.config/hepta-runtime-operator/token")==services and P.process_observation(process["pid"])==process
v=os.statvfs(R)
receipt={**intent,"completed":True,"removed_only":[str(T)],"preserved_artifacts_after":after,"services_unchanged":True,"process_unchanged":True,"v10_or_unrelated_worktrees_touched":False,"source_or_evidence_deleted":False,"installed_token_opened_or_changed":False,"available_bytes_after":v.f_bavail*v.f_frsize,"full_dc_replacement_qualified":False}
(Q/"receipt.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
print(json.dumps({"completed":True,"removed_only":[str(T)],"available_bytes_after":receipt["available_bytes_after"],"preserved_binary_bytes_inodes_links":True,"protected_service_identities_unchanged":True},sort_keys=True))
