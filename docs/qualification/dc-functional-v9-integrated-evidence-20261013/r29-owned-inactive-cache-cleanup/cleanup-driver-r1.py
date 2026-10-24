#!/usr/bin/env python3
import pathlib,os,stat,json,hashlib,subprocess,shutil,sys
R=pathlib.Path("/home/qian-qi/hepta-runtime-dc-functional-20261013")
Q=R/"docs/qualification/dc-functional-v9-integrated-evidence-20261013/r29-owned-inactive-cache-cleanup"
targets=[pathlib.Path("/home/qian-qi/hepta-runtime-cancel-identity-20261013/target/debug/incremental"),pathlib.Path("/home/qian-qi/hepta-runtime-credential-scope-20261013/target/debug/incremental"),R/"target/debug/incremental"]
def rust_processes():
 rows=[]
 for p in pathlib.Path("/proc").iterdir():
  if not p.name.isdigit():continue
  try:
   if p.stat().st_uid!=os.getuid():continue
   if (p/"comm").read_text().strip() not in ("cargo","rustc","sccache"):continue
   cwd=os.readlink(p/"cwd")
   if any(cwd.startswith(str(t.parents[2])) for t in targets):rows.append(int(p.name))
  except (OSError,ValueError):continue
 return rows
assert not rust_processes(),"leave all caches untouched while own target compiler is active"
sys.path.insert(0,"/home/qian-qi/hepta-successor-preflight-checker-3791c11-20261013-r3/deploy")
import preflight_dc_successor as P
import stage_dc_successor as S
services=P.service_observation("/home/qian-qi/.config/hepta-runtime-operator/token")
process=P.process_observation(int(services["units"][P.UNITS[0]]["MainPID"]))
artifacts=[R/"target/debug/hepta-runtime",R/"target/release/hepta-runtime",pathlib.Path("/home/qian-qi/hepta-runtime-v9-pinned-native-92c3ae-20261013")]
pins={str(p):S.snapshot(p,"retained compiled artifact",S.MAX_NATIVE_BYTES)[1] for p in artifacts}
before=[]
for t in targets:
 parent,name=S.open_parent(t)
 try:
  inf=os.stat(name,dir_fd=parent,follow_symlinks=False)
  assert stat.S_ISDIR(inf.st_mode) and inf.st_uid==os.getuid() and not inf.st_mode&0o022
 finally:os.close(parent)
 root=t.parents[2];assert root.name in ("hepta-runtime-cancel-identity-20261013","hepta-runtime-credential-scope-20261013","hepta-runtime-dc-functional-20261013")
 assert (root/".git").exists() and not (root/".git").is_symlink()
 count=0;total=0
 for p in t.rglob("*"):
  s=p.lstat();assert s.st_uid==os.getuid() and (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)) and not s.st_mode&0o022
  if stat.S_ISREG(s.st_mode):assert s.st_nlink==1;total+=s.st_size
  count+=1
 before.append({"path":str(t),"dev":inf.st_dev,"inode":inf.st_ino,"uid":inf.st_uid,"mode":oct(stat.S_IMODE(inf.st_mode)),"entries":count,"logical_file_bytes":total})
assert not Q.exists();Q.mkdir(mode=0o700)
(Q/"intent.json").write_text(json.dumps({"scope":"only named current-UID inactive Cargo incremental cache directories","targets":before,"preserved_compiled_artifacts":pins,"services_before":services,"process_before":process,"unrelated_operator_worktree_touched":False},sort_keys=True,indent=2)+"\n")
retired=[]
for t,pin in zip(targets,before):
 assert not rust_processes(),"stop cleanup before touching next cache if own compiler appears"
 parent,name=S.open_parent(t)
 try:
  current=os.stat(name,dir_fd=parent,follow_symlinks=False)
  assert (current.st_dev,current.st_ino,current.st_uid)==(pin["dev"],pin["inode"],pin["uid"])
  moved=name+".retired-dc-owned-20261013-r1"
  try:os.stat(moved,dir_fd=parent,follow_symlinks=False)
  except FileNotFoundError:pass
  else:raise FileExistsError("retired cache destination exists")
  os.rename(name,moved,src_dir_fd=parent,dst_dir_fd=parent)
  changed=os.stat(moved,dir_fd=parent,follow_symlinks=False)
  assert (changed.st_dev,changed.st_ino)==(pin["dev"],pin["inode"])
 finally:os.close(parent)
 owned=t.parent/moved
 shutil.rmtree(owned)
 retired.append(str(t))
 assert not t.exists() and not owned.exists()
after={str(p):S.snapshot(p,"retained compiled artifact",S.MAX_NATIVE_BYTES)[1] for p in artifacts}
assert after==pins and P.service_observation("/home/qian-qi/.config/hepta-runtime-operator/token")==services and P.process_observation(process["pid"])==process
v=os.statvfs(R)
receipt={"schema":"hepta-owned-inactive-incremental-cache-cleanup-v1","completed":True,"removed_only":retired,"targets_before":before,"preserved_compiled_artifacts_before":pins,"preserved_compiled_artifacts_after":after,"services_before":services,"services_after":services,"process_before":process,"process_after":process,"source_or_qualification_evidence_deleted":False,"live_token_opened_or_changed":False,"installed_native_or_dc_changed":False,"unrelated_operator_worktree_touched":False,"available_bytes_after":v.f_bavail*v.f_frsize,"full_dc_replacement_qualified":False}
(Q/"receipt.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
print(json.dumps({"completed":True,"removed_only":retired,"available_bytes_after":receipt["available_bytes_after"],"retained_binary_hashes_unchanged":True,"services_unchanged":True},sort_keys=True))
