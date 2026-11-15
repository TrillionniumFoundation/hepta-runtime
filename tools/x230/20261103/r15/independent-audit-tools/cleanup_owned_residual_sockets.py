#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Delete only six proven stale sockets and their two owned empty private directories."""
import argparse,datetime,hashlib,json,os,stat
from pathlib import Path
ROOT=Path("/home/qian/hepta-runtime-optimization-20261103-r15")
PARENT=Path("/home/qian/h15c1")
POOL="hp-o-2385590-59287ebcd523a7f4afc13dfa62cd7059"
NAMES={"m-13","m-15","m-19","m-21","m-23","m-55"}
OUT=ROOT/"independent-audit-tools/socket-cleanup-01.json"
def need(x,message):
 if not x:raise RuntimeError(message)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def open_dir(p):
 fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  for name in Path(p).parts[1:]:
   nxt=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);os.close(fd);fd=nxt
  return fd
 except BaseException:os.close(fd);raise
def meta(s):
 return {"dev":s.st_dev,"inode":s.st_ino,"uid":s.st_uid,"gid":s.st_gid,"mode":oct(stat.S_IMODE(s.st_mode)),
         "nlink":s.st_nlink,"size":s.st_size,"mtime_ns":s.st_mtime_ns,"ctime_ns":s.st_ctime_ns}
def dir_matches(fd,expected):
 s=os.fstat(fd)
 need(stat.S_ISDIR(s.st_mode) and [s.st_dev,s.st_ino,s.st_uid,s.st_mode]==expected,"owned directory binding differs")
def no_live(report):
 entries=[l for l in Path("/proc/net/unix").read_text().splitlines() if str(PARENT)+"/" in l]
 need(not entries,"kernel socket remains active in owned subtree")
 observed=[]
 for key in ("first_startup","after_crash_startup","after_cancel_startup"):
  observed.append((report[key]["pid"],report[key]["birth_ticks"]))
 for key in ("original_master","replacement_master"):
  row=report["transport_interruption"][key];observed.append((row["pid"],row["birth_ticks"]))
 for pid,birth in observed:
  try:
   f=Path("/proc",str(pid),"stat").read_text().rsplit(") ",1)[1].split()
   need(int(f[19])!=birth,"known owned process generation still exists")
  except FileNotFoundError:pass
 for d in Path("/proc").iterdir():
  if not d.name.isdigit():continue
  try:
   if (d/"comm").read_text().strip()!="ssh":continue
   args=(d/"cmdline").read_bytes().split(b"\0")
   need(not any(os.fsencode(str(PARENT)) in a for a in args),"SSH process still references private parent")
  except FileNotFoundError:pass
 return {"utc":now(),"kernel_entries":0,"matching_ssh_processes":0,"known_owned_generations_absent":True}
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--apply",action="store_true",required=True);parser.parse_args()
 os.umask(0o077)
 need(not OUT.exists(),"cleanup receipt already exists; no retry")
 diag_path=ROOT/"independent-audit-tools/socket-residual-readonly-01.json"
 need(sha(diag_path)=="45f86817d18b5b93a37279ef4ddee9273819f4800c0881aaa6c2508bda1176ab","before evidence changed")
 previous=json.loads(diag_path.read_bytes())
 remote_path=ROOT/"remote-campaigns-01/report.json"
 need(sha(remote_path)=="defff42c03b3a7f0a7910c627b7d0c6f392064980f5b3bb4a7f8b99d0a9acafd","remote report changed")
 remote=json.loads(remote_path.read_bytes())
 raw_path=ROOT/"cancel-recovery-01/report.json"
 need(sha(raw_path)=="f5f80f466ce4d1f33caecc605591576d3487d9aa808023ad9502b78e8b7a698c","recovery report changed")
 report=json.loads(raw_path.read_bytes())
 need(remote["success"] is True and report["passed"] is True,"formal recovery incomplete")
 need(report["first_startup"]["pid"]==2385590,"first controller changed")
 ownership=report["transport_interruption"]["replacement_master"]["private_directories"]
 need(ownership==[[str(PARENT),2053,2304071,1000,16832],[str(PARENT/POOL),2053,2304072,1000,16832]],"historical directory ownership differs")
 need(report["transport_interruption"]["original_master"]["private_directories"]==ownership,"owned master directory generations differ")
 parent_binding=remote["socket_parents"]["recovery"]
 need(parent_binding=={"device":2053,"inode":2304071,"uid":1000,"mode":448,"path":str(PARENT)},"orchestrator parent ownership differs")
 receipt={"schema":"hepta-r15-owned-stale-socket-cleanup/v1","success":False,"started_utc":now(),
  "script_sha256":sha(__file__),"signals_sent":0,"production_service_mutations":0,
  "before_diagnostic_sha256":sha(diag_path),"recovery_report_sha256":sha(raw_path),
  "remote_report_sha256":sha(remote_path),"historical_owned_directories":ownership,"removed":[]}
 def save():
  p=OUT.with_name(OUT.name+".next");p.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n");os.replace(p,OUT)
 home=parent=pool=None
 try:
  home=open_dir(PARENT.parent);parent=open_dir(PARENT);pool=open_dir(PARENT/POOL)
  dir_matches(parent,ownership[0][1:]);dir_matches(pool,ownership[1][1:])
  need(set(os.listdir(parent))=={POOL} and set(os.listdir(pool))==NAMES,"unexpected owned subtree entries")
  before={Path(x["path"]).name:x for x in previous["directory"] if x["type"]=="socket"}
  need(set(before)==NAMES,"before diagnostic socket set differs")
  receipt["before"]={"parent":meta(os.fstat(parent)),"pool":meta(os.fstat(pool)),"sockets":{}}
  for name in sorted(NAMES):
   s=os.stat(name,dir_fd=pool,follow_symlinks=False);m=meta(s)
   need(stat.S_ISSOCK(s.st_mode) and s.st_nlink==1 and s.st_uid==1000 and stat.S_IMODE(s.st_mode)==0o600,"selected leaf is not one private socket")
   need(all(m[k]==before[name][k] for k in ("dev","inode","uid","gid","mode","size","mtime_ns","ctime_ns")),"socket identity changed since readonly snapshot")
   receipt["before"]["sockets"][name]=m
  receipt["preflight_no_live"]=no_live(report);save()
  for name in sorted(NAMES):
   no_live(report);s=os.stat(name,dir_fd=pool,follow_symlinks=False)
   need(meta(s)==receipt["before"]["sockets"][name] and stat.S_ISSOCK(s.st_mode),"socket was replaced before unlink")
   os.unlink(name,dir_fd=pool)
   receipt["removed"].append({"path":str(PARENT/POOL/name),"identity":meta(s),"operation":"unlink-stale-socket","utc":now()});save()
  need(not os.listdir(pool),"owned pool not empty after exact socket removal")
  dir_matches(pool,ownership[1][1:]);dir_matches(parent,ownership[0][1:])
  need(meta(os.stat(POOL,dir_fd=parent,follow_symlinks=False))==meta(os.fstat(pool)),"pool path replaced")
  os.rmdir(POOL,dir_fd=parent);receipt["removed"].append({"path":str(PARENT/POOL),"operation":"rmdir-empty-owned-pool","utc":now()});save()
  need(not os.listdir(parent),"owned parent not empty")
  dir_matches(parent,ownership[0][1:])
  need(meta(os.stat(PARENT.name,dir_fd=home,follow_symlinks=False))==meta(os.fstat(parent)),"parent path replaced")
  os.rmdir(PARENT.name,dir_fd=home);receipt["removed"].append({"path":str(PARENT),"operation":"rmdir-empty-owned-parent","utc":now()})
  receipt["after_no_live"]=no_live(report)
  receipt["after"]={"parent_exists":os.path.lexists(PARENT),"pool_exists":os.path.lexists(PARENT/POOL),
   "selected_sockets_exist":{n:os.path.lexists(PARENT/POOL/n) for n in sorted(NAMES)}}
  need(receipt["after"]["parent_exists"] is False,"private parent unexpectedly exists after cleanup")
  receipt["success"]=True
 except BaseException as error:
  receipt["error"]={"type":type(error).__name__,"reason":str(error)}
  raise
 finally:
  receipt["finished_utc"]=now();save()
  for fd in (pool,parent,home):
   if fd is not None:os.close(fd)
  print(json.dumps({"success":receipt["success"],"path":str(OUT),"sha256":sha(OUT),"removed_count":len(receipt["removed"]),"error":receipt.get("error")}),flush=True)

if __name__=="__main__":main()
