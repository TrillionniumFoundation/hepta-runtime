#!/usr/bin/env python3
"""Run the declared fixed-source control adapter while rejecting semantic execution."""
from __future__ import annotations
import argparse,ctypes,hashlib,importlib.util,json,mmap,os,runpy,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import filesystem_fast_guard
sys.dont_write_bytecode=True
ROOT=Path("/home/runner/work/_temp/hia-historical-public58")
SCRIPTS={
 "filesystem":("tests/hia_native/filesystem_parity/qualify_pipeline.py","aec910dc9f700e94d1f5e61910c9bd0afce35ba659ba02e2afe70adc2ca9493b"),
 "regex":("tests/hia_native/check_regex_evidence.py","0b259f75ff2ee54c802552ac1fc19e9f0de62b75c9b382276375acbde327c1ee")}
def need(v,s):
 if not v:raise ValueError(s)
def main():
 p=argparse.ArgumentParser();p.add_argument("--kind",choices=SCRIPTS,required=True)
 p.add_argument("--audit-receipt",type=Path,required=True);p.add_argument("args",nargs=argparse.REMAINDER);a=p.parse_args()
 relative,digest=SCRIPTS[a.kind];source=ROOT/relative;raw=source.read_bytes()
 need(hashlib.sha256(raw).hexdigest()==digest,"exact unchanged original control source")
 argv=a.args[1:] if a.args and a.args[0]=="--" else a.args
 need(argv and argv[0]==str(source),"actual original control path")
 need(not a.audit_receipt.exists(),"create-only audit receipt")
 sys.path[:0]=[str(ROOT/"scripts"),str(ROOT/"tests/hia_native")]
 # Load ordinary definitions before the execution-denial scope. The original
 # main remains byte-for-byte and is invoked with its original argument shape.
 if a.kind=="filesystem":import hia_native_filesystem_parity_qualification
 else:import hia_native_config_qualification
 forbidden=[];active=[True];probe=[False];rejected_probes=[]
 def audit(event,args):
  if not active[0]:return
  if event in {"subprocess.Popen","os.system","os.exec","os.posix_spawn","os.fork","os.forkpty"} or event.startswith("ctypes.") or event=="mmap.__new__":
   row={"event":event,"probe":probe[0]};forbidden.append(row)
   raise PermissionError("pure evidence control cannot execute a process or native image: "+event)
 sys.addaudithook(audit)
 start=time.monotonic_ns();status="FAIL";error=None;adapter=None
 try:
  for label,fn in [
   ("process",lambda:subprocess.Popen(["/bin/true"])),
   ("native-map",lambda:mmap.mmap(-1,4096)),
   ("native-library",lambda:ctypes.CDLL(None))]:
   probe[0]=True;n=len(forbidden)
   try:fn()
   except PermissionError:need(len(forbidden)==n+1,"control guard probe did not reach its audit event");rejected_probes.append(label)
   else:raise ValueError("control guard probe was admitted")
   finally:probe[0]=False
  sys.argv=argv
  if a.kind=="filesystem":adapter=filesystem_fast_guard.run_original(source,a.audit_receipt.parent)
  else:runpy.run_path(str(source),run_name="__main__")
  need(not any(not x["probe"] for x in forbidden),"original control attempted semantic execution")
  status="PASS"
 except BaseException as exc:
  error={"type":type(exc).__name__,"message":str(exc)};raise
 finally:
  active[0]=False
  value={"schema":"hepta.history.skipped-control-audit.v1","status":status,"kind":a.kind,
   "source":{"path":relative,"bytes":len(raw),"sha256":digest},"argv":argv,
   "pid":os.getpid(),"parent_pid":os.getppid(),"pgid":os.getpgrp(),
   "elapsed_ns":time.monotonic_ns()-start,"native_or_rust_executions":0,
   "execution_attempts":forbidden,"guard_probes":rejected_probes,"error":error,
   "filesystem_guard_adapter":adapter}
  with a.audit_receipt.open("xb") as f:f.write((json.dumps(value,sort_keys=True,indent=2)+"\n").encode())
if __name__=="__main__":main()
