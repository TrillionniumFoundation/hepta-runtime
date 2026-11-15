#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""One-shot independent R15 configuration and recovery audits after all measurements."""
import argparse,json,os,subprocess,sys,time
from pathlib import Path
import r15_configuration_recovery_common as c

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("--expected-ready-sha256",required=True)
 args=parser.parse_args();os.umask(0o077)
 here=Path(__file__).resolve().parent
 out=here/"configuration-recovery-audit-attempt-01"
 out.mkdir(mode=0o700,exist_ok=False)
 execution={"schema":"hepta-r15-configuration-recovery-audit-execution/v1","success":False,"started_utc":c.now(),"stages":[],"automatic_retries":0,"rust_tests_run":0,"benchmarks_run":0,"compilation_started":False}
 def save():
  temp=out/"execution.next";temp.write_text(json.dumps(execution,indent=2)+"\n");os.replace(temp,out/"execution.json")
 save()
 try:
  ready=c.load(here/"configuration-recovery-auditors-ready-01.json",args.expected_ready_sha256)
  c.need(ready.get("success") is True and ready.get("formal_workloads_started") is False,"auditor readiness differs")
  for item in ready["files"]:c.bind(item["path"],item["sha256"])
  c.all_measurements_finished()
  c.need(not (c.ROOT/"qualification-audit-summary.json").exists() and not (c.ROOT/"independent-recovery-audit.json").exists(),"independent outputs already exist; no overwrite/retry")
  for name,script,timeout in (("qualification","audit_qualification_r15.py",900),("recovery","audit_recovery_r15.py",300)):
   row={"name":name,"script":str(here/script),"started_utc":c.now(),"returncode":None,"automatic_retries":0}
   execution["stages"].append(row);save();started=time.monotonic()
   stdout,stderr=out/(name+".stdout"),out/(name+".stderr")
   try:
    with stdout.open("xb") as a,stderr.open("xb") as b:
     completed=subprocess.run(["/usr/bin/python3","-B",str(here/script)],cwd=c.ROOT,
      env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C","PYTHONDONTWRITEBYTECODE":"1","PYTHONNOUSERSITE":"1"},
      stdout=a,stderr=b,timeout=timeout)
    row["returncode"]=completed.returncode
    c.need(completed.returncode==0,"independent "+name+" audit failed; no automatic retry")
   finally:
    row["seconds"]=time.monotonic()-started;row["finished_utc"]=c.now()
    row["stdout"]={"path":str(stdout),"sha256":c.sha_file(stdout)}
    row["stderr"]={"path":str(stderr),"sha256":c.sha_file(stderr)};save()
  for name in ("qualification-audit-summary.json","independent-recovery-audit.json"):
   report=c.load(c.ROOT/name);c.need(report.get("success") is True,"independent terminal report unsuccessful")
   execution.setdefault("outputs",[]).append({"path":str(c.ROOT/name),"sha256":c.sha_file(c.ROOT/name)})
  for item in ready["files"]:c.bind(item["path"],item["sha256"])
  execution["success"]=True
 except BaseException as error:
  execution["error"]={"type":type(error).__name__,"reason":str(error)[:3000]}
 finally:
  execution["finished_utc"]=c.now();save()
  print(json.dumps({"success":execution["success"],"execution":str(out/"execution.json"),"sha256":c.sha_file(out/"execution.json"),"outputs":execution.get("outputs"),"error":execution.get("error")}),flush=True)
 return 0 if execution["success"] else 1

if __name__=="__main__":sys.exit(main())
