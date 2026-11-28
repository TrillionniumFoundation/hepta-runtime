#!/usr/bin/env python3
"""Complete only the two originally skipped, unchanged evidence-control steps."""
from __future__ import annotations
import argparse,hashlib,json,os,signal,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from read_recovered import SOURCE,CAPTURE,PYTHON,REPORT_SHA,need,pin,put
from run_control import SCRIPTS
FS_LABELS=["native_deadline_not_180","native_claimed_as_original_phase","original_claimed_as_native_phase",
 "duplicate_private_summary_field","resigned_private_return_mismatch","resigned_private_refusal_mutation",
 "retirement_binds_other_native_evidence","reintroduced_live_fixture","another_declared_compiler_than_actual_build",
 "unchanged_original_module_changed","missing_original_retirement"]
REGEX_LABELS=["missing-complete-nfa-half","duplicated-actual-suite","sigkill-cannot-be-pass",
 "timeout-cannot-be-pass","changed-completed-stdout","extended-suite-budget","changed-actual-suite-command",
 "changed-native-source","changed-real-embedded-image","changed-actual-native-corpus",
 "rehash-does-not-admit-duplicated-case","missing-full-original-match-replay",
 "changed-full-original-output","missing-original-startup-refusal-side"]
def execute(folder,kind,args):
 process=None;started=time.monotonic_ns();timed_out=False;failure=None;pgid=None
 stdout=folder/(kind+".stdout");stderr=folder/(kind+".stderr");receipt=folder/(kind+".process.json")
 audit=folder/(kind+".audit.json");command=[str(PYTHON),"-I","-B",str(Path(__file__).with_name("run_control.py")),
  "--kind",kind,"--audit-receipt",str(audit),"--",str(SOURCE/SCRIPTS[kind][0]),*args]
 try:
  with stdout.open("xb") as out,stderr.open("xb") as err:
   process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=out,stderr=err,
    cwd=SOURCE,start_new_session=True)
   pgid=os.getpgid(process.pid);need(pgid==process.pid,"actual owned control process group")
   try:process.wait(timeout=max(0,180-(time.monotonic_ns()-started)/1e9))
   except subprocess.TimeoutExpired:timed_out=True
 except BaseException as exc:
  failure={"type":type(exc).__name__,"message":str(exc)}
 finally:
  # Reap before any receipt write. A full disk or write error cannot skip
  # cleanup of a running child or its owned process group.
  if process is not None:
   try:
    if process.poll() is None:
     try:os.killpg(process.pid,signal.SIGKILL)
     except ProcessLookupError:pass
   finally:process.wait()
 elapsed=time.monotonic_ns()-started
 value={"schema":"hepta.history.skipped-control-process.v1","kind":kind,"command":command,
  "cwd":str(SOURCE),"timeout_seconds":180,"elapsed_ns":elapsed,
  "parent_pid":os.getpid(),"parent_pgid":os.getpgrp(),"pid":process.pid if process else None,"pgid":pgid,
  "exit_code":process.returncode if process else None,"timed_out":timed_out,"start_error":failure,
  "stdout":pin(stdout) if stdout.exists() else None,"stderr":pin(stderr) if stderr.exists() else None,
  "original_source":pin(SOURCE/SCRIPTS[kind][0]),"wrapper_source":pin(Path(__file__).with_name("run_control.py")),
  "original_failed_report_sha256":REPORT_SHA,"native_or_rust_executions":0}
 put(receipt,value)
 need(failure is None and process is not None and process.returncode==0 and not timed_out
      and elapsed<=180000000000,"original evidence control did not finish inside its unchanged 180 seconds")
 need(stderr.read_bytes()==b"","actual evidence-control stderr")
 observed=json.loads(stdout.read_bytes());guard=json.loads(audit.read_bytes())
 need(guard["status"]=="PASS" and guard["pid"]==process.pid and guard["parent_pid"]==os.getpid()
  and guard["pgid"]==pgid and guard["kind"]==kind and guard["argv"]==command[9:]
  and guard["native_or_rust_executions"]==0
  and guard["guard_probes"]==["process","native-map","native-library"]
  and len(guard["execution_attempts"])==3
  and all(x["probe"] is True for x in guard["execution_attempts"]),"actual control audit custody")
 need(observed["status"]=="PASS","original full controls did not pass")
 if kind=="filesystem":
  need(observed["controls"]==11 and [x["name"] for x in observed["events"]]==FS_LABELS
   and all(x["status"]=="REJECTED" for x in observed["events"])
   and observed["physical_relocations"]==2 and observed["actual_foreign_path_refusals"]==12
   and observed["all_source_and_artifacts_unchanged"] is True
   and observed["new_native_calls"]==observed["new_rust_processes"]==observed["new_processes"]==0,
   "complete original filesystem controls")
 else:
  need(observed["negative_control_count"]==14 and [x["name"] for x in observed["negative_controls"]]==REGEX_LABELS
   and all(x["rejected"] is True for x in observed["negative_controls"])
   and observed["actual_baseline_admissions"]==6 and observed["source_and_artifacts_restored"] is True
   and observed["native_calls_added"]==observed["original_processes_added"]==0
   and observed["actual_process_report_sha256"]==REPORT_SHA,"complete original configuration/regex controls")
 return {"process":value,"audit":guard,"original_summary":observed}
def main():
 p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
 out=a.output.absolute();out.mkdir(mode=0o700,parents=True,exist_ok=False)
 need(pin(CAPTURE/"result.json")["sha256"]==REPORT_SHA,"keep original failed report")
 common=["--repo",str(SOURCE),"--output",str(CAPTURE),"--report",str(CAPTURE/"result.json")]
 fs=execute(out,"filesystem",[*common,"--controls",str(out/"filesystem-controls")])
 regex=execute(out,"regex",[*common,"--receipt",str(out/"regex-controls.json")])
 need(pin(CAPTURE/"result.json")["sha256"]==REPORT_SHA,"original report changed during controls")
 result={"schema":"hepta.history.skipped-evidence-controls.v1","status":"PASS",
  "filesystem":fs,"regex":regex,"original_failed_report_preserved":True,
  "original_completed_controls_rerun":False,"native_or_rust_executions":0}
 put(out/"SKIPPED_CONTROLS.json",result)
 print(json.dumps({"status":result["status"],"filesystem_controls":11,"regex_controls":14,
  "native_or_rust_executions":0},sort_keys=True))
if __name__=="__main__":main()
