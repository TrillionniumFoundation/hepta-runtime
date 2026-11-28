#!/usr/bin/env python3
"""Independently bind complete original config/regex controls to their sealed physical inputs."""
from __future__ import annotations
import argparse,gzip,hashlib,json,os,stat,sys,time,zipfile
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import read_only_guard as guard
from origin import verify_origin,artifact_expectations
SOURCE="/home/runner/work/_temp/hia-historical-public58"
CAPTURE="/home/runner/work/_temp/hia-runtime-native"
RUN="/home/runner/work/_temp/history-regex-proof/run"
REPORT={"bytes":94615186,"sha256":"83437daf7232222bf19025a2c4b395ec4da70179984f2a52763abb452fd98078"}
LABELS=["missing-complete-nfa-half","duplicated-actual-suite","sigkill-cannot-be-pass",
 "timeout-cannot-be-pass","changed-completed-stdout","extended-suite-budget","changed-actual-suite-command",
 "changed-native-source","changed-real-embedded-image","changed-actual-native-corpus",
 "rehash-does-not-admit-duplicated-case","missing-full-original-match-replay",
 "changed-full-original-output","missing-original-startup-refusal-side"]
def need(v,s):
    if not v:raise ValueError(s)
def read(p):return json.loads(p.read_bytes())
def gz(p):
    with gzip.open(p,"rb") as f:return json.loads(f.read())
def pin(p):
    info=p.lstat();need(stat.S_ISREG(info.st_mode) and p.resolve()==p.absolute(),"ordinary retained file")
    with p.open("rb") as f:h=hashlib.file_digest(f,"sha256").hexdigest()
    after=p.lstat()
    need(all(getattr(info,k)==getattr(after,k) for k in
             ("st_mode","st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns")),"whole file stable")
    return {"bytes":info.st_size,"sha256":h}
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def table(root):
    return {p.relative_to(root).as_posix():{**pin(p),"mode":stat.S_IMODE(p.lstat().st_mode)}
            for p in root.rglob("*") if p.is_file()}
def snapshot_files(values):
    return {name:{"bytes":row["bytes"],"sha256":row["sha256"],"mode":stat.S_IMODE(row["mode"])}
            for name,row in values.items() if stat.S_ISREG(row["mode"])}
def verify(home,archive_pin):
    complete=read(home/"COMPLETE_READBACK.json");members=read(home/"COMPLETE_MEMBER_PINS.json")
    need(complete["status"]=="COMPLETE_ARCHIVE_BYTES_AND_GIT_SOURCES_PASS" and complete["kind"]=="regex"
         and complete["zip"]==archive_pin==artifact_expectations("regex")["zip"]
         and complete["inner_archive"]==artifact_expectations("regex")["inner"]
         and complete["continuation_status"]=="PASS","complete exact artifact admission")
    root=home/"proof";proof=root/"proof";source=root/"source";hs=root/"historical-source";cap=root/"regex-input";run=proof/"run"
    need({p.relative_to(root).as_posix() for p in root.rglob("*")}=={r["path"] for r in members},"entire physical member set")
    for row in members:
        p=root/row["path"];info=p.lstat();need(stat.S_IMODE(info.st_mode)==row["mode"],"all complete modes")
        if row["type"]=="file":need(pin(p)=={k:row[k] for k in ("bytes","sha256")},"all complete file bytes")
        else:need(row["type"]=="directory" and stat.S_ISDIR(info.st_mode),"all ordinary directory types")
    need(pin(source/"SOURCE_MANIFEST.json")=={"bytes":3666,"sha256":"e3529089f07568839f4a9867d7dc84a7d4dac156140d11682b8b39798a1bfe15"},"exact executed continuation source closure")
    manifest=read(source/"SOURCE_MANIFEST.json")
    need(set(table(source))==set(manifest["files"])|{"SOURCE_MANIFEST.json"} and len(manifest["files"])==16,"complete executed source set")
    for name,row in manifest["files"].items():
        raw=(source/name).read_bytes()
        need(pin(source/name)=={k:row[k] for k in ("bytes","sha256")}
             and hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==row["git_blob"],"all executed Git blobs")
    prep=read(proof/"preparation/PREPARATION.json");result=read(run/"CONTINUATION.json")
    need(prep["status"]=="COMPLETE_SEALED_INPUT_SUBSET_PASS" and prep["source"]==SOURCE and prep["capture"]==CAPTURE
         and prep["source_pins_rebound"] is False and prep["full_aggregate_reexecuted"] is False
         and prep["original_failure_reclassified_as_pass"] is False and prep["native_or_rust_executions"]==0
         and prep["original_report"]==REPORT and prep["subset_only"] is True,"exact untouched original subset boundary")
    count,logical=verify_origin(proof,hs,cap,prep,"regex")
    need(result["status"]=="PASS" and result["error"] is None and result["preparation"]==pin(proof/"preparation/PREPARATION.json")
         and result["source_manifest"]==pin(source/"SOURCE_MANIFEST.json")
         and result["full_input_bytes_modes_restored"] is True and result["full_aggregate_reexecuted"] is False
         and result["original_failure_reclassified_as_pass"] is False and result["native_or_rust_executions"]==0,"actual complete pending-control result")
    before=gz(run/"before.json.gz");after=gz(run/"after.json.gz")
    for role,folder,key in (("source",hs,"source_files"),("capture",cap,"output_files")):
        need(set(before[role])==set(after[role]),"all original inputs retained")
        need(table(folder)==prep[key]==snapshot_files(before[role])==snapshot_files(after[role]),"all complete input byte/mode identities restored")
        for name,row in before[role].items():
            need(all(row[field]==after[role][name][field] for field in ("mode","inode","device","bytes","sha256")),
                 "all original inodes/devices/bytes/modes retained")
    need(len(prep["source_files"])==2879 and pin(cap/"result.json")==REPORT,"complete original materialized source and report")
    original=read(cap/"result.json")
    need(original["status"]=="PASS" and original["phase"]=="complete" and len(original["checks"])==405
         and len(original["original_rust_comparisons"])==81,"original aggregate unchanged; outer workflow remains FAIL")
    sealed=[original["config_evidence"]["artifact_sha256"],
            original["original_rust_comparisons"]["runtime_config"]["configuration"]["artifact_sha256"],
            original["original_rust_comparisons"]["runtime_config"]["regex"]["artifact_sha256"]]
    union={}
    for one in sealed:
        for name,digest in one.items():
            need(name not in union or union[name]==digest,"no conflicting sealed identity");union[name]=digest
    need(union==prep["sealed_artifact_subset"],"all original config/regex seals")
    need({name:row["sha256"] for name,row in prep["output_files"].items()}=={**union,"result.json":REPORT["sha256"]},"entire exact union")
    bundle=read(cap/"build/config-build.json");old_manifest=Path(bundle["executables"]["mcp"]["path"])
    need(old_manifest.is_relative_to(Path(CAPTURE)),"original captured manifest path")
    local_manifest=cap/old_manifest.relative_to(CAPTURE);elf=old_manifest.parent/read(local_manifest)["executable"]
    need(elf.is_relative_to(Path(CAPTURE)),"original captured ELF path")
    allowed={"source":["native/regex_nfa.hepta"],"capture":sorted([
      elf.relative_to(CAPTURE).as_posix(),"regex-native/nfa-0/native-output.txt",
      "regex-native/nfa-0/case-indices.json","regex-native/nfa-0/native-corpus.json","test_regex_nfa_0.py.stdout",
      "regex-original/report.json","regex-original/match.stdout.gz","config-original/regex-mcp/report.json"])}
    changes={role:sorted(name for name in before[role] if before[role][name]!=after[role][name]) for role in before}
    need(changes==allowed==result["allowed_metadata_changes"]==result["actual_metadata_changes"],"only and all nine original controlled metadata changes")
    process=read(run/"regex.process.json");audit=read(run/"regex.audit.json");summary=read(run/"regex.stdout")
    need(result["actual_regex_control"]=={"process":process,"audit":audit,"original_summary":summary},"all actual child receipts/streams")
    for field in ("pid","pgid","parent_pid","parent_pgid","elapsed_ns","timeout_seconds","exit_code"):
        need(type(process[field])is int,"precise integer process field")
    need(process["kind"]=="regex" and process["cwd"]==SOURCE and process["pid"]==process["pgid"]>0
         and process["parent_pid"]>0 and process["parent_pgid"]>0 and process["pid"]!=process["parent_pid"]
         and process["exit_code"]==0 and process["timed_out"] is False and process["start_error"] is None
         and process["timeout_seconds"]==180 and 0<process["elapsed_ns"]<=180000000000,"actual original child deadline and owned reaping")
    need(process["elapsed_ns"]==artifact_expectations("regex")["child_elapsed_ns"],"actual fixed CI child duration")
    expected=[SOURCE+"/tests/hia_native/check_regex_evidence.py","--repo",SOURCE,"--output",CAPTURE,
              "--report",CAPTURE+"/result.json","--receipt",RUN+"/regex-controls.json"]
    need(process["command"]==["/home/runner/work/_temp/hia-native-python/bin/python3","-I","-B",
        "/home/runner/work/hepta-runtime/hepta-runtime/reader/qualification/history99/controls-v1/run_control.py",
        "--kind","regex","--audit-receipt",RUN+"/regex.audit.json","--",*expected],"fixed original execution wire")
    need(process["original_source"]==pin(hs/"tests/hia_native/check_regex_evidence.py")
         and process["original_source"]["sha256"]=="0b259f75ff2ee54c802552ac1fc19e9f0de62b75c9b382276375acbde327c1ee"
         and process["wrapper_source"]==pin(source/"run_control.py")
         and process["wrapper_source"]["sha256"]=="2e8947267d551870ceb8772b913684f3ab0f0f374eb4fa7a2101d85803b0f1f4"
         and process["original_failed_report_sha256"]==REPORT["sha256"],"unchanged original code and audit wrapper")
    for name in ("stdout","stderr"):need(process[name]==pin(run/("regex."+name)),"whole child stream identity")
    need((run/"regex.stderr").read_bytes()==b"" and summary==read(run/"regex-controls.json"),"actual stdout/empty stderr/original receipt")
    need(audit["status"]=="PASS" and audit["error"] is None and audit["kind"]=="regex" and audit["argv"]==expected
         and audit["pid"]==process["pid"] and audit["parent_pid"]==process["parent_pid"] and audit["pgid"]==process["pgid"]
         and audit["native_or_rust_executions"]==0 and audit["guard_probes"]==["process","native-map","native-library"]
         and audit["execution_attempts"]==[{"event":"subprocess.Popen","probe":True},{"event":"mmap.__new__","probe":True},
                                          {"event":"ctypes.dlopen","probe":True}],"actual no-execution audit/probes")
    need(summary["status"]=="PASS" and summary["negative_control_count"]==14
         and [r["name"] for r in summary["negative_controls"]]==LABELS
         and all(r["rejected"] is True and r["message"] and r["elapsed_seconds"]>=0 for r in summary["negative_controls"])
         and summary["actual_baseline_admissions"]==6 and summary["source_and_artifacts_restored"] is True
         and summary["native_calls_added"]==summary["original_processes_added"]==0
         and summary["actual_process_report_sha256"]==REPORT["sha256"]
         and summary["checker_sha256"]==process["original_source"]["sha256"]
         and summary["unconstrained_regex_resources_closed"] is False,"all original refusal and admission domains")
    for name,digest in summary["source_pins"].items():
        need(prep["source_files"][name]["sha256"]==digest,"complete original source seal")
    return {"schema":"hepta.history.regex-continuation-independent.v1","status":"COMPLETE_REGEX_CONTINUATION_READBACK_PASS",
      "archive":complete,"original_report":REPORT,"source_files":2879,"sealed_artifacts":len(union),
      "original_index_entries":count,"original_logical_bytes":logical,
      "original_refusals":14,"complete_admissions":6,"actual_metadata_changes":changes,"process":process,
      "all_input_bytes_modes_restored":True,"original_failure_reclassified_as_pass":False,"native_or_rust_executions":0}
def main():
    p=argparse.ArgumentParser();p.add_argument("--readback",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--zip-bytes",type=int,required=True);p.add_argument("--zip-sha256",required=True);a=p.parse_args()
    out=a.output.absolute();out.mkdir(mode=0o700,parents=True,exist_ok=False);start=time.monotonic_ns()
    home=a.readback.absolute();archive_pin={"bytes":a.zip_bytes,"sha256":a.zip_sha256}
    gzip.decompress(gzip.compress(b"preload",mtime=0))
    diagnostics=[];result=guard.guarded(lambda:verify(home,archive_pin),roots=[home,Path(__file__).resolve().parent],
         foreign_path="/home/runner/work/_temp/hia-runtime-native/unadmitted",diagnostics=diagnostics)
    need(not [r for r in diagnostics if r["phase"]=="reader"],"zero swallowed read denial")
    for name in ("before","after","external_before","external_after"):
        value=result.pop(name)
        with gzip.open(out/(name+".json.gz"),"xb",compresslevel=1) as f:f.write(encoded(value))
    result["elapsed_ns"]=time.monotonic_ns()-start;result["reader_source"]=pin(Path(__file__))
    with (out/"READBACK.json").open("xb") as f:f.write(encoded(result))
    with (out/"DIAGNOSTICS.json").open("xb") as f:f.write(encoded(diagnostics))
    print(json.dumps({"status":result["evidence"]["status"],"guards":len(result["probes"]),
         "original_refusals":14,"complete_admissions":6,"elapsed_ns":result["elapsed_ns"],"native_or_rust_executions":0},sort_keys=True))
if __name__=="__main__":main()
