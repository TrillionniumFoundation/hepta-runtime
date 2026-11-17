#!/usr/bin/env python3
"""Independently inspect retained skipped-control failure after whole archive read."""
from __future__ import annotations
import argparse,gzip,hashlib,json,stat,time
from pathlib import Path

def need(value,message):
    if not value:
        raise ValueError(message)
def pin(path):
    info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and path.resolve()==path.absolute(),"ordinary retained file")
    with path.open("rb") as stream:
        digest=hashlib.file_digest(stream,"sha256").hexdigest()
    after=path.lstat()
    fields=("st_mode","st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns")
    need(all(getattr(info,key)==getattr(after,key) for key in fields),"retained file changed during full read")
    return {"bytes":info.st_size,"sha256":digest}
def read(path):
    return json.loads(path.read_bytes())
def gzread(path):
    with gzip.open(path,"rb") as stream:
        return json.loads(stream.read())
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--readback",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args();started=time.monotonic_ns()
    complete=read(args.readback/"COMPLETE_READBACK.json")
    members=read(args.readback/"COMPLETE_MEMBER_PINS.json")
    need(complete["status"]=="COMPLETE_ARCHIVE_BYTES_AND_GIT_SOURCES_PASS"
         and complete["aggregate_recovery_pass"] is False
         and complete["native_or_rust_executions"]==0,"complete failed proof archive first")
    root=args.readback/"proof/recovery"
    for row in members:
        path=args.readback/"proof"/row["path"]
        need(stat.S_IMODE(path.lstat().st_mode)==row["mode"],"complete retained proof mode")
        if row["type"]=="file":
            need(pin(path)=={key:row[key] for key in ("bytes","sha256")},"all proof file bytes reopened")
        else:
            need(row["type"]=="directory" and stat.S_ISDIR(path.lstat().st_mode),"ordinary proof directory")
    need(not (root/"FINAL.json").exists(),"overall failed recovery is not a complete pass")
    source=root/"recovery-source"
    need(pin(source/"SOURCE_MANIFEST.json")["sha256"]==
         "ef304f1000a49279bf1f51c8088ee27220e145c6564c020a2abd3116e7ea3b32",
         "exact V10 source closure")
    aggregate=read(root/"reader/READBACK.json")
    evidence=aggregate["evidence"]
    need(evidence["status"]=="COMPLETE_RETAINED_AGGREGATE_READBACK_PASS"
         and evidence["actual_checks"]==405 and evidence["recipes"]==81
         and evidence["original_status"]=="FAIL" and evidence["source_pins_rebound"] is False
         and evidence["original_failure_reclassified_as_pass"] is False
         and aggregate["reader_writes"]==aggregate["native_or_rust_executions"]==0,
         "completed aggregate read remains distinct from the failed skipped control")
    diagnostic=read(root/"reader/GUARD_DIAGNOSTICS.json")
    need(diagnostic["completed_guarded_read"] is True
         and diagnostic["reader_denials"]==0 and diagnostic["probe_denials"]==12
         and diagnostic["guard_source"]==pin(source/"read_only_guard.py")
         and diagnostic["native_or_rust_executions"]==0,"complete actual aggregate guard")
    before=gzread(root/"reader/before.json.gz")
    after=gzread(root/"reader/after.json.gz")
    external_before=gzread(root/"reader/external_before.json.gz")
    external_after=gzread(root/"reader/external_after.json.gz")
    need(before==after and external_before==external_after,"complete aggregate before/after entries unchanged")
    need(len(before)==aggregate["full_snapshot_entries"]
         and len(external_before)==aggregate["external_snapshot_entries"],"complete aggregate snapshot counts")
    delta=read(root/"failure-working-copy-delta/DELTA.json")
    need(delta["schema"]=="hepta.history.failed-working-copy-delta.v1"
         and delta["status"]=="RETAINED" and delta["original_archive_modified"] is False
         and delta["original_failure_reclassified_as_pass"] is False
         and delta["native_or_rust_executions"]==0,"preserved original failure and complete working-copy delta")
    need(len(delta["retained_source_files"])==2877,"entire materialized historical source retained")
    for name,expected in delta["retained_source_files"].items():
        need(pin(root/"failure-working-copy-delta/materialized-source"/name)==expected,
             "complete materialized source bytes")
    controls=[]
    for kind in ("filesystem","regex"):
        path=root/"skipped"/(kind+".process.json")
        if not path.exists():
            controls.append({"kind":kind,"process_present":False})
            continue
        process=read(path)
        streams={}
        for stream in ("stdout","stderr"):
            actual=root/"skipped"/(kind+"."+stream)
            streams[stream]=pin(actual)
            need(streams[stream]==process[stream],"complete control process stream identity")
        audit_path=root/"skipped"/(kind+".audit.json")
        audit=read(audit_path) if audit_path.exists() else None
        if audit is not None:
            need(audit["pid"]==process["pid"] and audit["parent_pid"]==process["parent_pid"]
                 and audit["pgid"]==process["pgid"],"control audit PID/parent/group custody")
        controls.append({"kind":kind,"process_present":True,"process":process,"audit":audit,
                         "streams":streams,"full_stderr":(root/"skipped"/(kind+".stderr")).read_bytes().decode("utf-8")})
    actual=[row for row in controls if row["process_present"]]
    need(actual and any(row["process"]["exit_code"]!=0 or row["process"]["timed_out"] is True
                       for row in actual),"retained actual skipped-control failure")
    orchestration_error=(root/"logs/skipped.stderr").read_bytes()
    need(orchestration_error and not (root/"skipped/SKIPPED_CONTROLS.json").exists(),
         "incomplete skipped control summary remains absent")
    result={"schema":"hepta.history.skipped-control-failure-full-readback.v1",
            "status":"COMPLETE_SKIPPED_CONTROL_FAILURE_READBACK_PASS",
            "recovery_status":"FAILURE","aggregate_readback_status":"SUCCESS",
            "original_failure_reclassified_as_pass":False,"archive":complete,
            "aggregate_readback":pin(root/"reader/READBACK.json"),
            "aggregate_evidence":evidence,"full_snapshot_entries":len(before),
            "external_snapshot_entries":len(external_before),
            "retained_materialized_sources":len(delta["retained_source_files"]),
            "working_copy_delta":pin(root/"failure-working-copy-delta/DELTA.json"),
            "working_copy_delta_entries":len(delta["capture_entries"]),
            "controls":controls,"orchestration_stderr":pin(root/"logs/skipped.stderr"),
            "full_orchestration_stderr":orchestration_error.decode("utf-8"),
            "native_or_rust_executions":0,"reader_source":pin(Path(__file__)),
            "elapsed_ns":time.monotonic_ns()-started}
    with args.output.open("xb") as stream:
        stream.write((json.dumps(result,sort_keys=True,indent=2,allow_nan=False)+"\n").encode())
    print(json.dumps({key:value for key,value in result.items() if key!="archive"},sort_keys=True))
if __name__=="__main__":
    main()
