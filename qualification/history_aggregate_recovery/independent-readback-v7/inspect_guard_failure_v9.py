#!/usr/bin/env python3
"""Read retained guard-denial evidence after complete archive byte verification."""
from __future__ import annotations
import argparse,hashlib,json,stat,time
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
    need(not (root/"FINAL.json").exists() and not (root/"reader/READBACK.json").exists(),
         "do not relabel the failed guarded aggregate")
    source=root/"recovery-source"
    need(pin(source/"SOURCE_MANIFEST.json")["sha256"]==
         "a8d6dfb580710edf285497f314a24ae5aa34545bbd3961e762903a7128faa639",
         "exact diagnostic-only V9 source closure")
    evidence=read(root/"reader/GUARD_DIAGNOSTICS.json")
    need(evidence["schema"]=="hepta.history.guard-denial-diagnostics.v1"
         and evidence["status"]=="RECORDED" and evidence["completed_guarded_read"] is False
         and evidence["permissions_changed"] is False and evidence["native_or_rust_executions"]==0
         and evidence["guard_source"]==pin(source/"read_only_guard.py"),"exact unchanged-permission diagnostic source")
    events=evidence["events"]
    probes=[row for row in events if row["phase"]=="probes"]
    readers=[row for row in events if row["phase"]=="reader"]
    need(len(probes)==evidence["probe_denials"]==12
         and len(readers)==evidence["reader_denials"]>0
         and len(events)==len(probes)+len(readers),"full actual denial domain")
    for row in events:
        need(row["frames"] and type(row["kind"])is str
             and all(type(frame["file"])is str and type(frame["function"])is str
                 and type(frame["line"])is int and frame["line"]>0 for frame in row["frames"]),
             "complete metadata-only denial stack")
    error=(root/"logs/reader.stderr").read_bytes()
    need(error.endswith(b"ValueError: reader attempted a forbidden operation\n"),
         "preserve the actual final guard refusal")
    need((root/"logs/reader.stdout").read_bytes()==b"","no aggregate pass output")
    delta=read(root/"failure-working-copy-delta/DELTA.json")
    need(delta["schema"]=="hepta.history.failed-working-copy-delta.v1" and delta["status"]=="RETAINED"
         and delta["capture_entries"]==[] and delta["original_archive_modified"] is False
         and delta["original_failure_reclassified_as_pass"] is False
         and delta["native_or_rust_executions"]==0,"all original capture bytes and modes preserved")
    need(len(delta["retained_source_files"])==2877,"entire original materialized source retained")
    for name,expected in delta["retained_source_files"].items():
        need(pin(root/"failure-working-copy-delta/materialized-source"/name)==expected,
             "complete materialized source bytes")
    code=read(root/"reader/STATIC_CODE_ADMISSION.json")
    reconstruction=read(root/"reader/SOURCE_RECONSTRUCTION.json")
    schema=read(root/"reader/RETAINED_SCHEMA_WRITES.json")
    mechanical=read(root/"reader/MECHANICAL_READS.json")
    need(code["execution_attempts"]==[] and code["new_executable_mappings"]==0
         and code["native_or_rust_executions"]==0
         and mechanical["violations"]==[] and mechanical["native_or_rust_executions"]==0,
         "no semantic execution or undeclared mechanical operation")
    result={"schema":"hepta.history.guard-failure-full-readback.v1",
            "status":"COMPLETE_FAILED_GUARD_DIAGNOSTICS_READBACK_PASS",
            "recovery_status":"FAILURE","original_failure_reclassified_as_pass":False,
            "archive":complete,"retained_materialized_sources":len(delta["retained_source_files"]),
            "capture_delta":[],"static_admissions":len(code["admissions"]),
            "source_reconstructions":len(reconstruction["records"]),"retained_schema_pairs":len(schema["records"]),
            "stderr":pin(root/"logs/reader.stderr"),"full_stderr":error.decode("utf-8"),
            "diagnostics":evidence,"diagnostics_pin":pin(root/"reader/GUARD_DIAGNOSTICS.json"),
            "native_or_rust_executions":0,"reader_source":pin(Path(__file__)),
            "elapsed_ns":time.monotonic_ns()-started}
    with args.output.open("xb") as stream:
        stream.write((json.dumps(result,sort_keys=True,indent=2,allow_nan=False)+"\n").encode())
    print(json.dumps({key:value for key,value in result.items() if key!="archive"},sort_keys=True))
if __name__=="__main__":
    main()
