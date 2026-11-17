#!/usr/bin/env python3
"""Recover the exact self-contained filesystem control inputs from retained copies."""
from __future__ import annotations
import argparse,gzip,hashlib,json,os,stat,time
from pathlib import Path
SOURCE=Path("/home/runner/work/_temp/hia-historical-public58")
CAPTURE=Path("/home/runner/work/_temp/hia-runtime-native")
REPORT={"bytes":94614535,"sha256":"6159169d8c0763d2418c8f625e5cd67099a06179f69927f7a1e62972a1eafa41"}
def need(value,label):
    if not value:raise ValueError(label)
def pin(path):
    info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and path.resolve()==path.absolute(),"ordinary complete input")
    with path.open("rb") as stream:result={"bytes":info.st_size,"sha256":hashlib.file_digest(stream,"sha256").hexdigest()}
    after=path.lstat()
    need((info.st_mode,info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)==
         (after.st_mode,after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),"stable input")
    return result
def read(path):return json.loads(path.read_bytes())
def write(path,value):
    with path.open("xb") as stream:stream.write((json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode())
def relative(name):
    path=Path(name)
    need(type(name)is str and path.as_posix()==name and not path.is_absolute() and ".." not in path.parts,
         "ordinary relative source name")
    return path
def copy_exact(src,dst,expected,mode):
    need(pin(src)==expected,"retained input bytes before copy")
    dst.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with src.open("rb") as incoming,dst.open("xb") as outgoing:
        while block:=incoming.read(1024*1024):outgoing.write(block)
    dst.chmod(mode)
    need(pin(dst)==expected and stat.S_IMODE(dst.stat().st_mode)==mode,"complete physical input copy")
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--readback",type=Path,required=True)
    parser.add_argument("--original-report",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args();start=time.monotonic_ns()
    need(not SOURCE.exists() and not CAPTURE.exists(),"new exact recorded source/capture paths")
    need(not args.output.exists(),"new preparation receipt")
    complete=read(args.readback/"COMPLETE_READBACK.json")
    need(complete["status"]=="COMPLETE_ARCHIVE_BYTES_AND_GIT_SOURCES_PASS"
         and complete["zip"]=={"bytes":60667950,"sha256":"92f1a5e72db1e982b2b237084b4423aaa1204f045e5050960626f54ef5533798"},
         "complete original V10 proof archive admitted")
    old=args.readback/"proof/recovery"
    aggregate=read(old/"reader/READBACK.json")
    need(aggregate["evidence"]["status"]=="COMPLETE_RETAINED_AGGREGATE_READBACK_PASS"
         and aggregate["evidence"]["actual_checks"]==405 and aggregate["evidence"]["recipes"]==81,
         "retain completed full aggregate admission")
    with gzip.open(old/"reader/before.json.gz","rb") as stream:before=json.loads(stream.read())
    with gzip.open(old/"reader/after.json.gz","rb") as stream:after=json.loads(stream.read())
    need(before==after,"complete aggregate input metadata unchanged")
    need(pin(args.original_report)==REPORT,"exact complete failed original report")
    report=read(args.original_report)
    need(report["status"]=="FAIL","preserve original failed result")
    native=report["filesystem_parity_evidence"]
    source_pins=native["source_sha256"]
    output_pins={**native["artifact_sha256"],**report["filesystem_parity_fixture_retirement"]["artifact_sha256"],
                 **report["original_rust_comparisons"]["filesystem_parity"]["artifact_sha256"]}
    need(len(source_pins)==30 and len(output_pins)==901,"complete sealed filesystem subset")
    delta=read(old/"failure-working-copy-delta/DELTA.json")
    need(delta["capture_entries"]==[] and len(delta["retained_source_files"])==2877,
         "retained original source and capture unchanged")
    untouched=old/"skipped/filesystem-controls/moved-two"
    for role,table,prefix in (("source",source_pins,"1:"),("output",output_pins,"0:")):
        folder=untouched/role
        actual={p.relative_to(folder).as_posix() for p in folder.rglob("*") if p.is_file()}
        need(actual==set(table),"complete untouched physical relocation member set")
        for name,digest in table.items():
            expected={"bytes":before[prefix+name]["bytes"],"sha256":digest}
            need(before[prefix+name]["sha256"]==digest and pin(folder/relative(name))==expected,
                 "all untouched relocated inputs match the original sealed full capture")
    SOURCE.mkdir(mode=0o700);CAPTURE.mkdir(mode=0o700)
    source_rows={};output_rows={}
    for key,row in before.items():
        if key.startswith("1:") and stat.S_ISDIR(row["mode"]):
            target=SOURCE/relative(key[2:]);target.mkdir(mode=0o700,parents=True,exist_ok=True)
    for name,expected in delta["retained_source_files"].items():
        original=before["1:"+name]
        need(expected=={field:original[field] for field in ("bytes","sha256")},"entire original materialized source pin")
        copy_exact(old/"failure-working-copy-delta/materialized-source"/relative(name),
                   SOURCE/relative(name),expected,stat.S_IMODE(original["mode"]))
        source_rows[name]={**expected,"mode":stat.S_IMODE(original["mode"])}
    for key,row in sorted(before.items(),reverse=True):
        if key.startswith("1:") and stat.S_ISDIR(row["mode"]):
            (SOURCE/relative(key[2:])).chmod(stat.S_IMODE(row["mode"]))
    for name,digest in output_pins.items():
        row=before["0:"+name];expected={"bytes":row["bytes"],"sha256":digest}
        copy_exact(untouched/"output"/relative(name),CAPTURE/relative(name),expected,stat.S_IMODE(row["mode"]))
        output_rows[name]={**expected,"mode":stat.S_IMODE(row["mode"])}
    copy_exact(args.original_report,CAPTURE/"result.json",REPORT,stat.S_IMODE(before["0:result.json"]["mode"]))
    output_rows["result.json"]={**REPORT,"mode":stat.S_IMODE(before["0:result.json"]["mode"])}
    need({p.relative_to(CAPTURE).as_posix() for p in CAPTURE.rglob("*") if p.is_file()}==set(output_rows),
         "no undeclared subset file")
    value={"schema":"hepta.history.filesystem-control-input-continuation.v1","status":"COMPLETE_SEALED_INPUT_SUBSET_PASS",
           "source":str(SOURCE),"capture":str(CAPTURE),"retained_full_aggregate":pin(old/"reader/READBACK.json"),
           "retained_v10_complete_archive":complete["zip"],"original_report":REPORT,
           "source_files":source_rows,"output_files":output_rows,"sealed_source_subset":source_pins,
           "sealed_artifact_subset":output_pins,"source_pins_rebound":False,
           "original_failure_reclassified_as_pass":False,"native_or_rust_executions":0,
           "subset_only":True,"full_aggregate_reexecuted":False,"elapsed_ns":time.monotonic_ns()-start}
    write(args.output,value)
    print(json.dumps({k:v for k,v in value.items() if k not in ("source_files","output_files","sealed_source_subset","sealed_artifact_subset")},sort_keys=True))
if __name__=="__main__":main()
