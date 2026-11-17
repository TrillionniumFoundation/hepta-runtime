#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Restore every retained byte, then independently run only the pure evidence reader."""
from pathlib import Path,PurePosixPath
import argparse
import hashlib
import os
import re
import stat
import sys
import tarfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,owned,pin,require,source_evidence
from process import Recorder
from reader_controls import NAMES
PROBES=["write","os-open-write","mkdir","rename","unlink","chmod","utime","subprocess","ctypes","mmap","foreign-read"]
def identity(path):
    require(path.resolve()==path.absolute() and stat.S_ISREG(path.lstat().st_mode),"ordinary archive object required")
    return dict(**pin(path),mode=stat.S_IMODE(path.stat().st_mode))
def safe(name):
    p=PurePosixPath(name)
    require(type(name) is str and p.as_posix()==name and not p.is_absolute() and ".." not in p.parts and p.parts[0] in ("source","run"),
        "invalid logical archive path")
    return p
def process(row,folder,budget):
    require(row["completed"] is True and row["exit_code"]==0 and row["timed_out"] is False
        and row["timeout_seconds"]==budget and 0<=row["elapsed_seconds"]<budget+1
        and row["pid"]==row["pgid"] and row["pid"]>0,"retained process did not pass its original budget")
    for suffix in ("stdout","stderr"):
        value=row[suffix]
        require(pin(owned(folder,value["file"]))=={k:value[k] for k in ("bytes","sha256")},"retained full process stream changed")
def proof(value,files,directories,roots):
    require(value["status"]=="READONLY_PASS" and value["before"]==value["after"],"readonly proof lost exact before/after custody")
    require([p["name"] for p in value["probes"]]==PROBES and all(p["rejected"] is True for p in value["probes"]),
        "readonly capability probes changed")
    require(value["native_executed"] is False and value["rust_executed"] is False and value["evidence_written"] is False,
        "readonly proof executed or wrote evidence")
    require(len(set(value["roots"]))==len(value["roots"]) and set(value["roots"])<=set(roots),"readonly root binding missing")
    actual_files=set();actual_dirs=set()
    for row in value["before"]:
        require(type(row["root"]) is int and 0<=row["root"]<len(value["roots"]),"readonly root index invalid")
        prefix=roots[value["roots"][row["root"]]]
        logical=prefix if row["path"]=="." else prefix+"/"+row["path"]
        safe(logical)
        if stat.S_ISREG(row["mode"]):
            require(logical not in actual_files and logical in files,"readonly ordinary file duplicated or missing")
            actual_files.add(logical);expected=files[logical]
            require(row["sha256"]==expected["sha256"] and row["bytes"]==expected["bytes"] and
                stat.S_IMODE(row["mode"])==expected["mode"],"readonly proof file differs from archived complete bytes")
        else:
            require(stat.S_ISDIR(row["mode"]) and logical not in actual_dirs and logical in directories,"readonly directory changed")
            actual_dirs.add(logical)
            require(stat.S_IMODE(row["mode"])==directories[logical],"readonly directory mode changed")
    prefixes=[roots[name] for name in value["roots"]]
    require(actual_files=={name for name in files if any(name.startswith(p+"/") for p in prefixes)},"readonly complete file set changed")
    require(actual_dirs=={name for name in directories if any(name==p or name.startswith(p+"/") for p in prefixes)},
        "readonly complete directory set changed")
def main():
    p=argparse.ArgumentParser();p.add_argument("--archive",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--proof-output",type=Path,required=True)
    p.add_argument("--source-manifest-sha256",required=True);a=p.parse_args()
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.source_manifest_sha256,"archive reader source manifest changed")
    current=source_evidence(ROOT)
    archive=a.archive.resolve(strict=True);before=identity(archive)
    require(not a.output.exists() and not a.proof_output.exists(),"independent archive output must be fresh")
    a.output.mkdir(parents=True);out=a.output.resolve()
    a.proof_output.mkdir(parents=True);proofroot=a.proof_output.resolve()
    objects=out/"objects";objects.mkdir()
    observed={};manifest=None
    with tarfile.open(archive,"r|gz") as stream:
        while member:=stream.next():
            require(member.isfile() and member.name not in observed and member.size>=0,"invalid complete archive member")
            if member.name=="artifact-manifest.json":
                raw=stream.extractfile(member).read();require(len(raw)==member.size,"short archive index")
                observed[member.name]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),mode=member.mode)
                manifest=decode(raw)
            else:
                require(re.fullmatch(r"objects/[0-9a-f]{64}-[0-7]{3}",member.name),"invalid object name")
                target=objects/member.name.split("/",1)[1];digest=hashlib.sha256();size=0
                with stream.extractfile(member) as origin,target.open("xb") as handle:
                    while part:=origin.read(1<<20):
                        handle.write(part);digest.update(part);size+=len(part)
                target.chmod(member.mode)
                require(size==member.size,"short complete object bytes")
                observed[member.name]=dict(bytes=size,sha256=digest.hexdigest(),mode=member.mode)
                require(identity(target)==observed[member.name],"restored object bytes differ")
            stream.members.clear()
    require(manifest and manifest["schema"]=="hepta.runtime.binary-call-plan.complete-archive.v1","wrong complete archive schema")
    require(manifest["gate_status"]=="PASS" and manifest["native_or_rust_executions"]==0,"archive does not contain a passing gate")
    files=manifest["files"];directories=manifest["directories"];expected={}
    for logical,value in files.items():
        safe(logical)
        require(value["object"]=="objects/"+value["sha256"]+"-"+format(value["mode"],"03o"),"object naming changed")
        declared={k:value[k] for k in ("bytes","sha256","mode")}
        require(observed[value["object"]]==declared,"logical file differs from complete object bytes")
        if value["object"] in expected:require(expected[value["object"]]==declared,"object alias identity differs")
        expected[value["object"]]=declared
    require(set(observed)==set(expected)|{"artifact-manifest.json"},"unbound or missing archive objects")
    require(files["source/SOURCE_MANIFEST.json"]["sha256"]==a.source_manifest_sha256,"archive source identity differs")
    restored=out/"restored";restored.mkdir()
    for logical,mode in sorted(directories.items(),key=lambda pair:(len(PurePosixPath(pair[0]).parts),pair[0])):
        safe(logical);require(type(mode) is int and 0<=mode<=0o777,"invalid directory mode")
        target=restored/logical;target.mkdir();target.chmod(mode)
    for logical,value in sorted(files.items()):
        target=restored/logical
        require(target.parent.is_dir() and not target.exists(),"logical file parent missing or file duplicated")
        os.link(out/value["object"],target)
    actual_files={p.relative_to(restored).as_posix():identity(p) for p in restored.rglob("*") if p.is_file()}
    actual_dirs={p.relative_to(restored).as_posix():stat.S_IMODE(p.stat().st_mode) for p in restored.rglob("*") if p.is_dir()}
    require(actual_files=={p:{k:v[k] for k in ("bytes","sha256","mode")} for p,v in files.items()} and
        actual_dirs==directories,"complete restored file/directory bytes, modes or set changed")
    require(source_evidence(restored/"source")==current,"restored archive reader/source differs from frozen source")
    gate=decode(owned(restored,"run/GATE.json").read_bytes())
    require(gate["status"]=="PASS" and gate["stage"]=="complete" and gate["failure"] is None and
        gate["source_manifest_sha256"]==a.source_manifest_sha256,"retained gate closure changed")
    budgets={"source-check":60,"producers":900,"read-only-admission":180,"physical-controls":180,"read-only-controls":180}
    require([r["name"] for r in gate["processes"]]==list(budgets) and gate["processes"]==
        decode(owned(restored,"run/processes/processes.json").read_bytes()),"gate process set differs")
    origin=decode(owned(restored,"run/capture/ORIGIN.json").read_bytes())
    oldsource=Path(origin["source"]);oldcapture=Path(origin["output"])
    base=[origin["python"],"-I","-S","-B",str(oldsource/"scripts/run_ci.py")]
    expected_argv={
        "source-check":base+["check","--source",str(oldsource)],
        "producers":base+["run","--source",str(oldsource),"--hepta",origin["hepta"],"--rust-bin",origin["rust_bin"],"--output",str(oldcapture)],
        "read-only-admission":base+["verify","--source",str(oldsource),"--output",str(oldcapture)],
        "physical-controls":base+["controls","--source",str(oldsource),"--output",str(oldcapture)],
        "read-only-controls":base+["verify-controls","--source",str(oldsource),"--output",str(oldcapture)],
    }
    for row in gate["processes"]:
        process(row,restored/"run/processes",budgets[row["name"]])
        require(row["argv"]==expected_argv[row["name"]] and row["cwd"]==str(oldsource),"retained gate command changed")
    roots={str(oldsource):"source",str(oldcapture):"run/capture",
        str(oldcapture)+"-reader-controls":"run/capture-reader-controls"}
    first=decode(owned(restored,"run/processes/read-only-admission.stdout").read_bytes())
    final=decode(owned(restored,"run/processes/read-only-controls.stdout").read_bytes())
    proof(first,files,directories,roots);proof(final,files,directories,roots)
    require(first["evidence"]["status"]==final["evidence"]["status"]=="COMPLETE_CALL_PLAN_COMPARISON_PASS","typed comparison did not pass")
    controls=decode(owned(restored,"run/capture-reader-controls/controls.json").read_bytes())
    require(controls["status"]=="PHYSICAL_READER_CONTROLS_PASS" and
        [row["name"] for row in controls["controls"]]==list(NAMES),"physical controls domain changed")
    for row in controls["controls"]:
        prefix="run/capture-reader-controls/"+row["name"]
        saved=decode(owned(restored,"run/capture-reader-controls/"+row["name"]+"-readonly.json").read_bytes())
        proof(saved,files,directories,{str(oldsource):"source",str(oldcapture)+"-reader-controls/"+row["name"]:prefix})
        require(saved["evidence"]==row and row["rejected"]==(not row["name"].startswith("relocated")),
            "physical control outcome changed")
    rec=Recorder(restored/"source",proofroot/"processes")
    raw,row=rec.run("independent-pure-admission",[sys.executable,"-I","-S","-B",
        restored/"source/scripts/run_ci.py","verify-controls","--source",restored/"source",
        "--output",restored/"run/capture"],timeout=180)
    independent=decode(raw)
    proof(independent,files,directories,{
        str(restored/"source"):"source",str(restored/"run/capture"):"run/capture",
        str(restored/"run/capture-reader-controls"):"run/capture-reader-controls"})
    require(independent["evidence"]==final["evidence"],"independent full comparison differs from captured comparison")
    require(identity(archive)==before and source_evidence(ROOT)==current,"archive/reader source changed during complete read")
    result=dict(schema="hepta.runtime.binary-call-plan.independent-archive.v1",status="PASS",
        archive=before,source_manifest_sha256=a.source_manifest_sha256,logical_files=len(files),
        directories=len(directories),logical_bytes=sum(v["bytes"] for v in files.values()),
        unique_objects=len(expected),unique_bytes=sum(v["bytes"] for v in expected.values()),
        all_object_bytes_read=True,all_logical_files_and_directories_restored=True,
        restored_regular_files_share_immutable_objects=True,physical_reader_refusals=6,complete_relocations=2,
        retained_guard_proofs=10,retained_guard_probes=110,independent_guard_probes=11,
        independent_comparison=independent["evidence"],native_or_rust_executions=0,whole_runtime_replaced=False)
    (proofroot/"ARCHIVE_READ.json").write_bytes(canonical(result))
    print(canonical(result).decode(),end="")
if __name__=="__main__":main()
