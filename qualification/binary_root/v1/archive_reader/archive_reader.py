#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independent full uploaded ZIP/TAR read and guarded actual typed comparison."""
from pathlib import Path,PurePosixPath
import argparse
import encodings.cp437
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import tarfile
import zipfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("binary_qualified_recover",ROOT/"qualified/scripts/recover.py")
recover=importlib.util.module_from_spec(spec);spec.loader.exec_module(recover)
require=recover.require
decode=recover.decode
encoded=recover.encode
pin=recover.pin
identity_file=recover.identity
def identity(expected=None):
    raw=(ROOT/"SOURCE_MANIFEST.json").read_bytes();value=decode(raw);rows=value["files"]
    require(expected is None or recover.sha(raw)==expected,"independent reader source binding changed")
    actual={p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*") if p.is_file()}
    require(actual=={r["path"] for r in rows}|{"SOURCE_MANIFEST.json"} and len(rows)==len(actual)-1,
        "independent reader source set changed")
    for row in rows:
        path=ROOT/row["path"];body=path.read_bytes()
        require(path.resolve()==path.absolute() and not (path.stat().st_mode&0o111)
            and recover.rawpin(body)=={k:row[k] for k in ("bytes","sha256")}
            and hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest()==row["git_blob"],
            "independent reader complete source bytes differ")
    return recover.sha(raw)
def restore(work,binding):
    archive=work/"download/complete.zip"
    require(pin(archive)=={k:binding["artifact"][k] for k in ("bytes","sha256")},"complete uploaded ZIP changed")
    out=work/"restored-archive";out.mkdir();zipped=out/"zip";zipped.mkdir()
    zip_rows={}
    with zipfile.ZipFile(archive) as stream:
        for member in stream.infolist():
            recover.safe(member.filename)
            require(not member.is_dir() and member.filename not in zip_rows,"duplicate/non-ordinary ZIP member")
            mode=member.external_attr>>16
            require(mode==0 or stat.S_ISREG(mode) or stat.S_IFMT(mode)==0,"ZIP member is not an ordinary file")
            target=zipped/member.filename;target.parent.mkdir(parents=True,exist_ok=True)
            digest=hashlib.sha256();size=0
            with stream.open(member) as source,target.open("xb") as dest:
                while part:=source.read(1<<20):
                    dest.write(part);digest.update(part);size+=len(part)
            require(size==member.file_size,"short uploaded ZIP member")
            zip_rows[member.filename]=dict(bytes=size,sha256=digest.hexdigest())
    tar=zipped/"evidence.tar.gz"
    require(pin(tar)=={k:binding["tar"][k] for k in ("bytes","sha256")},"uploaded complete TAR changed")
    objects=out/"objects";objects.mkdir();manifest=None;seen={}
    with tarfile.open(tar,"r|gz") as stream:
        while member:=stream.next():
            require(member.isfile() and member.name not in seen and member.size>=0,"duplicate/non-ordinary TAR member")
            if member.name=="artifact-manifest.json":
                raw=stream.extractfile(member).read();require(len(raw)==member.size,"short full TAR index")
                manifest=decode(raw);seen[member.name]=dict(**recover.rawpin(raw),mode=member.mode)
            else:
                require(re.fullmatch(r"objects/[0-9a-f]{64}-[0-7]{3}",member.name),"invalid complete object name")
                target=objects/member.name.split("/",1)[1];digest=hashlib.sha256();size=0
                with stream.extractfile(member) as source,target.open("xb") as dest:
                    while part:=source.read(1<<20):
                        dest.write(part);digest.update(part);size+=len(part)
                require(size==member.size,"short complete TAR object")
                target.chmod(member.mode);seen[member.name]=dict(bytes=size,sha256=digest.hexdigest(),mode=member.mode)
                require(identity_file(target)==seen[member.name],"restored physical object bytes differ")
            stream.members.clear()
    require(manifest and manifest["schema"]=="hepta.runtime.binary-root-pure-recovery.complete-archive.v1"
        and manifest["gate_status"]=="PASS" and manifest["git_head"]==binding["qualified_recovery_commit"],
        "uploaded successful recovery identity differs")
    files=manifest["files"];dirs=manifest["directories"];objects_expected={}
    for logical,value in files.items():
        recover.safe(logical,{"source","run"});name=value["object"]
        require(name=="objects/"+value["sha256"]+"-"+format(value["mode"],"03o"),"logical object identity changed")
        item={k:value[k] for k in ("bytes","sha256","mode")}
        require(seen[name]==item,"logical bytes or mode differ")
        if name in objects_expected:require(objects_expected[name]==item,"shared logical object differs")
        objects_expected[name]=item
    require(set(seen)==set(objects_expected)|{"artifact-manifest.json"} and len(files)==binding["tar"]["logical_files"]
        and len(dirs)==binding["tar"]["directories"]
        and sum(v["bytes"] for v in files.values())==binding["tar"]["logical_bytes"]
        and len(objects_expected)==binding["tar"]["unique_objects"]
        and sum(v["bytes"] for v in objects_expected.values())==binding["tar"]["unique_bytes"],
        "complete uploaded archive file/byte/object domain differs")
    root=out/"restored";root.mkdir()
    for logical,mode in sorted(dirs.items(),key=lambda p:(len(PurePosixPath(p[0]).parts),p[0])):
        recover.safe(logical,{"source","run"});target=root/logical;target.mkdir();target.chmod(mode)
    for logical,value in sorted(files.items()):
        target=root/logical;require(target.parent.is_dir() and not target.exists(),"invalid logical file parent")
        os.link(out/value["object"],target)
    actual={p.relative_to(root).as_posix():identity_file(p) for p in root.rglob("*") if p.is_file()}
    actual_dirs={p.relative_to(root).as_posix():stat.S_IMODE(p.stat().st_mode) for p in root.rglob("*") if p.is_dir()}
    require(actual=={p:{k:v[k] for k in ("bytes","sha256","mode")} for p,v in files.items()} and actual_dirs==dirs,
        "complete restored file/directory bytes/modes/set differ")
    local={p.relative_to(ROOT/"qualified").as_posix():p.read_bytes() for p in (ROOT/"qualified").rglob("*") if p.is_file()}
    saved={p.relative_to(root/"source").as_posix():p.read_bytes() for p in (root/"source").rglob("*") if p.is_file()}
    require(saved==local and files["source/SOURCE_MANIFEST.json"]["sha256"]==binding["qualified_recovery_source_manifest_sha256"],
        "archive pure reader source differs from the exact trusted Git source")
    require(recover.frozen(binding["qualified_recovery_source_manifest_sha256"])[0]==binding["qualified_recovery_source_manifest_sha256"],
        "trusted qualified reader source changed")
    return root,manifest,zip_rows
def inspect(work,binding):
    archive=work/"download/complete.zip";before=identity_file(archive)
    root,manifest,zip_rows=restore(work,binding);run=root/"run"
    source,capture,run_ci,readonly,controls,old,qualified=recover.context(run)
    spec=importlib.util.spec_from_file_location("root_archive_proof_check",ROOT/"qualified/scripts/proof_check.py")
    checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
    gate=decode((run/"GATE.json").read_bytes())
    require(gate["status"]=="PASS"and gate["stage"]=="complete"and gate["original_run_status"]=="FAIL"
        and gate["original_failed_stage"]=="read"and gate["native_or_rust_executions"]==0
        and gate["source_manifest_sha256"]==binding["qualified_recovery_source_manifest_sha256"],
        "pure recovery gate status or original failure changed")
    names=["fetch","unpack","read","controls","verify"]
    require([row["stage"]for row in gate["stages"]]==names,"pure recovery stage order changed")
    old_source=Path(gate["stages"][0]["process"]["cwd"])
    argv=gate["stages"][0]["process"]["argv"];old_work=Path(argv[argv.index("--work")+1]);old_py=argv[0]
    for stage in gate["stages"]:
        name=stage["stage"];row=stage["process"]
        require(stage==decode((run/(name.upper()+".json")).read_bytes())and stage["status"]=="PASS"
            and stage["native_or_rust_executions"]==0,"pure recovery process state changed")
        checker.process(row,run/"steps"/name,60 if name=="fetch"else 180)
        require(row["argv"]==[old_py,"-I","-S","-B",str(old_source/"scripts/recover.py"),name,
            "--work",str(old_work),"--source-manifest-sha256",binding["qualified_recovery_source_manifest_sha256"]]
            and row["cwd"]==str(old_source),"actual pure reader command changed")
    roots={str(old_source):"source",str(old_work/"original"):"run/original",
        str(old_work/"download"):"run/download",str(old_work/"qualified"):"run/qualified"}
    for name in("read","verify"):
        saved=decode((run/"steps"/name/(name+".stdout")).read_bytes())
        files=manifest["files"];directories=manifest["directories"]
        if name=="read":
            # The first admission predates the declared physical-control setup.
            # Its complete roots exclude only that subsequently created subtree.
            prefix="run/qualified/continued/physical-controls"
            files={p:v for p,v in files.items()if not p.startswith(prefix+"/")}
            directories={p:v for p,v in directories.items()if p!=prefix and not p.startswith(prefix+"/")}
        checker.proof(saved,files,directories,roots)
        require(saved["evidence"]==decode((run/(name.upper()+".json")).read_bytes())["evidence"],
            "retained complete pure admission differs")
    home=run/"qualified/continued/physical-controls"
    reports=decode((home/"RESULT.json").read_bytes())
    require(reports==decode((run/"CONTROLS.json").read_bytes())["evidence"]
        and [r["name"]for r in reports["records"]]==list(controls.NAMES)+["relocated-one","nested-relocated-two"],
        "physical reader domain omitted")
    for row in reports["records"]:
        saved=decode((home/row["proof"]).read_bytes())
        checker.proof(saved,manifest["files"],manifest["directories"],{
            str(old_work/"qualified/original/restored/source"):"run/qualified/original/restored/source",
            str(old_work/"qualified/continued/physical-controls"/row["path"]):
                "run/qualified/continued/physical-controls/"+row["path"]})
        require(saved["evidence"]["status"]==row["status"]and pin(home/row["proof"])==row["proof_pin"],
            "complete physical variant proof changed")
    actual=recover.verify(run)
    require(actual["before"]==actual["after"]and len(actual["probes"])==11
        and actual["native_executed"]is False and actual["rust_executed"]is False,"independent pure reader custody failed")
    require(actual["evidence"]==decode((run/"VERIFY.json").read_bytes())["evidence"],
        "independent complete original/native and physical-control comparison differs")
    proof=work/"proof";proof.mkdir(exist_ok=True)
    (proof/"READONLY.json").write_bytes(encoded(actual))
    require(identity_file(archive)==before,"uploaded complete ZIP changed during read")
    native=actual["evidence"]["native"]
    require(native["original_cases"]==135 and native["wire_controls"]==12 and native["capacity_controls"]==14,
        "actual retained binary root domain changed")
    result=dict(schema="hepta.runtime.binary-root.independent-uploaded-archive.v1",status="PASS",
        zip=pin(archive),zip_members=zip_rows,tar=binding["tar"],source_manifest_sha256=binding["qualified_recovery_source_manifest_sha256"],
        original_run_status="FAIL",continuation_run_status="FAIL",recovery_run_status="PASS",
        retained_guard_proofs=10,retained_guard_probes=110,independent_guard_probes=11,
        first_admission_precedes_declared_physical_control_setup=True,
        independent_unchanged_entries=actual["entries"],complete_object_bytes_and_modes_read=True,
        complete_logical_files_and_directories_restored=True,
        full_native_buffer_record_bytes=native["complete_buffer_bytes"],original_cases=135,
        native_calls=native["native_calls"],boundary_controls=26,wire_controls=12,capacity_controls=14,
        physical_reader_refusals=6,complete_relocations=2,independent_complete_comparison=actual["evidence"],
        native_or_rust_executions=0,whole_runtime_replaced=False)
    (proof/"READ.json").write_bytes(encoded(result))
    return result
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["fetch","read"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args();identity_before=identity(a.source_manifest_sha256);binding=decode((ROOT/"BINDING.json").read_bytes())
    work=a.work.absolute()
    result=recover.fetch(work,binding) if a.stage=="fetch" else inspect(work,binding)
    require(identity()==identity_before,"independent source changed during full read")
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
