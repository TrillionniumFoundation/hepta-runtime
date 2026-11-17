#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bounded recovery of complete original typed evidence; no semantic execution."""
from pathlib import Path,PurePosixPath
import argparse
import encodings.cp437
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import urllib.parse
import urllib.request
import zipfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
def encode(value):
    return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,allow_nan=False)+"\n").encode()
def require(value,message):
    if not value:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def decode(raw):
    def unique(rows):
        out={}
        for k,v in rows:
            require(k not in out,"duplicate evidence key");out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError("nonfinite evidence")))
def rawpin(raw):return dict(bytes=len(raw),sha256=sha(raw))
_CACHE={}
def pin(path):
    before=path.stat();key=(before.st_dev,before.st_ino,before.st_mode,before.st_uid,before.st_gid,
        before.st_nlink,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
    require(stat.S_ISREG(before.st_mode) and path.resolve()==path.absolute(),"ordinary owned file required")
    if key not in _CACHE:
        with path.open("rb") as stream:digest=hashlib.file_digest(stream,"sha256").hexdigest()
        after=path.stat()
        require(key==(after.st_dev,after.st_ino,after.st_mode,after.st_uid,after.st_gid,
            after.st_nlink,after.st_size,after.st_mtime_ns,after.st_ctime_ns),"file changed during full read")
        _CACHE[key]=digest
    return dict(bytes=before.st_size,sha256=_CACHE[key])
def identity(path):return dict(**pin(path),mode=stat.S_IMODE(path.stat().st_mode))
class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        new=super().redirect_request(req,fp,code,msg,headers,newurl)
        if new is not None and urllib.parse.urlparse(newurl).hostname!="api.github.com":
            new.remove_header("Authorization")
        return new
def fetch(work,binding):
    folder=work/"download";folder.mkdir(parents=True,exist_ok=False)
    target=folder/"complete.zip"
    request=urllib.request.Request(
        "https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/"+str(binding["artifact"]["id"])+"/zip",
        headers={"Accept":"application/vnd.github+json","Authorization":"Bearer "+os.environ["GH_TOKEN"],
            "X-GitHub-Api-Version":"2022-11-28"})
    count=0;digest=hashlib.sha256()
    with urllib.request.build_opener(Redirect()).open(request,timeout=60) as source,target.open("xb") as out:
        while part:=source.read(1<<20):
            count+=len(part);require(count<=binding["artifact"]["bytes"],"artifact exceeds frozen extent")
            digest.update(part);out.write(part)
    result=dict(bytes=count,sha256=digest.hexdigest())
    require(result=={k:binding["artifact"][k] for k in result},"complete original ZIP differs")
    return dict(status="PASS",zip=result,native_or_rust_executions=0)
def safe(name,roots=None):
    p=PurePosixPath(name)
    require(type(name) is str and p.as_posix()==name and not p.is_absolute() and ".." not in p.parts and p.parts,
        "archive path is not an owned relative path")
    require(roots is None or p.parts[0] in roots,"archive root differs")
    return p
def unpack(work,binding):
    original=work/"original";original.mkdir()
    archive=work/"download/complete.zip"
    require(pin(archive)=={k:binding["artifact"][k] for k in ("bytes","sha256")},"original ZIP changed")
    zipped=original/"zip";zipped.mkdir();zip_rows={}
    with zipfile.ZipFile(archive) as stream:
        for member in stream.infolist():
            safe(member.filename)
            require(not member.is_dir() and member.filename not in zip_rows,"ZIP member duplicate/kind changed")
            mode=member.external_attr>>16
            require(mode==0 or stat.S_ISREG(mode) or stat.S_IFMT(mode)==0,"ZIP contains a non-ordinary entry")
            target=zipped/member.filename;target.parent.mkdir(parents=True,exist_ok=True)
            digest=hashlib.sha256();count=0
            with stream.open(member) as source,target.open("xb") as out:
                while part:=source.read(1<<20):
                    out.write(part);count+=len(part);digest.update(part)
            require(count==member.file_size,"incomplete ZIP member")
            zip_rows[member.filename]=dict(bytes=count,sha256=digest.hexdigest())
    tar=zipped/"evidence.tar.gz"
    require(pin(tar)=={k:binding["tar"][k] for k in ("bytes","sha256")},"complete original TAR differs")
    objects=original/"objects";objects.mkdir();observed={};manifest=None
    with tarfile.open(tar,"r|gz") as stream:
        while member:=stream.next():
            require(member.isfile() and member.name not in observed and member.size>=0,"TAR member duplicate/kind changed")
            if member.name=="artifact-manifest.json":
                raw=stream.extractfile(member).read();require(len(raw)==member.size,"short TAR index")
                observed[member.name]=dict(**rawpin(raw),mode=member.mode);manifest=decode(raw)
                (original/"ARTIFACT_MANIFEST.json").write_bytes(raw)
            else:
                require(re.fullmatch(r"objects/[0-9a-f]{64}-[0-7]{3}",member.name),"TAR object name changed")
                target=objects/member.name.split("/",1)[1];digest=hashlib.sha256();count=0
                with stream.extractfile(member) as source,target.open("xb") as out:
                    while part:=source.read(1<<20):
                        out.write(part);count+=len(part);digest.update(part)
                require(count==member.size,"short TAR object")
                target.chmod(member.mode);observed[member.name]=dict(bytes=count,sha256=digest.hexdigest(),mode=member.mode)
                require(identity(target)==observed[member.name],"complete retained object changed")
            stream.members.clear()
    require(manifest and manifest["schema"]=="hepta.runtime.binary-read-stdio.complete-archive.v1"
        and manifest["gate_status"]=="FAIL" and manifest["git_head"]==binding["commit"],"original successful build identity differs")
    files=manifest["files"];dirs=manifest["directories"];expected={}
    for logical,value in files.items():
        safe(logical,{"source","run"});name=value["object"]
        require(name=="objects/"+value["sha256"]+"-"+format(value["mode"],"03o"),"logical object identity changed")
        item={k:value[k] for k in ("bytes","sha256","mode")}
        require(observed[name]==item,"logical file bytes differ")
        if name in expected:require(expected[name]==item,"shared object differs")
        expected[name]=item
    require(set(observed)==set(expected)|{"artifact-manifest.json"} and len(files)==binding["tar"]["logical_files"]
        and sum(v["bytes"] for v in files.values())==binding["tar"]["logical_bytes"]
        and len(dirs)==binding["tar"]["directories"]and len(expected)==binding["tar"]["unique_objects"]
        and sum(v["bytes"] for v in expected.values())==binding["tar"]["unique_bytes"],"complete original archive set/count changed")
    require(files["source/SOURCE_MANIFEST.json"]["sha256"]==binding["manifest_sha256"],"original source binding differs")
    restored=original/"restored";restored.mkdir()
    for logical,mode in sorted(dirs.items(),key=lambda p:(len(PurePosixPath(p[0]).parts),p[0])):
        safe(logical,{"source","run"});target=restored/logical;target.mkdir();target.chmod(mode)
    for logical,value in sorted(files.items()):
        target=restored/logical;require(target.parent.is_dir() and not target.exists(),"invalid restored file parent")
        os.link(original/value["object"],target)
    actual={p.relative_to(restored).as_posix():identity(p) for p in restored.rglob("*") if p.is_file()}
    actual_dirs={p.relative_to(restored).as_posix():stat.S_IMODE(p.stat().st_mode) for p in restored.rglob("*") if p.is_dir()}
    require(actual=={p:{k:v[k] for k in ("bytes","sha256","mode")} for p,v in files.items()} and actual_dirs==dirs,
        "complete restored logical file/directory bytes, modes or set differ")
    result=dict(status="PASS",original_status="FAIL",zip=pin(archive),zip_members=zip_rows,tar=pin(tar),
        logical_files=len(files),logical_bytes=sum(v["bytes"] for v in files.values()),
        directories=len(dirs),unique_objects=len(expected),unique_bytes=sum(v["bytes"] for v in expected.values()),
        all_objects_fully_read=True,all_logical_files_and_directories_restored=True,native_or_rust_executions=0)
    (original/"UNPACK.json").write_bytes(encode(result))
    return result

def frozen(expected=None):
    raw=(ROOT/"SOURCE_MANIFEST.json").read_bytes();manifest=decode(raw)
    require(expected is None or sha(raw)==expected,"uploaded reader source binding differs")
    rows=manifest["files"];actual={p.relative_to(ROOT).as_posix()for p in ROOT.rglob("*")if p.is_file()}
    require(actual=={r["path"]for r in rows}|{"SOURCE_MANIFEST.json"}and len(rows)==len(actual)-1,
        "uploaded reader complete source set differs")
    for row in rows:
        p=ROOT/row["path"];data=p.read_bytes()
        require(rawpin(data)=={k:row[k]for k in("bytes","sha256")}and stat.S_IMODE(p.stat().st_mode)==0o644
            and hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()==row["git_blob"],
            "uploaded reader source byte/mode differs")
    return sha(raw),decode((ROOT/"BINDING.json").read_bytes())
def context(work):
    base=work/"original/restored";source=base/"source";capture=base/"run/capture"
    sys.path.insert(0,str(source/"scripts"))
    import common,read_all,reader_controls,readonly
    read_all.prepare(capture)
    return base,source,capture,common,read_all,reader_controls,readonly
def complete(work):
    base,source,capture,common,read_all,controls,readonly=context(work)
    import read_stdio
    bound=decode((ROOT/"BINDING.json").read_bytes())
    def operation():
        manifest=decode((work/"original/ARTIFACT_MANIFEST.json").read_bytes())
        actual={p.relative_to(base).as_posix():identity(p)for p in base.rglob("*")if p.is_file()}
        dirs={p.relative_to(base).as_posix():stat.S_IMODE(p.stat().st_mode)for p in base.rglob("*")if p.is_dir()}
        require(actual=={n:{k:r[k]for k in("bytes","sha256","mode")}for n,r in manifest["files"].items()}
            and dirs==manifest["directories"],"complete failed archive identity")
        trusted=ROOT/"qualified"
        require({p.relative_to(source).as_posix():identity(p)for p in source.rglob("*")if p.is_file()}==
            {p.relative_to(trusted).as_posix():identity(p)for p in trusted.rglob("*")if p.is_file()},
            "frozen complete failed source")
        require(common.pin(source/"SOURCE_MANIFEST.json")["sha256"]==bound["manifest_sha256"],
            "failed qualification source binding")
        gate=decode((base/"run/GATE.json").read_bytes())
        require(gate["status"]=="FAIL"and gate["stage"]=="controls-controls","preserved capture-stage failure")
        records=decode((capture/"processes/processes.json").read_bytes())
        require(len(records)==23 and records[-1]["name"]=="controls-controls"and records[-1]["exit_code"]==1
            and records[-1]["completed"]is True and records[-1]["timed_out"]is False,"actual producer failure custody")
        for record in records:
            for channel in("stdout","stderr"):
                item=record[channel]
                require(pin(capture/"processes"/item["file"])=={k:item[k]for k in("bytes","sha256")},
                    "complete saved producer stream")
        successful=[]
        for record in records[:-1]:
            actual,stdout=read_all.process(capture/"processes",record["name"],record["timeout_seconds"])
            require(actual==record,"preserved successful producer")
            successful.append(dict(name=record["name"],exit_code=record["exit_code"],stdout_status=stdout.get("status")))
        control_root=capture/"controls/controls";control_rows=decode((control_root/"cases.json").read_bytes())
        diagnostics=[]
        for folder in sorted(p for p in control_root.iterdir()if p.is_dir()and p.name.startswith("case-")):
            p=decode((folder/"PROCESS.json").read_bytes());streams={}
            for channel,row in p["streams"].items():
                raw=read_stdio.stream(folder/(channel+".gz"),row)
                streams[channel]=dict(bytes=len(raw),sha256=sha(raw))
            diagnostics.append(dict(case=folder.name,completed=p["completed"],failure=p.get("failure"),
                returncode=p["returncode"],wait_status=p["wait_status"],reaped=p["reaped"],
                timed_out=p["timed_out"],stdin_closed=p["stdin_closed"],stdin_broken_pipe=p["stdin_broken_pipe"],
                before_eof=p["before_eof"],expected_input_bytes=p["expected_input_bytes"],
                written_bytes=sum(v["count"]for v in p["writes"]),pid=p["pid"],parent_pid=p["parent_pid"],
                parent_pgid=p["parent_pgid"],child_pgid=p["child_pgid"],same_outer_process_group=p["same_outer_process_group"],
                after_reap_proc_absent=p["after_reap_proc_absent"],elapsed_ns=p["elapsed_ns"],streams=streams))
        main_groups=[];semantic_error=None
        try:
            build=read_all.build_reuse.verify(source,capture/"build-reuse")
            queries,fixtures,setup=read_stdio.setup(source,capture/"setup");qs={r["id"]:r for r in queries}
            origin=decode((capture/"ORIGIN.json").read_bytes())
            for g in read_stdio.domain()["groups"]:
                name=g["name"];reference,a=read_stdio.capture(source,capture,"original",name,qs,fixtures,{},origin)
                production,b=read_stdio.capture(source,capture,"production",name,qs,fixtures,reference,origin)
                for key,value in reference.items():value["native_production"]=production[key]
                observed,c=read_stdio.capture(source,capture,"observed",name,qs,fixtures,reference,origin)
                main_groups.append(dict(group=name,original=a,production=b,observed=c))
        except(Exception)as error:
            semantic_error=dict(type=type(error).__name__,message=str(error))
        return dict(status="COMPLETE_FAILED_STDIO_ARCHIVE_DIAGNOSTIC_READ",original_gate_status="FAIL",
            binding=bound,complete_files=len(manifest["files"]),complete_directories=len(dirs),
            logical_bytes=sum(r["bytes"]for r in manifest["files"].values()),
            successful_producers=successful,completed_control_rows=len(control_rows),
            control_summary_present=(control_root/"CAPTURE.json").exists(),control_processes=diagnostics,
            completed_strict_main_groups=main_groups,strict_main_error=semantic_error,
            semantic_qualification_claim=False,application_hia_executions=0,rust_executions=0)
    return readonly.guarded(operation,roots=[ROOT,work/"download",work/"original"])
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["fetch","restore","read"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args();before,bound=frozen(a.source_manifest_sha256);work=a.work.absolute()
    if a.stage=="fetch":result=fetch(work,bound)
    elif a.stage=="restore":result=unpack(work,bound)
    else:
        result=complete(work);(work/"proof/READONLY.json").write_bytes(encode(result))
        result=dict(status=result["evidence"]["status"],evidence=result["evidence"],
            guard_probes=len(result["probes"]),unchanged_entries=result["entries"],
            application_hia_executions=0,rust_executions=0)
    require(frozen()[0]==before,"uploaded reader changed during complete read")
    print(encode(result).decode(),end="")
