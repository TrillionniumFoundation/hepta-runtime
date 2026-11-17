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
    require(manifest and manifest["schema"]=="hepta.runtime.path-error.complete-archive.v1"
        and manifest["gate_status"]=="PASS" and manifest["git_head"]==binding["commit"],"original successful build identity differs")
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
    result=dict(status="PASS",original_status="PASS",zip=pin(archive),zip_members=zip_rows,tar=pin(tar),
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
    bound=decode((ROOT/"BINDING.json").read_bytes())
    def operation():
        manifest=decode((work/"original/ARTIFACT_MANIFEST.json").read_bytes())
        files=manifest["files"];directories=manifest["directories"]
        actual={p.relative_to(base).as_posix():identity(p)for p in base.rglob("*")if p.is_file()}
        dirs={p.relative_to(base).as_posix():stat.S_IMODE(p.stat().st_mode)for p in base.rglob("*")if p.is_dir()}
        require(actual=={n:{k:r[k]for k in("bytes","sha256","mode")}for n,r in files.items()}and dirs==directories,
            "uploaded complete logical file/directory bytes, modes or set differs")
        trusted=ROOT/"qualified";left={p.relative_to(source).as_posix():identity(p)for p in source.rglob("*")if p.is_file()}
        right={p.relative_to(trusted).as_posix():identity(p)for p in trusted.rglob("*")if p.is_file()}
        require(left==right and common.pin(source/"SOURCE_MANIFEST.json")["sha256"]==bound["manifest_sha256"],
            "uploaded source differs from frozen qualified complete source")
        result=read_all.verify(source,capture);physical=controls.verify(source,capture,base/"run/controls")
        gate=decode((base/"run/GATE.json").read_bytes())
        require(gate["status"]=="PASS"and gate["stage"]=="complete"and gate["source"]==result["source"]
            and gate["domain"]==result["domain"]and gate["producer_processes"]==331
            and gate["physical_refusals"]==9 and gate["physical_relocations"]==2
            and gate["original_or_native_replayed"]is False,"actual qualification gate differs")
        records=decode((base/"run/processes/processes.json").read_bytes())
        require([r["name"]for r in records]==["read","controls","verify"],"outer pure process order")
        saved={}
        for row in records:
            name=row["name"]
            require(row["completed"]is True and row["timed_out"]is False and row["exit_code"]==0
                and row["timeout_seconds"]==180 and 0<=row["elapsed_seconds"]<181
                and row["pgid"]==row["pid"]and row["stdin"]is None,"pure process limit/custody")
            for which in("stdout","stderr"):
                value=row[which]
                require(value["file"]==name+"."+which and {k:value[k]for k in("bytes","sha256")}==
                    pin(base/"run/processes"/value["file"]),"full pure process stream differs")
            require(row["stderr"]["bytes"]==0,"pure process stderr")
            saved[name]=decode((base/"run/processes"/row["stdout"]["file"]).read_bytes())
        for name,file in(("read","READ.json"),("verify","VERIFY.json")):
            proof=decode((base/"run"/file).read_bytes())
            require(proof==saved[name]and proof["status"]=="READONLY_PASS"and proof["before"]==proof["after"]
                and len(proof["probes"])==11 and all(r["rejected"]is True for r in proof["probes"])
                and proof["native_executed"]is False and proof["rust_executed"]is False
                and proof["evidence_written"]is False,"saved complete pure custody differs")
        require(saved["read"]["evidence"]==result,"saved comparison differs from independent full comparison")
        require(saved["verify"]["evidence"]==dict(result,physical_controls=physical),"saved full verification differs")
        require(saved["controls"]==decode((base/"run/controls/controls.json").read_bytes())==
            decode((base/"run/CONTROLS.json").read_bytes()),"saved physical controls differ")
        return dict(status="COMPLETE_PATH_ERROR_UPLOADED_READ_PASS",binding=bound,
            complete_files=len(files),complete_directories=len(directories),logical_bytes=sum(r["bytes"]for r in files.values()),
            comparison=result["comparison"],native_calls=result["native_calls"],
            native_full_buffer_bytes=result["native_full_buffer_bytes"],original_full_bytes=result["original_full_bytes"],
            physical_controls=physical,build=result["build"],producer_processes=result["producer_processes"],
            source=result["source"],application_hia_executions=0,rust_executions=0,scope=common.SCOPE)
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
