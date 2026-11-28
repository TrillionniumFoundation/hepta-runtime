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
ROOT=Path(__file__).resolve().parents[1]
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
    require(manifest and manifest["schema"]=="hepta.runtime.file-info-at-qualification.complete-archive.v1"
        and manifest["gate_status"]==binding["gate_status"] and manifest["git_head"]==binding["commit"],"original successful build identity differs")
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
        and len(expected)==binding["tar"]["unique_objects"]
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
    result=dict(status="PASS",original_status=binding["gate_status"],zip=pin(archive),zip_members=zip_rows,tar=pin(tar),
        logical_files=len(files),logical_bytes=sum(v["bytes"] for v in files.values()),
        directories=len(dirs),unique_objects=len(expected),unique_bytes=sum(v["bytes"] for v in expected.values()),
        all_objects_fully_read=True,all_logical_files_and_directories_restored=True,native_or_rust_executions=0)
    (original/"UNPACK.json").write_bytes(encode(result))
    return result

def selection(source,name):
    bound=decode((Path(source)/"INPUTS.json").read_bytes())
    require(name in bound["groups"],"unfrozen uploaded info group")
    return bound["groups"][name]
def verify(source,work,binding):
    source,work=Path(source),Path(work);original=work/"original"
    require(pin(work/"download/complete.zip")=={k:binding["artifact"][k]for k in("bytes","sha256")},"full uploaded ZIP identity")
    zipped=original/"zip";zip_rows={}
    with zipfile.ZipFile(work/"download/complete.zip")as archive:
        for member in archive.infolist():
            safe(member.filename);require(not member.is_dir()and member.filename not in zip_rows,"unique ordinary ZIP member")
            with archive.open(member)as stream:
                digest=hashlib.sha256();count=0
                while part:=stream.read(1<<20):count+=len(part);digest.update(part)
            row=dict(bytes=count,sha256=digest.hexdigest())
            require(count==member.file_size and pin(zipped/member.filename)==row,"every complete uploaded ZIP member")
            zip_rows[member.filename]=row
    require({p.relative_to(zipped).as_posix()for p in zipped.rglob("*")if p.is_file()}==set(zip_rows),"complete stored ZIP member set")
    tar=zipped/"evidence.tar.gz";require(pin(tar)=={k:binding["tar"][k]for k in("bytes","sha256")},"complete semantic TAR")
    observed={};manifest=None
    with tarfile.open(tar,"r|gz")as stream:
        while member:=stream.next():
            require(member.isfile()and member.name not in observed,"complete unique ordinary TAR member")
            with stream.extractfile(member)as file:
                if member.name=="artifact-manifest.json":
                    raw=file.read();require(len(raw)==member.size,"whole logical manifest")
                    manifest=decode(raw);require(raw==(original/"ARTIFACT_MANIFEST.json").read_bytes(),"retained logical manifest bytes")
                    row=dict(**rawpin(raw),mode=member.mode)
                else:
                    require(re.fullmatch(r"objects/[0-9a-f]{64}-[0-7]{3}",member.name),"complete object name")
                    digest=hashlib.sha256();count=0
                    while part:=file.read(1<<20):count+=len(part);digest.update(part)
                    row=dict(bytes=count,sha256=digest.hexdigest(),mode=member.mode)
                    require(count==member.size and identity(original/member.name)==row,"complete object data/mode")
            observed[member.name]=row;stream.members.clear()
    require(manifest and manifest["schema"]=="hepta.runtime.file-info-at-qualification.complete-archive.v1"
        and manifest["git_head"]==binding["commit"]and manifest["gate_status"]==binding["gate_status"],"original complete successful semantic archive")
    expected={};logical=manifest["files"];directories=manifest["directories"]
    for path,row in logical.items():
        safe(path,{"source","run"});require(row["object"]=="objects/"+row["sha256"]+"-"+format(row["mode"],"03o"),"logical object identity")
        item={k:row[k]for k in("bytes","sha256","mode")}
        require(observed[row["object"]]==item,"whole logical object bytes/mode");expected[row["object"]]=item
    require(set(observed)==set(expected)|{"artifact-manifest.json"}and len(logical)==binding["tar"]["logical_files"]
        and sum(x["bytes"]for x in logical.values())==binding["tar"]["logical_bytes"]and len(expected)==binding["tar"]["unique_objects"]
        and sum(x["bytes"]for x in expected.values())==binding["tar"]["unique_bytes"],"entire semantic archive extent")
    require({p.name for p in(original/"objects").iterdir()}=={k.split("/",1)[1]for k in expected},"complete object file set")
    restored=original/"restored"
    actual={p.relative_to(restored).as_posix():identity(p)for p in restored.rglob("*")if p.is_file()}
    dirs={p.relative_to(restored).as_posix():stat.S_IMODE(p.stat().st_mode)for p in restored.rglob("*")if p.is_dir()}
    require(actual=={p:{k:v[k]for k in("bytes","sha256","mode")}for p,v in logical.items()}and dirs==directories,"all restored semantic files/directories")
    old=restored/"source";trusted=source/"trusted-qualification"/binding["profile"]
    trusted_rows={p.relative_to(trusted).as_posix():identity(p)for p in trusted.rglob("*")if p.is_file()}
    old_rows={p.relative_to(old).as_posix():identity(p)for p in old.rglob("*")if p.is_file()}
    require(old_rows==trusted_rows and pin(old/"SOURCE_MANIFEST.json")["sha256"]==binding["manifest_sha256"],"all archived/frozen source bytes")
    gate=decode((restored/"run/GATE.json").read_bytes());require(gate["status"]==binding["gate_status"]and gate["group"]==binding["group"],"actual terminal group")
    unpacked=decode((original/"UNPACK.json").read_bytes())
    require(unpacked["zip_members"]==zip_rows and unpacked["logical_files"]==len(logical)and unpacked["logical_bytes"]==sum(v["bytes"]for v in logical.values()),"full restoration receipt")
    return dict(status="ALL_UPLOADED_INFO_ARCHIVE_BYTES_PASS",group=binding["group"],zip=pin(work/"download/complete.zip"),tar=pin(tar),
        logical_files=len(logical),logical_bytes=sum(v["bytes"]for v in logical.values()),directories=len(dirs),unique_objects=len(expected),application_executions=0)
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["fetch","unpack","admit"])
    p.add_argument("--source",type=Path,required=True);p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True)
    a=p.parse_args();sys.path.insert(0,str(a.source/"scripts"))
    from evidence_common import source_evidence
    identity_before=source_evidence(a.source);bound=selection(a.source,a.group)
    if a.stage=="fetch":result=fetch(a.work,bound)
    elif a.stage=="unpack":result=unpack(a.work,bound)
    else:result=verify(a.source,a.work,bound)
    require(source_evidence(a.source)==identity_before,"frozen pure restore source changed")
    print(encode(result).decode(),end="")
