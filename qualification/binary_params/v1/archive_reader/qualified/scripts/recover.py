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
def frozen(expected=None):
    manifest=ROOT/"SOURCE_MANIFEST.json";raw=manifest.read_bytes();value=decode(raw)
    require(expected is None or sha(raw)==expected,"recovery source manifest changed")
    rows=value["files"];require(len({r["path"] for r in rows})==len(rows),"duplicate recovery source")
    actual={p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*") if p.is_file()}
    require(actual=={r["path"] for r in rows}|{"SOURCE_MANIFEST.json"},"recovery source file set changed")
    for row in rows:
        p=ROOT/row["path"];data=p.read_bytes()
        require(p.resolve()==p.absolute() and p.is_file() and not (p.stat().st_mode&0o111),"recovery source kind/mode changed")
        require(rawpin(data)=={k:row[k] for k in ("bytes","sha256")} and
            hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()==row["git_blob"],"recovery source byte pin changed")
    binding=decode((ROOT/"BINDING.json").read_bytes())
    old=(ROOT/"scripts/reader_controls_original.py.txt").read_text()
    patch=binding["reader_change"]
    require(old.count(patch["replacement"]["before"])==1,"reader patch location changed")
    changed=old.replace(patch["replacement"]["before"],patch["replacement"]["after"])
    require((ROOT/"scripts/reader_controls.py").read_text()==changed and sha(old.encode())==patch["original_sha256"]
        and sha(changed.encode())==patch["patched_sha256"],"pure recovery exceeds its exact one-line change")
    return sha(raw),binding
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
    require(manifest and manifest["schema"]=="hepta.runtime.binary-params.complete-archive.v1"
        and manifest["gate_status"]=="FAIL" and manifest["git_head"]==binding["commit"],"original failed capture identity differs")
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
    result=dict(status="PASS",original_status="FAIL",zip=pin(archive),zip_members=zip_rows,tar=pin(tar),
        logical_files=len(files),logical_bytes=sum(v["bytes"] for v in files.values()),
        directories=len(dirs),unique_objects=len(expected),unique_bytes=sum(v["bytes"] for v in expected.values()),
        all_objects_fully_read=True,all_logical_files_and_directories_restored=True,native_or_rust_executions=0)
    (original/"UNPACK.json").write_bytes(encode(result))
    return result
def context(work):
    restored=work/"original/restored";source=restored/"source";capture=restored/"run/capture"
    sys.path.insert(0,str(source/"scripts"))
    import common,params_cases,read_params,registry_evidence,run_ci,readonly
    require(common.pin(source/"SOURCE_MANIFEST.json")["sha256"]==decode((ROOT/"BINDING.json").read_bytes())["manifest_sha256"],
        "original reader source manifest differs")
    common.source_evidence(source)
    require((source/"scripts/reader_controls.py").read_bytes()==(ROOT/"scripts/reader_controls_original.py.txt").read_bytes(),
        "original reader bytes differ from exact patch baseline")
    spec=importlib.util.spec_from_file_location("reader_controls",ROOT/"scripts/reader_controls.py")
    controls=importlib.util.module_from_spec(spec);sys.modules["reader_controls"]=controls;spec.loader.exec_module(controls)
    proof_spec=importlib.util.spec_from_file_location("binary_recovery_proof_check",ROOT/"scripts/proof_check.py")
    checker=importlib.util.module_from_spec(proof_spec);proof_spec.loader.exec_module(checker)
    return source,capture,run_ci,readonly,controls,checker
def validate_original(work,source,capture,run_ci,checker):
    restored=work/"original/restored"
    binding=decode((ROOT/"BINDING.json").read_bytes())
    manifest=decode((work/"original/ARTIFACT_MANIFEST.json").read_bytes())
    gate=decode((restored/"run/GATE.json").read_bytes())
    require(gate["status"]=="FAIL" and gate["stage"]=="physical-controls"
        and gate["source_manifest_sha256"]==binding["manifest_sha256"],"original failure state changed")
    require([row["name"] for row in gate["processes"]]==["source-check","producers","read-only-admission","physical-controls"],
        "original process order changed")
    require(gate["processes"]==decode((restored/"run/processes/processes.json").read_bytes()),"original gate process records changed")
    for row,budget in zip(gate["processes"][:3],[60,900,180]):
        checker.process(row,restored/"run/processes",budget)
    failed=gate["processes"][3]
    require(failed["completed"] is True and failed["exit_code"]==1 and failed["timed_out"] is False
        and failed["timeout_seconds"]==180,"original control failure changed")
    for suffix in ("stdout","stderr"):
        value=failed[suffix]
        require(pin(restored/"run/processes"/value["file"])=={k:value[k] for k in ("bytes","sha256")},"original failure stream changed")
    first=decode((restored/"run/processes/read-only-admission.stdout").read_bytes())
    origin=decode((capture/"ORIGIN.json").read_bytes())
    checker.proof(first,manifest["files"],manifest["directories"],{
        origin["source"]:"source",origin["output"]:"run/capture"})
    result=run_ci.read_all(source,capture)
    require(result==first["evidence"],"complete original/native comparison changed")
    native=result["native"]
    require(native["cases"]==1388 and native["calls"]==8143 and native["controls"]==170
        and native["full_record_bytes"]==924760099 and native["typed_successes"]==501
        and native["value_admitted"]==1308,"actual native domain changed")
    return result
def read(work):
    source,capture,run_ci,readonly,controls,checker=context(work)
    return readonly.guarded(lambda:validate_original(work,source,capture,run_ci,checker),
        roots=[ROOT,work/"original",work/"download"])
def make_controls(work):
    source,capture,run_ci,readonly,controls,checker=context(work)
    result=controls.create(source,capture,work/"recovery-controls")
    require(result["status"]=="PHYSICAL_READER_CONTROLS_PASS","physical recovery controls failed")
    return result
def verify(work):
    source,capture,run_ci,readonly,controls,checker=context(work)
    def complete():
        result=validate_original(work,source,capture,run_ci,checker)
        result["physical_controls"]=controls.verify(source,capture,work/"recovery-controls")
        return result
    return readonly.guarded(complete,roots=[ROOT,work/"original",work/"download",work/"recovery-controls"])
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["fetch","unpack","read","controls","verify"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args();identity_before,binding=frozen(a.source_manifest_sha256)
    work=a.work.absolute()
    if a.stage=="fetch":result=fetch(work,binding)
    elif a.stage=="unpack":result=unpack(work,binding)
    elif a.stage=="read":result=read(work)
    elif a.stage=="controls":result=make_controls(work)
    else:result=verify(work)
    require(frozen()[0]==identity_before,"pure recovery source changed during stage")
    print(encode(result).decode(),end="")
if __name__=="__main__":main()
