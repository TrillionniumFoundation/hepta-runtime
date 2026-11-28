#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bounded recovery of complete original typed evidence; no semantic execution."""
from pathlib import Path,PurePosixPath
import argparse
import encodings.cp437
import hashlib
import gzip
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
    sys.path.insert(0,str(ROOT/"scripts"))
    from continuation_proof import frozen as check
    return check(ROOT,expected)
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
    require(manifest and manifest["schema"]=="hepta.runtime.binary-root.complete-archive.v1"
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

def inventory(root):
    result={}
    for p in[root,*sorted(root.rglob("*"))]:
        info=p.lstat();name="."if p==root else p.relative_to(root).as_posix()
        require(stat.S_ISREG(info.st_mode)or stat.S_ISDIR(info.st_mode),"ordinary complete capture required")
        result[name]=dict(mode=stat.S_IMODE(info.st_mode),kind="directory"if stat.S_ISDIR(info.st_mode)else"file")
        if stat.S_ISREG(info.st_mode):result[name].update(pin(p))
    return result

def original_failure(work):
    restored=work/"original/restored";capture=restored/"run/capture"
    binding=decode((ROOT/"BINDING.json").read_bytes())
    gate=decode((restored/"run/GATE.json").read_bytes())
    require(gate["status"]=="FAIL"and gate["stage"]=="producers"
        and gate["source_manifest_sha256"]==binding["manifest_sha256"],"original failed gate changed")
    require(gate["processes"]==decode((restored/"run/processes/processes.json").read_bytes())
        and [r["name"]for r in gate["processes"]]==["source-check","producers"],"original actual stage set changed")
    from proof_check import process
    process(gate["processes"][0],restored/"run/processes",60)
    failed=gate["processes"][1]
    require(failed["completed"]is True and failed["exit_code"]==1 and failed["timed_out"]is False
        and failed["timeout_seconds"]==900 and 0<=failed["elapsed_seconds"]<901,"producer failure state changed")
    for suffix in("stdout","stderr"):
        row=failed[suffix];require(pin(restored/"run/processes"/row["file"])=={k:row[k]for k in("bytes","sha256")},
            "original full failure stream changed")
    receipt=decode((capture/"processes/native-controls.json").read_bytes())
    require(receipt["returncode"]==1 and receipt["timed_out"]is False,"original failed native-control receipt changed")
    require(not(capture/"controls/PROGRESS.json").exists()and not(capture/"controls/CONTROLS.json").exists()
        and not(capture/"controls/RESULT.json").exists(),"capacity control may already have executed")
    with gzip.open(capture/"controls/calls.bin.gz","rb")as stream:
        require(stream.read()==b"","capacity control journal already contains an entry")
    return restored,capture,gate

def continue_controls(work):
    import gzip
    restored,original,gate=original_failure(work)
    origin=decode((original/"ORIGIN.json").read_bytes());capture=Path(origin["output"])
    require(capture==Path("/home/runner/work/_temp/binary-root-run/capture")
        and not capture.parent.exists(),"exact recorded native owner path is not fresh")
    require(Path(sys.executable)==Path(origin["python"]),"actual Python invocation path changed")
    before=inventory(original);capture.parent.mkdir(mode=0o700);shutil.copytree(original,capture,copy_function=shutil.copy2)
    require(inventory(capture)==before,"complete working copy differs from original artifact")
    failed=capture/"original-failure";failed.mkdir(mode=0o700);(failed/"processes").mkdir(mode=0o700)
    os.rename(capture/"controls",failed/"controls")
    for suffix in("json","stdin","stdout","stderr"):
        os.rename(capture/("processes/native-controls."+suffix),failed/("processes/native-controls."+suffix))
    shutil.copytree(ROOT,capture/"continuation-source",copy_function=shutil.copy2)
    from continuation_proof import frozen as check
    require(check(capture/"continuation-source")[0]==frozen()[0],"actual continuation source copy differs")
    from run_ci import run_process
    py=[sys.executable,"-I","-S","-B"];destination=work/"continued";require(not destination.exists(),"continued output reused")
    result=None;failure=None
    try:
        row=run_process(capture,"native-controls",py+[capture/"continuation-source/scripts/native_capture.py",
            "--qualification",capture,"--controls"],env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"},limit=60)
        from continuation_proof import validate
        validation=validate(capture)
        result=dict(status="PASS",new_native_capacity_calls=14,original_native_cases_replayed=0,
            original_wire_controls_replayed=0,rust_executions=0,compiler_executions=0,
            process=row,validation=validation)
        return result
    except BaseException as error:
        failure=dict(type=type(error).__name__,message=str(error));raise
    finally:
        after=inventory(capture);unchanged={}
        for name,value in before.items():
            mapped=name
            if name=="controls"or name.startswith("controls/"):mapped="original-failure/"+name
            if name in{"processes/native-controls."+suffix for suffix in("json","stdin","stdout","stderr")}:
                mapped="original-failure/"+name
            require(after.get(mapped)==value,"original source/capture changed during unstarted capacity controls: "+name)
            unchanged[name]=mapped
        extra=set(after)-set(unchanged.values())
        require(all(name=="original-failure"or name=="original-failure/processes"or name=="continuation-source"
            or name.startswith("continuation-source/")or name=="controls"or name.startswith("controls/")
            or name in{"processes/native-controls."+s for s in("json","stdin","stdout","stderr")}for name in extra),
            "undeclared continuation output")
        receipt=dict(schema="hepta.runtime.binary-root.unstarted-controls.v1",status="PASS"if result else"FAIL",
            original_capture=before,original_mapping=unchanged,all_original_bytes_modes_and_sets_unchanged=True,
            before_original=inventory(original),failure=failure,result=result)
        require(receipt["before_original"]==before,"retained immutable original changed")
        os.rename(capture.parent,destination)
        (destination/"CONTINUATION.json").write_bytes(encode(receipt))

def context(work):
    restored=work/"original/restored";source=restored/"source";capture=work/"continued/capture"
    sys.path.insert(0,str(ROOT/"scripts"))
    import common,root_cases,read_root,registry_evidence,run_ci,readonly,reader_controls,continuation_proof
    common.source_evidence(source)
    require(frozen()[0]==continuation_proof.frozen(capture/"continuation-source")[0],"executed continuation source differs")
    return source,capture,run_ci,readonly,reader_controls

def unchanged_original(work,capture):
    _,original,_=original_failure(work)
    receipt=decode((work/"continued/CONTINUATION.json").read_bytes())
    require(receipt["status"]=="PASS"and receipt["all_original_bytes_modes_and_sets_unchanged"]is True,
        "unstarted capacity continuation did not finish")
    before=inventory(original);require(before==receipt["original_capture"]==receipt["before_original"],
        "complete original artifact changed after continuation")
    after=inventory(capture);mapping=receipt["original_mapping"]
    require(set(mapping)==set(before)and len(set(mapping.values()))==len(mapping),"original custody mapping incomplete")
    for name,relative in mapping.items():
        require(after.get(relative)==before[name],"original complete byte/mode/set changed after continuation")
    return receipt["result"]

def read(work):
    source,capture,run_ci,readonly,controls=context(work)
    def operation():
        retained=unchanged_original(work,capture)
        result=run_ci.read_all(source,capture);result["continuation"]=retained
        return result
    return readonly.guarded(operation,roots=[ROOT,work/"original",work/"download",work/"continued"])

def make_controls(work):
    source,capture,run_ci,readonly,controls=context(work)
    return controls.produce(source,capture)

def verify(work):
    source,capture,run_ci,readonly,controls=context(work)
    def operation():
        retained=unchanged_original(work,capture)
        result=controls.verify(source,capture);result["continuation"]=retained
        return result
    return readonly.guarded(operation,roots=[ROOT,work/"original",work/"download",work/"continued"])

def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["fetch","unpack","continue","read","controls","verify"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    a=p.parse_args();identity_before,binding=frozen(a.source_manifest_sha256);work=a.work.absolute()
    if a.stage=="fetch":result=fetch(work,binding)
    elif a.stage=="unpack":result=unpack(work,binding)
    elif a.stage=="continue":result=continue_controls(work)
    elif a.stage=="read":result=read(work)
    elif a.stage=="controls":result=make_controls(work)
    else:result=verify(work)
    require(frozen()[0]==identity_before,"continuation source changed during stage")
    print(encode(result).decode(),end="")
if __name__=="__main__":main()
