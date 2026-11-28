#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Recover one fixed capture and apply two explicit reader-only repairs."""
from pathlib import Path,PurePosixPath
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import sys
import tarfile
import traceback
import urllib.error
import urllib.parse
import urllib.request
import zipfile
sys.dont_write_bytecode=True
REPO="TrillionniumFoundation/hepta-runtime"
ARTIFACT=14298321824
RUN=44014937696
ZIP_PIN=dict(bytes=96442467,sha256="3d16498eb96906fbfab04bf33eb8bbcc62e1dc81cfc7f132adb66690491b8003")
TAR_PIN=dict(bytes=94206481,sha256="4a4eed6b25d851ece9667dc9373c9c6c77e0b55a65f5015cbc8fc075208cd28a")
def need(v,m):
    if not v:raise ValueError(m)
def encoded(v):return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def pin(path):
    with path.open("rb") as f:return dict(bytes=path.stat().st_size,sha256=hashlib.file_digest(f,"sha256").hexdigest())
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,msg,headers,newurl):return None


def recover(root):
    token=os.environ.pop("GH_TOKEN")
    url=f"https://api.github.com/repos/{REPO}/actions/artifacts/{ARTIFACT}"
    headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"}
    with urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=60) as s:meta=json.load(s)
    need(meta["id"]==ARTIFACT and meta["workflow_run"]["id"]==RUN and meta["size_in_bytes"]==ZIP_PIN["bytes"]
        and meta["digest"]=="sha256:"+ZIP_PIN["sha256"] and meta["expired"] is False,"artifact metadata changed")
    try:
        urllib.request.build_opener(NoRedirect).open(urllib.request.Request(url+"/zip",headers=headers),timeout=60)
        raise ValueError("missing artifact redirect")
    except urllib.error.HTTPError as e:
        need(e.code==302,"artifact redirect status changed");location=e.headers["Location"]
    need(urllib.parse.urlsplit(location).scheme=="https","nonHTTPS artifact")
    archive=root/"artifact.zip"
    with urllib.request.urlopen(urllib.request.Request(location),timeout=60) as incoming,archive.open("xb") as f:shutil.copyfileobj(incoming,f,1024*1024)
    need(pin(archive)==ZIP_PIN,"whole ZIP bytes differ")
    with zipfile.ZipFile(archive) as z:
        members=z.infolist()
        need(len(members)==3 and {m.filename for m in members}=={"evidence.tar.gz","FILES.json","ARCHIVE.json"},"ZIP member set changed")
        for m in members:
            need(not m.is_dir() and not stat.S_ISLNK(m.external_attr>>16),"ZIP member type differs")
            with z.open(m) as s,(root/m.filename).open("xb") as f:shutil.copyfileobj(s,f,1024*1024)
    need(pin(root/"evidence.tar.gz")==TAR_PIN,"whole TAR bytes differ")
    index=json.loads((root/"FILES.json").read_bytes());wanted={r["path"]:r for r in index["files"]}
    need(len(wanted)==len(index["files"])==9217,"member index differs")
    extracted=root/"retained";extracted.mkdir();seen=set()
    with tarfile.open(root/"evidence.tar.gz","r:gz") as tar:
        for m in tar:
            p=PurePosixPath(m.name)
            need(m.isfile() and not p.is_absolute() and ".." not in p.parts and p.as_posix()==m.name
                and m.name in wanted and m.name not in seen,"TAR member invalid")
            seen.add(m.name);row=wanted[m.name]
            need(m.size==row["bytes"] and m.mode==row["mode"],"member size/mode changed")
            target=extracted/m.name;target.parent.mkdir(parents=True,exist_ok=True)
            with tar.extractfile(m) as incoming,target.open("xb") as f:shutil.copyfileobj(incoming,f,1024*1024)
            target.chmod(m.mode)
            need(pin(target)=={k:row[k] for k in ("bytes","sha256")},"complete member bytes differ")
    need(seen==set(wanted),"TAR member omitted")
    return extracted,index,meta

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value
    spec.loader.exec_module(value);return value

def archive_controls(root,proof):
    rows=[];archive=proof/"controls.tar.gz"
    with tarfile.open(archive,"w:gz",compresslevel=1,format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(root.rglob("*")):
            if path.is_dir():continue
            info=path.lstat();need(stat.S_ISREG(info.st_mode),"control non-ordinary evidence")
            name=path.relative_to(root).as_posix()
            row=dict(path=name,mode=info.st_mode&0o777,**pin(path));rows.append(row)
            header=tarfile.TarInfo(name);header.size=row["bytes"];header.mode=row["mode"];header.mtime=0
            with path.open("rb") as f:tar.addfile(header,f)
    wanted={r["path"]:r for r in rows};seen=set()
    with tarfile.open(archive,"r:gz") as tar:
        for member in tar:
            need(member.isfile() and member.name in wanted and member.name not in seen,"control archive set differs")
            seen.add(member.name);row=wanted[member.name]
            need(member.mode==row["mode"] and member.size==row["bytes"],"control archive extent/mode differs")
            need(hashlib.file_digest(tar.extractfile(member),"sha256").hexdigest()==row["sha256"],"control full bytes differ")
    need(seen==set(wanted),"control archive omitted file")
    (proof/"CONTROL_FILES.json").write_bytes(encoded(dict(files=rows,archive=pin(archive))))
    return dict(files=len(rows),logical_bytes=sum(r["bytes"] for r in rows),archive=pin(archive))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    root=a.output.absolute();need(not root.exists(),"fresh reader output required");root.mkdir(parents=True)
    proof=root/"proof";proof.mkdir();here=Path(__file__).resolve().parent
    retained,index,metadata=recover(root)
    capture=retained/"capture";source=capture/"source";scripts=source/"scripts"
    need(pin(source/"SOURCE_MANIFEST.json")["sha256"]=="24927588d1125326a9cf8eb4e2279cb4fb4049714311246de851b3b238b239e4",
        "retained exact source manifest differs")
    before_build=(scripts/"read_build.py").read_text();after_build=(here/"read_build.py").read_text()
    need(before_build.count("build/typed-params.json")==2
        and after_build==before_build.replace("build/typed-params.json","BUILD.json"),"build reader repair is not the exact stale-path fix")
    before_controls=(scripts/"reader_controls.py").read_text();after_controls=(here/"reader_controls.py").read_text()
    need(after_controls==before_controls.replace("copy_function=os.link","copy_function=shutil.copy2")
        .replace("else:os.link(incoming,target)","else:shutil.copy2(incoming,target)"),"control copy repair changed semantics")
    sys.path.insert(0,str(scripts))
    import run_ci
    import body_cases
    import registry_evidence
    module("read_build",here/"read_build.py")
    import read_body
    controls=module("reader_controls",here/"reader_controls.py")
    import readonly
    original_before=readonly.snapshot([retained])
    for path in here.iterdir():
        if path.is_file():shutil.copyfile(path,proof/path.name)
    for name in ("FILES.json","ARCHIVE.json"):shutil.copyfile(root/name,proof/("ORIGINAL_"+name))
    try:
        value=run_ci.bounded(lambda:run_ci.read_all(source,capture))
    except BaseException:
        traceback.print_exc()
        # Diagnostic reads retain full data and do not revise a failed comparison.
        try:
            left=read_body.lane_rows(source,capture,"native")
            right=read_body.lane_rows(source,capture,"original")
            differences=[]
            for position,(a,b) in enumerate(zip(left[4],right[4])):
                if a!=b:
                    row=dict(case_id=position,fields=[k for k in a if a[k]!=b[k]],native=a,original=b)
                    differences.append(row)
                    print("BODY_DIFFERENCE "+json.dumps(dict(case_id=position,fields=row["fields"],
                        native_result=a["result"],original_result=b["result"]),sort_keys=True))
            (proof/"DIFFERENCES.json").write_bytes(encoded(differences))
        except BaseException:traceback.print_exc()
        raise
    (proof/"COMPARISON.json").write_bytes(encoded(value))
    control_root=root/"physical-controls"
    run_ci.bounded(lambda:controls.create(source,capture,control_root))
    need(readonly.snapshot([retained])==original_before,"creating controls changed retained evidence metadata/bytes")
    def operation():
        value=run_ci.read_all(source,capture);value["physical_controls"]=controls.verify(source,capture,control_root);return value
    guarded=run_ci.bounded(lambda:readonly.guarded(operation,roots=[retained,control_root,here]))
    need(readonly.snapshot([retained])==original_before,"whole retained evidence changed")
    need(pin(root/"artifact.zip")==ZIP_PIN and pin(root/"evidence.tar.gz")==TAR_PIN,"original archive changed")
    control_archive=archive_controls(control_root,proof)
    report=dict(status="PRIVATE_TEXT_PUBLICATION_RETAINED_READER_V2_PASS",semantic_capture_commit="966bb9eff9d61176700796fd0452429bc9674717",
        semantic_ci_original_conclusion="failure",run=RUN,artifact=ARTIFACT,zip=ZIP_PIN,tar=TAR_PIN,
        complete_original_files=len(index["files"]),complete_original_bytes=sum(r["bytes"] for r in index["files"]),
        patches={name:pin(here/name) for name in ("read_build.py","reader_controls.py")},
        guarded=guarded,original_whole_metadata_and_bytes_unchanged=True,
        controls=control_archive,native_or_rust_executions=0,failure_reclassified=False)
    (proof/"READBACK.json").write_bytes(encoded(report))
    for path in here.iterdir():
        if path.is_file():shutil.copyfile(path,proof/path.name)
    for name in ("FILES.json","ARCHIVE.json"):shutil.copyfile(root/name,proof/("ORIGINAL_"+name))
    print("BODY_READER_RESULT "+json.dumps({k:report[k] for k in report if k!="guarded"},sort_keys=True))
    print("BODY_EVIDENCE "+json.dumps(guarded["evidence"],sort_keys=True))

if __name__=="__main__":
    try:main()
    except BaseException:
        traceback.print_exc()
        raise
