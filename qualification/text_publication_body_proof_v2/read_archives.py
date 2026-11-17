#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read two immutable publication evidence archives in full without importing any runtime."""
from pathlib import Path,PurePosixPath
import argparse
import hashlib
import json
import os
import shutil
import stat
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPO="TrillionniumFoundation/hepta-runtime"
ORIGINAL=dict(id=14298321824,run=44014937696,bytes=96442467,
    sha256="3d16498eb96906fbfab04bf33eb8bbcc62e1dc81cfc7f132adb66690491b8003")
PROOF=dict(id=14298952020,run=44016123612,bytes=162767940,
    sha256="598cb50d285c05e21c4fdb8fa8e52cfaf2e654b15bc77ff96125d4ea1e1f6eb5")
TAR=dict(bytes=94206481,sha256="4a4eed6b25d851ece9667dc9373c9c6c77e0b55a65f5015cbc8fc075208cd28a")
CONTROL_TAR=dict(bytes=121176113,sha256="4337d1d1730555e5fc8dd432134dfeca3cd90065882ad765a35fe93bb69e0824")
PATCHES={
 "read_build.py":dict(bytes=5350,sha256="46f0c26198a1d56dd183394d139f434e6a86feeb50c2951c9aed521b576408f2"),
 "reader_controls.py":dict(bytes=5419,sha256="71ef29f710a09012e785f8a32a2c81ccafd352421e4a814f3845c2cac35c4de4"),
 "read_retained.py":dict(bytes=10271,sha256="2c01a145c90e1abe253396c50cf8c0c0d21396c59e602fe0d7d9552866b0c3d1")}
NAMES=("missing-effect","changed-input","changed-workspace","changed-image","changed-result","extra-original-wire")
PROBES=("write","os-open-write","mkdir","rename","unlink","chmod","utime","subprocess","ctypes","mmap","foreign-read")
def need(v,m):
    if not v:raise ValueError(m)
def encode(v):return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def decode(raw):
    def unique(items):
        out={}
        for k,v in items:need(k not in out,"duplicate JSON key");out[k]=v
        return out
    return json.loads(raw,object_pairs_hook=unique)
def pin(path):
    with path.open("rb") as f:return dict(bytes=path.stat().st_size,sha256=hashlib.file_digest(f,"sha256").hexdigest())
def safe(name):
    p=PurePosixPath(name)
    need(type(name) is str and not p.is_absolute() and ".." not in p.parts
        and p.as_posix()==name and p.parts,"noncanonical member")
    return p
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,msg,headers,newurl):return None
def download(root,item,token):
    url=f"https://api.github.com/repos/{REPO}/actions/artifacts/{item['id']}"
    headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"}
    with urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=60) as response:meta=decode(response.read())
    need(meta["id"]==item["id"] and meta["workflow_run"]["id"]==item["run"]
        and meta["size_in_bytes"]==item["bytes"] and meta["digest"]=="sha256:"+item["sha256"]
        and meta["expired"] is False,"artifact identity differs")
    try:
        urllib.request.build_opener(NoRedirect).open(urllib.request.Request(url+"/zip",headers=headers),timeout=60)
        raise ValueError("missing redirect")
    except urllib.error.HTTPError as error:
        need(error.code==302,"unexpected redirect status");location=error.headers["Location"]
    need(urllib.parse.urlsplit(location).scheme=="https","unsigned scheme")
    root.mkdir()
    path=root/"artifact.zip"
    with urllib.request.urlopen(urllib.request.Request(location),timeout=60) as incoming,path.open("xb") as outgoing:
        shutil.copyfileobj(incoming,outgoing,1024*1024)
    need(pin(path)=={k:item[k] for k in ("bytes","sha256")},"complete ZIP differs")
    return path,meta
def unzip(path,root,names):
    rows=[]
    with zipfile.ZipFile(path) as archive:
        members=archive.infolist()
        need(len(members)==len(names) and {m.filename for m in members}==set(names),"ZIP member set differs")
        for member in members:
            safe(member.filename)
            need(not member.is_dir() and not stat.S_ISLNK(member.external_attr>>16),"ZIP nonordinary member")
            target=root/member.filename
            with archive.open(member) as incoming,target.open("xb") as outgoing:shutil.copyfileobj(incoming,outgoing,1024*1024)
            rows.append(dict(path=member.filename,mode=(member.external_attr>>16)&0o777,**pin(target)))
    return rows
def table(index,count):
    rows=index["files"];out={r["path"]:r for r in rows}
    need(len(rows)==len(out)==count,"index count differs")
    for name,row in out.items():
        safe(name);need(type(row["bytes"]) is int and row["bytes"]>=0
            and type(row["mode"]) is int and 0<=row["mode"]<=0o777,"invalid indexed metadata")
    return out
def read_tar(path,wanted,keep):
    seen=set();saved={}
    with tarfile.open(path,"r:gz") as archive:
        for member in archive:
            safe(member.name)
            need(member.isfile() and member.name in wanted and member.name not in seen,"TAR member set/type differs")
            seen.add(member.name);row=wanted[member.name]
            need(member.size==row["bytes"] and member.mode==row["mode"],"TAR member metadata differs")
            digest=hashlib.sha256();parts=[]
            with archive.extractfile(member) as incoming:
                while True:
                    chunk=incoming.read(1024*1024)
                    if not chunk:break
                    digest.update(chunk)
                    if keep(member.name):parts.append(chunk)
            need(digest.hexdigest()==row["sha256"],"complete TAR member bytes differ")
            if keep(member.name):saved[member.name]=b"".join(parts)
    need(seen==set(wanted),"TAR omitted indexed evidence")
    return saved
def snapshot_table(rows,number):
    result={r["path"]:r for r in rows if r["root"]==number}
    need(len(result)==sum(r["root"]==number for r in rows),"duplicate snapshot entry")
    return result
def verify_snapshot(rows,wanted):
    directories={"."}
    for name in wanted:
        p=PurePosixPath(name)
        directories.update(q.as_posix() for q in p.parents)
    need(set(rows)==set(wanted)|directories,"complete snapshot closure differs")
    for name,row in rows.items():
        if name in wanted:
            expect=wanted[name]
            need(stat.S_ISREG(row["mode"]) and row["mode"]&0o777==expect["mode"]
                and row["bytes"]==expect["bytes"] and row["sha256"]==expect["sha256"]
                and row["links"]==1,"snapshot file bytes/mode/links differ")
        else:need(stat.S_ISDIR(row["mode"]) and "sha256" not in row,"snapshot directory differs")
def verify_controls(wanted,original,saved,evidence):
    expected=decode(saved["CONTROLS.json"])
    need(expected==dict(names=list(NAMES),controls=6),"control declarations differ")
    need({r["name"] for r in evidence["controls"]}==set(NAMES)
        and evidence["native_or_rust_executed"] is False,"control result scope differs")
    for name in NAMES:
        record=decode(saved[name+"/CONTROL.json"])
        need(record["name"]==name and record["native_or_rust_executed"] is False,"control identity differs")
        prefix=name+"/capture/"
        actual={p[len(prefix):]:{k:r[k] for k in ("bytes","sha256","mode")}
            for p,r in wanted.items() if p.startswith(prefix)}
        need(actual==record["after"],"complete physical clone differs")
        before=record["before"];change=record["change"]
        need(set(before)==set(actual) and {p for p in before if before[p]!=actual[p]}=={change["path"]},
            "physical change count differs")
        for p,row in before.items():
            original_row=original["capture/"+p]
            need(row=={k:original_row[k] for k in ("bytes","sha256","mode")},"control before differs from original")
        need(change["before"]=={k:before[change["path"]][k] for k in ("bytes","sha256")}
            and change["after"]=={k:actual[change["path"]][k] for k in ("bytes","sha256")}
            and type(record["expected_error"]) is str and record["expected_error"],"mutation receipt differs")
        public=next(r for r in evidence["controls"] if r["name"]==name)
        need(public==dict(name=name,change=change,rejected=True),"guarded control result differs")
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--output",type=Path,required=True);args=parser.parse_args()
    root=args.output.absolute();need(not root.exists(),"fresh byte-read destination required");root.mkdir(parents=True)
    token=os.environ.pop("GH_TOKEN")
    old,oldmeta=download(root/"original",ORIGINAL,token)
    proof,proofmeta=download(root/"proof",PROOF,token)
    del token
    old_members=unzip(old,old.parent,("evidence.tar.gz","FILES.json","ARCHIVE.json"))
    proof_names=("read_build.py","reader_controls.py","read_retained.py","ORIGINAL_FILES.json","ORIGINAL_ARCHIVE.json",
        "COMPARISON.json","CONTROL_FILES.json","READBACK.json","controls.tar.gz")
    proof_members=unzip(proof,proof.parent,proof_names)
    need(pin(old.parent/"evidence.tar.gz")==TAR and pin(proof.parent/"controls.tar.gz")==CONTROL_TAR,"archive extent/digest differs")
    need((old.parent/"FILES.json").read_bytes()==(proof.parent/"ORIGINAL_FILES.json").read_bytes()
        and (old.parent/"ARCHIVE.json").read_bytes()==(proof.parent/"ORIGINAL_ARCHIVE.json").read_bytes(),"original index custody differs")
    original=table(decode((old.parent/"FILES.json").read_bytes()),9217)
    controls_index=decode((proof.parent/"CONTROL_FILES.json").read_bytes())
    need(controls_index["archive"]==CONTROL_TAR,"control index archive differs")
    controls=table(controls_index,36217)
    original_saved=read_tar(old.parent/"evidence.tar.gz",original,lambda n:n in {
        "capture/source/scripts/read_build.py","capture/source/scripts/reader_controls.py","capture/source/SOURCE_MANIFEST.json"})
    control_saved=read_tar(proof.parent/"controls.tar.gz",controls,lambda n:n=="CONTROLS.json" or n.endswith("/CONTROL.json"))
    need(sum(r["bytes"] for r in original.values())==349821210
        and sum(r["bytes"] for r in controls.values())==711622595,"complete archive totals differ")
    for name,value in PATCHES.items():need(pin(proof.parent/name)==value,"frozen patch source differs")
    before=original_saved["capture/source/scripts/read_build.py"].decode()
    need(before.count("build/typed-params.json")==2 and (proof.parent/"read_build.py").read_text()
        ==before.replace("build/typed-params.json","BUILD.json"),"stale-path patch not exact")
    before=original_saved["capture/source/scripts/reader_controls.py"].decode()
    need((proof.parent/"reader_controls.py").read_text()==before.replace("copy_function=os.link","copy_function=shutil.copy2")
        .replace("else:os.link(incoming,target)","else:shutil.copy2(incoming,target)"),"metadata-preserving clone patch not exact")
    need(hashlib.sha256(original_saved["capture/source/SOURCE_MANIFEST.json"]).hexdigest()
        =="24927588d1125326a9cf8eb4e2279cb4fb4049714311246de851b3b238b239e4","original source differs")
    report=decode((proof.parent/"READBACK.json").read_bytes());comparison=decode((proof.parent/"COMPARISON.json").read_bytes())
    need(report["status"]=="PRIVATE_TEXT_PUBLICATION_RETAINED_READER_V2_PASS"
        and report["native_or_rust_executions"]==0 and report["failure_reclassified"] is False
        and report["semantic_ci_original_conclusion"]=="failure"
        and report["semantic_capture_commit"]=="966bb9eff9d61176700796fd0452429bc9674717"
        and report["original_whole_metadata_and_bytes_unchanged"] is True
        and report["run"]==ORIGINAL["run"] and report["artifact"]==ORIGINAL["id"]
        and report["zip"]=={k:ORIGINAL[k] for k in ("bytes","sha256")} and report["tar"]==TAR,
        "retained reader report identity/scope differs")
    guard=report["guarded"]
    need(guard["status"]=="READONLY_PASS" and guard["before"]==guard["after"]
        and guard["entries"]==len(guard["before"])
        and all(guard[k] is False for k in ("native_executed","rust_executed","evidence_written"))
        and guard["probes"]==[dict(name=n,rejected=True) for n in PROBES],"actual guard proof differs")
    need(len(guard["roots"])==3 and {r["root"] for r in guard["before"]}=={0,1,2},"guard roots differ")
    for number,path in enumerate(guard["roots"]):
        if path.endswith("/retained"):wanted=original
        elif path.endswith("/physical-controls"):wanted=controls
        else:
            need(path.endswith("/qualification/text_publication_body_reader_v2"),"unknown guarded root")
            wanted={n:dict(path=n,mode=0o644,**p) for n,p in PATCHES.items()}
        verify_snapshot(snapshot_table(guard["before"],number),wanted)
    evidence=guard["evidence"];without={k:v for k,v in evidence.items() if k!="physical_controls"}
    need(without==comparison,"comparison and guarded re-read differ")
    need(evidence["status"]=="COMPLETE_PRIVATE_BODY_ORIGINAL_AND_FILES_PASS" and evidence["cases"]==82
        and evidence["physical"]==dict(actions=2144,cases=82,controls=20,native_calls=2863)
        and evidence["original_tests"]==8 and evidence["registry_packages"]==33
        and evidence["all_other_response_and_file_bytes_equal"] is True,"complete semantic evidence differs")
    scope=evidence["scope"]
    need(scope.get("private_publication_body") is True and all(v is False for k,v in scope.items() if k!="private_publication_body")
        and set(scope)=={"private_publication_body","configured_path_authority","async_task_lifecycle",
            "cache_forget_connected","public_route","full_sdk","all_136_handlers","old_stack_removed"},"qualification scope differs")
    verify_controls(controls,original,control_saved,evidence["physical_controls"])
    out=root/"result";out.mkdir()
    result=dict(status="INDEPENDENT_PUBLICATION_BODY_ARCHIVE_READBACK_PASS",original_artifact=ORIGINAL,proof_artifact=PROOF,
        original_tar=TAR,control_tar=CONTROL_TAR,original_files=len(original),original_bytes=sum(r["bytes"] for r in original.values()),
        control_files=len(controls),control_bytes=sum(r["bytes"] for r in controls.values()),snapshot_entries=guard["entries"],
        snapshot_before_after_equal=True,guard_probes=11,physical_refusals=6,complete_comparison=evidence,
        imported_runtime_or_reader=False,native_or_rust_executions=0,original_failure_reclassified=False,
        original_zip_members=old_members,proof_zip_members=proof_members)
    (out/"READBACK.json").write_bytes(encode(result))
    (out/"ORIGINAL_FILES.json").write_bytes((old.parent/"FILES.json").read_bytes())
    (out/"CONTROL_FILES.json").write_bytes((proof.parent/"CONTROL_FILES.json").read_bytes())
    for name in ("COMPARISON.json","READBACK.json"):
        shutil.copyfile(proof.parent/name,out/("RETAINED_"+name))
    shutil.copyfile(Path(__file__),out/"read_archives.py")
    print("INDEPENDENT_READBACK "+json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
