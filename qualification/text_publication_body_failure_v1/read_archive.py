#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Recover every byte of one fixed failed artifact, without native or Rust execution."""
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

def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    root=a.output.absolute();need(not root.exists(),"fresh output required");root.mkdir(parents=True)
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
    with urllib.request.urlopen(urllib.request.Request(location),timeout=60) as incoming,archive.open("xb") as f:
        shutil.copyfileobj(incoming,f,1024*1024)
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
    proof=root/"proof";proof.mkdir();seen=set();selected=[];sources={}
    with tarfile.open(root/"evidence.tar.gz","r:gz") as tar:
        for m in tar:
            p=PurePosixPath(m.name)
            need(m.isfile() and not p.is_absolute() and ".." not in p.parts and p.as_posix()==m.name
                and m.name in wanted and m.name not in seen,"TAR member invalid")
            seen.add(m.name);row=wanted[m.name]
            need(m.size==row["bytes"] and m.mode==row["mode"],"member size/mode changed")
            s=tar.extractfile(m);digest=hashlib.sha256();chunks=[]
            keep=(m.name=="driver.stderr" or m.name.startswith("capture/processes/") and m.name.endswith((".stderr",".json"))
                or m.name in ("capture/BUILD.json","capture/native/FAILURE.json","capture/original/FAILURE.json",
                    "capture/generated/text_file_publication.hepta","capture/generated/text_file_publication_composition.json"))
            while True:
                chunk=s.read(1024*1024)
                if not chunk:break
                digest.update(chunk)
                if keep:chunks.append(chunk)
            need(digest.hexdigest()==row["sha256"],"complete member bytes differ")
            if keep:
                raw=b"".join(chunks);target=proof/m.name;target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(raw);target.chmod(m.mode)
                selected.append(dict(path=m.name,**pin(target)))
                if m.name.endswith((".stderr",".json")):print("SELECTED "+json.dumps(dict(path=m.name,text=raw.decode()),sort_keys=True))
                if m.name.endswith("text_file_publication.hepta"):sources[m.name]=raw.decode()
    need(seen==set(wanted),"TAR member omitted")
    report=dict(status="COMPLETE_FAILED_ARCHIVE_BYTES_PASS",run=RUN,artifact=ARTIFACT,zip=ZIP_PIN,tar=TAR_PIN,
        files=len(seen),logical_bytes=sum(r["bytes"] for r in wanted.values()),selected=selected,
        native_or_rust_executed=False,failure_reclassified=False)
    for name in ("FILES.json","ARCHIVE.json"):shutil.copyfile(root/name,proof/name)
    (proof/"READBACK.json").write_bytes(encoded(report))
    for path,text in sources.items():print("GENERATED_SOURCE "+json.dumps(dict(path=path,text=text),sort_keys=True))
    print("READBACK "+json.dumps(report,sort_keys=True))

if __name__=="__main__":main()
