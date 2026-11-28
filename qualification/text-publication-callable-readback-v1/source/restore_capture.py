#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Byte-only restoration of one complete frozen GitHub Actions artifact."""
from pathlib import Path,PurePosixPath
from decimal import Decimal
import hashlib
import os
import shutil
import tarfile
import urllib.request
import urllib.error
import zipfile
from callable_common import decode,encoded,owned,pin,require
ARTIFACT=14301412857
ZIP=dict(bytes=95695225,sha256="4ece18d9770d6d860167d1d363c7a4fd81b2257195a49f2ee1a9cd7f778019d3")
TAR=dict(bytes=94195871,sha256="db6b443d974a19d53b6915a59c238db776eb818411b04ff6854bb9fb447176ee")
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None

def fetch(output):
    require(os.environ.get("GITHUB_ACTIONS")=="true","artifact restore restricted to owned CI")
    root=Path(output);require(not root.exists(),"restore output exists");root.mkdir(parents=True)
    url="https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/"+str(ARTIFACT)+"/zip"
    request=urllib.request.Request(url,headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],
        "Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    try:response=urllib.request.build_opener(NoRedirect).open(request,timeout=60)
    except urllib.error.HTTPError as response:
        require(response.code in (301,302,303,307,308),"artifact endpoint did not redirect")
        location=response.headers["Location"]
    else:raise ValueError("artifact endpoint unexpectedly returned inline content")
    require(location.startswith("https://"),"artifact redirect not HTTPS")
    archive=root/"artifact.zip"
    with urllib.request.urlopen(location,timeout=60) as response,archive.open("xb") as file:
        shutil.copyfileobj(response,file,1<<20)
    require(pin(archive)==ZIP and archive.open("rb").read(4)==b"PK\x03\x04","complete frozen ZIP differs")
    zipped={}
    with zipfile.ZipFile(archive) as stream:
        entries=stream.infolist();require(len(entries)==3 and {r.filename for r in entries}=={"FILES.json","ARCHIVE.json","evidence.tar.gz"},
            "complete ZIP member set differs")
        for item in entries:
            require(not item.is_dir() and not item.flag_bits&1,"ZIP member type/encryption differs")
            target=root/item.filename
            with stream.open(item) as incoming,target.open("xb") as file:shutil.copyfileobj(incoming,file,1<<20)
            require(target.stat().st_size==item.file_size,"whole ZIP member length differs");zipped[item.filename]=pin(target)
    require(pin(root/"evidence.tar.gz")==TAR,"complete retained tar differs")
    index=decode((root/"FILES.json").read_bytes());receipt=decode((root/"ARCHIVE.json").read_bytes())
    wanted={r["path"]:r for r in index["files"]}
    require(len(wanted)==len(index["files"])==6014 and sum(r["bytes"] for r in wanted.values())==352388782,
        "complete retained logical set differs")
    require(receipt==dict(status="COMPLETE_ARCHIVE_BYTES_PASS",files=6014,logical_bytes=352388782,archive=TAR),"retained archive receipt differs")
    destination=root/"extracted";destination.mkdir();seen=set();rows=[]
    with tarfile.open(root/"evidence.tar.gz","r:gz") as stream:
        for member in stream:
            name=PurePosixPath(member.name)
            require(member.isfile() and not name.is_absolute() and ".." not in name.parts and name.as_posix()==member.name
                and member.name in wanted and member.name not in seen,"tar member path/type/set differs")
            seen.add(member.name);expected=wanted[member.name]
            require(member.size==expected["bytes"] and member.mode==expected["mode"]
                and int(Decimal(member.pax_headers["mtime"])*1000000000)==expected["original_mtime_ns"],"complete tar member metadata differs")
            target=destination/member.name;target.parent.mkdir(parents=True,exist_ok=True)
            with stream.extractfile(member) as incoming,target.open("xb") as file:shutil.copyfileobj(incoming,file,1<<20)
            target.chmod(member.mode);os.utime(target,ns=(expected["original_mtime_ns"],expected["original_mtime_ns"]))
            require(pin(target)=={k:expected[k] for k in ("bytes","sha256")},"full logical member bytes differ")
            rows.append(dict(path=member.name,**pin(target),mode=target.stat().st_mode&0o777))
    require(seen==set(wanted) and len(list(destination.rglob("*")))>len(wanted),"tar omitted retained bytes")
    result=dict(status="COMPLETE_FROZEN_ARTIFACT_RESTORED",artifact=ARTIFACT,zip=ZIP,tar=TAR,zip_members=zipped,
        files=rows,logical_bytes=352388782,native_executed=False,rust_executed=False)
    (root/"RESTORE.json").write_bytes(encoded(result));return destination
