#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read all retained failed-gateway archive bytes; execute no captured program."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import shutil
import struct
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ARTIFACT=14308301274
ZIP=dict(bytes=1989315830,sha256="de313d2042984fc611c3b638a83495c0813d01faac0f1e6997d2a4264221c8ed")
TAR=dict(bytes=1984480861,sha256="e713a1972e1357afdea805dedfda2f8a9ebe0d6a3ec60f34b2be59d9e7489c8f")
FILES=16845
LOGICAL=2943583972
def require(value,message):
    if not value:raise ValueError(message)
def encode(value):return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
def pin(path):
    with path.open("rb") as f:return dict(bytes=path.stat().st_size,sha256=hashlib.file_digest(f,"sha256").hexdigest())
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None
def download(destination):
    url="https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/"+str(ARTIFACT)+"/zip"
    request=urllib.request.Request(url,headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],
        "Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    try:response=urllib.request.build_opener(NoRedirect()).open(request,timeout=60)
    except urllib.error.HTTPError as error:
        require(error.code in (301,302,303,307,308),"artifact redirect")
        location=error.headers["Location"]
        require(urllib.parse.urlparse(location).scheme=="https","artifact HTTPS")
        response=urllib.request.urlopen(location,timeout=60)
    with response,destination.open("xb") as out:shutil.copyfileobj(response,out,1<<20)
    require(pin(destination)==ZIP,"entire ZIP identity")
def name_ok(name):
    p=PurePosixPath(name)
    return not p.is_absolute() and ".." not in p.parts and p.as_posix()==name
def extract(output):
    class Arguments:pass
    a=Arguments();a.output=Path(output)
    require(not a.output.exists(),"fresh pure-read destination");a.output.mkdir(parents=True)
    archive=a.output/"artifact.zip";download(archive)
    with zipfile.ZipFile(archive) as z:
        require(len(z.infolist())==3 and set(z.namelist())=={"evidence.tar.gz","FILES.json","ARCHIVE.json"},"exact ZIP set")
        for item in z.infolist():
            require(not item.is_dir() and item.flag_bits&1==0,"ordinary unencrypted ZIP member")
            with z.open(item) as inp,(a.output/item.filename).open("xb") as out:shutil.copyfileobj(inp,out,1<<20)
    require(pin(a.output/"evidence.tar.gz")==TAR,"entire TAR identity")
    index=json.loads((a.output/"FILES.json").read_bytes())
    receipt=json.loads((a.output/"ARCHIVE.json").read_bytes())
    require(receipt["archive"]==TAR,"producer archive pin")
    wanted={r["path"]:r for r in index["files"]}
    require(len(wanted)==len(index["files"])==FILES and sum(r["bytes"] for r in wanted.values())==LOGICAL,"full manifest cardinality")
    require(all(name_ok(n) for n in wanted),"manifest ordinary relative names")
    seen=set()
    selected=a.output/"selected";selected.mkdir()
    with tarfile.open(a.output/"evidence.tar.gz","r|gz") as tar:
        for member in tar:
            require(member.isfile() and member.name in wanted and member.name not in seen,"TAR type/set")
            row=wanted[member.name]
            inspect=member.name.startswith(("capture/profiles/", "recipe-source/")) or member.name=="capture/frozen-graph/DEPENDENCIES.json"
            with tar.extractfile(member) as stream:
                if inspect:
                    value=stream.read();digest=hashlib.sha256(value).hexdigest()
                else:digest=hashlib.file_digest(stream,"sha256").hexdigest()
            require(member.size==row["bytes"] and member.mode==row["mode"] and digest==row["sha256"],"complete TAR bytes/mode: "+member.name)
            seen.add(member.name)
            if not inspect:continue
            dest=selected/member.name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(value);dest.chmod(member.mode)
    require(seen==set(wanted),"complete TAR set")
    report=dict(status="COMPLETE_FAILED_GATEWAY_V3_ARTIFACT_BYTES_PASS",source_commit="0b7c15818c9cbfac1ec710122e62de9a078f74d9",
        artifact=ARTIFACT,run=44037633975,job=133884253395,zip=ZIP,archive=TAR,files=FILES,logical_bytes=LOGICAL,
        executed_hia=False,executed_rust=False)
    # The frozen exporter records ordinary files, so a genuinely empty
    # Writer block directory has no TAR member. Restore only the exact store
    # whose complete snapshot has zero blocks and whose full manifest prefix
    # is absent. No evidence content, reader rule or filesystem observation changes.
    empty=[]
    for profile in ("configured","absent","denied","fence_required","capabilities","body"):
        prefix="capture/profiles/"+profile
        target=selected/prefix/"retired-fixture-buffers"
        if target.exists():continue
        snapshot=selected/prefix/"RETIRED_FIXTURE.json"
        require(snapshot.is_file(),"missing complete retired snapshot")
        retirement=json.loads(snapshot.read_bytes())
        def no_blocks(value):
            if isinstance(value,dict):
                if "blocks" in value:
                    require(set(value)=={"bytes","sha256","blocks"} and value["bytes"]==0
                        and value["blocks"]==[] and value["sha256"]==hashlib.sha256(b"").hexdigest(),
                        "missing retired buffer directory contains required bytes")
                for child in value.values():no_blocks(child)
            elif isinstance(value,list):
                for child in value:no_blocks(child)
        no_blocks(retirement["complete_snapshot"])
        require(not any(name.startswith(prefix+"/retired-fixture-buffers/") for name in wanted),
            "manifest contained missing retired buffer bytes")
        target.mkdir()
        empty.append(dict(path=prefix+"/retired-fixture-buffers",snapshot=pin(snapshot),
            complete_manifest_prefix_files=0,complete_snapshot_blocks=0))
    (a.output/"EMPTY_STORES.json").write_bytes(encode(empty))
    (a.output/"REVIEW.json").write_bytes(encode(report))
    print(json.dumps(report,sort_keys=True),flush=True)
    return selected
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--output",required=True,type=Path)
    extract(p.parse_args().output)
