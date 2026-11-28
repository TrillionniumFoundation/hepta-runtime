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

ARTIFACT=14306501241
ZIP=dict(bytes=1570118667,sha256="0dc3c45c22992669e6db7c06f8426e272bee7d959ad4146e38e0f016ae47fa0b")
TAR=dict(bytes=1567009954,sha256="de8bf5f2265d6c65e836782e1db5594a4f71f7db89c89849a4f2749a8c913b97")
FILES=11243
LOGICAL=2152786745
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
def trace_summary(raw):
    if not raw:return dict(bytes=0,records=0,sha256=hashlib.sha256(raw).hexdigest())
    if len(raw)%224 or any(raw[i:i+8]!=b"HRGTR002" for i in range(0,len(raw),224)):
        return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
            is_fixed_trace=False,prefix_hex=raw[:128].hex(),text_prefix=raw[:512].decode(errors="replace"))
    def row(at):
        words=struct.unpack_from("<28Q",raw,at)
        return dict(offset=at,sequence=words[1],slot=words[2],event=words[3],return_u64=words[4],
            work_capacity=words[5],output_capacity=words[6],phase=words[7],
            continuation_sequence=words[8],extent=words[9],action_hex=raw[at+80:at+192].hex(),
            output_header_hex=raw[at+192:at+224].hex())
    counts={}
    for at in range(0,len(raw),224):
        words=struct.unpack_from("<28Q",raw,at)
        require(words[2]<68 and words[3] in (1,2,3,4),"fixed trace admitted slot/event")
        key=str(words[2])+":"+str(words[3]);counts[key]=counts.get(key,0)+1
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),is_fixed_trace=True,
        records=len(raw)//224,counts=counts,tail=[row(at) for at in range(max(0,len(raw)-32*224),len(raw),224)])
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",required=True,type=Path);a=p.parse_args()
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
    seen=set();diagnosis=[]
    selected=a.output/"selected";selected.mkdir()
    with tarfile.open(a.output/"evidence.tar.gz","r|gz") as tar:
        for member in tar:
            require(member.isfile() and member.name in wanted and member.name not in seen,"TAR type/set")
            row=wanted[member.name]
            inspect=member.name.startswith("capture/profiles/") and member.name.endswith(("/PROCESS.json","/CAPTURE.json","/stderr","/records.jsonl"))
            with tar.extractfile(member) as stream:
                if inspect:
                    value=stream.read();digest=hashlib.sha256(value).hexdigest()
                else:digest=hashlib.file_digest(stream,"sha256").hexdigest()
            require(member.size==row["bytes"] and member.mode==row["mode"] and digest==row["sha256"],"complete TAR bytes/mode: "+member.name)
            seen.add(member.name)
            if not inspect:continue
            dest=selected/member.name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(value)
            if member.name.endswith("/stderr"):
                diagnosis.append(dict(path=member.name,trace=trace_summary(value)))
            elif member.name.endswith(("/PROCESS.json","/CAPTURE.json")):
                item=json.loads(value)
                if member.name.endswith("/CAPTURE.json"):
                    item={k:v for k,v in item.items() if k not in ("source_dependencies","complete_buffers","roles")}
                diagnosis.append(dict(path=member.name,value=item))
            else:
                rows=[json.loads(line) for line in value.splitlines()]
                diagnosis.append(dict(path=member.name,rows=len(rows),
                    first_input=rows[0]["input"] if rows else None,last_input=rows[-1]["input"] if rows else None))
    require(seen==set(wanted),"complete TAR set")
    report=dict(status="COMPLETE_FAILED_GATEWAY_V2_ARTIFACT_BYTES_PASS",source_commit="59ec3228ffa1207916957569b1f78445f2376c28",
        artifact=ARTIFACT,run=44033499631,job=133870746092,zip=ZIP,archive=TAR,files=FILES,logical_bytes=LOGICAL,
        executed_hia=False,executed_rust=False)
    (a.output/"REVIEW.json").write_bytes(encode(report))
    (a.output/"DIAGNOSTIC.json").write_bytes(encode(diagnosis))
    print("GATEWAY_FAILURE_V2_DIAGNOSTIC="+json.dumps(diagnosis,sort_keys=True))
    print(json.dumps(report,sort_keys=True))
if __name__=="__main__":main()
