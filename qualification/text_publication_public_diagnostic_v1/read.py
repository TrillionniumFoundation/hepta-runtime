#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read complete frozen public artifacts and retained diagnostics; execute no implementation."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,io,json,os,tarfile,urllib.request,urllib.error,zipfile
def need(v,m):
    if not v:raise ValueError(m)
def sha(v):return hashlib.sha256(v).hexdigest()
def encode(v):return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
def fetch(artifact):
    q=urllib.request.Request("https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/"+str(artifact)+"/zip",
        headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],"Accept":"application/vnd.github+json"})
    try:r=urllib.request.build_opener(NoRedirect()).open(q,timeout=60)
    except urllib.error.HTTPError as error:
        need(error.code in (301,302,303,307,308),"artifact redirect")
        target=error.headers["Location"];need(target.startswith("https://"),"artifact HTTPS")
        r=urllib.request.urlopen(target,timeout=60)
    with r:return r.read()
def read(item,out):
    raw=fetch(item["artifact"])
    need(dict(bytes=len(raw),sha256=sha(raw))==item["zip"],"complete artifact ZIP identity")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        need(len(z.namelist())==3 and set(z.namelist())=={"evidence.tar.gz","FILES.json","ARCHIVE.json"} and z.testzip() is None,"ZIP inventory")
        data={name:z.read(name) for name in z.namelist()}
    index=json.loads(data["FILES.json"]);archive=json.loads(data["ARCHIVE.json"])
    need(dict(bytes=len(data["evidence.tar.gz"]),sha256=sha(data["evidence.tar.gz"]))==archive["archive"],"complete TAR identity")
    wanted={r["path"]:r for r in index["files"]};need(len(wanted)==len(index["files"]),"unique full member set")
    seen=set();selected={}
    with tarfile.open(fileobj=io.BytesIO(data["evidence.tar.gz"]),mode="r:gz") as tar:
        for member in tar:
            name=PurePosixPath(member.name)
            need(member.isfile() and member.name in wanted and member.name not in seen
                and not name.is_absolute() and ".." not in name.parts,"member path/type/set")
            row=wanted[member.name]
            with tar.extractfile(member) as stream:
                if member.name in ("driver.stderr","driver.stdout","capture/CAPTURE.json","capture-result.json",
                    "capture/native/PROCESS.json","capture/original/PROCESS.json"):
                    content=stream.read();selected[member.name]=content;digest=sha(content)
                else:digest=hashlib.file_digest(stream,"sha256").hexdigest()
            need(member.size==row["bytes"] and member.mode==row["mode"] and digest==row["sha256"],"complete member bytes/mode")
            seen.add(member.name)
    need(seen==set(wanted) and len(wanted)==archive["files"]
        and sum(x["bytes"] for x in wanted.values())==archive["logical_bytes"],"complete archive coverage")
    here=out/str(item["artifact"]);here.mkdir()
    for name in ("FILES.json","ARCHIVE.json"):(here/name).write_bytes(data[name])
    for name,content in selected.items():
        (here/name.replace("/","--")).write_bytes(content)
        if name=="driver.stderr":
            print(json.dumps(dict(artifact=item["artifact"],name=item["name"],selected=name,
                bytes=len(content),sha256=sha(content),text=content.decode()),sort_keys=True),flush=True)
    result=dict(status="COMPLETE_UPLOADED_PUBLIC_ARTIFACT_READ_PASS",input=item,archive=archive,
        selected={name:dict(bytes=len(v),sha256=sha(v)) for name,v in selected.items()},hia_executed=False,rust_executed=False)
    (here/"READ.json").write_bytes(encode(result))
    return result
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    need(not a.output.exists(),"fresh pure-read output");a.output.mkdir(parents=True)
    rows=json.loads((Path(__file__).with_name("INPUTS.json")).read_bytes())
    results=[read(r,a.output) for r in rows]
    (a.output/"RESULT.json").write_bytes(encode(dict(status="COMPLETE_READ_PASS",results=results)))
if __name__=="__main__":main()
