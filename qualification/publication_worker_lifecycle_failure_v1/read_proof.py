#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read complete already-uploaded proof bytes; no HIA/Rust/application invocation."""
from pathlib import Path
import argparse,hashlib,io,json,os,tarfile,urllib.error,urllib.parse,urllib.request,zipfile
def require(v,m):
    if not v:raise ValueError(m)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def unique(items):
    d={}
    for k,v in items:require(k not in d,"duplicate JSON key");d[k]=v
    return d
def decode(raw):return json.loads(raw,object_pairs_hook=unique)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    require(not a.output.exists(),"fresh proof read directory");a.output.mkdir(parents=True)
    req=urllib.request.Request("https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/14328073348/zip",
        headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    try:incoming=urllib.request.build_opener(NoRedirect()).open(req,timeout=60)
    except urllib.error.HTTPError as e:
        require(e.code in (301,302,303,307,308),"artifact redirect")
        url=e.headers["Location"];require(urllib.parse.urlparse(url).scheme=="https","HTTPS artifact")
        incoming=urllib.request.urlopen(url,timeout=60)
    with incoming:raw=incoming.read()
    require(pin(raw)==dict(bytes=121129607,sha256="842d8387f884605025a50702434c62e5402ce7e4bf8ffa91457f5b572947c57d"),"full immutable proof ZIP")
    (a.output/"proof.zip").write_bytes(raw)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        require(len(z.namelist())==3 and set(z.namelist())=={"FILES.json","ARCHIVE.json","evidence.tar.gz"} and z.testzip() is None,"complete proof ZIP set")
        data={name:z.read(name) for name in z.namelist()}
    require(pin(data["evidence.tar.gz"])==dict(bytes=120777655,sha256="9ce226edad763161f106b4157ec36583a32e4de7a60579fbb1d59dc2ad5515f3"),"full proof TAR")
    index=decode(data["FILES.json"]);rows=index["files"]+index["directories"]
    wanted={r["path"]:r for r in rows};seen=set();contents={}
    require(len(wanted)==len(rows) and len(index["files"])==1292 and len(index["directories"])==75,"complete proof archive index")
    with tarfile.open(fileobj=io.BytesIO(data["evidence.tar.gz"]),mode="r:gz") as stream:
        for member in stream:
            require(member.name in wanted and member.name not in seen,"exact proof archive member")
            seen.add(member.name);row=wanted[member.name]
            require(member.mode==row["mode"] and member.size==row["bytes"],"proof archive physical extent/mode")
            require(member.pax_headers.get("mtime")==str(row["mtime_ns"]//1000000000)+"."+f'{row["mtime_ns"]%1000000000:09d}',"proof exact mtime")
            require({k[len("HEPTA.xattr.hex.v1."):]:v for k,v in member.pax_headers.items() if k.startswith("HEPTA.xattr.hex.v1.")}==row["xattrs"],"proof complete xattrs")
            if row["kind"]=="file":
                require(member.isfile(),"proof regular member")
                value=stream.extractfile(member).read();require(pin(value)=={k:row[k] for k in ("bytes","sha256")},"proof whole bytes")
                contents[member.name]=value
            else:require(row["kind"]=="dir" and member.isdir() and member.size==0,"proof directory member")
    require(seen==set(wanted),"complete proof archive set")
    source=decode(contents["recipe-source/SOURCE_MANIFEST.json"])
    require(pin(contents["recipe-source/SOURCE_MANIFEST.json"])==dict(bytes=14480,sha256="241660f63f225f6b90ee7f8aab830f4e8b019eb6bf6bc6c3019f8df2927d3b5d"),"exact qualified domain source manifest")
    for row in source["files"]:
        value=contents["recipe-source/"+row["path"]]
        require(pin(value)=={k:row[k] for k in ("bytes","sha256")} and hashlib.sha1(b"blob "+str(len(value)).encode()+b"\0"+value).hexdigest()==row["git_blob"],"full qualified source identity")
    diagnostics={}
    for name,value in contents.items():
        if name in ("driver.stdout","driver.stderr","capture/capture.stdout","capture/capture.stderr") or (name.startswith("capture/native/") and name.endswith((".json",".jsonl",".stderr")) and len(value)<65536):
            diagnostics[name]=dict(pin=pin(value),text=value.decode("utf-8","replace"))
    report=dict(status="FAILED_LIFECYCLE_COMPLETE_ARCHIVE_READ_PASS",
        source_head="4b96ee6d51918ebee3b920d256e3f4dcd5853aeb",run=44083526245,artifact=14328073348,
        zip=pin(raw),tar=pin(data["evidence.tar.gz"]),files=len(index["files"]),directories=len(index["directories"]),
        logical_bytes=sum(r["bytes"] for r in index["files"]),diagnostics=diagnostics,
        native_paths=[r["path"] for r in index["files"] if r["path"].startswith("capture/native/")],
        hia_executed=False,rust_executed=False,application_executed=False,failed_semantics_not_upgraded=True)
    (a.output/"FULL_READ.json").write_text(json.dumps(report,ensure_ascii=False,sort_keys=True,separators=(",",":"))+"\n")
    print(json.dumps(report,ensure_ascii=False,sort_keys=True))
if __name__=="__main__":main()
