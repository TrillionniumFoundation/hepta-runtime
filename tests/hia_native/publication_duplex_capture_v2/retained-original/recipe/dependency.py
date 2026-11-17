#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Restore complete immutable CI bytes without rerunning a compiler or application."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,os,shutil,sys,tarfile,urllib.request,urllib.error,urllib.parse,zipfile
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require
PACKAGE=Path(__file__).resolve().parents[1]

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None

def declaration():
    return decode((PACKAGE/"DEPENDENCY.json").read_bytes())

def safe(name):
    p=PurePosixPath(name)
    require(not p.is_absolute() and ".." not in p.parts and p.as_posix()==name,"archive path")
    return p

def restore(output,zip_input=None):
    output=Path(output).absolute();output.mkdir(parents=True,exist_ok=False)
    d=declaration();archive=output/"reference.zip"
    if zip_input is None:
        token=os.environ["GITHUB_TOKEN"]
        req=urllib.request.Request("https://api.github.com/repos/"+d["repository"]+
            "/actions/artifacts/"+str(d["artifact_id"])+"/zip",
            headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
                "X-GitHub-Api-Version":"2022-11-28"})
        try:response=urllib.request.build_opener(NoRedirect()).open(req,timeout=60)
        except urllib.error.HTTPError as error:
            require(error.code in (301,302,303,307,308),"artifact redirect")
            location=error.headers["Location"]
            require(urllib.parse.urlparse(location).scheme=="https","artifact requires HTTPS")
            response=urllib.request.urlopen(location,timeout=60)
        with response,archive.open("xb") as dest:shutil.copyfileobj(response,dest,1<<20)
    else:
        with Path(zip_input).open("rb") as source,archive.open("xb") as dest:shutil.copyfileobj(source,dest,1<<20)
    require(pin(archive)==d["zip"],"full reference ZIP identity")
    outer=output/"outer";outer.mkdir()
    with zipfile.ZipFile(archive) as z:
        require(set(z.namelist())=={"FILES.json","ARCHIVE.json","evidence.tar.gz"},"reference ZIP member set")
        for member in z.infolist():
            require(not member.is_dir(),"reference ZIP entry type")
            safe(member.filename)
            with z.open(member) as source,(outer/member.filename).open("xb") as dest:
                shutil.copyfileobj(source,dest,1<<20)
        require(z.testzip() is None,"reference ZIP CRC")
    require(pin(outer/"evidence.tar.gz")==d["tar"],"full reference TAR identity")
    index=decode((outer/"FILES.json").read_bytes())
    wanted={r["path"]:r for r in index["files"]}
    require(len(wanted)==len(index["files"])==d["files"],"complete reference member count")
    require(sum(r["bytes"] for r in wanted.values())==d["logical_bytes"],"complete logical extent")
    root=output/"extracted";root.mkdir();seen=set()
    with tarfile.open(outer/"evidence.tar.gz","r|gz") as stream:
        for member in stream:
            require(member.isfile() and member.name in wanted and member.name not in seen,"reference TAR member admission")
            safe(member.name);seen.add(member.name)
            row=wanted[member.name]
            require(member.size==row["bytes"] and member.mode==row["mode"],"reference TAR mode/extent")
            path=root/member.name;path.parent.mkdir(parents=True,exist_ok=True)
            with stream.extractfile(member) as source,path.open("xb") as dest:
                shutil.copyfileobj(source,dest,1<<20)
            path.chmod(row["mode"])
            os.utime(path,ns=(row["original_mtime_ns"],row["original_mtime_ns"]))
            require(pin(path)=={k:row[k] for k in ("bytes","sha256")},"complete restored member bytes")
    require(seen==set(wanted),"complete reference TAR closure")
    require(pin(root/d["binary_relative"])==d["binary"],"restored original executable")
    result=dict(status="COMPLETE_IMMUTABLE_REFERENCE_RESTORED",declaration=d,
        files=len(seen),logical_bytes=d["logical_bytes"],compiler_executed=False,application_executed=False)
    (output/"RESTORED.json").write_bytes(canonical(result))
    print(json.dumps(result,sort_keys=True))
    return result

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True)
    p.add_argument("--zip",type=Path);a=p.parse_args();restore(a.output,a.zip)
