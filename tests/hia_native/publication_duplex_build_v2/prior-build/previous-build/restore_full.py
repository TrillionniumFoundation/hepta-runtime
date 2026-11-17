#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Byte-only download, complete archive verification and optional relocation."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,os,stat,tarfile,urllib.request,zipfile
from async_build_common import require,pin,put
class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        out=super().redirect_request(req,fp,code,msg,headers,newurl)
        if out is not None:out.remove_header("Authorization")
        return out
def download(path,artifact):
    request=urllib.request.Request("https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/"+str(artifact)+"/zip",
        headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],"Accept":"application/vnd.github+json","User-Agent":"publication-complete-byte-reader"})
    with urllib.request.build_opener(Redirect()).open(request,timeout=60) as response,Path(path).open("xb") as out:
        while b:=response.read(1<<20):out.write(b)
def safe(name):
    p=PurePosixPath(name)
    require(name and not p.is_absolute() and ".." not in p.parts and p.as_posix()==name,"archive path")
def restore(output,identity,*,extract=True):
    output=Path(output).absolute();require(not output.exists(),"fresh restore output");output.mkdir(parents=True)
    archive=output/"artifact.zip";download(archive,identity["artifact"])
    require(pin(archive)==identity["zip"],"whole uploaded ZIP identity")
    target=output/"extracted"
    if extract:target.mkdir()
    with zipfile.ZipFile(archive) as z:
        require(set(z.namelist())=={"ARCHIVE.json","FILES.json","evidence.tar.gz"} and len(z.infolist())==3,"complete outer member set")
        require(all(not m.is_dir() and not stat.S_ISLNK(m.external_attr>>16) for m in z.infolist()),"ordinary ZIP members")
        index=json.loads(z.read("FILES.json"));receipt=json.loads(z.read("ARCHIVE.json"))
        expected=identity.get("archive",receipt["archive"])
        require(receipt["archive"]==expected,"archive receipt pin")
        with z.open("evidence.tar.gz") as src,(output/"evidence.tar.gz").open("xb") as dst:
            while b:=src.read(1<<20):dst.write(b)
        require(pin(output/"evidence.tar.gz")==expected,"whole compressed TAR identity")
        rows=index["files"]+index.get("directories",[]);wanted={r["path"]:r for r in rows}
        require(len(wanted)==len(rows),"unique full archive set")
        seen=set();directories=[]
        with tarfile.open(output/"evidence.tar.gz","r:gz") as tar:
            for m in tar:
                safe(m.name);require(m.name in wanted and m.name not in seen,"exact TAR set");seen.add(m.name);r=wanted[m.name]
                require(m.mode==r["mode"] and m.size==r["bytes"],"complete member mode/extent")
                directory=r.get("kind")=="dir"
                require(m.isdir() if directory else m.isfile(),"ordinary TAR member kind")
                ns=r.get("mtime_ns",r.get("original_mtime_ns"))
                if ns is not None:
                    require(m.pax_headers.get("mtime")==str(ns//1000000000)+"."+f"{ns%1000000000:09d}","full member mtime")
                if "xattrs" in r:
                    require({k[len("HEPTA.xattr.hex.v1."):]:v for k,v in m.pax_headers.items() if k.startswith("HEPTA.xattr.hex.v1.")}==r["xattrs"],"full xattr header")
                p=target/m.name
                if directory:
                    if extract:p.mkdir(parents=True,exist_ok=True);directories.append((p,r))
                    continue
                if extract:p.parent.mkdir(parents=True,exist_ok=True)
                h=hashlib.sha256();count=0;out=p.open("xb") if extract else None
                try:
                    with tar.extractfile(m) as src:
                        while b:=src.read(1<<20):
                            h.update(b);count+=len(b)
                            if out is not None:out.write(b)
                finally:
                    if out is not None:out.close()
                require(count==r["bytes"] and h.hexdigest()==r["sha256"],"complete retained bytes: "+m.name)
                if extract:
                    p.chmod(r["mode"])
                    for name,value in r.get("xattrs",{}).items():os.setxattr(p,name,bytes.fromhex(value),follow_symlinks=False)
                    if ns is not None:os.utime(p,ns=(ns,ns))
        require(seen==set(wanted),"complete retained set")
        if extract:
            for p,r in sorted(directories,key=lambda x:len(x[0].parts),reverse=True):
                p.chmod(r["mode"])
                for name,value in r.get("xattrs",{}).items():os.setxattr(p,name,bytes.fromhex(value),follow_symlinks=False)
                if "mtime_ns" in r:os.utime(p,ns=(r["mtime_ns"],r["mtime_ns"]))
        require(receipt["files"]==len(index["files"]) and receipt["logical_bytes"]==sum(r["bytes"] for r in index["files"]),"archive complete declared quantities")
        if "directories" in receipt:require(receipt["directories"]==len(index["directories"]),"archive directory quantity")
        for name in ("ARCHIVE.json","FILES.json"):(output/name).write_bytes(z.read(name))
    report=dict(status="COMPLETE_UPLOADED_ARCHIVE_READ_PASS",artifact=identity["artifact"],zip=identity["zip"],archive=expected,
        files=len(index["files"]),directories=len(index.get("directories",[])),logical_bytes=sum(r["bytes"] for r in index["files"]),
        extracted=extract,native_or_rust_executed=False)
    put(output/"READ.json",report);return target,report
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);p.add_argument("--identity",type=Path,required=True)
    p.add_argument("--no-extract",action="store_true");a=p.parse_args()
    _,r=restore(a.output,json.loads(a.identity.read_bytes()),extract=not a.no_extract);print(json.dumps(r,sort_keys=True),flush=True)
if __name__=="__main__":main()
