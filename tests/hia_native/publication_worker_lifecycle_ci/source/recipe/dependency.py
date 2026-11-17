#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Verify every immutable native-build archive byte; materialize only exact needed originals."""
from pathlib import Path,PurePosixPath
import hashlib,os,shutil,sys,tarfile,urllib.error,urllib.parse,urllib.request,zipfile
from common import canonical,decode,pin,require
import archive
PACKAGE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PACKAGE/"worker-source/scripts"))
import read_worker_build
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):return None
def declaration():return decode((PACKAGE/"DEPENDENCY.json").read_bytes())
def selected(name):
    return name in ("recipe-source","capture","capture/native") or name.startswith(("recipe-source/","capture/native/"))
def full_archive(path,extract=None):
    d=declaration();require(pin(path)==d["zip"],"entire frozen build ZIP")
    with zipfile.ZipFile(path) as z:
        require(len(z.namelist())==3 and set(z.namelist())=={"FILES.json","ARCHIVE.json","evidence.tar.gz"}
            and z.testzip() is None,"full build ZIP members/CRC")
        index=decode(z.read("FILES.json"));receipt=decode(z.read("ARCHIVE.json"))
        require(len(index["files"])==d["files"] and len(index["directories"])==d["directories"]
            and sum(r["bytes"] for r in index["files"])==d["logical_bytes"],"complete build archive index")
        with z.open("evidence.tar.gz") as incoming:
            require(dict(bytes=z.getinfo("evidence.tar.gz").file_size,
                sha256=hashlib.file_digest(incoming,"sha256").hexdigest())==d["tar"],"entire frozen build TAR")
        wanted={r["path"]:r for r in index["files"]+index["directories"]};seen=set()
        require(len(wanted)==d["files"]+d["directories"],"unique complete build archive paths")
        with z.open("evidence.tar.gz") as incoming,tarfile.open(fileobj=incoming,mode="r|gz") as stream:
            for member in stream:
                archive.safe(member.name);require(member.name in wanted and member.name not in seen,"exact build archive entry")
                seen.add(member.name);row=wanted[member.name]
                require(member.mode==row["mode"] and member.size==row["bytes"],"complete build extent/mode")
                stamp=str(row["mtime_ns"]//1000000000)+"."+f'{row["mtime_ns"]%1000000000:09d}'
                require(member.pax_headers.get("mtime")==stamp,"complete archived build timestamp")
                attrs={k[len("HEPTA.xattr.hex.v1."):]:v for k,v in member.pax_headers.items() if k.startswith("HEPTA.xattr.hex.v1.")}
                require(attrs==row["xattrs"],"complete archived build xattrs")
                target=extract/member.name if extract is not None and selected(member.name) else None
                if row["kind"]=="dir":
                    require(member.isdir() and member.size==0,"complete build directory")
                    if target is not None:target.mkdir(parents=True,exist_ok=True)
                else:
                    require(row["kind"]=="file" and member.isfile(),"ordinary complete build file")
                    digest=hashlib.sha256();size=0
                    output=None
                    if target is not None:
                        target.parent.mkdir(parents=True,exist_ok=True);output=target.open("xb")
                    try:
                        with stream.extractfile(member) as src:
                            while raw:=src.read(1<<20):
                                digest.update(raw);size+=len(raw)
                                if output is not None:output.write(raw)
                    finally:
                        if output is not None:output.close()
                    require(size==row["bytes"] and digest.hexdigest()==row["sha256"],"every original build byte")
        require(seen==set(wanted),"whole original build archive closure")
    if extract is not None:
        for row in sorted((r for r in wanted.values() if selected(r["path"])),key=lambda r:len(PurePosixPath(r["path"]).parts),reverse=True):
            p=extract/row["path"];p.chmod(row["mode"])
            for key,value in row["xattrs"].items():os.setxattr(p,key,bytes.fromhex(value),follow_symlinks=False)
            os.utime(p,ns=(row["mtime_ns"],row["mtime_ns"]),follow_symlinks=False)
    return index,receipt
def restore(root):
    root=Path(root);require(not root.exists(),"fresh immutable build restoration");root.mkdir(parents=True)
    d=declaration();req=urllib.request.Request("https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/"+str(d["artifact"])+"/zip",
        headers={"Authorization":"Bearer "+os.environ["GH_TOKEN"],"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"})
    try:response=urllib.request.build_opener(NoRedirect()).open(req,timeout=60)
    except urllib.error.HTTPError as error:
        require(error.code in (301,302,303,307,308),"artifact HTTPS redirect")
        location=error.headers["Location"];require(urllib.parse.urlparse(location).scheme=="https","HTTPS artifact")
        response=urllib.request.urlopen(location,timeout=60)
    with response,(root/"artifact.zip").open("xb") as out:shutil.copyfileobj(response,out,1<<20)
    extracted=root/"extracted";extracted.mkdir()
    index,receipt=full_archive(root/"artifact.zip",extracted)
    (root/"FILES.json").write_bytes(canonical(index));(root/"ARCHIVE.json").write_bytes(canonical(receipt))
    result=read(root);(root/"RESTORED.json").write_bytes(canonical(result));return result
def read(root):
    root=Path(root);d=declaration();index,receipt=full_archive(root/"artifact.zip")
    require(decode((root/"FILES.json").read_bytes())==index and decode((root/"ARCHIVE.json").read_bytes())==receipt,"complete archive metadata binding")
    extracted=root/"extracted";wanted={r["path"]:r for r in index["files"]+index["directories"] if selected(r["path"])}
    require({p.relative_to(extracted).as_posix() for p in extracted.rglob("*")}==set(wanted),"exact selected physical closure")
    for name,row in wanted.items():
        p=extracted/name;require(p.stat().st_mode&0o777==row["mode"] and p.stat().st_mtime_ns==row["mtime_ns"]
            and archive.attrs(p)==row["xattrs"],"selected original metadata")
        if row["kind"]=="file":require(pin(p)=={k:row[k] for k in ("bytes","sha256")},"selected original complete file")
    source=extracted/"recipe-source"
    require({p.relative_to(source).as_posix():pin(p) for p in source.rglob("*") if p.is_file()}==
        {p.relative_to(PACKAGE/"worker-source").as_posix():pin(p) for p in (PACKAGE/"worker-source").rglob("*") if p.is_file()},
        "exact qualified worker source package")
    build=read_worker_build.verify(source,extracted/"capture/native")
    require(build["executable"]==d["binary"] and pin(extracted/d["binary_relative"])==d["binary"],"actual built executable")
    result=dict(status="COMPLETE_QUALIFIED_WORKER_BUILD_RESTORED",declaration=d,archive=receipt,build=build,
        selected_entries=len(wanted),all_original_entries_read=True,native_executed=False,rust_executed=False)
    if (root/"RESTORED.json").exists():require(decode((root/"RESTORED.json").read_bytes())==result,"restoration receipt")
    return result
