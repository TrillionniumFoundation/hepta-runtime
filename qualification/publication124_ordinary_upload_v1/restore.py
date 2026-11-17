#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Restore a whole fixed ordinary archive, including its exact directory index."""
from pathlib import Path,PurePosixPath
import hashlib,os,stat,tarfile,zipfile
from common import canonical,decode,pin,require
from dependencies import download

def safe(name):
    p=PurePosixPath(name)
    require(type(name) is str and name and not p.is_absolute() and ".." not in p.parts
        and p.as_posix()==name and name!=".","canonical archive path")
    return p

def restore(item,out):
    out=Path(out);require(not out.exists(),"fresh whole archive destination");out.mkdir(parents=True)
    download(item,out/"artifact.zip")
    with zipfile.ZipFile(out/"artifact.zip") as z:
        require(len(z.infolist())==3 and set(z.namelist())=={"FILES.json","ARCHIVE.json","evidence.tar.gz"}
            and all(not m.is_dir() and not stat.S_ISLNK(m.external_attr>>16) for m in z.infolist())
            and z.testzip() is None,"complete ordinary outer ZIP")
        for name in z.namelist():
            with z.open(name) as src,(out/name).open("xb") as dst:
                while block:=src.read(1<<20):dst.write(block)
    index=decode((out/"FILES.json").read_bytes());receipt=decode((out/"ARCHIVE.json").read_bytes())
    require(index["schema"]=="hepta.runtime.text-publisher.archive.v2"
        and index["captured_failure_or_success"] is True
        and index["ordinary_hardlinks_exported_as_complete_files"] is True,"exact ordinary archive format")
    require(pin(out/"evidence.tar.gz")==item["archive"]==receipt["archive"]
        and receipt["status"]=="COMPLETE_ARCHIVE_BYTES_PASS"
        and receipt["files"]==item["files"] and receipt["logical_bytes"]==item["logical_bytes"],
        "complete uploaded archive receipt")
    files=index["files"];dirs=index["directories"];wanted={r["path"]:r for r in files}
    require(len(wanted)==len(files)==item["files"] and len({r["path"] for r in dirs})==len(dirs)
        and not set(wanted)&{r["path"] for r in dirs},"whole distinct file and directory sets")
    root=out/"extracted";root.mkdir()
    for row in sorted(dirs,key=lambda r:(len(safe(r["path"]).parts),r["path"])):
        name=safe(row["path"]);require(type(row["mode"]) is int and 0<=row["mode"]<=0o777,"directory mode")
        p=root/name;require(p.parent==root or p.parent.is_dir(),"directory parent index")
        p.mkdir()
    seen=set()
    with tarfile.open(out/"evidence.tar.gz","r:gz") as tar:
        for member in tar:
            name=safe(member.name)
            require(member.isfile() and member.name in wanted and member.name not in seen,
                "whole ordinary TAR file type and set")
            row=wanted[member.name];seen.add(member.name)
            require(member.size==row["bytes"] and member.mode==row["mode"],"complete TAR extent and mode")
            ns=row["original_mtime_ns"]
            require(type(ns) is int and member.pax_headers.get("mtime")==
                str(ns//1000000000)+"."+f"{ns%1000000000:09d}","complete original file mtime header")
            p=root/name;require(p.parent.is_dir(),"complete file parent directory index")
            digest=hashlib.sha256();count=0
            with tar.extractfile(member) as src,p.open("xb") as dst:
                while block:=src.read(1<<20):dst.write(block);digest.update(block);count+=len(block)
            require(count==row["bytes"] and digest.hexdigest()==row["sha256"],"every uploaded file byte")
            p.chmod(row["mode"]);os.utime(p,ns=(ns,ns))
    require(seen==set(wanted) and sum(r["bytes"] for r in files)==item["logical_bytes"],
        "no omitted uploaded byte")
    require({p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_dir()}=={r["path"] for r in dirs}
        and {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}==set(wanted),
        "complete actual restored member sets")
    for row in sorted(dirs,key=lambda r:len(PurePosixPath(r["path"]).parts),reverse=True):
        (root/row["path"]).chmod(row["mode"])
    result=dict(status="COMPLETE_UPLOADED_ORDINARY_ARCHIVE_PASS",artifact=item["artifact"],zip=item["zip"],
        archive=item["archive"],files=len(files),directories=len(dirs),logical_bytes=item["logical_bytes"],
        whole_file_bytes_modes_mtime=True,application_executions=0)
    (out/"READ.json").write_bytes(canonical(result));return root,result
