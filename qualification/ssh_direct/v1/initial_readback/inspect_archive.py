#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read every uploaded ZIP/TAR member and emit selected original bytes; never execute captures."""
from pathlib import Path, PurePosixPath
import argparse, base64, hashlib, json, os, stat, tarfile, zipfile
def require(value,message):
    if not value:raise ValueError(message)
def parse(raw):
    def unique(items):
        result={}
        for k,v in items:
            require(k not in result,"duplicate JSON key");result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=unique)
def identity(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def safe(name):
    p=PurePosixPath(name)
    require(not p.is_absolute() and ".." not in p.parts and p.as_posix()==name,"unsafe archive member")
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--archive",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--role",choices=("child","reference-failure"),required=True)
    a=p.parse_args();require(not a.output.exists(),"fresh read output");a.output.mkdir()
    specs={
      "child":dict(bytes=13354334,sha256="9146b5e81b8c73a56d522d221818921f7cc215725805f71856582bc6496fe3fb",
        select=["capture/generated/ssh_original_child.hepta","capture/build/modules/ssh-original-child/manifest.json",
          "capture/build/modules/ssh-original-child/module.image.bin"]),
      "reference-failure":dict(bytes=88819040,sha256="16bbe39f129433aeeda6ed9f3cbbf9be70ffc8e1e0b94ab1a56c459e9537e442",
        select=["capture/processes/build.stderr","capture/processes/build.stdout","capture/processes/build.json",
          "capture/reference/Cargo.lock"])}
    spec=specs[a.role];before=a.archive.stat()
    with a.archive.open("rb") as f:
        require(before.st_size==spec["bytes"] and hashlib.file_digest(f,"sha256").hexdigest()==spec["sha256"],"whole uploaded ZIP identity")
    with zipfile.ZipFile(a.archive) as z:
        members=z.infolist()
        require(len(members)==3 and {m.filename for m in members}=={"ARCHIVE.json","FILES.json","evidence.tar.gz"},"complete outer ZIP members")
        for m in members:
            safe(m.filename);require(not m.is_dir(),"ZIP ordinary files")
        archive=parse(z.read("ARCHIVE.json"));index=parse(z.read("FILES.json"))
        expected=index["files"]+index["directories"];wanted={r["path"]:r for r in expected}
        require(len(wanted)==len(expected),"unique index")
        temp=a.output/"retained.tar.gz"
        h=hashlib.sha256();total=0
        with z.open("evidence.tar.gz") as incoming,temp.open("xb") as outgoing:
            while True:
                b=incoming.read(1<<20)
                if not b:break
                h.update(b);total+=len(b);outgoing.write(b)
        require(dict(bytes=total,sha256=h.hexdigest())==archive["archive"],"whole inner TAR identity")
    seen=set();selected={};logical=0
    with tarfile.open(temp,"r:gz") as t:
        for m in t:
            safe(m.name);require(m.name in wanted and m.name not in seen,"complete TAR member set");seen.add(m.name)
            r=wanted[m.name];require(m.size==r["bytes"] and m.mode==r["mode"],"full member extent/mode")
            exact_time=str(r["mtime_ns"]//1000000000)+"."+f'{r["mtime_ns"]%1000000000:09d}'
            require(m.pax_headers.get("mtime")==exact_time,"full member mtime")
            attrs={k[len("HEPTA.xattr.hex.v1."):]:v for k,v in m.pax_headers.items() if k.startswith("HEPTA.xattr.hex.v1.")}
            require(attrs==r["xattrs"],"full member xattrs")
            if r["kind"]=="dir":
                require(m.isdir() and m.size==0,"ordinary directory");continue
            require(r["kind"]=="file" and m.isfile(),"ordinary file")
            digest=hashlib.sha256();size=0;chunks=[] if m.name in spec["select"] else None
            with t.extractfile(m) as incoming:
                while True:
                    b=incoming.read(1<<20)
                    if not b:break
                    digest.update(b);size+=len(b)
                    if chunks is not None:chunks.append(b)
            require(size==r["bytes"] and digest.hexdigest()==r["sha256"],"whole member bytes: "+m.name)
            logical+=size
            if chunks is not None:
                raw=b"".join(chunks);require(len(raw)<=2<<20,"selected output bounded")
                path=a.output/("selected-"+str(len(selected))+".bin");path.write_bytes(raw)
                selected[m.name]=dict(**identity(raw),file=path.name,base64=base64.b64encode(raw).decode())
    require(seen==set(wanted) and set(selected)==set(spec["select"]),"complete selected and full TAR sets")
    require(logical==archive["logical_bytes"] and len(index["files"])==archive["files"] and len(index["directories"])==archive["directories"],"exact archive receipt counts")
    after=a.archive.stat()
    require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
        (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),"input archive unchanged")
    result=dict(status="COMPLETE_UPLOADED_ARCHIVE_READ_PASS",role=a.role,archive=archive,
        selected={name:{k:v for k,v in row.items() if k!="base64"} for name,row in selected.items()},
        hia_applications=0,rust_applications=0,old_failure_preserved=True)
    (a.output/"READ.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps(result,sort_keys=True))
    for name,row in selected.items():
        print("EXACT_SELECTED_BYTES "+json.dumps(dict(path=name,**row),sort_keys=True))
if __name__=="__main__":main()
