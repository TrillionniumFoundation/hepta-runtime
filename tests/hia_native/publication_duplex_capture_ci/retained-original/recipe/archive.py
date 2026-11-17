#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Export full ordinary evidence, including empty directories and metadata."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,os,stat,sys,tarfile
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require

def safe(name):
    p=PurePosixPath(name)
    require(not p.is_absolute() and ".." not in p.parts and p.as_posix()==name,"exact archive path")
    return p

def attrs(path):
    return {n:os.getxattr(path,n,follow_symlinks=False).hex()
        for n in sorted(os.listxattr(path,follow_symlinks=False))}

def stable(info):
    return (info.st_dev,info.st_ino,info.st_size,info.st_mode,info.st_uid,
        info.st_gid,info.st_nlink,info.st_mtime_ns,info.st_ctime_ns)

def verify(archive,index):
    require(index["schema"]=="hepta.runtime.publisher.async.archive.v1","archive schema")
    rows=index["files"]+index["directories"];wanted={r["path"]:r for r in rows}
    require(len(wanted)==len(rows),"duplicate archive index")
    seen=set()
    with tarfile.open(archive,"r:gz") as stream:
        for member in stream:
            safe(member.name)
            require(member.name in wanted and member.name not in seen,"complete archive member set")
            seen.add(member.name);row=wanted[member.name]
            require(member.mode==row["mode"] and member.size==row["bytes"],"archive mode/extent")
            exact_time=str(row["mtime_ns"]//1000000000)+"."+f'{row["mtime_ns"]%1000000000:09d}'
            require(member.pax_headers.get("mtime")==exact_time,"archive complete mtime")
            xattrs={key[len("HEPTA.xattr.hex.v1."):]:value for key,value in member.pax_headers.items() if key.startswith("HEPTA.xattr.hex.v1.")}
            require(xattrs==row["xattrs"],"archive complete xattrs")
            if row["kind"]=="file":
                require(member.isfile(),"archive regular file type")
                with stream.extractfile(member) as incoming:
                    require(hashlib.file_digest(incoming,"sha256").hexdigest()==row["sha256"],"archive full file bytes")
            else:
                require(row["kind"]=="dir" and member.isdir() and member.size==0,"archive directory type")
    require(seen==set(wanted),"complete archive file/directory closure")
    return dict(status="COMPLETE_ARCHIVE_BYTES_AND_DIRECTORIES_PASS",
        files=len(index["files"]),directories=len(index["directories"]),
        logical_bytes=sum(r["bytes"] for r in index["files"]),archive=pin(archive))

def pack(source,capture,output,driver_prefix):
    source=Path(source).resolve(strict=True);capture=Path(capture).absolute();output=Path(output).absolute()
    require(not output.exists(),"fresh archive output");output.mkdir(parents=True)
    roots=[("recipe-source",source)]
    if capture.exists():roots.append(("capture",capture))
    items=[]
    for prefix,root in roots:
        for path in [root,*sorted(root.rglob("*"))]:
            info=path.lstat()
            require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),"ordinary retained evidence only")
            name=prefix if path==root else prefix+"/"+path.relative_to(root).as_posix()
            items.append((name,path))
    proof=capture.parent/(capture.name+"-readonly.json")
    if proof.exists():items.append(("capture-readonly.json",proof))
    for suffix in ("stdout","stderr"):
        path=Path(str(driver_prefix)+"."+suffix)
        if path.exists():items.append(("driver."+suffix,path))
    require(len({n for n,p in items})==len(items),"unique export paths")
    files=[];directories=[];target=output/"evidence.tar.gz"
    with tarfile.open(target,"w:gz",compresslevel=1,format=tarfile.PAX_FORMAT,dereference=False) as stream:
        for name,path in sorted(items):
            safe(name);before=path.lstat()
            kind="file" if stat.S_ISREG(before.st_mode) else "dir"
            row=dict(path=name,kind=kind,mode=before.st_mode&0o777,mtime_ns=before.st_mtime_ns,xattrs=attrs(path),
                bytes=before.st_size if kind=="file" else 0)
            if kind=="file":row["sha256"]=pin(path)["sha256"]
            header=tarfile.TarInfo(name)
            header.type=tarfile.REGTYPE if kind=="file" else tarfile.DIRTYPE
            header.size=row["bytes"];header.mode=row["mode"];header.uid=header.gid=0
            header.mtime=row["mtime_ns"]//1000000000
            header.pax_headers={"mtime":str(header.mtime)+"."+f'{row["mtime_ns"]%1000000000:09d}'}
            header.pax_headers.update({"HEPTA.xattr.hex.v1."+key:value for key,value in row["xattrs"].items()})
            if kind=="file":
                with path.open("rb") as incoming:stream.addfile(header,incoming)
                require(pin(path)=={key:row[key] for key in ("bytes","sha256")},"export input changed bytes")
                files.append(row)
            else:stream.addfile(header);directories.append(row)
            require(stable(before)==stable(path.lstat()) and attrs(path)==row["xattrs"],"export input changed metadata")
    index=dict(schema="hepta.runtime.publisher.async.archive.v1",files=files,directories=directories,
        captured_failure_or_success=True,empty_directories_retained=True,hardlinks_exported_as_complete_files=True)
    (output/"FILES.json").write_bytes(canonical(index))
    result=verify(target,index);(output/"ARCHIVE.json").write_bytes(canonical(result))
    print(json.dumps(result,sort_keys=True))

def main():
    p=argparse.ArgumentParser();p.add_argument("mode",choices=("pack","verify"))
    p.add_argument("--source",type=Path);p.add_argument("--capture",type=Path)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--driver-prefix",type=Path)
    a=p.parse_args()
    if a.mode=="pack":pack(a.source,a.capture,a.output,a.driver_prefix)
    else:
        value=verify(a.output/"evidence.tar.gz",decode((a.output/"FILES.json").read_bytes()))
        require(value==decode((a.output/"ARCHIVE.json").read_bytes()),"complete archive receipt")
        print(json.dumps(value,sort_keys=True))
if __name__=="__main__":main()
