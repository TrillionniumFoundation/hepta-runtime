# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Exact immutable uploaded-build extraction and complete frozen input bytes."""
from pathlib import Path,PurePosixPath
import hashlib,json,os,stat,struct,tarfile,zipfile
def need(v,m):
    if not v:raise ValueError(m)
def canonical(v):return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode()
def decode(raw):
    def pairs(items):
        v={}
        for k,x in items:need(k not in v,"duplicate evidence key");v[k]=x
        return v
    return json.loads(raw,object_pairs_hook=pairs)
def pin(p):
    p=Path(p)
    with p.open("rb") as f:return dict(bytes=p.stat().st_size,sha256=hashlib.file_digest(f,"sha256").hexdigest())
def raw_pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def stable(p):
    s=Path(p).stat();return (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def safe(name):
    p=PurePosixPath(name);need(type(name)is str and not p.is_absolute() and ".."not in p.parts and p.as_posix()==name,"canonical member");return p
def unpack(path,root,spec):
    path=Path(path);root=Path(root);need(not root.exists(),"fresh expanded build");before=stable(path);need(pin(path)==spec["zip"],"whole uploaded build ZIP")
    root.mkdir(parents=True);tarpath=root/"uploaded.tar.gz"
    with zipfile.ZipFile(path)as z:
        rows=z.infolist();need(len(rows)==3 and {x.filename for x in rows}=={"ARCHIVE.json","FILES.json","evidence.tar.gz"},"complete build ZIP set")
        receipt=decode(z.read("ARCHIVE.json"));index=decode(z.read("FILES.json"))
        need(receipt["archive"]==spec["tar"],"fixed inner build archive")
        with z.open("evidence.tar.gz")as src,tarpath.open("xb")as dst:
            while b:=src.read(1<<20):dst.write(b)
    need(pin(tarpath)==spec["tar"],"complete compressed build bytes")
    allrows=index["files"]+index["directories"];wanted={r["path"]:r for r in allrows}
    need(len(wanted)==len(allrows),"unique complete build index");seen=set();dirs=[];logical=0
    with tarfile.open(tarpath,"r:gz")as t:
        for m in t:
            p=safe(m.name);need(m.name in wanted and m.name not in seen,"complete build TAR member set");seen.add(m.name);r=wanted[m.name]
            need(m.mode==r["mode"]and m.size==r["bytes"],"full build extent/mode")
            ts=str(r["mtime_ns"]//1000000000)+"."+f'{r["mtime_ns"]%1000000000:09d}'
            need(m.pax_headers.get("mtime")==ts,"full build mtime")
            attrs={k[len("HEPTA.xattr.hex.v1."):]:v for k,v in m.pax_headers.items()if k.startswith("HEPTA.xattr.hex.v1.")}
            need(attrs==r["xattrs"],"full build xattrs")
            dst=root/p
            if r["kind"]=="dir":
                need(m.isdir()and m.size==0,"ordinary build directory");dst.mkdir(parents=True,exist_ok=True);dirs.append((dst,r));continue
            need(r["kind"]=="file"and m.isfile(),"ordinary complete build file");dst.parent.mkdir(parents=True,exist_ok=True)
            with t.extractfile(m)as src,dst.open("xb")as out:
                while b:=src.read(1<<20):out.write(b)
            need(pin(dst)=={k:r[k]for k in("bytes","sha256")},"complete expanded build bytes "+m.name);logical+=m.size
            os.chmod(dst,r["mode"]);os.utime(dst,ns=(r["mtime_ns"],r["mtime_ns"]))
            for k,v in attrs.items():os.setxattr(dst,k,bytes.fromhex(v))
    for dst,r in reversed(dirs):
        os.chmod(dst,r["mode"]);os.utime(dst,ns=(r["mtime_ns"],r["mtime_ns"]))
        for k,v in r["xattrs"].items():os.setxattr(dst,k,bytes.fromhex(v))
    need(seen==set(wanted)and logical==receipt["logical_bytes"],"whole build file closure")
    need(len(index["files"])==receipt["files"]and len(dirs)==receipt["directories"],"whole build directory closure")
    for r in allrows:
        p=root/r["path"];s=p.lstat()
        need((stat.S_ISREG(s.st_mode)if r["kind"]=="file"else stat.S_ISDIR(s.st_mode))and stat.S_IMODE(s.st_mode)==r["mode"]
            and s.st_mtime_ns==r["mtime_ns"],"complete installed build metadata")
    need(stable(path)==before,"uploaded source changed; read atime is not a mutation")
    (root/"VERIFIED.json").write_bytes(canonical(dict(status="COMPLETE_BUILD_ARCHIVE_READ_AND_EXTRACT_PASS",zip=spec["zip"],archive=receipt)))
    return root/"capture"
def case_bytes(c):
    header=[int.from_bytes(b"HSSCASE1","little"),c["id"],c["mode"],c["count"],c["deadline_ms"],c["flags"],c["entry"],
        c["input_bytes"],c["stdout_bytes"],c["stderr_bytes"],c["exit"],c["delay_us"],c["behavior"],c["close_input"],0,0]
    data=bytes(((i*73)^(c["id"]*19)^(i>>3))&255 for i in range(c["input_bytes"]))
    return struct.pack("<16Q",*header)+data
def inventories(root):
    rows=[]
    for p in sorted(Path(root).rglob("*")):
        s=p.lstat();need(stat.S_ISREG(s.st_mode)or stat.S_ISDIR(s.st_mode),"ordinary capture member")
        r=dict(path=p.relative_to(root).as_posix(),kind="file"if p.is_file()else"dir",mode=stat.S_IMODE(s.st_mode),mtime_ns=s.st_mtime_ns)
        if p.is_file():r.update(pin(p))
        rows.append(r)
    return rows
