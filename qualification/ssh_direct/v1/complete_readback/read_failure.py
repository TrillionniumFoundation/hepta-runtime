#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read the complete immutable installed-3289 failure ZIP/TAR; execute nothing retained."""
from pathlib import Path, PurePosixPath
import argparse, base64, hashlib, json, stat, tarfile, zipfile

EXPECTED={"bytes":1305964335,"sha256":"fcbf2e416deafa7a699594c6ff08b2573cae7553d61e56bfe4fdbc4369795867"}
def require(value,message):
    if not value:raise ValueError(message)
def decode(raw):
    def unique(rows):
        result={}
        for k,v in rows:
            require(k not in result,"duplicate JSON key");result[k]=v
        return result
    return json.loads(raw,object_pairs_hook=unique)
def encode(v):return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True)+"\n").encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def metadata(p):
    s=p.stat();return dict(dev=s.st_dev,ino=s.st_ino,mode=s.st_mode,nlink=s.st_nlink,
        bytes=s.st_size,mtime_ns=s.st_mtime_ns,ctime_ns=s.st_ctime_ns)
def path_name(name,tar=False):
    if tar and name in (".","./"):return "."
    n=name[2:] if tar and name.startswith("./") else name
    p=PurePosixPath(n)
    require(not p.is_absolute() and ".." not in p.parts and p.as_posix()==n.rstrip("/"),"unsafe/noncanonical member")
    return n.rstrip("/")
class HashReader:
    def __init__(self,source):self.source=source;self.h=hashlib.sha256();self.n=0
    def read(self,size=-1):
        b=self.source.read(size);self.h.update(b);self.n+=len(b);return b
    def identity(self):return dict(bytes=self.n,sha256=self.h.hexdigest())
def selected(name):
    return (name in ("result.json","filesystem-public/original/ORIGINAL.json",
         "filesystem-public/original-controls-plan.json")
      or (name.startswith("filesystem-public/original-controls/") and
          (name.endswith("/REFUSAL.json") or name.endswith("/PROCESS.json")
           or name.rsplit("/",1)[-1] in ("RESULT.json","SOURCE.json","REFUSALS.json","remote-process.json"))))
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--archive",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();require(not a.output.exists(),"fresh output");a.output.mkdir()
    before=metadata(a.archive);require(stat.S_ISREG(before["mode"]),"ordinary ZIP")
    with a.archive.open("rb") as f:
        actual=dict(bytes=before["bytes"],sha256=hashlib.file_digest(f,"sha256").hexdigest())
    require(actual==EXPECTED,"complete uploaded failure ZIP identity")
    outer={};index=[];select={};controls=[];logical=0;seen=set()
    with zipfile.ZipFile(a.archive) as z:
        infos=z.infolist();names=[x.filename for x in infos]
        require(len(set(names))==len(names),"duplicate outer member")
        for info in infos:path_name(info.filename)
        require("manifest.json" in names and "failure-evidence.tar" in names,"fixed failure archive shape")
        manifest=decode(z.read("manifest.json"))
        require(manifest["schema"]=="hepta.runtime.native-failure-evidence.v1"
            and manifest["status"]=="COMPLETE"
            and manifest["archive"]["complete"] is True
            and manifest["original_failure_reclassified_as_pass"] is False,"retained failure exporter completion")
        tar_expected=manifest["archive"]["archive"]
        require(tar_expected["path"]=="failure-evidence.tar","fixed complete tar path")
        for info in infos:
            if info.filename=="failure-evidence.tar":continue
            if info.is_dir():
                outer[info.filename]=dict(kind="dir",bytes=0);continue
            digest=hashlib.sha256();size=0;chunks=[]
            with z.open(info) as f:
                while b:=f.read(1<<20):digest.update(b);size+=len(b);chunks.append(b)
            require(size==info.file_size,"complete outer member extent")
            outer[info.filename]=dict(kind="file",bytes=size,sha256=digest.hexdigest())
            if info.filename.startswith("diagnostics/") and size<=4<<20:
                select["ZIP/"+info.filename]=b"".join(chunks)
        for row in manifest["diagnostics"].values():
            require(row["complete"] is True,"complete retained diagnostic")
            got=outer[row["destination"]]
            require({k:got[k] for k in ("bytes","sha256")}==row["copy"],"copied diagnostic bytes")
        with z.open("failure-evidence.tar") as stream:
            hashing=HashReader(stream)
            with tarfile.open(fileobj=hashing,mode="r|") as t:
                for m in t:
                    name=path_name(m.name,tar=True)
                    require(name not in seen,"duplicate complete TAR member");seen.add(name)
                    row=dict(path=name,mode=m.mode,uid=m.uid,gid=m.gid,size=m.size,
                        mtime=m.mtime,type=m.type.decode("ascii"),linkname=m.linkname,
                        pax=m.pax_headers)
                    if m.isfile():
                        h=hashlib.sha256();size=0;chunks=[] if selected(name) and m.size<=4<<20 else None
                        with t.extractfile(m) as f:
                            while b:=f.read(1<<20):
                                h.update(b);size+=len(b)
                                if chunks is not None:chunks.append(b)
                        require(size==m.size,"full TAR file extent")
                        row["sha256"]=h.hexdigest();logical+=size
                        if chunks is not None:select["TAR/"+name]=b"".join(chunks)
                        if name.startswith("filesystem-public/original-controls/"):controls.append(row)
                    else:
                        require(m.isdir() or m.issym() or m.islnk() or m.isfifo(),"unsupported retained member kind")
                    index.append(row)
            while hashing.read(1<<20):pass
            require(hashing.identity()=={k:tar_expected[k] for k in ("bytes","sha256")},"whole raw TAR bytes")
            outer["failure-evidence.tar"]=dict(kind="file",**hashing.identity())
        require(len(index)==manifest["archive"]["tar_members"],"full original TAR member count")
    require(metadata(a.archive)==before,"source ZIP metadata unchanged")
    out_rows={}
    for number,(name,raw) in enumerate(sorted(select.items())):
        dest="selected-"+str(number)+".bin";(a.output/dest).write_bytes(raw)
        out_rows[name]=dict(file=dest,**pin(raw))
    facts={}
    for name,raw in select.items():
        if name.endswith("/result.json"):
            value=decode(raw)
            facts["checks"]=[{k:r.get(k) for k in ("name","exit_code","timed_out","start_error","duration_ns","elapsed_seconds")} for r in value.get("checks",[])]
        elif name.endswith("/REFUSAL.json"):
            v=decode(raw);facts.setdefault("completed_refusals",[]).append(v)
        elif name.endswith("/PROCESS.json"):
            facts.setdefault("reader_processes",[]).append(decode(raw))
    (a.output/"MEMBERS.json").write_bytes(encode(dict(outer=outer,tar=index)))
    (a.output/"CONTROL_FILES.json").write_bytes(encode(controls))
    (a.output/"SELECTED.json").write_bytes(encode(out_rows))
    (a.output/"FACTS.json").write_bytes(encode(facts))
    result=dict(status="COMPLETE_UPLOADED_FAILURE_BYTES_READ_PASS",zip=actual,
        tar={k:tar_expected[k] for k in ("bytes","sha256")},members=len(index),
        logical_regular_bytes=logical,complete_outer_members=len(outer),
        controls_files=len(controls),completed_refusals=len(facts.get("completed_refusals",[])),
        reader_processes=len(facts.get("reader_processes",[])),
        indices={n:pin((a.output/n).read_bytes()) for n in ("MEMBERS.json","CONTROL_FILES.json","SELECTED.json","FACTS.json")},
        applications_executed=0,retained_code_executed=0,physical_controls_replayed=0,
        semantic_qualification=False,original_failure_preserved=True,
        original_exporter_source_snapshot_guaranteed=manifest["source_snapshot_guaranteed"])
    (a.output/"READ.json").write_bytes(encode(result))
    print(json.dumps(result,sort_keys=True))
    print("RETAINED_FAILURE_FACTS "+json.dumps(facts,sort_keys=True))
if __name__=="__main__":main()
