#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bind actual retained reader source before the sole unfinished relocation; execute no retained code."""
from pathlib import Path,PurePosixPath
import argparse,base64,hashlib,json,stat,tarfile,zipfile
ZIP=dict(bytes=1305964335,sha256="fcbf2e416deafa7a699594c6ff08b2573cae7553d61e56bfe4fdbc4369795867")
TAR=dict(bytes=10807767040,sha256="47bb1aaafccd05bf42425f2b440b742e5d8c191e06c723b008af56808817836e")
PREFIX="filesystem-public/original-controls/"
def need(v,m):
    if not v:raise ValueError(m)
def canonical(v):return (json.dumps(v,sort_keys=True,separators=(",",":"))+"\n").encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def safe(name):
    n=name[2:] if name.startswith("./") else name
    if n==".":return n
    p=PurePosixPath(n);need(not p.is_absolute() and ".." not in p.parts and p.as_posix()==n.rstrip("/"),"safe retained member")
    return n.rstrip("/")
class Reader:
    def __init__(self,f):self.f=f;self.n=0;self.h=hashlib.sha256()
    def read(self,n=-1):
        b=self.f.read(n);self.n+=len(b);self.h.update(b);return b
    def pin(self):return dict(bytes=self.n,sha256=self.h.hexdigest())
def selected(n):
    if not n.startswith(PREFIX):return False
    r=n[len(PREFIX):]
    return (r.endswith(".py") and (r.startswith("relocated-one/") or r.startswith("relocated-two/"))
        or "/" not in r and r.endswith(".json")
        or r in ("relocation-1/PROCESS.json","relocation-1/EVIDENCE.json","relocation-1/NATIVE-EVIDENCE.json",
                 "relocation-2/PROCESS.json","relocation-2/EVIDENCE.json","relocation-2/NATIVE-EVIDENCE.json")
        or (r in ("relocated-one/mapping.json","relocated-two/mapping.json")))
def main():
    p=argparse.ArgumentParser();p.add_argument("--archive",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();need(not a.output.exists(),"fresh binding output");a.output.mkdir()
    before=a.archive.stat();need(stat.S_ISREG(before.st_mode),"ordinary uploaded ZIP")
    with a.archive.open("rb") as f:need(dict(bytes=before.st_size,sha256=hashlib.file_digest(f,"sha256").hexdigest())==ZIP,"whole uploaded ZIP")
    rows=[];seen=set();chosen={};controls=[]
    with zipfile.ZipFile(a.archive) as z:
        need(len({m.filename for m in z.infolist()})==len(z.infolist()),"unique ZIP members")
        with z.open("failure-evidence.tar") as stream:
            reader=Reader(stream)
            with tarfile.open(fileobj=reader,mode="r|") as t:
                for m in t:
                    name=safe(m.name);need(name not in seen,"unique TAR members");seen.add(name)
                    if name.startswith(PREFIX):
                        row=dict(path=name,kind=m.type.decode(),bytes=m.size,mode=m.mode,linkname=m.linkname,pax=m.pax_headers)
                        rows.append(row)
                    if not selected(name):continue
                    need(m.isfile(),"selected reader is ordinary complete file")
                    with t.extractfile(m) as f:raw=f.read()
                    need(len(raw)==m.size,"full selected bytes")
                    dest="source-"+str(len(chosen))+".bin";(a.output/dest).write_bytes(raw)
                    chosen[name]=dict(file=dest,**pin(raw))
                    if name.endswith(".py") or name.endswith("/mapping.json") or name==PREFIX+"SOURCE.json":
                        need(len(raw)<=4<<20,"source export bound")
                        print("EXACT_INSTALLED_READER "+json.dumps(dict(path=name,**pin(raw),base64=base64.b64encode(raw).decode()),sort_keys=True))
            while reader.read(1<<20):pass
            need(reader.pin()==TAR,"whole retained TAR bytes")
    need(len(seen)==110036,"whole retained member count")
    need(a.archive.stat()==before,"archive source unchanged")
    need(PREFIX+"relocation-1/PROCESS.json" in chosen,"completed relocation 1 receipt present")
    p1=json.loads((a.output/chosen[PREFIX+"relocation-1/PROCESS.json"]["file"]).read_bytes())
    need(p1["exit_code"]==0 and p1["timed_out"] is False,"relocation 1 remains complete")
    roots=sorted({n[len(PREFIX):].split("/")[0] for n in chosen if "/admission/" in n})
    need(len(roots)==1 and roots[0] in ("relocated-one","relocated-two"),"one retained original bundle")
    need(not any(n.startswith(PREFIX+"relocation-2/") for n in chosen),"unfinished relocation 2 must have no observed completed/UNKNOWN process")
    (a.output/"MEMBERS.json").write_bytes(canonical(rows));(a.output/"SELECTED.json").write_bytes(canonical(chosen))
    result=dict(status="INSTALLED_RELOCATION_READER_SOURCE_BOUND",archive=ZIP,tar=TAR,bundle_root=roots[0],
        selected=chosen,member_index=pin((a.output/"MEMBERS.json").read_bytes()),applications_executed=0,
        retained_code_executed=0,physical_controls_replayed=0,completed_relocation_replayed=0,relocation2_executed=0,
        original_failure_preserved=True,remaining="only the second relocation after exact source review and freeze")
    (a.output/"BIND.json").write_bytes(canonical(result));print("INSTALLED_SOURCE_BIND "+json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
