#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Physical complete-buffer changes to retained direct-future trace bytes."""
from pathlib import Path
import gzip,hashlib,struct
from common import canonical,decode,pin,require
U=lambda b,n:struct.unpack_from("<Q",b,n)[0]
SPECS=(
    ("drop-generation",23,3,"actual future Drop issues one Scope-cancel action without post-await forget"),
    ("drop-scope-cancel",23,3,"complete actual Scope close or Scope-cancel loan for this lifecycle"),
    ("pending-body-loan",23,1,"unfinished actual await and complete body child2 loan"),
    ("pending-scope-token",23,1,"same actual Scope stack token"),
    ("pending-worker-tag",23,1,"unfinished actual await and complete body child2 loan"),
    ("normal-forget-phase",26,2,"actual result forget then Scope close"),
)
def transform(root,name):
    root=Path(root);spec=next(x for x in SPECS if x[0]==name)
    process=decode((root/"process/PROCESS.json").read_bytes())
    result=decode((root/"RESULT.json").read_bytes())
    require(result["process"]==process,"whole prior process custody")
    path=root/"process/host-trace.gz";before=pin(path)
    require(before==process["files"]["host-trace"]["gzip"],"prior compressed identity")
    target=path.with_name("host-trace.new");oldh=hashlib.sha256();newh=hashlib.sha256()
    logical=0;frames=0;selected=0;active=False;phase=None;tag=None;patches=[]
    def replace(buf,pos,old,new,label):
        require(bytes(buf[pos:pos+len(old)])==old and len(old)==len(new) and old!=new,"actual selected byte before-image")
        buf[pos:pos+len(old)]=new
        patches.append(dict(offset=logical+pos,bytes=len(old),before=old.hex(),after=new.hex(),field=label))
    def word(buf,pos,old,new,label):
        require(0<=new<1<<64,"exact u64 mutation")
        replace(buf,pos,struct.pack("<Q",old),struct.pack("<Q",new),label)
    with gzip.open(path,"rb") as incoming,target.open("xb") as physical:
        with gzip.GzipFile(fileobj=physical,mode="wb",mtime=0,compresslevel=1,filename="") as outgoing:
            while True:
                magic=incoming.read(8)
                if not magic:break
                require(len(magic)==8,"whole original trace prefix")
                if magic==b"HRGTR002":size=224
                elif magic==b"HRCNAK02":size=128
                else:
                    require(magic==b"HPTREV01","frozen host trace framing")
                    header=magic+incoming.read(120);require(len(header)==128,"whole event header")
                    size=U(header,8)
                    require(128<=size<=768<<20 and size==128+sum(U(header,n) for n in (72,80,88)),"complete bounded event extent")
                if magic==b"HPTREV01":
                    raw=header+incoming.read(size-128)
                else:raw=magic+incoming.read(size-8)
                require(len(raw)==size,"every original trace byte retained")
                buf=bytearray(raw);start=len(patches)
                if magic==b"HPTREV01":
                    event=U(raw,24);la,lb,lc=(U(raw,n) for n in (72,80,88));bo=128+la
                    if event==19:
                        require(not active,"no partial selected group")
                        require(la==lb==4096 and lc==0,"whole node and await context")
                        phase=U(raw,bo+56);tag=U(raw,bo+48)
                        active=selected==0 and phase==spec[2]
                        if active:
                            selected+=1
                            if name=="drop-generation":
                                require(U(raw,128+216)==3,"actual detached publisher node")
                                pos=128+1216+2*64+24
                                word(buf,pos,tag+1,tag+2,"saved caller descriptor generation")
                            elif name=="pending-worker-tag":
                                word(buf,bo+48,tag,tag+1,"saved actual worker capability tag")
                    elif active:
                        if event==17 and name=="pending-scope-token":
                            require(la==64 and lb>=72 and raw[bo:bo+8]==b"HRSCST01","actual Scope mapping")
                            token=U(raw,bo+64);require(token>0,"actual active token")
                            word(buf,bo+64,token,token+1,"actual Scope token")
                        elif event==23:
                            require(la==64 and lb>=4096 and raw[bo:bo+8]==b"HTPCST01","actual caller66 complete workspace")
                            if name=="drop-generation":
                                word(buf,128+24,tag+1,tag+2,"observed caller descriptor generation")
                                word(buf,bo+16,tag+1,tag+2,"actual caller generation")
                                word(buf,bo+264,tag+1,tag+2,"actual action generation")
                            elif name=="drop-scope-cancel":
                                at=U(raw,bo+288);extent=U(raw,bo+296)
                                require(extent==64 and 4096<=at<=lb-64 and raw[bo+at:bo+at+8]==b"HRSCQ001","full actual Scope-cancel loan")
                                word(buf,bo+at+8,8,7,"actual Scope cancel opcode")
                            elif name=="pending-body-loan":
                                at=U(raw,bo+288);extent=U(raw,bo+296)
                                require(extent>64 and 4096<=at<=lb-extent and raw[bo+at:bo+at+8]==b"HTPBQ001","full actual pending body loan")
                                pos=bo+at+64;old=raw[pos:pos+1]
                                replace(buf,pos,old,bytes([old[0]^1]),"actual body input byte")
                            elif name=="normal-forget-phase":
                                word(buf,bo+440,3,0,"actual completed post-await forget phase")
                        elif event==24 and name=="pending-worker-tag":
                            require(la==64 and lb==4096 and raw[bo:bo+8]==b"HTPAWC01","same capability in actual67 mapping")
                            word(buf,bo+48,tag,tag+1,"observed worker capability tag")
                        if event==25:active=False
                if patches[start:]:
                    exact=bytearray(raw)
                    for patch in patches[start:]:
                        at=patch["offset"]-logical
                        require(bytes(exact[at:at+patch["bytes"]]).hex()==patch["before"],"ordered declared before-image")
                        exact[at:at+patch["bytes"]]=bytes.fromhex(patch["after"])
                    require(buf==exact and buf!=raw,"only declared physical byte spans changed")
                else:require(buf==raw,"all unselected complete frames unchanged")
                oldh.update(raw);newh.update(buf);outgoing.write(buf);logical+=size;frames+=1
    require(selected==1 and not active,"one complete actual lifecycle group selected")
    counts={"drop-generation":4,"drop-scope-cancel":1,"pending-body-loan":1,
        "pending-scope-token":1,"pending-worker-tag":2,"normal-forget-phase":1}
    require(len(patches)==counts[name],"whole declared mutation inventory")
    oldraw=dict(bytes=logical,sha256=oldh.hexdigest());newraw=dict(bytes=logical,sha256=newh.hexdigest())
    require(oldraw==process["files"]["host-trace"]["raw"] and oldraw!=newraw,"complete before/after logical stream")
    target.replace(path)
    newzip=pin(path)
    with gzip.open(path,"rb") as incoming:
        h=hashlib.sha256();n=0
        while chunk:=incoming.read(1<<20):h.update(chunk);n+=len(chunk)
    require(dict(bytes=n,sha256=h.hexdigest())==newraw,"complete new compressed stream independently reread")
    process["files"]["host-trace"]["raw"]=newraw;process["files"]["host-trace"]["gzip"]=newzip
    result["process"]=process
    (root/"process/PROCESS.json").write_bytes(canonical(process))
    (root/"RESULT.json").write_bytes(canonical(result))
    return dict(name=name,case=spec[1],expected_refusal=spec[3],frames=frames,patches=patches,
        before_raw=oldraw,after_raw=newraw,before_gzip=before,after_gzip=newzip,
        honest_outer_reseal=True,application_executed=False)
