#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Pure complete HIA-call, workspace, effect and child-state journal admission."""
from pathlib import PurePosixPath
import base64,gzip,hashlib,stat,struct
from common import pin,require
U=lambda b,o:struct.unpack_from("<Q",b,o)[0]
I=lambda n:n-(1<<64)if n>>63 else n
CLASSES={1:"ValueError",2:"PermissionError",3:"OSError",4:"FileNotFoundError",
 5:"NotADirectoryError",6:"IsADirectoryError",7:"FileExistsError",8:"InterruptedError",
 9:"BlockingIOError",10:"BrokenPipeError",11:"TimeoutError",12:"ConnectionResetError",
 13:"ConnectionAbortedError",14:"ConnectionRefusedError"}
def result(frame):
    require(len(frame)>=64 and frame[:8]==b"HBRDS001"and len(frame)==64+U(frame,56),"terminal frame extent")
    kind=U(frame,8)
    if kind==6:
        require(U(frame,24)<=2147483647 and U(frame,32)==len(frame)-64 and U(frame,40)==U(frame,48)==0,"parent loan shape")
        return dict(ok=True,name=frame[64:].decode(),fd=U(frame,24))
    if kind==0:
        require(all(U(frame,p)==0 for p in(24,32,40,48,56))and len(frame)==64,"parent close success shape")
        return dict(ok=True)
    require(kind==3,"nonterminal parent frame")
    code,number,count,named=(U(frame,p)for p in(24,32,40,48))
    require(code in CLASSES and number<=4095 and count<=len(frame)-64 and named in(0,1),"exception shape")
    require(named or count==len(frame)-64,"unnamed literal extent")
    return dict(ok=False,error=dict(type=CLASSES[code],errno=number or None,
        filename=frame[64+count:].decode()if named else None,message=frame[64:64+count].decode()))
class Journal:
    def __init__(self,path):
        self.path=path;self.stream=gzip.open(path,"rb");self.digest=hashlib.sha256()
        self.position=0;self.events=0;self.full_buffer_bytes=0;self.calls=0;self.children=0;self.effects=0
    def take(self,event,generation,call):
        header=self.stream.read(128);require(len(header)==128,"short full journal header")
        self.digest.update(header);self.position+=128
        require(header[:8]==b"HPRDJR01","journal magic")
        h=struct.unpack("<16Q",header)
        require(h[1]==event and h[2]==generation and h[3]==call and h[5]==1 and h[7]==0,
            "journal event/generation/call/state differs")
        require(h[4]<=256<<20 and h[8]%4096==h[9]%4096==0 and h[8]>=4096 and h[9]>=4096,
            "owned journal extent differs")
        raw=self.stream.read(h[4]);require(len(raw)==h[4],"short complete journal span")
        self.digest.update(raw);self.position+=len(raw);self.events+=1;self.full_buffer_bytes+=len(raw)
        return h,raw
    def finish(self,receipt):
        require(not self.stream.read(1),"unread journal suffix");self.stream.close()
        require(dict(bytes=self.position,sha256=self.digest.hexdigest())==receipt["raw"]
            and pin(self.path)==receipt["compressed"]and receipt["complete_raw_bytes_in_gzip"]is True
            and receipt["no_expanded_ordinary_copy_created"]is True,"complete journal custody differs")
        return dict(events=self.events,full_buffer_bytes=self.full_buffer_bytes,body_calls=self.calls,
            child_calls=self.children,raw_os_effects=self.effects,journal_bytes=self.position)
def stat_reply(raw,entry):
    require(len(raw)==144,"Linux stat extent")
    expected=dict(dev=U(raw,0),inode=U(raw,8),links=U(raw,16),mode=struct.unpack_from("<I",raw,24)[0],
        uid=struct.unpack_from("<I",raw,28)[0],gid=struct.unpack_from("<I",raw,32)[0],size=I(U(raw,48)),
        mtime_ns=I(U(raw,88))*1000000000+U(raw,96),ctime_ns=I(U(raw,104))*1000000000+U(raw,112))
    require(all(entry[k]==v for k,v in expected.items()),"actual fstat differs from complete original fixture")

def stat_value(raw):
    require(len(raw)==144,"complete Linux stat")
    return dict(dev=U(raw,0),inode=U(raw,8),links=U(raw,16),mode=struct.unpack_from("<I",raw,24)[0],
        uid=struct.unpack_from("<I",raw,28)[0],gid=struct.unpack_from("<I",raw,32)[0],size=I(U(raw,48)),
        mtime_ns=I(U(raw,88))*1000000000+U(raw,96),ctime_ns=I(U(raw,104))*1000000000+U(raw,112))
def invocation(journal,start,terminal,generation,prior,hooks):
    incoming=start;last=prior.get("work");call=prior.get("call",0);fds=dict(prior.get("fds",{}))
    if U(start,8)==1:call=0;require(not fds,"start with owned descriptors")
    elif U(start,8)==3:
        require(last is not None and len(fds)==1 and U(start,16)==U(last,16)and U(last,8)==20 and U(last,432)==1,"close continuation ownership")
    else:raise ValueError("unowned parent command")
    consumed=0;effects=[]
    while True:
        call+=1;journal.calls+=1
        h,raw=journal.take(1,generation,call)
        require(raw==incoming and h[11]==len(incoming)and h[10]==len(fds),"complete parent input/FD count")
        hb,wb=journal.take(10,generation,call)
        require(len(wb)==hb[8]and hb[10]==len(fds)and(wb==last if last is not None else wb==bytes(len(wb))),"workspace continuation")
        ho,ob=journal.take(12,generation,call)
        require(len(ob)==ho[9]and ob==b"\xa5"*len(ob),"output initialization")
        ha,oa=journal.take(2,generation,call);hw,wa=journal.take(11,generation,call)
        require(ha[6]==hw[6]==64 and len(oa)==ha[9]==len(ob)and len(wa)==hw[8]==len(wb)
            and ha[10]==hw[10]==len(fds),"actual HIA return/full arenas")
        require(oa[:8]==b"HBRDS001"and U(oa,8)in(0,1,3,4,5,6),"parent response")
        extent=64+U(oa,56);require(extent<=len(oa)and oa[extent:]==ob[extent:],"full output tail")
        frame=oa[:extent];kind=U(frame,8);last=wa
        if kind in(0,3,6):
            if terminal is not None:require(frame==terminal,"terminal full bytes differ")
            if kind==6:
                fd=U(frame,24)
                require(set(fds)=={fd}and U(wa,88)==fd and U(wa,96)==U(wa,112)==(1<<64)-1
                    and U(wa,8)==20 and U(wa,432)==1 and U(wa,16)==U(frame,16),"held parent HIA ownership")
            else:require(not fds and U(wa,432)==0,"terminal still owns directory")
            result(frame)
            return dict(work=wa,output=oa,call=call,fds=fds,terminal=frame,hooks=consumed,effects=effects)
        if kind in(4,5):
            require(all(U(frame,p)==0 for p in(16,24,40,48,56)),"growth reserved words")
            need=U(frame,32);old=len(wb)if kind==4 else len(ob)
            require(old<need<=(256<<20 if kind==4 else 128<<20),"growth extent")
            if kind==4:
                _,before=journal.take(3,generation,call);hg,after=journal.take(4,generation,call)
                require(before==wa==wb and len(after)==hg[8]==(need+4095)&~4095
                    and after[:len(before)]==before and after[len(before):]==bytes(len(after)-len(before)),"full workspace growth")
                last=after
            continue
        require(kind==1,"unexpected child or effect")
        seq,op,fd,a,b=(U(frame,p)for p in(16,24,32,40,48));name=frame[64:]
        he,request=journal.take(8,generation,call);journal.effects+=1
        require(request==frame and he[12:14]==(seq,op)and he[10]==len(fds)and seq>0,"OS request ownership")
        hr,resume=journal.take(9,generation,call);rawret=I(U(resume,24))
        require(op in(1,2,5)and a==b==0,"undeclared parent effect")
        require(consumed<len(hooks),"missing actual effect barrier");hook=hooks[consumed];consumed+=1
        require(hook["raw_bytes"]==journal.hook_magic+struct.pack("<7Q",generation,call,seq,op,fd,a,b)
            and hook["ack_bytes"]==bytes(8),"actual effect notification bytes")
        if op==1:require(fd==0 and not name,"root-open args")
        else:require(fd in fds and hook["fd"]==fd and hook["stat"]["mode"]&61440==16384,"effect outside actual directory ownership")
        if op==2:require(name.endswith(b"\0")and b"\0"not in name[:-1],"openat component")
        if op==5:require(not name,"close payload")
        if op in(1,2)and rawret>=0:
            require(rawret not in fds and rawret<=2147483647,"descriptor duplicate/range")
            fds[rawret]="/"if op==1 else fds[fd]+"/"+name[:-1].decode()
        elif op==5:del fds[fd]
        require(resume[:8]==b"HPRDQ001"and U(resume,8)==2 and U(resume,16)==seq
            and all(U(resume,p)==0 for p in(32,40,48,56,64,72,80,88))and len(resume)==96
            and hr[12:14]==(seq,op)and hr[14]==U(resume,24)and hr[15]==0 and hr[10]==len(fds),"full actual resume")
        effects.append(dict(operation=op,fd=fd,result=rawret,name=name));incoming=resume
