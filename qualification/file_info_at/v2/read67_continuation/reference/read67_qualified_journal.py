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
    from common import decode,canonical
    require(len(frame)>=64 and frame[:8]==b"HBRDS001"and len(frame)==64+U(frame,56),"terminal frame extent")
    kind=U(frame,8)
    if kind==0:
        require(all(U(frame,p)==0 for p in(24,32,40,48)),"success reserved words")
        value=decode(frame[64:]);require(canonical(value)[:-1]==frame[64:],"canonical result bytes differ")
        return dict(ok=True,value=value,canonical=frame[64:].decode())
    require(kind==3,"nonterminal frame")
    code,number,count,named=(U(frame,p)for p in(24,32,40,48))
    require(code in CLASSES and number<=4095 and count<=len(frame)-64 and named in(0,1),"exception envelope")
    require(named or count==len(frame)-64,"unnamed exception payload")
    return dict(ok=False,error=dict(type=CLASSES[code],errno=number or None,
        filename=frame[64+count:].decode()if named else None,message=frame[64:64+count].decode()))
class Journal:
    def __init__(self,path):
        self.path=path;self.stream=gzip.open(path,"rb");self.digest=hashlib.sha256()
        self.position=0;self.events=0;self.full_buffer_bytes=0;self.calls=0;self.children=0;self.effects=0
    def take(self,event,generation,call):
        header=self.stream.read(128);require(len(header)==128,"short full journal header")
        self.digest.update(header);self.position+=128
        require(header[:8]==b"HBRDJR01","journal magic")
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
def state(raw,count):
    require(len(raw)==128 and raw[:8]==b"HSHA2561"and U(raw,8)==count and U(raw,16)==count%64
        and raw[56+count%64:120]==bytes(64-count%64)and raw[120:]==bytes(8),"complete SHA continuation state differs")
    if count<64:
        require(raw[24:56]==struct.pack("<8I",0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
            0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19),"initial SHA chaining state differs")
def invocation(journal,start,terminal,generation,fixture=None,previous_work=None,borrowed=None,hooks=None):
    incoming=start;last_work=previous_work;call=0;fds={}if borrowed is None else{borrowed[0]:borrowed[1]}
    positions={};stream_state=None;stream_hash=None;stream_count=0;hook_index=0;effects=[];orphans=[];last_sequence=0
    def owned_count():return len(fds)-(borrowed is not None)
    while True:
        call+=1;journal.calls+=1
        h,raw=journal.take(1,generation,call)
        require(raw==incoming and h[11]==len(incoming)and h[10]==owned_count(),"complete body input/FD binding differs")
        hb,wb=journal.take(10,generation,call)
        require(len(wb)==hb[8]and hb[10]==owned_count()and(last_work is None or wb==last_work),"workspace continuation differs")
        ho,ob=journal.take(12,generation,call)
        require(len(ob)==ho[9]and ob==b"\xa5"*len(ob),"body output initialization differs")
        ha,oa=journal.take(2,generation,call)
        hw,wa=journal.take(11,generation,call)
        require(ha[6]==hw[6]==64 and len(oa)==ha[9]==len(ob)and len(wa)==hw[8]==len(wb)
            and ha[10]==hw[10]==owned_count(),"actual HIA return or complete arenas differ")
        require(oa[:8]==b"HBRDS001"and U(oa,8)in range(6),"body response header")
        extent=64+U(oa,56)
        require(extent<=len(oa)and oa[extent:]==ob[extent:],"body output tail changed")
        frame=oa[:extent];kind=U(frame,8);last_work=wa
        if kind in(0,3):
            require(set(fds)==(set()if borrowed is None else{borrowed[0]})and (terminal is None or frame==terminal),
                "terminal borrow or owned descriptor set differs")
            require(hooks is None or hook_index==len(hooks),"unread native effect notification")
            result(frame)
            return dict(workspace=wa,output=oa,body_calls=call,frame=frame,effects=effects,orphans=orphans)
        if kind in(4,5):
            require(all(U(frame,p)==0 for p in(16,24,40,48,56)),"growth frame reserved words")
            need=U(frame,32);old=len(wb)if kind==4 else len(ob)
            require(old<need<=(256<<20 if kind==4 else 128<<20),"growth extent differs")
            if kind==4:
                _,before=journal.take(3,generation,call);hg,after=journal.take(4,generation,call)
                require(before==wa and before==wb and len(after)==hg[8]==(need+4095)&~4095
                    and after[:len(before)]==before and after[len(before):]==bytes(len(after)-len(before)),
                    "complete retained workspace growth differs")
                last_work=after
            continue
        operation=U(frame,24);sequence=U(frame,16)
        require(sequence==last_sequence+1,"complete monotonically owned effect sequence");last_sequence=sequence
        if kind==1:
            he,request=journal.take(8,generation,call);journal.effects+=1
            require(request==frame and he[12:14]==(sequence,operation)and he[10]==owned_count(),"OS request binding")
            hr,resume=journal.take(9,generation,call)
            rawret=I(U(resume,24));payload=resume[96:]
            require(operation in(1,2,3,4,5,6,9,11,19),"undeclared filesystem operation")
            fd,a,b=(U(frame,p)for p in(32,40,48));name=frame[64:]
            hook=None
            if hooks is not None:
                require(hook_index<len(hooks),"missing native effect notification");hook=hooks[hook_index];hook_index+=1
                require(hook["raw_bytes"]==b"HBRDHK01"+struct.pack("<7Q",generation,call,sequence,operation,fd,a,b),
                    "actual notification differs from full HIA OS request")
                require(hook["ack_bytes"]==bytes(8),"effect acknowledgement changed")
            if borrowed is not None and fd==borrowed[0]:
                require(operation==3,"borrowed directory used outside openat")
            if operation in(1,9):
                require(fd==a==b==0 and not name,"root/euid raw effect args")
            else:require(fd in fds,"effect used an unowned descriptor")
            if operation in(2,3):
                require(a==b==0 and name.endswith(b"\0")and b"\0"not in name[:-1],"openat name envelope")
            elif operation not in(1,9):
                require(not name and b==0 and(operation in(11,19)or a==0),"fixed effect arguments")
            if operation in(1,2,3):
                require(not payload,"open returned extra bytes")
                if rawret>=0:
                    require(rawret not in fds,"descriptor acquired twice")
                    path="/"if operation==1 else str(PurePosixPath(fds[fd])/name[:-1].decode())
                    fds[rawret]=path;positions[rawret]=0
            elif operation==4:
                require(rawret==0 and not payload and(borrowed is None or fd!=borrowed[0])
                    and U(wa,8)==35 and U(wa,96)==fd,"exact first-fstat orphan request and acknowledgement")
                require(effects and effects[-1]["operation"]==6 and effects[-1]["phase"]==25
                    and effects[-1]["fd"]==fd and effects[-1]["raw_return"]<0
                    and effects[-1]["raw_return"]!=-4,"orphan only after original regular first-fstat non-EINTR failure")
                orphans.append(dict(fd=fd,generation=generation,sequence=sequence,path=fds[fd]))
                del fds[fd];positions.pop(fd,None)
            elif operation==5:
                require(not payload and(borrowed is None or fd!=borrowed[0]),"borrowed close or extra close bytes");del fds[fd];positions.pop(fd,None)
            elif operation==6:
                require(len(payload)==(144 if rawret==0 else 0),"fstat result extent")
                if rawret==0:
                    if hook is not None:
                        require("fd_stat"in hook,"missing actual pre-syscall descriptor observation")
                        stat_reply(payload,hook["fd_stat"])
                        from protocol import stat_decode
                        require(stat_decode(payload)==hook["after"]["stat"],"complete actual fstat fields")
                    elif fixture is not None:
                        entry=fixture.get(fds[fd]);require(entry is not None,"fstat outside captured fixture")
                        stat_reply(payload,entry)
            elif operation==9:require(rawret>=0 and not payload,"geteuid result")
            elif operation==19:
                require(not payload and(rawret<0 or rawret==a),"seek result")
                if rawret>=0:positions[fd]=rawret
            elif operation==11:
                require(0<a<=1048576 and len(payload)==(rawret if rawret>=0 else 0),"read result extent")
                if rawret>=0:
                    require(rawret<=a,"read exceeded requested extent")
                    if fixture is not None:
                        entry=fixture.get(fds[fd]);require(entry is not None and entry["kind"]=="file","read outside fixture")
                        expected=entry["raw"][positions[fd]:positions[fd]+a]
                        require(payload==expected[:rawret]and(rawret>0 or not expected),"actual read bytes differ from retained fixture")
                    positions[fd]+=rawret
            require(hr[10]==owned_count(),"effect FD ownership count differs")
            effects.append(dict(operation=operation,fd=fd,a=a,b=b,request=name.hex(),phase=U(wa,8),
                raw_return=rawret,payload=payload.hex(),returned_bytes=len(payload),returned_sha256=hashlib.sha256(payload).hexdigest()))

        else:
            require(kind==2 and operation in(1,2)and all(U(frame,p)==0 for p in(32,40,48)),"child request envelope")
            _,request=journal.take(5,generation,call)
            _,cb=journal.take(13,generation,call);_,cw=journal.take(14,generation,call)
            hc,ca=journal.take(6,generation,call);_,cwa=journal.take(7,generation,call)
            journal.children+=1;count=hc[14]
            cap,work=(1398104,1184)if operation==1 else(128,256)
            require(request==frame[64:]and len(cb)==len(ca)==cap and len(cw)==len(cwa)==work
                and cb==b"\xa5"*cap and cw==bytes(work)and count<=cap and hc[15]==count
                and ca[count:]==cb[count:],"complete child arena or return tail differs")
            value=ca[:count]
            if operation==2:
                require(len(request)==72 and request[:8]==b"HSTVER01"and U(request,8)==1,"stat codec input")
                words=struct.unpack("<7Q",request[16:])
                expected=":".join(map(str,(*words[:3],I(words[3])*1000000000+words[4],I(words[5])*1000000000+words[6]))).encode()
                require(value==expected,"stat codec exact output")
            else:
                require(len(request)>=24 and request[:8]==b"HRCODEC1"and U(request,16)==0,"byte codec input")
                op=U(request,8);data=request[24:]
                if op==2:require(value==hashlib.sha256(data).hexdigest().encode(),"one-shot hash differs")
                elif op==7:
                    require(value==base64.b64encode(data)and cwa==cw,"canonical Base64 or scratch preservation differs")
                elif op==3:
                    require(not data,"initial SHA payload")
                    stream_hash=hashlib.sha256();stream_count=0;state(value,0);stream_state=value
                elif op==4:
                    require(stream_state is not None and data[:128]==stream_state,"SHA state continuity")
                    block=data[128:];stream_hash.update(block);stream_count+=len(block);state(value,stream_count)
                    pending=stream_state[56:56+U(stream_state,16)]+block
                    require(value[56:56+stream_count%64]==pending[-(stream_count%64):]if stream_count%64 else value[56:120]==bytes(64),
                        "SHA buffered complete bytes differ")
                    stream_state=value
                elif op==6:
                    require(data==stream_state and value==stream_hash.hexdigest().encode(),"stream final digest differs")
                else:raise ValueError("undeclared byte codec operation")
            hr,resume=journal.take(9,generation,call)
            require(U(resume,24)==count and resume[96:]==value and hr[10]==owned_count(),"complete child resume differs")
        require(resume[:8]==b"HBRDQ001"and U(resume,8)==2 and U(resume,16)==sequence
            and all(U(resume,p)==0 for p in(32,40,48,56,64,72,80))
            and U(resume,88)==len(resume)-96 and hr[12:14]==(sequence,operation)
            and hr[14]==U(resume,24)and hr[15]==len(resume)-96,"full effect resume ownership differs")
        incoming=resume
