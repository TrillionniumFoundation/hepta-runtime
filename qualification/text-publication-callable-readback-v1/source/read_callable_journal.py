#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Streaming complete native effect journal admission. No native code is loaded."""
from pathlib import Path
import gzip
import hashlib
import os
import struct
from callable_common import pin,require
MASK=(1<<64)-1
word=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]

class Journal:
    def __init__(self,path,identity):
        self.path=Path(path);require(pin(self.path)==identity["compressed"],"journal gzip changed")
        self.stream=gzip.open(self.path,"rb");self.identity=identity["raw"]
        self.count=0;self.frames=0;self.digest=hashlib.sha256();self.calls=0;self.actions=0;self.codec_calls=0;self.errno_calls=0
    def raw(self,n):
        value=self.stream.read(n);require(len(value)==n,"truncated complete journal")
        self.digest.update(value);self.count+=len(value);return value
    def event(self,expected,generation,call,wcap,ocap,live):
        head=self.raw(128)
        require(head[:8]==b"HTPCJR01","journal frame magic differs")
        fields=struct.unpack_from("<15Q",head,8);event,gen,number,size,state,code,extent,wc,oc,fd_count,il,seq,op,rc,rl=fields
        require(event==expected and gen==generation and number==call and state==1 and extent==0
            and wc==wcap and oc==ocap and fd_count==live and size<=256<<20,"journal complete header/state differs")
        data=self.raw(size);self.frames+=1
        return dict(code=code,input_length=il,sequence=seq,operation=op,raw=rc,reply_length=rl),data
    def finish(self):
        require(self.stream.read(1)==b"","extra journal tail");self.stream.close()
        require(dict(bytes=self.count,sha256=self.digest.hexdigest())==self.identity,"full decompressed journal changed")
        return dict(frames=self.frames,body_calls=self.calls,actions=self.actions,codec_calls=self.codec_calls,
            errno_calls=self.errno_calls,bytes=self.count,sha256=self.digest.hexdigest())

def invoke(journal,wire,response,previous):
    """One complete synchronous invoke, including all actual grows and callbacks."""
    generation=word(response,32);wcap,ocap=previous
    require(len(wire)>=64 and wire[:8]==b"HTPBQ001" and word(wire,8)==1 and word(wire,16)==0,"public body input changed")
    next_input=wire;sequence=0;live=set();call=0;last=None;digest=None;codec_state=None
    while True:
        call+=1;journal.calls+=1
        pre,actual=journal.event(1,generation,call,wcap,ocap,len(live))
        require(actual==next_input and pre["input_length"]==len(actual),"body did not receive exact callback/request")
        post,out=journal.event(2,generation,call,wcap,ocap,len(live))
        require(post["code"]==64 and post["input_length"]==len(actual) and len(out)==ocap and out[:8]==b"HTPBS001",
            "actual body return/full output differs")
        kind,seq,op,a,b,c,n=struct.unpack_from("<7Q",out,8)
        require(n<=len(out)-64 and out[64+n:]==b"\xa5"*(len(out)-64-n),"body output suffix differs")
        payload=out[64:64+n]
        if kind in (4,5):
            require(seq==op==b==c==n==0 and a>(wcap if kind==4 else ocap),"growth descriptor differs")
            size=(a+4095)&~4095
            require(size<=(256<<20 if kind==4 else 128<<20),"growth profile differs")
            if kind==4:
                _,old=journal.event(3,generation,call,wcap,ocap,len(live))
                _,new=journal.event(4,generation,call,size,ocap,len(live))
                require(len(old)==wcap and len(new)==size and new==old+bytes(size-len(old)),"actual growth lost/changed old bytes")
                wcap=size
            else:ocap=size
            continue
        if kind in (0,3):
            require(op==a==b==c==0 and seq==sequence and not live and response[64:]==out[:64+n]
                and word(response,8)==64 and word(response,24)==2 and word(response,40)==0
                and word(response,48)==ocap and word(response,56)==wcap,"published result has pending/changed resources")
            return dict(body_calls=call,sequence=sequence,workspace_capacity=wcap,output_capacity=ocap,
                final_output=out,final_input=actual,final_kind=kind)
        require(kind in (1,2) and seq==sequence+1,"effect sequence differs");sequence=seq;journal.actions+=1
        if kind==2:
            require(op in (3,4,6) and (a,b,c)==(0,0,0) and payload[:8]==b"HRCODEC1"
                and word(payload,8)==op and word(payload,16)==0,"fixed codec action differs")
            require(len(payload)==24 if op==3 else len(payload)==152 if op==6 else 152<=len(payload)<=152+1048576,
                "complete codec payload differs")
            _,child_input=journal.event(5,generation,call,wcap,ocap,len(live));require(child_input==payload,"actual codec input differs")
            child,child_out=journal.event(6,generation,call,wcap,ocap,len(live))
            _,child_work=journal.event(7,generation,call,wcap,ocap,len(live))
            rc=64 if op==6 else 128
            require(child["raw"]==child["reply_length"]==rc and len(child_out)==128 and len(child_work)==1184
                and child_out[rc:]==b"\xa5"*(128-rc),"complete codec output/workspace differs")
            result=child_out[:rc]
            if op==3:digest=hashlib.sha256()
            elif op==4:
                require(digest is not None and payload[24:152]==codec_state,"codec borrowed state differs")
                digest.update(payload[152:])
            else:require(digest is not None and payload[24:]==codec_state and result==digest.hexdigest().encode(),"actual HIA digest differs")
            if op in (3,4):codec_state=result
            journal.codec_calls+=1
        else:
            require(1<=op<=18,"OS operation not in fixed HIA capability set")
            before,action=journal.event(8,generation,call,wcap,ocap,len(live))
            require(action==out[:64+n] and before["sequence"]==seq and before["operation"]==op,"actual OS action differs")
            if op in (2,3,4,5,6,7,8,10,11,13,14,15,16,17):require(a in live,"effect borrowed a foreign/unowned fd")
            errno_data=None
            if op==18:
                _,request=journal.event(18,generation,call,wcap,ocap,len(live))
                require(request==b"HMDERQ01"+struct.pack("<Q",a) and 0<a<=4095,"actual errno HIA request differs")
                child,errno_out=journal.event(19,generation,call,wcap,ocap,len(live))
                require(errno_out[:8]==b"HMDERR01" and len(errno_out)==4096 and word(errno_out,8)==a,"actual errno HIA output differs")
                count=word(errno_out,16);errno_data=errno_out[24:24+count]
                require(count<=4096-24 and errno_out[24+count:]==b"\xa5"*(4096-24-count)
                    and child["raw"]==child["reply_length"]==count
                    and errno_data==(os.strerror(a)+" (os error "+str(a)+")").encode(),"complete target errno bytes differ")
                journal.errno_calls+=1
            # The reply event contains the actual syscall return and transferred bytes.
            head=journal.raw(128);require(head[:8]==b"HTPCJR01","OS reply journal magic")
            fields=struct.unpack_from("<15Q",head,8);event,gen,number,size,state,code,extent,wc,oc,fd_count,il,sq,oper,rc,rl=fields
            require(event==9 and gen==generation and number==call and state==1 and code==64 and extent==0
                and wc==wcap and oc==ocap and size==64+rl and size<=1052672 and il==size
                and sq==seq and oper==op,"actual OS reply descriptor differs")
            reply=journal.raw(size);journal.frames+=1
            require(reply==b"HTPBQ001"+struct.pack("<7Q",2,seq,rc,0,0,0,rl)+reply[64:],"OS resume framing differs")
            result=reply[64:];success=rc<(1<<63)
            if op in (1,2,3,4) and success:require(rc not in live and rc>=4,"opened fd overlaps existing owner");live.add(rc)
            if op==5 and success:require(rc==0,"close return differs");live.remove(a)
            require(fd_count==len(live),"complete FD ledger differs")
            if op in (6,7):require(len(result)==(144 if success else 0),"complete stat bytes differ")
            elif op in (11,12,18):
                require(len(result)==(rc if success else 0),"returned byte extent differs")
                if op==11:require(not success or rc<=b,"read exceeds requested bytes")
                if op==12:require(not success or rc<=a,"random exceeds requested bytes")
                if op==18:require(result==errno_data,"parent did not borrow actual errno HIA result")
            else:require(result==b"","unexpected syscall data bytes")
            if op==14:require(b==len(payload) and (not success or rc<=b),"write transfer differs")
            if op==16:require(b in (0,1) and 0<c<len(payload) and payload[:c].endswith(b"\0") and payload[c:].endswith(b"\0"),"rename spans differ")
            next_input=reply;continue
        # Codec callback publication follows all complete child observations.
        callback,reply=journal.event(9,generation,call,wcap,ocap,len(live))
        require(callback["sequence"]==seq and callback["operation"]==op and callback["raw"]==rc
            and callback["reply_length"]==len(result) and callback["input_length"]==len(reply)
            and reply==b"HTPBQ001"+struct.pack("<7Q",2,seq,rc,0,0,0,len(result))+result,"parent did not borrow actual codec result")
        next_input=reply
