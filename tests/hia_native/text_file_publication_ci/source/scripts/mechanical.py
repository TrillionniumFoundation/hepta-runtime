#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Fixed raw OS effects and exact borrowed HIA calls; publication policy stays in HIA."""
from pathlib import Path
import ctypes
import os
import struct
import time
from common import canonical, decode, pin, require
from hia_native_loader import NativeModule

MASK=(1<<64)-1
word=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]

class Effects:
    def __init__(self):
        self.libc=ctypes.CDLL(None,use_errno=True)
        self.live=set()
        def bind(name,args,ret):
            fn=getattr(self.libc,name);fn.argtypes=args;fn.restype=ret
        I=ctypes.c_int;U=ctypes.c_uint;P=ctypes.c_void_p;S=ctypes.c_size_t;C=ctypes.c_char_p;L=ctypes.c_ssize_t
        for name,args,ret in (
            ("open",[C,I,U],I),("openat",[I,C,I,U],I),("close",[I],I),
            ("fstat",[I,P],I),("fstatat",[I,C,P,I],I),("flock",[I,I],I),
            ("geteuid",[],U),("flistxattr",[I,P,S],L),("read",[I,P,S],L),
            ("getrandom",[P,S,U],L),("fchmod",[I,U],I),("write",[I,P,S],L),
            ("fsync",[I],I),("renameat2",[I,C,I,C,U],I),("unlinkat",[I,C,I],I)):
            bind(name,args,ret)

    @staticmethod
    def name(raw):
        require(raw and raw[-1:]==b"\0" and b"\0" not in raw[:-1],"invalid owned C-name span")
        return raw

    def call(self,op,a,b,c,payload):
        require(1<=op<=18,"unknown mechanical action")
        if op in (2,3,4,5,6,7,8,10,11,13,14,15,16,17):
            require(a in self.live,"unowned action fd")
        data=b"";buffer=None
        ctypes.set_errno(0)
        flags=os.O_CLOEXEC|os.O_NOFOLLOW
        if op==1:
            require((a,b,c,payload)==(0,0,0,b""),"root open arguments")
            rc=self.libc.open(b"/",flags|os.O_RDONLY|os.O_DIRECTORY,0)
        elif op in (2,3,4):
            require((b,c)==(0,0),"openat arguments")
            name=self.name(payload)
            extra=(os.O_RDONLY|os.O_DIRECTORY if op==2 else
                os.O_RDONLY|os.O_NONBLOCK if op==3 else os.O_WRONLY|os.O_CREAT|os.O_EXCL)
            rc=self.libc.openat(a,name,flags|extra,0o600 if op==4 else 0)
        elif op==5:
            require((b,c,payload)==(0,0,b""),"close arguments")
            rc=self.libc.close(a)
        elif op in (6,7):
            require((b,c)==(0,0),"stat arguments")
            buffer=ctypes.create_string_buffer(144)
            if op==6:
                require(payload==b"","fstat payload")
                rc=self.libc.fstat(a,buffer)
            else:
                rc=self.libc.fstatat(a,self.name(payload),buffer,0x100)
            if rc==0:data=buffer.raw
        elif op==8:
            require((b,c,payload)==(0,0,b""),"flock arguments")
            rc=self.libc.flock(a,2)
        elif op==9:
            require((a,b,c,payload)==(0,0,0,b""),"geteuid arguments")
            rc=self.libc.geteuid()
        elif op==10:
            require((b,c,payload)==(0,0,b""),"xattr arguments")
            rc=self.libc.flistxattr(a,None,0)
        elif op==11:
            require(0<b<=1048576 and (c,payload)==(0,b""),"read arguments")
            buffer=ctypes.create_string_buffer(b)
            rc=self.libc.read(a,buffer,b)
            if rc>=0:data=buffer.raw[:rc]
        elif op==12:
            require(0<a<=1048576 and (b,c,payload)==(0,0,b""),"getrandom arguments")
            buffer=ctypes.create_string_buffer(a)
            rc=self.libc.getrandom(buffer,a,0)
            if rc>=0:data=buffer.raw[:rc]
        elif op==13:
            require(b<=0o777 and (c,payload)==(0,b""),"fchmod arguments")
            rc=self.libc.fchmod(a,b)
        elif op==14:
            require(b==len(payload) and 0<b<=1048576 and c==0,"write arguments")
            buffer=ctypes.create_string_buffer(payload)
            rc=self.libc.write(a,buffer,b)
        elif op==15:
            require((b,c,payload)==(0,0,b""),"fsync arguments")
            rc=self.libc.fsync(a)
        elif op==16:
            require(b in (0,1) and 0<c<len(payload),"rename arguments")
            rc=self.libc.renameat2(a,self.name(payload[:c]),a,self.name(payload[c:]),b)
        elif op==17:
            require((b,c)==(0,0),"unlink arguments")
            rc=self.libc.unlinkat(a,self.name(payload),0)
        else:
            require(0<a<4096 and (b,c,payload)==(0,0,b""),"OS display arguments")
            data=(os.strerror(a)+" (os error "+str(a)+")").encode()
            rc=len(data)
        number=ctypes.get_errno() if rc<0 else 0
        raw_return=(-number if rc<0 else rc)&MASK
        if op in (1,2,3,4) and rc>=0:
            require(rc not in self.live,"fd ownership duplicated");self.live.add(rc)
        if op==5 and rc==0:
            self.live.remove(a)
        return raw_return,data,dict(libc_return=rc,errno=number,live_fds=sorted(self.live))

    def close_after_failure(self):
        for fd in sorted(self.live):
            self.libc.close(fd)
        self.live.clear()

class NativeBody:
    def __init__(self, qualification, capture, store, calls, effects):
        self.root=Path(qualification);self.capture=Path(capture);self.store=store
        self.calls=calls;self.effects=effects;self.ordinal=0;self.effect_ordinal=0
        self.modules={}
        build=decode((self.root/"BUILD.json").read_bytes())
        for name,row in build["members"].items():
            self.modules[name]=NativeModule(self.root/row["manifest"],
                manifest_sha256=row["identity"]["sha256"])

    def invoke(self,session,wire,case_id,owner):
        old=ctypes.string_at(session._workspace,session.workspace_capacity)
        ctypes.memset(session._output,0xA5,session.output_capacity)
        out_old=ctypes.string_at(session._output,session.output_capacity)
        addresses=dict(output=ctypes.addressof(session._output),workspace=ctypes.addressof(session._workspace))
        begin=time.monotonic_ns()
        code,out,after=session.invoke_raw(wire)
        elapsed=time.monotonic_ns()-begin
        self.ordinal+=1
        row=dict(call=self.ordinal,case_id=case_id,owner=owner,return_code=code,
            elapsed_ns=elapsed,addresses=addresses,input=self.store.put(wire),
            workspace_before=self.store.put(old),output_before=self.store.put(out_old),
            output=self.store.put(out),workspace_after=self.store.put(after))
        self.calls.write(canonical(row));self.calls.flush()
        return code,out,after

    def run(self,request):
        cid=request["id"];path=request["path"].encode();content=request["content"].encode();expected=request["expected_sha256"].encode()
        mode={"create":1,"replace":2,"append":3}[request["mode"]]
        wire=b"HTPBQ001"+struct.pack("<7Q",1,0,mode,len(path),len(content),len(expected),len(path)+len(content)+len(expected))+path+content+expected
        module=self.modules["text-file-publication"]
        session=module.session(output_capacity=64,workspace_capacity=4096)
        effect=Effects()
        begin=time.monotonic_ns();first=self.ordinal+1
        try:
            for step in range(1024):
                require(time.monotonic_ns()-begin<60_000_000_000,"publication exchange deadline")
                code,out,after=self.invoke(session,wire,cid,"body")
                require(code==64 and out[:8]==b"HTPBS001","publication native framing/refusal")
                kind,seq,op,a,b,c,size=struct.unpack_from("<7Q",out,8)
                require(size<=len(out)-64,"publication complete output extent")
                require(out[64+size:]==b"\xa5"*(len(out)-64-size),"publication output tail")
                if kind in (4,5):
                    require(seq==op==b==c==size==0,"growth reserved fields")
                    ocap=session.output_capacity;wcap=session.workspace_capacity
                    if kind==4:
                        require(wcap<a<=module.metadata["workspace_capacity"],"workspace growth range");wcap=a
                    else:
                        require(ocap<a<=module.metadata["output_capacity"],"output growth range");ocap=a
                    newer=module.session(output_capacity=ocap,workspace_capacity=wcap)
                    ctypes.memmove(newer._workspace,after,len(after))
                    session.close();session=newer
                    continue
                if kind in (0,3):
                    require(op==a==b==c==0 and not effect.live,"final borrowed resources still owned")
                    return dict(id=cid,ok=kind==0,text=out[64:64+size].decode()),dict(first_call=first,last_call=self.ordinal,
                        elapsed_ns=time.monotonic_ns()-begin,last_sequence=seq)
                require(kind in (1,2),"unknown publication action")
                payload=out[64:64+size]
                self.effect_ordinal+=1
                event=dict(effect=self.effect_ordinal,case_id=cid,body_call=self.ordinal,kind=kind,
                    sequence=seq,operation=op,a=a,b=b,c=c,payload=self.store.put(payload))
                if kind==1:
                    rc,data,osrow=effect.call(op,a,b,c,payload)
                    event["os"]=osrow
                else:
                    require((a,b,c)==(0,0,0) and op in (3,4,6),"SHA child action framing")
                    child=self.modules["binary-codec"]
                    with child.session(output_capacity=128,workspace_capacity=1184) as child_session:
                        rc,child_out,_=self.invoke(child_session,payload,cid,"codec")
                    require(rc in (64,128) and child_out[rc:]==b"\xa5"*(128-rc),"SHA complete output framing")
                    data=child_out[:rc];event["child_call"]=self.ordinal
                event["return_code"]=rc;event["reply"]=self.store.put(data)
                self.effects.write(canonical(event));self.effects.flush()
                wire=b"HTPBQ001"+struct.pack("<7Q",2,seq,rc,0,0,0,len(data))+data
            raise ValueError("publication exceeded private action count")
        finally:
            session.close();effect.close_after_failure()

    def close(self):
        for module in self.modules.values():module.close()
