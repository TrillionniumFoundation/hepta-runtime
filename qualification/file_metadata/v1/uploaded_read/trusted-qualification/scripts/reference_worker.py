#!/usr/bin/env python3
"""The unchanged original target executed with read-only observation wrappers."""
from pathlib import Path
import hashlib,json,os,stat,struct,sys
sys.dont_write_bytecode=True
SOURCE=Path(sys.argv[1]).resolve(strict=True)
sys.path.insert(0,str(SOURCE/"scripts"))
from evidence_common import decode,encoded,require
from protocol import exception,original_snapshot,stat_encode,stat_value,U
from cases import original_snapshot as input_snapshot
target=SOURCE/"target/file_metadata.py"
raw=target.read_bytes()
require(hashlib.sha256(raw).hexdigest()=="24b9df89816536db16dd35a74d6460b1a215981a00798393a00853da6077f5d3","original exact target")
namespace={"__name__":"frozen_original_file_metadata","__file__":str(target)}
exec(compile(raw,str(target),"exec"),namespace)
def write(fd,raw):
    while raw:
        n=os.write(fd,raw);require(n>0,"complete original write");raw=raw[n:]
def read(fd,count,optional=False):
    result=b""
    while len(result)<count:
        part=os.read(fd,count-len(result))
        if not part and optional and not result:return None
        require(part,"complete original input");result+=part
    return result
class ObservedOS:
    def __init__(self):self.observer=True;self.generation=0;self.calls=0
    def __getattr__(self,key):return getattr(os,key)
    def call(self,op,fd,args,method,values):
        self.calls+=1;number=self.calls
        a=b=0
        if op==4:a,b=args
        elif op==5:a=args[0]
        if self.observer:
            write(4,b"HMDTHK01"+struct.pack("<7Q",self.generation,number,number,op,fd,a,b))
            require(read(5,8)==bytes(8),"original fixed acknowledgement")
        try:
            value=method(fd,*args)
        except BaseException as e:
            if self.observer:write(3,encoded(dict(generation=self.generation,call=number,operation=op,fd=fd,args=values,ok=False,error=exception(e))))
            raise
        if self.observer:
            if op==1:record=stat_value(value)
            elif op==2:record=[os.fsencode(n).hex()for n in value]
            elif op==3:record=value.hex()
            else:record=value
            write(3,encoded(dict(generation=self.generation,call=number,operation=op,fd=fd,args=values,ok=True,value=record)))
        return value
    def fstat(self,fd):return self.call(1,fd,(),os.fstat,{})
    def listxattr(self,fd):return self.call(2,fd,(),os.listxattr,{})
    def getxattr(self,fd,name):return self.call(3,fd,(name,),os.getxattr,dict(name_hex=os.fsencode(name).hex()))
    def fchown(self,fd,uid,gid):return self.call(4,fd,(uid,gid),os.fchown,dict(uid=uid,gid=gid))
    def fchmod(self,fd,mode):return self.call(5,fd,(mode,),os.fchmod,dict(mode=mode))
    def removexattr(self,fd,name):return self.call(6,fd,(name,),os.removexattr,dict(name_hex=os.fsencode(name).hex()))
    def setxattr(self,fd,name,value):return self.call(7,fd,(name,value),os.setxattr,dict(name_hex=os.fsencode(name).hex(),value_hex=value.hex()))
    def fsync(self,fd):return self.call(8,fd,(),os.fsync,{})
proxy=ObservedOS();namespace["os"]=proxy
fds=[[None,None],[None,None]];saved=[None,None];generations=[0,0];closed=set()
def reply(ret,data=b"",generation=0):
    write(1,b"HMDTFR01"+struct.pack("<7Q",ret&((1<<64)-1),len(data),0,generation,0,0,0)+data)
while True:
    head=read(0,8,True)
    if head is None:break
    length=U(head,0);require(64<=length<=134217792,"original fixture extent")
    raw=read(0,length);require(raw[:8]==b"HMDTFQ01"and len(raw)==64+U(raw,24)and raw[32:64]==bytes(32),"original private frame")
    command,slot=U(raw,8),U(raw,16);require(slot in(0,1),"original fixture slot");payload=raw[64:]
    if command in(8,9):
        require(not payload,"original create payload");generations[slot]=0;saved[slot]=None;reply(0);continue
    if command in(10,11):
        role=command-10;require(fds[slot][role]is None and payload.endswith(b"\0")and b"\0"not in payload[:-1],"original held path")
        fd=os.open(payload[:-1],os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
        fds[slot][role]=fd;closed.discard(fd);reply(fd);continue
    if command in(14,15):
        fd=fds[slot][command-14];require(fd is not None,"original stat absent file")
        try:reply(0,stat_encode(os.fstat(fd)))
        except OSError as e:reply(-e.errno)
        continue
    if command in(12,13,16,17):
        role=(command-12)if command in(12,13)else(command-16);fd=fds[slot][role];require(fd is not None,"original close absent file")
        try:os.close(fd);ret=0;closed.add(fd)
        except OSError as e:ret=-e.errno
        if command in(12,13):fds[slot][role]=None
        reply(ret);continue
    require(command==1,"original unsupported private command")
    query=decode(payload);generations[slot]+=1;proxy.generation=generations[slot];proxy.calls=0;proxy.observer=query["observer"]
    try:
        mode=query["mode"]
        if mode in("capture","capture-summary"):
            value=namespace["metadata_capture"](fds[slot][0]);saved[slot]=value;value=original_snapshot(value);code=1
        elif mode=="summary-held":
            require(saved[slot]is not None,"original actual snapshot required")
            value=namespace["metadata_summary"](saved[slot]);code=2
        elif mode=="summary":
            value=namespace["metadata_summary"](input_snapshot(query["snapshot"]));code=2
        elif mode=="preserve":
            value=namespace["metadata_preserve"](*fds[slot]);code=3
        else:raise ValueError("unknown fixed original entry")
        result=dict(ok=True,mode=code,value=value)
        if code in(2,3):result["value_json"]=json.dumps(value,separators=(",",":"),ensure_ascii=True,allow_nan=False)
    except BaseException as e:result=dict(ok=False,error=exception(e))
    reply(0,encoded(result),generations[slot])
for pair in fds:
    for fd in pair:
        if fd is not None and fd not in closed:os.close(fd)
