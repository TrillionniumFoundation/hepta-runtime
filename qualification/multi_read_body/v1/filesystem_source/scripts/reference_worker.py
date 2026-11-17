#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Execute the unchanged target multi_read and binary parent/regular functions."""
from pathlib import Path
import ast,ctypes,hashlib,json,os,struct,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import encoded,decode,pin,require,sha
from protocol import U,exception,stat_value
SOURCE=Path(sys.argv[1]);binary=SOURCE/"target/binary_file.py";multi=SOURCE/"target/multi_read_host.py"
namespace=dict(__name__="qualified_original_multi_read",__file__=str(binary))
exec(compile(binary.read_bytes(),str(binary),"exec"),namespace)
namespace["__file__"]=str(multi)
exec(compile(multi.read_bytes(),str(multi),"exec"),namespace)
def asts(path,names):
    nodes={n.name:n for n in ast.parse(path.read_bytes()).body if isinstance(n,ast.FunctionDef)}
    return {name:sha(ast.dump(nodes[name],include_attributes=False).encode())for name in names}
binding=dict(binary=pin(binary),multi=pin(multi),metadata=pin(SOURCE/"target/file_metadata.py"),
    binary_functions=asts(binary,("parent","regular","version")),
    multi_functions=asts(multi,("_batch_path","_wire_size","multi_read","run_multi_read")),
    original_functions_unmodified=True,observation_only_at_real_os_boundary=True)
def read(fd,size,eof=False):
    raw=b""
    while len(raw)<size:
        part=os.read(fd,size-len(raw))
        if not part:
            if eof and not raw:return None
            raise ValueError("original fixture premature EOF")
        raw+=part
    return raw
def write(fd,raw):
    pending=memoryview(raw)
    while pending:
        n=os.write(fd,pending);require(n>0,"full original write");pending=pending[n:]
class Filter(ctypes.Structure):_fields_=[("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint)]
class Program(ctypes.Structure):_fields_=[("len",ctypes.c_ushort),("filter",ctypes.POINTER(Filter))]
libc=ctypes.CDLL(None,use_errno=True);libc.prctl.restype=ctypes.c_int;libc.syscall.restype=ctypes.c_long
def real_fstat_error(fd):
    require(0<=fd<=2147483647,"fixed kernel-error FD")
    filters=(Filter*7)(Filter(0x20,0,0,0),Filter(0x15,1,0,5),Filter(0x15,0,3,262),
        Filter(0x20,0,0,16),Filter(0x15,0,1,fd),Filter(0x06,0,0,0x00050005),Filter(0x06,0,0,0x7fff0000))
    program=Program(7,filters)
    require(libc.prctl(38,1,0,0,0)==0,"actual no-new-privs")
    require(libc.syscall(317,1,0,ctypes.byref(program))==0,"actual seccomp fstat filter")
MAGIC={"body":b"HMRDHK01","parent0":b"HPD0HK01","parent1":b"HPD1HK01"}
class Proxy:
    def __init__(self):
        self.observer=True;self.owner="body";self.generation=0;self.calls={};self.parent_generations=[0,0]
        self.parent_count=0;self.fstats=0;self.arm=None;self.filters=0;self.fd_owners={}
    def __getattr__(self,name):return getattr(os,name)
    def begin(self,generation,observer):
        self.generation=generation;self.observer=observer;self.owner="body";self.calls={"body":0}
        self.parent_count=0;self.fstats=0
    def call(self,owner,operation,fd,args,method,a=0,b=0):
        n=self.calls.get(owner,0)+1;self.calls[owner]=n
        generation=self.generation if owner=="body"else self.parent_generations[int(owner[-1])]
        if self.observer:
            write(4,MAGIC[owner]+struct.pack("<7Q",generation,n,n,operation,fd,a,b))
            require(read(5,8)==bytes(8),"fixed original ACK")
        if owner=="body"and operation==2:
            self.fstats+=1
            if self.arm is not None:
                wanted={(23,0):1,(31,0):2,(41,0):3,(23,1):4,(61,1):5}[self.arm]
                if self.fstats==wanted:
                    require(self.observer,"actual fault requires real barrier")
                    real_fstat_error(fd);self.arm=None;self.filters+=1
        try:value=method()
        except BaseException as e:
            if self.observer:write(3,encoded(dict(owner=owner,generation=generation,call=n,
                operation=operation,fd=fd,args=args,ok=False,error=exception(e))))
            raise
        if self.observer:
            if isinstance(value,os.stat_result):stored=stat_value(value)
            elif isinstance(value,bytes):stored=dict(bytes_hex=value.hex())
            else:stored=value
            write(3,encoded(dict(owner=owner,generation=generation,call=n,
                operation=operation,fd=fd,args=args,ok=True,value=stored)))
        return value
    def open(self,path,flags,mode=0o777,*,dir_fd=None):
        owner=self.owner;operation=(1 if dir_fd is None else 2)if flags&os.O_DIRECTORY else 1
        value=self.call(owner,operation,0 if dir_fd is None else dir_fd,
            dict(path=path,flags=flags,mode=mode),lambda:os.open(path,flags,mode,dir_fd=dir_fd))
        self.fd_owners[value]=owner;return value
    def fstat(self,fd):return self.call("body",2,fd,{},lambda:os.fstat(fd))
    def read(self,fd,size):return self.call("body",5,fd,dict(count=size),lambda:os.read(fd,size),a=size)
    def close(self,fd):
        owner=self.fd_owners.get(fd,self.owner);op=3 if owner=="body"else 5
        try:return self.call(owner,op,fd,{},lambda:os.close(fd))
        finally:self.fd_owners.pop(fd,None)
proxy=Proxy();namespace["os"]=proxy;original_parent=namespace["parent"]
def observed_parent(root,path):
    slot=proxy.parent_count%2;proxy.parent_count+=1;owner="parent"+str(slot)
    proxy.parent_generations[slot]+=1;proxy.calls[owner]=0;prior=proxy.owner;proxy.owner=owner
    try:return original_parent(root,path)
    finally:proxy.owner=prior
namespace["parent"]=observed_parent
hashlib.sha256(b"loaded").digest();json.dumps(binding)
state=[None,None];generation=[0,0];control=0
def reply(ret,data=b"",slot=0):
    write(1,b"HMRDFR01"+struct.pack("<7Q",ret&((1<<64)-1),len(data),
        state[slot]or 0,generation[slot]if state[slot]is not None else 0,0,0,0)+data)
while True:
    header=read(control,8,True)
    if header is None:break
    size=U(header,0);require(64<=size<=134217792,"original full frame size");packet=read(control,size)
    require(packet[:8]==b"HMRDFQ01"and U(packet,24)==len(packet)-64 and packet[32:64]==bytes(32),"original full frame")
    command,slot=U(packet,8),U(packet,16);require(slot in(0,1),"original context slot");payload=packet[64:]
    if command in(8,9):
        require(not payload and state[slot]is None,"fresh original context")
        state[slot]=0;generation[slot]=0;reply(0,slot=slot);continue
    if command==17:
        require(control==0,"control already moved");control=os.dup(0);os.close(0);reply(0,slot=slot);continue
    if command==18:
        require(len(payload)==16 and proxy.arm is None,"single real fault arm")
        phase,role=struct.unpack("<2Q",payload);require((phase,role)in((23,0),(31,0),(41,0),(23,1),(61,1)),"frozen fstat phase")
        proxy.arm=(phase,role);reply(0,slot=slot);continue
    if command==2:
        require(state[slot]==2,"original result not live");state[slot]=0;reply(0,slot=slot);continue
    if command==3:
        require(state[slot]==0,"original context not idle");state[slot]=None;reply(0,slot=slot);continue
    require(command==1 and state[slot]==0,"fixed original invocation")
    q=decode(payload);generation[slot]+=1;proxy.begin(generation[slot],q["observer"])
    try:
        value=namespace["multi_read"](q["request"])
        raw_json=json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"))
        value=dict(ok=True,value=value,raw_json=raw_json)
    except BaseException as e:
        value=dict(ok=False,error=exception(e),diagnostic=type(e).__name__+": "+str(e))
        if isinstance(e,UnicodeDecodeError):
            value["error"].update(start=e.start,end=e.end,reason=e.reason,object_hex=e.object.hex(),encoding=e.encoding)
    value["binding"]=binding;value["actual_seccomp_filters"]=proxy.filters
    require(q["fault"]is None or proxy.arm is None,"frozen kernel fault was not reached")
    state[slot]=2;reply(0,encoded(value),slot)
# The unchanged original finally blocks already ran. Their first-fstat leaked FDs
# remain physically open through every logical context release/destroy and EOF.
if control:os.close(control)
write(4,b"HMRDEOF1"+bytes(56));require(read(5,8)==bytes(8),"original pre-exit ACK")
