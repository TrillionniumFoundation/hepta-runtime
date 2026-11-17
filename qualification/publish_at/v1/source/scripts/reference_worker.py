#!/usr/bin/env python3
"""Execute the exact original publish/expected/current/regular/metadata helpers."""
from pathlib import Path
import ast,copy,ctypes,hashlib,json,os,struct,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import encoded,decode,pin,require,sha
from protocol import U,stat_value,stat_encode,exception
SOURCE=Path(sys.argv[1]);target=SOURCE/"target/binary_file.py";raw=target.read_bytes()
namespace=dict(__name__="qualified_binary_original",__file__=str(target))
exec(compile(raw,str(target),"exec"),namespace)
module=ast.parse(raw)
helpers={n.name:ast.dump(n,include_attributes=False)for n in module.body if isinstance(n,ast.FunctionDef)
    and n.name in("publish","expected","current","regular","version")}
require(set(helpers)=={"publish","expected","current","regular","version"},"complete original publication helpers")
binding=dict(original=pin(target),metadata=pin(SOURCE/"target/file_metadata.py"),
    original_helper_ast_sha256={name:sha(value.encode())for name,value in sorted(helpers.items())},
    exact_publish_and_metadata_functions_unedited=True)
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
        n=os.write(fd,pending);require(n>0,"full original observer write");pending=pending[n:]
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
class Proxy:
    def __init__(self):
        self.observer=True;self.generation=0;self.calls={};self.operations={};self.arm=None;self.arm_seen=0;self.filters=0;self.open_roles={}
    def __getattr__(self,name):return getattr(os,name)
    def owner(self):
        frame=sys._getframe(2);names=[];metadata=False
        while frame is not None:
            names.append(frame.f_code.co_name)
            if frame.f_code.co_filename.endswith("file_metadata.py"):metadata=True
            frame=frame.f_back
        return "metadata"if metadata else"publish"
    def begin(self,generation,observer):
        self.generation=generation;self.observer=observer;self.calls={};self.operations={}
    def call(self,operation,fd,args,method,a=0,b=0):
        owner=self.owner();self.calls[owner]=self.calls.get(owner,0)+1;n=self.calls[owner]
        key=(owner,operation);self.operations[key]=self.operations.get(key,0)+1
        if self.observer:
            magic={"publish":b"HPUBHK01","metadata":b"HMDTHK01"}[owner]
            write(4,magic+struct.pack("<7Q",self.generation,n,n,operation,fd,a,b))
            require(read(5,8)==bytes(8),"original fixed ACK")
        if self.arm and owner=="publish"and operation==2 and args["regular_first"]:
            if self.open_roles.get(fd)==self.arm["role"]:
                self.arm_seen+=1
                if self.arm_seen==self.arm["occurrence"]:
                    require(self.observer,"fault input requires actual before-syscall witness")
                    real_fstat_error(fd);self.arm=None;self.filters+=1
        try:value=method()
        except BaseException as e:
            if self.observer:write(3,encoded(dict(owner=owner,generation=self.generation,call=n,operation=operation,
                fd=fd,args=args,ok=False,error=exception(e))))
            raise
        if self.observer:
            if isinstance(value,os.stat_result):stored=stat_value(value)
            elif isinstance(value,bytes):stored=dict(bytes_hex=value.hex())
            elif isinstance(value,list):stored=[os.fsencode(x).hex()for x in value]
            else:stored=value
            write(3,encoded(dict(owner=owner,generation=self.generation,call=n,operation=operation,fd=fd,args=args,ok=True,value=stored)))
        return value
    def open(self,path,flags,mode=0o777,*,dir_fd=None):
        frames=[];frame=sys._getframe(1)
        while frame is not None:frames.append(frame.f_code.co_name);frame=frame.f_back
        role=1 if "current"in frames else 2 if flags&os.O_RDWR else 3
        operation=6 if flags&os.O_RDWR else 1
        fd=self.call(operation,dir_fd,dict(path=path,flags=flags,mode=mode),lambda:os.open(path,flags,mode,dir_fd=dir_fd))
        self.open_roles[fd]=role
        return fd
    def fstat(self,fd):
        owner=self.owner();operation=1 if owner=="metadata"else 2
        return self.call(operation,fd,dict(regular_first=sys._getframe(1).f_code.co_name=="regular"),lambda:os.fstat(fd))
    def close(self,fd):
        try:return self.call(3,fd,{},lambda:os.close(fd))
        finally:self.open_roles.pop(fd,None)
    def geteuid(self):return self.call(5,0,{},lambda:os.geteuid())
    def fsync(self,fd):return self.call(8 if self.owner()=="metadata"else 7,fd,{},lambda:os.fsync(fd))
    def listxattr(self,fd):return self.call(2,fd,{},lambda:os.listxattr(fd))
    def getxattr(self,fd,name):return self.call(3,fd,dict(name_hex=os.fsencode(name).hex()),lambda:os.getxattr(fd,name))
    def fchown(self,fd,uid,gid):return self.call(4,fd,dict(uid=uid,gid=gid),lambda:os.fchown(fd,uid,gid),a=uid,b=gid)
    def fchmod(self,fd,mode):return self.call(5,fd,dict(mode=mode),lambda:os.fchmod(fd,mode),a=mode)
    def removexattr(self,fd,name):return self.call(6,fd,dict(name_hex=os.fsencode(name).hex()),lambda:os.removexattr(fd,name))
    def setxattr(self,fd,name,value,flags=0):
        return self.call(7,fd,dict(name_hex=os.fsencode(name).hex(),value_hex=value.hex(),flags=flags),lambda:os.setxattr(fd,name,value,flags),a=len(os.fsencode(name)),b=len(value))
    def link(self,src,dst,*,src_dir_fd=None,dst_dir_fd=None,follow_symlinks=True):
        require(src_dir_fd==dst_dir_fd and not follow_symlinks,"original fixed link call")
        return self.call(8,src_dir_fd,dict(source=src,destination=dst,follow_symlinks=follow_symlinks),
            lambda:os.link(src,dst,src_dir_fd=src_dir_fd,dst_dir_fd=dst_dir_fd,follow_symlinks=follow_symlinks),a=len(dst.encode())+1,b=len(src.encode())+1)
    def replace(self,src,dst,*,src_dir_fd=None,dst_dir_fd=None):
        require(src_dir_fd==dst_dir_fd,"original fixed replace call")
        return self.call(10,src_dir_fd,dict(source=src,destination=dst),
            lambda:os.replace(src,dst,src_dir_fd=src_dir_fd,dst_dir_fd=dst_dir_fd),a=len(dst.encode())+1,b=len(src.encode())+1)
    def unlink(self,path,*,dir_fd=None):
        return self.call(9,dir_fd,dict(path=path),lambda:os.unlink(path,dir_fd=dir_fd))
proxy=Proxy();namespace["os"]=proxy
# Import and exercise only module initialization before any RLIMIT_NOFILE input.
hashlib.sha256(b"loaded").digest();json.dumps(binding)
parents=[None,None];state=[None,None];generation=[0,0];closed=set();control=0
def reply(ret,data=b"",slot=0):
    write(1,b"HPUBFR01"+struct.pack("<7Q",ret&((1<<64)-1),len(data),state[slot]or 0,generation[slot],0,0,0)+data)
while True:
    head=read(control,8,True)
    if head is None:break
    size=U(head,0);require(64<=size<=134217792,"original frame extent");packet=read(control,size)
    require(packet[:8]==b"HPUBFQ01"and U(packet,24)==len(packet)-64 and packet[32:64]==bytes(32),"original full frame")
    command,slot=U(packet,8),U(packet,16);require(slot in(0,1),"original context slot");payload=packet[64:]
    if command in(8,9):
        require(not payload and state[slot]is None,"fresh original context");state[slot]=0;generation[slot]=0;reply(0,slot=slot);continue
    if command==10:
        require(parents[slot]is None and payload.endswith(b"\0")and b"\0"not in payload[:-1],"held parent input")
        fd=os.open(payload[:-1],os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW);parents[slot]=fd;closed.discard(fd)
        reply(fd,slot=slot);continue
    if command==14:
        require(parents[slot]is not None,"missing original parent")
        try:reply(0,stat_encode(os.fstat(parents[slot])),slot)
        except OSError as e:reply(-e.errno,slot=slot)
        continue
    if command in(12,16):
        fd=parents[slot];require(fd is not None,"missing parent close")
        try:os.close(fd);ret=0;closed.add(fd)
        except OSError as e:ret=-e.errno
        if command==12:parents[slot]=None
        reply(ret,slot=slot);continue
    if command==17:
        require(control==0,"control already moved");control=os.dup(0);os.close(0);closed.add(0);reply(0,slot=slot);continue
    if command==18:
        require(not proxy.arm and len(payload)==16,"fstat failure fixed arm");role,n=struct.unpack("<2Q",payload);require(role in(1,2,3)and 1<=n<=8,"fixed first-fstat selector");proxy.arm=dict(role=role,occurrence=n);proxy.arm_seen=0;reply(0,slot=slot);continue
    if command==2:
        require(state[slot]==2,"original result not live");state[slot]=0;reply(0,slot=slot);continue
    if command==3:
        require(state[slot]==0,"original logical context not idle");state[slot]=None;reply(0,slot=slot);continue
    require(command==1 and state[slot]==0 and parents[slot]is not None,"fixed original invocation")
    q=decode(payload);generation[slot]+=1;proxy.begin(generation[slot],q["observer"])
    try:
        value=namespace["publish"](parents[slot],q["basename"],q["tempname"],q["prior_value"])
        result=dict(ok=True,value=value,original_json=json.dumps(value,ensure_ascii=True,allow_nan=False))
    except BaseException as e:result=dict(ok=False,error=exception(e))
    result["binding"]=binding;result["actual_seccomp_filters"]=proxy.filters
    require(not q["arm_fstat_error"]or not proxy.arm,"frozen actual seccomp trigger was not reached")
    state[slot]=2;reply(0,encoded(result),slot)
for fd in parents:
    if fd is not None and fd not in closed:os.close(fd)
if control:os.close(control)
# Original leaked regular() FDs remain open here; only OS process exit retires them.
