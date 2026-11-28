#!/usr/bin/env python3
"""Unedited original helpers and exact AST copy of main's info branch."""
from pathlib import Path
import ast,copy,ctypes,hashlib,json,os,struct,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import encoded,decode,pin,require,sha
from protocol import U,stat_value,stat_encode,exception
SOURCE=Path(sys.argv[1]);target=SOURCE/"target/binary_file.py";raw=target.read_bytes()
namespace=dict(__name__="qualified_binary_original",__file__=str(target))
exec(compile(raw,str(target),"exec"),namespace)
module=ast.parse(raw);main=next(n for n in module.body if isinstance(n,ast.FunctionDef)and n.name=="main")
branches=[n for n in ast.walk(main)if isinstance(n,ast.If)and isinstance(n.test,ast.Compare)
    and isinstance(n.test.left,ast.Name)and n.test.left.id=="op"
    and any(isinstance(v,ast.Constant)and v.value=="info"for v in n.test.comparators)]
require(len(branches)==1,"unique actual original info branch")
body=copy.deepcopy(branches[0].body)
fn=ast.FunctionDef(name="info_at",args=ast.arguments(posonlyargs=[],args=[ast.arg(arg=x)for x in("fd","name","q")],
    vararg=None,kwonlyargs=[],kw_defaults=[],kwarg=None,defaults=[]),body=body,decorator_list=[])
wrapper=ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[]))
branch=lambda b:ast.dump(ast.Module(body=b,type_ignores=[]),include_attributes=False)
require(branch(body)==branch(branches[0].body),"original branch AST changed")
exec(compile(wrapper,str(target)+"#info_at","exec"),namespace)
binding=dict(original=pin(target),metadata=pin(SOURCE/"target/file_metadata.py"),
    info_branch_ast_sha256=sha(branch(body).encode()),exact_info_branch=True,
    fingerprint_regular_version_and_metadata_functions_unedited=True)
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
class ObservedFile:
    def __init__(self,file,proxy):self.file=file;self.proxy=proxy
    def __enter__(self):self.file.__enter__();return self
    def fileno(self):return self.file.fileno()
    def read(self,size=-1):
        return self.proxy.call(11,self.fileno(),dict(count=size),lambda:self.file.read(size),a=size)
    def __exit__(self,*args):
        fd=self.fileno();return self.proxy.call(5,fd,{},lambda:self.file.__exit__(*args))
class Proxy:
    def __init__(self):
        self.observer=True;self.generation=0;self.calls={};self.operations={};self.arm=False;self.filters=0
    def __getattr__(self,name):return getattr(os,name)
    def owner(self):
        frame=sys._getframe(2);names=[];metadata=False
        while frame is not None:
            names.append(frame.f_code.co_name)
            if frame.f_code.co_filename.endswith("file_metadata.py"):metadata=True
            frame=frame.f_back
        return "metadata"if metadata else"read"if "fingerprint"in names else"info"
    def begin(self,generation,observer):
        self.generation=generation;self.observer=observer;self.calls={};self.operations={}
    def call(self,operation,fd,args,method,a=0,b=0):
        owner=self.owner();self.calls[owner]=self.calls.get(owner,0)+1;n=self.calls[owner]
        key=(owner,operation);self.operations[key]=self.operations.get(key,0)+1
        if self.observer:
            magic={"info":b"HINFHK01","read":b"HBRDHK01","metadata":b"HMDTHK01"}[owner]
            write(4,magic+struct.pack("<7Q",self.generation,n,n,operation,fd,a,b))
            require(read(5,8)==bytes(8),"original fixed ACK")
        if self.arm and owner=="info"and operation==2 and self.operations[key]==1:
            require(self.observer,"fault input requires actual before-syscall witness")
            real_fstat_error(fd);self.arm=False;self.filters+=1
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
        owner=self.owner();op=3 if owner=="read"else 1
        return self.call(op,dir_fd,dict(path=path,flags=flags,mode=mode),lambda:os.open(path,flags,mode,dir_fd=dir_fd))
    def fstat(self,fd):
        owner=self.owner();op={"read":6,"info":2,"metadata":1}[owner]
        return self.call(op,fd,{},lambda:os.fstat(fd))
    def close(self,fd):
        op=5 if self.owner()=="read"else 3
        return self.call(op,fd,{},lambda:os.close(fd))
    def fdopen(self,fd,*args,**kw):return ObservedFile(os.fdopen(fd,*args,**kw),self)
    def listxattr(self,fd):return self.call(2,fd,{},lambda:os.listxattr(fd))
    def getxattr(self,fd,name):return self.call(3,fd,dict(name_hex=os.fsencode(name).hex()),lambda:os.getxattr(fd,name))
proxy=Proxy();namespace["os"]=proxy
# Import and exercise only module initialization before any RLIMIT_NOFILE input.
hashlib.sha256(b"loaded").digest();json.dumps(binding)
parents=[None,None];state=[None,None];generation=[0,0];closed=set();control=0
def reply(ret,data=b"",slot=0):
    write(1,b"HIFXFR01"+struct.pack("<7Q",ret&((1<<64)-1),len(data),state[slot]or 0,generation[slot],0,0,0)+data)
while True:
    head=read(control,8,True)
    if head is None:break
    size=U(head,0);require(64<=size<=134217792,"original frame extent");packet=read(control,size)
    require(packet[:8]==b"HIFXFQ01"and U(packet,24)==len(packet)-64 and packet[32:64]==bytes(32),"original full frame")
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
        require(not proxy.arm,"fstat failure already armed");proxy.arm=True;reply(0,slot=slot);continue
    if command==2:
        require(state[slot]==2,"original result not live");state[slot]=0;reply(0,slot=slot);continue
    if command==3:
        require(state[slot]==0,"original logical context not idle");state[slot]=None;reply(0,slot=slot);continue
    require(command==1 and state[slot]==0 and parents[slot]is not None,"fixed original invocation")
    q=decode(payload);generation[slot]+=1;proxy.begin(generation[slot],q["observer"])
    try:
        value=namespace["info_at"](parents[slot],q["basename"],dict(path=q["original_path"]))
        result=dict(ok=True,value=value,original_json=json.dumps(value,ensure_ascii=True,allow_nan=False))
    except BaseException as e:result=dict(ok=False,error=exception(e))
    result["binding"]=binding;result["actual_seccomp_filters"]=proxy.filters
    require(not q["arm_fstat_error"]or not proxy.arm,"frozen actual seccomp trigger was not reached")
    state[slot]=2;reply(0,encoded(result),slot)
for fd in parents:
    if fd is not None and fd not in closed:os.close(fd)
if control:os.close(control)
# Original leaked regular() FDs remain open here; only OS process exit retires them.
