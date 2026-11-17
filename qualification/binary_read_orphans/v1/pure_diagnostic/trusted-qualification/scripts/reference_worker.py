#!/usr/bin/env python3
"""Unedited original read/fingerprint/regular and exact private-read branch."""
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
    and any(isinstance(v,ast.Constant)and v.value=="private_read"for v in n.test.comparators)]
require(len(branches)==1,"unique actual original private-read branch")
body=copy.deepcopy(branches[0].body)
fn=ast.FunctionDef(name="private_at",args=ast.arguments(posonlyargs=[],args=[ast.arg(arg=x)for x in("fd","name")],
    vararg=None,kwonlyargs=[],kw_defaults=[],kwarg=None,defaults=[]),body=body,decorator_list=[])
wrapper=ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[]))
branch=lambda b:ast.dump(ast.Module(body=b,type_ignores=[]),include_attributes=False)
require(branch(body)==branch(branches[0].body),"original private branch AST changed")
exec(compile(wrapper,str(target)+"#private_at","exec"),namespace)
binding=dict(original=pin(target),metadata=pin(SOURCE/"target/file_metadata.py"),
    private_branch_ast_sha256=sha(branch(body).encode()),exact_private_branch=True,
    fingerprint_regular_parent_main_functions_unedited=True)
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
    def seek(self,offset,whence=0):
        return self.proxy.call(19,self.fileno(),dict(offset=offset,whence=whence),lambda:self.file.seek(offset,whence),a=offset)
    def __exit__(self,*args):
        fd=self.fileno();return self.proxy.call(5,fd,{},lambda:self.file.__exit__(*args))
class Proxy:
    def __init__(self):
        self.observer=True;self.generation=0;self.calls=0;self.operations={};self.arm=0;self.filters=0
    def __getattr__(self,name):return getattr(os,name)
    def begin(self,generation,observer):
        self.generation=generation;self.observer=observer;self.calls=0;self.operations={}
    def call(self,operation,fd,args,method,a=0,b=0):
        self.calls+=1;n=self.calls;self.operations[operation]=self.operations.get(operation,0)+1
        if self.observer:
            write(4,b"HBRDHK01"+struct.pack("<7Q",self.generation,n,n,operation,fd,a,b))
            require(read(5,8)==bytes(8),"original fixed ACK")
        if self.arm and operation==6 and self.operations[6]==self.arm:
            require(self.observer,"fault input requires actual before-syscall witness")
            real_fstat_error(fd);self.arm=0;self.filters+=1
        try:value=method()
        except BaseException as e:
            if self.observer:write(3,encoded(dict(owner="read",generation=self.generation,call=n,operation=operation,
                fd=fd,args=args,ok=False,error=exception(e))))
            raise
        if self.observer:
            if isinstance(value,os.stat_result):stored=stat_value(value)
            elif isinstance(value,bytes):stored=dict(bytes_hex=value.hex())
            else:stored=value
            write(3,encoded(dict(owner="read",generation=self.generation,call=n,operation=operation,
                fd=fd,args=args,ok=True,value=stored)))
        return value
    def open(self,path,flags,mode=0o777,*,dir_fd=None):
        operation=(1 if path=="/"else 2)if flags&os.O_DIRECTORY else 3
        return self.call(operation,0 if dir_fd is None else dir_fd,
            dict(path=path,flags=flags,mode=mode),lambda:os.open(path,flags,mode,dir_fd=dir_fd))
    def fstat(self,fd):return self.call(6,fd,{},lambda:os.fstat(fd))
    def close(self,fd):return self.call(5,fd,{},lambda:os.close(fd))
    def geteuid(self):return self.call(9,0,{},lambda:os.geteuid())
    def fdopen(self,fd,*args,**kw):return ObservedFile(os.fdopen(fd,*args,**kw),self)
proxy=Proxy();namespace["os"]=proxy
hashlib.sha256(b"loaded").digest();json.dumps(binding)
parents=[None,None];state=[None,None];generation=[0,0];closed=set();control=0;eof_witness=False
def reply(ret,data=b"",slot=0):
    write(1,b"HBRDFR01"+struct.pack("<7Q",ret&((1<<64)-1),len(data),state[slot]or 0,generation[slot],0,0,0)+data)
while True:
    head=read(control,8,True)
    if head is None:break
    size=U(head,0);require(64<=size<=134217792,"original frame extent");packet=read(control,size)
    require(packet[:8]==b"HBRDFQ01"and U(packet,24)==len(packet)-64 and packet[32:64]==bytes(32),"original full frame")
    command,slot=U(packet,8),U(packet,16);require(slot in(0,1),"original context slot");payload=packet[64:]
    if command in(8,9):
        require(not payload and state[slot]is None,"fresh original context");state[slot]=0;generation[slot]=0;reply(0,slot=slot);continue
    if command==10:
        require(parents[slot]is None and payload.endswith(b"\0")and b"\0"not in payload[:-1],"held parent input")
        fd=os.open(payload[:-1],os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW);parents[slot]=fd;closed.discard(fd)
        reply(fd,slot=slot);continue
    if command==13:
        require(parents[slot]is not None,"missing original parent")
        try:reply(0,stat_encode(os.fstat(parents[slot])),slot)
        except OSError as e:reply(-e.errno,slot=slot)
        continue
    if command in(12,21):
        fd=parents[slot];require(fd is not None,"missing parent close")
        try:os.close(fd);ret=0;closed.add(fd)
        except OSError as e:ret=-e.errno
        if command==12:parents[slot]=None
        reply(ret,slot=slot);continue
    if command==17:
        require(control==0,"control already moved");control=os.dup(0);os.close(0);closed.add(0);reply(0,slot=slot);continue
    if command in(15,16,23):
        require(not proxy.arm,"fstat failure already armed");proxy.arm={15:1,16:2,23:3}[command];reply(0,slot=slot);continue
    if command==22:
        require(not eof_witness,"EOF already armed");eof_witness=True;reply(0,slot=slot);continue
    if command==2:
        require(state[slot]==2,"original result not live");state[slot]=0;reply(0,slot=slot);continue
    if command==3:
        require(state[slot]==0,"original logical context not idle");state[slot]=None;reply(0,slot=slot);continue
    require(command in(1,11)and state[slot]==0 and parents[slot]is not None,"fixed original invocation")
    q=decode(payload);generation[slot]+=1;proxy.begin(generation[slot],q["observer"])
    require((command==11)==(q["entry"]=="at"),"actual original entry binding")
    try:
        if q["entry"]=="at":
            require(q["mode"]in("fingerprint","private"),"fixed borrowed entry mode")
            value=namespace["fingerprint"if q["mode"]=="fingerprint"else"private_at"](parents[slot],q["request"]["name"])
        elif q["mode"]=="fingerprint":
            fd,name=namespace["parent"](q["request"]["root"],q["request"]["path"])
            try:value=namespace["fingerprint"](fd,name)
            finally:proxy.close(fd)
        else:value=namespace["main"](q["request"])
        value=dict(ok=True,value=value,original_json=json.dumps(value,ensure_ascii=True,allow_nan=False))
    except BaseException as e:value=dict(ok=False,error=exception(e))
    value["binding"]=binding;value["actual_seccomp_filters"]=proxy.filters
    require(q["arm"]is None or not proxy.arm,"frozen actual seccomp trigger was not reached")
    state[slot]=2;reply(0,encoded(value),slot)
for fd in parents:
    if fd is not None and fd not in closed:os.close(fd)
if eof_witness:
    write(4,b"HBRDEOF1"+bytes(56));require(read(5,8)==bytes(8),"original pre-exit ACK")
if control:os.close(control)
# The exact original leaked regular() FDs remain open until whole OS process exit.
