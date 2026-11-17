#!/usr/bin/env python3
"""Call the unchanged original helpers and exact original locked write suite."""
from pathlib import Path
import ast,copy,ctypes,fcntl,hashlib,json,os,resource,signal,struct,sys,uuid
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import encoded,decode,pin,require,sha
from protocol import U,stat_value,stat_encode,exception
SOURCE=Path(sys.argv[1]).resolve(strict=True);target=SOURCE/"target/binary_file.py";raw=target.read_bytes()
namespace=dict(__name__="qualified_binary_original",__file__=str(target))
exec(compile(raw,str(target),"exec"),namespace)
module=ast.parse(raw);main=next(n for n in module.body if isinstance(n,ast.FunctionDef)and n.name=="main")
suite=next(n for n in main.body if isinstance(n,ast.Try)).body
op=next(n for n in suite if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=="op"for t in n.targets))
lockname=next(n for n in suite if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=="lockname"for t in n.targets))
locked=next(n for n in suite if isinstance(n,ast.With)and isinstance(n.items[0].optional_vars,ast.Name)
    and n.items[0].optional_vars.id=="lock")
require(isinstance(locked.body[1],ast.If)and ast.unparse(locked.body[1].test)=="op == 'write'",
    "exact original lock/body selection")
body=ast.FunctionDef(name="write_body",args=ast.arguments(posonlyargs=[],args=[ast.arg(arg=n)for n in("fd","name","q")],
    vararg=None,kwonlyargs=[],kw_defaults=[],kwarg=None,defaults=[]),
    body=[copy.deepcopy(op),copy.deepcopy(lockname),copy.deepcopy(locked)],decorator_list=[],type_params=[])
for original,copied in zip((op,lockname,locked),body.body):
    require(ast.dump(original,include_attributes=True)==ast.dump(copied,include_attributes=True),
        "original locked suite and all unreachable branches are byte-position-preserving AST copies")
wrapped=ast.fix_missing_locations(ast.Module(body=[body],type_ignores=[]))
exec(compile(wrapped,str(target),"exec"),namespace)
names=("regular","current","expected","all_write","fingerprint","publish","version","json_read","json_save")
helpers={n.name:ast.dump(n,include_attributes=False)for n in module.body if isinstance(n,ast.FunctionDef)and n.name in names}
require(set(helpers)==set(names),"all original helpers")
binding=dict(original=pin(target),metadata=pin(SOURCE/"target/file_metadata.py"),
    helper_ast_sha256={k:sha(v.encode())for k,v in sorted(helpers.items())},
    original_suite_ast_sha256={name:sha(ast.dump(n,include_attributes=True).encode())
        for name,n in(("op",op),("lockname",lockname),("locked_suite",locked))},
    exact_original_helpers_and_locked_suite=True,borrowed_parent_boundary=True,
    original_fdopen=dict(module=os.fdopen.__module__,qualname=os.fdopen.__qualname__),original_uuid_module=pin(Path(uuid.__file__)),
    signal_profile={str(n):int(signal.getsignal(n))for n in(signal.SIGPIPE,signal.SIGXFSZ)})
require(binding["signal_profile"]=={"13":1,"25":1},"original CPython signal-ignore profile")
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
        n=os.write(fd,pending);require(n>0,"complete original observer write");pending=pending[n:]
class Filter(ctypes.Structure):
    _fields_=[("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint)]
class Program(ctypes.Structure):_fields_=[("len",ctypes.c_ushort),("filter",ctypes.POINTER(Filter))]
libc=ctypes.CDLL(None,use_errno=True);libc.prctl.restype=ctypes.c_int;libc.syscall.restype=ctypes.c_long
def install(number,error,fd,match_fd):
    require(0<=number<=511 and 1<=error<=4095 and match_fd in(0,1),"fixed real syscall fault")
    require(not match_fd or 0<=fd<=2147483647,"fixed actual syscall FD")
    rows=[(0x20,0,0,0),(0x15,1 if match_fd else 3,0,number),
        (0x15,0 if match_fd else 2,3,262 if number==5 else number),
        (0x20,0,0,16),(0x15,0,1,fd&0xffffffff),(0x06,0,0,0x00050000|error),(0x06,0,0,0x7fff0000)]
    items=(Filter*7)(*(Filter(*r)for r in rows));program=Program(7,items)
    require(libc.prctl(38,1,0,0,0)==0,"actual no-new-privs")
    require(libc.syscall(317,1,0,ctypes.byref(program))==0,"actual seccomp errno filter")
    return dict(number=number,errno=error,fd=fd,match_fd=match_fd,bpf=rows)
class Proxy:
    def __init__(self):
        self.observer=True;self.generation=0;self.calls={};self.operations={};self.roles={}
        self.plans=[];self.plan_at=0;self.plan_seen=0;self.filters=[]
    def __getattr__(self,name):return getattr(os,name)
    def frames(self):
        frame=sys._getframe(2);rows=[]
        while frame is not None:
            rows.append((frame.f_code.co_name,frame.f_code.co_filename,frame.f_lineno));frame=frame.f_back
        return rows
    def owner(self,frames):
        if any(path.endswith("file_metadata.py")for _,path,_ in frames):return "metadata"
        if any(name=="publish"for name,_,_ in frames):return "publish"
        if any(name=="fingerprint"for name,_,_ in frames):return "read"
        return "write"
    def begin(self,generation,observer):
        self.generation=generation;self.observer=observer;self.calls={};self.operations={}
    def call(self,operation,fd,args,method,a=0,b=0,owner=None):
        frames=self.frames();owner=owner or self.owner(frames)
        caller=next((name for name,path,_ in frames if path==str(target)or path.endswith("file_metadata.py")),"observer")
        role=self.roles.get(fd,args.get("role"))
        self.calls[owner]=self.calls.get(owner,0)+1;n=self.calls[owner]
        key=(owner,operation);self.operations[key]=self.operations.get(key,0)+1
        witness=dict(owner=owner,generation=self.generation,call=n,operation=operation,fd=fd,args=args,caller=caller,role=role)
        if self.observer:
            magic={"write":b"HBWTHK01","publish":b"HPUBHK01","read":b"HBRDHK01","metadata":b"HMDTHK01","entropy":b"HENTHK01"}[owner]
            write(4,magic+struct.pack("<7Q",self.generation,n,n,operation,fd&((1<<64)-1),a,b))
            require(read(5,8)==bytes(8),"original zero-only ACK")
        if self.plan_at<len(self.plans):
            plan=self.plans[self.plan_at];selector=plan["original"]
            match=(owner==selector["owner"]and operation==selector["operation"]
                and("role"not in selector or role==selector["role"])
                and("caller"not in selector or caller==selector["caller"]))
            if match:
                self.plan_seen+=1
                if self.plan_seen==selector["occurrence"]:
                    require(self.observer,"fault plan needs before-real-effect observation")
                    native=plan["native"];row=install(native[4],native[5],fd,native[6])
                    self.filters.append(dict(plan_index=self.plan_at,selector=selector,witness=witness,installed=row))
                    self.plan_at+=1;self.plan_seen=0
        try:value=method()
        except BaseException as e:
            if self.observer:write(3,encoded(dict(witness,ok=False,error=exception(e))))
            raise
        if self.observer:
            if isinstance(value,os.stat_result):stored=stat_value(value)
            elif isinstance(value,bytes):stored=dict(bytes_hex=value.hex())
            elif isinstance(value,list):stored=[os.fsencode(x).hex()for x in value]
            elif isinstance(value,uuid.UUID):stored=dict(uuid_hex=value.hex)
            elif operation==20:stored=dict(type=type(value).__name__,fd=value.fileno(),mode=value.mode)
            else:stored=value
            write(3,encoded(dict(witness,ok=True,value=stored)))
        return value
    def open(self,path,flags,mode=0o777,*,dir_fd=None):
        frames=self.frames();owner=self.owner(frames)
        role="lock"if str(path).startswith(".hepta-lock-")else"temporary"if str(path).startswith(".hepta-write-")else"destination"
        operation=(6 if role=="lock"else 7 if role=="temporary"else 1)if owner=="write"else(6 if flags&os.O_RDWR else 1)
        fd=self.call(operation,dir_fd,dict(path=path,flags=flags,mode=mode,role=role),lambda:os.open(path,flags,mode,dir_fd=dir_fd))
        self.roles[fd]=role;return fd
    def fstat(self,fd):
        owner=self.owner(self.frames())
        return self.call(1 if owner=="metadata"else 2,fd,{},lambda:os.fstat(fd))
    def close(self,fd):
        try:return self.call(3,fd,{},lambda:os.close(fd))
        finally:self.roles.pop(fd,None)
    def geteuid(self):return self.call(5,0,{},lambda:os.geteuid())
    def fsync(self,fd):
        owner=self.owner(self.frames());op=8 if owner=="metadata"else 7 if owner=="publish"else 12
        return self.call(op,fd,{},lambda:os.fsync(fd))
    def write(self,fd,data):return self.call(11,fd,dict(bytes_hex=bytes(data).hex()),lambda:os.write(fd,data),a=len(data))
    def fdopen(self,fd,mode="r",*args,**kwargs):
        return self.call(20,fd,dict(mode=mode),lambda:os.fdopen(fd,mode,*args,**kwargs))
    def listxattr(self,fd):return self.call(2,fd,{},lambda:os.listxattr(fd))
    def getxattr(self,fd,name):return self.call(3,fd,dict(name_hex=os.fsencode(name).hex()),lambda:os.getxattr(fd,name))
    def fchown(self,fd,uid,gid):return self.call(4,fd,dict(uid=uid,gid=gid),lambda:os.fchown(fd,uid,gid),a=uid,b=gid)
    def fchmod(self,fd,mode):return self.call(5,fd,dict(mode=mode),lambda:os.fchmod(fd,mode),a=mode)
    def removexattr(self,fd,name):return self.call(6,fd,dict(name_hex=os.fsencode(name).hex()),lambda:os.removexattr(fd,name))
    def setxattr(self,fd,name,value,flags=0):
        return self.call(7,fd,dict(name_hex=os.fsencode(name).hex(),value_hex=value.hex(),flags=flags),
            lambda:os.setxattr(fd,name,value,flags),a=len(os.fsencode(name)),b=len(value))
    def link(self,src,dst,*,src_dir_fd=None,dst_dir_fd=None,follow_symlinks=True):
        require(src_dir_fd==dst_dir_fd and not follow_symlinks,"fixed original publication link")
        return self.call(8,src_dir_fd,dict(source=src,destination=dst,follow_symlinks=False),
            lambda:os.link(src,dst,src_dir_fd=src_dir_fd,dst_dir_fd=dst_dir_fd,follow_symlinks=False),a=len(dst.encode())+1,b=len(src.encode())+1)
    def replace(self,src,dst,*,src_dir_fd=None,dst_dir_fd=None):
        require(src_dir_fd==dst_dir_fd,"fixed original publication replace")
        return self.call(10,src_dir_fd,dict(source=src,destination=dst),
            lambda:os.replace(src,dst,src_dir_fd=src_dir_fd,dst_dir_fd=dst_dir_fd),a=len(dst.encode())+1,b=len(src.encode())+1)
    def unlink(self,path,*,dir_fd=None):
        op=9 if self.owner(self.frames())=="publish"else 13
        return self.call(op,dir_fd,dict(path=path),lambda:os.unlink(path,dir_fd=dir_fd))
proxy=Proxy()
class Fcntl:
    def __getattr__(self,name):return getattr(fcntl,name)
    def flock(self,fd,operation):
        require(operation==fcntl.LOCK_EX,"fixed original lock operation")
        return proxy.call(10,fd,{},lambda:fcntl.flock(fd,operation))
class UUID:
    def __getattr__(self,name):return getattr(uuid,name)
    def uuid4(self):return proxy.call(20,0,{},uuid.uuid4,owner="entropy")
namespace["os"]=proxy;namespace["fcntl"]=Fcntl();namespace["uuid"]=UUID()
# Initialization and dependency loading precede every fixed resource fault.
hashlib.sha256(b"loaded").digest();json.dumps(binding)
parents=[None,None];state=[None,None];generation=[0,0];control=0;eof_witness=False
def reply(ret,data=b"",slot=0):
    write(1,b"HBWTFR01"+struct.pack("<7Q",ret&((1<<64)-1),len(data),state[slot]or 0,generation[slot],0,0,0)+data)
while True:
    head=read(control,8,True)
    if head is None:break
    size=U(head,0);require(64<=size<=134217792,"original complete private frame extent");packet=read(control,size)
    require(packet[:8]==b"HBWTFQ01"and U(packet,24)==len(packet)-64 and packet[32:64]==bytes(32),"original full private frame")
    command,slot=U(packet,8),U(packet,16);require(slot in(0,1),"original logical context slot");payload=packet[64:]
    if command in(8,9):
        require(not payload and state[slot]is None,"fresh original logical context")
        state[slot]=0;generation[slot]=0;reply(0,slot=slot);continue
    if command==10:
        require(parents[slot]is None and payload.endswith(b"\0")and b"\0"not in payload[:-1],"owned held parent input")
        parents[slot]=os.open(payload[:-1],os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
        reply(parents[slot],slot=slot);continue
    if command==14:
        require(parents[slot]is not None,"missing original parent")
        try:reply(0,stat_encode(os.fstat(parents[slot])),slot)
        except OSError as e:reply(-e.errno,slot=slot)
        continue
    if command in(12,16):
        fd=parents[slot];require(fd is not None,"missing original parent close")
        try:os.close(fd);ret=0
        except OSError as e:ret=-e.errno
        if command==12:parents[slot]=None
        reply(ret,slot=slot);continue
    if command==17:
        require(control==0,"original control pipe already moved")
        control=os.dup(0);os.close(0);reply(0,slot=slot);continue
    if command==18:
        require(proxy.plan_at==len(proxy.plans),"unused original fault plan")
        value=decode(payload);require(1<=len(value)<=4,"fixed bounded actual fault plans")
        proxy.plans=value;proxy.plan_at=0;proxy.plan_seen=0;reply(0,slot=slot);continue
    if command==23:
        require(not payload,"original EOF witness command payload")
        eof_witness=True;reply(0,slot=slot);continue
    if command==24:
        require(len(payload)==8 and U(payload,0)<=1048576,"actual regular-file size resource bound")
        resource.setrlimit(resource.RLIMIT_FSIZE,(U(payload,0),U(payload,0)));reply(0,slot=slot);continue
    if command==2:
        require(state[slot]==2,"original result not live");state[slot]=0;reply(0,slot=slot);continue
    if command==3:
        require(state[slot]==0,"original logical context not idle");state[slot]=None;reply(0,slot=slot);continue
    require(command==1 and state[slot]==0 and parents[slot]is not None,"fixed original write invocation")
    q=decode(payload);require(q["op"]=="write","exact write-only private qualification")
    generation[slot]+=1;proxy.begin(generation[slot],q["observer"])
    try:
        value=namespace["write_body"](parents[slot],q["basename"],q)
        result=dict(ok=True,value=value,original_json=json.dumps(value,ensure_ascii=True,allow_nan=False))
    except BaseException as e:result=dict(ok=False,error=exception(e))
    result["binding"]=binding;result["actual_seccomp_filters"]=list(proxy.filters)
    result["unused_fault_plans"]=len(proxy.plans)-proxy.plan_at
    state[slot]=2;reply(0,encoded(result),slot)
for fd in parents:
    if fd is not None:
        try:os.close(fd)
        except OSError as e:
            if e.errno!=9:raise
if control:os.close(control)
if eof_witness:
    # No reference pool is fabricated: /proc and actual syscall evidence bind survivors.
    write(4,b"HBWTEOF1"+bytes(56));require(read(5,8)==bytes(8),"original EOF zero-only ACK")
# The actual CPython device cache and leaked regular/FileIO FDs survive to OS exit.
