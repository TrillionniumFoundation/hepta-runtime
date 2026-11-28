#!/usr/bin/env python3
"""Actual unchanged CPython or fixed HIA native owner; observation never supplies results."""
from pathlib import Path
import argparse,ctypes,fcntl,hashlib,json,mmap,os,resource,stat,struct,sys,uuid
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import decode,encoded,pin,require,sha
from protocol import HEADER,MASK,exception,request,u
class Filter(ctypes.Structure):
    _fields_=[("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_=[("len",ctypes.c_ushort),("filter",ctypes.POINTER(Filter))]
LIBC=ctypes.CDLL(None,use_errno=True)
LIBC.prctl.restype=ctypes.c_int
LIBC.syscall.restype=ctypes.c_long
LIBC.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
LIBC.mmap.restype=ctypes.c_void_p
def write(fd,raw):
    pending=memoryview(raw)
    while pending:
        n=os.write(fd,pending);require(n>0,"complete observation write");pending=pending[n:]
def install(numbers,number,conditions=()):
    require(all(0<=n<512 for n in numbers)and 0<=number<=4095,"fixed real fault")
    rows=[(0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,0x80000000)]
    for call in numbers:
        rows.extend([(0x20,0,0,0),(0x15,0,2*len(conditions)+1,call)])
        for j,(arg,value)in enumerate(conditions):
            require(0<=arg<=5 and 0<=value<1<<32,"fixed syscall selector")
            rows.extend([(0x20,0,0,16+8*arg),(0x15,0,2*(len(conditions)-j-1)+1,value)])
        rows.append((0x06,0,0,0x00050000|number))
    rows.append((0x06,0,0,0x7fff0000))
    items=(Filter*len(rows))(*(Filter(*r)for r in rows));program=Program(len(rows),items)
    require(LIBC.prctl(38,1,0,0,0)==0,"actual no-new-privs")
    require(LIBC.syscall(317,1,0,ctypes.byref(program))==0,"actual seccomp fault installation")
    return dict(numbers=list(numbers),errno=number,conditions=[list(x)for x in conditions],bpf=[list(x)for x in rows])
def fd_snapshot():
    rows={}
    for fd in range(128):
        path="/proc/self/fd/"+str(fd)
        try:
            name=os.readlink(path);s=os.stat(path);flags=fcntl.fcntl(fd,fcntl.F_GETFD)
        except OSError as e:
            if e.errno in(2,9):continue
            raise
        rows[str(fd)]=dict(target=name,dev=s.st_dev,inode=s.st_ino,mode=s.st_mode,links=s.st_nlink,
            uid=s.st_uid,gid=s.st_gid,size=s.st_size,cloexec=bool(flags&fcntl.FD_CLOEXEC))
    return rows
class Journal:
    def __init__(self,fd):
        self.fd=fd;self.bytes=0;self.count=0;self.digest=hashlib.sha256();self.errors=[]
    def emit(self,kind,context,pointer,raw):
        state=ctypes.string_at(context,4096)if context else b""
        frame=HEADER.pack(b"HENTEV01",kind,context,pointer,len(raw),len(state))+state+raw
        write(self.fd,frame);self.digest.update(frame);self.bytes+=len(frame);self.count+=1
    def callback(self,opaque,context,kind,pointer,size):
        try:
            require(opaque==0 and context and size<=1048576,"fixed observational callback")
            self.emit(kind,context,pointer,ctypes.string_at(pointer,size));return 0
        except BaseException as e:
            self.errors.append(type(e).__name__+": "+str(e));return 1
    def pin(self):return dict(bytes=self.bytes,sha256=self.digest.hexdigest(),events=self.count)
class Native:
    def __init__(self,build,binding,journal,observer):
        meta=decode((build/"BUILD.json").read_bytes());raw=(build/"binary-entropy-callable.elf").read_bytes()
        require(dict(bytes=len(raw),sha256=sha(raw))==binding["elf"]==meta["executable"],"actual fixed executable")
        self.build=meta;fd=os.memfd_create("hia-entropy-qualified-image",os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        try:
            write(fd,raw);seals=15;fcntl.fcntl(fd,1033,seals)
            require(fcntl.fcntl(fd,1034)&seals==seals,"all four kernel image seals")
            self.base=LIBC.mmap(None,len(raw),mmap.PROT_READ|mmap.PROT_EXEC,mmap.MAP_PRIVATE,fd,0)
            require(self.base not in(None,ctypes.c_void_p(-1).value),"sealed complete image mapping")
        finally:os.close(fd)
        def entry(name,count):
            at=meta["exports"][name]
            require(type(at)is int and 0<=at<len(raw)-256,"fixed exported image entry")
            return ctypes.CFUNCTYPE(ctypes.c_uint64,*([ctypes.c_void_p]*count))(self.base+256+at)
        self.callback_type=ctypes.CFUNCTYPE(ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64,
            ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64)
        self.callback=self.callback_type(journal.callback)
        self.create=entry("binary_entropy_create",3);self.invoke=entry("binary_entropy_invoke",3)
        self.release=entry("binary_entropy_release",1);self.pool_create=entry("hia_process_orphans_create",0)
        self.pool=self.pool_create();require(0<self.pool<(1<<63),"actual shared pool creation")
        callback=ctypes.cast(self.callback,ctypes.c_void_p).value if observer else 0
        self.callback_address=callback
        self.context=self.create(callback,0,self.pool)
        require(0<self.context<(1<<63),"actual entropy context creation")
        self.journal=journal
    def snapshot(self):
        c=ctypes.string_at(self.context,4096)
        for kind,offset in((20,88),(21,104),(22,64),(23,120)):
            at,size=u(c,offset),u(c,offset+8)
            require(at and size==4096,"actual fixed arena extent")
            self.journal.emit(kind,self.context,at,ctypes.string_at(at,size))
        self.journal.emit(24,self.context,self.pool,ctypes.string_at(self.pool,4096))
        page=u(ctypes.string_at(self.pool,4096),32);seen=set()
        while page:
            require(page not in seen and len(seen)<128,"complete ordinary orphan page chain")
            seen.add(page);raw=ctypes.string_at(page,4096);self.journal.emit(25,self.context,page,raw);page=u(raw,16)
    def call(self,mode):
        raw=request(mode);packet=ctypes.create_string_buffer(raw,len(raw));at=ctypes.addressof(packet)
        self.journal.emit(30,self.context,at,raw);code=self.invoke(self.context,at,len(raw))
        self.journal.emit(31,self.context,at,bytes(packet));self.snapshot()
        c=ctypes.string_at(self.context,4096);used=u(c,168)
        payload=ctypes.string_at(u(c,104),used)if 0<used<=4096 else b""
        released=self.release(self.context)if code==64 and u(c,56)==2 else None
        work=u(ctypes.string_at(self.context,4096),88)
        self.journal.emit(26,self.context,work,ctypes.string_at(work,4096))
        return dict(native_return=code,state_before_release=u(c,56),release_return=released,
            response_hex=payload.hex(),context=self.context,pool=self.pool)
def main():
    p=argparse.ArgumentParser()
    for name in("source","build","output","runtime"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--role",choices=["native","original"],required=True);p.add_argument("--case",required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);out=a.output.resolve(strict=True)
    domain=decode((source/"DOMAIN.json").read_bytes());case=next(q for q in domain["cases"]if q["name"]==a.case)
    runtime=decode((a.runtime/"BINDING.json").read_bytes())
    require(pin(Path(sys.executable).resolve())==runtime["python"] and pin(Path(uuid.__file__))==runtime["uuid"],
        "actual original interpreter and UUID module")
    binding=decode((source/"BUILD_REUSE.json").read_bytes())
    event_fd=os.open(out/"events.bin",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o644)
    result_fd=os.open(out/"results.jsonl",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o644)
    foreign_fd=os.open(out/"foreign-file",os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600)
    write(foreign_fd,b"foreign descriptor must survive cache replacement\n")
    journal=Journal(event_fd);native=Native(a.build,binding,journal,case["observer"])if a.role=="native"else None
    original_urandom=os.urandom;original_uuid4=uuid.uuid4
    filters=[];actions=[];limits=None
    if case["kind"]=="fd-zero":os.close(0);actions.append(dict(kind="close-stdin",fd=0))
    probe=os.open("/dev/null",os.O_RDONLY|os.O_CLOEXEC);next_fd=probe;os.close(probe)
    initial=fd_snapshot()
    require(next_fd<128 and str(next_fd)not in initial,"fixed next device descriptor")
    require(set(map(int,initial))|{next_fd}>=set(range(max(map(int,initial))+1)),"bounded descriptor layout")
    kind=case["kind"]
    if kind=="getrandom-error":filters.append(install([318],case["errno"]))
    elif kind not in("normal",):filters.append(install([318],case.get("errno",38)if kind in("fallback","sticky")else 38))
    if kind=="open-error":filters.append(install([257],case["errno"],[(2,524288)]))
    if kind in("initial-stat","initial-stat-close"):filters.append(install([5,262],case["errno"],[(0,next_fd)]))
    if kind=="initial-stat-close":filters.append(install([3],case["close_errno"],[(0,next_fd)]))
    if kind=="read-error":filters.append(install([0],case["errno"],[(0,next_fd)]))
    if kind in("one-free","no-free"):
        before=resource.getrlimit(resource.RLIMIT_NOFILE);maximum=max(map(int,initial))
        require(set(map(int,initial))==set(range(maximum+1)),"descriptor limit input has no holes")
        soft=maximum+(2 if kind=="one-free"else 1)
        resource.setrlimit(resource.RLIMIT_NOFILE,(soft,before[1]))
        limits=dict(before=list(before),during=list(resource.getrlimit(resource.RLIMIT_NOFILE)),free=soft-maximum-1)
    mapping=dict(address=native.base,bytes=binding["elf"]["bytes"],seals=15,read=True,write=False,execute=True,
        callback=native.callback_address,exports=native.build["exports"])if native else None
    write(result_fd,encoded(dict(record="START",case=case,role=a.role,pid=os.getpid(),initial_fds=initial,
        next_fd=next_fd,foreign_fd=foreign_fd,filters=list(filters),actions=actions,limits=limits,
        runtime=runtime,build_elf=binding["elf"]if native else None,image_mapping=mapping,original_unchanged=True)))
    for index,mode in enumerate(case["modes"]):
        step_actions=[]
        if index==1 and kind in("sticky","cache-stat","cache-replaced","cache-closed"):
            previous=fd_snapshot()
            if native:
                work=ctypes.string_at(u(ctypes.string_at(native.context,4096),88),4096);cache=u(work,72)
            else:
                devices=[int(fd)for fd,r in previous.items()if r["target"]=="/dev/urandom"and fd not in initial]
                require(len(devices)==1,"one actual original cached device before mutation");cache=devices[0]
            require(cache<128 and str(cache)in previous,"real live cached device")
            if kind=="sticky":
                installed=install([318],case["after_errno"]);filters.append(installed)
                try:probe_value=dict(ok=True,raw_hex=os.getrandom(1).hex())
                except OSError as e:probe_value=dict(ok=False,error=exception(e))
                step_actions.append(dict(kind="stronger-getrandom-fault",filter=installed,probe=probe_value))
            elif kind=="cache-stat":
                installed=install([5,262],case["errno"],[(0,cache)]);filters.append(installed)
                step_actions.append(dict(kind="cached-fstat-fault",fd=cache,filter=installed))
            elif kind=="cache-replaced":
                os.dup2(foreign_fd,cache,inheritable=False)
                step_actions.append(dict(kind="actual-dup2-foreign",source=foreign_fd,fd=cache,
                    before=previous[str(cache)],after=fd_snapshot()[str(cache)]))
            else:
                os.close(cache);step_actions.append(dict(kind="actual-close-cache",fd=cache,before=previous[str(cache)]))
        before=fd_snapshot();start=journal.pin();observed=[]
        if native:value=native.call(mode)
        else:
            def observe(n):
                try:raw=original_urandom(n)
                except BaseException as e:observed.append(dict(size=n,ok=False,error=exception(e)));raise
                observed.append(dict(size=n,ok=True,raw_hex=raw.hex()));return raw
            if case["observer"]:os.urandom=observe
            try:
                data=os.urandom(16)if mode==1 else original_uuid4().hex.encode("ascii")
                value=dict(ok=True,payload_hex=data.hex())
            except BaseException as e:value=dict(ok=False,error=exception(e))
            finally:os.urandom=original_urandom
        after=fd_snapshot()
        row=dict(record="CALL",index=index,mode=mode,actions=step_actions,before_fds=before,after_fds=after,
            result=value,original_observations=observed,event_start=start,event_end=journal.pin())
        write(result_fd,encoded(row))
        if native:require(value["native_return"]==64 and value["release_return"]==0 and not journal.errors,
            "native application completion refused; all completed bytes retained, no replay")
    if limits:
        resource.setrlimit(resource.RLIMIT_NOFILE,tuple(limits["before"]));limits["after"]=list(resource.getrlimit(resource.RLIMIT_NOFILE))
    write(result_fd,encoded(dict(record="DONE",calls=len(case["modes"]),events=journal.pin(),
        callback_errors=journal.errors,final_fds=fd_snapshot(),filters=filters,limits=limits,
        process_lifetime_cache_not_explicitly_closed=True)))
    os.close(result_fd);os.close(event_fd)
if __name__=="__main__":main()
