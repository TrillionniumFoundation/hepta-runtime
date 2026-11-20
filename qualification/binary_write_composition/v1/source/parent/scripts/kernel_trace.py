#!/usr/bin/env python3
"""Read-only ptrace custody of the actual direct child; never inject results or memory."""
from pathlib import Path
import ctypes,errno,gzip,hashlib,os,signal,struct,time
from evidence_common import encoded,pin,require
LIBC=ctypes.CDLL(None,use_errno=True)
LIBC.ptrace.argtypes=[ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p]
LIBC.ptrace.restype=ctypes.c_long
class Iovec(ctypes.Structure):
    _fields_=[("base",ctypes.c_void_p),("length",ctypes.c_size_t)]
LIBC.process_vm_readv.argtypes=[ctypes.c_int,ctypes.POINTER(Iovec),ctypes.c_ulong,
    ctypes.POINTER(Iovec),ctypes.c_ulong,ctypes.c_ulong]
LIBC.process_vm_readv.restype=ctypes.c_ssize_t
MASK=(1<<64)-1
MAX_BUFFER=134217792
OPTIONS=1|16|(1<<20)
def ptrace(request,pid,address=0,data=0):
    require(request in(24,0x4200,0x420e),"observer forbids ptrace memory/register writes and result injection")
    ctypes.set_errno(0)
    result=LIBC.ptrace(request,pid,ctypes.c_void_p(address),ctypes.c_void_p(data))
    if result<0:raise OSError(ctypes.get_errno(),"read-only ptrace request "+str(request))
    return result
def memory(pid,address,size):
    require(type(size)is int and 0<=size<=MAX_BUFFER,"complete syscall buffer extent")
    if not size:return b""
    require(0<address<(1<<63) and address+size<(1<<63),"ordinary observed user address")
    raw=ctypes.create_string_buffer(size);local=Iovec(ctypes.addressof(raw),size);remote=Iovec(address,size)
    ctypes.set_errno(0);count=LIBC.process_vm_readv(pid,ctypes.byref(local),1,ctypes.byref(remote),1,0)
    if count!=size:raise OSError(ctypes.get_errno()or errno.EIO,"incomplete process_vm_readv "+str(count)+"/"+str(size))
    return raw.raw
def cstring(pid,address):
    require(0<address<(1<<63),"ordinary observed string address")
    parts=[];used=0
    while used<4096:
        size=min(256,4096-used,4096-((address+used)&4095))
        block=memory(pid,address+used,size);end=block.find(b"\0")
        if end>=0:return b"".join(parts)+block[:end+1]
        parts.append(block);used+=len(block)
    raise ValueError("observed pathname exceeds bounded NUL profile")
def signed(n):return n-(1<<64)if n>>63 else n
class Trace:
    def __init__(self,pid,folder):
        self.pid=pid;self.folder=Path(folder);self.path=self.folder/"kernel.jsonl.gz"
        self.file=self.path.open("xb")
        self.stream=gzip.GzipFile(filename="",fileobj=self.file,mode="wb",compresslevel=1,mtime=0)
        self.digest=hashlib.sha256();self.bytes=0;self.rows=0;self.calls=0;self.signals=0;self.execs=0
        self.current=None;self.status=None;self.scope="launch";self.phase=None;self.closed=False
        self.application_calls=0;self.capture_errors=[];self.last_wait=None
        deadline=time.monotonic()+60
        while True:
            got,status=os.waitpid(pid,os.WNOHANG)
            if got:break
            require(time.monotonic()<deadline,"trace launch SIGSTOP deadline");time.sleep(.001)
        require(os.WIFSTOPPED(status)and os.WSTOPSIG(status)==signal.SIGSTOP,
            "direct unchanged target did not stop before exec")
        ptrace(0x4200,pid,data=OPTIONS)
        self.emit(dict(record="START",pid=pid,options=OPTIONS,initial_wait_status=status,
            ptrace_requests=[24,0x4200,0x420e],memory_reader="process_vm_readv",
            register_or_memory_writes=0,syscall_result_replacements=0,follow_forks=False))
        ptrace(24,pid)
    def emit(self,row):
        data=encoded(dict(trace_row=self.rows,**row));self.rows+=1
        self.stream.write(data);self.digest.update(data);self.bytes+=len(data)
    def mark(self,label,application=False):
        require(self.status is None,"mark after process exit")
        self.pump()
        self.scope=label;self.phase=None
        if application:self.application_calls+=1
        row=dict(record="MARK",scope=label,application=application,calls=self.calls,
            open_call=self.current["ordinal"]if self.current else None)
        self.emit(row);return dict(trace_row=self.rows-1,calls=self.calls,scope=label)
    def take(self,label,address,size=None,string=False):
        try:
            raw=cstring(self.pid,address)if string else memory(self.pid,address,size)
            return dict(label=label,address=address,bytes=len(raw),hex=raw.hex())
        except BaseException as e:
            row=dict(label=label,address=address,requested=size,string=string,
                error_type=type(e).__name__,error=str(e))
            self.capture_errors.append(dict(scope=self.scope,call=self.calls,**row))
            return row
    def entry_memory(self,n,a):
        rows=[]
        def string(label,address):rows.append(self.take(label,address,string=True))
        def span(label,address,size):rows.append(self.take(label,address,size))
        if n in(2,87,89):string("path",a[0])
        elif n in(257,258,262,263,267):string("path",a[1])
        elif n==82:string("source",a[0]);string("destination",a[1])
        elif n in(264,265,316):string("source",a[1]);string("destination",a[3])
        elif n in(190,193,199):
            string("attribute",a[1])
            if n==190:span("value",a[2],a[3])
        elif n==1 and a[0] not in(1,2,3,4):
            span("write",a[1],a[2])
        elif n==1 and a[0]==4:
            span("notification",a[1],a[2])
        elif n==20 and a[0] not in(1,2,3,4):
            require(a[2]<=1024,"bounded observed writev")
            raw=memory(self.pid,a[1],16*a[2]);span("iovec",a[1],16*a[2])
            for index in range(a[2]):
                address,size=struct.unpack_from("<2Q",raw,index*16);span("writev-"+str(index),address,size)
        elif n==13 and a[1]:span("sigaction",a[1],32)
        elif n==317 and a[0]==1:
            head=memory(self.pid,a[2],16);count=struct.unpack_from("<H",head,0)[0]
            pointer=struct.unpack_from("<Q",head,8)[0]
            require(1<=count<=64,"bounded frozen actual BPF program")
            span("sock-fprog",a[2],16);span("seccomp-bpf",pointer,8*count)
        elif n==160 and a[1]:span("rlimit",a[1],16)
        elif n==302 and a[2]:span("new-limit",a[2],16)
        return rows
    def exit_memory(self,n,a,result):
        rows=[]
        if result<0:return rows
        def span(label,address,size):rows.append(self.take(label,address,size))
        if n==5:span("stat",a[1],144)
        elif n==262:span("stat",a[2],144)
        elif n==0 and a[0]==5:span("ack",a[1],result)
        elif n in(0,17)and a[0] not in(3,5):span("read",a[1],result)
        elif n==318:span("random",a[0],result)
        elif n==193:span("attribute-value",a[2],result if a[3]else 0)
        elif n==196:span("attribute-list",a[1],result if a[2]else 0)
        elif n==267:span("link",a[2],result)
        elif n==16 and a[1]==0x5401 and a[2]:span("termios",a[2],36)
        elif n==13 and a[2]:span("old-sigaction",a[2],32)
        elif n==97 and a[1]:span("rlimit",a[1],16)
        elif n==302 and a[3]:span("old-limit",a[3],16)
        return rows
    def pump(self):
        if self.status is not None:return
        for _ in range(4096):
            try:got,status=os.waitpid(self.pid,os.WNOHANG|0x40000000)
            except InterruptedError:continue
            if not got:return
            self.last_wait=status
            if os.WIFEXITED(status)or os.WIFSIGNALED(status):
                self.status=status
                require(self.current is None or self.current["number"]in(60,231),
                    "process ended with an unclosed non-exit syscall")
                self.emit(dict(record="EXIT",wait_status=status,returncode=os.waitstatus_to_exitcode(status),
                    open_exit=self.current,scope=self.scope))
                self.current=None;return
            require(os.WIFSTOPPED(status),"unknown actual ptrace wait state")
            sig=os.WSTOPSIG(status);event=status>>16
            if sig==signal.SIGTRAP|0x80:
                buffer=ctypes.create_string_buffer(128)
                size=ptrace(0x420e,self.pid,128,ctypes.addressof(buffer));raw=buffer.raw
                require(size>=24 and struct.unpack_from("<I",raw,4)[0]==0xc000003e,
                    "observed syscall architecture is not Linux x86_64")
                operation=raw[0]
                if operation==1:
                    require(size>=80 and self.current is None,"syscall entry/exit sequence")
                    number,*args=struct.unpack_from("<7Q",raw,24);self.calls+=1
                    current=dict(ordinal=self.calls,number=number,args=args,
                        instruction_pointer=struct.unpack_from("<Q",raw,8)[0],scope=self.scope,phase=self.phase,
                        syscall_info_hex=raw[:size].hex(),input=self.entry_memory(number,args))
                    self.current=current;self.emit(dict(record="ENTER",**current))
                elif operation==2:
                    require(size>=33 and self.current is not None,"syscall exit without entry")
                    result=struct.unpack_from("<q",raw,24)[0];error=raw[32]
                    require(error in(0,1),"kernel is_error field")
                    current=self.current;number=current["number"];args=current["args"]
                    output=self.exit_memory(number,args,result)
                    self.emit(dict(record="LEAVE",ordinal=current["ordinal"],number=number,scope=current["scope"],
                        result=result,is_error=error,syscall_info_hex=raw[:size].hex(),output=output))
                    if number==1 and args[0]==4 and result==64:
                        data=next((bytes.fromhex(v["hex"])for v in current["input"]if v["label"]=="notification"and"hex"in v),b"")
                        if len(data)==64:self.phase=dict(magic_hex=data[:8].hex(),words=list(struct.unpack("<7Q",data[8:])))
                    self.current=None
                else:raise ValueError("unexpected syscall stop operation "+str(operation))
                ptrace(24,self.pid);continue
            if sig==signal.SIGTRAP and event==4:
                self.execs+=1
                self.emit(dict(record="EXEC",scope=self.scope,wait_status=status,
                    pending_call=self.current["ordinal"]if self.current else None))
                ptrace(24,self.pid);continue
            require(event==0,"unrequested ptrace event")
            self.signals+=1
            self.emit(dict(record="SIGNAL",signal=sig,wait_status=status,scope=self.scope,
                forwarded_without_change=True))
            ptrace(24,self.pid,data=sig)
        raise ValueError("observer failed to yield after bounded stop drain")
    def finish(self):
        require(self.status is not None and not self.closed,"trace not terminal or already closed")
        self.emit(dict(record="DONE",calls=self.calls,signals=self.signals,execs=self.execs,
            application_calls=self.application_calls,capture_errors=self.capture_errors,
            register_or_memory_writes=0,syscall_result_replacements=0))
        self.stream.close();self.file.close();self.closed=True
        digest=hashlib.sha256();count=0
        with gzip.open(self.path,"rb")as stream:
            while chunk:=stream.read(1<<20):digest.update(chunk);count+=len(chunk)
        require(dict(bytes=count,sha256=digest.hexdigest())==dict(bytes=self.bytes,sha256=self.digest.hexdigest()),
            "complete kernel observation gzip readback")
        result=dict(compressed=pin(self.path),raw=dict(bytes=self.bytes,sha256=self.digest.hexdigest()),
            rows=self.rows,calls=self.calls,signals=self.signals,execs=self.execs,returncode=os.waitstatus_to_exitcode(self.status),
            application_calls=self.application_calls,capture_errors=self.capture_errors,
            register_or_memory_writes=0,syscall_result_replacements=0)
        (self.folder/"kernel-process.json").write_bytes(encoded(result));return result
    def close_failure(self):
        if not self.closed:
            self.stream.close();self.file.close();self.closed=True
            (self.folder/"kernel-failure.json").write_bytes(encoded(dict(last_wait=self.last_wait,status=self.status,
                pending=self.current,scope=self.scope,calls=self.calls,capture_errors=self.capture_errors,
                compressed=pin(self.path),raw=dict(bytes=self.bytes,sha256=self.digest.hexdigest()))))
