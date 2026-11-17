#!/usr/bin/env python3
"""Frozen small actual-kernel domain for qualifying the passive observer."""
from pathlib import Path
import ctypes,errno,fcntl,json,os,resource,signal,struct,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import decode,encoded,require
from protocol import U,stat_value,exception
def read(fd,n,eof=False):
    raw=b""
    while len(raw)<n:
        q=os.read(fd,n-len(raw))
        if not q:
            if eof and not raw:return None
            raise ValueError("short actual probe frame")
        raw+=q
    return raw
def write(fd,raw):
    while raw:
        n=os.write(fd,raw);require(n>0,"actual probe complete write");raw=raw[n:]
def error_filter(fd):
    class Filter(ctypes.Structure):_fields_=[("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint)]
    class Program(ctypes.Structure):_fields_=[("len",ctypes.c_ushort),("filter",ctypes.POINTER(Filter))]
    filters=(Filter*7)(Filter(0x20,0,0,0),Filter(0x15,1,0,5),Filter(0x15,0,3,262),
        Filter(0x20,0,0,16),Filter(0x15,0,1,fd),Filter(0x06,0,0,0x50005),Filter(0x06,0,0,0x7fff0000))
    program=Program(7,filters);libc=ctypes.CDLL(None,use_errno=True)
    require(libc.prctl(38,1,0,0,0)==0 and libc.syscall(317,1,0,ctypes.byref(program))==0,"real probe seccomp")
def reply(ret,payload=b"",state=0):
    write(1,b"HBWTFR01"+struct.pack("<7Q",ret,len(payload),state,0,0,0,0)+payload)
control=0;invoked=False
while True:
    head=read(control,8,True)
    if head is None:break
    q=read(control,U(head,0));require(q[:8]==b"HBWTFQ01"and U(q,24)==len(q)-64,"fixed actual probe input")
    command=U(q,8)
    if command==17:
        control=os.dup(0);os.close(0);reply(0);continue
    require(command==1 and not invoked,"one frozen actual observer probe per process");invoked=True
    p=decode(q[64:]);data=bytes.fromhex(p["data_hex"]);kind=p["kind"]
    result=dict(kind=kind,signal_profile={str(n):int(signal.getsignal(n))for n in(13,25)},random_hex=os.urandom(16).hex())
    fd=os.open(p["path"],os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC,0o600);result["fd"]=fd;result["initial_stat"]=stat_value(os.fstat(fd))
    if kind=="seccomp-eio":
        error_filter(fd)
        try:os.fstat(fd);raise ValueError("actual fault absent")
        except OSError as e:result["error"]=exception(e)
        os.close(fd)
    elif kind=="partial-write":
        resource.setrlimit(resource.RLIMIT_FSIZE,(23,23))
        result["first_write"]=os.write(fd,data)
        try:os.write(fd,data[result["first_write"]:]);raise ValueError("actual size bound absent")
        except OSError as e:result["error"]=exception(e)
        os.lseek(fd,0,os.SEEK_SET);result["read_hex"]=os.read(fd,64).hex();os.close(fd)
    else:
        with os.fdopen(fd,"a")as file:
            result["fileio_stat"]=stat_value(os.fstat(file.fileno()))
            result["text_count"]=file.write(data.decode("ascii"));file.flush();os.fsync(file.fileno())
        with open(p["path"],"rb")as file:result["read_hex"]=file.read().hex()
    write(3,encoded(dict(actual_kernel_probe=kind,bytes=len(data))))
    reply(0,encoded(result),2)
if control:os.close(control)
write(4,b"HBWTEOF1"+bytes(56));require(read(5,8)==bytes(8),"real probe EOF ACK")
