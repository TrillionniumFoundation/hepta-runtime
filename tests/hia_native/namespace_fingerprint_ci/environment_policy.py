"""Actual bounded seccomp faults and descriptor layout, never a fake filesystem ACK."""
import ctypes as C,errno,fcntl,os,struct
from common import require
ROOT_FD=96
STREAM_FD=80
GROUPS={
 "ordinary":[], "names":[], "wide":[],
 "open-eacces":[(257,0,ROOT_FD,13)],
 "fdopendir-eperm":[(72,1,3,1)],
 "readdir-eio":[(217,None,None,5)],
 "readdir-eintr":[(217,None,None,4)],
 "closedir-eio":[(3,0,STREAM_FD,5)],
 "fdopendir-eperm-close-eio":[(72,1,3,1),(3,0,STREAM_FD,5)],
 "readdir-eio-close-eacces":[(217,None,None,5),(3,0,STREAM_FD,13)],
}
def filters(group):
    require(group in GROUPS,"fixed owned kernel environment")
    out=[(0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,0x80000000),(0x20,0,0,0)]
    for number,index,value,error in GROUPS[group]:
        if index is None:out.extend([(0x15,0,1,number),(0x06,0,0,0x50000|error)])
        else:
            out.extend([(0x15,0,4,number),(0x20,0,0,16+index*8),
                        (0x15,0,1,value),(0x06,0,0,0x50000|error),(0x20,0,0,0)])
    out.append((0x06,0,0,0x7fff0000))
    return out
def reserve():
    for fd in (STREAM_FD,ROOT_FD):
        try:fcntl.fcntl(fd,fcntl.F_GETFD)
        except OSError as e:require(e.errno==errno.EBADF,"fixed borrowed FD is absent")
        else:raise ValueError("fixture cannot overwrite existing FD")
    base=os.open("/dev/null",os.O_RDONLY|os.O_CLOEXEC)
    held=[]
    for fd in range(3,128):
        if fd in (STREAM_FD,ROOT_FD):continue
        try:fcntl.fcntl(fd,fcntl.F_GETFD)
        except OSError as e:
            require(e.errno==errno.EBADF,"owned descriptor hole")
            os.dup2(base,fd,inheritable=False);held.append(fd)
    return dict(base=base,held=held,stream_fd=STREAM_FD,root_fd=ROOT_FD)
def open_root(path):
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC)
    require(fd==STREAM_FD,"actual next open uses the fixed empty stream slot")
    os.dup2(fd,ROOT_FD,inheritable=False);os.close(fd)
    return ROOT_FD
def install(group):
    raw=filters(group)
    if not GROUPS[group]:return dict(group=group,installed=False,filters=raw)
    class Filter(C.Structure):_fields_=[("code",C.c_ushort),("jt",C.c_ubyte),("jf",C.c_ubyte),("k",C.c_uint32)]
    class Program(C.Structure):_fields_=[("len",C.c_ushort),("filter",C.POINTER(Filter))]
    rows=(Filter*len(raw))(*(Filter(*r)for r in raw));program=Program(len(raw),rows)
    lib=C.CDLL("libc.so.6",use_errno=True);lib.prctl.restype=C.c_int
    require(lib.prctl(38,1,0,0,0)==0,"actual NO_NEW_PRIVS")
    require(lib.prctl(22,2,C.byref(program),0,0)==0,"actual SECCOMP")
    return dict(group=group,installed=True,filters=raw)
