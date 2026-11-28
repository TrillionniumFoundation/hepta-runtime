"""Explicit owned Linux seccomp test environments; no intercepted callback or fake ACK."""
import ctypes as C
import struct
from common import require
GROUPS={
 "normal":[],
 "enosys":[(318,38)],
 "eperm":[(318,1)],
 "entropy-eio":[(318,5)],
 "fsync-eio":[(74,5)],
 "link-eacces":[(265,13)],
 "unlink-eacces":[(263,13)],
 "enosys-unlink-eacces":[(318,38),(263,13)],
 "eperm-fsync-eio":[(318,1),(74,5)],
}
def filters(group):
    require(group in GROUPS,"fixed real environment")
    out=[(0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,0x80000000),(0x20,0,0,0)]
    for syscall,errno in GROUPS[group]:
        out.extend([(0x15,0,1,syscall),(0x06,0,0,0x50000|errno)])
    out.append((0x06,0,0,0x7fff0000))
    return out
def install(group):
    raw=filters(group)
    if not GROUPS[group]:return dict(group=group,installed=False,filters=raw)
    class Filter(C.Structure):_fields_=[("code",C.c_ushort),("jt",C.c_ubyte),("jf",C.c_ubyte),("k",C.c_uint32)]
    class Program(C.Structure):_fields_=[("len",C.c_ushort),("filter",C.POINTER(Filter))]
    rows=(Filter*len(raw))(*(Filter(*r) for r in raw));program=Program(len(raw),rows)
    lib=C.CDLL("libc.so.6",use_errno=True);lib.prctl.restype=C.c_int
    require(lib.prctl(38,1,0,0,0)==0,"actual PR_SET_NO_NEW_PRIVS")
    require(lib.prctl(22,2,C.byref(program),0,0)==0,"actual SECCOMP_MODE_FILTER")
    return dict(group=group,installed=True,filters=raw)
