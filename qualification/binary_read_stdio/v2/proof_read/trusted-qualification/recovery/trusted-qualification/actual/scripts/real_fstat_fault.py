#!/usr/bin/env python3
"""Real immutable seccomp input: fstat/newfstatat return kernel EIO after installation."""
import ctypes,errno
class Filter(ctypes.Structure):
    _fields_=[("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_=[("length",ctypes.c_ushort),("instructions",ctypes.POINTER(Filter))]
LIBC=ctypes.CDLL(None,use_errno=True)
LIBC.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
LIBC.prctl.restype=ctypes.c_int
LIBC.syscall.restype=ctypes.c_long
FILTER=(Filter*6)(Filter(0x20,0,0,0),Filter(0x15,0,1,5),Filter(0x06,0,0,0x50000|errno.EIO),
    Filter(0x15,0,1,262),Filter(0x06,0,0,0x50000|errno.EIO),Filter(0x06,0,0,0x7fff0000))
PROGRAM=Program(len(FILTER),FILTER)
def install():
    if LIBC.prctl(38,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),"PR_SET_NO_NEW_PRIVS")
    if LIBC.syscall(317,1,0,ctypes.byref(PROGRAM))!=0:raise OSError(ctypes.get_errno(),"seccomp EIO installation")
