#!/usr/bin/env python3
"""Launch the unchanged target under a read-only syscall observer, retaining its PID."""
import ctypes,os,signal,sys
libc=ctypes.CDLL(None,use_errno=True)
libc.ptrace.argtypes=[ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p]
libc.ptrace.restype=ctypes.c_long
if len(sys.argv)<2 or not os.path.isabs(sys.argv[1]):raise ValueError("fixed absolute target")
if libc.ptrace(0,0,None,None)!=0:raise OSError(ctypes.get_errno(),"PTRACE_TRACEME")
os.kill(os.getpid(),signal.SIGSTOP)
os.execve(sys.argv[1],sys.argv[1:],dict(os.environ))
