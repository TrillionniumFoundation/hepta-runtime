#!/usr/bin/env python3
"""Single direct child launch; TRACEME custody and optional actual seccomp input."""
from pathlib import Path
import ctypes,os,signal,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from real_fstat_fault import install
libc=ctypes.CDLL(None,use_errno=True);libc.ptrace.restype=ctypes.c_long
if len(sys.argv)<3 or sys.argv[1]not in("normal","native-first-fstat"):raise SystemExit(111)
mode=sys.argv[1];argv=sys.argv[2:]
if libc.ptrace(0,0,None,None)!=0:raise OSError(ctypes.get_errno(),"PTRACE_TRACEME")
os.kill(os.getpid(),signal.SIGSTOP)
if mode=="native-first-fstat":install()
os.execve(argv[0],argv,dict(os.environ))
