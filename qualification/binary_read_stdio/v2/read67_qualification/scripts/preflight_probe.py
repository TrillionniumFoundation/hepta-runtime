#!/usr/bin/env python3
"""Two independent observer probes; no frozen original or HIA application is imported."""
from pathlib import Path
import os,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from real_fstat_fault import install
if len(sys.argv)!=3 or sys.argv[1]not in("normal","fault"):raise SystemExit(111)
mode,path=sys.argv[1:];payload=sys.stdin.buffer.read()
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
if mode=="fault":
    install()
    try:os.fstat(fd)
    except OSError as e:
        os.write(2,(type(e).__name__+": "+str(e)+"\n").encode());raise SystemExit(1)
    raise SystemExit(111)
os.fstat(fd);data=os.read(fd,4096);os.close(fd)
os.write(1,payload+data)
