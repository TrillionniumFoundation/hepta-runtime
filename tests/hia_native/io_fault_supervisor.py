#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Qualification only: supervise direct syscalls of one owned native child.

The child installs an unprivileged seccomp notification filter before exec.
Ordinary operations continue in the kernel. Selected tests inject EINTR or
change their own temporary fixture just before a read. No file-read semantics
or native output are implemented by this supervisor.
"""
import argparse
import array
import ctypes
import errno
import json
import os
from pathlib import Path
import select
import socket
import sys

class Filter(ctypes.Structure):
    _fields_=[("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_=[("length",ctypes.c_ushort),("filter",ctypes.POINTER(Filter))]
class Data(ctypes.Structure):
    _fields_=[("nr",ctypes.c_int),("arch",ctypes.c_uint),("ip",ctypes.c_uint64),("args",ctypes.c_uint64*6)]
class Notification(ctypes.Structure):
    _fields_=[("id",ctypes.c_uint64),("pid",ctypes.c_uint),("flags",ctypes.c_uint),("data",Data)]
class Response(ctypes.Structure):
    _fields_=[("id",ctypes.c_uint64),("value",ctypes.c_int64),("error",ctypes.c_int),("flags",ctypes.c_uint)]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log",required=True,type=Path)
    parser.add_argument("--mode",required=True,choices=["eintr","change","close","read_error"])
    parser.add_argument("--fixture",type=Path)
    parser.add_argument("--close-ordinal",type=int,default=0)
    parser.add_argument("command",nargs=argparse.REMAINDER)
    args=parser.parse_args()
    command=args.command[1:] if args.command[:1]==["--"] else args.command
    assert len(command)==2 and ctypes.sizeof(Notification)==80 and ctypes.sizeof(Response)==24
    parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
    libc=ctypes.CDLL(None,use_errno=True)
    pid=os.fork()
    if pid==0:
        parent.close()
        try:
            if libc.prctl(38,1,0,0,0):raise OSError(ctypes.get_errno(),"PR_SET_NO_NEW_PRIVS")
            instructions=(Filter*5)(Filter(0x20,0,0,0),Filter(0x15,1,0,17),Filter(0x15,0,1,3),
                                    Filter(0x06,0,0,0x7fc00000),Filter(0x06,0,0,0x7fff0000))
            program=Program(len(instructions),instructions)
            listener=libc.syscall(317,1,8,ctypes.byref(program))
            if listener<0:raise OSError(ctypes.get_errno(),"seccomp notification unavailable")
            os.set_inheritable(listener,False)
            child.sendmsg([b"L"],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[listener]))])
            os.execve(command[0],command,dict(os.environ))
        except BaseException as error:
            os.write(2,(str(error)+"\n").encode());os._exit(75)
    child.close()
    if not select.select([parent],[],[],5)[0]:
        os.kill(pid,9);os.waitpid(pid,0)
        raise RuntimeError("owned child could not install seccomp notification")
    message,ancillary,_,_=parent.recvmsg(1,socket.CMSG_SPACE(4));parent.close()
    descriptors=array.array("i");descriptors.frombytes(ancillary[0][2][:4]);listener=descriptors[0]
    events=[];read_count=0;close_count=0;wait_status=None
    try:
        while True:
            ended,status=os.waitpid(pid,os.WNOHANG)
            if ended:
                wait_status=status;break
            if not select.select([listener],[],[],0.1)[0]:continue
            note=Notification()
            if libc.ioctl(listener,0xc0502100,ctypes.byref(note)):
                if ctypes.get_errno() in (errno.EINTR,errno.ENOENT):continue
                raise OSError(ctypes.get_errno(),"SECCOMP_IOCTL_NOTIF_RECV")
            answer=Response(note.id,0,0,1)
            native=0x400000<=note.data.ip<0x500000
            if native:
                event={"syscall":note.data.nr,"mode":"continue"}
                if note.data.nr==17:
                    read_count+=1
                    event.update(offset=int(note.data.args[3]),count=int(note.data.args[2]))
                    if args.mode=="eintr" and read_count==1:
                        answer.error=-errno.EINTR;answer.flags=0;event["mode"]="injected_eintr"
                    if args.mode=="change" and read_count==1:
                        args.fixture.write_bytes(b"shortened");event["mode"]="changed_fixture_before_kernel_read"
                    if args.mode=="read_error" and read_count==1:
                        answer.error=-errno.EIO;answer.flags=0;event["mode"]="injected_eio"
                if note.data.nr==3:
                    close_count+=1
                    if args.mode=="close" and close_count==args.close_ordinal:
                        answer.error=-errno.EINTR;answer.flags=0;event["mode"]="injected_eintr"
                events.append(event)
            if libc.ioctl(listener,0xc0182101,ctypes.byref(answer)) and ctypes.get_errno()!=errno.ENOENT:
                raise OSError(ctypes.get_errno(),"SECCOMP_IOCTL_NOTIF_SEND")
    finally:
        os.close(listener)
        if wait_status is None:
            os.kill(pid,9);_,wait_status=os.waitpid(pid,0)
        args.log.write_text(json.dumps(events,sort_keys=True)+"\n")
    raise SystemExit(os.waitstatus_to_exitcode(wait_status))

if __name__=="__main__":main()
