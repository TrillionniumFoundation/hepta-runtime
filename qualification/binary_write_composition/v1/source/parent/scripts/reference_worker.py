#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Invoke the complete unchanged original main(write), parent and outer finally."""
import ast
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from evidence_common import encoded, decode, pin, require, sha
from protocol import U, exception

SOURCE = Path(sys.argv[1]).resolve(strict=True)
target = SOURCE / "reference/binary_file.py"
raw = target.read_bytes()
require(sha(raw) == "c15e8900b0ab867b221ff08d5a10401c8b656c87676f57b478b9a21219f7fe12", "fixed full original target source")
require(sys.version_info[:3] == (3, 12, 3), "original CPython 3.12.3 is mandatory")
require(pin(Path(sys.executable).resolve()) == dict(bytes=8020928, sha256="e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f"),
        "original whole interpreter bytes")
require(signal.getsignal(13) == signal.getsignal(25) == signal.SIG_IGN, "fixed actual original signal profile")
namespace = dict(__name__="fixed_original_binary_parent", __file__=str(target))
exec(compile(raw, str(target), "exec"), namespace)
module = ast.parse(raw)
functions = {node.name: node for node in module.body if isinstance(node, ast.FunctionDef)}
main_try = next(node for node in functions["main"].body if isinstance(node, ast.Try))
parent_try = next(node for node in functions["parent"].body if isinstance(node, ast.Try))
outer_close_line = main_try.finalbody[0].lineno
cleanup_close_line = parent_try.handlers[0].body[0].lineno
normal_close_line = next(node.lineno for node in parent_try.body[0].body if isinstance(node, ast.Expr))
binding = dict(original=pin(target), metadata=pin(SOURCE / "reference/file_metadata.py"),
               interpreter=pin(Path(sys.executable).resolve()), python_version=list(sys.version_info[:3]),
               main_ast_sha256=sha(ast.dump(functions["main"], include_attributes=True).encode()),
               parent_ast_sha256=sha(ast.dump(functions["parent"], include_attributes=True).encode()),
               whole_original_main_executed=True, outer_finally_ast_sha256=sha(ast.dump(main_try.finalbody[0], include_attributes=True).encode()),
               outer_close_line=outer_close_line, cleanup_close_line=cleanup_close_line, normal_close_line=normal_close_line)


def read(fd, size, eof=False):
    raw = b""
    while len(raw) < size:
        part = os.read(fd, size - len(raw))
        if not part:
            if eof and not raw:
                return None
            raise ValueError("original private input ended early")
        raw += part
    return raw


def write(fd, raw):
    pending = memoryview(raw)
    while pending:
        count = os.write(fd, pending)
        require(count > 0, "original complete output")
        pending = pending[count:]


class Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class Program(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]


libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.restype = ctypes.c_int
libc.syscall.restype = ctypes.c_long


def install(number, error, fd, match_fd):
    require(0 <= number <= 511 and 1 <= error <= 4095 and match_fd in (0, 1), "fixed real syscall fault")
    require(not match_fd or 0 <= fd <= 2147483647, "actual syscall descriptor selector")
    rows = [(0x20, 0, 0, 0), (0x15, 1 if match_fd else 3, 0, number),
            (0x15, 0 if match_fd else 2, 3, 262 if number == 5 else number),
            (0x20, 0, 0, 16), (0x15, 0, 1, fd & 0xffffffff),
            (0x06, 0, 0, 0x00050000 | error), (0x06, 0, 0, 0x7fff0000)]
    items = (Filter * len(rows))(*(Filter(*row) for row in rows))
    program = Program(len(rows), items)
    require(libc.prctl(38, 1, 0, 0, 0) == 0, "actual no-new-privileges")
    require(libc.syscall(317, 1, 0, ctypes.byref(program)) == 0, "actual seccomp errno filter")
    return dict(number=number, errno=error, fd=fd, match_fd=match_fd, bpf=rows)


class ParentObserver:
    """Before-effect observation only; original function bodies remain unchanged."""
    def __init__(self):
        self.generation=0
        self.enabled=False
        self.plans=[]
        self.plan_at=0
        self.plan_seen=0
        self.filters=[]
        self.events=[]
        self.calls=0
        self.body_calls=0
        self.previous=None
        self.actor=0
        self.actor_step=0
        self.actor_events=[]

    def __getattr__(self, name):
        return getattr(os, name)

    def frame(self):
        frame=sys._getframe(2)
        while frame is not None:
            if frame.f_code.co_filename == str(target):
                return frame.f_code.co_name, frame.f_lineno
            frame=frame.f_back
        return None, None

    def begin(self, generation, enabled):
        self.generation=generation
        self.enabled=enabled
        self.calls=0
        self.body_calls=0
        self.events=[]
        self.previous=None

    def call(self, operation, fd, phase, args, method):
        self.calls += 1
        row=dict(owner="parent", generation=self.generation, call=self.calls,
                 operation=operation, fd=fd, phase=phase, args=args)
        if self.enabled:
            write(4, b"HBPWHK01"+struct.pack("<7Q", self.generation, self.calls, self.calls,
                                           operation, fd & ((1<<64)-1), phase, 0))
            require(read(5,8)==bytes(8), "original observational ACK is zero only")
        if self.actor==1 and operation==3:
            if phase==5 and self.actor_step==0:
                actual=os.close(fd)
                require(actual is None,"actual private actor closed the old descriptor")
                self.actor_events.append(dict(action=1,phase=phase,fd=fd,result=0))
                self.actor_step=1
            elif phase==6 and self.actor_step==1:
                actual=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                require(actual==fd,"actual private actor reopened the same free numeric descriptor")
                self.actor_events.append(dict(action=2,phase=phase,fd=fd,result=actual))
                self.actor_step=2
        if self.plan_at < len(self.plans):
            plan=self.plans[self.plan_at]
            require(len(plan)==7 and plan[0]==6, "parent-only original kernel fault plan")
            if (phase,operation)==(plan[1],plan[2]):
                self.plan_seen += 1
                if self.plan_seen==plan[3]:
                    require(self.enabled, "actual fault requires the observed original call")
                    installed=install(plan[4],plan[5],fd,plan[6])
                    self.filters.append(dict(plan=plan, call=self.calls, phase=phase, installed=installed))
                    self.plan_at += 1
                    self.plan_seen=0
        try:
            result=method()
        except BaseException as error:
            row.update(ok=False,error=exception(error))
            self.previous=row
            self.events.append(row)
            if self.enabled:write(3, encoded(row))
            raise
        row.update(ok=True,value=result)
        self.previous=row
        self.events.append(row)
        if self.enabled:write(3,encoded(row))
        return result

    def open(self,path,flags,mode=0o777,*,dir_fd=None):
        caller,line=self.frame()
        if caller!="parent":
            self.body_barrier(1,0 if dir_fd is None else dir_fd)
            return os.open(path,flags,mode,dir_fd=dir_fd)
        root=dir_fd is None
        return self.call(1 if root else 2,0 if root else dir_fd,2 if root else 4,
                         dict(path=path,flags=flags,mode=mode,dir_fd=dir_fd),
                         lambda:os.open(path,flags,mode,dir_fd=dir_fd))

    def close(self,fd):
        caller,line=self.frame()
        if caller=="parent":
            if line==normal_close_line:
                phase=5
            else:
                require(line==cleanup_close_line,"exact original parent cleanup call site")
                phase=6 if self.previous is not None and self.previous["operation"]==3 else 91
        elif caller=="main" and line==outer_close_line:
            phase=9
        else:
            self.body_barrier(3,fd)
            return os.close(fd)
        return self.call(3,fd,phase,{},lambda:os.close(fd))

    def body_barrier(self,operation,fd):
        if self.enabled:
            self.body_calls+=1
            write(4,b"HBWTHK01"+struct.pack("<7Q",self.generation,self.body_calls,self.body_calls,
                                           operation,fd&((1<<64)-1),0,0))
            require(read(5,8)==bytes(8),"original body observation cannot replace a result")


proxy=ParentObserver()
namespace["os"]=proxy
# Load all evidence serializers before installing target-side resource faults.
hashlib.sha256(b"loaded").digest()
encoded(binding)
states=[None,None]
generations=[0,0]
control=0
eof_witness=False


def reply(result,payload=b"",slot=0):
    write(1,b"HBWTFR01"+struct.pack("<7Q",result&((1<<64)-1),len(payload),states[slot]or 0,generations[slot],0,0,0)+payload)


def error_chain(error):
    rows=[]
    seen=set()
    while error is not None:
        require(id(error)not in seen,"acyclic original exception context")
        seen.add(id(error))
        rows.append(dict(error=exception(error),explicit_cause=error.__cause__ is not None,
                         suppress_context=error.__suppress_context__))
        error=error.__cause__ if error.__cause__ is not None else error.__context__
    return rows


while True:
    header=read(control,8,True)
    if header is None:break
    size=U(header,0)
    require(64<=size<=134217792,"original fixed complete input extent")
    packet=read(control,size)
    require(packet[:8]==b"HBWTFQ01" and U(packet,24)==size-64 and packet[32:64]==bytes(32),"original exact private frame")
    command,slot=U(packet,8),U(packet,16)
    require(slot in (0,1),"fixed original logical context")
    payload=packet[64:]
    if command in (8,9):
        require(not payload and states[slot] is None,"fresh original logical context")
        states[slot]=0;generations[slot]=0;reply(0,slot=slot);continue
    if command==17:
        require(control==0 and not payload,"move original control descriptor once")
        control=os.dup(0);os.close(0);reply(0,slot=slot);continue
    if command==18:
        require(proxy.plan_at==len(proxy.plans) and 56<=len(payload)<=224 and len(payload)%56==0,"whole ordered kernel fault plan")
        proxy.plans=[list(struct.unpack_from("<7Q",payload,at))for at in range(0,len(payload),56)]
        proxy.plan_at=0;proxy.plan_seen=0;reply(0,slot=slot);continue
    if command==23:
        require(not payload,"original EOF witness payload")
        eof_witness=True;reply(0,slot=slot);continue
    if command==24:
        require(len(payload)==8 and U(payload,0)<=1048576,"actual regular-file resource bound")
        resource.setrlimit(resource.RLIMIT_FSIZE,(U(payload,0),U(payload,0)));reply(0,slot=slot);continue
    if command==27:
        require(len(payload)==8 and U(payload,0)==1 and proxy.actor==0,"one fixed private descriptor-table actor")
        proxy.actor=1;proxy.actor_step=0;reply(0,slot=slot);continue
    if command==2:
        require(states[slot]==2 and not payload,"original result must be held")
        states[slot]=0;reply(0,slot=slot);continue
    if command==3:
        require(states[slot]==0 and not payload,"original context must be idle")
        states[slot]=None;reply(0,slot=slot);continue
    require(command==1 and states[slot]==0,"one admitted original invocation")
    query=decode(payload)
    require(set(query)=={"op","root","path","expected_version","data_base64","observer"} and query["op"]=="write",
            "exact retained main write arguments")
    generations[slot]+=1
    proxy.begin(generations[slot],query["observer"])
    try:
        value=namespace["main"](query)
        result=dict(ok=True,value=value,original_json=json.dumps(value,ensure_ascii=True,allow_nan=False))
    except BaseException as error:
        result=dict(ok=False,error=exception(error),error_chain=error_chain(error))
    result.update(binding=binding,parent_events=proxy.events,actual_seccomp_filters=list(proxy.filters),
                  unused_fault_plans=len(proxy.plans)-proxy.plan_at,descriptor_actor=proxy.actor_events,
                  descriptor_actor_complete=proxy.actor==0 or proxy.actor_step==2)
    states[slot]=2
    reply(0,encoded(result),slot)
if control:os.close(control)
if eof_witness:
    write(4,b"HBWTEOF1"+bytes(56))
    require(read(5,8)==bytes(8),"original final live FD witness ACK")
