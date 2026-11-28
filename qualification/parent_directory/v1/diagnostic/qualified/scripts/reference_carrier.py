#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Framed actual original process, separate fixed barrier and fixture owner."""
from pathlib import Path
import fcntl,os,selectors,signal,sys,time
from common import canonical,decode,pin,require
class Reference:
    def __init__(self,source,folder,store):
        self.source=source;self.folder=folder;self.store=store;self.hooks=None;self.ordinal=0;self.finished=False
        self.sent=(folder/"original.stdin").open("xb");self.received=(folder/"original.stdout").open("xb")
        self.errors=(folder/"original.stderr").open("xb");self.records=(folder/"exchanges.jsonl").open("xb")
        ir,iw=os.pipe();orr,ow=os.pipe();nr,nw=os.pipe();ar,aw=os.pipe();duplicates=[];actions=[]
        self.notify_buffer=b""
        try:
            for original,target in((ir,0),(ow,1),(self.errors.fileno(),2),(nw,4),(ar,5)):
                copy=fcntl.fcntl(original,fcntl.F_DUPFD_CLOEXEC,64);duplicates.append(copy)
                actions.append((os.POSIX_SPAWN_DUP2,copy,target))
            actions.extend((os.POSIX_SPAWN_CLOSE,fd)for fd in duplicates)
            argv=[sys.executable,"-I","-S","-B",str(source/"scripts/reference_worker.py"),str(source)]
            self.pid=os.posix_spawn(sys.executable,argv,dict(os.environ),file_actions=actions)
            self.receipt=dict(pid=self.pid,argv=argv,started_ns=time.monotonic_ns(),parent_pgid=os.getpgrp(),
                child_pgid=os.getpgid(self.pid),fixed_notify_fd=4,fixed_ack_fd=5)
            require(self.receipt["parent_pgid"]==self.receipt["child_pgid"],"reference escaped producer group")
        except BaseException:
            for fd in(iw,orr,nr,aw):os.close(fd)
            raise
        finally:
            for fd in(ir,ow,nw,ar,*duplicates):os.close(fd)
        self.input_fd=iw;self.output_fd=orr;self.notify_fd=nr;self.ack_fd=aw
        for fd in(iw,orr,nr):os.set_blocking(fd,False)
    def drain_hooks(self):
        while True:
            try:part=os.read(self.notify_fd,4096)
            except BlockingIOError:break
            if not part:break
            self.notify_buffer+=part
            while len(self.notify_buffer)>=64:
                frame,self.notify_buffer=self.notify_buffer[:64],self.notify_buffer[64:]
                require(self.hooks is not None,"original emitted an unowned barrier")
                ack=self.hooks.consume(frame);require(os.write(self.ack_fd,ack)==8,"complete original ack")
    def exchange(self,value):
        raw=canonical(value);self.sent.write(raw);self.sent.flush();pending=memoryview(raw);reply=b""
        start=time.monotonic_ns();deadline=time.monotonic()+60;selector=selectors.DefaultSelector()
        selector.register(self.input_fd,selectors.EVENT_WRITE);selector.register(self.output_fd,selectors.EVENT_READ)
        selector.register(self.notify_fd,selectors.EVENT_READ)
        try:
            while pending or not reply.endswith(b"\n"):
                events=selector.select(max(0,deadline-time.monotonic()));require(events,"original exchange deadline")
                for key,_ in events:
                    if key.fd==self.input_fd:
                        count=os.write(key.fd,pending);require(count>0,"original input write");pending=pending[count:]
                        if not pending:selector.unregister(self.input_fd)
                    elif key.fd==self.notify_fd:self.drain_hooks()
                    else:
                        part=os.read(self.output_fd,1<<20);require(part,"original EOF before response")
                        reply+=part;require(len(reply)<=8<<20 and b"\n"not in reply[:-1],"original response framing")
            self.drain_hooks()
        finally:selector.close()
        self.received.write(reply);self.received.flush();self.ordinal+=1
        row=dict(exchange=self.ordinal,input=self.store.put(raw),output=self.store.put(reply),
            elapsed_ns=time.monotonic_ns()-start)
        self.records.write(canonical(row));self.records.flush();return decode(reply),self.ordinal
    def finish(self):
        os.close(self.input_fd);self.input_fd=None;deadline=time.monotonic()+60
        while True:
            pid,status=os.waitpid(self.pid,os.WNOHANG)
            if pid:break
            self.drain_hooks()
            require(time.monotonic()<deadline,"original final reap deadline");time.sleep(.001)
        require(os.waitstatus_to_exitcode(status)==0,"original worker failed")
        self.receipt.update(returncode=0,elapsed_ns=time.monotonic_ns()-self.receipt["started_ns"])
        require(os.read(self.output_fd,1)==b""and os.read(self.notify_fd,1)==b""and not self.notify_buffer,
            "original unread stream suffix")
        for name in("input_fd","output_fd","notify_fd","ack_fd"):
            fd=getattr(self,name)
            if fd is not None:os.close(fd);setattr(self,name,None)
        for s in(self.sent,self.received,self.errors,self.records):s.close()
        require((self.folder/"original.stderr").read_bytes()==b"","original stderr differs")
        self.receipt["streams"]={n:pin(self.folder/("original."+n))for n in("stdin","stdout","stderr")}
        (self.folder/"original-process.json").write_bytes(canonical(self.receipt));self.finished=True
        return self.receipt
    def cleanup(self):
        if not self.finished:
            try:os.kill(self.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            try:os.waitpid(self.pid,0)
            except ChildProcessError:pass
        for name in("input_fd","output_fd","notify_fd","ack_fd"):
            fd=getattr(self,name,None)
            if fd is not None:
                try:os.close(fd)
                except OSError:pass
                setattr(self,name,None)
        for name in("sent","received","errors","records"):
            s=getattr(self,name,None)
            if s and not s.closed:s.close()
