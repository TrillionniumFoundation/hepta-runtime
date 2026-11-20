#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Owned-process binary transport; no binary file or expected-result decisions."""
from pathlib import Path
import fcntl
import gzip
import hashlib
import os
import selectors
import signal
import struct
import time
import sys
from kernel_trace import Trace,ptrace
from evidence_common import decode,encoded,pin,require
WORD=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
def _sigchld_wakeup(signum,frame):
    # set_wakeup_fd writes the actual signal byte; no target value is supplied.
    pass
class Carrier:
    TRACE_CLASS=Trace
    def __init__(self,binary,folder,store,argv=None):
        self.binary=Path(binary);self.folder=Path(folder);self.store=store;self.ordinal=0
        self.hooks=None;self.notify_buffer=b"";self.notify_eof=False;self.trace=None
        self.records=(self.folder/"exchanges.jsonl").open("xb")
        self.sent=(self.folder/"carrier.stdin").open("xb")
        self.received_raw=(self.folder/"carrier.stdout.gz").open("xb")
        self.received=gzip.GzipFile(filename="",fileobj=self.received_raw,mode="wb",compresslevel=1,mtime=0)
        self.received_digest=hashlib.sha256();self.received_bytes=0
        self.errors=(self.folder/"carrier.stderr").open("xb")
        self.journal_raw=(self.folder/"carrier.journal.gz").open("xb")
        self.journal=gzip.GzipFile(filename="",fileobj=self.journal_raw,mode="wb",compresslevel=1,mtime=0)
        self.journal_digest=hashlib.sha256();self.journal_bytes=0;self.journal_eof=False
        input_read,input_write=os.pipe();output_read,output_write=os.pipe()
        journal_read,journal_write=os.pipe()
        notify_read,notify_write=os.pipe();ack_read,ack_write=os.pipe()
        descriptors=[];actions=[]
        self.wakeup_read=self.wakeup_write=None
        self.previous_sigchld=None;self.wakeup_installed=False
        try:
            self.open_wakeup()
            for source,target in ((input_read,0),(output_write,1),(self.errors.fileno(),2),(journal_write,3),(notify_write,4),(ack_read,5)):
                duplicate=fcntl.fcntl(source,fcntl.F_DUPFD_CLOEXEC,64);descriptors.append(duplicate)
                actions.append((os.POSIX_SPAWN_DUP2,duplicate,target))
            actions += [(os.POSIX_SPAWN_CLOSE,fd) for fd in descriptors]
            environment=dict(os.environ);environment["PATH"]=""
            argv=[str(self.binary)] if argv is None else [str(x) for x in argv]
            require(argv and argv[0]==str(self.binary),"owned executable argv")
            target_argv=argv
            launcher=Path(__file__).with_name("trace_launch.py").resolve(strict=True)
            executable=Path(sys.executable).resolve(strict=True)
            launch_argv=[str(executable),"-I","-S","-B",str(launcher),*target_argv]
            self.pid=os.posix_spawn(str(executable),launch_argv,environment,file_actions=actions)
            self.receipt=dict(binary=pin(self.binary),pid=self.pid,argv=target_argv,
                launcher=pin(launcher),launcher_python=pin(executable),launcher_argv=launch_argv,
                started_ns=time.monotonic_ns(),parent_pgid=os.getpgrp(),child_pgid=os.getpgid(self.pid),
                same_outer_process_group=os.getpgid(self.pid)==os.getpgrp(),fixed_journal_fd=3,fixed_notify_fd=4,fixed_ack_fd=5,returncode=None)
            self.receipt["observer_wait"]=dict(kind="SIGCHLD-pipe",parent_only=True,target_signal_replacement=False)
            require(self.receipt["same_outer_process_group"],"carrier escaped observer process group")
            self.trace=self.TRACE_CLASS(self.pid,self.folder)
        except BaseException:
            self.close_wakeup()
            os.close(input_write);os.close(output_read);os.close(journal_read);os.close(notify_read);os.close(ack_write);raise
        finally:
            os.close(input_read);os.close(output_write);os.close(journal_write);os.close(notify_write);os.close(ack_read)
            for fd in descriptors:os.close(fd)
        self.input_fd=input_write;self.output_fd=output_read;self.journal_fd=journal_read
        self.notify_fd=notify_read;self.ack_fd=ack_write
        for fd in(self.input_fd,self.output_fd,self.journal_fd,self.notify_fd):os.set_blocking(fd,False)
        self.buffer=b"";self.finished=False

    def open_wakeup(self):
        require(signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL,"owned observer requires the default parent SIGCHLD handler")
        self.previous_sigchld=signal.getsignal(signal.SIGCHLD)
        self.wakeup_read,self.wakeup_write=os.pipe2(os.O_NONBLOCK|os.O_CLOEXEC)
        signal.signal(signal.SIGCHLD,_sigchld_wakeup)
        previous=signal.set_wakeup_fd(self.wakeup_write,warn_on_full_buffer=False)
        if previous!=-1:
            signal.set_wakeup_fd(previous)
            signal.signal(signal.SIGCHLD,self.previous_sigchld)
            os.close(self.wakeup_read);os.close(self.wakeup_write)
            self.wakeup_read=self.wakeup_write=None;self.previous_sigchld=None
            raise ValueError("an existing parent signal wakeup owner is active")
        self.wakeup_installed=True

    def drain_wakeup(self):
        while True:
            try:raw=os.read(self.wakeup_read,4096)
            except BlockingIOError:return
            require(raw and all(value==signal.SIGCHLD for value in raw),"unexpected parent observer wakeup signal")

    def close_wakeup(self):
        if self.wakeup_read is None:return
        if self.wakeup_installed:
            require(signal.set_wakeup_fd(-1)==self.wakeup_write,"parent observer wakeup ownership changed")
        signal.signal(signal.SIGCHLD,self.previous_sigchld)
        os.close(self.wakeup_read);os.close(self.wakeup_write)
        self.wakeup_read=self.wakeup_write=None;self.previous_sigchld=None;self.wakeup_installed=False

    def drain_journal(self):
        while not self.journal_eof:
            try:chunk=os.read(self.journal_fd,1<<20)
            except BlockingIOError:break
            if not chunk:self.journal_eof=True;break
            self.journal.write(chunk);self.journal_digest.update(chunk);self.journal_bytes+=len(chunk)

    def drain_hooks(self):
        while not self.notify_eof:
            try:part=os.read(self.notify_fd,4096)
            except BlockingIOError:break
            if not part:self.notify_eof=True;break
            self.notify_buffer+=part
            while len(self.notify_buffer)>=64:
                frame,self.notify_buffer=self.notify_buffer[:64],self.notify_buffer[64:]
                require(self.hooks is not None,"native emitted an unowned notification")
                ack=self.hooks.consume(frame);require(os.write(self.ack_fd,ack)==8,"complete native ack")
    def exchange(self,command,session,payload=b"",application=False):
        require(command in range(1,35) and session in (0,1),"private fixture command differs")
        raw=b"HBWTFQ01"+struct.pack("<7Q",command,session,len(payload),0,0,0,0)+payload
        raw=struct.pack("<Q",len(raw))+raw
        begin=time.monotonic_ns();deadline=time.monotonic()+60
        trace_begin=self.trace.mark("exchange-"+str(self.ordinal+1)+"-command-"+str(command),application=application)
        self.drain_journal();before=self.journal_bytes
        self.sent.write(raw);self.sent.flush()
        pending=memoryview(raw);output=b"";wanted=64
        selector=selectors.DefaultSelector()
        selector.register(self.input_fd,selectors.EVENT_WRITE);selector.register(self.output_fd,selectors.EVENT_READ)
        selector.register(self.journal_fd,selectors.EVENT_READ)
        selector.register(self.notify_fd,selectors.EVENT_READ)
        selector.register(self.wakeup_read,selectors.EVENT_READ)
        try:
            while pending or len(output)<wanted:
                require(time.monotonic()<deadline,"carrier exchange exceeded 60 seconds")
                # Drain before waitpid, never after it: otherwise a fresh stop's
                # only wakeup could be consumed just before the blocking wait.
                self.drain_wakeup();self.trace.pump()
                events=selector.select(max(0,deadline-time.monotonic()))
                if not events:continue
                for key,mask in events:
                    if key.fd==self.wakeup_read:
                        self.drain_wakeup();self.trace.pump()
                    elif key.fd==self.journal_fd:
                        self.drain_journal();require(not self.journal_eof,"journal closed before complete response")
                    elif key.fd==self.notify_fd:
                        self.drain_hooks();require(not self.notify_eof,"notification pipe closed early")
                    elif key.fd==self.input_fd:
                        count=os.write(key.fd,pending)
                        require(count>0,"zero carrier input write");pending=pending[count:]
                        if not pending:selector.unregister(self.input_fd)
                    else:
                        chunk=os.read(key.fd,1<<20)
                        require(chunk,"carrier EOF before complete private response")
                        self.received.write(chunk);self.received_digest.update(chunk);self.received_bytes+=len(chunk);output+=chunk
                        if len(output)>=64:
                            require(output[:8]==b"HBWTFR01","carrier response magic")
                            wanted=64+WORD(output,16)
                            require(wanted<=256*(1<<20)+64,"carrier private response exceeds owned profile")
                            require(len(output)<=wanted,"carrier extra response bytes")
            require(not pending and len(output)==wanted,"carrier incomplete exchange")
        finally:selector.close()
        self.received.flush()
        # The fixture completes each journal write before publishing its response.
        # Drain all bytes already in the observer pipe before binding this exchange.
        self.drain_journal();after=self.journal_bytes;self.ordinal+=1
        row=dict(exchange=self.ordinal,command=command,session=session,elapsed_ns=time.monotonic_ns()-begin,
            input=self.store.put(raw),output=self.store.put(output),journal_begin=before,journal_end=after,
            trace_begin=trace_begin,trace_end=dict(rows=self.trace.rows,calls=self.trace.calls),application=application)
        self.records.write(encoded(row));self.records.flush()
        return output,row["exchange"]

    def observed_process(self):
        root=Path("/proc")/str(self.pid)
        descriptors={p.name:os.readlink(p) for p in sorted((root/"fd").iterdir(),key=lambda p:int(p.name))}
        return dict(fd=descriptors,maps=self.store.put((root/"maps").read_bytes()))

    def observed_context(self,expected):
        """Read every guarded context candidate from the actual quiescent process."""
        require(len(expected)==4096 and expected[:8]in(b"HBPWCI01",b"HBCWCI01"),"complete returned parent context")
        from kernel_trace import memory
        path=Path("/proc")/str(self.pid)/"maps";before=path.read_bytes();ranges=[]
        for line in before.decode().splitlines():
            fields=line.split();lo,hi=(int(x,16)for x in fields[0].split("-"))
            ranges.append((lo,hi,fields[1]))
        candidates=[];matches=[]
        for lo,hi,permission in ranges:
            if permission!="rw-p"or hi-lo<4096:continue
            if not any(a<=hi and hi+4096<=b and p=="---p"for a,b,p in ranges):continue
            address=hi-4096;first=memory(self.pid,address,4096);second=memory(self.pid,address,4096)
            require(first==second,"quiescent complete candidate changed during observation")
            candidates.append(dict(address=address,bytes=self.store.put(first),second=self.store.put(second)))
            if first==expected:matches.append(address)
        after=path.read_bytes()
        require(before==after and len(matches)==1,"one actual complete root context and stable mapping")
        return dict(address=matches[0],maps_before=self.store.put(before),maps_after=self.store.put(after),
            candidates=candidates,observation="process_vm_readv",writes=0)
 
    def finish(self):
        require(not self.finished,"carrier already finished")
        self.trace.mark("fixture-eof");os.close(self.input_fd);self.input_fd=None
        selector=selectors.DefaultSelector();selector.register(self.output_fd,selectors.EVENT_READ)
        selector.register(self.journal_fd,selectors.EVENT_READ);selector.register(self.notify_fd,selectors.EVENT_READ)
        selector.register(self.wakeup_read,selectors.EVENT_READ)
        output_eof=False;deadline=time.monotonic()+60
        try:
            while not output_eof or not self.journal_eof or not self.notify_eof:
                require(time.monotonic()<deadline,"carrier EOF deadline")
                self.drain_wakeup();self.trace.pump();events=selector.select(max(0,deadline-time.monotonic()))
                for key,_ in events:
                    if key.fd==self.wakeup_read:
                        self.drain_wakeup();self.trace.pump()
                    elif key.fd==self.journal_fd:
                        self.drain_journal()
                        if self.journal_eof:selector.unregister(self.journal_fd)
                    elif key.fd==self.notify_fd:
                        self.drain_hooks()
                        if self.notify_eof:selector.unregister(self.notify_fd)
                    else:
                        chunk=os.read(self.output_fd,65536)
                        require(not chunk,"carrier produced extra stdout after EOF")
                        output_eof=True;selector.unregister(self.output_fd)
        finally:selector.close()
        for name in("output_fd","journal_fd","notify_fd","ack_fd"):
            os.close(getattr(self,name));setattr(self,name,None)
        while self.trace.status is None:
            self.trace.pump()
            require(time.monotonic()<deadline,"carrier final reap deadline")
            if self.trace.status is None:time.sleep(.001)
        require(not self.notify_buffer,"unread native effect suffix")
        self.receipt["returncode"]=os.waitstatus_to_exitcode(self.trace.status)
        self.receipt["kernel"]=self.trace.finish()
        self.close_wakeup()
        require(self.receipt["returncode"]==0,"carrier process failed")
        self.finished=True;self.receipt["elapsed_ns"]=time.monotonic_ns()-self.receipt["started_ns"]
        for stream in (self.sent,self.received,self.received_raw,self.errors,self.records,self.journal,self.journal_raw):stream.close()
        require((self.folder/"carrier.stderr").read_bytes()==b"","native carrier stderr")
        raw_pin=dict(bytes=self.journal_bytes,sha256=self.journal_digest.hexdigest())
        archive=self.folder/"carrier.journal.gz"
        with gzip.open(archive,"rb") as reader:
            digest=hashlib.sha256();count=0
            while True:
                block=reader.read(1<<20)
                if not block:break
                digest.update(block);count+=len(block)
        require(dict(bytes=count,sha256=digest.hexdigest())==raw_pin,"complete raw journal gzip differs")
        self.receipt["journal"]=dict(raw=raw_pin,compressed=pin(archive),complete_raw_bytes_in_gzip=True,no_expanded_ordinary_copy_created=True)
        self.receipt["streams"]={name:pin(self.folder/("carrier."+name)) for name in ("stdin","stderr")}
        self.receipt["stdout"]=dict(raw=dict(bytes=self.received_bytes,sha256=self.received_digest.hexdigest()),compressed=pin(self.folder/"carrier.stdout.gz"))
        (self.folder/"carrier-process.json").write_bytes(encoded(self.receipt))
        return self.receipt

    def cleanup(self):
        if not self.finished:
            try:os.kill(self.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            status=None;deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                try:pid,status=os.waitpid(self.pid,os.WNOHANG|0x40000000)
                except ChildProcessError:break
                if not pid:time.sleep(.001);continue
                if os.WIFEXITED(status)or os.WIFSIGNALED(status):break
                if os.WIFSTOPPED(status):
                    try:ptrace(24,self.pid,data=signal.SIGKILL)
                    except ProcessLookupError:break
            self.receipt["cleanup_wait_status"]=status
            if self.trace is not None:self.trace.close_failure()
        self.close_wakeup()
        for name in ("input_fd","output_fd","journal_fd","notify_fd","ack_fd"):
            fd=getattr(self,name,None)
            if fd is not None:
                try:os.close(fd)
                except OSError:pass
                setattr(self,name,None)
        for name in ("sent","received","received_raw","errors","records","journal","journal_raw"):
            stream=getattr(self,name,None)
            if stream is not None and not stream.closed:stream.close()
        if not self.finished:
            self.receipt["failed"]=True
            self.receipt["journal"]=dict(raw=dict(bytes=self.journal_bytes,sha256=self.journal_digest.hexdigest()),compressed=pin(self.folder/"carrier.journal.gz"))
            self.receipt["streams"]={name:pin(self.folder/("carrier."+name)) for name in ("stdin","stderr")}
            self.receipt["stdout"]=dict(raw=dict(bytes=self.received_bytes,sha256=self.received_digest.hexdigest()),compressed=pin(self.folder/"carrier.stdout.gz"))
            (self.folder/"carrier-failure-process.json").write_bytes(encoded(self.receipt))
