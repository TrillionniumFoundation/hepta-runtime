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
from common import decode,encoded,pin,require
WORD=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
class Carrier:
    def __init__(self,binary,folder,store):
        self.binary=Path(binary);self.folder=Path(folder);self.store=store;self.ordinal=0
        self.hooks=None;self.notify_buffer=b"";self.notify_eof=False
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
        try:
            for source,target in ((input_read,0),(output_write,1),(self.errors.fileno(),2),(journal_write,3),(notify_write,4),(ack_read,5)):
                duplicate=fcntl.fcntl(source,fcntl.F_DUPFD_CLOEXEC,64);descriptors.append(duplicate)
                actions.append((os.POSIX_SPAWN_DUP2,duplicate,target))
            actions += [(os.POSIX_SPAWN_CLOSE,fd) for fd in descriptors]
            environment=dict(os.environ);environment["PATH"]=""
            self.pid=os.posix_spawn(str(self.binary),[str(self.binary)],environment,file_actions=actions)
            self.receipt=dict(binary=pin(self.binary),pid=self.pid,argv=[str(self.binary)],
                started_ns=time.monotonic_ns(),parent_pgid=os.getpgrp(),child_pgid=os.getpgid(self.pid),
                same_outer_process_group=os.getpgid(self.pid)==os.getpgrp(),fixed_journal_fd=3,fixed_notify_fd=4,fixed_ack_fd=5,returncode=None)
            require(self.receipt["same_outer_process_group"],"carrier escaped observer process group")
        except BaseException:
            os.close(input_write);os.close(output_read);os.close(journal_read);os.close(notify_read);os.close(ack_write);raise
        finally:
            os.close(input_read);os.close(output_write);os.close(journal_write);os.close(notify_write);os.close(ack_read)
            for fd in descriptors:os.close(fd)
        self.input_fd=input_write;self.output_fd=output_read;self.journal_fd=journal_read
        self.notify_fd=notify_read;self.ack_fd=ack_write
        for fd in(self.input_fd,self.output_fd,self.journal_fd,self.notify_fd):os.set_blocking(fd,False)
        self.buffer=b"";self.finished=False

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
    def exchange(self,command,session,payload=b""):
        require(command in range(1,14) and session in (0,1),"private fixture command differs")
        raw=b"HBRDFQ01"+struct.pack("<7Q",command,session,len(payload),0,0,0,0)+payload
        raw=struct.pack("<Q",len(raw))+raw
        begin=time.monotonic_ns();deadline=time.monotonic()+60
        self.drain_journal();before=self.journal_bytes
        self.sent.write(raw);self.sent.flush()
        pending=memoryview(raw);output=b"";wanted=64
        selector=selectors.DefaultSelector()
        selector.register(self.input_fd,selectors.EVENT_WRITE);selector.register(self.output_fd,selectors.EVENT_READ)
        selector.register(self.journal_fd,selectors.EVENT_READ)
        selector.register(self.notify_fd,selectors.EVENT_READ)
        try:
            while pending or len(output)<wanted:
                require(time.monotonic()<deadline,"carrier exchange exceeded 60 seconds")
                events=selector.select(max(0,deadline-time.monotonic()))
                require(events,"carrier exchange deadline")
                for key,mask in events:
                    if key.fd==self.journal_fd:
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
                            require(output[:8]==b"HBRDFR01","carrier response magic")
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
            input=self.store.put(raw),output=self.store.put(output),journal_begin=before,journal_end=after)
        self.records.write(encoded(row));self.records.flush()
        return output,row["exchange"]

    def observed_process(self):
        root=Path("/proc")/str(self.pid)
        descriptors={p.name:os.readlink(p) for p in sorted((root/"fd").iterdir(),key=lambda p:int(p.name))}
        return dict(fd=descriptors,maps=self.store.put((root/"maps").read_bytes()))

    def run(self,query,observer=True):
        from cases import wire
        from hooks import Hooks
        from read_journal import result as parse_result
        body=wire(query);session=query["id"]%2;chain=dict(session=session,parents=[],controls=[])
        held,index=self.exchange(10,session,query["parent"].encode()+b"\0")
        parent=WORD(held,8);require(parent<2147483648 and WORD(held,16)==0,"fixture failed to hold parent")
        chain.update(hold_exchange=index,parent_fd=parent,begin_exchange=index)
        def parent_stat(label):
            raw,n=self.exchange(13,session)
            require(WORD(raw,8)==0 and WORD(raw,16)==144,"borrowed parent was lost: "+label)
            chain["parents"].append(dict(label=label,exchange=n,bytes=self.store.put(raw[64:])))
        def context():
            raw,n=self.exchange(4,session);require(WORD(raw,8)==0,"full context observation")
            return raw[64:],n
        def refusal(label,command,payload,code):
            before,first=context();raw,n=self.exchange(command,session,payload);after,last=context()
            require(WORD(raw,8)==code and before==after,"refusal changed full context: "+label)
            chain["controls"].append(dict(name=label,command=command,exchange=n,code=code,
                before=dict(exchange=first,bytes=self.store.put(before)),
                after=dict(exchange=last,bytes=self.store.put(after))))
        parent_stat("before")
        if query["id"]in(1,2)and observer:
            raw,n=self.exchange(8,session);require(WORD(raw,8)==0,"fresh explicit context")
            chain["explicit_create"]=n
            invalid=bytearray(body);struct.pack_into("<Q",invalid,32,123)
            refusal("caller-selected-fd",11,bytes(invalid),0xffffffff)
            refusal("at-packet-through-path-entry",1,body,0xffffffff)
        hooks=Hooks(query,self.pid,self.store);self.hooks=hooks;hooks.limit_enter()
        try:raw,first=self.exchange(11 if query["entry"]=="at"else 1,session,body)
        finally:hooks.limit_leave()
        require(WORD(raw,8)==64 and WORD(raw,24)==2 and WORD(raw,40)==0,"native body did not publish/drain")
        frame=raw[64:];result=parse_result(frame)
        snapshots={}
        for command,name in((4,"context"),(5,"workspace"),(6,"output"),(7,"input")):
            captured,n=self.exchange(command,session)
            require(WORD(captured,8)==0 and WORD(captured,24)==2,"complete arena observation failed")
            snapshots[name]=dict(exchange=n,bytes=self.store.put(captured[64:]))
        if query["id"]in(1,2)and observer:
            refusal("invoke-with-live-result-loan",11,body,0xfffffffd)
            refusal("destroy-with-live-result-loan",3,b"",0xfffffffd)
        parent_stat("after-result")
        process=self.observed_process()
        released,release=self.exchange(2,session)
        require(WORD(released,8)==0 and WORD(released,24)==0 and WORD(released,40)==0,"result loan release")
        parent_stat("after-release")
        if query["id"]%3==0 and observer:
            destroyed,n=self.exchange(3,session)
            require(WORD(destroyed,8)==0 and WORD(destroyed,24)==0,"context destruction")
            chain["destroy_exchange"]=n;parent_stat("after-destroy")
        dropped,last=self.exchange(12,session);require(WORD(dropped,8)==0,"caller parent release failed")
        self.hooks=None
        chain.update(first_exchange=first,last_exchange=last,release_exchange=release,
            generation=WORD(raw,32),snapshots=snapshots,process=process)
        return result,chain,hooks.result()

    def finish(self):
        require(not self.finished,"carrier already finished");os.close(self.input_fd);self.input_fd=None
        selector=selectors.DefaultSelector();selector.register(self.output_fd,selectors.EVENT_READ)
        selector.register(self.journal_fd,selectors.EVENT_READ);output_eof=False
        deadline=time.monotonic()+60
        try:
            while not output_eof or not self.journal_eof:
                events=selector.select(max(0,deadline-time.monotonic()));require(events,"carrier EOF deadline")
                for key,_ in events:
                    if key.fd==self.journal_fd:
                        self.drain_journal()
                        if self.journal_eof:selector.unregister(self.journal_fd)
                    else:
                        chunk=os.read(self.output_fd,65536)
                        require(not chunk,"carrier produced extra stdout after EOF")
                        output_eof=True;selector.unregister(self.output_fd)
        finally:selector.close()
        os.close(self.output_fd);self.output_fd=None
        os.close(self.journal_fd);self.journal_fd=None
        while True:
            pid,status=os.waitpid(self.pid,os.WNOHANG)
            if pid:break
            require(time.monotonic()<deadline,"carrier final reap deadline")
            time.sleep(.001)
        self.drain_hooks();require(self.notify_eof and not self.notify_buffer,"unread native effect suffix")
        os.close(self.notify_fd);self.notify_fd=None;os.close(self.ack_fd);self.ack_fd=None
        self.receipt["returncode"]=os.waitstatus_to_exitcode(status)
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
            try:pid,status=os.waitpid(self.pid,0)
            except ChildProcessError:status=None
            self.receipt["cleanup_wait_status"]=status
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
            self.receipt["streams"]={name:pin(self.folder/("carrier."+name)) for name in ("stdin","stderr")}
            self.receipt["stdout"]=dict(raw=dict(bytes=self.received_bytes,sha256=self.received_digest.hexdigest()),compressed=pin(self.folder/"carrier.stdout.gz"))
            (self.folder/"carrier-failure-process.json").write_bytes(encoded(self.receipt))
