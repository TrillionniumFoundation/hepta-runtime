#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Owned-process binary transport; no publication or expected-result decisions."""
from pathlib import Path
import fcntl
import gzip
import hashlib
import os
import selectors
import signal
import struct
import time
from callable_common import decode,encoded,pin,require
WORD=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
class Carrier:
    def __init__(self,binary,folder,store):
        self.binary=Path(binary);self.folder=Path(folder);self.store=store;self.ordinal=0
        self.records=(self.folder/"exchanges.jsonl").open("xb")
        self.sent=(self.folder/"carrier.stdin").open("xb")
        self.received_raw=(self.folder/"carrier.stdout.gz").open("xb")
        self.received=gzip.GzipFile(filename="",fileobj=self.received_raw,mode="wb",compresslevel=1,mtime=0)
        self.received_digest=hashlib.sha256();self.received_bytes=0
        self.errors=(self.folder/"carrier.stderr").open("xb")
        self.journal=(self.folder/"carrier.journal.raw").open("xb")
        input_read,input_write=os.pipe();output_read,output_write=os.pipe()
        descriptors=[];actions=[]
        try:
            for source,target in ((input_read,0),(output_write,1),(self.errors.fileno(),2),(self.journal.fileno(),3)):
                duplicate=fcntl.fcntl(source,fcntl.F_DUPFD_CLOEXEC,64);descriptors.append(duplicate)
                actions.append((os.POSIX_SPAWN_DUP2,duplicate,target))
            actions += [(os.POSIX_SPAWN_CLOSE,fd) for fd in descriptors]
            self.pid=os.posix_spawn(str(self.binary),[str(self.binary)],dict(os.environ),file_actions=actions)
            self.receipt=dict(binary=pin(self.binary),pid=self.pid,argv=[str(self.binary)],
                started_ns=time.monotonic_ns(),parent_pgid=os.getpgrp(),child_pgid=os.getpgid(self.pid),
                same_outer_process_group=os.getpgid(self.pid)==os.getpgrp(),fixed_journal_fd=3,returncode=None)
            require(self.receipt["same_outer_process_group"],"carrier escaped observer process group")
        except BaseException:
            os.close(input_write);os.close(output_read);raise
        finally:
            os.close(input_read);os.close(output_write)
            for fd in descriptors:os.close(fd)
        self.input_fd=input_write;self.output_fd=output_read
        os.set_blocking(self.input_fd,False);os.set_blocking(self.output_fd,False)
        self.buffer=b"";self.finished=False

    def exchange(self,command,session,payload=b""):
        require(command in range(1,9) and session in (0,1),"private fixture command differs")
        raw=b"HTPCFQ01"+struct.pack("<7Q",command,session,len(payload),0,0,0,0)+payload
        raw=struct.pack("<Q",len(raw))+raw
        begin=time.monotonic_ns();deadline=time.monotonic()+60
        before=os.fstat(self.journal.fileno()).st_size
        self.sent.write(raw);self.sent.flush()
        pending=memoryview(raw);output=b"";wanted=64
        selector=selectors.DefaultSelector()
        selector.register(self.input_fd,selectors.EVENT_WRITE);selector.register(self.output_fd,selectors.EVENT_READ)
        try:
            while pending or len(output)<wanted:
                require(time.monotonic()<deadline,"carrier exchange exceeded 60 seconds")
                events=selector.select(max(0,deadline-time.monotonic()))
                require(events,"carrier exchange deadline")
                for key,mask in events:
                    if key.fd==self.input_fd:
                        count=os.write(key.fd,pending)
                        require(count>0,"zero carrier input write");pending=pending[count:]
                        if not pending:selector.unregister(self.input_fd)
                    else:
                        chunk=os.read(key.fd,1<<20)
                        require(chunk,"carrier EOF before complete private response")
                        self.received.write(chunk);self.received_digest.update(chunk);self.received_bytes+=len(chunk);output+=chunk
                        if len(output)>=64:
                            require(output[:8]==b"HTPCFR01","carrier response magic")
                            wanted=64+WORD(output,16)
                            require(wanted<=256*(1<<20)+64,"carrier private response exceeds owned profile")
                            require(len(output)<=wanted,"carrier extra response bytes")
            require(not pending and len(output)==wanted,"carrier incomplete exchange")
        finally:selector.close()
        self.received.flush()
        after=os.fstat(self.journal.fileno()).st_size;self.ordinal+=1
        row=dict(exchange=self.ordinal,command=command,session=session,elapsed_ns=time.monotonic_ns()-begin,
            input=self.store.put(raw),output=self.store.put(output),journal_begin=before,journal_end=after)
        self.records.write(encoded(row));self.records.flush()
        return output,row["exchange"]

    def observed_process(self):
        root=Path("/proc")/str(self.pid)
        descriptors={p.name:os.readlink(p) for p in sorted((root/"fd").iterdir(),key=lambda p:int(p.name))}
        return dict(fd=descriptors,maps=self.store.put((root/"maps").read_bytes()))

    def run(self,request):
        path=request["path"].encode();content=request["content"].encode();expected=request["expected_sha256"].encode()
        mode={"create":1,"replace":2,"append":3}[request["mode"]]
        body=b"HTPBQ001"+struct.pack("<7Q",1,0,mode,len(path),len(content),len(expected),
            len(path)+len(content)+len(expected))+path+content+expected
        session=request["id"]%2
        raw,first=self.exchange(1,session,body)
        require(WORD(raw,8)==64 and WORD(raw,24)==2 and WORD(raw,40)==0,"native callable did not publish/drain")
        frame=raw[64:]
        require(frame[:8]==b"HTPBS001" and len(frame)==64+WORD(frame,56)
            and WORD(frame,8) in (0,3) and all(WORD(frame,at)==0 for at in (24,32,40,48)),"body complete result framing")
        result=dict(id=request["id"],ok=WORD(frame,8)==0,text=frame[64:].decode())
        snapshots={}
        for command,name in ((4,"context"),(5,"workspace"),(6,"output"),(7,"input")):
            captured,number=self.exchange(command,session)
            require(WORD(captured,8)==0 and WORD(captured,24)==2,"private complete arena observation failed")
            snapshots[name]=dict(exchange=number,bytes=self.store.put(captured[64:]))
        process=self.observed_process()
        release,last=self.exchange(2,session)
        require(WORD(release,8)==0 and WORD(release,16)==0 and WORD(release,24)==0
            and WORD(release,40)==0,"explicit final borrow release failed")
        return result,dict(first_exchange=first,last_exchange=last,session=session,
            generation=WORD(raw,32),snapshots=snapshots,process=process)

    def finish(self):
        require(not self.finished,"carrier already finished");os.close(self.input_fd);self.input_fd=None
        selector=selectors.DefaultSelector();selector.register(self.output_fd,selectors.EVENT_READ)
        deadline=time.monotonic()+60
        try:
            while True:
                events=selector.select(max(0,deadline-time.monotonic()));require(events,"carrier EOF deadline")
                chunk=os.read(self.output_fd,65536)
                if not chunk:break
                self.received.write(chunk);self.received_digest.update(chunk);self.received_bytes+=len(chunk)
                raise ValueError("carrier produced extra stdout after EOF")
        finally:selector.close()
        os.close(self.output_fd);self.output_fd=None
        while True:
            pid,status=os.waitpid(self.pid,os.WNOHANG)
            if pid:break
            require(time.monotonic()<deadline,"carrier final reap deadline")
            time.sleep(.001)
        self.receipt["returncode"]=os.waitstatus_to_exitcode(status)
        require(self.receipt["returncode"]==0,"carrier process failed")
        self.finished=True;self.receipt["elapsed_ns"]=time.monotonic_ns()-self.receipt["started_ns"]
        for stream in (self.sent,self.received,self.received_raw,self.errors,self.records,self.journal):stream.close()
        require((self.folder/"carrier.stderr").read_bytes()==b"","native carrier stderr")
        raw_path=self.folder/"carrier.journal.raw";raw_pin=pin(raw_path);archive=self.folder/"carrier.journal.gz"
        with raw_path.open("rb") as incoming,archive.open("xb") as target:
            with gzip.GzipFile(filename="",fileobj=target,mode="wb",compresslevel=1,mtime=0) as out:
                while True:
                    block=incoming.read(1<<20)
                    if not block:break
                    out.write(block)
        with gzip.open(archive,"rb") as reader:
            digest=hashlib.sha256();count=0
            while True:
                block=reader.read(1<<20)
                if not block:break
                digest.update(block);count+=len(block)
        require(dict(bytes=count,sha256=digest.hexdigest())==raw_pin,"complete raw journal gzip differs")
        self.receipt["journal"]=dict(raw=raw_pin,compressed=pin(archive),ordinary_raw_removed_only_after_complete_equal_read=True)
        raw_path.unlink()
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
        for name in ("input_fd","output_fd"):
            fd=getattr(self,name,None)
            if fd is not None:
                try:os.close(fd)
                except OSError:pass
                setattr(self,name,None)
        for name in ("sent","received","received_raw","errors","records","journal"):
            stream=getattr(self,name,None)
            if stream is not None and not stream.closed:stream.close()
        if not self.finished:
            self.receipt["failed"]=True
            self.receipt["streams"]={name:pin(self.folder/("carrier."+name)) for name in ("stdin","stderr")}
            self.receipt["stdout"]=dict(raw=dict(bytes=self.received_bytes,sha256=self.received_digest.hexdigest()),compressed=pin(self.folder/"carrier.stdout.gz"))
            (self.folder/"carrier-failure-process.json").write_bytes(encoded(self.receipt))
