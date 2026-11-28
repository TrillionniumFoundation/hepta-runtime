#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""A separate fixture owner changes real files before a fixed actual OS call."""
from pathlib import Path
import os,resource,struct
from common import require
from filesystem import snapshot,metadata
WORD=lambda b,o:struct.unpack_from("<Q",b,o)[0]
class Hooks:
    def __init__(self,query,pid,store):
        self.query=query;self.pid=pid;self.store=store;self.rows=[];self.counts={};self.mutations=[];self.limit=None
    def limit_enter(self):
        if not self.query["fd_limit"]:return None
        descriptors={p.name:os.readlink(p)for p in(Path("/proc")/str(self.pid)/"fd").iterdir()}
        numbers=sorted(int(n)for n in descriptors)
        require(numbers==list(range(max(numbers)+1)),"descriptor fixture has a hole below highest FD")
        before=resource.prlimit(self.pid,resource.RLIMIT_NOFILE);soft=max(numbers)+2
        require(soft<=before[1],"insufficient hard descriptor limit")
        resource.prlimit(self.pid,resource.RLIMIT_NOFILE,(soft,before[1]))
        actual=resource.prlimit(self.pid,resource.RLIMIT_NOFILE)
        require(actual==(soft,before[1]),"descriptor limit was not installed")
        self.limit=dict(before=list(before),during=list(actual),fds=descriptors,only_free_fd=soft-1)
        return self.limit
    def limit_leave(self):
        if self.limit is not None and "after"not in self.limit:
            resource.prlimit(self.pid,resource.RLIMIT_NOFILE,tuple(self.limit["before"]))
            self.limit["after"]=list(resource.prlimit(self.pid,resource.RLIMIT_NOFILE))
            require(self.limit["after"]==self.limit["before"],"descriptor limit not restored")
    def apply(self,operation,occurrence):
        q=self.query;mutation=q["mutation"]
        if mutation is None:return
        trigger=(3,1)if mutation=="rename_parent"else(6,3)
        if (operation,occurrence)!=trigger:return
        require(not self.mutations,"mutation applied twice")
        before=snapshot(q["fixture"],self.store);parent=Path(q["parent"]);target=parent/"data.bin"
        if mutation=="rename_parent":parent.rename(parent.with_name("moved"))
        elif mutation=="append":
            with target.open("ab")as stream:stream.write(b"\x99\x01");stream.flush();os.fsync(stream.fileno())
        elif mutation=="truncate":
            with target.open("r+b")as stream:stream.truncate(1);stream.flush();os.fsync(stream.fileno())
        elif mutation=="overwrite":
            with target.open("r+b")as stream:
                first=stream.read(1);stream.seek(0);stream.write(bytes([first[0]^255]));stream.flush();os.fsync(stream.fileno())
        elif mutation=="chmod":target.chmod((target.stat().st_mode&0o777)^0o100)
        elif mutation=="utime":
            st=target.stat();os.utime(target,ns=(st.st_atime_ns,st.st_mtime_ns+2_000_000_001))
        elif mutation=="hardlink":os.link(target,parent/"mutation-link.bin")
        elif mutation=="unlink":target.unlink()
        elif mutation=="replace":os.replace(parent/"replacement.bin",target)
        else:raise ValueError("undeclared mutation")
        after=snapshot(q["fixture"],self.store)
        self.mutations.append(dict(name=mutation,operation=operation,occurrence=occurrence,
            before=before,after=after,actor_pid=os.getpid(),target_pid=self.pid,separate_process=os.getpid()!=self.pid))
    def consume(self,raw):
        require(len(raw)==64 and raw[:8]==b"HBRDHK01","complete fixed effect notification differs")
        operation=WORD(raw,32);occurrence=self.counts.get(operation,0)+1;self.counts[operation]=occurrence
        self.apply(operation,occurrence)
        row=dict(raw=self.store.put(raw),operation=operation,occurrence=occurrence,
            mutation=len(self.mutations),ack=self.store.put(bytes(8)))
        if operation==6:
            row["fd_stat"]=metadata(os.stat("/proc/"+str(self.pid)+"/fd/"+str(WORD(raw,40))))
        self.rows.append(row)
        return bytes(8)
    def result(self):
        require(len(self.mutations)==int(self.query["mutation"]is not None),"frozen mutation not performed")
        self.limit_leave()
        return dict(events=self.rows,mutations=self.mutations,descriptor_limit=self.limit)
