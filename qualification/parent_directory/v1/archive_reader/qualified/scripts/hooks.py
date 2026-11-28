# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
from pathlib import Path,PurePosixPath
import os,resource,struct
from common import require
from filesystem import snapshot,metadata
U=lambda b,o:struct.unpack_from("<Q",b,o)[0]
class Hooks:
    def __init__(self,pid,store):
        self.pid=pid;self.store=store;self.query=None;self.rows=[];self.counts={};self.mutations=[];self.limit=None
    def select(self,q):
        self.query=q;self.counts={};self.limit=None
    def limit_enter(self):
        q=self.query
        if q["free_fds"]is None:return
        descriptors={p.name:os.readlink(p)for p in(Path("/proc")/str(self.pid)/"fd").iterdir()}
        numbers=sorted(map(int,descriptors));require(numbers==list(range(6)),"fixed six descriptor fixture differs")
        before=resource.prlimit(self.pid,resource.RLIMIT_NOFILE);soft=6+q["free_fds"]
        resource.prlimit(self.pid,resource.RLIMIT_NOFILE,(soft,before[1]))
        require(resource.prlimit(self.pid,resource.RLIMIT_NOFILE)==(soft,before[1]),"descriptor limit not installed")
        self.limit=dict(before=list(before),during=[soft,before[1]],fds=descriptors,free=q["free_fds"])
    def limit_leave(self):
        if self.limit is not None and "after"not in self.limit:
            resource.prlimit(self.pid,resource.RLIMIT_NOFILE,tuple(self.limit["before"]))
            self.limit["after"]=list(resource.prlimit(self.pid,resource.RLIMIT_NOFILE))
            require(self.limit["after"]==self.limit["before"],"descriptor limit not restored")
    def apply(self,phase,operation=None,occurrence=None):
        q=self.query
        if q is None or q["mutation"]is None:return
        name=q["mutation"]
        if phase=="walk":
            if name not in("walk_symlink","walk_rename")or operation!=2:return
            parts=PurePosixPath(q["request"]["path"]).parts[1:-1]
            if occurrence!=len(parts):return
        elif phase=="held":
            if not name.startswith("held_"):return
        else:raise ValueError("unknown fixture phase")
        require(not any(r["id"]==q["id"]for r in self.mutations),"mutation twice")
        root=Path(q["fixture"]);before=snapshot(root,self.store);parent=root/"parent";sub=parent/"sub"
        if name=="held_rename":sub.rename(parent/"moved")
        elif name=="held_replace":
            sub.rename(parent/"moved");sub.mkdir();(sub/"replacement.bin").write_bytes(b"new-path-owner")
        elif name=="held_unlink":(parent/"empty").rmdir()
        elif name=="held_chmod":sub.chmod(0o711)
        elif name=="walk_symlink":sub.rename(parent/"moved");os.symlink("moved",sub)
        elif name=="walk_rename":
            parent.rename(root/"moved-parent");parent.mkdir();(parent/"sub").mkdir()
        else:raise ValueError("unknown actual mutation")
        after=snapshot(root,self.store)
        self.mutations.append(dict(id=q["id"],name=name,phase=phase,operation=operation,occurrence=occurrence,
            before=before,after=after,actor_pid=os.getpid(),target_pid=self.pid,separate_process=os.getpid()!=self.pid))
    def consume(self,raw):
        require(len(raw)==64 and raw[:8]==b"HPRDHK01","actual hook frame")
        op=U(raw,32);self.counts[op]=self.counts.get(op,0)+1;occ=self.counts[op]
        self.apply("walk",op,occ)
        row=dict(id=None if self.query is None else self.query["id"],raw=self.store.put(raw),
            operation=op,occurrence=occ,ack=self.store.put(bytes(8)))
        if op in(2,5):
            fd=U(raw,40);path="/proc/"+str(self.pid)+"/fd/"+str(fd)
            row["fd"]=fd;row["target"]=os.readlink(path);row["stat"]=metadata(os.stat(path))
        self.rows.append(row);return bytes(8)
