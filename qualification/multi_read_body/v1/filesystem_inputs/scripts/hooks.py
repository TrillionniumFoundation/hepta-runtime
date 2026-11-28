"""Actual before-effect barriers and independent file mutations; ACK is always zero."""
from pathlib import Path
import os,resource,struct
from evidence_common import require
from protocol import stat_value,exception,proc_fds
OWNERS={b"HMRDHK01":"body",b"HPD0HK01":"parent0",b"HPD1HK01":"parent1"}
class Hooks:
    def __init__(self,q,pid,fixture,store,reference=False):
        self.query=q;self.pid=pid;self.fixture=fixture;self.store=store;self.reference=reference
        self.counts={};self.events=[];self.actions=[];self.used=set();self.limits=[];self.attempt=0;self.eof=[]
    def begin(self,attempt):self.attempt=attempt;self.counts={}
    def descriptor(self,fd):
        try:return dict(ok=True,stat=stat_value(os.stat(Path("/proc")/str(self.pid)/"fd"/str(fd))))
        except OSError as e:return dict(ok=False,error=exception(e))
    def limit_enter(self):
        free=self.query["fd_free"]
        if free is None:return
        fds=proc_fds(self.pid);numbers=sorted(map(int,fds))
        require(numbers==list(range(max(numbers)+1)),"FD profile has a hole")
        before=resource.prlimit(self.pid,resource.RLIMIT_NOFILE);soft=max(numbers)+1+free
        require(soft<=before[1],"RLIMIT hard bound")
        resource.prlimit(self.pid,resource.RLIMIT_NOFILE,(soft,before[1]))
        during=resource.prlimit(self.pid,resource.RLIMIT_NOFILE)
        require(during==(soft,before[1]),"real FD limit")
        self.limits.append(dict(attempt=self.attempt,before=list(before),during=list(during),fds=fds,
            exactly_free_fds=list(range(max(numbers)+1,soft))))
    def limit_leave(self):
        if not self.limits or "after"in self.limits[-1]:return
        row=self.limits[-1];resource.prlimit(self.pid,resource.RLIMIT_NOFILE,tuple(row["before"]))
        row["after"]=list(resource.prlimit(self.pid,resource.RLIMIT_NOFILE))
        require(row["after"]==row["before"],"restore real descriptor limit")
    def consume(self,raw):
        if len(raw)==64 and raw[:8]==b"HMRDEOF1":
            require(not self.eof,"single pre-exit witness")
            self.eof.append(dict(raw=self.store.put(raw),ack=self.store.put(bytes(8)),
                fds=proc_fds(self.pid),maps=self.store.put((Path("/proc")/str(self.pid)/"maps").read_bytes())))
            return bytes(8)
        require(len(raw)==64 and raw[:8]in OWNERS,"complete declared effect barrier")
        owner=OWNERS[raw[:8]];generation,call,seq,op,fd,a,b=struct.unpack("<7Q",raw[8:])
        require(self.query["observer"],"observer-off emitted an effect")
        key=(owner,op);self.counts[key]=self.counts.get(key,0)+1;n=self.counts[key]
        event=dict(raw=self.store.put(raw),ack=self.store.put(bytes(8)),owner=owner,generation=generation,
            call=call,sequence=seq,operation=op,fd=fd,a=a,b=b,occurrence=n,attempt=self.attempt,
            before=self.descriptor(fd),actions=[])
        for i,action in enumerate(self.query["actions"]):
            if (owner,op,n,self.attempt)==(action["owner"],action["operation"],action["occurrence"],action["attempt"]):
                require(i not in self.used,"actor repeated");self.used.add(i)
                before=self.fixture.all();self.fixture.effect(action);after=self.fixture.all()
                row=dict(attempt=self.attempt,index=i,input=action,before=before,after=after,
                    actor_pid=os.getpid(),target_pid=self.pid)
                event["actions"].append(row);self.actions.append(row)
        event["after"]=self.descriptor(fd);self.events.append(event);return bytes(8)
    def result(self):
        self.limit_leave()
        require(self.used==set(range(len(self.query["actions"]))),"not every frozen actor input ran")
        return dict(events=self.events,actions=self.actions,limits=self.limits,eof=self.eof,
            actual_actor_count=len(self.actions),replacements_of_native_result=0,ack_is_only_eight_zero_bytes=True)
