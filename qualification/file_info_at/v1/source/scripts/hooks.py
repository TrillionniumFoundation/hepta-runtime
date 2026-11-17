"""Fixed before-real-effect barriers; ACK never supplies a result."""
from pathlib import Path
import os,resource,struct
from evidence_common import require
from protocol import stat_value,exception,proc_fds
OWNERS={b"HINFHK01":"info",b"HBRDHK01":"read",b"HMDTHK01":"metadata"}
def metadata(st):
    return dict(dev=st["st_dev"],inode=st["st_ino"],links=st["st_nlink"],mode=st["st_mode"],
        uid=st["st_uid"],gid=st["st_gid"],size=st["st_size"],mtime_ns=st["st_mtime_ns"],ctime_ns=st["st_ctime_ns"])
class Hooks:
    def __init__(self,q,pid,parents,fixture,store,reference=False):
        self.query=q;self.pid=pid;self.parents=parents;self.fixture=fixture;self.store=store;self.reference=reference
        self.counts={};self.events=[];self.actions=[];self.used=set();self.limits=[];self.attempt=0
    def begin(self,attempt):
        self.attempt=attempt;self.counts={}
    def descriptor(self,fd):
        try:return dict(ok=True,stat=stat_value(os.stat(Path("/proc")/str(self.pid)/"fd"/str(fd))))
        except OSError as e:return dict(ok=False,error=exception(e))
    def limit_enter(self):
        if not self.query["fd_limit"]:return
        fds=proc_fds(self.pid);numbers=sorted(map(int,fds));require(numbers==list(range(max(numbers)+1)),"FD profile has a hole")
        before=resource.prlimit(self.pid,resource.RLIMIT_NOFILE);soft=max(numbers)+2
        require(soft<=before[1],"RLIMIT hard bound")
        resource.prlimit(self.pid,resource.RLIMIT_NOFILE,(soft,before[1]))
        actual=resource.prlimit(self.pid,resource.RLIMIT_NOFILE);require(actual==(soft,before[1]),"real FD limit")
        self.limits.append(dict(attempt=self.attempt,before=list(before),during=list(actual),fds=fds,only_free_fd=soft-1))
    def limit_leave(self):
        if not self.limits or "after"in self.limits[-1]:return
        row=self.limits[-1];resource.prlimit(self.pid,resource.RLIMIT_NOFILE,tuple(row["before"]))
        row["after"]=list(resource.prlimit(self.pid,resource.RLIMIT_NOFILE));require(row["after"]==row["before"],"restore real limit")
    def consume(self,raw):
        require(len(raw)==64 and raw[:8]in OWNERS,"fixed complete info/child barrier")
        owner=OWNERS[raw[:8]];generation,call,seq,op,fd,a,b=struct.unpack("<7Q",raw[8:])
        retry=not self.reference and owner=="metadata"and op in(2,3)and a==65536
        key=(owner,op)
        if not retry:self.counts[key]=self.counts.get(key,0)+1
        n=self.counts.get(key,0);require(n>0,"metadata fallback without first try")
        event=dict(raw=self.store.put(raw),ack=self.store.put(bytes(8)),owner=owner,generation=generation,call=call,
            sequence=seq,operation=op,fd=fd,a=a,b=b,occurrence=n,retry_capacity=retry,attempt=self.attempt,
            before=self.descriptor(fd),actions=[])
        for i,action in enumerate(self.query["actions"]):
            if not retry and (owner,op,n)==(action["owner"],action["operation"],action["occurrence"]):
                require((self.attempt,i)not in self.used,"actor repeated");self.used.add((self.attempt,i))
                before=self.fixture.all(self.pid,self.parents);self.fixture.effect(action);after=self.fixture.all(self.pid,self.parents)
                row=dict(attempt=self.attempt,index=i,input=action,before=before,after=after,actor_pid=os.getpid(),target_pid=self.pid)
                event["actions"].append(row);self.actions.append(row)
        event["after"]=self.descriptor(fd)
        if event["after"]["ok"]:event["fd_stat"]=metadata(event["after"]["stat"])
        self.events.append(event);return bytes(8)
    def result(self):
        self.limit_leave()
        require(len(self.actions)==len(self.query["actions"])*self.query["attempts"],"not every fixed actor input ran")
        return dict(events=self.events,actions=self.actions,limits=self.limits,actual_actor_count=len(self.actions),
            replacements_of_native_result=0,ack_is_only_eight_zero_bytes=True)
