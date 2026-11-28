"""Fixed before-real-syscall barriers and independently owned fixture effects."""
from pathlib import Path
import os,struct
from evidence_common import require
from protocol import stat_value,exception
class Hooks:
    def __init__(self,query,pid,fds,fixture,store,reference=False):
        self.query=query;self.pid=pid;self.fds=fds;self.fixture=fixture;self.store=store;self.reference=reference
        self.counts={};self.events=[];self.actions=[];self.used=set()
    def descriptor(self,fd):
        try:return dict(ok=True,stat=stat_value(os.stat(Path("/proc")/str(self.pid)/"fd"/str(fd))))
        except OSError as e:return dict(ok=False,error=exception(e))
    def consume(self,raw):
        require(len(raw)==64 and raw[:8]==b"HMDTHK01","actual fixed metadata barrier")
        generation,call,sequence,op,fd,a,b=struct.unpack("<7Q",raw[8:])
        roles=[r for r,n in self.fds.items()if n==fd];require(len(roles)==1,"actual barrier outside held capability")
        role=roles[0];key=(op,role)
        retry=not self.reference and op in(2,3)and a==65536
        if not retry:self.counts[key]=self.counts.get(key,0)+1
        occurrence=self.counts.get(key,0);require(occurrence>0,"retry before original attempt")
        event=dict(raw=self.store.put(raw),ack=self.store.put(bytes(8)),generation=generation,call=call,sequence=sequence,
            operation=op,fd=fd,role=role,occurrence=occurrence,retry_capacity=retry,before=self.descriptor(fd),actions=[])
        for i,action in enumerate(self.query["actions"]):
            if not retry and (op,role,occurrence)==(action["operation"],action["fd_role"],action["occurrence"]):
                require(i not in self.used,"fixture action repeated");self.used.add(i)
                before=self.fixture.all(self.pid,self.fds);self.fixture.effect(action);after=self.fixture.all(self.pid,self.fds)
                row=dict(index=i,input=action,before=before,after=after);event["actions"].append(row);self.actions.append(row)
        event["after"]=self.descriptor(fd);self.events.append(event)
        return bytes(8)
    def result(self):
        require(self.used==set(range(len(self.query["actions"]))),"not every frozen actor input executed")
        return dict(events=self.events,actions=self.actions,actual_actor_count=len(self.actions),
            replacements_of_native_result=0,ack_is_only_eight_zero_bytes=True)
