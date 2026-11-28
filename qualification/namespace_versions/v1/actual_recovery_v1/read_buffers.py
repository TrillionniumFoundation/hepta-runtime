"""Independently join complete actual parent/child bytes, native effects and lifetime frames."""
import struct
from common import loads,read,pin,require
from versions_contract import q,zero,request,terminal,pending,ack,workspace,environment,object_state,file_pin,watcher,fingerprint
from read_memory import walk
from read_libc import verify as read_libc
class Native:
    def __init__(self,folder,case,process):
        self.folder=folder;self.case=case;self.process=process
        self.report=loads(read(folder/"NATIVE.json"));self.libc=read_libc(folder);self.pointers=self.libc["pointers"]
        self.pid=process["pid"];self.env=None;self.invocations={};self.terminals={};self.checkpoints=[];self.entries=[]
        self.counts={};self.effects=[];self.cas=[];self.lifecycle=[];self.held={};self.seeds=[];self.clones=0;self.releases=0;self.kernel=[];self.read_before={};self.kernel_physical=[];self.lifecycle_pending={}
        require(self.report["status"]=="PASS"and self.report["errors"]==[]and self.report["pid"]==self.pid
            and self.report["application_replays"]==self.report["original_rust_executions"]==0 and self.report["globals_reset"]is False,
            "precise complete actual native process result")
    def get_inv(self,row,parent):
        key=(row["tid"],row["meta"]["invocation"])
        if key not in self.invocations:
            require(q(parent,120)==0,"first entire observation precedes first HIA invocation")
            self.invocations[key]=dict(owner_before=None,effect_before=None,pending=None,last_child=None,last_fp=None,seq=0,
                owner_calls=0,lock=False,finished=False,initial=parent[2048:2048+q(parent,56)])
        return key,self.invocations[key]
    def observe(self,row,b):
        m=row["meta"];require(len(b)>=7 and len(b[0])==128,"all actual observer buffers")
        e=b[0];require(e.hex()==m["event"]and e[:8]==b"HNVOBS01","entire event metadata mirrors native bytes")
        stage,phase=q(e,8),q(e,16);require(stage in range(1,12)and stage!=5 and phase in(0,1),"no transport quarantine event")
        inv,obj=q(e,40),q(e,48);require(inv==m["invocation"]and obj==m["object"],"actual invocation/object pointers")
        ranges=[(q(e,a),q(e,a+8))for a in(80,96,112)]
        require(m["ranges"]==[dict(pointer=p,bytes=n)for p,n in ranges]and [len(v)for v in b[1:4]]==[n for p,n in ranges],
            "every full actual borrowed range")
        parent=b[4];require(len(parent)==131072 and parent[:8]==b"HNVCTX01"and q(parent,8)==obj and q(parent,16)==self.env
            and parent[256:384]==e and q(e,56)==q(parent,40)==1 and q(parent,48)in range(1,7),"complete real parent invocation")
        environment(b[5],self.pid,self.pointers);object_state(b[6],obj,self.env,self.pid)
        require(len(b[6])==m["object_bytes"]and len(b)==7+len(m["children"])+len(m["pins"]),"all complete child and File extents")
        children={}
        for p,raw in zip(m["children"],b[7:7+len(m["children"])]):watcher(raw,self.pointers);children[p]=raw
        for p,raw in zip(m["pins"],b[7+len(m["children"]):]):
            require(p>0 and p%4096==0,"actual native File mapping address");file_pin(raw,self.pointers)
        for p,raw in children.items():
            wanted={q(raw,512+16*i)for i in range(q(raw,104))}
            if q(raw,32):wanted.add(q(raw,32))
            require(wanted<=set(m["pins"]),"every actual child's owned and borrowed File page fully retained")
        if stage in(1,2):
            require(ranges==[(inv,131072),(obj,len(b[6])),(self.env,4096)]and b[1]==parent,
                "entire primary parent snapshot and real ranges")
        elif stage==3:
            child=b[1];watcher(child,self.pointers)
            require(ranges[0][1]==131072 and ranges[1]==(ranges[0][0]+24960,128)and child[24960:25088]==b[2]
                and b[2][:8]in(b"HNWOWN01",b"HNWBN001")and q(b[2],8)==phase,"whole actual qualified Watcher callback")
            legacy=b[2];pointer=ranges[0][0]
            if legacy[:8]==b"HNWOWN01"and phase==0 and q(legacy,32)in(2,3)and q(legacy,40)==0:
                require(child[98336:114720]==bytes(16384),"whole actual kernel read buffer begins zero before every drain generation")
                self.kernel_physical.append(dict(index=row["index"],step=row["step"],tid=row["tid"],kind="drain-initial-zero",pointer=pointer,generation=q(legacy,24)))
            if legacy[:8]==b"HNWBN001"and q(legacy,40)==2:
                bk=(row["tid"],pointer,q(legacy,24),q(legacy,48))
                if phase==0:
                    require(bk not in self.read_before,"one full physical pre-read buffer")
                    self.read_before[bk]=dict(raw=child[98336:114720],index=row["index"])
                else:
                    require(bk in self.read_before,"each actual kernel read joins its physical before buffer")
                    prior=self.read_before.pop(bk);returned=q(legacy,96);returned=returned-(1<<64)if returned>=1<<63 else returned
                    require(returned==-1 or 0<=returned<=16384,"bounded actual raw kernel read result")
                    unchanged=max(returned,0)
                    require(child[98336+unchanged:114720]==prior["raw"][unchanged:],"every kernel read leaves all unwritten physical tail bytes unchanged")
                    self.kernel_physical.append(dict(index=row["index"],before_index=prior["index"],step=row["step"],tid=row["tid"],
                        kind="complete-read-tail",pointer=pointer,generation=q(legacy,24),sequence=q(legacy,48),returned=returned,unchanged_bytes=16384-unchanged))
            if b[2][:8]==b"HNWBN001"and phase==1:
                r=b[2];returned=q(r,96);returned=returned-(1<<64)if returned>=1<<63 else returned
                self.kernel.append(dict(index=row["index"],tid=row["tid"],worker=row["worker"],step=row["step"],
                    child=ranges[0][0],op=q(r,40),sequence=q(r,48),args=[q(r,a)for a in(56,64,72)],
                    event_fd=q(r,80),root_fd=q(r,88),returned=returned,errno=q(r,104),
                    read_hex=child[98336:98336+returned].hex()if q(r,40)==2 and returned>0 else "",
                    full_kernel_read_buffer=pin(child[98336:114720])if q(r,40)==2 else None,
                    stat_hex=child[6144:6288].hex()if q(r,40)==3 else None,
                    path_hex=child[6400:6464].hex()if q(r,40)==5 else None))

        elif stage==4:
            fingerprint(b[1],self.pointers)
            require(ranges[1]==(ranges[0][0]+4864,128)and b[1][4864:4992]==b[2]and q(b[2],0)in(1,2)
                and q(b[2],8)==phase and q(parent,72)==0,"whole actual fingerprint callback only after mutex release")
        else:
            size=131072 if stage in(6,7,8)else 32768
            require(ranges==[(ranges[0][0],size),(inv,131072),(obj,len(b[6]))]and b[2]==parent,"complete actual lifecycle physical ranges")
            if (stage in(6,9)and phase==0)or(stage in(8,11)and phase==1):
                require(b[1]==bytes(size),"entire new/disposed child mapping before actual unmap")
            elif size==131072:watcher(b[1],self.pointers)
            else:fingerprint(b[1],self.pointers)
            if phase==1:require(q(e,24)==(128 if stage in(7,10)else 0),"actual child lifecycle return")
            lk=(row["tid"],stage,ranges[0][0],inv)
            if phase==0:
                require(lk not in self.lifecycle_pending,"one complete child lifecycle begins");self.lifecycle_pending[lk]=row["index"]
            else:require(lk in self.lifecycle_pending,"every actual lifecycle completion has its whole before");self.lifecycle_pending.pop(lk)
            self.lifecycle.append(dict(index=row["index"],tid=row["tid"],stage=stage,phase=phase,pointer=ranges[0][0],bytes=size,
                invocation=inv,object=obj,step=row["step"]))
        key,state=self.get_inv(row,parent)
        if stage in(1,2):
            length=q(parent,56);require(96<=length<=65760,"whole actual parent input length")
            inp=parent[2048:2048+length];out=parent[68096:68288];work=parent[69632:77824]
            require(parent[68288:68304]==b"\xa5"*16 and parent[77824:77840]==b"\x5a"*16,"entire parent output/workspace guards")
            workspace(work)
            if stage==1:
                require(parent[2048+length:2064+length]==b"\xc3"*16,"entire parent input guard")
                if phase==0:
                    require(state["owner_before"]is None and out==b"\xa5"*192,"whole pre-HIA output and pairing")
                    if inp[:8]==b"HNVSQ001":request(inp);require(state["owner_calls"]==0,"one exact initial source request")
                    else:
                        require(state["pending"]is not None,"no orphan continuation");ack(inp,state["pending"])
                    state["owner_before"]=(inp,work)
                else:
                    require(state["owner_before"]is not None and inp==state["owner_before"][0],"all borrowed input bytes unchanged across real HIA")
                    state["owner_before"]=None;state["owner_calls"]+=1
                    extent=q(e,24);require(extent in(128,192)and q(parent,160)==extent and q(parent,120)==state["owner_calls"],"actual HIA extent and call counter")
                    if q(out,8)==6:
                        p=pending(out[:extent]);require(p["sequence"]==state["seq"]+1,"every HIA-selected native effect once")
                        state["pending"]=p
                    else:
                        require(extent==128 and out[128:]==b"\xa5"*64 and not state["lock"],"complete terminal after releasing mutex")
                        terminal(out[:128]);require(q(out,32)==state["seq"],"whole terminal exact effect count")
                        self.terminals.setdefault(row["tid"],[]).append(dict(raw=out[:128],initial=state["initial"],object=obj,
                            calls=state["owner_calls"],effects=state["seq"],step=row["step"],worker=row["worker"],invocation=inv))
                        state["finished"]=True
            else:
                p=state["pending"];require(p is not None and p["op"]==q(e,72)and p["sequence"]==q(e,64)==q(parent,64),
                    "exact effect record belongs to prior actual HIA request")
                if phase==0:
                    require(state["effect_before"]is None,"one corresponding actual mechanical invocation")
                    state["effect_before"]=(parent,b[6],b[5]);state["seq"]=p["sequence"]
                    if p["op"]==6:require(not state["lock"]and q(parent,72)==0,"fingerprint outside actual shared mutex")
                else:
                    require(state["effect_before"]is not None,"actual complete mechanical after")
                    before,object_before,env_before=state["effect_before"];ack(inp,p);op=p["op"]
                    if op==1:
                        require(not state["lock"]and q(parent,72)==1 and q(b[6],56)==inv and inp[96:160]==b[6][64:128]
                            and q(inp,32)==q(b[6],40)and q(parent,152)==0,"actual locked state and source poison copied in full")
                        state["lock"]=True
                    elif op==2:
                        require(state["lock"]and q(parent,72)==0 and q(parent,152)==0,"actual mutex release completed")
                        state["lock"]=False
                        if row["operation"]not in("parallel-read","parallel-new"):
                            require(b[6][64:128]==before[68224:68288],"all HIA-provided committed protected bytes")
                    elif op in(3,4,5):
                        child=state["last_child"];require(child is not None and inp[96:224]==child["parent"][640:768]
                            and inp[224:]==child["raw"][32768:98304],"all child terminal/workspace ACK bytes copied from actual completed child")
                        if op in(4,5):require(q(inp,48)==p["args"][0],"same native child capability")
                    elif op==6:
                        child=state["last_fp"];require(child is not None and inp[96:224]==child["parent"][896:1024]
                            and q(parent,72)==0,"all fingerprint terminal bytes and unlocked custody")
                    elif op==7:
                        require(state["lock"],"real set mutex owns atomic allocation policy")
                        if row["operation"]!="parallel-new":require(q(inp,48)==q(b[5],24),"actual sequential atomic load witness")
                    elif op==8:
                        require(state["lock"],"real constructor state remains locked across strong CAS")
                        self.cas.append(dict(index=row["index"],step=row["step"],tid=row["tid"],worker=row["worker"],
                            expected=p["args"][0],proposed=p["args"][1],observed=q(inp,48),success=q(inp,56)))
                        if row["operation"]!="parallel-new":
                            require(q(inp,56)==1 and q(b[5],24)==p["args"][1],"actual sequential atomic CAS storage")
                    self.effects.append(dict(index=row["index"],step=row["step"],tid=row["tid"],worker=row["worker"],object=obj,
                        invocation=inv,sequence=p["sequence"],op=op,ack=pin(inp),pending=p))
                    state["effect_before"]=None
        elif stage==7 and phase==1:state["last_child"]=dict(raw=b[1],parent=parent,pointer=ranges[0][0])
        elif stage==10 and phase==1:state["last_fp"]=dict(raw=b[1],parent=parent,pointer=ranges[0][0])
    def checkpoint(self,row,b):
        m=row["meta"];environment(b[0],self.pid,self.pointers);n=len(m["objects"]);nc=len(m["children"]);np=len(m["pins"])
        require(len(b)==1+n+nc+np,"all full checkpoint objects, children and pin pages")
        objects={};children={};pins={}
        for desc,raw in zip(m["objects"],b[1:1+n]):
            require(desc["bytes"]==len(raw),"whole actual object extent");object_state(raw,desc["pointer"],self.env,self.pid)
            require(q(raw,56)==q(raw,176)==q(raw,184)==q(raw,192)==0,"complete checkpoint is quiescent")
            objects[desc["pointer"]]=raw
        for p,raw in zip(m["children"],b[1+n:1+n+nc]):watcher(raw,self.pointers);children[p]=raw
        for p,raw in zip(m["pins"],b[1+n+nc:]):file_pin(raw,self.pointers);pins[p]=raw
        def view(obj):
            raw=objects[obj];child=q(raw,48);require(child==q(raw,80),"whole native/policy child custody")
            if not child:return None
            require(child in children,"complete checkpoint child physical bytes");c=children[child];w=c[32768:98304]
            require(q(c,8)==0 and q(w,8)==1,"same actual live idle child")
            watches=[]
            for i in range(q(w,88)):
                at=1024+64*i;p=q(w,at);require(p in pins,"every actual watch has a full pin page")
                page=pins[p];watches.append(dict(device=q(w,at+8),inode=q(w,at+16),wd=q(w,at+24),id=q(w,at+32),
                    generation=q(w,at+40),dead=bool(q(w,at+48)),pin_fd=q(page,16),strong_count=q(page,8)))
            require(q(c,104)==len(watches)and {q(c,512+16*i)for i in range(q(c,104))}=={q(w,1024+64*i)for i in range(q(w,88))},
                "entire real owned File ledger equals all retained HIA records")
            return dict(event_fd=q(c,96),next=q(w,80),limit=q(w,56),content=bool(q(w,64)),watches=watches)
        globals_=[]
        for k,p in(("ordinary",self.env+256),("content",self.env+512)):
            raw=objects[p];globals_.append(dict(kind=k,initialized=bool(q(raw,104)),poison=bool(q(raw,40)),watcher=view(p)))
        sets=[]
        for sid,p in sorted(m["sets"].items(),key=lambda x:int(x[0])):
            raw=objects[p];require(q(raw,104)==1,"actual published scope")
            sets.append(dict(sid=int(sid),id=q(raw,88),poison=bool(q(raw,40)),invalid=bool(q(raw,96)),watcher=view(p)))
        roots=[]
        expected=m["state"]["roots"];require(len(expected)==len(m["roots"]),"complete caller-root list")
        for root in expected:
            actual=m["roots"][str(root["root"])];page=pins[actual["pointer"]]
            require(q(page,16)==root["fd"]==actual["fd"]and q(page,8)==root["strong_count"],"actual complete caller File metadata")
            roots.append(root)
        state=dict(globals=globals_,sets=sets,next=q(b[0],24),roots=roots)
        require(state==m["state"],"complete reported state derived independently from actual HIA/native memory")
        self.checkpoints.append(dict(step=row["step"],operation=row["operation"],state=state,
            roots=m["roots"],sets=m["sets"],objects=m["objects"],children=m["children"],environment=self.env))
    def consume(self,row,b):
        kind=row["kind"];m=row["meta"];self.counts[kind]=self.counts.get(kind,0)+1
        require(row["case"]in(None,self.case["case"])and type(row["tid"])is int and row["tid"]>0,"actual memory event source case and TID")
        if kind=="loaded-image":
            require(len(b)==1 and pin(b[0])==self.report["callable"]and m==self.report["loaded_image"],"every actual loaded native image byte")
            address=m["address"];size=m["bytes"]
            require(any(v["lo"]<=address and address+size<=v["hi"]and v["permissions"][:3]=="r-x"for v in self.libc["maps"]),
                "whole actually executed image has a real read/execute mapping")
        elif kind=="initialize":
            require(self.env is None and len(b)==4 and m["returned"]==0 and b[0]==bytes(4096)+b"\x5a"*16
                and b[1]==b[3]==self.libc["table"],"whole actual initial environment and libc table")
            self.env=m["environment"];environment(b[2],self.pid,self.pointers)
            require(bool(q(b[2],216))==m["observer"]==self.report["observer"]and q(b[2],224)==0,"actual optional observer pointer and no effect authority")
        elif kind=="observation":self.observe(row,b)
        elif kind=="entry":
            require(len(b)==8 and m["before_count"]==m["after_count"]==4 and m["returned"]==128,"all eight actual outer entry buffers")
            r=request(b[0][:-16]);require(b[0][-16:]==b"\xc3"*16 and b[4]==b[0]and b[1]==b"\xa5"*208
                and b[5][128:]==b"\xa5"*80,"whole input immutability and output prefix/tail")
            value=terminal(b[5][:128]);require(r["cmd"]==m["cmd"]and r["kind"]==m["kind"]and q(b[5],16)==r["generation"]
                and q(b[5],24)==r["cmd"],"entire actual terminal identity")
            for v in(b[2],b[6]):object_state(v,m["object"],self.env,self.pid)
            for v in(b[3],b[7]):environment(v,self.pid,self.pointers)
            if self.report["observer"]:
                queue=self.terminals.get(row["tid"],[]);require(queue,"actual observed terminal precedes outer return")
                t=queue.pop(0);require(t["raw"]==b[5][:128]and t["initial"]==b[0][:-16]and t["object"]==m["object"],
                    "entire external terminal equals actual HIA terminal and initial input")
                key=(row["tid"],t["invocation"]);require(self.invocations[key]["finished"],"complete observed invocation")
                del self.invocations[key]
            self.entries.append(dict(step=row["step"],worker=row["worker"],tid=row["tid"],request=r,raw=b[5][:128].hex(),semantic=value))
        elif kind=="checkpoint":self.checkpoint(row,b)
        elif kind=="pin-adopt":
            require(len(b)==1 and q(b[0],8)==1 and q(b[0],16)==m["fd"],"complete actual caller pin adoption");file_pin(b[0],self.pointers)
        elif kind=="pin-clone":
            require(len(b)==2 and m["returned"]==m["pointer"],"actual caller clone result")
            for raw in b:file_pin(raw,self.pointers)
            if row["worker"]is None:require(q(b[1],8)==q(b[0],8)+1,"actual sequential caller reference increment")
            self.clones+=1
        elif kind=="pin-release":
            require(len(b)==4 and m["returned"]==0 and b[1]==b"\xa5"*80 and b[3][:8]==b"HNWFPR01"and b[3][64:]==b"\xa5"*16,
                "whole exact actual File release frame")
            file_pin(b[0],self.pointers);require(q(b[3],8)>0 and q(b[3],16)==q(b[3],8)-1 and q(b[3],24)==m["fd"]and q(b[3],56)==0,
                "real atomic File decrement result")
            if q(b[3],16):file_pin(b[2],self.pointers);require(q(b[3],32)==q(b[3],48)==0,"nonfinal caller release has no close/unmap")
            else:require(b[2]==b""and q(b[3],32)==q(b[3],48)==0,"whole actual final File close/unmap completes")
            self.releases+=1
        elif kind=="set-allocate":
            require(len(b)==2 and m["returned"]==m["object"]and m["object"]%4096==0,"real owned set allocation")
            object_state(b[0],m["object"],self.env,self.pid);require(b[0][40:128]==bytes(88),"complete new set state is empty")
            environment(b[1],self.pid,self.pointers)
        elif kind=="set-dispose":
            require(len(b)==3 and m["returned"]==0 and q(b[0],48)==q(b[0],56)==q(b[0],80)==q(b[0],104)==q(b[0],176)==0,
                "actual final set disposal releases only empty unborrowed owner")
            object_state(b[0],m["object"],self.env,self.pid)
            environment(b[1],self.pid,self.pointers);environment(b[2],self.pid,self.pointers)
        elif kind=="fixture-seed-next":
            require(len(b)==2 and b[0][:24]==b[1][:24]and b[0][32:]==b[1][32:]and q(b[1],24)==m["value"]
                and m["atomic_address"]==self.env+24,"only explicit actual original Atomic fixture changes")
            self.seeds.append(dict(step=row["step"],value=m["value"]))
        elif kind=="fixture-seed-watcher":
            require(len(b)==2 and b[0][:32848]==b[1][:32848]and b[0][32856:]==b[1][32856:]and q(b[1],32848)==m["value"],
                "only the explicit actual Watcher next field is seeded")
        elif kind=="fixture-poison":
            require(len(b)==2 and b[0][:40]==b[1][:40]and b[0][48:]==b[1][48:]and q(b[0],40)==0 and q(b[1],40)==1
                and m["actual_unwind"]is True,"actual held fixture unwind marks only source poison")
        elif kind in("fixture-lock","fixture-unlock"):
            require(len(b)==4 and m["returned"]==0,"real complete private pthread operation")
            for raw in(b[0],b[2]):object_state(raw,m["object"],self.env,self.pid)
            require(b[0][:128]==b[2][:128]and b[0][168:]==b[2][168:],"fixture mutex changes only its actual mutex storage")
        elif kind=="fixture-child-bind":
            require(len(b)==2 and m["returned"]==0 and q(b[1],24)==(1<<64)-1 and q(b[1],32)==0,
                "real qualified child borrowed capability clear")
        elif kind=="fixture-changed":
            require(len(b)==8 and m["returned"]==128 and b[0]==b[4]and b[1]==b"\xa5"*144 and b[5][128:]==b"\xa5"*16
                and b[3]==b[7]and b[5][:8]==b"HNWR0001","all actual original changed fixture buffers")
            watcher(b[2],self.pointers);watcher(b[6],self.pointers)
        else:raise ValueError("unlisted entire native record: "+kind)
    def finish(self):
        summary=walk(self.folder,self.consume)
        require(not self.read_before and not self.lifecycle_pending,"all actual read and lifecycle physical pairs completed")
        require(not self.invocations and not any(self.terminals.values())and self.env is not None and
            len(self.checkpoints)==len(self.case["steps"])+2,"every actual invocation and full checkpoint completed")
        require(summary["records"]==self.report["records"]and summary["objects"]==self.report["objects"]
            and summary["logical_bytes"]==self.report["logical_bytes"]and len(self.entries)==self.report["entry_calls"],
            "all actual native report counts derived from full bytes")
        require(bool(self.counts.get("observation",0))==self.report["observer"],"observer-off executes without callbacks")
        return dict(**summary,typed_records=self.counts,entries=self.entries,checkpoints=self.checkpoints,effects=self.effects,
            actual_cas=self.cas,child_lifecycle=self.lifecycle,actual_caller_clones=self.clones,actual_caller_releases=self.releases,
            actual_atomic_seeds=self.seeds,kernel_witnesses=self.kernel,kernel_physical=self.kernel_physical,libc=self.libc["library"],image=self.report["callable"],pid=self.pid)
def verify(folder,case,process):return Native(folder,case,process).finish()
