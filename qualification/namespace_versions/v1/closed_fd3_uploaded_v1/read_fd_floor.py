"""Independent full bytes of actual qualified Watcher lifetimes with closed standard descriptors."""
import struct
from common import pin,require
from versions_contract import q,watcher,file_pin
class Reader:
    def __init__(self,parent):
        self.parent=parent;self.current=None;self.pointer=None;self.rows=[];self.entries=0;self.owner={};self.boundary={}
        self.pending=None;self.results=[];self.observations=0;self.initialized=False;self.disposed=False
    def context(self,raw):
        require(len(raw)==131088 and raw[131072:]==b"\x5a"*16,"whole closed-fd Watcher caller-context guard")
        watcher(raw[:131072],self.parent.pointers)
    def view(self,raw,pages):
        w=raw[32768:98304];require(q(raw,8)==0 and q(w,8)==1,"complete quiescent closed-fd HIA Watcher")
        rows=[]
        for i in range(q(w,88)):
            at=1024+64*i;p=q(w,at);require(p in pages,"whole live closed-fd pin page")
            page=pages[p];rows.append(dict(device=q(w,at+8),inode=q(w,at+16),wd=q(w,at+24),id=q(w,at+32),
                generation=q(w,at+40),dead=bool(q(w,at+48)),pin_fd=q(page,16),strong_count=q(page,8)))
        require(q(raw,104)==len(rows),"all real closed-fd native File ownership")
        return dict(event_fd=q(raw,96),next=q(w,80),limit=q(w,56),content=bool(q(w,64)),watches=rows)
    def consume(self,row,b):
        k=row["kind"];m=row["meta"];step=row["step"];operation=self.parent.case["steps"][step]["operation"]
        require(operation["op"]=="closed-standard-watcher"and m["mask"]==operation["mask"]and m["content"]==operation["content"],
            "each actual direct child belongs to its frozen closed-fd operation")
        if k=="fd-watcher-initialize":
            require(not self.initialized and len(b)==4 and b[0]==bytes(131072)+b"\x5a"*16 and
                b[1]==b[3]==struct.pack("<9Q",*self.parent.pointers[:8],0)and m["returned"]==0,
                "whole actual standalone initialization and immutable libc table")
            self.pointer=m["context"];self.context(b[2])
            require(q(b[2],96)==(1<<64)-1 and q(b[2],16)==0 and q(b[2],104)==0 and b[2][32768:98304]==bytes(65536)
                and bool(q(b[2],40))==m["observer"]==self.parent.report["observer"]and q(b[2],48)==0,
                "exact initially empty closed-fd Watcher and real optional observer")
            self.current=b[2];self.initialized=True
        else:
            require(self.initialized and self.pointer==m["context"],"same actual independent child context")
            if k=="fd-watcher-bind":
                require(len(b)==2 and m["returned"]==0 and b[0]==self.current and q(b[1],24)==m["fd"]and q(b[1],32)==0
                    and b[0][:24]==b[1][:24]and b[0][40:]==b[1][40:],"binding changes only the actual borrowed directory and pin words")
                self.context(b[1]);self.current=b[1]
            elif k=="fd-watcher-entry":
                require(len(b)==6+len(m["pins"])and m["returned"]==128 and b[0]==b[3]
                    and b[0][96:]==b"\xc3"*16 and b[1]==b"\xa5"*144 and b[4][128:]==b"\xa5"*16
                    and b[2]==self.current,"every complete closed-fd caller input/output/context before and after")
                self.entries+=1;command=[1,2,2,2,2,3,4][self.entries-1];generation=self.entries
                expected=b"HNWQ0001"+struct.pack("<11Q",command,generation,1 if command==2 else 0,0,
                    128 if command==1 else 0,int(operation["content"])if command==1 else 0,0,0,0,0,0)
                require(b[0][:96]==expected and m["command"]==command and m["generation"]==generation,"all exact source-defined direct Watcher requests")
                self.context(b[5]);self.current=b[5];out=b[4][:128]
                require(out[:8]==b"HNWR0001"and q(out,8)==0 and q(out,16)==generation and q(out,32)==command
                    and out[40:88]==bytes(48)and q(out,120)==0,"whole actual successful direct Watcher terminal")
                pages={}
                for p,raw in zip(m["pins"],b[6:]):file_pin(raw,self.parent.pointers);pages[p]=raw
                state=self.view(b[5],pages)if command!=4 else None
                action=["new","version-0","version-1","version-2","version-3","drain","drop"][generation-1]
                require(m["action"]==action and(command!=2 or q(b[2],24)==[operation["first"],operation["first"],operation["second"],operation["second"]][generation-2]+512),
                    "all repeated borrowed source root descriptors")
                self.rows.append(dict(action=action,token=[q(out,88),q(out,96)]if command==2 else None,watcher=state))
                if command==4:require(q(b[5],96)==(1<<64)-1 and q(b[5],104)==0 and q(b[5],32776)==0,"complete direct HIA drop owns no event or File")
            elif k=="fd-watcher-observation":
                require(self.parent.report["observer"]and len(b)==2+len(m["pins"])and m["record"]==self.pointer+24960
                    and b[0][24960:25088]==b[1]and b[1].hex()==m["event"],"all live direct child callback bytes and addresses")
                self.context(b[0]);raw=b[0];e=b[1];phase=q(e,8);require(phase in(0,1),"actual legacy callback phase")
                pages={}
                for p,body in zip(m["pins"],b[2:]):file_pin(body,self.parent.pointers);pages[p]=body
                require({q(raw,512+16*i)for i in range(q(raw,104))}<=set(pages),"every owned live direct File page captured")
                generation=q(e,24);require(generation==q(raw,16)and q(e,32)==q(raw,144),"whole live direct Watcher generation and command")
                self.observations+=1
                if e[:8]==b"HNWOWN01":
                    require(q(e,48)==self.pointer+8192 and q(e,56)==q(raw,112)and q(e,64)==self.pointer+24704
                        and q(e,72)==128 and q(e,80)==self.pointer+32768 and q(e,88)==65536,"all actual HIA borrowed ranges")
                    n=q(e,56);require(96<=n<=16480 and raw[8192+n:8208+n]==b"\xc3"*16,
                        "entire direct HIA input guard")
                    key=(generation,q(e,96))
                    if phase==0:
                        require(key not in self.owner,"one corresponding direct HIA before")
                        self.owner[key]=raw[8192:8192+n]
                        if q(e,32)in(2,3)and q(e,40)==0:
                            require(raw[98336:114720]==bytes(16384),"whole closed-fd kernel read buffer begins zero")
                    else:
                        require(key in self.owner and self.owner.pop(key)==raw[8192:8192+n]and q(e,16)==128,"complete real direct HIA immutable input and return")
                        out=raw[24704:24832]
                        require(out[:8]==b"HNWR0001"and q(out,8)in(0,1,2)and q(out,16)==generation,"whole actual direct HIA output")
                        if q(out,8)==2:self.pending=out
                elif e[:8]==b"HNWBN001":
                    key=(generation,q(e,48));op=q(e,40)
                    require(1<=op<=8 and self.pending is not None and q(self.pending,24)==q(e,48)
                        and q(self.pending,40)==op and self.pending[48:72]==e[56:80],"entire actual boundary is selected by the preceding HIA output")
                    if phase==0:
                        require(key not in self.boundary,"one complete actual before-boundary")
                        self.boundary[key]=raw
                    else:
                        require(key in self.boundary,"whole actual matching after-boundary");before=self.boundary.pop(key)
                        returned=q(e,96);returned=returned-(1<<64)if returned>=1<<63 else returned
                        if op==2:
                            require(returned==-1 or 0<=returned<=16384,"complete bounded actual direct read return")
                            tail=max(returned,0)
                            require(raw[98336+tail:114720]==before[98336+tail:114720],"every closed-fd read preserves every unwritten kernel byte")
                        self.parent.kernel.append(dict(index=row["index"],tid=row["tid"],worker=row["worker"],step=step,child=self.pointer,
                            op=op,sequence=q(e,48),args=[q(e,a)for a in(56,64,72)],event_fd=q(e,80),root_fd=q(e,88),
                            returned=returned,errno=q(e,104),read_hex=raw[98336:98336+returned].hex()if op==2 and returned>0 else "",
                            full_kernel_read_buffer=pin(raw[98336:114720])if op==2 else None))
                else:raise ValueError("unexpected actual direct Watcher record tag")
            elif k=="fd-watcher-dispose":
                require(len(b)==2 and m["returned"]==0 and b[0]==self.current and self.entries==7
                    and b[1]==bytes(131072)+b"\x5a"*16,"entire empty direct Watcher transport disposal")
                self.current=b[1];self.disposed=True
            elif k=="fd-fixture-result":
                require(self.disposed and len(b)==1 and b[0]==self.current,"complete zero context remains caller-owned after disposal")
                value=m["control"];event=self.rows[0]["watcher"]["event_fd"];duplicates=[r["pin_fd"]for r in self.rows[5]["watcher"]["watches"]]
                require(event==min(i for i in range(3)if operation["mask"]&(1<<i))and duplicates==[32,33],
                    "actual event uses the lowest closed standard FD, while real File copies start in the reserved pool")
                expected=dict(mask=operation["mask"],content=operation["content"],rows=self.rows,event_fd=event,duplicate_fds=duplicates,
                    closed_owned_fds=[event,*duplicates],all_duplicates_at_least_three=True,restored=True,restored_flags=value["restored_flags"])
                require(value==expected and len(value["restored_flags"])==3 and all(v in(0,1)for v in value["restored_flags"]),
                    "entire reported low-fd lifecycle derives from actual full native buffers")
                self.results.append(dict(step=step,control=expected,child=self.pointer,entries=self.entries,observations=self.observations))
            else:raise ValueError("unexpected complete closed-fd physical record")
    def finish(self):
        wanted=sum(s["operation"]["op"]=="closed-standard-watcher"for s in self.parent.case["steps"])
        require(not self.owner and not self.boundary and len(self.results)==wanted,"all closed-fd HIA and native physical lifetimes complete")
        if wanted:require(self.disposed and self.entries==7 and bool(self.observations)==self.parent.report["observer"],
            "whole observed/off direct child disposal and actual callback count")
        return self.results
