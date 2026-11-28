"""Complete multiplexed body/parent/formatter trace; every physical byte is read."""
import gzip,hashlib,struct
from evidence_common import pin,require
from protocol import U,I,stat_decode
import read_parent
MAGIC={"body":b"HMRDJR01","parent0":b"HPD0JR01","parent1":b"HPD1JR01"}
HOOK={"body":b"HMRDHK01","parent0":b"HPD0HK01","parent1":b"HPD1HK01"}
MASK=(1<<64)-1
class ParentView:
    def __init__(self,journal,owner):
        self.journal=journal;self.owner=owner;self.hook_magic=HOOK[owner];self.calls=0;self.effects=0
    def take(self,event,generation,call):return self.journal.take(self.owner,event,generation,call)
class Journal:
    def __init__(self,path,hooks):
        self.path=path;self.stream=gzip.open(path,"rb");self.digest=hashlib.sha256()
        self.position=0;self.events=0;self.full_buffer_bytes=0
        self.calls=0;self.parent_calls=0;self.children=0;self.formatters=0;self.os_calls=0
        self.hooks=hooks;self.hook_position=0
    def raw(self,size):
        require(0<=size<=256<<20,"bounded complete journal span")
        raw=self.stream.read(size);require(len(raw)==size,"short complete journal bytes")
        self.digest.update(raw);self.position+=size;return raw
    def take(self,owner,event,generation,call):
        raw=self.raw(128);require(raw[:8]==MAGIC[owner],"fixed actual trace owner")
        h=struct.unpack("<16Q",raw)
        require(h[1]==event and h[2]==generation and h[3]==call and h[5]==1 and h[7]==0,
            "actual trace event/generation/call/state")
        require(h[8]>=4096 and h[9]>=4096 and h[8]%4096==h[9]%4096==0
            and h[8]<=256<<20 and h[9]<=128<<20,"complete owned arena bounds")
        value=self.raw(h[4]);self.events+=1;self.full_buffer_bytes+=len(value);return h,value
    def hook(self,owner,generation,call,seq,op,fd,a,b):
        require(self.hook_position<len(self.hooks),"missing real effect barrier")
        row=self.hooks[self.hook_position];self.hook_position+=1
        require(row["raw_bytes"]==HOOK[owner]+struct.pack("<7Q",generation,call,seq,op,fd,a,b)
            and row["ack_bytes"]==bytes(8) and row["owner"]==owner,"complete actual effect and fixed ACK")
        return row
    def parent(self,slot,operation,packet,state,body_generation,body_call,held_elsewhere):
        owner="parent"+str(slot);prior=state["parents"][slot];view=ParentView(self,owner)
        generation=prior["generation"]+(operation==3)
        if operation==3:start=packet
        else:start=b"HPRDQ001"+struct.pack("<11Q",3,U(prior["work"],16),0,0,0,0,0,0,0,0)
        hooks=[]
        for h in self.hooks[self.hook_position:]:
            if h["owner"]!=owner:break
            observed=h["after"]
            hooks.append(dict(raw_bytes=h["raw_bytes"],ack_bytes=h["ack_bytes"],fd=h["fd"],
                stat=dict(mode=observed["stat"]["st_mode"])if observed["ok"]else{}))
        result=read_parent.invocation(view,start,None,generation,prior,hooks)
        used=result["hooks"];actual_hooks=self.hooks[self.hook_position:self.hook_position+used]
        require(len(actual_hooks)==used and all(h["owner"]==owner for h in actual_hooks),"nested parent effect order")
        self.hook_position+=used;self.parent_calls+=view.calls;self.os_calls+=view.effects
        live=set(held_elsewhere)|set(prior["fds"]);effects=[]
        for effect,hook in zip(result["effects"],actual_hooks):
            op,fd,ret=effect["operation"],effect["fd"],effect["result"]
            if op in(1,2)and ret>=0:
                require(ret not in live,"parent opened a live foreign descriptor");live.add(ret)
            if op==5:require(fd in live,"parent closed unowned descriptor");live.remove(fd)
            effects.append(dict(owner=owner,operation=op,fd=fd,raw_result=ret,name=effect["name"],
                data=b"",hook=hook))
        require(live==set(held_elsewhere)|set(result["fds"]),"complete nested directory ownership")
        h,frame=self.take("body",6,body_generation,body_call)
        require(frame==result["terminal"],"whole actual parent result loan")
        hc,context=self.take("body",15,body_generation,body_call)
        kind=U(frame,8);held=kind==6
        require(len(context)==4096 and context[:8]==b"HPDRCI01" and U(context,8)==4096
            and U(context,56)==(4 if held else 2) and U(context,168)==len(frame)
            and U(context,176)==64 and U(context,184)==len(result["fds"])
            and U(context,192)==generation and U(context,248)==result["call"],"complete child controller boundary")
        tokens=[U(context,p)for p in range(256,320,8)if U(context,p)!=MASK]
        require(set(tokens)==set(result["fds"])and len(tokens)==len(result["fds"]),"complete child operable ledger")
        if held:
            require(U(context,344)==U(frame,24) and U(context,352)==1 and U(context,360)==U(frame,16),
                "held parent token and continuation")
        else:require(U(context,344)==U(context,352)==U(context,360)==0,"retired parent loan")
        after=bytearray(context)
        if not held:
            for at in(56,168,176):struct.pack_into("<Q",after,at,0)
        result.update(generation=generation,ctx=bytes(after));state["parents"][slot]=result
        self.children+=1;return frame,effects
    def formatter(self,frame,diagnostic):
        nested=frame[64:]
        if nested[:8]==b"HUTFD001":
            require(diagnostic==nested[64:],"UTF8 diagnostic comes from actual child bytes");return
        values=[];caps=None
        for event in range(1,6):
            header=self.raw(64);h=struct.unpack("<8Q",header)
            require(header[:8]==b"HMFER001"and h[1]==event and h[6]==h[7]==0
                and h[4]>=4096 and h[4]%4096==0 and h[5]==12288,"complete fixed formatter header")
            if caps is None:caps=h[4:6]
            require(h[4:6]==caps and h[3]==(0 if event<4 else len(diagnostic)),"formatter capacity/return continuity")
            value=self.raw(h[2]);values.append(value);self.events+=1;self.full_buffer_bytes+=len(value)
        inp,wb,ob,oa,wa=values
        require(inp==nested and len(wb)==len(wa)==caps[1] and len(ob)==len(oa)==caps[0]
            and wb==bytes(len(wb))and ob==b"\xa5"*len(ob)
            and oa[:len(diagnostic)]==diagnostic and oa[len(diagnostic):]==ob[len(diagnostic):],
            "all actual formatter input/output/workspace spans")
        self.formatters+=1
    def finish(self,receipt):
        require(not self.stream.read(1),"unread actual journal suffix");self.stream.close()
        require(self.hook_position==len(self.hooks),"unconsumed real syscall notification")
        require(dict(bytes=self.position,sha256=self.digest.hexdigest())==receipt["raw"]
            and pin(self.path)==receipt["compressed"]and receipt["complete_raw_bytes_in_gzip"]is True
            and receipt["no_expanded_ordinary_copy_created"]is True,"whole journal custody")
        return dict(events=self.events,full_buffer_bytes=self.full_buffer_bytes,body_calls=self.calls,
            parent_calls=self.parent_calls,direct_children=self.children,formatter_calls=self.formatters,
            os_calls=self.os_calls,journal_bytes=self.position)
