"""Read every complete write/entropy/publish/read/metadata/codec boundary; no application execution."""
import binascii,hashlib,struct
from base64_3123 import strict_decode
from evidence_common import require
from protocol import U,I,result,error_frame,stat_decode,version
import read_publish_journal as publication
import read_read_journal as reading
MAGIC={"write":b"HBWTJR01","publish":b"HPUBJR01","read":b"HBRDJR01","metadata":b"HMDTJR01","entropy":b"HENTJR01"}
OUTPUT={"write":b"HBWTR001","entropy":b"HENTR001"}
class Journal(publication.Journal):
    def __init__(self,path):
        super().__init__(path)
        self.owner_counts={k:dict(calls=0,children=0,effects=0)for k in MAGIC}
        self.active={};self.effect_records=[];self.last_work={};self.generations={};self.application_scope=None
    def view(self,owner):return View(self,owner)
class View(publication.View):
    def __init__(self,parent,owner):
        super().__init__(parent,owner);self.workspace=None;self.context=parent.active[owner]
    def take(self,event,generation,call):
        h,raw=self.parent.raw_take(MAGIC[self.owner])
        require(h[1]==event and h[2]==generation and h[3]==call and h[5]==1 and h[7]==0,
            "complete mixed owner/generation/call/state")
        require(h[8]>=4096 and h[9]>=4096 and h[8]%4096==h[9]%4096==0,"actual guarded arena capacities")
        if event==11:self.workspace=raw
        if event==8:self.pending=(h,raw)
        if event==9 and self.pending is not None:
            before,request=self.pending;self.pending=None
            self.parent.effect_records.append(dict(owner=self.owner,context=self.context,generation=generation,call=call,application_scope=self.parent.application_scope,
                phase=U(self.workspace,8),sequence=U(request,16),operation=U(request,24),
                fd=U(request,32),a=U(request,40),b=U(request,48),request=request[64:],
                raw_return=I(U(raw,24)),data=raw[96:],before_owned=before[10],after_owned=h[10]))
        return h,raw
def hooks_for(hooks,owner,generation=None):
    return [q for q in hooks if q["owner"]==owner and(generation is None or q["generation"]==generation)]
def validate_resume(raw,h,magic,seq,op):
    require(raw[:8]==magic and U(raw,8)==2 and U(raw,16)==seq
        and all(U(raw,p)==0 for p in(32,40,48,56,64,72,80))and U(raw,88)==len(raw)-96
        and h[12:14]==(seq,op)and h[14]==U(raw,24)and h[15]==len(raw)-96,"complete exact child/effect resume")
def nested_return(view,owner,generation,call,child,magic):
    h,returned=view.take(6,generation,call);_,context=view.take(15,generation,call)
    require(returned==child and len(context)==4096 and context[:8]==magic and U(context,56)==2
        and U(context,168)==len(child),"complete nested output loan before explicit release")
    return context
def entropy(journal,packet,generation,hooks):
    view=journal.view("entropy");key=("entropy",view.context);last=journal.last_work.get(key)
    require(generation==journal.generations.get(key,0)+1,"shared process entropy generation")
    incoming=packet;call=0;seq=0;selected=hooks_for(hooks,"entropy",generation);hi=0
    owned=set()if last is None or U(last,72)==(1<<64)-1 else{U(last,72)}
    source=bytearray();effects=[]
    while True:
        call+=1;view.calls+=1;count=len(owned)
        h,raw=view.take(1,generation,call);require(raw==incoming and h[10]==count and h[11]==len(raw),"entropy full input/ownership")
        hb,wb=view.take(10,generation,call);ho,ob=view.take(12,generation,call)
        require(len(wb)==hb[8]and(last is None or wb==last)and len(ob)==ho[9]and ob==b"\xa5"*len(ob),
            "entropy complete before buffers")
        ha,oa=view.take(2,generation,call);hw,wa=view.take(11,generation,call)
        require(ha[6]==hw[6]==64 and len(oa)==len(ob)and len(wa)==len(wb)
            and ha[10]==hw[10]==count and oa[:8]==b"HENTR001","entropy complete after buffers")
        extent=64+U(oa,56);require(extent<=len(oa)and oa[extent:]==ob[extent:],"entropy untouched output tail")
        frame=oa[:extent];kind=U(frame,8);last=wa
        if kind in(0,3):
            require(hi==len(selected)and all(U(frame,p)==0 for p in(24,32,40,48)),"entropy terminal effect coverage")
            cache=U(wa,72);require(owned==(set()if cache==(1<<64)-1 else{cache}),"process cache remains operable")
            if kind==0:
                require(len(source)==16 and len(frame)==96,"complete observed UUID source")
                value=bytearray(source);value[6]=(value[6]&15)|64;value[8]=(value[8]&63)|128
                require(frame[64:]==value.hex().encode(),"UUID derives only from actual random bytes")
            else:
                require(len(frame)>=128,"complete entropy nested error");error_frame(frame[64:])
            journal.last_work[key]=wa;journal.generations[key]=generation;view.commit()
            return dict(frame=frame,workspace=wa,output=oa,calls=call,effects=effects,cache=cache)
        require(kind==1 and U(frame,16)==seq+1,"declared monotonic entropy effect");seq+=1
        op,fd,a,b=(U(frame,p)for p in(24,32,40,48))
        he,request=view.take(8,generation,call);view.effects+=1
        require(request==frame and he[12:14]==(seq,op)and hi<len(selected),"complete actual entropy effect")
        hook=selected[hi];hi+=1
        require(hook["raw_bytes"]==b"HENTHK01"+struct.pack("<7Q",generation,call,seq,op,fd,a,b)
            and hook["ack_bytes"]==bytes(8),"entropy before-effect witness")
        hr,resume=view.take(9,generation,call);ret=I(U(resume,24));data=resume[96:]
        require(not frame[64:]and b==0,"fixed entropy raw arguments")
        if op==1:
            require(0<fd<=16 and a==0 and len(data)==(ret if ret>=0 else 0)and(ret<0 or ret<=fd),
                "actual getrandom extent")
            if ret>0:source+=data
            if ret in(-38,-1,0):source.clear()
        elif op==2:
            require(fd==a==0 and not data,"fixed urandom open")
            if ret>=0:require(ret not in owned,"fresh entropy device token");owned.add(ret)
        elif op==3:
            require(fd in owned and a==0 and len(data)==(144 if ret==0 else 0),"full entropy fstat")
            if ret==0:require(hook["after"]["ok"]and stat_decode(data)==hook["after"]["stat"],"entropy fstat actual held descriptor")
        elif op in(4,6):
            require(fd in owned and a==0 and not data and(op==4 or ret==0),"entropy close/orphan token")
            owned.remove(fd)
        else:
            require(op==5 and fd in owned and 0<a<=16 and len(data)==(ret if ret>=0 else 0)
                and(ret<0 or ret<=a),"actual cached device bytes")
            if ret>0:source+=data
        require(hr[10]==len(owned),"entropy native ledger")
        validate_resume(resume,hr,b"HENTQ001",seq,op);incoming=resume
        effects.append(dict(operation=op,fd=fd,raw_return=ret,data=data.hex()))
def invocation(journal,start,terminal,generation,parent,hooks,contexts):
    journal.active=dict(contexts);view=journal.view("write");key=("write",view.context)
    require(generation==journal.generations.get(key,0)+1,"write context generation")
    packet=bytearray(start);struct.pack_into("<Q",packet,32,parent);incoming=bytes(packet)
    last=journal.last_work.get(key);owned={};call=0;seq=0;selected=hooks_for(hooks,"write");hi=0
    children=[];last_stat=None;entropy_generation=journal.generations.get(("entropy",contexts["entropy"]),0)
    while True:
        call+=1;view.calls+=1;count=len(owned)
        h,raw=view.take(1,generation,call)
        require(raw==incoming and h[11]==len(raw)and h[10]==count,"write full input/binding")
        hb,wb=view.take(10,generation,call);ho,ob=view.take(12,generation,call)
        require(len(wb)==hb[8]and(last is None or wb==last)and len(ob)==ho[9]and ob==b"\xa5"*len(ob),
            "write complete before buffers")
        if call==1 and last is None:require(wb==bytes(len(wb)),"fresh write workspace")
        ha,oa=view.take(2,generation,call);hw,wa=view.take(11,generation,call)
        require(ha[6]==hw[6]==64 and len(oa)==len(ob)and len(wa)==len(wb)
            and ha[10]==hw[10]==count and oa[:8]==b"HBWTR001","write complete after buffers")
        extent=64+U(oa,56);require(extent<=len(oa)and oa[extent:]==ob[extent:],"write untouched complete output suffix")
        frame=oa[:extent];kind=U(frame,8);last=wa
        if kind in(0,3):
            require(not owned and frame==terminal and hi==len(selected),"write terminal ownership/full frame/effects")
            result(frame);journal.last_work[key]=wa;journal.generations[key]=generation;view.commit()
            return dict(workspace=wa,output=oa,body_calls=call,children=children,frame=frame)
        if kind in(4,5):
            require(all(U(frame,p)==0 for p in(16,24,40,48,56)),"write growth reserved fields")
            need=U(frame,32);old=len(wb)if kind==4 else len(ob)
            require(old<need<=(256<<20 if kind==4 else 128<<20),"write bounded growth")
            if kind==4:
                _,before=view.take(3,generation,call);hg,after=view.take(4,generation,call)
                require(before==wa==wb and len(after)==hg[8]==((need+4095)&~4095)
                    and after[:len(before)]==before and after[len(before):]==bytes(len(after)-len(before)),
                    "write complete relocated bytes")
                last=after
            continue
        require(U(frame,16)==seq+1,"write monotonic action sequence");seq+=1
        op,fd,a,b=(U(frame,p)for p in(24,32,40,48));payload=frame[64:]
        if kind==1:
            he,request=view.take(8,generation,call);view.effects+=1
            require(request==frame and he[12:14]==(seq,op)and hi<len(selected),"write actual capability frame")
            hook=selected[hi];hi+=1
            require(hook["raw_bytes"]==b"HBWTHK01"+struct.pack("<7Q",generation,call,seq,op,fd,a,b)
                and hook["ack_bytes"]==bytes(8),"write actual before-effect witness")
            hr,resume=view.take(9,generation,call);ret=I(U(resume,24));data=resume[96:]
            require(b==0 and op in range(1,14),"fixed write capability profile")
            if op in(1,6,7):
                require(fd==parent and a==0 and payload.endswith(b"\0")and b"\0"not in payload[:-1]and not data,
                    "write borrowed-parent openat")
                role={1:"destination",6:"lock",7:"temporary"}[op]
                if op==1:require(payload[:-1]==start[96:96+U(start,40)],"admitted original destination bytes")
                if op==6:require(payload==b".hepta-lock-"+hashlib.sha256(start[96:96+U(start,40)]).hexdigest()[:24].encode()+b"\0",
                    "lock name derives from full original basename")
                if op==7:
                    uuid=next(x["frame"][64:]for x in reversed(children)if x["kind"]=="entropy")
                    require(payload==b".hepta-write-"+uuid+b"\0","temporary name uses actual shared UUID result")
                if ret>=0:require(ret not in owned and ret!=parent and ret<=2147483647,"new owned file token");owned[ret]=role
            elif op in(2,3,4):
                require(fd in owned and a==0 and not payload,"owned fstat/close/orphan token")
                if op==2:
                    require(ret<=0 and len(data)==(144 if ret==0 else 0),"complete write fstat payload")
                    if ret==0:
                        require(hook["after"]["ok"]and stat_decode(data)==hook["after"]["stat"],"write fstat matches live kernel descriptor")
                        last_stat=data
                else:
                    require(not data and(ret<=0 if op==3 else ret==0),"complete close/orphan ACK");del owned[fd]
            elif op==5:
                require(fd==a==0 and not payload and not data and 0<=ret<=4294967295,"geteuid scalar")
            elif op in(8,9,10):
                require(owned.get(fd)=="lock"and not payload and(op==8 or a==0),"exclusive lock FileIO capability")
                if op==8:require(a in(1,2)and not data,"FileIO seek offset/whence")
                if op==9:require(len(data)==(36 if ret==0 else 0),"complete isatty termios result")
                if op==10:require(ret<=0 and not data,"actual flock result")
            elif op in(11,12):
                require(owned.get(fd)=="temporary","private temporary writer capability")
                if op==11:require(0<a==len(payload)<=1048576 and not data and(ret<0 or ret<=a),"complete bounded write bytes")
                else:require(a==0 and not payload and ret<=0 and not data,"temporary fsync")
            else:
                require(fd==parent and a==0 and len(payload)==46 and payload.endswith(b"\0")
                    and payload.startswith(b".hepta-write-")and ret<=0 and not data,"fixed UUID temporary cleanup")
            require(hr[10]==len(owned),"write native ledger count")
        else:
            require(kind==2 and b==0 and op in range(1,7),"write declared composed child")
            _,request=view.take(5,generation,call);require(request==payload,"full child request bytes")
            if op<=3:
                require(fd==a==0,"direct HIA child has no FD capability")
                _,cb=view.take(13,generation,call);_,cw=view.take(14,generation,call)
                hc,ca=view.take(6,generation,call);_,cwa=view.take(7,generation,call);view.children+=1
                cap,work=(128,256)if op==1 else(64,1184)if op==2 else(max(512,(len(payload)+71)&~7),4096)
                returned=hc[14]
                require(len(cb)==len(ca)==cap and len(cw)==len(cwa)==work and cb==b"\xa5"*cap and cw==bytes(work)
                    and returned==hc[15]<=cap and ca[returned:]==cb[returned:],"complete direct HIA buffers")
                child=ca[:returned]
                if op==1:
                    require(payload[:8]==b"HSTVER01"and U(payload,8)==1 and len(payload)==72 and last_stat is not None,
                        "stat image declared input")
                    expected=b"HSTVER01"+struct.pack("<Q",1)+b"".join(last_stat[p:p+8]for p in(0,8,48,88,96,104,112))
                    require(payload==expected and child==version(stat_decode(last_stat)).encode(),"stat derives from actual immediately preceding fstat")
                elif op==2:
                    require(payload[:8]==b"HRCODEC1"and U(payload,8)==2 and U(payload,16)==0
                        and payload[24:]==start[96:96+U(start,40)]
                        and child==hashlib.sha256(payload[24:]).hexdigest().encode(),"lock SHA child complete original basename")
                else:
                    require(payload[:8]==b"HRCODEC1"and U(payload,8)==4 and U(payload,16)==0
                        and payload[24:]==start[96+U(start,40)+U(start,48):]and cwa==cw,
                        "strict Base64 complete admitted string and preserved workspace")
                    require(child[:8]==b"HBRDS001"and len(child)==64+U(child,56),"complete strict decoder envelope")
                    try:decoded=strict_decode(payload[24:].decode("utf-8"));error=None
                    except(ValueError,binascii.Error)as e:decoded=None;error=e
                    if error is None:require(U(child,8)==0 and child[64:]==decoded,"strict Base64 actual result bytes")
                    else:
                        actual=error_frame(child)
                        require(actual==dict(type=type(error).__name__,errno=None,filename=None,filename2=None,message=str(error)),
                            "strict Base64 complete literal exception")
                children.append(dict(kind="direct",operation=op,frame=child))
            elif op==4:
                require(fd==a==0 and payload[:8]==b"HENTQ001"and U(payload,24)==2,"one shared process UUID child")
                entropy_generation+=1;row=entropy(journal,payload,entropy_generation,hooks);child=row["frame"]
                c=nested_return(view,"entropy",generation,call,child,b"HENTCI01")
                require(U(c,192)==entropy_generation and U(c,376)>0,"actual shared entropy generation/pool")
                children.append(dict(kind="entropy",operation=op,frame=child))
            elif op==5:
                require(fd==parent and a==0 and payload[:8]==b"HPUBQ001","borrowed-parent publication child")
                row=publication.invocation(journal,payload,None,1,parent,hooks)
                child=row["output"][:64+U(row["output"],56)]
                c=nested_return(view,"publish",generation,call,child,b"HPUBCI01")
                require(U(c,192)==1 and U(c,184)==0 and U(c,344)==U(c,352)==0,"publication child fully drained")
                children.append(dict(kind="publish",operation=op,frame=child,evidence=row))
            else:
                require(fd==parent and a==0 and payload[:8]==b"HBRDFD01"and U(payload,24)==2,"borrowed fingerprint child")
                p=bytearray(payload);struct.pack_into("<Q",p,32,parent);rv=journal.view("read")
                row=reading.invocation(rv,bytes(p),None,1,borrowed=(parent,"<held-parent>"),hooks=hooks_for(hooks,"read",1))
                rv.commit();child=row["frame"];c=nested_return(view,"read",generation,call,child,b"HBRDCI01")
                require(U(c,192)==1 and U(c,184)==0 and U(c,344)==U(c,352)==0,"fingerprint child fully drained")
                children.append(dict(kind="read",operation=op,frame=child,evidence=row))
            hr,resume=view.take(9,generation,call)
            require(U(resume,24)==len(child)and resume[96:]==child and hr[10]==count,"complete copied child result")
        validate_resume(resume,hr,b"HBWTQ001",seq,op);incoming=resume
def formatter(journal,packet,text):
    rows=[]
    for stage in range(1,6):
        h,raw=journal.raw_take(b"HBWTER01",64);require(h[1]==stage and h[6]==h[7]==0,"complete formatter stage")
        rows.append((h,raw))
    require(rows[0][1]==packet and rows[1][1]==bytes(12288)and len(rows[2][1])>=6*len(packet)+1024
        and rows[2][1]==b"\xa5"*len(rows[2][1]),"complete 34-function error input/before arenas")
    h,after=rows[3];_,work=rows[4]
    require(h[3]==len(text)and h[4]==len(after)==len(rows[2][1])and h[5]==len(work)==12288
        and after[:len(text)]==text and after[len(text):]==rows[2][1][len(text):],"complete formatter actual return and suffix")
    journal.formatters+=1
