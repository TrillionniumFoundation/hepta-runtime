"""Read the actual multi-file continuation, all child buffers, and live FD ownership."""
import hashlib,struct
from evidence_common import require
from protocol import U,I,stat_decode,result
MASK=(1<<64)-1
def live_fds(state,orphans,exclude_parent=None):
    live=set(state["owned"])|set(orphans)
    for i,p in enumerate(state["parents"]):
        if i!=exclude_parent:live.update(p["fds"])
    return live
def parent_packet(start,workspace):
    index=U(workspace,88);count=U(start,32);require(index<count<=16,"current source entry")
    at=96
    for i in range(count):
        a,b=U(start,at),U(start,at+8);raw=start[at+16:at+16+a+b]
        require(len(raw)==a+b,"complete actual entry input")
        if i==index:return b"HPRDQ001"+struct.pack("<11Q",1,0,1,a,b,0,0,0,0,0,a+b)+raw
        at+=16+a+b
    raise ValueError("unowned input entry")
def direct(journal,op,packet,gen,call):
    outcap,workcap={1:(64,1184),2:(128,256),5:(256,512)}[op]
    h,ob=journal.take("body",13,gen,call);hw,wb=journal.take("body",14,gen,call)
    ha,oa=journal.take("body",6,gen,call);hz,wa=journal.take("body",7,gen,call)
    ret=ha[14]
    require(len(ob)==len(oa)==outcap and len(wb)==len(wa)==workcap and ob==b"\xa5"*outcap
        and wb==bytes(workcap) and hz[14]==ret and ret<=outcap and oa[ret:]==ob[ret:],
        "complete direct HIA capacities, before/after buffers and tail")
    if op==1:
        require(len(packet)>=24 and packet[:8]==b"HRCODEC1" and U(packet,8)==2 and U(packet,16)==0
            and len(packet)<=65560,"exact SHA codec reserved-zero input")
        require(ret==64 and oa==hashlib.sha256(packet[24:]).hexdigest().encode("ascii"),"actual full SHA child bytes")
    elif op==2:
        require(len(packet)==72 and packet[:8]==b"HSTVER01" and U(packet,8)==1,"exact stat child frame")
        value=":".join(map(str,(U(packet,16),U(packet,24),U(packet,32),
            I(U(packet,40))*1000000000+U(packet,48),I(U(packet,56))*1000000000+U(packet,64)))).encode()
        require(oa[:ret]==value,"actual complete stat-version child value")
    else:
        require(len(packet)>=16 and packet[:8]==b"HUTFQ001" and U(packet,8)==len(packet)-16,
            "complete strict UTF8 child input")
        require(64<=ret<=256 and oa[:8]==b"HUTFD001"and U(oa,48)==len(packet)-16
            and U(oa,8)in(0,3),"complete strict UTF8 child output")
        if U(oa,8)==0:
            require(ret==64 and oa[:64]==b"HUTFD001"+struct.pack("<7Q",0,0,0,0,0,len(packet)-16,0)
                and wa==wb,"whole successful UTF8 physical buffers")
        else:
            start,end,reason=(U(oa,p)for p in(16,24,32));message=oa[64:ret]
            require(start<end<=len(packet)-16 and reason in(1,2,3) and U(oa,40)==U(oa,56)==len(message),
                "actual UTF8 error extent")
            model=bytearray(wb);model[:len(message)]=message;model[384:408]=struct.pack("<3Q",start,end,reason)
            decimal=start if end==start+1 else end-1
            if decimal:
                digits=str(decimal).encode()[::-1];model[256:256+len(digits)]=digits
            require(wa==model,"all UTF8 workspace bytes including untouched tail")
    journal.children+=1;return ret,oa[:ret]
def invocation(journal,start,terminal,generation,state,orphans):
    incoming=start;last=state["work"];call=0;effects=[];orphaned=[];children=[]
    require(not state["owned"] and all(not p["fds"]for p in state["parents"]),"new request retains no live operable FD")
    while True:
        call+=1;journal.calls+=1;owned=state["owned"]
        h,raw=journal.take("body",1,generation,call)
        require(raw==incoming and h[11]==len(raw) and h[10]==len(owned),"complete actual HIA input and FD count")
        hb,wb=journal.take("body",10,generation,call);ho,ob=journal.take("body",12,generation,call)
        require(wb==last and len(wb)==hb[8] and hb[10]==len(owned)
            and len(ob)==ho[9] and ob==b"\xa5"*len(ob),"full body workspace/output preimage")
        ha,oa=journal.take("body",2,generation,call);hw,wa=journal.take("body",11,generation,call)
        require(ha[6]==hw[6]==64 and len(oa)==len(ob)==ha[9] and len(wa)==len(wb)==hw[8]
            and ha[10]==hw[10]==len(owned),"actual complete body return and buffers")
        require(oa[:8]==b"HMRDS001"and U(oa,8)in range(6),"declared body response")
        extent=64+U(oa,56);require(extent<=len(oa) and oa[extent:]==ob[extent:],"complete output tail")
        frame=oa[:extent];kind=U(frame,8);last=wa
        if kind in(0,3):
            require(frame==terminal and not owned and all(not p["fds"]for p in state["parents"])
                and U(wa,8)==99 and U(wa,24)==0 and U(frame,16)==U(wa,16),"terminal whole frame and retired ownership")
            result(frame);state.update(work=wa,output=oa,call=call,generation=generation)
            return dict(effects=effects,orphaned=orphaned,children=children,body_calls=call,
                terminal=frame,work=wa,output=oa)
        if kind in(4,5):
            require(all(U(frame,p)==0 for p in(16,24,40,48,56)),"growth reserved fields")
            need=U(frame,32);old=len(wb)if kind==4 else len(ob)
            require(old<need<=(256<<20 if kind==4 else 128<<20),"actual growth request")
            if kind==4:
                _,before=journal.take("body",3,generation,call);hg,after=journal.take("body",4,generation,call)
                require(before==wa==wb and len(after)==hg[8]==((need+4095)&~4095)
                    and after[:len(before)]==before and after[len(before):]==bytes(len(after)-len(before)),
                    "complete workspace growth preserves all old bytes")
                last=after
            continue
        seq,op,fd,a,b=(U(frame,p)for p in(16,24,32,40,48));payload=frame[64:]
        require(seq>0 and U(wa,16)==U(wa,24)==seq,"actual pending body continuation")
        if kind==2:
            he,request=journal.take("body",5,generation,call)
            require(request==payload and he[12:14]==(seq,op)and b==0,"complete fixed child request")
            if op in(3,4):
                require(fd in(0,1)and a==0,"fixed parent child slot")
                if op==3:require(payload==parent_packet(start,wa),"original root/path reaches exact parent owner")
                else:require(not payload and state["parents"][fd]["fds"],"close same still-held parent")
                child,pe=journal.parent(fd,op,payload,state,generation,call,live_fds(state,orphans,fd))
                effects+=pe;ret=len(child)
            else:
                require(op in(1,2,5) and fd==a==0,"fixed immutable direct child")
                base=U(wa,304)
                if op==1:require(payload[24:]==wa[base:base+U(wa,144)],"SHA receives actual complete file bytes")
                if op==5:require(payload[16:]==wa[base:base+U(wa,144)],"UTF8 receives actual complete file bytes")
                ret,child=direct(journal,op,payload,generation,call)
            children.append(dict(operation=op,input=payload,output=child))
            hr,resume=journal.take("body",9,generation,call)
            require(resume==b"HMRDQ001"+struct.pack("<11Q",2,seq,ret,0,0,0,0,0,0,0,len(child))+child
                and hr[14]==ret and hr[15]==len(child)and hr[10]==len(owned),"whole child reply continuation")
            incoming=resume;continue
        require(kind==1 and op in(1,2,3,4,5),"declared real capability")
        he,request=journal.take("body",8,generation,call)
        require(request==frame and he[12:14]==(seq,op)and he[10]==len(owned),"whole OS request")
        hook=journal.hook("body",generation,call,seq,op,fd,a,b);journal.os_calls+=1
        if op==1:
            role=U(wa,200);require(role in(0,1) and fd in state["parents"][role]["fds"]
                and a==b==0 and payload.endswith(b"\0")and b"\0"not in payload[:-1],"actual same-parent open")
            parent=state["parents"][role]["terminal"]
            require(payload[:-1]==parent[64:] and U(parent,24)==fd,"same complete basename loan")
        else:
            require(fd in owned and not payload and b==0,"actual owned file token")
            if op!=5:require(a==0,"reserved file capability argument")
            else:require(1<=a<=65537,"bounded full raw read request")
        hr,resume=journal.take("body",9,generation,call);ret=I(U(resume,24));data=resume[96:]
        require(resume[:8]==b"HMRDQ001"and U(resume,8)==2 and U(resume,16)==seq
            and all(U(resume,p)==0 for p in(32,40,48,56,64,72,80)) and U(resume,88)==len(data)
            and hr[12:14]==(seq,op)and hr[14]==U(resume,24)and hr[15]==len(data),"complete real OS return frame")
        require(ret>=0 or(not data and -4095<=ret<0),"raw negative errno has no payload")
        if op==1:
            require(not data,"open returns no payload")
            if ret>=0:
                require(ret<=2147483647 and ret not in live_fds(state,orphans),"new actual file descriptor")
                owned[ret]=dict(parent=fd,name=payload[:-1])
        elif op==2:
            require(ret<=0 and len(data)==(144 if ret==0 else 0),"full fstat result")
            if ret==0:
                require(hook["after"]["ok"] and stat_decode(data)==hook["after"]["stat"],"real full fstat matches independent held-FD observation")
        elif op==5:
            require(ret<=a and len(data)==max(ret,0),"every actual raw read byte")
        elif op==3:
            require(ret<=0 and not data,"close result");del owned[fd]
        else:
            require(ret==0 and not data and U(wa,8)==25,"successful process-lifetime orphan transfer")
            del owned[fd];require(fd not in orphans,"orphan duplicated")
            orphans.add(fd);orphaned.append(dict(fd=fd,generation=generation))
        require(hr[10]==len(owned),"complete post-effect operable ledger count")
        effects.append(dict(owner="body",operation=op,fd=fd,raw_result=ret,name=payload,
            data=data,hook=hook,phase=U(wa,8),regular_role=U(wa,200)))
        incoming=resume
