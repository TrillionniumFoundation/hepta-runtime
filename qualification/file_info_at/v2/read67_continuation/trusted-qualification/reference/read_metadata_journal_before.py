"""Pure complete HIA/OS/codec buffer reader; no image execution."""
import gzip,hashlib,struct
from evidence_common import pin,require
from protocol import U,I,result,stat_decode
class Journal:
    def __init__(self,path):
        self.path=path;self.stream=gzip.open(path,"rb");self.digest=hashlib.sha256()
        self.position=0;self.events=0;self.full_buffer_bytes=0;self.calls=0;self.children=0;self.effects=0
    def take(self,event,generation,call):
        header=self.stream.read(128);require(len(header)==128,"short full journal header")
        self.digest.update(header);self.position+=128
        require(header[:8]==b"HMDTJR01","journal magic")
        h=struct.unpack("<16Q",header)
        require(h[1]==event and h[2]==generation and h[3]==call and h[5]==1 and h[7]==0,
            "journal event/generation/call/state differs")
        require(h[4]<=256<<20 and h[8]%4096==h[9]%4096==0 and h[8]>=4096 and h[9]>=4096,
            "owned journal extent differs")
        raw=self.stream.read(h[4]);require(len(raw)==h[4],"short complete journal span")
        self.digest.update(raw);self.position+=len(raw);self.events+=1;self.full_buffer_bytes+=len(raw)
        return h,raw
    def finish(self,receipt):
        require(not self.stream.read(1),"unread journal suffix");self.stream.close()
        require(dict(bytes=self.position,sha256=self.digest.hexdigest())==receipt["raw"]
            and pin(self.path)==receipt["compressed"]and receipt["complete_raw_bytes_in_gzip"]is True
            and receipt["no_expanded_ordinary_copy_created"]is True,"complete journal custody differs")
        return dict(events=self.events,full_buffer_bytes=self.full_buffer_bytes,body_calls=self.calls,
            child_calls=self.children,raw_os_effects=self.effects,journal_bytes=self.position)

def invocation(journal,start,terminal,generation,files,hooks,previous_work=None):
    incoming=bytearray(start);mode=U(start,24)
    source=files.get("source",{}).get("fd",0)if mode!=2 else 0
    target=files.get("target",{}).get("fd",0)if mode==3 else 0
    struct.pack_into("<QQ",incoming,32,source,target);incoming=bytes(incoming)
    roles={row["fd"]:role for role,row in files.items()};last_work=previous_work;call=0;hook_at=0;effects=[];codec=[]
    while True:
        call+=1;journal.calls+=1
        h,raw=journal.take(1,generation,call)
        require(raw==incoming and h[11]==len(incoming)and h[10]==0,"body input/borrrow binding")
        hb,wb=journal.take(10,generation,call);ho,ob=journal.take(12,generation,call)
        require(len(wb)==hb[8]and hb[10]==0 and(last_work is None or wb==last_work)
            and len(ob)==ho[9]and ob==b"\xa5"*len(ob),"complete initial arenas")
        ha,oa=journal.take(2,generation,call);hw,wa=journal.take(11,generation,call)
        require(ha[6]==hw[6]==64 and len(oa)==ha[9]==len(ob)and len(wa)==hw[8]==len(wb)
            and ha[10]==hw[10]==0,"actual HIA return and arenas")
        require(oa[:8]==b"HMDSR001"and U(oa,8)in range(6),"body result ABI")
        extent=64+U(oa,56);require(extent<=len(oa)and oa[extent:]==ob[extent:],"complete output suffix")
        frame=oa[:extent];kind=U(frame,8);last_work=wa
        if kind in(0,3):
            require(frame==terminal and hook_at==len(hooks),"terminal frame/full notification set")
            result(frame)
            return dict(workspace=wa,output=oa,body_calls=call,effects=effects,codec=codec)
        if kind in(4,5):
            require(all(U(frame,p)==0 for p in(16,24,40,48,56)),"growth reserved words")
            need=U(frame,32);old=len(wb)if kind==4 else len(ob)
            require(old<need<=(256<<20 if kind==4 else 128<<20),"guarded growth extent")
            if kind==4:
                _,before=journal.take(3,generation,call);hg,after=journal.take(4,generation,call)
                require(before==wa==wb and len(after)==hg[8]==((need+4095)&~4095)
                    and after[:len(before)]==before and after[len(before):]==bytes(len(after)-len(before)),"workspace relocation bytes")
                last_work=after
            continue
        sequence,op=U(frame,16),U(frame,24);require(sequence>0,"effect sequence")
        if kind==1:
            he,request=journal.take(8,generation,call);journal.effects+=1
            hr,resume=journal.take(9,generation,call)
            require(request==frame and he[12:14]==(sequence,op)and he[10]==hr[10]==0,"real OS request custody")
            require(op in range(1,9)and hook_at<len(hooks),"declared OS effect and observer")
            hook=hooks[hook_at];hook_at+=1
            fd,a,b=(U(frame,p)for p in(32,40,48));payload=frame[64:];ret=I(U(resume,24));actual=resume[96:]
            require(fd in roles and mode!=2 and(fd==source or mode==3 and fd==target),"read file capability")
            require(op<4 or(mode==3 and fd==target),"write target capability")
            require(hook["raw_bytes"]==b"HMDTHK01"+struct.pack("<7Q",generation,call,sequence,op,fd,a,b)
                and hook["ack_bytes"]==bytes(8)and hook["role"]==roles[fd],"actual barrier and fixed ACK")
            args={}
            if op==1:
                require(a==b==0 and not payload and len(actual)==(144 if ret==0 else 0),"fstat envelope")
                if ret==0:
                    value=stat_decode(actual)
                    require(hook["after"]["ok"]and value==hook["after"]["stat"],"fstat vs actual immediately preceding descriptor")
            elif op==2:
                require(a in(256,65536)and b==0 and not payload and len(actual)==(ret if ret>=0 else 0)
                    and(ret<0 or ret<=a),"flistxattr buffer")
                if ret>=0:
                    require(not actual or actual.endswith(b"\0"),"list names terminator")
                    value=[n.hex()for n in actual.split(b"\0")[:-1]]
                    require(all(value),"empty kernel attribute name")
            elif op==3:
                require(a in(128,65536)and b==0 and payload.endswith(b"\0")and b"\0"not in payload[:-1]
                    and len(actual)==(ret if ret>=0 else 0)and(ret<0 or ret<=a),"fgetxattr exact buffer")
                args=dict(name_hex=payload[:-1].hex());value=actual.hex()
            elif op==4:
                require(a<=4294967295 and b<=4294967295 and not payload,"fchown arguments");args=dict(uid=a,gid=b)
            elif op==5:
                require(a<=4095 and b==0 and not payload,"fchmod arguments");args=dict(mode=a)
            elif op==6:
                require(a==b==0 and payload.endswith(b"\0")and b"\0"not in payload[:-1],"fremovexattr arguments")
                args=dict(name_hex=payload[:-1].hex())
            elif op==7:
                require(0<a<=65535 and b<=65536 and len(payload)==a+1+b and payload[a]==0 and b"\0"not in payload[:a],"fsetxattr arguments")
                args=dict(name_hex=payload[:a].hex(),value_hex=payload[a+1:].hex())
            else:require(a==b==0 and not payload,"fsync arguments")
            if op>=4:require(ret<=0 and not actual,"mutation real return");value=None
            row=dict(operation=op,role=roles[fd],args=args,ok=ret>=0,raw_return=ret,capacity=a if op in(2,3)else None,
                generation=generation,call=call,sequence=sequence)
            if ret>=0:row["value"]=value
            else:row["errno"]=-ret
            effects.append(row)
        else:
            require(kind==2 and op==1 and all(U(frame,p)==0 for p in(32,40,48)),"fixed SHA child")
            _,request=journal.take(5,generation,call);_,cb=journal.take(13,generation,call)
            _,cw=journal.take(14,generation,call);hc,ca=journal.take(6,generation,call)
            _,cwa=journal.take(7,generation,call);journal.children+=1
            require(request==frame[64:]and len(cb)==len(ca)==64 and len(cw)==len(cwa)==1184
                and cb==b"\xa5"*64 and cw==bytes(1184)and hc[14]==hc[15]==64,"complete SHA arenas")
            require(request[:8]==b"HRCODEC1"and U(request,8)==2 and U(request,16)==0 and len(request)>=24
                and ca==hashlib.sha256(request[24:]).hexdigest().encode(),"actual SHA child bytes")
            hr,resume=journal.take(9,generation,call)
            require(U(resume,24)==64 and resume[96:]==ca and hr[10]==0,"complete actual codec resume")
            codec.append(dict(input_bytes=len(request)-24,input_sha256=hashlib.sha256(request[24:]).hexdigest(),output=ca.decode()))
        require(resume[:8]==b"HMDTQ001"and U(resume,8)==2 and U(resume,16)==sequence
            and all(U(resume,p)==0 for p in(32,40,48,56,64,72,80))and U(resume,88)==len(resume)-96
            and hr[12:14]==(sequence,op)and hr[14]==U(resume,24)and hr[15]==len(resume)-96,"complete effect resume")
        incoming=resume

def collapse(effects):
    result=[];at=0
    while at<len(effects):
        row=effects[at];at+=1
        if row["operation"]in(2,3)and not row["ok"]and row["errno"]==34 and row["capacity"]in(128,256):
            require(at<len(effects),"ERANGE retry absent");other=effects[at];at+=1
            require((row["operation"],row["role"],row["args"])==(other["operation"],other["role"],other["args"])
                and other["capacity"]==65536,"exact CPython capacity fallback")
            row=other
        selected={k:row[k]for k in("operation","role","args","ok")}
        selected["value"if row["ok"]else"errno"]=row["value"if row["ok"]else"errno"]
        result.append(selected)
    return result
