# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independent byte expectations for already captured HIA calls; never loads code."""
import struct
from capture_util import need
MASK=(1<<64)-1
def word(tag):return int.from_bytes(tag.encode(),"little")
def q(data,at):return struct.unpack_from("<Q",data,at)[0]
def put(data,at,value):struct.pack_into("<Q",data,at,value&MASK)
def fields(data,start,end):return [q(data,i)for i in range(start,end,8)]
def pack(values):return struct.pack("<"+"Q"*len(values),*values)
def before(lo,hi,dl,dh):return (hi,lo)<(dh,dl)
class M:
    def __init__(self,raw):self.w=bytearray(raw)
    def g(self,p):return q(self.w,p)
    def p(self,p,v):put(self.w,p,v)
    def add(self,p,n=1):self.p(p,self.g(p)+n)
    def zero(self,a,b):self.w[a:b]=bytes(b-a)
    def issue(self,phase,seq,what):self.add(seq);self.p(phase,what)
    def clock(self,lo,hi,at,seen):
        need(not self.g(seen)or not before(lo,hi,self.g(at),self.g(at+8)),"monotonic actual policy clock")
        self.p(at,lo);self.p(at+8,hi);self.p(seen,1)
def initial(m,magic,cap,gen,extent):
    need(not any(m.w[:extent]),"new policy workspace not zero")
    m.p(0,word(magic));m.p(8,cap);m.p(16,gen)
def identity(m,magic,cap,gen):
    need(m.g(0)==word(magic)and m.g(8)==cap and m.g(16)==gen,"policy capability/generation")
def admission(s,m):
    op,cap,gen,a,b,c,lo,hi,seq=fields(s,8,80);status=reason=0
    need(op<=10 and cap and gen and not any(s[80:]),"admission complete input")
    if op not in(0,1,4):need(lo==hi==0,"admission reserved clock")
    if op==0:
        need(a<=1 and b==c==seq==0,"admission initialization")
        initial(m,"HSDARS01",cap,gen,256);m.p(40,lo);m.p(48,hi);m.p(56,a)
    else:
        identity(m,"HSDARS01",cap,gen)
        if op in(6,7,8):
            need(seq==m.g(104)and seq,"admission effect acknowledgement")
            if op==6:
                need(m.g(112)==1 and a<=1 and c==0,"entry acknowledgement phase")
                if a:
                    need(b,"entry failure identity");m.p(112,0);m.p(80,4);m.p(120,b);status,reason=3,4
                else:
                    need(b==0,"successful entry");m.p(72,1);m.p(80,2);m.issue(112,104,2);status=1
            elif op==7:
                need(m.g(112)==2 and a<=1,"spawn acknowledgement phase")
                if a==0:
                    need(b and c==m.g(160),"original spawned child identity")
                    for at,v in((88,b),(96,c),(72,0),(80,3),(112,0)):m.p(at,v)
                else:
                    need(0<b<=4095 and c==0,"actual spawn errno");m.p(120,b)
                    if m.g(72):m.p(80,6);m.issue(112,104,3);status=1
                    else:m.p(80,7);m.p(112,0);status,reason=3,5
            else:
                need(m.g(112)==3 and a==b==c==0,"failed-spawn guard release")
                m.p(72,0);m.p(80,7);m.p(112,0);status,reason=3,5
        else:
            need(seq==0,"unexpected admission sequence")
            if op in(1,4):
                need(a<=1,"admission actual stop")
                m.clock(lo,hi,136,152)
                inactive=a or m.g(32)or not before(lo,hi,m.g(40),m.g(48))
                if op==1:
                    need(b==c==0,"active reserved");status,reason=(3,1)if inactive else(0,0)
                else:
                    need(b<=2 and 0<c<MASK and m.g(160)==m.g(80)==0,"single original commit")
                    if b==2:status,reason=3,6
                    elif b==0:status,reason=3,3
                    elif inactive:status,reason=3,1
                    elif m.g(24):status,reason=3,2
                    else:m.p(24,2);m.p(160,c)
            else:
                need(a==b==c==0,"admission reserved effects")
                if op==2:
                    if m.g(24)==0:m.p(24,1)
                elif op==3:m.p(32,1)
                elif op==5:
                    need(m.g(24)==2 and m.g(80)==0,"consume original entry only after commit")
                    if m.g(56):m.p(64,1);m.p(80,1);m.issue(112,104,1)
                    else:m.p(80,2);m.issue(112,104,2)
                    status=1
                elif op==9:pass
                elif op==10:
                    need(m.g(80)in(3,4,7)and m.g(72)==m.g(112)==0,"retired admission clear");m.zero(0,256)
                else:need(False,"unhandled admission operation")
    if m.g(0)==word("HSDARS01"):m.p(128,reason)
    return [word("HSDARR01"),320,op,status,m.g(112),m.g(104),reason,m.g(120)],256
def child(s,m):
    op,ident,cap,gen,seq,a,b,lo,hi=fields(s,8,80);status=reason=error=0
    need(op<=14 and ident and cap and gen and not any(s[80:]),"complete child input")
    if op not in(6,8):need(lo==hi==0,"child reserved clock")
    if op==0:
        need(seq==0 and a<=1 and b==0 and not any(m.w[:512]),"child initial workspace")
        for at,v in((0,word("HSDCST01")),(8,ident),(16,cap),(24,gen),(88,a),(96,1)):m.p(at,v)
    else:
        need(m.g(0)==word("HSDCST01")and(m.g(8),m.g(16),m.g(24))==(ident,cap,gen),"same original child capability")
        if op in(4,6,7,8,9,11,13):need(seq and seq==m.g(40),"single child effect acknowledgement")
        else:need(seq==0,"child unexpected effect acknowledgement")
        def issue(phase):
            m.issue(32,40,phase)
        def consumed():m.p(216,m.g(40))
        def wait_result(kind,value):
            nonlocal status,reason,error
            m.p(32,0);consumed()
            if kind==0:
                need(value<=0xffffffff,"actual raw wait status")
                for at,v in((48,1),(112,1),(120,value),(176,1)):m.p(at,v)
            else:
                need(kind==1 and 0<value<=4095,"actual wait errno")
                m.p(56,1);status,reason,error=3,5 if op==8 else 4,value
        if op in(6,7,8,9,11,13):
            phase=m.g(32)
            if op==6:
                need(phase==2 and a<=2,"try_wait same original child")
                if a:
                    need(lo==hi==0,"nonclock try_wait")
                    wait_result(0 if a==1 else 1,b)
                else:
                    need(b==0,"alive try_wait")
                    m.clock(lo,hi,152,168)
                    dl,dh=m.g(72),m.g(80)
                    if not m.g(64):
                        deadline=(hi<<64|lo)+3000000000;need(deadline<(1<<128),"cleanup deadline overflow");dl,dh=deadline&MASK,deadline>>64
                    if not before(lo,hi,dl,dh):
                        m.p(32,0);consumed();status,reason=3,3
                    else:
                        for at,v in((64,1),(72,dl),(80,dh),(128,0)):m.p(at,v)
                        m.add(192);consumed();issue(3);status=1
            elif op==7:
                need(phase==3 and a<=4095 and b==0,"kill actual acknowledgement")
                m.p(128,a);consumed();issue(4);status=1
            elif op==8:
                need(phase==4 and a<=2,"original bounded cleanup wait")
                if a==2:
                    need(b==0 and not before(lo,hi,m.g(72),m.g(80)),"cleanup timeout same immutable deadline")
                    m.clock(lo,hi,152,168);m.p(32,0);consumed();status,reason,error=3,6,m.g(128)
                else:
                    need(lo==hi==0,"actual wait without synthetic clock");wait_result(a,b)
            elif op==9:
                need(phase==1 and a<=1,"normal original wait");wait_result(a,b)
            elif op==11:
                need(phase==5 and a<=1 and b==0,"registry original identity acknowledgement")
                if a:m.p(32,0);consumed();status,reason=3,8
                else:m.p(96,0);consumed();issue(6);status=1
            else:
                need(phase==6 and a==b==0,"original guard drop after registry release")
                m.p(88,0);m.p(32,7);consumed()
        elif op==12:need(a==b==0,"child observe")
        else:
            need(a==b==0,"child unused arguments")
            if op==4:
                need(m.g(32)==1,"only cancel current normal wait");m.p(32,0);m.add(224);consumed()
            else:
                need(m.g(32)==0 or op==14,"child effect already in progress")
                if op==1:need(m.g(96)==1 and not m.g(104),"borrow original pipes");m.p(104,1)
                elif op==2:need(m.g(104)==1,"end original pipe borrow");m.p(104,0)
                elif op==3:
                    if m.g(56):status,reason=3,1
                    elif not m.g(48):m.add(184);issue(1);status=1
                elif op==5:
                    need(not m.g(104),"no reap while pipes borrowed")
                    if m.g(48):pass
                    elif m.g(56):status,reason=3,2
                    else:m.add(200);issue(2);status=1
                elif op==10:
                    need(not m.g(104),"no registry release while pipes borrowed")
                    if not m.g(48):status,reason=3,7
                    else:need(m.g(96)==1,"registry still owns original");m.add(208);issue(5);status=1
                elif op==14:
                    need(m.g(32)==7 and m.g(96)==m.g(88)==m.g(104)==0,"retired child clear");m.zero(0,512)
                else:need(False,"unhandled child operation")
    if m.g(0)==word("HSDCST01"):m.p(136,reason);m.p(144,error)
    return [word("HSDCCR01"),576,op,status,m.g(32)if status==1 else 0,m.g(40),reason,error],512
def core(s,m):
    op,cap,gen,ident,request,generation,a,b,c,seq=fields(s,8,88)
    need(op<=15 and cap and gen and c==0 and not any(s[88:]),"complete core input")
    status=reason=effect=0
    def freeze():m.p(40,0);m.p(48,1)
    def join_status():
        return (2,0)if not m.g(120)else((0,0)if not m.g(128)else(3,12))
    def find(kind,i,cp,g):
        for p in range(320,m.g(96),64):
            if(m.g(p+24),m.g(p),m.g(p+8),m.g(p+16))==(kind,i,cp,g):return p
        return 0
    def free_row():
        for p in range(320,m.g(96),64):
            if not m.g(p+24)and p!=m.g(208):return p
        p=m.g(96)
        if len(m.w)-p<64:return 0
        need(not any(m.w[p:p+64]),"new dynamic registry row zero");return p
    def take_row():
        p=free_row()
        if not p:return 0
        if p==m.g(96):m.p(96,p+64)
        return p
    if op==0:
        need(ident==request==generation==a==b==seq==0,"core initial arguments")
        initial(m,"HSDCPS01",cap,gen,320);m.p(56,1);m.p(96,320)
    else:
        identity(m,"HSDCPS01",cap,gen)
        need((seq>0)if op in(2,12)else seq==0,"core effect sequence shape")
        if op in(5,6,7,8,9):
            need(m.g(24)==2 and request and generation,"live original registry")
            if op==5:
                need(ident==a==b==0 and m.g(64)==0 and find(2,0,request,generation),"reserve registered original task")
                if m.g(192):m.p(48,1);status,reason=3,4
                elif m.g(56)==MASK:m.p(56,0);m.p(48,1);status,reason=3,5
                elif m.g(56)==0:m.p(56,1);status,reason=3,6
                else:
                    p=take_row()
                    if not p:return [word("HGRWS002"),1,m.g(96)+64,0],-1
                    m.p(64,m.g(56));m.add(56);m.p(72,request);m.p(80,generation);m.p(208,p)
            elif op==6:
                need(ident and(ident,request,generation)==(m.g(64),m.g(72),m.g(80))and a<=1,"consume original reservation")
                if a:
                    need(b,"registered child capability");p=m.g(208)
                    for at,v in((p,ident),(p+8,b),(p+16,generation),(p+24,1)):m.p(at,v)
                    m.add(88);m.add(216)
                else:need(b==0,"aborted reservation")
                for at in(64,72,80,208):m.p(at,0)
            elif op==7:
                need(ident and a<=1 and b==0 and m.g(64)==0,"original registry removal")
                p=find(1,ident,request,generation)
                if not a:m.p(48,1);status,reason=3,7
                elif not p:m.p(48,1);status,reason=3,8
                else:
                    if m.g(192):m.p(48,1)
                    m.zero(p,p+64);m.add(88,-1);m.add(224)
            else:
                need(ident==a==b==0,"task registry arguments")
                if op==8:
                    need(not find(2,0,request,generation),"original task unique")
                    p=take_row()
                    if not p:return [word("HGRWS002"),1,m.g(96)+64,0],-1
                    for at,v in((p+8,request),(p+16,generation),(p+24,2)):m.p(at,v)
                    m.add(160)
                else:
                    p=find(2,0,request,generation)
                    need(p and(m.g(72),m.g(80))!=(request,generation),"task retired without reservation")
                    m.zero(p,p+64);m.add(160,-1)
        else:
            need(ident==request==generation==0,"core unused capability fields")
            if op==1:
                need(a==b==0,"core start arguments")
                if m.g(32):status,reason=3,1
                elif m.g(24)==0:m.add(168);m.p(176,m.g(168));m.p(24,1);status,effect=1,1
                elif m.g(24)==1:status=2
                elif m.g(24)==3:status,reason=3,2
                elif m.g(48):freeze();status,reason=3,3
            elif op==2:
                need(m.g(24)==1 and seq==m.g(176)and a<=1 and b,"original owner creation acknowledgement")
                m.p(176,0)
                if a:m.p(24,3);m.p(136,b);status,reason=3,2
                else:
                    m.p(24,2);m.p(104,b)
                    if m.g(32)==m.g(48)==0:m.p(40,1)
                    else:freeze()
            elif op in(3,4):
                need(a==b==0,"freeze arguments")
                if op==3:m.p(32,1)
                freeze()
            elif op==10:
                need(a<=1 and m.g(24)==2 and not m.g(144),"original owner exit once")
                need((a and b)or(a==b==m.g(160)==m.g(88)==m.g(64)==0),"owner successful drain")
                m.p(144,1);m.p(152,b);freeze()
            elif op==11:
                need(a<=1 and b==0 and m.g(24)==2,"unique independent join")
                freeze()
                if not a:status,reason=3,10
                elif not m.g(112):
                    if not m.g(104):status,reason=3,11
                    else:
                        m.add(168);m.p(184,m.g(168));m.p(232,m.g(104));m.p(104,0);m.p(112,1);status,effect=1,2
                else:status,reason=join_status()
            elif op==12:
                need(m.g(24)==2 and m.g(112)==1 and m.g(120)==0 and seq==m.g(184)and a<=1,"unique original join acknowledgement")
                need((a and b)or(a==b==m.g(152)==m.g(88)==m.g(160)==m.g(64)==0 and m.g(144)==1),"confirmed join complete")
                m.p(120,1);m.p(128,b);m.p(184,0)
                if not m.g(144):m.p(144,1);m.p(152,b)
                status,reason=join_status()
            elif op==13:
                need(a==b==0,"persistent join observer")
                status,reason=join_status()if m.g(112)else(3,11)
            elif op==14:
                need(a<=1 and b==0,"poison arguments");m.p(192 if not a else 200,1)
            elif op==15:need(a==b==0,"core observation")
            else:need(False,"unhandled core operation")
    return [word("HSDCPR01"),384,op,status,reason,effect,m.g(64),m.g(168)],320
def io(s,m):
    op,cap,gen,a,b,c,lo,hi,seq=fields(s,8,80)
    need(op<=3 and cap and gen and not any(s[80:]),"complete IO policy input")
    status=0
    def fail(reason,error=0):m.p(24,2);m.p(104,reason);m.p(112,error)
    def clear():m.zero(200,224)
    def issue(action,offset=0,count=0):
        nonlocal status
        m.issue(168,176,action);m.p(184,count);m.p(192,offset);status=1
    if op==0:
        need(b<=7 and c==seq==0,"IO initialization")
        initial(m,"HSDIOS01",cap,gen,256)
        for at,v in((32,a),(224,b),(48,b&1),(56,(b>>1)&1),(64,(b>>2)&1),(120,lo),(128,hi)):m.p(at,v)
        for bit,reason in((1,4),(2,5),(4,6)):
            if not b&bit:fail(reason);break
    else:
        identity(m,"HSDIOS01",cap,gen)
        if op==2:
            need(lo==hi==0 and seq and seq==m.g(176)and m.g(168),"IO effect sequence")
            action=m.g(168);negative=bool(a>>63);error=(-a)&MASK if negative else 0
            need(not negative or 0<error<=4095,"real syscall errno")
            if action<=3:
                need(c==0 and(b==0 if action==1 or negative or a==0 else b==a),"IO actual byte count")
                need(negative or a<=m.g(184),"IO bounded syscall count")
            elif action==4:
                need(c and(b==0 if negative or not a else a==c and b<=0xffffffff),"original wait PID and status")
            else:need(b==c==0 and(negative or a==0),"close actual return")
            clear();m.p(168,0);m.p(184,0);m.p(192,0)
            if action<=4:m.p(160,action&3)
            if action>=5:m.p(48+(action-5)*8,0);m.add(240)
            elif negative:
                if error!=4 and not(action<=3 and error==11):fail({1:7,2:9,3:10,4:13}[action],error);status=3
            elif action==1:
                if a:m.add(40,a)
                else:fail(8);status=3
            elif action==4:
                if a:m.p(72,1);m.p(80,b)
            elif not a:m.p(56+(action-2)*8,2)
            else:
                offset=88+(action-2)*8;previous=m.g(offset)
                if a>8388608-previous:fail(9+action);status=3
                else:m.p(offset,previous+a);m.p(200,action-1);m.p(208,previous);m.p(216,a)
        else:
            need(seq==0 and not m.g(168),"IO no outstanding effect")
            if op==3:need(a==b==c==lo==hi==0,"IO observation arguments")
            else:
                need(a<=1 and b<=1 and c<=15,"actual cancellation stop readiness")
                m.clock(lo,hi,136,152);clear()
                if m.g(24)==1:status=2
                else:
                    if not m.g(24):
                        if a:fail(1)
                        elif b:fail(2)
                        elif not before(lo,hi,m.g(120),m.g(128)):fail(3)
                    if m.g(24)==2:
                        for at,action in((48,5),(56,6),(64,7)):
                            if m.g(at):issue(action);break
                        else:status=3
                    elif m.g(48)==1 and m.g(40)==m.g(32):issue(5)
                    elif m.g(56)==2:issue(6)
                    elif m.g(64)==2:issue(7)
                    elif m.g(48)==m.g(56)==m.g(64)==0 and m.g(72):m.p(24,1);status=2
                    else:
                        for j in range(4):
                            cursor=(m.g(160)+j)&3
                            if cursor==0 and m.g(48)==1 and c&1:issue(1,m.g(40),min(8192,m.g(32)-m.g(40)));break
                            if cursor==1 and m.g(56)==1 and c&2:issue(2,m.g(88),8192);break
                            if cursor==2 and m.g(64)==1 and c&4:issue(3,m.g(96),8192);break
                            if cursor==3 and not m.g(72)and c&8:issue(4);break
    return [word("HSDIOR01"),320,op,status,m.g(168),m.g(176),m.g(200),m.g(208)],256
def future(s,m):
    op,cap,gen,ready,failed,stop,lo,hi,cancel=fields(s,8,80)
    need(op<=1 and cap and gen and max(ready,failed,stop,cancel)<=1 and not any(s[80:]),"complete caller future input")
    if op==0:
        need(ready==failed==stop==cancel==0,"future initialization")
        initial(m,"HSSFS001",cap,gen,128);m.p(24,lo);m.p(32,hi)
    else:
        identity(m,"HSSFS001",cap,gen)
        if not m.g(40):
            m.clock(lo,hi,80,96);m.add(104)
            for at,v in((48,ready),(56,failed),(64,stop),(72,cancel)):m.p(at,v)
            expired=not before(lo,hi,m.g(24),m.g(32))
            phase=(3 if expired else 0)if not ready else(1 if failed else(4 if stop or cancel or expired else 2))
            m.p(40,phase)
    return [word("HSSFR001"),192,op,m.g(40),m.g(104),0,0,0],128
def command(s,m):
    need(len(s)>=64 and not any(s[48:64]),"complete fixed command")
    pathlen,argc,envc,flags,size=fields(s,8,48)
    need(size==len(s)and argc and flags<=63 and not((flags&7)&(flags>>3)),"fixed command shape")
    def nul(at,n):
        need(n<len(s)-at and not any(x==0 for x in s[at:at+n])and s[at+n]==0,"complete NUL terminated owned bytes")
        return at+n+1
    need(pathlen>0,"nonempty trusted executable");at=nul(64,pathlen);offsets=[];strings=[]
    for i in range(argc+envc):
        need(at+8<=len(s),"command record extent");n=q(s,at);at+=8;offsets.append(at);strings.append(s[at:at+n]);at=nul(at,n)
    need(at==len(s),"command complete byte consumption")
    extent=64+8*(argc+envc)
    return pack([word("HSCMLY01"),extent,64,argc,envc,flags,len(s),0,*offsets]),strings
REQUESTS={1:b"HSDARQ01",2:b"HSDCCQ01",3:b"HSDCPQ01",4:b"HSDIOQ01",5:b"HSSFQ001"}
MODELS={1:admission,2:child,3:core,4:io,5:future}
def expected(module,input_before,work_before,output_before):
    need(module in MODELS and not any(output_before),"known native policy and complete zeroed output")
    m=M(work_before)
    if module==4 and input_before[:8]==b"HSDCMD01":
        raw,strings=command(input_before,m);ret=len(raw)
    else:
        need(len(input_before)==128 and input_before[:8]==REQUESTS[module],"exact native policy request")
        head,extent=MODELS[module](input_before,m)
        if extent==-1:ret=0xffffffd0;raw=pack(head)
        else:ret=64+extent;raw=pack(head)+m.w[:extent]
    need(len(raw)<=len(output_before),"complete output capacity")
    return ret,bytes(m.w),raw+bytes(len(output_before)-len(raw))
