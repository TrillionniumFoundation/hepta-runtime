"""Bind complete HIA/real-native before/after borrows to exact kernel effects."""
import struct
from reader_common import require,word,integer
from read_pairs import exact
from read_native_state import N,W,I,O,E,P,U,put,signed,same_except,context,slots,pin_page,release_frame
def owner_event(ctx,ptr):
    return b"HNWOWN01"+struct.pack("<15Q",0,0,word(ctx,16),word(ctx,144),word(ctx,72),
        ptr+I,word(ctx,112),ptr+O,128,ptr+W,65536,word(ctx,64),word(ctx,128),word(ctx,96),word(ctx,104))
def boundary_event(ctx,phase=0):
    r=ctx[O:O+128]
    return b"HNWBN001"+struct.pack("<15Q",phase,word(ctx,80)if phase else 0,
        word(ctx,16),word(ctx,144),word(r,40),word(ctx,72),word(r,48),word(r,56),word(r,64),
        word(ctx,96),word(ctx,24),word(ctx,80)if phase else 0,word(ctx,88)if phase else 0,
        word(ctx,104),word(ctx,128))
def request(op,generation):
    code={"new":1,"version":2,"drain":3,"drop":4,"changed":5}[op["op"]]
    return b"HNWQ0001"+struct.pack("<11Q",code,generation,1 if code==2 else 0,
        3 if code==2 and op["shared"]else 0,op["limit"]if code==1 else 0,
        int(op["content"])if code==1 else 0,(op["wd"]&0xffffffff)if code==5 else 0,
        op["mask"]if code==5 else 0,0,0,0)
def response(raw,work,generation,command):
    require(len(raw)==128 and raw[:8]==b"HNWR0001"and word(raw,8)in(0,1,2)
        and word(raw,16)==generation and word(raw,32)==command and word(raw,120)==0
        and word(raw,24)==word(work,32)and word(raw,104)==word(work,80)
        and word(raw,112)==word(work,88),"every complete HIA response and persistent-state identity")
    if word(raw,8)==2:
        require(1<=word(raw,40)<=8 and raw[72:104]==bytes(32)and word(work,16)==command
            and word(work,48)==word(raw,40),"complete requested actual effect")
    else:
        require(raw[40:72]==bytes(32)and word(work,16)==word(work,40)==word(work,48)==0,
            "whole terminal and quiescent HIA state")
        if word(raw,8)==0:require(raw[72:88]==bytes(16),"whole successful original terminal")
        else:require(word(raw,72)in(1,2)and 1<=word(raw,80)<=(4095 if word(raw,72)==1 else 8)
            and raw[88:104]==bytes(16),"whole original error terminal")
def full_pin_snapshot(ledger,meta,raws,expected):
    require(meta["pins"]==sorted(expected)and len(raws)==1+len(expected),"complete actual current File-page borrow")
    for ptr,raw in zip(meta["pins"],raws[1:]):
        require(raw==ledger.pages[ptr],"all prior live File bytes preserved")
def expected_pins(ctx):
    out={p for p,_ in slots(ctx)}
    if word(ctx,32):out.add(word(ctx,32))
    return out
def next_owner(previous):
    out=bytearray(previous);n=word(out,112);out[I+n:I+n+16]=b"\xc3"*16
    out[E:E+128]=owner_event(out,0) # caller relocates the three checked pointers
    return out
class Turn:
    def __init__(self,ledger,ptr,op,generation,kernel):
        self.ledger=ledger;self.ptr=ptr;self.op=op;self.generation=generation
        self.wire=request(op,generation);self.command=word(self.wire,8)
        self.before=ledger.contexts[ptr];self.current=self.before[:N];self.stage="owner-before"
        self.first=True;self.pending=None;self.last_ns=0;self.kernel=kernel;self.at=0;self.hia=0;self.boundaries=0
    def kernel_effect(self,wanted):
        require(self.at<len(self.kernel),"every native effect has an actual syscall")
        actual=self.kernel[self.at];self.at+=1
        exact(actual,wanted,"complete actual kernel effect equals the native borrowed result")
    def feed(self,row,raws):
        require(self.ledger.observer and row["kind"]=="observation"and raws,"only actual enabled observation")
        meta=row["meta"];ctx=raws[0];event=ctx[E:E+128]
        require(meta["context"]==self.ptr and meta["event"]==event.hex()and integer(meta["observed_ns"],1)
            and meta["observed_ns"]>=self.last_ns,"same owned context, full event and monotonic observation")
        self.last_ns=meta["observed_ns"];context(ctx,self.ledger.table,True,False)
        phase=word(event,8);magic=event[:8]
        expected_magic=b"HNWOWN01"if self.stage.startswith("owner")else b"HNWBN001"
        require(magic==expected_magic and phase==(1 if self.stage.endswith("after")else 0),"every source-order HIA/native before-after edge")
        if self.stage=="owner-before":
            out=bytearray(self.current)
            if self.first:
                for at,value in((8,1),(16,self.generation),(72,0),(112,96),(144,self.command)):put(out,at,value)
                require(word(ctx,56)>0 and word(ctx,56)%4==0 and word(ctx,136)<=0xffffffff,"actual thread errno location and value")
                if hasattr(self.ledger,"tls"):require(word(ctx,56)==self.ledger.tls,"same actual thread errno location")
                else:self.ledger.tls=word(ctx,56)
                put(out,56,word(ctx,56));put(out,136,word(ctx,136));out[I:I+96]=self.wire
                if self.command in(2,3):out[98336:98336+16384]=bytes(16384)
                out[O:O+144]=b"\xa5"*144;out[W+65536:W+65552]=b"\x5a"*16;self.first=False
            n=word(out,112);require(96<=n<=16480,"whole native HIA input extent")
            out[I+n:I+n+16]=b"\xc3"*16;out[E:E+128]=owner_event(out,self.ptr)
            require(ctx==out,"complete source-derived mechanical preparation before HIA")
            full_pin_snapshot(self.ledger,meta,raws,expected_pins(ctx))
            self.pending=(ctx,dict(zip(meta["pins"],raws[1:])))
            self.current=ctx;self.stage="owner-after"
        elif self.stage=="owner-after":
            before,pages=self.pending;require(meta["pins"]==sorted(pages)and raws[1:]==[pages[p]for p in sorted(pages)],
                "HIA cannot change actual native File pages")
            out=bytearray(before);out[O:O+128]=ctx[O:O+128];out[W:W+65536]=ctx[W:W+65536]
            put(out,64,word(before,64)+1);put(out,120,128);put(out,E+8,1);put(out,E+16,128)
            require(ctx==out,"whole HIA before/after buffers and all immutable mechanical bytes")
            response(ctx[O:O+128],ctx[W:W+65536],self.generation,self.command)
            require(ctx[I+word(ctx,112):I+word(ctx,112)+16]==b"\xc3"*16
                and ctx[O+128:O+144]==b"\xa5"*16 and ctx[W+65536:W+65552]==b"\x5a"*16,"all HIA guard bytes")
            self.hia+=1;self.current=ctx;self.pending=None
            self.stage="boundary-before"if word(ctx,O+8)==2 else"terminal"
        elif self.stage=="boundary-before":
            r=self.current[O:O+128];seq=word(self.current,72)+1;require(word(r,24)==seq,"no skipped native prepared effect")
            out=bytearray(self.current);put(out,72,seq);put(out,80,0);put(out,88,0);put(out,112,96)
            out[I:I+96]=b"HNWAK001"+struct.pack("<11Q",self.generation,seq,word(r,40),0,0,0,0,0,0,96,0)
            out[6528:6592]=bytes(64);out[E:E+128]=boundary_event(out)
            require(ctx==out,"entire mechanical effect admission before real libc")
            full_pin_snapshot(self.ledger,meta,raws,expected_pins(ctx))
            self.pending=(ctx,dict(self.ledger.pages));self.current=ctx;self.stage="boundary-after"
        elif self.stage=="boundary-after":
            before,pages=self.pending;self.boundary(before,ctx,meta,raws,pages)
            self.boundaries+=1;self.current=ctx;self.pending=None;self.stage="owner-before"
        else:raise ValueError("observation after complete terminal")
        self.ledger.set_context(self.ptr,ctx)
    def boundary(self,before,ctx,meta,raws,pages):
        op=word(before,O+40);a,b,c=[word(before,O+x)for x in(48,56,64)]
        result=signed(word(ctx,80));error=word(ctx,88)
        require(error<=0xffffffff and result>=-1 and(result!=-1 or 1<=error<=4095),"complete actual libc return and errno")
        out=bytearray(before);ack=bytearray(before[I:I+96]);put(out,80,word(ctx,80));put(out,88,error)
        put(out,136,error);put(out,128,word(before,128)+1)
        status=int(result==-1)
        if status:put(ack,32,1);put(ack,40,error)
        kernel=dict(result=result,errno=error if status else 0)
        expected_pages=dict(pages);payload=b""
        if op==1:
            require((a,b,c)==(526336,0,0)and word(before,96)==U,"actual inotify initialization request")
            self.kernel_effect(dict(op="init",flags=a,**kernel))
            if not status:put(out,96,result);put(ack,48,2)
        elif op==2:
            require((a,b,c)==(2,16384,0),"full original read capacity")
            if not status:
                require(0<=result<=16384,"actual full read result extent")
                payload=ctx[98336:98336+result];out[98336:98336+result]=payload
                put(ack,48,result);put(ack,72,result);put(ack,80,96+result);put(out,112,96+result)
            self.kernel_effect(dict(op="read",fd=word(before,96),capacity=16384,data=payload.hex(),**kernel))
        elif op==3:
            require((a,b,c)==(1,0,0),"same borrowed real metadata capability")
            out[6144:6288]=ctx[6144:6288]
            if not status:
                require(result==0,"actual metadata success")
                values=[word(ctx,6144),word(ctx,6152),int.from_bytes(ctx[6168:6172],"little")]
                for at,value in zip((48,56,64),values):put(ack,at,value)
            else:values=None
            self.kernel_effect(dict(op="stat",fd=word(before,24),identity=values,**kernel))
        elif op==4:
            require(a==1 and(c==0 and b==0 or c==1 and b==3),"exact native clone/duplicate mode")
            if c==0:
                self.kernel_effect(dict(op="clone",fd=word(before,24),**kernel))
                if not status:
                    fresh=[p for p in meta["pins"]if p not in pages]
                    require(len(fresh)==1,"one actual new owned pin after duplicate")
                    p=fresh[0];raw=raws[1+meta["pins"].index(p)]
                    require(pin_page(raw,self.ledger.table)==dict(strong=1,fd=result),"actual new pin owns the duplicated kernel FD")
                    expected_pages[p]=raw
            else:
                p=word(before,32);require(not status and p in pages and result==p,"actual shared caller reference clone")
                raw=bytearray(pages[p]);put(raw,8,word(raw,8)+1);expected_pages[p]=bytes(raw)
            if not status:
                count=word(before,104);require(count<259 and p not in dict(slots(before)),"one new native owned reference")
                put(out,P+count*16,p);put(out,P+count*16+8,U);put(out,104,count+1);put(ack,48,p)
        elif op==5:
            require(a==2 and b in dict(slots(before))and c in(16781248,16781262),"exact watch mask and held File")
            path=b"/proc/self/fd/"+str(word(pages[b],16)).encode()
            # The real assembly copies the prefix and writes its temporary digit suffix.
            expected_path=bytearray(before[6400:6464]);expected_path[:14]=b"/proc/self/fd/"
            digits=str(word(pages[b],16)).encode();expected_path[63]=0
            expected_path[63-len(digits):63]=digits;expected_path[14:15+len(digits)]=digits+b"\0"
            out[6400:6464]=expected_path
            self.kernel_effect(dict(op="add",fd=word(before,96),path=path.hex(),mask=c,**kernel))
            if not status:
                index=[p for p,_ in slots(before)].index(b);put(out,P+index*16+8,result);put(ack,48,result)
        elif op==6:
            require(a==2 and c==0 and b in[w for _,w in slots(before)],"actual held watch removal")
            self.kernel_effect(dict(op="remove",fd=word(before,96),wd=b,**kernel))
        elif op==7:
            require(b==c==0 and a in pages and a in dict(slots(before)),"actual last/shared held File release")
            old=pages[a];new=bytearray(old);put(new,8,word(old,8)-1)
            remaining=bytes(new)if word(old,8)>1 else b""
            facts=release_frame(old,remaining,ctx[6528:6592],self.ledger.table)
            require(result==facts["result"]and error==word(ctx,6528+40),"complete actual close/error release facts")
            if facts["last"]:
                self.kernel_effect(dict(op="close",fd=facts["fd"],result=facts["result"],errno=facts["errno"]))
                del expected_pages[a]
            else:expected_pages[a]=remaining
            out[6528:6592]=ctx[6528:6592];pairs=slots(before);index=[p for p,_ in pairs].index(a)
            pairs[index]=pairs[-1];pairs.pop();out[P:P+259*16]=bytes(259*16)
            for i,(ptr,wd)in enumerate(pairs):put(out,P+i*16,ptr);put(out,P+i*16+8,wd)
            put(out,104,len(pairs))
        elif op==8:
            require((a,b,c)==(2,0,0),"actual owned event descriptor close")
            self.kernel_effect(dict(op="close",fd=word(before,96),**kernel));put(out,96,U)
        else:raise ValueError("unlisted actual effect")
        out[I:I+96]=ack
        if payload:out[I+96:I+96+len(payload)]=payload
        out[E:E+128]=boundary_event(out,1)
        require(ctx==out,"every complete native before/after byte has its exact mechanical cause")
        expected=expected_pins(ctx);require(meta["pins"]==sorted(expected)and len(raws)==1+len(expected),"complete native page ownership after effect")
        for ptr,raw in zip(meta["pins"],raws[1:]):
            require(ptr in expected_pages and raw==expected_pages[ptr],"entire actual live File page after exact native effect")
        self.ledger.pages=expected_pages
    def finish(self,row,raws):
        require(len(raws)==6 and row["meta"]==dict(context=self.ptr,cmd=self.command,generation=self.generation,returned=128),
            "all complete outer entry facts")
        bi,bo,bw,ai,ao,aw=raws
        require(bi==ai==self.wire+b"\xc3"*16 and bo==b"\xa5"*144
            and len(ao)==144 and ao[128:]==b"\xa5"*16 and bw==self.before and len(aw)==N+16
            and aw[N:]==b"\x5a"*16,"entire actual outer entry buffers and immutable guards")
        if self.ledger.observer:
            require(self.stage=="terminal"and self.pending is None,"all before/after observations and terminal are complete")
            out=bytearray(self.current);put(out,8,0);put(out,56,0);put(out,136,0)
            require(aw[:N]==out and ao[:128]==self.current[O:O+128],"exact native terminal copy and borrow cleanup")
        else:
            require(self.stage=="owner-before"and self.first,"no hidden observer calls")
            context(aw,self.ledger.table,False)
            same_except(bw,aw,[(8,24),(56,160),(P,P+259*16),(6144,6288),(6400,6464),(6528,6592),
                (I,I+16480+16),(O,O+144),(E,E+128),(W,W+65552),(98336,98336+16384)],
                "complete observer-off entry outside fixed owned regions")
            require(word(aw,8)==word(aw,56)==word(aw,136)==0 and word(aw,16)==self.generation
                and word(aw,144)==self.command and ao[:128]==aw[O:O+128],"actual observer-off terminal identity")
            require(word(aw,64)-word(bw,64)==word(aw,128)-word(bw,128)+1,"all real observer-off HIA/native calls accounted")
        response(ao[:128],aw[W:W+65536],self.generation,self.command)
        require(word(ao,8)in(0,1)and word(ao,24)==word(aw,72)and word(ao,112)==word(aw,104)
            and word(ao,104)==word(aw,W+80),"whole final native terminal ownership and sequence")
        self.ledger.set_context(self.ptr,aw)
        if self.ledger.observer:require(self.at==len(self.kernel),"no unclaimed actual kernel effect inside the native method")
        return ao[:128]
