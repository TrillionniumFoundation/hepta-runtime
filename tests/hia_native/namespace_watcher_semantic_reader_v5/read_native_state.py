"""Complete physical native context, shared File pages and quiescent projections."""
import struct
from collections import Counter
from reader_common import require,word,integer
from read_pairs import exact
N=131072;W=32768;I=8192;O=24704;E=24960;P=512;U=(1<<64)-1
def put(raw,at,value):struct.pack_into("<Q",raw,at,value)
def signed(value):return value-(1<<64)if value>>63 else value
def same_except(before,after,spans,message):
    require(len(before)==len(after),message+" extent")
    spans=sorted(spans);at=0
    for lo,hi in spans:
        require(0<=lo<=hi<=len(before),message+" allowed span")
        if lo>at:require(before[at:lo]==after[at:lo],message+" unchanged bytes")
        at=max(at,hi)
    require(before[at:]==after[at:],message+" complete tail")
def pin_page(raw,table):
    require(len(raw)==4096 and raw[:8]==b"HNWFP001"and 1<=word(raw,8)<1<<63
        and 32<=word(raw,16)<=771 and word(raw,24)==4096 and raw[32:48]==table[48:64]
        and raw[48:]==bytes(4048),"whole actual live File page, extent and untouched tail")
    return dict(strong=word(raw,8),fd=word(raw,16))
def slots(ctx):
    count=word(ctx,104);require(count<=259,"whole native ownership table count")
    result=[(word(ctx,P+i*16),word(ctx,P+i*16+8))for i in range(count)]
    require(len({p for p,_ in result})==count and all(p>0 and p%4096==0 and(w==U or w<=0x7fffffff)for p,w in result)
        and ctx[P+count*16:P+259*16]==bytes((259-count)*16),"whole distinct native pin table and unused tail")
    return result
def context(raw,table,observer,outer=True):
    require(len(raw)==N+(16 if outer else 0)and(not outer or raw[N:]==b"\x5a"*16),"whole native context and actual outer guard")
    require(raw[:8]==b"HNWCTX01"and word(raw,8)in(0,1)
        and(word(raw,24)==U or 32<=word(raw,24)<=771)
        and(word(raw,32)==0 or word(raw,32)%4096==0)
        and bool(word(raw,40))==observer and word(raw,48)==0 and word(raw,152)==0
        and raw[160:256]==bytes(96)and raw[256:320]==table[:64]and raw[320:512]==bytes(192),
        "entire native header, bound libc table and complete reserved bytes")
    require(word(raw,96)==U or 32<=word(raw,96)<320,"actual bounded event descriptor")
    require(raw[P+259*16:6144]==bytes(6144-P-259*16)
        and raw[6288:6400]==bytes(112)and raw[6464:6528]==bytes(64)
        and raw[6592:I]==bytes(I-6592)and raw[I+16480+16:O]==bytes(O-I-16480-16)
        and raw[O+144:E]==bytes(E-O-144)and raw[E+128:W]==bytes(W-E-128)
        and raw[W+65536+16:98336]==bytes(16)and raw[98336+16384:N]==bytes(N-98336-16384),
        "all untouched mechanical context holes and full tail")
    slots(raw)
def release_frame(before,after,out,table):
    old=pin_page(before,table);require(len(out)==64 and out[:8]==b"HNWFPR01"
        and word(out,8)==old["strong"]and word(out,16)==old["strong"]-1
        and word(out,24)==old["fd"]and word(out,48)==word(out,56)==0
        and word(out,40)<=0xffffffff,"complete actual File release facts")
    if old["strong"]==1:
        require(after==b""and signed(word(out,32))in(0,-1)
            and(word(out,32)==0 or 1<=word(out,40)<=4095),"actual last reference close and successful unmap")
    else:
        expected=bytearray(before);put(expected,8,old["strong"]-1)
        require(after==expected and word(out,32)==0,"whole shared reference decrement without close")
    return dict(fd=old["fd"],last=old["strong"]==1,result=signed(word(out,32)),
        errno=word(out,40)if signed(word(out,32))==-1 else 0)
class Ledger:
    def __init__(self,table,observer):
        self.table=table;self.observer=observer;self.contexts={};self.wids={};self.roots={};self.pages={}
    def set_context(self,ptr,raw):
        require(integer(ptr,1)and ptr%8==0,"actual full context address")
        context(raw,self.table,self.observer,len(raw)==N+16)
        self.contexts[ptr]=bytes(raw[:N])+b"\x5a"*16
    def page(self,ptr,raw):
        require(integer(ptr,1)and ptr%4096==0,"actual full File ownership address")
        pin_page(raw,self.table);self.pages[ptr]=raw
    def snapshot(self,row,raws):
        meta=row["meta"];ctx=raws[0];ptr=meta["context"]
        require(set(meta)=={"context","event","pins","observed_ns"}and integer(meta["observed_ns"],1)
            and len(raws)==1+len(meta["pins"])and len(ctx)==N and ctx[E:E+128].hex()==meta["event"],
            "whole exclusive physical observation")
        context(ctx,self.table,self.observer,False)
        expected={p for p,_ in slots(ctx)}
        if word(ctx,32):expected.add(word(ctx,32))
        require(meta["pins"]==sorted(expected),"all complete currently borrowed File pages, no extra or omitted page")
        for pin,body in zip(meta["pins"],raws[1:]):self.page(pin,body)
        self.set_context(ptr,ctx)
        return ctx,dict(zip(meta["pins"],raws[1:]))
    def owned_counts(self):
        counts=Counter(r["pointer"]for r in self.roots.values())
        for ctx in self.contexts.values():counts.update(p for p,_ in slots(ctx))
        require(set(counts)==set(self.pages),"complete owned File-page set")
        for p,count in counts.items():
            require(pin_page(self.pages[p],self.table)["strong"]==count,"actual strong count equals all real caller and watcher holdings")
    def checkpoint(self,row,raws,wanted):
        meta=row["meta"]
        require(set(meta)=={"contexts","pins","roots","state"}and
            meta["contexts"]==[dict(wid=w,pointer=p)for w,p in sorted(self.wids.items())]
            and meta["roots"]=={str(i):v for i,v in self.roots.items()},"complete active context/root registry")
        contexts=meta["contexts"];pins=meta["pins"]
        require(pins==sorted(self.pages)and len(raws)==len(contexts)+len(pins),"all complete checkpoint contexts and File pages")
        for rec,raw in zip(contexts,raws):
            require(raw==self.contexts[rec["pointer"]],"entire previous native context retained at checkpoint")
            context(raw,self.table,self.observer)
        for p,raw in zip(pins,raws[len(contexts):]):
            require(raw==self.pages[p],"entire previous File page retained at checkpoint")
        self.owned_counts();projected=[];roots=[]
        for wid,ptr in sorted(self.wids.items()):
            ctx=self.contexts[ptr];work=ctx[W:W+65536]
            require(word(ctx,8)==word(ctx,56)==word(ctx,136)==0 and work[:8]==b"HNWST001"
                and word(work,8)==1 and word(work,16)==word(work,48)==0 and word(work,72)==2
                and word(work,88)==word(ctx,104)and word(work,88)<=258
                and work[288:512]==bytes(224)and work[1024+word(work,88)*64:32768]==bytes(32768-1024-word(work,88)*64)
                and work[49152:]==bytes(16384),"complete quiescent HIA state, unused record/tail bytes and ownership cardinality")
            rows=[];pairs=[]
            for i in range(word(work,88)):
                at=1024+i*64;p=word(work,at);require(p in self.pages and word(work,at+56)==0
                    and word(work,at+48)in(0,1),"entire HIA-owned watch row")
                page=pin_page(self.pages[p],self.table);pairs.append((p,word(work,at+24)))
                rows.append(dict(device=word(work,at+8),inode=word(work,at+16),wd=word(work,at+24),
                    id=word(work,at+32),generation=word(work,at+40),dead=bool(word(work,at+48)),
                    pin_fd=page["fd"],strong_count=page["strong"]))
            require(sorted(pairs)==sorted(slots(ctx)),"HIA watch holdings equal actual native ownership table")
            projected.append(dict(wid=wid,state=dict(event_fd=word(ctx,96),next=word(work,80),
                limit=word(work,56),content=bool(word(work,64)),watches=rows)))
        # Device/inode/mode come from the same real root FD and are independently
        # bound by read_pairs to the input-owned tree and by complete syscall stat.
        require(type(wanted)is dict and set(wanted)=={"roots","watchers"},"whole expected original state")
        for i,r in sorted(self.roots.items()):
            matches=[v for v in wanted["roots"]if v["root"]==i];require(len(matches)==1,"complete actual root projection")
            v=matches[0];page=pin_page(self.pages[r["pointer"]],self.table)
            require(v["fd"]==r["fd"]==page["fd"]and v["strong_count"]==page["strong"],"real held File reference projection")
            roots.append(v)
        result=dict(roots=roots,watchers=projected)
        exact(result,meta["state"],"full physical context/page state equals captured checkpoint")
        exact(result,wanted,"full physical native state equals unchanged original complete state")
