"""Complete read-only borrows from the native-owned fingerprint pump."""
import ctypes as C
from contextlib import ExitStack
import gzip,struct,time
from common import encoded,pin,require
from callable_contract import OFFSETS,response,word
from callable_loader import OBSERVER
HEADER=struct.Struct("<12Q")
class Observe:
    def __init__(self,output):
        self.output=output;self.rows=[];self.errors=[];self.pending=None
        self.case=self.step=self.context=None;self.last_state=None;self.last_terminal=None;self.ack=None
        resources=ExitStack()
        try:
            self.raw=resources.enter_context((output/"records.bin.gz").open("xb"))
            self.stream=resources.enter_context(gzip.GzipFile(filename="",mode="wb",compresslevel=1,fileobj=self.raw,mtime=0))
            self.index=resources.enter_context((output/"RECORDS.json").open("xb"))
            self.errorfile=resources.enter_context((output/"OBSERVER-ERRORS.json").open("xb"))
            self.pendingfile=resources.enter_context((output/"FAILED-PENDING.bin").open("xb"))
            self.stream.write(b"NFRCLOG1")
        except BaseException:resources.close();raise
        self.resources=resources.pop_all();self.closed=False;self.callback=OBSERVER(self.observe)
    def select(self,case,step,context):
        require(self.pending is None and self.ack is None,"complete preceding actual operation")
        self.case,self.step,self.context=case,step,context
        self.last_state=None;self.last_terminal=None
    def snapshot(self,pointer,user):
        require(user in(None,0) and pointer==self.context+OFFSETS["observation"],"actual native observer borrow")
        raw=C.string_at(pointer,128);words=struct.unpack("<16Q",raw)
        kind,phase,returned,ip,ni,op,no,wp,nw,context,seq,generation,actual,err,r0,r1=words
        require(kind in(1,2)and phase in(0,1)and context==self.context and r0==r1==0,"fixed actual observer record")
        if kind==1:
            require((ip,op,no,wp,nw)==(context+256,context+4608,128,context+8192,16384)
                    and (ni==64 or 96<=ni<=4192),"complete HIA borrowed ranges")
            guards=(16,16,16)
        else:
            require((ip,ni,op,no,wp,nw)==(context+4608,128,context+256,4192,context,256),
                    "complete native boundary ranges")
            guards=(0,0,0)
        spans=tuple(C.string_at(p,n+g)for p,n,g in zip((ip,op,wp),(ni,no,nw),guards))
        return dict(raw=raw,words=words,guards=guards,spans=spans,observed_ns=time.monotonic_ns())
    def observe(self,pointer,user):
        if self.errors:return
        try:
            value=self.snapshot(pointer,user);w=value["words"];kind,phase=w[:2]
            if phase==0:
                require(self.pending is None,"native before/after exact order")
                if kind==1:
                    wire=value["spans"][0][:w[4]]
                    if self.last_state is None:
                        require(len(wire)==64 and wire[:8]==b"HNFRQ001","actual first owner input")
                    else:
                        require(self.last_state["kind"]==2 and self.ack is not None and wire==self.ack,
                                "actual native ACK delivered once to HIA")
                        self.ack=None
                else:
                    require(self.last_state is not None and self.last_state["kind"]==2 and self.ack is None,
                            "actual boundary after one undelivered HIA effect")
                    require(response(value["spans"][0])==self.last_state,"exact full HIA boundary request")
                self.pending=value;return
            before=self.pending
            require(before is not None and before["words"][0]==kind and before["words"][3:12]==w[3:12],
                    "native borrowed pointers and identity unchanged across call")
            require(before["spans"][0]==value["spans"][0],"input borrow fully unchanged")
            self.pending=None
            ni,no,nw=w[4],w[6],w[8];guards=value["guards"]
            if kind==1:
                require(w[2]==128 and w[12:]==(0,0,0,0),"full successful actual owner return")
                require(before["spans"][1]==b"\xa5"*144,"complete initialized HIA output")
                require(value["spans"][0][ni:]==b"\xc3"*16 and value["spans"][1][128:]==b"\xa5"*16 and
                        value["spans"][2][16384:]==b"\x5a"*16,"all HIA borrowed guards")
                self.last_state=response(value["spans"][1][:128])
                if self.last_state["kind"]<2:self.last_terminal=value["spans"][1][:128]
            else:
                ack=value["spans"][1];extent=word(ack,64)
                require(96<=extent<=4192 and ack[:8]==b"HNFACK01","actual complete native ACK")
                require(word(ack,8)==w[11] and word(ack,16)==w[10] and
                        word(ack,24)==self.last_state["operation"],"same actual effect generation and sequence")
                self.ack=ack[:extent]
            index=len(self.rows);elapsed=value["observed_ns"]-before["observed_ns"]
            header=HEADER.pack(index,self.case,self.step,kind,ni,no,nw,*guards,elapsed,0)
            self.stream.write(b"NFRCAL01"+header+before["raw"]+value["raw"])
            for raw in before["spans"]+value["spans"]:self.stream.write(raw)
            self.rows.append(dict(index=index,case=self.case,step=self.step,kind=kind,input_bytes=ni,
                output_capacity=no,workspace_capacity=nw,guards=list(guards),elapsed_ns=elapsed,
                before_record=pin(before["raw"]),after_record=pin(value["raw"]),
                before=[pin(r)for r in before["spans"]],after=[pin(r)for r in value["spans"]]))
        except BaseException as error:self.errors.append(repr(error))
    def close(self,success):
        if self.closed:return
        self.closed=True
        try:
            if success:
                require(not self.errors and self.pending is None and self.ack is None,"complete actual callback lifecycle")
                self.stream.write(b"NFRCEND1"+struct.pack("<Q",len(self.rows)))
            self.index.write(encoded(self.rows));self.errorfile.write(encoded(self.errors))
            if self.pending is not None:self.pendingfile.write(self.pending["raw"]+b"".join(self.pending["spans"]))
        finally:self.resources.close()
