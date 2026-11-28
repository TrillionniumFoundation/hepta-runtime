"""Complete actual native buffers; callback copies only and never supplies effects."""
import ctypes as C,gzip,struct,time
from common import pin,require
from evidence_codec import encoded
from watcher_loader import CONTEXT_BYTES,OBSERVER,word
class Capture:
    def __init__(self,output):
        self.output=output;self.rows=[];self.errors=[];self.active=None;self.offset=8
        self.case=None;self.step=None;self.operation=None
        self.raw=(output/"complete-native-buffers.bin.gz").open("xb")
        self.stream=gzip.GzipFile(filename="",mode="wb",compresslevel=1,fileobj=self.raw,mtime=0)
        self.stream.write(b"HNWLOG01");self.callback=OBSERVER(self.observe)
    def record(self,kind,raws,meta):
        row=dict(index=len(self.rows),kind=kind,offset=self.offset,case=self.case,step=self.step,
            operation=self.operation,meta=meta,buffers=[pin(raw)for raw in raws])
        header=encoded(row);wire=struct.pack("<Q",len(header))+header
        complete=b"".join((wire,*raws))
        self.stream.write(complete);self.offset+=len(complete)
        self.rows.append(row)
    def observe(self,user,ctx,size,record,n):
        if self.errors:return
        try:
            require(user in(None,0) and ctx==self.active and size==CONTEXT_BYTES
                and record==ctx+24960 and n==128,"actual exclusive native observation borrow")
            raw=C.string_at(ctx,size);event=raw[24960:25088]
            require(event[:8]in(b"HNWOWN01",b"HNWBN001",b"HNWNCL01") and word(event,8)in(0,1),"exact native observation frame")
            pins=set()
            count=word(raw,104);require(count<=259,"actual bounded native pin set")
            for i in range(count):pins.add(word(raw,512+16*i))
            shared=word(raw,32)
            if shared:pins.add(shared)
            pages=[]
            for ptr in sorted(pins):
                require(ptr>0 and ptr%4096==0,"actual private pin alignment")
                page=C.string_at(ptr,4096)
                require(page[:8]==b"HNWFP001" and word(page,8)>0 and word(page,24)==4096,
                    "complete actual live File reference")
                pages.append((ptr,page))
            self.record("observation",(raw,)+tuple(page for _,page in pages),
                dict(context=ctx,event=event.hex(),pins=[ptr for ptr,_ in pages],observed_ns=time.monotonic_ns()))
        except BaseException as error:self.errors.append(repr(error))
    def close(self,success):
        try:
            if success and not self.errors:self.stream.write(b"HNWEND01"+struct.pack("<Q",len(self.rows)))
            self.stream.close();self.raw.close()
        finally:
            (self.output/"RECORDS.json").write_bytes(encoded(self.rows))
            (self.output/"OBSERVER-ERRORS.json").write_bytes(encoded(self.errors))
