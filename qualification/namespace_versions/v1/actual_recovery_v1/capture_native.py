"""Whole actual native memory capture with lossless, deduplicated binary objects."""
import ctypes as C,gzip,hashlib,struct,threading,time
from common import encoded,pin,require
from versions_loader import OBSERVER,word
class Capture:
    def __init__(self,output,environment):
        self.output=output;self.environment=environment;self.records=[];self.objects={};self.errors=[]
        self.offset=8;self.logical_bytes=0;self.case=None;self.step=None;self.operation=None
        self.threads={};self.guard=threading.RLock()
        self.raw=(output/"complete-native-buffers.bin.gz").open("xb")
        self.stream=gzip.GzipFile(filename="",mode="wb",compresslevel=1,fileobj=self.raw,mtime=0);self.stream.write(b"HNVLOG02")
        self.callback=OBSERVER(self.observe)
    def record(self,kind,raws,meta):
        with self.guard:
            refs=[]
            for raw in raws:
                raw=bytes(raw);row=pin(raw);digest=row["sha256"];self.logical_bytes+=len(raw)
                if digest not in self.objects:
                    start=self.offset;wire=b"NVOBJ001"+struct.pack("<Q",len(raw))+bytes.fromhex(digest)+raw
                    self.stream.write(wire);self.offset+=len(wire);self.objects[digest]=dict(**row,offset=start)
                require(self.objects[digest]["bytes"]==len(raw),"whole content-addressed actual object size")
                refs.append(row)
            tid=threading.get_native_id();thread=self.threads.get(tid)
            row=dict(index=len(self.records),kind=kind,case=self.case,step=self.step,operation=self.operation,
                tid=tid,worker=thread,meta=meta,buffers=refs,offset=self.offset)
            raw=encoded(row);wire=b"NVREC001"+struct.pack("<Q",len(raw))+raw
            self.stream.write(wire);self.offset+=len(wire);self.records.append(row)
    def observe(self,user,record,size):
        if self.errors:return
        try:
            require(user in(None,0)and size==128,"actual optional copy-only observer")
            event=C.string_at(record,128);require(event[:8]==b"HNVOBS01","whole native event")
            stage=word(event,8);phase=word(event,16);inv=word(event,40);obj=word(event,48)
            require(1<=stage<=11 and phase in(0,1)and inv>0 and record==inv+256,"exact actual invocation record borrow")
            ranges=[(word(event,at),word(event,at+8))for at in(80,96,112)]
            require(all(p>0 and 0<n<=131072 for p,n in ranges),"whole bounded actual native borrows")
            snapshots=[C.string_at(p,n)for p,n in ranges]
            parent=C.string_at(inv,131072)
            require(parent[:8]==b"HNVCTX01"and word(parent,8)==obj and word(parent,16)==self.environment
                and parent[256:384]==event,"actual composed invocation custody")
            buffers=[event,*snapshots,parent,C.string_at(self.environment,4096)];descriptions=[dict(pointer=p,bytes=n)for p,n in ranges]
            children={}
            for (p,n),raw in zip(ranges,snapshots):
                if n==131072 and raw[:8]==b"HNWCTX01":children[p]=raw
            # The object kind, not the caller output capacity, selects its physical extent.
            header=C.string_at(obj,256);object_size=4096 if word(header,24)==3 else 256
            object_bytes=C.string_at(obj,object_size);buffers.append(object_bytes)
            actual_child=word(header,48)
            if actual_child and actual_child not in children:
                raw=C.string_at(actual_child,131072)
                if raw[:8]==b"HNWCTX01":children[actual_child]=raw
                else:require(raw==bytes(131072)and stage==8 and phase==1,"actual disposed child remains mapped until unmap")
            pins=set()
            for ptr,raw in children.items():
                require(word(raw,104)<=259,"whole actual native pin ledger")
                for i in range(word(raw,104)):pins.add(word(raw,512+16*i))
                shared=word(raw,32)
                if shared:pins.add(shared)
                buffers.append(raw)
            pages=[]
            for ptr in sorted(pins):
                require(ptr>0 and ptr%4096==0,"actual File reference page")
                page=C.string_at(ptr,4096)
                require(page[:8]==b"HNWFP001"and word(page,8)>0 and word(page,24)==4096,"whole live File reference")
                pages.append(page)
            self.record("observation",(*buffers,*pages),dict(event=event.hex(),ranges=descriptions,
                invocation=inv,object=obj,object_bytes=object_size,children=list(children),pins=sorted(pins),observed_ns=time.monotonic_ns()))
        except BaseException as error:
            self.errors.append(repr(error))
    def close(self,success):
        with self.guard:
            if success and not self.errors:
                self.stream.write(b"NVEND001"+struct.pack("<3Q",len(self.records),len(self.objects),self.logical_bytes))
            self.stream.close();self.raw.close()
            (self.output/"RECORDS.json").write_bytes(encoded(self.records))
            (self.output/"OBJECTS.json").write_bytes(encoded(self.objects))
            (self.output/"OBSERVER-ERRORS.json").write_bytes(encoded(self.errors))
