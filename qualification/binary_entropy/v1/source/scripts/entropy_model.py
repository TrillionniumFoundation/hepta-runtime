"""Independent CPython entropy control-flow reader; never executes a native image."""
import struct
from evidence_common import require
from protocol import MASK,project,signed,u
KINDS={"PermissionError":2,"FileNotFoundError":4,"NotADirectoryError":5,"IsADirectoryError":6,
    "FileExistsError":7,"InterruptedError":8,"BlockingIOError":9,"BrokenPipeError":10,
    "TimeoutError":11,"ConnectionResetError":12,"ConnectionAbortedError":13,"ConnectionRefusedError":14}
class Model:
    def __init__(self):
        self.available=True;self.cache=None;self.device=(0,0);self.random=bytearray(16)
        self.reply=bytearray(144);self.orphans=[];self.generation=0;self.previous=bytes(4096)
    def start(self,mode):
        self.generation+=1;self.mode=mode;self.sequence=0;self.last_sequence=0;self.raw_return=0
        self.payload_size=0;self.cursor=0;self.candidate=None;self.error=None;self.pending=None
        self.generator=self.flow();self.advance()
    def advance(self,value=None):
        try:self.pending=next(self.generator)if value is None else self.generator.send(value)
        except StopIteration:self.pending=None;self.phase=99
    def resume(self,raw):
        require(raw[:8]==b"HENTQ001"and len(raw)>=96 and u(raw,8)==2 and u(raw,16)==self.sequence
            and raw[32:88]==bytes(56)and u(raw,88)==len(raw)-96,"complete exact actual resume")
        value=signed(u(raw,24));payload=raw[96:]
        require(len(payload)<=144 and(value>=0 or not payload),"bounded real syscall response")
        self.last_sequence=self.sequence;self.raw_return=u(raw,24);self.payload_size=len(payload)
        self.reply[:len(payload)]=payload
        self.advance((value,payload))
    def exchange(self,phase,op,a=0,b=0):
        self.phase=phase;self.sequence+=1
        value,payload=yield(op,a,b)
        return value,payload
    def os_error(self,number,named=False):
        require(1<=number<=4095,"real negative OS error")
        name=type(OSError(number,"")).__name__
        self.error=dict(klass=KINDS.get(name,3),number=number,named=named,literal=b"",code=0)
    def literal_error(self,code):
        text=b"/dev/urandom (or equivalent) not found"if code==1 else(
            "Failed to read "+str(16-self.cursor)+" bytes from /dev/urandom").encode()
        self.error=dict(klass=16 if code==1 else 17,number=0,named=False,literal=text,code=code)
    def consume(self,value,payload):
        require(0<=value<=16-self.cursor and len(payload)==value,"complete requested random bytes")
        self.random[self.cursor:self.cursor+value]=payload;self.cursor+=value
    def flow(self):
        if self.available:
            while self.cursor<16:
                value,payload=yield from self.exchange(3,1,16-self.cursor)
                if value==-4:continue
                if value in(-1,-38):
                    self.available=False;self.cursor=0;break
                if value<0:self.os_error(-value);return
                self.consume(value,payload)
            if self.available:return
        if self.cache is not None:
            value,payload=yield from self.exchange(11,3,self.cache)
            require(value<0 or(value==0 and len(payload)==144),"cached stat response")
            if value<0 or struct.unpack_from("<QQ",payload)!=self.device:
                value,payload=yield from self.exchange(13,6,self.cache)
                require(value==0 and not payload,"successful process orphan transfer")
                self.orphans.append((self.cache,self.generation));self.cache=None;self.device=(0,0)
        if self.cache is None:
            while True:
                value,payload=yield from self.exchange(21,2)
                require(not payload,"open has no byte payload")
                if value==-4:continue
                break
            if value<0:
                if -value in(2,6,19,13):self.literal_error(1)
                else:self.os_error(-value,True)
                return
            require(value<=2147483647,"opened descriptor width");self.candidate=value
            value,payload=yield from self.exchange(23,3,self.candidate)
            if value<0:
                self.os_error(-value)
                closed,body=yield from self.exchange(25,4,self.candidate)
                require(closed<=0 and not body,"single candidate close preserves first stat failure")
                self.candidate=None;return
            require(value==0 and len(payload)==144,"complete initial device stat")
            self.cache=self.candidate;self.candidate=None;self.device=struct.unpack_from("<QQ",payload)
        while self.cursor<16:
            value,payload=yield from self.exchange(31,5,self.cache,16-self.cursor)
            if value==-4:continue
            if value<0:self.os_error(-value);return
            if value==0:
                require(not payload,"actual device EOF has no payload");self.literal_error(2);return
            self.consume(value,payload)
    def workspace(self):
        raw=bytearray(4096);raw[:8]=b"HENTW001"
        error=self.error or dict(klass=0,number=0,named=False,code=0)
        fields={8:self.phase,16:self.sequence,24:self.sequence if self.pending is not None else 0,
            32:self.last_sequence,40:self.raw_return,48:self.payload_size,56:self.mode,
            64:int(self.available),72:MASK if self.cache is None else self.cache,
            80:self.device[0],88:self.device[1],96:MASK if self.candidate is None else self.candidate,
            104:MASK,112:self.cursor,120:0,128:error["klass"],136:error["number"],
            144:int(error["named"]),152:error["code"]}
        for at,value in fields.items():struct.pack_into("<Q",raw,at,value)
        raw[256:272]=self.random;raw[512:656]=self.reply
        return bytes(raw)
    def response(self):
        if self.pending is not None:
            op,a,b=self.pending
            return b"HENTR001"+struct.pack("<7Q",1,self.sequence,op,a,b,0,0)
        if self.error is None:
            require(self.cursor==16,"completed kernel entropy length")
            payload=project(bytes(self.random),self.mode);kind=0
        else:
            e=self.error;name=b"/dev/urandom"if e["named"]else b""
            payload=b"HBRDS001"+struct.pack("<7Q",3,self.sequence,e["klass"],e["number"],
                len(e["literal"]),int(e["named"]),len(e["literal"])+len(name))+e["literal"]+name;kind=3
        return b"HENTR001"+struct.pack("<7Q",kind,self.sequence,0,0,0,0,len(payload))+payload
