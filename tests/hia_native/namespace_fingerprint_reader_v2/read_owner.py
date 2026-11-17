"""Independent byte model of the retained fingerprint state and standard SHA-256.

No HIA or Rust is loaded or executed. This verifies every captured workspace byte.
"""
import hashlib,struct
from common import require
from callable_contract import word,response
MASK=(1<<64)-1
K=(
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2)
IV=(0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)
def put(b,at,value):struct.pack_into("<Q",b,at,value)
def ror(value,n):return ((value>>n)|(value<<(32-n)))&0xffffffff
class Model:
    def __init__(self):
        self.work=bytearray(16384);self.material=bytearray();self.entries=[];self.padding=set()
    def sha_init(self):
        w=self.work
        for i,k in enumerate(K):put(w,8*i,k)
        for i,k in enumerate(IV):put(w,1024+8*i,k)
        put(w,1088,0);put(w,1096,0);put(w,1104,1)
        w[1112:1176]=bytes(64);put(w,1176,3554263975777875528)
        self.material.clear();self.entries.clear()
    def compress(self):
        w=self.work;words=list(struct.unpack(">16I",w[1112:1176]))
        for i in range(16,64):
            x,y=words[i-15],words[i-2]
            words.append((words[i-16]+(ror(x,7)^ror(x,18)^(x>>3))+words[i-7]+
                          (ror(y,17)^ror(y,19)^(y>>10)))&0xffffffff)
        for i,v in enumerate(words):put(w,512+8*i,v)
        original=[word(w,1024+8*i)for i in range(8)];a,b,c,d,e,f,g,h=original
        for k,x in zip(K,words):
            t1=(h+(ror(e,6)^ror(e,11)^ror(e,25))+((e&f)^((0xffffffff^e)&g))+k+x)&0xffffffff
            t2=((ror(a,2)^ror(a,13)^ror(a,22))+((a&b)^(a&c)^(b&c)))&0xffffffff
            a,b,c,d,e,f,g,h=(t1+t2)&0xffffffff,a,b,c,(d+t1)&0xffffffff,e,f,g
        for i,v in enumerate((a,b,c,d,e,f,g,h)):put(w,1024+8*i,(original[i]+v)&0xffffffff)
    def update(self,raw):
        w=self.work;used=word(w,1096);self.material.extend(raw)
        for value in raw:
            w[1112+used]=value;used+=1
            if used==64:self.compress();used=0
        put(w,1096,used);put(w,1088,(word(w,1088)+len(raw))&MASK)
    def finish_hash(self):
        w=self.work;used=word(w,1096);w[1112+used]=128;used+=1
        while used!=56:
            if used==64:self.compress();used=0
            else:w[1112+used]=0;used+=1
        w[1168:1176]=((word(w,1088)<<3)&MASK).to_bytes(8,"big");self.compress()
        digest=b"".join(word(w,1024+8*i).to_bytes(4,"big")for i in range(8))
        require(digest==hashlib.sha256(self.material).digest(),"independent standard SHA-256 and captured input material")
        w[2304:2336]=digest
    def issue(self,op,a,b):
        w=self.work;put(w,2080,word(w,2080)+1);put(w,2088,op);put(w,2112,op)
        out=bytearray(128);out[:8]=b"HNFRS001"
        for at,v in((8,2),(16,word(w,2080)),(24,word(w,2064)),(32,op),(40,a),(48,b)):put(out,at,v)
        return bytes(out)
    def complete(self):
        w=self.work;put(w,2056,2);put(w,2088,0);put(w,2112,0)
        out=bytearray(128);out[:8]=b"HNFRS001"
        for at,v in((8,word(w,2160)),(16,word(w,2080)),(24,word(w,2064)),(32,1)):put(out,at,v)
        if word(w,2160):put(out,80,1);put(out,88,word(w,2120))
        else:out[96:128]=w[2304:2336]
        return bytes(out)
    def call(self,wire):
        w=self.work
        if wire[:8]==b"HNFRQ001":
            require(len(wire)==64 and word(wire,8)==1 and word(wire,24)==1 and
                    wire[32:]==bytes(32) and word(wire,16)>word(w,2064),"complete monotonic initial request")
            w[2048:2304]=bytes(256);w[2048:2056]=b"HNFWK001"
            put(w,2056,1);put(w,2064,word(wire,16));put(w,2072,1)
            return self.issue(1,1,589824)
        require(wire[:8]==b"HNFACK01" and 96<=len(wire)<=4192 and word(wire,64)==len(wire)and
                word(wire,56)==len(wire)-96 and wire[72:96]==bytes(24),"complete actual acknowledgement")
        phase=word(w,2088)
        require((word(wire,8),word(wire,16),word(wire,24))==(word(w,2064),word(w,2080),phase)and
                word(w,2056)==1 and word(w,2112)==phase,"same actual HIA pending effect")
        status,error,value,size=[word(wire,x)for x in(32,40,48,56)]
        require(status in(0,1,2)and error<=4095,"actual effect reply status/errno")
        for at,v in((2128,status),(2136,error),(2144,value),(2152,size),(2112,0)):put(w,at,v)
        w[8192:8192+size]=wire[96:]
        self.padding.difference_update(range(8192,8192+size))
        if size:
            end=wire.find(b"\0",115)
            require(end>=115,"complete native name before retained dirent padding")
            self.padding.update(range(8192+end-96+1,8192+size))
        if phase==1:
            if status==1:put(w,2120,error);put(w,2160,1);return self.complete()
            require((status,error,value,size)==(0,0,2,0),"actual open capability")
            put(w,2096,2);return self.issue(2,2,0)
        if phase==2:
            if status==1:return self.issue(4,2,0)
            require((status,error,value,size)==(0,0,3,0),"actual DIR capability")
            put(w,2104,3);put(w,2096,0);self.sha_init();return self.issue(3,3,0)
        if phase==3:
            if status==1:
                put(w,2120,error);put(w,2160,1);return self.issue(5,3,0)
            if status==2:
                require(error==value==size==0,"actual readdir EOF")
                self.finish_hash();put(w,2168,1);return self.issue(5,3,0)
            require(status==error==0 and value==size and 20<=size<=4096 and
                    int.from_bytes(wire[112:114],"little")==size,"full actual native dirent")
            raw=wire[96:];end=raw.find(b"\0",19)
            require(end>=19,"actual complete dirent name");name=raw[19:end]
            self.entries.append(dict(name=name,inode=word(raw,0),dtype=raw[18],raw=raw))
            if name not in(b".",b".."):
                put(w,12288,len(name))
                for piece in(len(name).to_bytes(8,"little"),name,raw[:8],raw[18:19]):self.update(piece)
            return self.issue(3,3,0)
        if phase==4:
            require(status in(0,1)and value==size==0,"actual owned close reply")
            put(w,2096,0);put(w,2120,error);put(w,2160,1);return self.complete()
        require(phase==5 and status in(0,1)and value==size==0,"actual owned closedir reply")
        put(w,2104,0);return self.complete()
