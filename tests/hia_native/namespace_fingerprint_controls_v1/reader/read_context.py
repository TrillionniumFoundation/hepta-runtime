"""Inert full-byte model of native transport writes and actual libc ownership."""
import struct
from common import require
from callable_contract import word,response,initial
from read_owner import Model,put,MASK
def signed(value):return value if value<1<<63 else value-(1<<64)
class Context:
    def __init__(self,binding,table,maps):
        self.binding=binding;self.base=binding["context"];self.maps=maps;self.data=bytearray(32768);self.padding=set()
        self.data[:8]=b"HNFCTX01";self.data[64:112]=table[:48]
        for at,value in((24,binding["root_fd"]),(32,binding["observer"]),(112,MASK)):put(self.data,at,value)
        self.model=Model();self.acks=[];self.effects=[];self.first_boundary=False
    def raw(self):return bytes(self.data)+b"\x5a"*16
    def write(self,at,raw):
        require(0<=at<=32768 and len(raw)<=32768-at,"whole modeled native write")
        self.data[at:at+len(raw)]=raw;self.padding.difference_update(range(at,at+len(raw)))
    def span(self,at,size):return bytes(self.data[at:at+size])
    def observation(self,kind,phase=0,returned=0,actual=0,error=0):
        if kind==1:fields=(self.base+256,word(self.data,144),self.base+4608,128,self.base+8192,16384)
        else:fields=(self.base+4608,128,self.base+256,4192,self.base,256)
        raw=struct.pack("<16Q",kind,phase,returned,*fields,self.base,word(self.data,128),word(self.data,16),actual,error,0,0)
        self.write(4864,raw);return raw
    def begin(self,wire):
        require(wire==initial(word(wire,16))and word(wire,16)>word(self.data,16),"whole native initial request")
        put(self.data,16,word(wire,16));put(self.data,8,1);put(self.data,128,0);put(self.data,144,64)
        self.write(256,wire);self.first_boundary=True;self.acks=[];self.effects=[]
        self.model.entries=[];self.model.material.clear()
    def owner(self,records,case,step):
        size=word(self.data,144);wire=self.span(256,size)
        self.write(256+size,b"\xc3"*16);self.write(4608,b"\xa5"*144);self.write(8192+16384,b"\x5a"*16)
        before_record=self.observation(1);row=records.next(case,step,self.binding,word(self.data,16))
        require(row["kind"]==1 and row["before_record"]==before_record and
                row["before"]==[self.span(256,size+16),self.span(4608,144),self.span(8192,16400)],
                "complete actual HIA input/output/workspace preimages and native before record")
        require(self.span(8192,16384)==bytes(self.model.work),"independent owner workspace continuity")
        output=self.model.call(wire)
        require(row["after"]==[row["before"][0],output+b"\xa5"*16,bytes(self.model.work)+b"\x5a"*16],
                "all HIA output and workspace bytes equal independent state/hash model")
        self.write(4608,row["after"][1]);self.write(8192,row["after"][2])
        self.padding.update(8192+x for x in self.model.padding)
        put(self.data,152,128);put(self.data,56,word(self.data,56)+1)
        after_record=self.observation(1,1,128)
        require(row["after_record"]==after_record,"whole HIA completion record")
        state=response(output)
        require(state["generation"]==word(self.data,16),"same complete generation")
        if state["kind"]<2:
            require(state["sequence"]==word(self.data,128)and word(self.data,112)==MASK and
                    word(self.data,120)==0,"terminal after all actual owned resources consumed")
            return output
        require(state["sequence"]==word(self.data,128)+1,"every actual effect dispatched exactly once")
        put(self.data,128,state["sequence"]);op=state["operation"]
        if op==1:require((state["a"],state["b"],word(self.data,112),word(self.data,120))==(1,589824,MASK,0),"fixed real open")
        elif op in(2,4):require(state["a"]==2 and state["b"]==0 and word(self.data,112)==80 and word(self.data,120)==0,"owned stream FD")
        else:require(state["a"]==3 and state["b"]==0 and word(self.data,112)==MASK and word(self.data,120)>4096,"owned DIR handle")
        self.write(256,bytes(96));self.write(256,b"HNFACK01")
        for at,value in((264,word(self.data,16)),(272,word(self.data,128)),(280,op),(320,96),(144,96),(168,0),(176,0)):put(self.data,at,value)
        self.effects.append(dict(operation=op,sequence=state["sequence"],request=output))
        return None
    def boundary(self,records,case,step):
        row=records.next(case,step,self.binding,word(self.data,16));require(row["kind"]==2,"one actual libc call for each HIA effect")
        if self.first_boundary:
            tls,ambient=word(row["before"][2],48),word(row["before"][2],136)
            require(tls%4==0 and any(m["lo"]<=tls<=m["hi"]-4 and m["permissions"][1]=="w"for m in self.maps)
                    and 0<=ambient<(1<<32),"actual errno TLS lies in writable process storage")
            put(self.data,48,tls);put(self.data,136,ambient);self.first_boundary=False
        before_record=self.observation(2)
        require(row["before_record"]==before_record and
                row["before"]==[self.span(4608,128),self.span(256,4192),self.span(0,256)],
                "every actual libc preimage, complete retained ACK tail and native context header")
        op=word(self.data,280);ret=signed(row["new"][12]);err=row["new"][13]
        require(type(err)is int and 0<=err<=4095,"immediate real libc errno")
        for at,value in((168,ret&MASK),(176,err),(136,err)):put(self.data,at,value)
        status=0;value=0;payload=b""
        if op==1:
            require(ret in(-1,80),"actual open uses the vacant owned descriptor slot")
            if ret==-1:status=1
            else:put(self.data,112,ret);value=2
        elif op==2:
            require(ret==0 or ret>4096,"actual fdopendir pointer")
            if ret==0:status=1
            else:put(self.data,120,ret);put(self.data,112,MASK);value=3
        elif op==3:
            require(ret==0 or ret>4096,"actual readdir pointer")
            if ret==0:status=1 if err else 2
            else:
                size=word(row["after"][1],56)
                require(20<=size<=4096,"complete actual d_reclen extent")
                payload=row["after"][1][96:96+size]
                require(int.from_bytes(payload[16:18],"little")==size and payload.find(b"\0",19)>=19,
                        "actual directory entry bytes and complete raw name")
                value=size
        else:
            require(op in(4,5)and ret in(-1,0),"actual owned cleanup return")
            if op==4:put(self.data,112,MASK)
            else:put(self.data,120,0)
            if ret==-1:status=1
            put(self.data,296,err)
        if status==1:
            require(err>0,"nonzero actual failing errno");put(self.data,296,err)
        put(self.data,288,status);put(self.data,304,value)
        if payload:
            put(self.data,312,len(payload));put(self.data,320,96+len(payload))
            put(self.data,144,96+len(payload));self.write(352,payload)
            self.padding.update(range(352+payload.find(b"\0",19)+1,352+len(payload)))
        put(self.data,184,word(self.data,184)+1)
        after_record=self.observation(2,1,ret&MASK,ret&MASK,err)
        require(row["after_record"]==after_record and row["after"]==
                [self.span(4608,128),self.span(256,4192),self.span(0,256)],
                "complete actual libc return, ACK, stale tail, errno and resource transition")
        ack=self.span(256,word(self.data,144));self.acks.append(ack)
        self.effects[-1].update(actual_return=ret,actual_errno=err,ack=ack)
    def complete(self):
        out=self.span(4608,128)
        for at in(8,48,136):put(self.data,at,0)
        return out
