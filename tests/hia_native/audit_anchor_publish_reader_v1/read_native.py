"""Read complete native input/output/workspace observations without executing either owner."""
from pathlib import Path
import gzip
import struct
from common import loads,pin,read,require
from protocol import (INVALID,CAPACITY,cases,initial,response,semantic,word,put,acknowledgement)

class Calls:
    def __init__(self,folder):
        self.rows=loads(read(folder/'INVOCATIONS.json'))
        self.index=0;self.logical_bytes=0
        self.raw=(folder/'buffers.bin.gz').open('rb')
        self.file=gzip.GzipFile(fileobj=self.raw,mode='rb')
        require(self.file.read(8)==b'AIOLOG01','complete physical journal header')
    def exact(self,n):
        raw=self.file.read(n);require(len(raw)==n,'complete physical buffer extent')
        self.logical_bytes+=n;return raw
    def call(self,module,wire,out_size,work,case,step,probe=None):
        require(self.index<len(self.rows),'every actual call present')
        require(self.exact(8)==b'AIOCAL01','actual invocation marker')
        fields=struct.unpack('<9Q',self.exact(72))
        index,ci,si,mod,result,ni,no,nw,isp=fields
        require((index,ci,si,mod,ni,no,nw,isp)==
                (self.index,case,step,module,len(wire),out_size,len(work),int(probe is not None)),
                'exact source-owned ordered call identity')
        before=[self.exact(n+16) for n in (ni,no,nw)]
        after=[self.exact(n+16) for n in (ni,no,nw)]
        require(before==[wire+b'\xc3'*16,b'\xa5'*(no+16),work+b'\x5a'*16],
                'actual complete native input and buffer preimages')
        require(after[0]==before[0] and after[1][no:]==b'\xa5'*16 and after[2][nw:]==b'\x5a'*16,
                'every actual input byte and both borrowed guards')
        row=self.rows[index]
        require(row==dict(index=index,case=case,step=step,module=module,result=result,probe=probe,
            input_bytes=ni,output_capacity=no,workspace_capacity=nw,elapsed_ns=row['elapsed_ns'],
            before=[pin(v) for v in before],after=[pin(v) for v in after])
            and type(row['elapsed_ns']) is int and row['elapsed_ns']>=0,
            'every full buffer pin and call receipt')
        if probe is not None:
            require(result==probe['expected'] and after[1:]==before[1:],
                    'actual full-buffer rejection atomicity')
        elif result in (INVALID,CAPACITY):
            require(module==1 and result==INVALID and after[1]==before[1],
                    'only actual typed JSON rejection may return INVALID')
        else:
            require(result<=no and after[1][result:no]==b'\xa5'*(no-result),
                    'complete produced output and untouched unused tail')
        self.index+=1
        return result,after[1][:no],after[2][:nw],index
    def probes(self,rows,workspace,case,step,prefix):
        for name,wire,out_size,work_size,writes,expected in rows:
            work=bytearray((workspace+b'\x79'*max(0,work_size-len(workspace)))[:work_size])
            for at,value in writes:put(work,at,value)
            self.call(0,wire,out_size,bytes(work),case,step,
                dict(name=prefix+'/'+name,expected=expected,writes=[list(x) for x in writes]))
    def finish(self):
        require(self.exact(8)==b'AIOEND01' and struct.unpack('<Q',self.exact(8))[0]==self.index
                and self.index==len(self.rows) and not self.file.read(1),'all native calls and closed gzip/footer')
        self.close()
        return dict(calls=self.index,logical_buffer_bytes=self.logical_bytes)
    def close(self):
        try:self.file.close()
        finally:self.raw.close()

def filesystem_reply(state,row,capabilities):
    require("kind" not in row and row["generation"]==state["generation"] and row["sequence"]==state["sequence"] and
            row["operation"]==state["operation"] and row["arguments"]==list(state["arguments"]) and
            row["payloads"]==[p.hex() for p in state["payloads"]] and row["capabilities_before"]==capabilities,
            "complete actual publisher effect")
    actual=row["observed"];ret=actual["actual_return"];err=actual["actual_errno"]
    require(type(ret) is int and type(err) is int and 0<=err<=4095,"exact actual syscall result")
    op=state["operation"];a,b,c=state["arguments"];after=dict(capabilities);status=0;value=0;payload=b""
    if ret<0:
        require(ret==-1 and err>0,"actual OS error");status=1
    elif op in (1,18):
        value=word(bytes.fromhex(row["acknowledgement_hex"]),56)
        require(value>1 and str(value) not in after,"fresh unique owned descriptor capability");after[str(value)]="file"
    elif op in (4,17):
        payload=bytes.fromhex(row["acknowledgement_hex"])[128:];value=ret
        require(ret==len(payload)<=(a if op==17 else b),"whole actual entropy bytes")
    elif op==5:require(ret<=b,"actual partial/full write");value=ret
    elif op==19:
        require(ret==1,"actual infinite one-FD poll completion");value=ret
    else:require(op in (6,7,8,9) and ret==0,"actual durable filesystem completion")
    if op==7:require(a!=1 and after.pop(str(a),None)=="file","actual owned close consumes capability")
    if status==0 and op!=7:err=0
    ack=acknowledgement(state,status=status,errno=err,value=value,payload=payload)
    require(ack.hex()==row["acknowledgement_hex"] and after==row["capabilities_after"],"whole native ACK and capability conservation")
    return ack,after
