"""Append complete public-call buffers, including unchanged guards and actual table."""
from contextlib import ExitStack
import gzip,struct
from common import encoded,pin,require
from callable_contract import CONTEXT_BYTES
HEADER=struct.Struct("<12Q")
class Outer:
    def __init__(self,output):
        self.rows=[];self.closed=False;resources=ExitStack()
        try:
            self.raw=resources.enter_context((output/"outer.bin.gz").open("xb"))
            self.stream=resources.enter_context(gzip.GzipFile(filename="",mode="wb",compresslevel=1,fileobj=self.raw,mtime=0))
            self.index=resources.enter_context((output/"OUTER.json").open("xb"))
            self.stream.write(b"NFTOP001")
        except BaseException:resources.close();raise
        self.resources=resources.pop_all()
    def record(self,case,step,kind,returned,before,after,elapsed,args):
        require(len(before)==len(after)==4 and all(len(x)==len(y)for x,y in zip(before,after)),
                "entire actual outer buffers")
        guards=(16,16,16)if kind==1 else(0,0,16)
        ni=len(before[0])-guards[0];no=len(before[1])-guards[1]
        require(len(before[2])==CONTEXT_BYTES+16 and len(before[3])==56,"whole context and fixed actual table")
        index=len(self.rows);fields=(index,case,step,kind,returned,ni,no,CONTEXT_BYTES,56,*guards)
        self.stream.write(b"NFTOPCAL"+HEADER.pack(*fields))
        for raw in before+after:self.stream.write(raw)
        self.rows.append(dict(index=index,case=case,step=step,kind=kind,returned=returned,input_bytes=ni,
            output_capacity=no,context_capacity=CONTEXT_BYTES,table_bytes=56,guards=list(guards),
            elapsed_ns=elapsed,args=args,before=[pin(x)for x in before],after=[pin(x)for x in after]))
    def close(self,success):
        if self.closed:return
        self.closed=True
        try:
            if success:self.stream.write(b"NFTOPEND"+struct.pack("<Q",len(self.rows)))
            self.index.write(encoded(self.rows))
        finally:self.resources.close()
