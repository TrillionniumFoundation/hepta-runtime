"""Read every physical HIA/libc/outer buffer with exact framing, guards and receipts."""
import gzip,io,struct
from common import encoded,loads,pin,read,require
def equal(a,b,message):require(encoded(a)==encoded(b),message)
class Stream:
    def __init__(self,path,index,magic):
        self.rows=loads(read(index));require(type(self.rows)is list,"complete record receipt array")
        self.position=0;self.logical_bytes=0;self.file=gzip.GzipFile(fileobj=io.BytesIO(read(path)),mode="rb")
        require(self.exact(8)==magic,"whole journal magic")
    def exact(self,n):
        require(type(n)is int and n>=0,"bounded exact physical read")
        body=self.file.read(n);require(len(body)==n,"whole physical frame, not a prefix")
        self.logical_bytes+=len(body);return body
    def end(self,magic):
        require(self.position==len(self.rows)and self.exact(8)==magic and
                struct.unpack("<Q",self.exact(8))[0]==self.position and self.file.read()==b"",
                "entire unique record set, footer, gzip CRC and absence of suffix")
        self.file.close();return self.logical_bytes
class Records(Stream):
    def __init__(self,folder):super().__init__(folder/"records.bin.gz",folder/"RECORDS.json",b"NFRCLOG1")
    def next(self,case,step,binding,generation):
        require(self.position<len(self.rows)and self.exact(8)==b"NFRCAL01","next actual borrowed native record")
        h=struct.unpack("<12Q",self.exact(96));index,ci,si,kind,ni,no,nw,gi,go,gw,elapsed,reserved=h
        require((index,ci,si,reserved)==(self.position,case,step,0)and kind in(1,2),"exact ordered native record")
        if kind==1:require((no,nw,gi,go,gw)==(128,16384,16,16,16)and(ni==64 or 96<=ni<=4192),"complete HIA regions")
        else:require((ni,no,nw,gi,go,gw)==(128,4192,256,0,0,0),"complete actual libc regions")
        before_record=self.exact(128);after_record=self.exact(128)
        before=[self.exact(n+g)for n,g in zip((ni,no,nw),(gi,go,gw))]
        after=[self.exact(n+g)for n,g in zip((ni,no,nw),(gi,go,gw))]
        old=struct.unpack("<16Q",before_record);new=struct.unpack("<16Q",after_record)
        base=binding["context"]
        require(old[0]==new[0]==kind and old[1]==0 and new[1]==1 and old[2]==0 and old[3:12]==new[3:12]and
                old[9]==base and old[11]==generation and old[12:]==(0,0,0,0)and new[14:]==(0,0),
                "complete actual observation records and control identity")
        expected=(base+256,ni,base+4608,128,base+8192,16384)if kind==1 else(base+4608,128,base+256,4192,base,256)
        require(old[3:9]==expected and before[0]==after[0],"exact real borrowed addresses and unchanged input")
        if kind==1:
            require(new[2]==128 and new[12:]==(0,0,0,0)and before[1]==b"\xa5"*144 and
                    before[0][ni:]==after[0][ni:]==b"\xc3"*16 and
                    before[2][nw:]==after[2][nw:]==b"\x5a"*16 and after[1][no:]==b"\xa5"*16,
                    "full successful HIA return, initialized output and all guards")
        else:require(new[2]==new[12]and new[13]<=4095,"actual returned register and errno")
        wanted=dict(index=index,case=case,step=step,kind=kind,input_bytes=ni,output_capacity=no,workspace_capacity=nw,
            guards=[gi,go,gw],elapsed_ns=elapsed,before_record=pin(before_record),after_record=pin(after_record),
            before=[pin(r)for r in before],after=[pin(r)for r in after])
        equal(self.rows[index],wanted,"whole immutable physical borrow receipt")
        self.position+=1
        return dict(index=index,kind=kind,ni=ni,no=no,nw=nw,before=before,after=after,
            before_record=before_record,after_record=after_record,old=old,new=new)
    def finish(self):return self.end(b"NFRCEND1")
class Outer(Stream):
    def __init__(self,folder):super().__init__(folder/"outer.bin.gz",folder/"OUTER.json",b"NFTOP001")
    def next(self,case,step,kind,args,table):
        require(self.position<len(self.rows)and self.exact(8)==b"NFTOPCAL","all actual outer calls")
        h=struct.unpack("<12Q",self.exact(96));index,ci,si,k,returned,ni,no,nw,nt,gi,go,gw=h
        wanted=(index,case,step,kind,128 if kind==1 else 0,64 if kind==1 else 0,128 if kind==1 else 0,32768,56,
                16 if kind==1 else 0,16 if kind==1 else 0,16)
        require(h==wanted and index==self.position,"exact outer ABI, capacities, ordered case and return")
        before=[self.exact(n+g)for n,g in zip((ni,no,nw,nt),(gi,go,gw,0))]
        after=[self.exact(n+g)for n,g in zip((ni,no,nw,nt),(gi,go,gw,0))]
        require(before[3]==after[3]==table and before[2][-16:]==after[2][-16:]==b"\x5a"*16,"full actual libc table and outer guards")
        if kind==1:
            require(before[0]==after[0]and before[0][64:]==b"\xc3"*16 and before[1]==b"\xa5"*144 and
                    after[1][128:]==b"\xa5"*16,"complete native initial input and output guards")
        row=self.rows[index]
        require(type(row.get("elapsed_ns"))is int and row["elapsed_ns"]>=0,"exact observed elapsed value")
        expected=dict(index=index,case=case,step=step,kind=kind,returned=returned,input_bytes=ni,output_capacity=no,
            context_capacity=nw,table_bytes=nt,guards=[gi,go,gw],elapsed_ns=row["elapsed_ns"],args=args,
            before=[pin(x)for x in before],after=[pin(x)for x in after])
        equal(row,expected,"whole physical outer invocation receipt")
        self.position+=1;return before,after
    def finish(self):return self.end(b"NFTOPEND")
