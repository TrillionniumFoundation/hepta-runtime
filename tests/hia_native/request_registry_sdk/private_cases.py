"""Deterministic complete private ABI corpus and actual-buffer capture.

The semantic/private function bodies are unchanged from the qualified development
corpus. Native execution supplies ctypes and NativeModule; the pure reader uses
only bytearray replay of retained calls, never a machine loader.
"""
from pathlib import Path
import collections,ctypes,gzip,hashlib,itertools,json,os,random,struct,time
INVALID,CAPACITY,STATE,RESOURCE=0xffffffff,0xfffffffe,0xfffffff9,0xfffffffc
MAX=(1<<64)-1
def sha(raw):return hashlib.sha256(raw).hexdigest()
def wire(op,generation=0,kind=0,key=b'',reason=0):
    return struct.pack('<8s7Q',b'HRQREG01',op,generation,kind,len(key),reason,0,0)+key
def response(op,generation=0,related=0,decision=0,live=0,mapped=0,status=0):
    return struct.pack('<8s7Q',b'HRQRR001',op,status,generation,related,decision,live,mapped)
class Rejected(Exception):
    def __init__(self,code):self.code=code
class Model:
    def __init__(self):
        self.active=False;self.next=1;self.records={};self.mapping={};self.parent=False;self.drain=0
    def result(self,op,generation=0,related=0,decision=0):
        return response(op,generation,related,decision,len(self.records),len(self.mapping))
    def flags(self,g):
        r=self.records[g]
        return int(r['cancelled'])+2*int(r['completed'])+4*int(self.mapping.get(r['id'])==g)
    def step(self,op,g=0,kind=0,key=b'',reason=0):
        if op==0:
            if self.active:raise Rejected(STATE)
            self.active=True;return self.result(op)
        if not self.active:raise Rejected(STATE)
        if op in (1,2)and self.drain:raise Rejected(STATE)
        if op==1:
            if self.next==0:raise Rejected(RESOURCE)
            new=self.next;self.next=0 if new==MAX else new+1
            ident=(kind,key);previous=self.mapping.get(ident,0)
            self.records[new]={'id':ident,'cancelled':self.parent,'completed':False};self.mapping[ident]=new
            return self.result(op,new,previous,4+int(self.parent))
        if op==2:
            affected=self.mapping.pop((kind,key),0)
            if affected:self.records[affected]['cancelled']=True
            return self.result(op,related=affected,decision=int(bool(affected)))
        if op==6:
            changed=not self.parent;self.parent=True
            for record in self.records.values():record['cancelled']=True
            return self.result(op,decision=int(changed))
        if op==7:
            if self.drain or(reason==2 and not self.parent):raise Rejected(STATE)
            self.drain=reason;return self.result(op,decision=5000 if reason==1 else 2000)
        if g not in self.records:raise Rejected(STATE)
        if op==5:return self.result(op,g,decision=self.flags(g)+8*int(self.parent)+16*int(bool(self.drain)))
        if op==4:
            if not self.records[g]['completed']:raise Rejected(STATE)
            del self.records[g];return self.result(op,g)
        if self.records[g]['completed']:raise Rejected(STATE)
        affected=self.mapping.pop(self.records[g]['id'],0)
        if affected:self.records[affected]['cancelled']=True
        self.records[g]['completed']=True
        return self.result(op,g,affected,int(bool(affected)))
class Capture:
    def __init__(self,path):
        self.path=path;path.mkdir();(path/'blobs').mkdir();self.rows=gzip.open(path/'calls.jsonl.gz','xb',compresslevel=1)
        self.seen=set();self.count=0;self.sessions=0;self.domains=collections.Counter();self.growth=0;self.errors=collections.Counter()
    def content(self,raw):
        chunks=[]
        for at in range(0,len(raw),4096):
            piece=raw[at:at+4096];digest=sha(piece);chunks.append(digest)
            if digest not in self.seen:
                with (self.path/'blobs'/digest).open('xb')as out:out.write(piece)
                self.seen.add(digest)
        return {'bytes':len(raw),'sha256':sha(raw),'chunks':chunks}
    def row(self,session,domain,raw,expected_code,expected,out_before,work_before,actual,out_after,work_after,start,end):
        self.count+=1;self.domains[domain]+=1
        if actual>=0xffff0000:self.errors[str(actual)]+=1
        value={'ordinal':self.count,'session':session,'domain':domain,'pid':os.getpid(),'started_monotonic_ns':start,'finished_monotonic_ns':end,
            'actual_code':actual,'expected_code':expected_code,'request':self.content(raw),'expected':self.content(expected),
            'output_before':self.content(out_before),'output_after':self.content(out_after),
            'workspace_before':self.content(work_before),'workspace_after':self.content(work_after)}
        self.rows.write((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode())
    def close(self):self.rows.close()
class Session:
    def __init__(self,module,capture,domain,capacity=64):
        capture.sessions+=1;self.sid=capture.sessions;self.module=module;self.capture=capture;self.domain=domain;self.model=Model()
        self.native=module.session(output_capacity=96,workspace_capacity=capacity)
        ctypes.memset(self.native._output,0xa7,96);self.call(0)
    def buffers(self):
        return ctypes.string_at(self.native._output,self.native.output_capacity),ctypes.string_at(self.native._workspace,self.native.workspace_capacity)
    def call(self,op,g=0,kind=0,key=b'',reason=0):
        raw=wire(op,g,kind,key,reason)
        while True:
            before,old=self.buffers();start=time.monotonic_ns()
            code,output,state=self.native.invoke_raw(raw);end=time.monotonic_ns()
            if code==64 and struct.unpack_from('<Q',output,16)[0]==2:
                needed=64 if op==0 else struct.unpack_from('<Q',old,16)[0]+((48+len(key)+7)&~7)
                assert op in (0,1)and needed>len(old)and state==old
                expected=response(op,status=2,related=needed,live=len(self.model.records),mapped=len(self.model.mapping))
                assert output[:64]==expected and output[64:]==before[64:]
                self.capture.row(self.sid,self.domain+'/growth',raw,64,expected,before,old,code,output,state,start,end);self.capture.growth+=1
                replacement=self.module.session(output_capacity=96,workspace_capacity=max(needed,len(old)*2))
                ctypes.memmove(replacement._workspace,self.native._workspace,len(old));ctypes.memset(replacement._output,0xa7,96)
                self.native.close();self.native=replacement;continue
            try:expected=self.model.step(op,g,kind,key,reason);expected_code=64
            except Rejected as error:expected=b'';expected_code=error.code
            self.capture.row(self.sid,self.domain,raw,expected_code,expected,before,old,code,output,state,start,end)
            assert code==expected_code,(self.domain,op,g,code,expected_code)
            if code==64:
                assert output[:64]==expected and output[64:]==before[64:],(self.domain,op,g,output[:64].hex(),expected.hex())
                self.inspect(state);return struct.unpack('<8s7Q',expected)[3]
            assert output==before and state==old;return None
    def inspect(self,state):
        magic,next_value,used,count,mapped,parent,drain,reserved=struct.unpack_from('<8s7Q',state)
        assert magic==b'HRQRS001'and next_value==self.model.next and count==len(self.model.records)and mapped==len(self.model.mapping)
        assert parent==int(self.model.parent)and drain==self.model.drain and reserved==0
        records={};at=64
        while at<used:
            extent,g,kind,n,flags,zero=struct.unpack_from('<6Q',state,at)
            assert zero==0 and extent>=48+n and extent-48-n<8 and extent%8==0
            assert state[at+48+n:at+extent]==bytes(extent-48-n)
            records[g]=((kind,state[at+48:at+48+n]),flags);at+=extent
        assert at==used and set(records)==set(self.model.records)
        for g,(ident,flags)in records.items():assert ident==self.model.records[g]['id']and flags==self.model.flags(g)
        assert state[used:]==bytes(len(state)-used)
    def raw(self,raw,expected_code,domain='private-refusal'):
        before,old=self.buffers();start=time.monotonic_ns();code,output,state=self.native.invoke_raw(raw);end=time.monotonic_ns()
        self.capture.row(self.sid,domain,raw,expected_code,b'',before,old,code,output,state,start,end)
        assert code==expected_code and output==before and state==old,(domain,code,expected_code)
    def finish(self):
        for g in list(self.model.records):
            if not self.model.records[g]['completed']:self.call(3,g)
            self.call(4,g)
        assert not self.model.mapping;self.native.close()

def semantic(module,capture):
    identifiers=[(1,struct.pack('<q',n))for n in (0,1,-1,-(1<<63),(1<<63)-1)]
    identifiers +=[(2,text.encode())for text in ('','1','-1','0','a\0b','\0','é','e\u0301','😀','\n"\\','零','007')]
    session=Session(module,capture,'typed-id')
    ids=[session.call(1,kind=k,key=b)for k,b in identifiers]
    for g in ids:session.call(5,g)
    for k,b in reversed(identifiers):session.call(2,kind=k,key=b)
    session.finish()
    for actions in itertools.permutations(('older','newer','cancel')):
        for ident in [(1,struct.pack('<q',1)),(2,b'1'),(2,b''),(2,'é\0😀'.encode())]:
            s=Session(module,capture,'duplicate-order');k,b=ident
            a=s.call(1,kind=k,key=b);c=s.call(1,kind=k,key=b)
            s.call(5,a);s.call(5,c)
            for action in actions:
                if action=='cancel':s.call(2,kind=k,key=b)
                else:s.call(3,a if action=='older'else c)
                s.call(5,a);s.call(5,c)
            s.call(3,a);s.call(3,c);s.finish()
    for mode in range(6):
        s=Session(module,capture,'parent-and-drain')
        a=s.call(1,kind=2,key=b'duplicate');b=s.call(1,kind=2,key=b'duplicate')
        if mode<3:
            s.call(6);c=s.call(1,kind=1,key=struct.pack('<q',8));s.call(5,c);s.call(6)
            s.call(7,reason=1 if mode==0 else 2)
        else:
            s.call(7,reason=2);s.call(7,reason=1)
            if mode!=3:s.call(6)
        s.call(5,a);s.call(5,b);s.call(7,reason=1);s.call(7,reason=2)
        s.call(1,kind=2,key=b'closed');s.call(2,kind=2,key=b'duplicate');s.finish()
    s=Session(module,capture,'retirement-and-stale-generation')
    old=s.call(1,kind=2,key=b'same');s.call(4,old);s.call(3,old);s.call(4,old)
    new=s.call(1,kind=2,key=b'same');assert new>old
    s.call(3,old);s.call(4,old);s.call(5,old);s.call(5,new);s.call(0);s.finish()
    rng=random.Random(944622)
    for run in range(8):
        s=Session(module,capture,'mixed-interleavings')
        for step in range(180):
            choice=rng.randrange(8);records=list(s.model.records);kind,key=identifiers[rng.randrange(len(identifiers))]
            if choice<3:s.call(1,kind=kind,key=key)
            elif choice==3:s.call(2,kind=kind,key=key)
            elif records:s.call(rng.choice((3,4,5)),rng.choice(records))
            if step==150 and run%2==0:s.call(6)
        s.finish()
    s=Session(module,capture,'unbounded-retained-contexts')
    ids=[s.call(1,kind=1,key=struct.pack('<q',n))for n in range(2049)]
    duplicates=[s.call(1,kind=2,key=b'duplicate-retained')for _ in range(257)]
    s.call(3,duplicates[0]);s.call(5,duplicates[-1])
    for g in ids[::3]:s.call(2,kind=1,key=struct.pack('<q',g-1))
    for g in ids[1::7]:s.call(5,g)
    s.finish()
    s=Session(module,capture,'complete-five-mib-id')
    key=b'z'*(5<<20)+b'\0'+'😀'.encode();a=s.call(1,kind=2,key=key);b=s.call(1,kind=2,key=key)
    s.call(5,a);s.call(3,a);s.call(5,b);s.finish()
    s=Session(module,capture,'private-generation-exhaustion')
    ctypes.memmove(ctypes.addressof(s.native._workspace)+8,struct.pack('<Q',MAX-1),8);s.model.next=MAX-1
    a=s.call(1,kind=1,key=struct.pack('<q',1));b=s.call(1,kind=2,key=b'1')
    assert a==MAX-1 and b==MAX
    s.call(1,kind=2,key=b'future');s.finish()
def private(module,capture):
    s=Session(module,capture,'private-input')
    base=wire(5,1)
    for n in range(64):s.raw(base[:n],INVALID)
    s.raw(base+b'\0',INVALID)
    for at in (0,48,56):
        changed=bytearray(wire(0));changed[at]=255;s.raw(bytes(changed),INVALID)
    for op in (8,9,255,MAX):s.raw(wire(op),INVALID)
    for op in (3,4,5):s.raw(wire(op),INVALID)
    for op in (0,6,7):
        s.raw(wire(op,kind=2),INVALID);s.raw(wire(op,key=b'x'),INVALID);s.raw(wire(op,generation=1),INVALID)
    for n in list(range(8))+list(range(9,17)):s.raw(wire(1,kind=1,key=bytes(n)),INVALID)
    for kind in (0,3,MAX):s.raw(wire(1,kind=kind,key=b'x'),INVALID)
    for op in (1,2):
        s.raw(wire(op,generation=1,kind=2,key=b'x'),INVALID)
        s.raw(wire(op,kind=2,key=b'x',reason=1),INVALID)
    malformed=[bytes([b])for b in range(128,256)]
    malformed +=[b'\xc0\x80',b'\xc1\xbf',b'\xe0\x80\x80',b'\xed\xa0\x80',b'\xf0\x80\x80\x80',b'\xf4\x90\x80\x80',b'\xf5\x80\x80\x80',b'\xff',b'\xfe']
    valid=[chr(n).encode()for n in (0x80,0x7ff,0x800,0xd7ff,0xe000,0xffff,0x10000,0x10ffff)]
    for raw in valid:
        for n in range(1,len(raw)):malformed.append(raw[:n])
        for index in range(1,len(raw)):
            for byte in (0,127,192,255):malformed.append(raw[:index]+bytes([byte])+raw[index+1:])
    for raw in malformed:
        try:raw.decode('utf-8')
        except UnicodeError:s.raw(wire(1,kind=2,key=raw),INVALID)
        else:raise AssertionError('invalid UTF8 fixture is valid')
    for raw in valid:s.call(1,kind=2,key=raw)
    s.finish()
    for capacity in range(64):
        native=module.session(output_capacity=capacity,workspace_capacity=64);ctypes.memset(native._output,0xa7,capacity)
        old=ctypes.string_at(native._workspace,64);before=ctypes.string_at(native._output,capacity);start=time.monotonic_ns()
        code,out,after=native.invoke_raw(wire(0));end=time.monotonic_ns()
        capture.row(0,'short-output',wire(0),CAPACITY,b'',before,old,code,out,after,start,end)
        assert code==CAPACITY and out==before and after==old;native.close()
    for capacity in range(64):
        native=module.session(output_capacity=64,workspace_capacity=capacity);ctypes.memset(native._output,0xa7,64)
        before=ctypes.string_at(native._output,64);old=ctypes.string_at(native._workspace,capacity)
        start=time.monotonic_ns();code,out,after=native.invoke_raw(wire(0));end=time.monotonic_ns();expected=response(0,status=2,related=64)
        capture.row(0,'short-initial-arena',wire(0),64,expected,before,old,code,out,after,start,end)
        assert code==64 and out==expected and after==old;native.close()
    s=Session(module,capture,'private-corrupt-state');g=s.call(1,kind=2,key=b'abcdefghi');_,saved=s.buffers()
    corruptions=[(0,0),(8,1),(16,63),(16,len(saved)+8),(24,0),(32,0),(40,2),(48,3),(56,1),
        (64,0),(72,0),(80,0),(88,999),(96,8),(96,6),(104,1)]
    for at,value in corruptions:
        ctypes.memmove(s.native._workspace,saved,len(saved));ctypes.memmove(ctypes.addressof(s.native._workspace)+at,struct.pack('<Q',value),8)
        s.raw(wire(5,g),STATE,'corrupt-arena')
    ctypes.memmove(s.native._workspace,saved,len(saved));ctypes.memset(ctypes.addressof(s.native._workspace)+112,255,1);s.raw(wire(5,g),STATE,'corrupt-arena')
    ctypes.memmove(s.native._workspace,saved,len(saved));ctypes.memset(ctypes.addressof(s.native._workspace)+121,1,1);s.raw(wire(5,g),STATE,'corrupt-arena')
    ctypes.memmove(s.native._workspace,saved,len(saved));s.finish()

