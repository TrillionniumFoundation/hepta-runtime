"""Qualification-only typed framing and direct HIA completion harness."""
from __future__ import annotations
import ctypes, hashlib, json, os, struct, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_loader import NativeModule
INVALID,CAPACITY,STATE,CANCELED,EFFECT=0xffffffff,0xfffffffe,0xfffffff9,0xfffffff7,0xfffffff0
MAGIC=b'HRAWI001';RESULT=b'HRAWR001'
COMPILER='d3e2c90173cf733e42b299d0c4274df4b593a12f'
COMPILER_IMAGE='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'

def sha(raw):return hashlib.sha256(raw).hexdigest()
def frame(path,content=b'',op=1):
    assert isinstance(path,bytes) and isinstance(content,bytes)
    return struct.pack('<8s7Q',MAGIC,op,len(path),len(content),0,0,0,0)+path+content
def output(tag,stage=0,payload=b''):
    return struct.pack('<8s3Q',RESULT,tag,stage,len(payload))+payload
def stream(wires):return b''.join(struct.pack('<Q',len(w))+w for w in wires)
def read_results(raw):
    rows=[];at=0
    while at<len(raw):
        assert at+4<=len(raw)
        code=struct.unpack_from('<I',raw,at)[0];at+=4
        size=code if code<=1024<<20 else 0
        assert at+size<=len(raw)
        rows.append((code,raw[at:at+size]));at+=size
    return rows

class NativeAtomic:
    def __init__(self,manifest,*,source=ROOT/'native/atomic_write.hepta'):
        path=Path(manifest).resolve(strict=True);raw=path.read_bytes();data=json.loads(raw)
        assert data['source_sha256']==sha(Path(source).read_bytes())
        assert data['compiler_commit']==COMPILER and data['compiler_sha256']==COMPILER_IMAGE
        assert data['buffer_profile']=='batch-plan.v1'
        assert (data['input_capacity'],data['output_capacity'],data['workspace_capacity'])==(512<<20,1024<<20,1152<<20)
        self.module=NativeModule(path,manifest_sha256=sha(raw));self.state=0;self.calls=0;self.requests=0
        self.identity={'manifest_sha256':sha(raw),'source_sha256':data['source_sha256'],'image_sha256':data['image_sha256'],'compiler_commit':COMPILER,'compiler_sha256':COMPILER_IMAGE}
    def close(self):self.module.close()
    def run(self,wire,completion=None,*,output_capacity=None,workspace_capacity=None,initial=None):
        initial_state=self.state
        plen=struct.unpack_from('<Q',wire,16)[0] if len(wire)>=24 else 0
        plen=min(plen,len(wire))
        ocap=32+3*plen+256 if output_capacity is None else output_capacity
        wcap=2048+4*plen if workspace_capacity is None else workspace_capacity
        assert len(wire)<=512<<20 and 0<=ocap<=1024<<20 and 0<=wcap<=1152<<20
        source=ctypes.create_string_buffer(len(wire)+16);out=ctypes.create_string_buffer(ocap+16);work=ctypes.create_string_buffer(wcap+16)
        sa,oa,wa=ctypes.addressof(source),ctypes.addressof(out),ctypes.addressof(work)
        ctypes.memmove(sa,wire,len(wire));ctypes.memset(sa+len(wire),0x7c,16);ctypes.memset(oa,0xa5,ocap+16);ctypes.memset(wa+wcap,0x5a,16)
        def get(at):assert at+8<=wcap;return struct.unpack('<Q',ctypes.string_at(wa+at,8))[0]
        def put(at,value):assert at+8<=wcap;ctypes.memmove(wa+at,struct.pack('<Q',value),8)
        if wcap>=16:put(8,self.state)
        control={'get':get,'put':put,'work':wa,'output':oa,'source':sa,'wire':wire}
        if initial is not None:initial(control)
        effects=[];records=[]
        for step in range(10000):
            code=self.module._entry(source,len(wire),out,ocap,work,wcap);self.calls+=1
            assert ctypes.string_at(sa,len(wire))==wire
            assert ctypes.string_at(sa+len(wire),16)==b'\x7c'*16
            assert ctypes.string_at(oa+ocap,16)==b'\xa5'*16
            assert ctypes.string_at(wa+wcap,16)==b'\x5a'*16
            if code!=EFFECT:
                size=code if code<0xffff0000 else 0
                assert size<=ocap
                assert ctypes.string_at(oa+size,ocap-size)==b'\xa5'*(ocap-size)
                data=ctypes.string_at(oa,size)
                if wcap>=16:self.state=get(8)
                self.requests+=1
                return {'code':code,'output':data,'effects':effects,'completions':records,'workspace':bytes(work.raw[:wcap]),'calls':step+1,
                  'initial_statx_state':initial_state,'output_capacity':ocap,'workspace_capacity':wcap,
                  'source_unchanged':True,'guards_unchanged':True,'output_tail_unchanged':True}
            assert ctypes.string_at(oa,ocap)==b'\xa5'*ocap
            words=struct.unpack('<12Q',ctypes.string_at(wa+256,96))
            assert words[0]==int.from_bytes(b'HIAATFX1','little') and words[1]==len(effects)+1
            assert all(v==0 for v in words[6:])
            event={'sequence':words[1],'action':words[2],'arg0':words[3],'arg1':words[4],'arg2':words[5]}
            if event['action'] in (1,3,4,7,9,10):
                event['path_hex']=ctypes.string_at(wa+event['arg0'],event['arg1']).hex()
            effects.append(event)
            if completion is None:raise AssertionError(('unexpected effect',event))
            result=completion(event,control)
            assert len(result)==3
            error,value,aux=result
            put(256+56,value);put(256+64,error);put(256+72,aux);put(256+80,1)
            records.append({'error':error,'value':value,'aux':aux,'cancel':get(136)})
        raise AssertionError('qualification completion sequence exceeded its explicit finite case')
