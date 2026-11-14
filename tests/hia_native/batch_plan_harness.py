"""Qualification-only transport; decisions execute in fixed native HIA images."""
from __future__ import annotations
import ctypes
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_loader import NativeModule, BUFFER_PROFILES
CALL,CAPACITY,INVALID,CHILD=0xffffffe0,0xfffffffe,0xffffffff,0xfffffff8
META=24576
COMPILER='d3e2c90173cf733e42b299d0c4274df4b593a12f'
COMPILER_IMAGE='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pieces(address,size,chunk=1<<20):
    for offset in range(0,size,chunk):yield ctypes.string_at(address+offset,min(chunk,size-offset))
def digest_span(address,size):
    result=hashlib.sha256()
    for value in pieces(address,size):result.update(value)
    return result.hexdigest()
def all_bytes(address,size,expected):
    return all(value==bytes([expected])*len(value) for value in pieces(address,size))

class NativePlan:
    def __init__(self,manifests,*,source_root=ROOT,reference_root=ROOT):
        self.modules={};self.loaded=[]
        self.counts={'requests':0,'native_controller_calls':0,'native_endpoint_calls':0,'native_verify_calls':0}
        sources={1:Path(source_root)/'native/batch_plan.hepta',2:Path(reference_root)/'native/line_endpoint.hepta',3:Path(reference_root)/'native/line_verify.hepta'}
        for target in (1,2,3):
            path=Path(manifests[target]).resolve(strict=True);raw=path.read_bytes();metadata=json.loads(raw)
            assert metadata['source_sha256']==sha(sources[target].read_bytes())
            assert metadata['compiler_commit']==COMPILER and metadata['compiler_sha256']==COMPILER_IMAGE
            assert metadata['buffer_profile']=='batch-plan.v1'
            assert tuple(metadata[k] for k in ('input_capacity','output_capacity','workspace_capacity'))==BUFFER_PROFILES['batch-plan.v1']
            self.modules[target]=NativeModule(path,manifest_sha256=sha(raw))
            self.loaded.append({'id':target,'manifest_sha256':sha(raw),'source_sha256':metadata['source_sha256'],'image_sha256':metadata['image_sha256'],'compiler_commit':COMPILER,'compiler_sha256':COMPILER_IMAGE,'buffer_profile':'batch-plan.v1'})
    def close(self):
        for module in self.modules.values():module.close()
    def invoke(self,wire,capacity,*,workspace=None,fault=None,sink=None,check_clear=True,output_fill=0xa5):
        assert type(wire) is bytes and len(wire)<=BUFFER_PROFILES['batch-plan.v1'][0]
        assert 0<=capacity<=BUFFER_PROFILES['batch-plan.v1'][1]
        amount=META+capacity+2*len(wire)+8192 if workspace is None else workspace
        assert 0<=amount<=BUFFER_PROFILES['batch-plan.v1'][2]
        source=ctypes.create_string_buffer(wire+b'\x7c'*16)
        output=ctypes.create_string_buffer(capacity+16);work=ctypes.create_string_buffer(amount+16)
        oa,wa=ctypes.addressof(output),ctypes.addressof(work)
        ctypes.memset(oa,output_fill,capacity+16);ctypes.memset(wa,0x5a,amount+16)
        footer=amount-256
        def get(at):return struct.unpack('<Q',ctypes.string_at(wa+at,8))[0]
        def put(at,value):ctypes.memmove(wa+at,struct.pack('<Q',value),8)
        if amount>=256:
            ctypes.memset(wa+footer,0,256);put(0,0);put(footer+120,3);put(footer+128,1);put(footer+136,1)
        leaf_work={target:ctypes.create_string_buffer(size+16) for target,size in ((2,8),(3,192))}
        for leaf in leaf_work.values():ctypes.memset(ctypes.addressof(leaf)+ctypes.sizeof(leaf)-16,0x6b,16)
        sequence=0;trace=[];before_source=sha(wire)
        for step in range(204):
            code=self.modules[1]._entry(source,len(wire),output,capacity,work,amount)
            self.counts['native_controller_calls']+=1
            assert digest_span(ctypes.addressof(source),len(wire))==before_source
            assert ctypes.string_at(ctypes.addressof(source)+len(wire),16)==b'\x7c'*16
            assert ctypes.string_at(oa+capacity,16)==bytes([output_fill])*16
            assert ctypes.string_at(wa+amount,16)==b'\x5a'*16
            if code!=CALL:
                self.counts['requests']+=1;assert 0<=code<=0xffffffff
                size=0 if code>=0xffff0000 else code
                assert size<=capacity and all_bytes(oa+size,capacity-size,output_fill),'output tail changed'
                if check_clear and amount>=META+256:
                    tail=False
                    for chunk in pieces(wa,footer):
                        if not tail:
                            first=len(chunk)-len(chunk.lstrip(b'\0'))
                            if first!=len(chunk):tail=True;assert chunk[first:]==b'\x5a'*(len(chunk)-first),'private scratch retained'
                        else:assert chunk==b'\x5a'*len(chunk),'workspace tail changed'
                digest=hashlib.sha256()
                if sink is not None:sink.write(struct.pack('<Q',size))
                for chunk in pieces(oa,size):
                    digest.update(chunk)
                    if sink is not None:sink.write(chunk)
                actual=None if sink is not None else ctypes.string_at(oa,size)
                return {'code':code,'output':actual,'output_bytes':size,'output_sha256':digest.hexdigest(),'trace':trace,'output_capacity':capacity,'workspace_capacity':amount,'prefix':ctypes.string_at(oa,min(size,48))}
            assert amount>=META+256
            words=struct.unpack('<14Q',ctypes.string_at(wa+footer,112))
            magic,seq,target,region,start,size,oregion,out_at,out_size,reserved,result,ack,done,status=words
            assert magic==int.from_bytes(b'HIACAL01','little') and seq==sequence+1
            assert target in (2,3) and region==oregion==2
            assert 0<=start<=footer-size and 0<=out_at<=footer-out_size
            assert start+size<=out_at or out_at+out_size<=start
            assert reserved==result==ack==done==status==0
            assert size<=self.modules[target].metadata['input_capacity'] and out_size<=self.modules[target].metadata['output_capacity']
            sequence=seq;phase=get(0);before=digest_span(wa+start,size)
            leaf=leaf_work[target];leaf_size=ctypes.sizeof(leaf)-16
            result=self.modules[target]._entry(ctypes.c_void_p(wa+start),size,ctypes.c_void_p(wa+out_at),out_size,leaf,leaf_size)
            self.counts['native_endpoint_calls' if target==2 else 'native_verify_calls']+=1
            assert digest_span(wa+start,size)==before
            assert ctypes.string_at(ctypes.addressof(leaf)+leaf_size,16)==b'\x6b'*16
            assert result>=0xffff0000 or result<=out_size
            trace.append({'phase':phase,'target':target,'code':result,'input_sha256':before,'input_bytes':size,'output_sha256':digest_span(wa+out_at,result if result<0xffff0000 else 0)})
            put(footer+80,result);put(footer+88,seq);put(footer+96,1)
            if fault is not None:fault({'work':wa,'footer':footer,'phase':phase,'target':target,'destination':out_at,'capacity':out_size,'get':get,'put':put})
        raise AssertionError('batch continuation exceeded 50-operation envelope')
