"""Qualification transport for fixed apply4 -> EditableContent5 native calls."""
from __future__ import annotations
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
RUNTIME=Path(os.environ.get('HIA_RUNTIME_REPO',str(ROOT)))
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
    h=hashlib.sha256()
    for piece in pieces(address,size):h.update(piece)
    return h.hexdigest()
def all_bytes(address,size,value):
    return all(piece==bytes([value])*len(piece) for piece in pieces(address,size))
def dimensions(wire,capacity):
    try:
        _,mode,raw,_,_,_,_,_=struct.unpack_from('<8s7Q',wire)
        count=struct.unpack_from('<Q',wire,64+raw+16)[0]
        assert count<=50
        at=64+raw+48;total=0
        for _ in range(count):
            size=struct.unpack_from('<Q',wire,at+40)[0];at+=48+size;total+=size+1
        assert at==len(wire)
        bound=raw+total+1;body=max(0,capacity-80)
        request=(raw+48+32*(count+3)+1+total+7)&~7
        norm=max(raw+80,0 if mode==0 else min(bound,body)+80)
        render=max(0 if mode==1 else min(2*bound,body)+80,min(6*raw+4096,body))
        return META+request+norm+render+256
    except (ValueError,OverflowError,struct.error,AssertionError):
        return META+4*len(wire)+3*capacity+8192

class NativeApply:
    def __init__(self,manifest,editable,*,source_root=ROOT,reference_root=RUNTIME,editable_source=None):
        self.modules={};self.loaded=[]
        self.counts={'requests':0,'native_controller_calls':0,'native_editable_calls':0}
        for target,path,source in [(4,manifest,Path(source_root)/'native/batch_apply.hepta'),(5,editable,Path(editable_source) if editable_source else Path(reference_root)/'native/editable_content.hepta')]:
            path=Path(path).resolve(strict=True);raw=path.read_bytes();m=json.loads(raw)
            assert m['source_sha256']==sha(source.read_bytes())
            assert m['compiler_commit']==COMPILER and m['compiler_sha256']==COMPILER_IMAGE
            assert m['buffer_profile']=='batch-plan.v1'
            assert tuple(m[k] for k in ('input_capacity','output_capacity','workspace_capacity'))==BUFFER_PROFILES['batch-plan.v1']
            self.modules[target]=NativeModule(path,manifest_sha256=sha(raw))
            self.loaded.append({'id':target,'manifest_sha256':sha(raw),'source_sha256':m['source_sha256'],'image_sha256':m['image_sha256'],'compiler_commit':COMPILER,'compiler_sha256':COMPILER_IMAGE,'buffer_profile':'batch-plan.v1'})
    def close(self):
        for m in self.modules.values():m.close()
    def invoke(self,wire,capacity,*,workspace=None,leaf_workspace=None,fault=None,initial=None,sink=None,check_clear=True,output_fill=0xa5):
        assert type(wire) is bytes and len(wire)<=BUFFER_PROFILES['batch-plan.v1'][0]
        assert 0<=capacity<=BUFFER_PROFILES['batch-plan.v1'][1]
        amount=dimensions(wire,capacity) if workspace is None else workspace
        assert 0<=amount<=BUFFER_PROFILES['batch-plan.v1'][2]
        leaf_size=256+4*(len(wire)+1024) if leaf_workspace is None else leaf_workspace
        assert 0<=leaf_size<=BUFFER_PROFILES['batch-plan.v1'][2]
        source=ctypes.create_string_buffer(len(wire)+16)
        ctypes.memmove(source,wire,len(wire));ctypes.memset(ctypes.addressof(source)+len(wire),0x7c,16)
        output=ctypes.create_string_buffer(capacity+16);work=ctypes.create_string_buffer(amount+16)
        leaf=ctypes.create_string_buffer(leaf_size+16)
        oa,wa,la=ctypes.addressof(output),ctypes.addressof(work),ctypes.addressof(leaf)
        ctypes.memset(oa,output_fill,capacity+16);ctypes.memset(wa,0x5a,amount+16);ctypes.memset(la+leaf_size,0x6b,16)
        footer=amount-256
        def get(at):return struct.unpack('<Q',ctypes.string_at(wa+at,8))[0]
        def put(at,value):ctypes.memmove(wa+at,struct.pack('<Q',value),8)
        if amount>=256:
            ctypes.memset(wa+footer,0,256);put(0,0);put(footer+120,3);put(footer+128,4);put(footer+136,1)
        call_lengths={'input':len(wire),'output':capacity,'workspace':amount}
        if initial is not None:initial({'work':wa,'footer':footer,'get':get,'put':put,'lengths':call_lengths})
        sequence=0;trace=[];before_source=sha(wire)
        for step in range(4):
            code=self.modules[4]._entry(source,call_lengths['input'],output,call_lengths['output'],work,call_lengths['workspace'])
            self.counts['native_controller_calls']+=1
            assert digest_span(ctypes.addressof(source),len(wire))==before_source
            assert ctypes.string_at(ctypes.addressof(source)+len(wire),16)==b'\x7c'*16
            assert ctypes.string_at(oa+capacity,16)==bytes([output_fill])*16
            assert ctypes.string_at(wa+amount,16)==b'\x5a'*16
            if code!=CALL:
                self.counts['requests']+=1;assert 0<=code<=0xffffffff
                size=0 if code>=0xffff0000 else code
                assert size<=capacity and all_bytes(oa+size,capacity-size,output_fill),'output tail changed'
                cleared=0
                if check_clear and amount>=META+256 and call_lengths['workspace']==amount:
                    tail=False
                    for chunk in pieces(wa,footer):
                        if not tail:
                            first=len(chunk)-len(chunk.lstrip(b'\0'))
                            cleared+=first
                            if first!=len(chunk):tail=True;assert chunk[first:]==b'\x5a'*(len(chunk)-first),'private scratch retained'
                        else:assert chunk==b'\x5a'*len(chunk),'workspace tail changed'
                digest=hashlib.sha256()
                if sink is not None:sink.write(struct.pack('<Q',size))
                for chunk in pieces(oa,size):
                    digest.update(chunk)
                    if sink is not None:sink.write(chunk)
                return {'code':code,'output':None if sink is not None else ctypes.string_at(oa,size),'output_bytes':size,'output_sha256':digest.hexdigest(),'trace':trace,'output_capacity':capacity,'workspace_capacity':amount,'leaf_workspace_capacity':leaf_size,'prefix':ctypes.string_at(oa,min(size,80)),'cleared_prefix_bytes':cleared,'workspace_tail_bytes':footer-cleared if amount>=META+256 else None,'input_unchanged':True,'output_tail_unchanged':True,'guards_unchanged':True}
            words=struct.unpack('<14Q',ctypes.string_at(wa+footer,112))
            magic,seq,target,region,start,size,oregion,out_at,out_size,reserved,result,ack,done,status=words
            assert magic==int.from_bytes(b'HIACAL01','little') and seq==sequence+1
            assert target==5 and region==oregion==2
            assert 0<=start<=footer-size and 0<=out_at<=footer-out_size
            assert start+size<=out_at or out_at+out_size<=start
            assert reserved==result==ack==done==status==0
            assert size<=self.modules[5].metadata['input_capacity'] and out_size<=self.modules[5].metadata['output_capacity']
            sequence=seq;phase=get(0);before=digest_span(wa+start,size)
            result=self.modules[5]._entry(ctypes.c_void_p(wa+start),size,ctypes.c_void_p(wa+out_at),out_size,leaf,leaf_size)
            self.counts['native_editable_calls']+=1
            assert digest_span(wa+start,size)==before
            assert ctypes.string_at(la+leaf_size,16)==b'\x6b'*16
            assert result>=0xffff0000 or result<=out_size
            trace.append({'phase':phase,'target':target,'code':result,'input_sha256':before,'input_bytes':size,'output_sha256':digest_span(wa+out_at,result if result<0xffff0000 else 0)})
            put(footer+80,result);put(footer+88,seq);put(footer+96,1)
            if fault is not None:fault({'work':wa,'footer':footer,'phase':phase,'target':target,'destination':out_at,'capacity':out_size,'get':get,'put':put,'lengths':call_lengths})
        raise AssertionError('batch apply continuation exceeded its three-child-call envelope')
