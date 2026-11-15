"""Test-only fixed native Editable/Apply composition; no text-edit semantics."""
from pathlib import Path
import ctypes
import hashlib
import json
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_loader import NativeModule
from batch_apply_harness import NativeApply


def sha(raw):return hashlib.sha256(raw).hexdigest()


class Chain:
    def __init__(self,bundle):
        self.bundle=Path(bundle).resolve(strict=True);base=self.bundle.parent
        record=json.loads(self.bundle.read_bytes())
        assert record['schema']=='hepta.runtime.batch-diff-build.v1'
        assert record['public_batch_route_replaced'] is False and record['filesystem_effects_replaced'] is False
        assert set(record['members'])=={'diff','apply','editable'}
        self.members={}
        for key,value in record['members'].items():
            path=base/value['manifest'];raw=path.read_bytes();metadata=json.loads(raw)
            assert sha(raw)==value['manifest_sha256']
            assert metadata['source_sha256']==value['source_sha256']==sha((ROOT/value['source']).read_bytes())
            assert metadata['image_sha256']==value['image_sha256']
            self.members[key]=path
        self.diff=NativeModule(self.members['diff'],manifest_sha256=sha(self.members['diff'].read_bytes()))
        self.editable=NativeModule(self.members['editable'],manifest_sha256=sha(self.members['editable'].read_bytes()))
        self.apply=NativeApply(self.members['apply'],self.members['editable'],source_root=ROOT,reference_root=ROOT)
        self.editable_calls=0

    def close(self):
        self.diff.close();self.editable.close();self.apply.close()

    def transform(self,wire,capture):
        assert wire[:8]==b'HBACT001'
        size=struct.unpack_from('<Q',wire,16)[0];raw=wire[64:64+size];plan=wire[64+size:]
        identity=struct.pack('<8s5Q',b'HEDIT001',1,len(raw),0,0,0)+raw
        capacity=80+len(raw)+17;workspace=256+4*(len(raw)+64)
        code,out,state=self.editable.invoke_raw(identity,output_capacity=capacity,workspace_capacity=workspace,output_fill=0xa5,workspace_fill=0)
        self.editable_calls+=1;capture(10,code,identity,out,state)
        assert 80<=code<=capacity and out[:8]==b'HEDRES01'
        values=struct.unpack_from('<9Q',out,8)
        status,completed,ending,trailing,lines,nlen,rlen,selected,errors=values
        assert status==completed==errors==0 and selected==nlen and code==80+nlen
        assert out[code:]==b'\xa5'*(capacity-code)
        original=out[80:code]
        count=struct.unpack_from('<Q',plan,16)[0];cursor=48;total=0
        for _ in range(count):
            amount=struct.unpack_from('<Q',plan,cursor+40)[0];cursor+=48+amount;total+=amount+1
        assert cursor==len(plan)
        capacity=max(80+2*(len(raw)+total+1),80+6*len(raw)+4096)
        child_calls=[]
        def observe(context):
            address=context['work'];footer=context['footer'];get=context['get']
            start=get(footer+32);length=get(footer+40);target=get(footer+16)
            output=get(footer+56);extent=get(footer+64);code=get(footer+80)
            assert target==5
            incoming=ctypes.string_at(address+start,length);full=ctypes.string_at(address+output,extent)
            capture(12,code,incoming,full,b'')
            child_calls.append({'phase':context['phase'],'input_bytes':length,'input_sha256':sha(incoming),
                                'output_bytes':extent,'output_sha256':sha(full),'return':code})
        applied=self.apply.invoke(wire,capacity,fault=observe)
        out=applied['output'];code=applied['code'];capture(11,code,wire,out,b'')
        assert code<0xffff0000 and code>=80 and out[:8]==b'HBAPLR01'
        status,count_result,ending_result,trailing_result,final_lines,nlen,rlen,selected,errors=struct.unpack_from('<9Q',out,8)
        assert status in (0,1) and code==80+selected+errors
        assert ending_result==ending and trailing_result==trailing
        if status:
            assert count_result==selected==0 and errors
            parts=[original,b'',b'',plan,b'',out[80:]]
        else:
            assert count_result==count and selected==nlen+rlen and errors==0
            parts=[original,out[80:80+nlen],out[80+nlen:80+nlen+rlen],plan,b'',b'']
        return status,parts,{'apply':{k:v for k,v in applied.items() if k not in ('output','prefix')},'child_calls':child_calls}

