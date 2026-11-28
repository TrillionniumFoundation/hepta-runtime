#!/usr/bin/env python3
"""Real Value -> typed HIA calls; inputs only, no Rust expectations at runtime."""
from pathlib import Path
import ctypes
import gzip
import hashlib
import importlib.util
import json
import os
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_loader import NativeModule

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
inputs=load('_batch_params_inputs',Path(__file__).with_name('batch_edit_params_oracle')/'cases.py')
sha=lambda raw:hashlib.sha256(raw).hexdigest()
word=lambda raw,at:struct.unpack_from('<Q',raw,at)[0]
INVALID,CAPACITY=0xffffffff,0xfffffffe
CAPTURE=Path(os.environ['HIA_BATCH_EDIT_PARAMS_CAPTURE_DIR']).resolve()
MANIFEST=Path(os.environ['HIA_BATCH_EDIT_PARAMS_MANIFEST']).resolve()
VALUE=Path(os.environ['HIA_BATCH_EDIT_PARAMS_VALUE_MANIFEST']).resolve()


class Recorder:
    def __init__(self):
        CAPTURE.mkdir(parents=True,exist_ok=False)
        self.stream=gzip.open(CAPTURE/'calls.bin.gz','wb',compresslevel=6)
        self.index=[];self.offset=0;self.semantic=[];self.controls=[]
        self.modules={1:NativeModule(VALUE,manifest_sha256=sha(VALUE.read_bytes())),
                      2:NativeModule(MANIFEST,manifest_sha256=sha(MANIFEST.read_bytes()))}
        self.manifests={1:VALUE,2:MANIFEST}
        self.sources={str(p):sha(p.read_bytes()) for p in [Path(__file__),Path(inputs.__file__),ROOT/'scripts/hia_native_loader.py']}
        self.artifacts={}
        for p in [VALUE,MANIFEST]:
            meta=json.loads(p.read_bytes())
            for a in (p,p.parent/meta['image'],p.parent/meta['source']):self.artifacts[str(a)]=sha(a.read_bytes())
    def invoke(self,owner,case_id,label,wire,workspace,output_capacity):
        with self.modules[owner].session(workspace_capacity=len(workspace),output_capacity=output_capacity) as session:
            if workspace:ctypes.memmove(session._workspace,workspace,len(workspace))
            ctypes.memset(session._output,0xa5,output_capacity)
            code,out,after=session.invoke_raw(wire)
        index=len(self.index)+1
        header=struct.pack('<8Q',index,owner,case_id,code,len(wire),output_capacity,len(workspace),0)
        raw=header+wire+workspace+b'\xa5'*output_capacity+out+after
        self.stream.write(raw)
        row={'call':index,'owner':owner,'case_id':case_id,'label':label,'offset':self.offset,'bytes':len(raw),
             'return_code':code,'input_bytes':len(wire),'output_capacity':output_capacity,'workspace_capacity':len(workspace),
             'input_sha256':sha(wire),'before_sha256':sha(workspace),'output_before_sha256':sha(b'\xa5'*output_capacity),
             'output_sha256':sha(out),'after_sha256':sha(after),'record_sha256':sha(raw)}
        self.index.append(row);self.offset+=len(raw)
        return code,out,after,index
    def complete(self,owner,case_id,wire,workspace_capacity=None,output_capacity=None):
        workspace=bytes(workspace_capacity or (16512 if owner==1 else 65536))
        capacity=output_capacity if output_capacity is not None else (32 if owner==1 else 64)
        calls=[]
        while True:
            code,out,after,index=self.invoke(owner,case_id,'semantic',wire,workspace,capacity)
            calls.append(index)
            assert code==(32 if owner==1 else 64),hex(code)
            assert out[:8]==(b'HJSVR002' if owner==1 else b'HBPRR002')
            status=word(out,8)
            needed=word(out,24 if owner==1 else 48)
            if status in (2,3):
                header=32 if owner==1 else 64
                assert out[header:]==b'\xa5'*(len(out)-header)
                if status==2:
                    assert needed>len(workspace)
                    workspace=after+bytes(needed-len(after))
                else:
                    assert needed>capacity
                    capacity=needed;workspace=after
                continue
            if owner==1:
                assert status==0 and needed==0
                size=32+word(out,16)
            else:
                assert status in (0,1) and needed==0 and word(out,56)==0
                if status==0:
                    assert word(out,40)==0
                    size=64+word(out,16)+word(out,24)
                else:
                    assert out[16:40]==bytes(24)
                    size=64+word(out,40)
            assert size<=len(out) and out[size:]==b'\xa5'*(len(out)-size)
            return out[:size],calls
    def finish(self,success):
        self.stream.close()
        for module in self.modules.values():module.close()
        assert self.sources=={p:sha(Path(p).read_bytes()) for p in self.sources}
        assert self.artifacts=={p:sha(Path(p).read_bytes()) for p in self.artifacts}
        for name,rows in [('calls.jsonl',self.index),('native-cases.jsonl',self.semantic),('controls.jsonl',self.controls)]:
            (CAPTURE/name).write_bytes(b''.join((json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode() for row in rows))
        result={'status':'PASS' if success else 'FAIL','test_groups':3,'semantic_cases':len(self.semantic),
                'native_calls':len(self.index),'value_calls':sum(r['owner']==1 for r in self.index),
                'projection_calls':sum(r['owner']==2 for r in self.index),
                'controls':len(self.controls),'full_stream_bytes':self.offset,
                'source_sha256':self.sources,'artifact_sha256':self.artifacts,
                'manifest':str(MANIFEST),'value_manifest':str(VALUE),'python':sys.executable,
                'original_reference_status':'NOT_RUN','original_batch_handler_executed':False,
                'effects_executed':False,'public_route_replaced':False}
        (CAPTURE/'result.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
        return result


R=None
def frame(raw):return b'HBPRQ002'+struct.pack('<2Q',len(raw),0)+raw


class BatchParamsTests(unittest.TestCase):
    def test_01_complete_native_value_to_projection(self):
        for row in list(inputs.iter_cases())+list(inputs.extra_cases()):
            if row['domain']!='typed-object':continue
            raw=row['raw_json'].encode() if 'raw_json' in row else json.dumps(row['value'],ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
            value,value_calls=R.complete(1,row['case_id'],b'HJSVS002'+struct.pack('<2Q',1,len(raw))+raw)
            canonical=value[32:]
            result,typed_calls=R.complete(2,row['case_id'],frame(canonical))
            status,plen,nlen,count,dlen,needed,reserved=struct.unpack_from('<7Q',result,8)
            if status==0:
                decoded_path=result[64:64+plen].decode()
                normalized=result[64+plen:64+plen+nlen]
                shape=json.loads(normalized)
                self.assertEqual(shape['path'],decoded_path)
                self.assertEqual(len(shape['operations']),count)
                self.assertEqual(set(shape),{'path','operations'})
                for op in shape['operations']:
                    self.assertEqual(set(op),{'operation','start','end','content'})
                    self.assertIn(op['operation'],['insert','replace'])
                    self.assertIsInstance(op['content'],str)
            else:result[64:64+dlen].decode()
            R.semantic.append({'case_id':row['case_id'],'name':row['name'],'domain':row['domain'],
                               'input_bytes':len(raw),'input_sha256':sha(raw),'canonical_bytes':len(canonical),'canonical_sha256':sha(canonical),
                               'response_bytes':len(result),'response_sha256':sha(result),'status':status,
                               'value_calls':value_calls,'projection_calls':typed_calls})
    def test_02_closed_frame_and_full_refusals(self):
        raw=b'{"operations":[],"path":"p"}';good=frame(raw)
        bad=[b'',good[:7],good[:23],b'XXXXXXXX'+good[8:],good[:8]+struct.pack('<Q',len(raw)+1)+good[16:],
             good[:16]+struct.pack('<Q',1)+good[24:],frame(b'[]'),frame(b'null'),frame(b'{'),frame(b'{} '),
             frame(b'{"path":"p","operations":[],}'),frame(b'{"path":"p","operations":[}]}'),
             frame(b'{"path":"\xff","operations":[]}'),frame(b'{"path":"\\ud800","operations":[]}'),
             frame(b'{"path":"p","operations":[{"content":"x","operation":"insert","start":01}]}')]
        for n,wire in enumerate(bad):
            before=b'\x7b'*65536
            code,out,after,call=R.invoke(2,30000+n,'malformed-private-frame',wire,before,512)
            self.assertEqual(code,INVALID);self.assertEqual(out,b'\xa5'*512)
            R.controls.append({'kind':'malformed-private-frame','call':call,'expected_code':INVALID,'output_unchanged':True})
        for n,cap in enumerate([0,1,31,63]):
            before=b'\x7b'*65536
            code,out,after,call=R.invoke(2,30100+n,'short-output',good,before,cap)
            self.assertEqual((code,out,after),(CAPACITY,b'\xa5'*cap,before))
            R.controls.append({'kind':'short-output','call':call,'expected_code':CAPACITY,'output_unchanged':True,'workspace_unchanged':True})
    def test_03_exact_capacity_growth_and_dirty_reuse(self):
        examples=[b'{"operations":[],"path":"p"}',
                  b'{"operations":[{"content":"x","operation":{"insert":"bad"},"start":0}],"path":"p"}',
                  b'{"operations":[["insert",0,null,["a","b"]]],"path":"p"}']
        for n,raw in enumerate(examples):
            wire=frame(raw)
            full,calls=R.complete(2,31000+n,wire)
            for cap in [64,len(full)-1,len(full),len(full)+19]:
                before=b'\x7b'*65536
                code,out,after,call=R.invoke(2,31100+n,'output-boundary',wire,before,cap)
                self.assertEqual(code,64)
                if cap<len(full):
                    self.assertEqual(out[:64],b'HBPRR002'+struct.pack('<7Q',3,0,0,0,0,len(full),0))
                    self.assertEqual(out[64:],b'\xa5'*(cap-64))
                else:
                    self.assertEqual(out[:len(full)],full);self.assertEqual(out[len(full):],b'\xa5'*(cap-len(full)))
                R.controls.append({'kind':'output-boundary','call':call,'expected_response_sha256':sha(full),'required_capacity':len(full)})
            for wcap in [0,1,32767,32768]:
                before=b'\x7b'*wcap
                code,out,after,call=R.invoke(2,31200+n,'workspace-growth',wire,before,64)
                self.assertEqual(code,64);self.assertEqual(word(out,8),2)
                self.assertGreater(word(out,48),wcap)
                if wcap<32768:self.assertEqual(after,before)
                grown=b'\x7b'*word(out,48)
                actual,next_calls=R.complete(2,31300+n,wire,workspace_capacity=len(grown),output_capacity=len(full))
                self.assertEqual(actual,full)
                R.controls.append({'kind':'workspace-growth','call':call,'resume_calls':next_calls,'expected_response_sha256':sha(full)})
        with R.modules[2].session(workspace_capacity=65536,output_capacity=4096) as session:
            ctypes.memset(session._workspace,0x7b,65536)
            for n,raw in enumerate(examples+examples[::-1]):
                before=ctypes.string_at(session._workspace,65536)
                code,out,after,call=R.invoke(2,31400+n,'dirty-prior-state',frame(raw),before,4096)
                ctypes.memmove(session._workspace,after,len(after))
                full,_=R.complete(2,31500+n,frame(raw))
                self.assertEqual(code,64);self.assertEqual(out[:len(full)],full)
                R.controls.append({'kind':'dirty-prior-state','call':call,'expected_response_sha256':sha(full)})


if __name__=='__main__':
    R=Recorder()
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(BatchParamsTests)
    outcome=unittest.TextTestRunner(verbosity=2).run(suite)
    result=R.finish(outcome.wasSuccessful())
    result.update(skipped=len(outcome.skipped),errors=len(outcome.errors),failures=len(outcome.failures))
    print(json.dumps(result,sort_keys=True))
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
