"""Execute native owners first and retain every complete borrowed byte span."""
from pathlib import Path
import ctypes
import gzip
import hashlib
import json
import os
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts'),str(Path(__file__).parent)]
from hia_native_loader import NativeModule
from batch_plan_harness import NativePlan
from batch_plan_input_cases import cases

INVALID,CAPACITY=0xffffffff,0xfffffffe
NAMES={1:'value',2:'params',3:'editable',4:'input',5:'plan',6:'endpoint',7:'verify'}
SOURCES={'value':'serde_json_span','params':'batch_edit_params','editable':'editable_content',
         'input':'batch_plan_input','plan':'batch_plan','endpoint':'line_endpoint','verify':'line_verify'}
sha=lambda raw:hashlib.sha256(raw).hexdigest()
word=lambda raw,at:struct.unpack_from('<Q',raw,at)[0]
def canonical(value):return (json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))+'\n').encode()
def pin(path):
    with Path(path).open('rb') as stream:return {'bytes':Path(path).stat().st_size,'sha256':hashlib.file_digest(stream,'sha256').hexdigest()}


class Recorder:
    def __init__(self):
        self.output=Path(os.environ['HIA_BATCH_PLAN_INPUT_CAPTURE_DIR']).resolve();self.output.mkdir(parents=True,exist_ok=False)
        self.bundle=Path(os.environ['HIA_BATCH_PLAN_INPUT_MEMBERS']).resolve()
        self.members=json.loads(self.bundle.read_bytes())['members']
        self.modules={owner:NativeModule(Path(self.members[NAMES[owner]]['manifest']),manifest_sha256=self.members[NAMES[owner]]['manifest_sha256']) for owner in range(1,5)}
        self.planner=NativePlan({owner: self.members[name]['manifest'] for owner,name in [(1,'plan'),(2,'endpoint'),(3,'verify')]},source_root=ROOT,reference_root=ROOT)
        self.stream=gzip.open(self.output/'calls.bin.gz','wb',compresslevel=1)
        self.expected=(self.output/'native-results.bin').open('xb')
        self.original=(self.output/'original-input.jsonl').open('xb')
        self.index=[];self.rows=[];self.controls=[];self.offset=0;self.current_case=0;self.current_label=''
        self.sources={str(ROOT/name):pin(ROOT/name)['sha256'] for name in (
            'scripts/hia_native_loader.py','tests/hia_native/batch_plan_harness.py',
            'tests/hia_native/test_batch_plan_input.py','tests/hia_native/batch_plan_input_cases.py',
            'tests/hia_native/batch_edit_params_oracle/cases.py')}
        self.artifacts={str(self.bundle):pin(self.bundle)['sha256']}
        for name,member in self.members.items():
            path=Path(member['manifest']);meta=json.loads(path.read_bytes())
            assert meta['source_sha256']==pin(ROOT/'native'/(SOURCES[name]+'.hepta'))['sha256']
            assert meta['compiler_commit']=='d3e2c90173cf733e42b299d0c4274df4b593a12f'
            assert meta['compiler_sha256']=='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
            for p in [path,path.parent/meta['source'],path.parent/meta['image']]:self.artifacts[str(p)]=pin(p)['sha256']
        for target in (1,2,3):
            module=self.planner.modules[target];real=module._entry
            def captured(source,size,output,capacity,work,amount,*,target=target,real=real):
                wire=ctypes.string_at(source,size);before=ctypes.string_at(work,amount);old=ctypes.string_at(output,capacity)
                code=real(source,size,output,capacity,work,amount)
                self.record(target+4,self.current_case,self.current_label,wire,before,old,code,ctypes.string_at(output,capacity),ctypes.string_at(work,amount))
                return code
            module._entry=captured
    def record(self,owner,case_id,label,wire,before,old,code,out,after):
        index=len(self.index)+1;header=struct.pack('<8Q',index,owner,case_id,code,len(wire),len(old),len(before),0)
        digest=hashlib.sha256();size=0
        for part in [header,wire,before,old,out,after]:self.stream.write(part);digest.update(part);size+=len(part)
        row={'call':index,'owner':owner,'case_id':case_id,'label':label,'offset':self.offset,'bytes':size,'return_code':code,
             'input_bytes':len(wire),'output_capacity':len(old),'workspace_capacity':len(before),'input_sha256':sha(wire),
             'before_sha256':sha(before),'output_before_sha256':sha(old),'output_sha256':sha(out),'after_sha256':sha(after),'record_sha256':digest.hexdigest()}
        self.index.append(row);self.offset+=size;return index
    def invoke(self,owner,case_id,label,wire,work,capacity):
        with self.modules[owner].session(workspace_capacity=len(work),output_capacity=capacity) as session:
            if work:ctypes.memmove(session._workspace,work,len(work))
            ctypes.memset(session._output,0xa5,capacity)
            code,out,after=session.invoke_raw(wire)
        index=self.record(owner,case_id,label,wire,work,b'\xa5'*capacity,code,out,after)
        return code,out,after,index
    def complete(self,owner,case_id,wire,*,workspace=None,capacity=None,label='semantic'):
        calls=[]
        if owner==3:
            amount=word(wire,16);cap=amount+96
            code,out,after,index=self.invoke(owner,case_id,label,wire,bytes(4*amount+300),cap)
            assert code<0xffff0000 and out[:8]==b'HEDRES01' and word(out,8)==0
            assert out[code:]==b'\xa5'*(len(out)-code)
            return out[:code],[index]
        header=32 if owner==1 else 64;needed_at={1:24,2:48,4:40}[owner]
        magic={1:b'HJSVR002',2:b'HBPRR002',4:b'HBPIR002'}[owner]
        work=bytes(16512 if owner==1 else 32768) if workspace is None else workspace
        cap=header if capacity is None else capacity
        while True:
            code,out,after,index=self.invoke(owner,case_id,label,wire,work,cap);calls.append(index)
            assert code==header and out[:8]==magic,(owner,case_id,code)
            status=word(out,8);needed=word(out,needed_at)
            if status in (2,3):
                assert out[header:]==b'\xa5'*(cap-header)
                if status==2:
                    assert len(work)<needed<=self.modules[owner].metadata['workspace_capacity']
                    work=after+bytes(needed-len(after))
                else:
                    assert cap<needed<=self.modules[owner].metadata['output_capacity']
                    cap=needed;work=after
                continue
            assert status in ((0,1) if owner==2 else (0,)) and needed==0,(owner,case_id,status)
            size=header+word(out,16)
            if owner==2:size=64+word(out,16)+word(out,24)+word(out,40)
            assert size<=cap and out[size:]==b'\xa5'*(cap-size)
            return out[:size],calls
    def plan(self,case_id,wire):
        start=len(self.index);capacity=32768;attempts=[]
        self.current_case=case_id;self.current_label='planner'
        while True:
            result=self.planner.invoke(wire,capacity)
            attempts.append({key:value for key,value in result.items() if key not in ('output','prefix')})
            if result['code']==CAPACITY:
                assert capacity<self.planner.modules[1].metadata['output_capacity']
                capacity=min(capacity*2,self.planner.modules[1].metadata['output_capacity']);continue
            assert result['code']<0xffff0000 and result['output'][:8]==b'HBPLR001',result
            return {'calls':list(range(start+1,len(self.index)+1)),'attempts':attempts,
                    'response_bytes':len(result['output']),'response_sha256':sha(result['output'])}
    def finish(self,success):
        self.stream.close();self.expected.close();self.original.close();self.planner.close()
        for module in self.modules.values():module.close()
        assert self.sources=={p:pin(p)['sha256'] for p in self.sources}
        assert self.artifacts=={p:pin(p)['sha256'] for p in self.artifacts}
        for name,rows in [('calls.jsonl',self.index),('native-cases.jsonl',self.rows),('controls.jsonl',self.controls)]:
            (self.output/name).write_bytes(b''.join(canonical(row) for row in rows))
        result={'schema':'hepta.runtime.batch-plan-input-native.v1','status':'PASS' if success else 'FAIL','test_groups':3,
                'semantic_inputs':len(self.rows),'semantic_records':sum(len(row['modes']) for row in self.rows),
                'successful_inputs':sum(row['typed_status']==0 for row in self.rows),
                'native_calls':len(self.index),'owner_calls':{name:sum(row['owner']==owner for row in self.index) for owner,name in NAMES.items()},
                'controls':len(self.controls),'planner_counts':self.planner.counts,'full_stream_bytes':self.offset,
                'source_sha256':self.sources,'artifact_sha256':self.artifacts,'members':str(self.bundle),'python':sys.executable,
                'pid':os.getpid(),'execution_source_root':str(ROOT),'execution_output_root':str(self.output.parent),
                'original_reference_status':'NOT_RUN','original_batch_handler_executed':False,'effects_executed':False,'public_route_replaced':False}
        (self.output/'result.json').write_bytes(canonical(result));return result


def request(params,editable=b'',mode=0):return b'HBPIQ002'+struct.pack('<7Q',mode,len(params),len(editable),0,0,0,0)+params+editable
def changed(wire,at,value):return wire[:at]+struct.pack('<Q',value)+wire[at+8:]
R=None


class BatchPlanInputTests(unittest.TestCase):
    def test_01_native_typed_and_editable_pipeline(self):
        for row in cases():
            cid=row['case_id'];raw=row['raw_json'].encode();original=row['original_raw'].encode()
            value,vc=R.complete(1,cid,b'HJSVS002'+struct.pack('<2Q',1,len(raw))+raw)
            params,pc=R.complete(2,cid,b'HBPRQ002'+struct.pack('<2Q',len(value)-32,0)+value[32:])
            status=word(params,8);modes=[]
            for mode in (0,1):
                R.original.write(canonical({'case_id':cid,'mode':mode,'raw_json':row['raw_json'],'original_raw':row['original_raw']}))
                detail={'mode':mode,'editable_calls':[],'bridge_calls':[],'planner':None}
                if status==1:
                    kind=1;body=params[64:]
                else:
                    editable=b''
                    if mode:editable,detail['editable_calls']=R.complete(3,cid,b'HEDIT001'+struct.pack('<5Q',1,len(original),0,0,0)+original)
                    body,detail['bridge_calls']=R.complete(4,cid,request(params,editable,mode))
                    self.assertEqual(word(body,8),0);kind=0
                    if row['planner']:detail['planner']=R.plan(cid,body[64:])
                R.expected.write(struct.pack('<4Q',cid,mode,kind,len(body)));R.expected.write(body)
                detail.update(kind=kind,body_bytes=len(body),body_sha256=sha(body));modes.append(detail)
            R.rows.append({'case_id':cid,'name':row['name'],'input_bytes':len(raw),'input_sha256':sha(raw),
                           'original_bytes':len(original),'original_sha256':sha(original),'typed_status':status,
                           'value_calls':vc,'projection_calls':pc,'modes':modes})
    def test_02_malformed_private_frames_and_short_output(self):
        raw=b'{"operations":[],"path":"p"}'
        params,calls=R.complete(2,50000,b'HBPRQ002'+struct.pack('<2Q',len(raw),0)+raw,label='control-setup')
        R.controls.append({'kind':'setup','calls':calls,'response_sha256':sha(params)})
        good=request(params)
        bad=[b'',good[:7],good[:63],good[:127],b'XXXXXXXX'+good[8:],changed(good,8,2),changed(good,16,len(params)+1),
             changed(good,24,1),changed(good,32,1),changed(good,40,1),changed(good,48,1),changed(good,56,1),
             changed(good,64,0),changed(good,72,1),changed(good,80,2),changed(good,88,1),changed(good,96,1),
             changed(good,104,1),changed(good,112,1),changed(good,120,1),good[:128]+b'q'+good[129:],
             good[:128]+b'\xff'+good[129:],good[:-1]+b']']
        for n,wire in enumerate(bad):
            before=b'\x7b'*65536;code,out,after,index=R.invoke(4,50100+n,'invalid',wire,before,512)
            self.assertEqual(code,INVALID);self.assertEqual(out,b'\xa5'*512)
            R.controls.append({'kind':'invalid','call':index,'expected_code':INVALID})
        editable,ec=R.complete(3,50200,b'HEDIT001'+struct.pack('<5Q',1,4,0,0,0)+b'a\r\r\n',label='control-setup')
        R.controls.append({'kind':'setup','calls':ec,'response_sha256':sha(editable)})
        post=request(params,editable,1);at=64+len(params)
        for n,(offset,value) in enumerate([(0,0),(8,1),(16,1),(24,0),(24,3),(32,2),(48,99),(64,99),(72,1)]):
            code,out,after,index=R.invoke(4,50300+n,'invalid-editable',changed(post,at+offset,value),b'\x7b'*65536,512)
            self.assertEqual((code,out),(INVALID,b'\xa5'*512));R.controls.append({'kind':'invalid','call':index,'expected_code':INVALID})
        for n,cap in enumerate([0,1,31,63]):
            before=b'\x7b'*65536;code,out,after,index=R.invoke(4,50400+n,'short-output',good,before,cap)
            self.assertEqual((code,out,after),(CAPACITY,b'\xa5'*cap,before))
            R.controls.append({'kind':'short-output','call':index,'expected_code':CAPACITY})
    def test_03_exact_growth_and_dirty_workspace(self):
        nested=False
        for _ in range(17):nested=[nested]
        values=[{'path':'p','operations':[]},{'path':'\x00中文','operations':[{'operation':'insert','start':nested,'content':'x'}]}]
        for n,value in enumerate(values):
            raw=json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
            params,pc=R.complete(2,51000+n,b'HBPRQ002'+struct.pack('<2Q',len(raw),0)+raw,label='control-setup')
            R.controls.append({'kind':'setup','calls':pc,'response_sha256':sha(params)})
            wire=request(params);full,fc=R.complete(4,51100+n,wire,label='control-reference')
            R.controls.append({'kind':'setup','calls':fc,'response_sha256':sha(full)})
            for cap in [64,len(full)-1,len(full),len(full)+19]:
                code,out,after,index=R.invoke(4,51200+n,'output-boundary',wire,b'\x7b'*65536,cap)
                self.assertEqual(code,64)
                if cap<len(full):self.assertEqual(out,b'HBPIR002'+struct.pack('<7Q',3,0,0,0,len(full),0,0)+b'\xa5'*(cap-64))
                else:self.assertEqual(out,full+b'\xa5'*(cap-len(full)))
                R.controls.append({'kind':'output-boundary','call':index,'expected_response_sha256':sha(full),'required_capacity':len(full)})
            for wcap in [0,1,32767,32768]:
                before=b'\x7b'*wcap;code,out,after,index=R.invoke(4,51300+n,'workspace-growth',wire,before,64)
                self.assertEqual(code,64);self.assertEqual(word(out,8),2);self.assertGreater(word(out,40),wcap)
                if wcap<32768:self.assertEqual(after,before)
                resumed,rc=R.complete(4,51400+n,wire,workspace=after+bytes(word(out,40)-len(after)),capacity=len(full),label='growth-resume')
                self.assertEqual(resumed,full)
                R.controls.append({'kind':'workspace-growth','call':index,'resume_calls':rc,'expected_response_sha256':sha(full)})
            dirty=b'\x7b'*65536
            for repeat in range(3):
                code,out,dirty,index=R.invoke(4,51500+n,'dirty-reuse',wire,dirty,len(full)+13)
                self.assertEqual((code,out),(64,full+b'\xa5'*13))
                R.controls.append({'kind':'dirty-reuse','call':index,'expected_response_sha256':sha(full)})


if __name__=='__main__':
    R=Recorder();outcome=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BatchPlanInputTests))
    result=R.finish(outcome.wasSuccessful());result.update(skipped=len(outcome.skipped),errors=len(outcome.errors),failures=len(outcome.failures))
    print(json.dumps(result,sort_keys=True));raise SystemExit(0 if outcome.wasSuccessful() else 1)
