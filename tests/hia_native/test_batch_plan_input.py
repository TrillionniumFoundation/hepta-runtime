"""Execute native owners first and retain every complete borrowed byte span."""
from pathlib import Path
import ctypes
import gzip
import hashlib
import json
import os
import queue
import threading
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


def close_all(resources):
    error=None
    for resource in resources:
        if resource is None:continue
        try:resource.close()
        except BaseException as failed:
            if error is None:error=failed
    if error is not None:raise RuntimeError('batch transport resource close failed') from error


def join_all(workers):
    error=None
    for worker in workers:
        # Thread.start can be interrupted after registering a pending thread.
        # Wait for that start before join; skip only a never-started object.
        while worker.ident is None and worker in threading.enumerate():
            try:worker._started.wait()
            except BaseException as failed:
                if error is None:error=failed
        if worker.ident is None:continue
        while True:
            try:
                worker.join()
                break
            except BaseException as failed:
                if error is None:error=failed
                if not worker.is_alive():break
    if error is not None:raise RuntimeError('batch transport worker join interrupted') from error


class Transport:
    def __init__(self,sink):
        self.sink=sink;self.modules={};self.planner=None
        self.capture_ids=[];self.current_case=0;self.current_label='';self.rows=[]
        try:
            for owner in range(1,5):
                member=sink.members[NAMES[owner]]
                self.modules[owner]=NativeModule(Path(member['manifest']),manifest_sha256=member['manifest_sha256'])
            # Retain the partially initialized planner so every admitted map
            # can be closed even if a later member fails admission.
            self.planner=NativePlan.__new__(NativePlan)
            NativePlan.__init__(self.planner,{owner:sink.members[name]['manifest'] for owner,name in
                [(1,'plan'),(2,'endpoint'),(3,'verify')]},source_root=ROOT,reference_root=ROOT)
            for target in (1,2,3):
                module=self.planner.modules[target];real=module._entry
                def captured(source,size,output,capacity,work,amount,*,target=target,real=real):
                    self.sink.check_capture()
                    wire=ctypes.string_at(source,size);before=ctypes.string_at(work,amount);old=ctypes.string_at(output,capacity)
                    code=real(source,size,output,capacity,work,amount)
                    self.record(target+4,self.current_case,self.current_label,wire,before,old,code,ctypes.string_at(output,capacity),ctypes.string_at(work,amount))
                    return code
                module._entry=captured
        except BaseException:
            self.close()
            raise
    def close(self):
        close_all([*self.modules.values(),*getattr(self.planner,'modules',{}).values()])
    def record(self,*args):
        index=self.sink.record(*args);self.capture_ids.append(index);return index
    def invoke(self,owner,case_id,label,wire,work,capacity):
        self.sink.check_capture()
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
        start=len(self.capture_ids);capacity=32768;attempts=[]
        self.current_case=case_id;self.current_label='planner'
        while True:
            result=self.planner.invoke(wire,capacity)
            attempts.append({key:value for key,value in result.items() if key not in ('output','prefix')})
            if result['code']==CAPACITY:
                assert capacity<self.planner.modules[1].metadata['output_capacity']
                capacity=min(capacity*2,self.planner.modules[1].metadata['output_capacity']);continue
            assert result['code']<0xffff0000 and result['output'][:8]==b'HBPLR001',result
            return {'calls':self.capture_ids[start:],'attempts':attempts,
                    'response_bytes':len(result['output']),'response_sha256':sha(result['output'])}


class Recorder:
    def __init__(self):
        self.output=Path(os.environ['HIA_BATCH_PLAN_INPUT_CAPTURE_DIR']).resolve();self.output.mkdir(parents=True,exist_ok=False)
        self.bundle=Path(os.environ['HIA_BATCH_PLAN_INPUT_MEMBERS']).resolve()
        self.members=json.loads(self.bundle.read_bytes())['members']
        self.stream=None;self.expected=None;self.original=None;self.transports=[];self.semantic_workers=[]
        self.semantic_abort=threading.Event();self.capture_stop=threading.Event()
        self.index=[];self.rows=[];self.controls=[];self.offset=0
        self.capture_calls=0;self.capture_error=None;self.capture_lock=threading.Lock()
        self.capture_queue=queue.Queue(maxsize=2)
        self.capture_worker=threading.Thread(target=self.write_records,name='hia-batch-evidence',daemon=True)
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
        try:
            self.stream=gzip.open(self.output/'calls.bin.gz','wb',compresslevel=1)
            self.expected=(self.output/'native-results.bin').open('xb')
            self.original=(self.output/'original-input.jsonl').open('xb')
            for _ in range(2):self.transports.append(Transport(self))
            self.capture_worker.start()
        except BaseException:
            self.capture_stop.set()
            try:join_all([self.capture_worker])
            finally:close_all([*self.transports,self.stream,self.expected,self.original])
            raise
    def check_capture(self):
        if self.capture_error is not None:raise RuntimeError('complete evidence writer failed') from self.capture_error
        if self.capture_stop.is_set():raise RuntimeError('complete evidence writer is stopping')
    def record(self,owner,case_id,label,wire,before,old,code,out,after):
        if not all(type(part)is bytes for part in (wire,before,old,out,after)):
            raise TypeError('capture requires complete immutable native snapshots')
        # The enqueue belongs to the same lock as its ID and offset. Each
        # transport retains only its own IDs; complete records may interleave.
        with self.capture_lock:
            self.check_capture()
            index=self.capture_calls+1
            header=struct.pack('<8Q',index,owner,case_id,code,len(wire),len(old),len(before),0)
            size=sum(map(len,(header,wire,before,old,out,after)))
            row={'call':index,'owner':owner,'case_id':case_id,'label':label,'offset':self.offset,'bytes':size,'return_code':code,
                 'input_bytes':len(wire),'output_capacity':len(old),'workspace_capacity':len(before)}
            self.capture_queue.put((row,header,wire,before,old,out,after))
            self.capture_calls=index;self.offset+=size
            self.check_capture()
            return index
    def write_records(self):
        while True:
            try:item=self.capture_queue.get(timeout=.05)
            except queue.Empty:
                if self.capture_stop.is_set():return
                continue
            try:
                if item is None:return
                if self.capture_error is not None:continue
                row,header,wire,before,old,out,after=item
                digest=hashlib.sha256();size=0
                for part in (header,wire,before,old,out,after):
                    self.stream.write(part);digest.update(part);size+=len(part)
                if size!=row['bytes'] or row['call']!=len(self.index)+1:
                    raise ValueError('complete capture record order or extent differs')
                row.update(input_sha256=sha(wire),before_sha256=sha(before),output_before_sha256=sha(old),
                           output_sha256=sha(out),after_sha256=sha(after),record_sha256=digest.hexdigest())
                self.index.append(row)
            except BaseException as error:
                self.capture_error=error
            finally:
                self.capture_queue.task_done()
    def invoke(self,*args,**kwargs):return self.transports[0].invoke(*args,**kwargs)
    def complete(self,*args,**kwargs):return self.transports[0].complete(*args,**kwargs)
    def semantic(self,run_cases,rows):
        # Whole cases, including both modes and every continuation, stay with
        # one transport. Byte weights place the dense tail on both workers.
        weights=[4096+len(row['raw_json'].encode())+len(row['original_raw'].encode()) for row in rows]
        if len(weights)<2:raise ValueError('two nonempty case ranges are required')
        total=sum(weights);prefix=0;choices=[]
        for cut,weight in enumerate(weights[:-1],1):
            prefix+=weight;choices.append((abs(2*prefix-total),cut))
        cut=min(choices)[1];groups=(rows[:cut],rows[cut:])
        parts=[(self.output/('semantic-'+str(slot)+'.native.part'),
                self.output/('semantic-'+str(slot)+'.original.part')) for slot in range(2)]
        failures=[None,None]
        def worker(slot):
            if self.semantic_abort.is_set():return
            transport=self.transports[slot]
            try:
                with parts[slot][0].open('xb') as expected,parts[slot][1].open('xb') as original:
                    transport.expected=expected;transport.original=original
                    run_cases(transport,groups[slot])
            except BaseException as error:failures[slot]=error
        try:
            for slot in range(2):
                thread=threading.Thread(target=worker,args=(slot,),name='hia-batch-cases-'+str(slot))
                self.semantic_workers.append(thread);thread.start()
        except BaseException:
            self.semantic_abort.set()
            raise
        finally:
            join_all(self.semantic_workers)
        for error in failures:
            if error is not None:raise RuntimeError('batch case range failed') from error
        self.check_capture()
        # Only the two small semantic streams are merged. The full borrowed
        # byte capture was already written once, in its actual call order.
        for slot,paths in enumerate(parts):
            for path,destination in zip(paths,(self.expected,self.original)):
                with path.open('rb') as source:
                    while chunk:=source.read(1<<20):destination.write(chunk)
            self.rows.extend(self.transports[slot].rows)
        self.expected.flush();self.original.flush()
        self.check_capture()
        for paths in parts:
            for path in paths:path.unlink()
    def finish(self,success):
        join_error=None;close_error=None
        try:join_all(self.semantic_workers)
        except BaseException as error:join_error=error
        self.capture_stop.set()
        try:
            self.capture_queue.join()
        finally:
            try:join_all([self.capture_worker])
            finally:
                try:close_all([*self.transports,self.stream,self.expected,self.original])
                except BaseException as error:close_error=error
        if self.capture_error is not None:raise RuntimeError('complete evidence writer failed') from self.capture_error
        if join_error is not None:raise join_error
        if close_error is not None:raise close_error
        if len(self.index)!=self.capture_calls:raise ValueError('native calls omitted from complete capture')
        assert self.sources=={p:pin(p)['sha256'] for p in self.sources}
        assert self.artifacts=={p:pin(p)['sha256'] for p in self.artifacts}
        for name,rows in [('calls.jsonl',self.index),('native-cases.jsonl',self.rows),('controls.jsonl',self.controls)]:
            (self.output/name).write_bytes(b''.join(canonical(row) for row in rows))
        planner_counts={key:sum(transport.planner.counts[key] for transport in self.transports)
                        for key in self.transports[0].planner.counts}
        result={'schema':'hepta.runtime.batch-plan-input-native.v1','status':'PASS' if success else 'FAIL','test_groups':3,
                'semantic_inputs':len(self.rows),'semantic_records':sum(len(row['modes']) for row in self.rows),
                'successful_inputs':sum(row['typed_status']==0 for row in self.rows),
                'native_calls':len(self.index),'owner_calls':{name:sum(row['owner']==owner for row in self.index) for owner,name in NAMES.items()},
                'controls':len(self.controls),'planner_counts':planner_counts,'full_stream_bytes':self.offset,
                'source_sha256':self.sources,'artifact_sha256':self.artifacts,'members':str(self.bundle),'python':sys.executable,
                'pid':os.getpid(),'execution_source_root':str(ROOT),'execution_output_root':str(self.output.parent),
                'original_reference_status':'NOT_RUN','original_batch_handler_executed':False,'effects_executed':False,'public_route_replaced':False}
        (self.output/'result.json').write_bytes(canonical(result));return result


def request(params,editable=b'',mode=0):return b'HBPIQ002'+struct.pack('<7Q',mode,len(params),len(editable),0,0,0,0)+params+editable
def changed(wire,at,value):return wire[:at]+struct.pack('<Q',value)+wire[at+8:]
R=None


class BatchPlanInputTests(unittest.TestCase):
    def test_01_native_typed_and_editable_pipeline(self):
        R.semantic(self.run_cases,list(cases()))
    def run_cases(self,R,selected):
        for row in selected:
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
