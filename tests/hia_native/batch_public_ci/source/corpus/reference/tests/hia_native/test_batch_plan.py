"""Actual HIA batch planning, preserved diagnostics and original Rust corpus."""
from __future__ import annotations
import argparse,collections,copy,ctypes,gzip,hashlib,importlib.util,json,os,random,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
REFERENCE=Path(os.environ.get('HIA_REFERENCE_RUNTIME',ROOT))
sys.path.insert(0,str(Path(__file__).parent))
from batch_plan_harness import NativePlan,META,CAPACITY,INVALID,CHILD,sha
def load_reference(name):
    path=REFERENCE/'tests/hia_native'/('test_'+name+'.py')
    spec=importlib.util.spec_from_file_location('batch_reference_'+name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
endpoint_reference=load_reference('line_endpoint')
verify_reference=load_reference('line_verify')
U64=(1<<64)-1
def ep(value):
    if type(value) is int and -(1<<63)<=value<(1<<63):return endpoint_reference.frame(0,scalar=value)
    if type(value) in (int,float):return endpoint_reference.frame(1)
    if type(value) is str:return endpoint_reference.frame(2,value.encode())
    return endpoint_reference.frame(3,json.dumps(value,ensure_ascii=False,separators=(',',':'),sort_keys=True).encode())
def packet(operations,lines=(),path='file.txt',mode=1):
    path_raw=path.encode() if type(path) is str else b''
    line_bytes=b''.join(verify_reference.varint(len(line.encode()))+line.encode() for line in lines)
    records=bytearray()
    for item in operations:
        if type(item) is not dict:records.extend(bytes(72));continue
        operation=item.get('operation');start=item.get('start');end=item.get('end');content=item.get('content')
        fields=[operation.encode() if type(operation) is str else b'',b'' if start is None else ep(start),b'' if end is None else ep(end),content.encode() if type(content) is str else b'']
        records.extend(struct.pack('<9Q',1,int(type(operation) is str),int(start is not None),int(end is not None),int(type(content) is str),*map(len,fields)))
        records.extend(b''.join(fields))
    return struct.pack('<8s9Q',b'HBPLAN01',mode,int(type(path) is str),len(lines),len(operations),len(path_raw),len(line_bytes),len(records),0,0)+path_raw+line_bytes+records
def response(status,body=b'',count=0):return struct.pack('<8s5Q',b'HBPLR001',status,count,len(body),0,0)+body
def reference(operations,lines=(),path='file.txt',mode=1):
    def failure(value):return response(1,value.encode())
    if type(path) is not str:return failure("Missing required 'path' parameter for batch_edit")
    if not operations:return failure('Operations array is empty — nothing to do.')
    if len(operations)>50:return failure(f'Too many operations: {len(operations)} (max 50). Split into multiple calls.')
    if mode==0:return response(2)
    def parse(value):
        result=endpoint_reference.decoded(endpoint_reference.reference(ep(value)))
        if result['kind']=='error':raise ValueError(result['message'])
        return result
    def hint(value):
        if 1<=value<=len(lines):return f' — line {value} is currently `{value}:{verify_reference.hashed(lines[value-1])}` containing: '+lines[value-1].strip(endpoint_reference.WHITE_SPACE)
        return ''
    unresolved=[];errors=[]
    for index,item in enumerate(operations):
        try:
            if type(item) is not dict:raise ValueError('Operation must be an object')
            name=item.get('operation')
            if type(name) is not str:raise ValueError("Missing 'operation' field")
            if name not in ('insert','replace'):raise ValueError(f"Unsupported operation type: '{name}'. Supported operations: insert, replace")
            if item.get('start') is None:raise ValueError("Missing 'start' field")
            try:
                try:start=parse(item['start'])
                except ValueError as e:raise ValueError('invalid `start`: '+str(e)) from None
                end=None
                if name=='insert':
                    if start['kind']=='number' and start['number'] not in (0,-1):
                        n=start['number'];raise ValueError(f'insert anchor {n} is not verifiable: use a line id like "12:a3", or 0 (file start) / -1 (end)'+hint(n))
                else:
                    try:end=start if item.get('end') is None else parse(item['end'])
                    except ValueError as e:raise ValueError('invalid `end`: '+str(e)) from None
                    if start['kind']!='id' or end['kind']!='id':
                        hints=''.join(hint(v['number']) for v in (start,end) if v['kind']=='number')
                        raise ValueError('replace targets must be line ids like "12:a3" from view output, not plain numbers'+hints)
            except ValueError as e:raise ValueError('Invalid line target: '+str(e)) from None
            content=item.get('content')
            if type(content) is not str:raise ValueError("Missing 'content' field")
            if name=='insert' and content=='':content='\n'
            unresolved.append((index,name,start,end,content))
        except ValueError as error:errors.append(f'  op {index}: {error}')
    if errors:return failure(f'No operations were applied: {len(errors)} of {len(operations)} are malformed:\n'+'\n'.join(errors))
    resolved=[];errors=[]
    def verified(value):
        result=verify_reference.reference(1,value['line'],expected=value['hash'],lines=lines)
        if struct.unpack_from('<Q',result,8)[0]:return None,result[40:].decode()
        return struct.unpack_from('<Q',result,16)[0],None
    for index,name,start,end,content in unresolved:
        if name=='insert':
            if start['kind']=='number':first=0 if start['number']==0 else len(lines);error=None
            else:first,error=verified(start)
            last=0
        else:
            first,a=verified(start);last,b=verified(end)
            error='\n'.join(x for x in (a,b) if x is not None) if a is not None or b is not None else None
            if error is None and first>last:error=f'Range is reversed: start "{start["line"]}:{start["hash"]}" is after end "{end["line"]}:{end["hash"]}"; swap them.'
        if error is not None:errors.append(f'op {index}: {error}')
        else:resolved.append((index,1 if name=='insert' else 2,first,last,content.encode()))
    if errors:return failure(f'No operations were applied to {path}: {len(errors)} of {len(operations)} have stale or invalid targets:\n'+'\n---\n'.join(errors))
    body=b''.join(struct.pack('<6Q',index,kind,kind,first,last,len(content))+content for index,kind,first,last,content in resolved)
    return response(0,body,len(resolved))

def initial_cases():
    values=[None,{},[],True,False,0,1,-1,-2,(1<<63)-1,-(1<<63),1<<63,1.0,'','0','-1','+1',' 1 ','\u3000+1:AB\u00a0','1:00','2:ff','0:00','-1:00','18446744073709551615:ff','18446744073709551616:ff','1:gg','1:000','1:aB','x','1:ab:cd','\x00','１２:ab','²',{'a':1},[1,'x']]
    lines=['one',' two\r','same','','same','last😀']
    for path in [None,0,'','some\npath']:
        for count in [0,1,50,51]:yield 'early_admission',{'operations':[None]*count,'path':path,'mode':0}
    items=[None,[],{}, {'operation':7},{'operation':'Insert'},{'operation':'what\n😀'},{'operation':'insert'},{'operation':'replace','start':None},{'operation':'replace','start':'1:ab'},{'operation':'insert','start':0,'content':[]},{'operation':'replace','start':1,'end':'bad','content':''}]
    yield 'ordered_malformed',{'operations':items,'lines':lines}
    for name in ['insert','replace']:
        for value in values:
            for end in [None,'bad',1,'2:ff']:yield 'endpoint_order',{'operations':[{'operation':name,'start':value,'end':end,'content':''}],'lines':lines}
    for line in range(1,len(lines)+1):
        for name in ['insert','replace']:
            for end in [None,f'1:{verify_reference.hashed(lines[0])}',f'{len(lines)}:{verify_reference.hashed(lines[-1])}']:
                yield 'resolved_plans',{'operations':[{'operation':name,'start':f'{line}:{verify_reference.hashed(lines[line-1])}','end':end,'content':'a\r\nb\n'}],'lines':lines}
    for count in [1,2,49,50]:
        for target in [0,-1,1,'1:xx','1:00','99:ff','1:'+verify_reference.hashed(lines[0])]:
            yield 'full_operation_count',{'operations':[{'operation':'replace' if type(target) is str else 'insert','start':target,'content':''} for _ in range(count)],'lines':lines}

def random_cases():
    rng=random.Random(0xBA7C401);alphabet=['','a','same',' ', '\t','\r','é','😀','\x00','\u3000','{}','"','|']
    for trial in range(2200):
        lines=[''.join(rng.choice(alphabet) for _ in range(rng.randrange(9))) for _ in range(rng.randrange(18))]
        endpoints=[None,0,-1,1,-2,1<<63,1.0,True,[],{},'bad','0:aa',f'{U64}:FF']
        endpoints.extend(f'{i}:{verify_reference.hashed(line)}' for i,line in enumerate(lines,1))
        endpoints.extend(f'{rng.randrange(22)}:{rng.randrange(256):02x}' for _ in range(8))
        ops=[]
        for _ in range(rng.choice([1,1,2,3,4,7,12,50])):
            if rng.randrange(29)==0:ops.append(None);continue
            op={'operation':rng.choice(['insert','replace','replace','replace']) if trial%9 else rng.choice(['',None,'nope']),'start':rng.choice(endpoints),'end':rng.choice(endpoints),'content':rng.choice(['','x','\r\na\n','é😀',None])}
            if rng.randrange(4)==0:op.pop('end')
            ops.append(op)
        yield 'ordered_random',{'operations':ops,'lines':lines,'path':rng.choice(['','file.txt','a\0b','空间/\npath'])}

def resolved_cases():
    rng=random.Random(0x5A1E0123)
    for _ in range(600):
        lines=[rng.choice(['','a','same','😀',' x '])+str(n%7) for n in range(rng.randrange(1,60))]
        ops=[]
        for n in range(rng.choice([1,2,3,7,50])):
            def target():
                line=rng.randrange(1,len(lines)+1)
                if rng.randrange(7)==0:line=len(lines)+rng.randrange(1,9)
                hash=verify_reference.hashed(lines[line-1]) if line<=len(lines) and rng.randrange(4) else f'{rng.randrange(256):02x}'
                return f'{line}:{hash}'
            ops.append({'operation':rng.choice(['insert','replace']),'start':target(),'end':target(),'content':rng.choice(['','new','\r\nx\n'])})
        yield 'all_targets_and_relocation',{'operations':ops,'lines':lines}
    lines=[str(i) for i in range(100)]
    yield 'all_100_verification_slots',{'operations':[{'operation':'replace','start':f'{2*n+1}:00','end':f'{2*n+2}:00','content':''} for n in range(50)],'lines':lines}
    yield 'all_100_hint_slots',{'operations':[{'operation':'replace','start':2*n+1,'end':2*n+2,'content':''} for n in range(50)],'lines':lines}

def invalid_frames():
    valid=packet([{'operation':'insert','start':0,'content':'x'}],lines=['x'],path='p')
    for n in range(80):yield valid[:n]
    yield b'INVALID!'+valid[8:]
    for off,value in [(8,2),(16,2),(24,U64),(32,U64),(40,U64),(48,U64),(56,U64),(64,1),(72,1)]:
        bad=bytearray(valid);struct.pack_into('<Q',bad,off,value);yield bytes(bad)
    yield valid+b'x';yield valid[:-1]
    for raw in [b'\xff',b'\xc0\xaf',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',b'\xf0\x9f\x98']:
        line=verify_reference.varint(len(raw))+raw;ops=valid[83:]
        yield struct.pack('<8s9Q',b'HBPLAN01',1,1,1,1,1,len(line),len(ops),0,0)+b'p'+line+ops
    for encoded in [b'\x80\x00',b'\x81\x00x',b'\x80',b'\xff'*9+b'\x02',b'\x80'*10+b'\x00']:
        ops=valid[83:];yield struct.pack('<8s9Q',b'HBPLAN01',1,1,1,1,1,len(encoded),len(ops),0,0)+b'p'+encoded+ops
    for offset,value in [(83,2),(91,2),(99,2),(107,2),(115,2),(123,U64),(131,U64),(139,U64),(147,U64),(161,4),(169,4),(177,1)]:
        bad=bytearray(valid);struct.pack_into('<Q',bad,offset,value);yield bytes(bad)

class Corpus:
    def __init__(self,directory):
        self.directory=Path(directory);self.directory.mkdir(parents=True,exist_ok=False)
        self.requests=gzip.GzipFile(filename=str(self.directory/'requests.bin.gz'),mode='wb',mtime=0)
        self.outputs=gzip.GzipFile(filename=str(self.directory/'native-output.bin.gz'),mode='wb',mtime=0)
        self.history=gzip.GzipFile(filename=str(self.directory/'history.jsonl.gz'),mode='wb',mtime=0)
        self.rows=0;self.controls=0;self.domains=collections.Counter()
    def record(self,category,wire,result,reference=True,extra=None):
        row={key:value for key,value in result.items() if key not in ('output','prefix')}
        row.update(category=category,ordinal=self.rows+self.controls,reference=reference,input_bytes=len(wire),input_sha256=sha(wire),prefix_hex=result['prefix'].hex())
        if extra is not None:row['extra']=extra
        if reference:
            self.requests.write(struct.pack('<Q',len(wire)));self.requests.write(wire)
            if result['output'] is not None:self.outputs.write(struct.pack('<Q',len(result['output'])));self.outputs.write(result['output'])
            self.rows+=1
        else:
            row['input_hex']=wire.hex();row['output_hex']=(result['output'] or b'').hex();self.controls+=1
        self.domains[category]+=1
        self.history.write(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n')
    def close(self):
        self.requests.close();self.outputs.close();self.history.close()

def file_record(path):
    packed=path.read_bytes();digest=hashlib.sha256();size=0
    with gzip.open(path,'rb') as source:
        while value:=source.read(1<<20):digest.update(value);size+=len(value)
    return {'file':path.name,'gzip_sha256':sha(packed),'gzip_bytes':len(packed),'raw_sha256':digest.hexdigest(),'raw_bytes':size}

def ordinary(native,corpus):
    for category,case in (*initial_cases(),*random_cases(),*resolved_cases()):
        expected=reference(**case);wire=packet(**case);result=native.invoke(wire,len(expected)+7)
        assert result['output']==expected,(category,case,result['code'],result['output'],expected)
        if b'are malformed:' in expected:assert all(t['target']!=3 for t in result['trace'])
        corpus.record(category,wire,result)

def controls(native,corpus):
    for wire in invalid_frames():
        result=native.invoke(wire,1024);assert result['code']==INVALID,(wire.hex(),result)
        assert not result['trace'];corpus.record('frame_refusal',wire,result,False)
    examples=[{'operations':[],'mode':0}, {'operations':[None]},
        {'operations':[{'operation':'insert','start':0,'content':''}]},
        {'operations':[{'operation':'replace','start':1,'end':1,'content':''}],'lines':['x']},
        {'operations':[{'operation':'replace','start':'1:00','content':''}],'lines':['x']}]
    for case in examples:
        expected=reference(**case);wire=packet(**case)
        for capacity in [0,47,len(expected)-1]:
            result=native.invoke(wire,capacity);assert result['code']==CAPACITY
            corpus.record('capacity_refusal',wire,result,False)
        result=native.invoke(wire,len(expected));assert result['output']==expected
        corpus.record('exact_capacity',wire,result)
        result=native.invoke(wire,len(expected),workspace=META+255);assert result['code']==CAPACITY
        corpus.record('workspace_refusal',wire,result,False)
    wire=packet([{'operation':'replace','start':'1:00','end':'2:00','content':''}],lines=['x','y'])
    fields=[(0,0),(8,0),(16,3),(24,1),(32,0),(40,0),(48,1),(56,0),(64,0),(72,1),(80,31),(80,1<<32|32),(88,0),(96,0),(104,3),(120,1),(128,0)]
    for off,value in fields:
        applied=[]
        def fault(state,off=off,value=value):
            if not applied:state['put'](state['footer']+off,value);applied.append(1)
        result=native.invoke(wire,4096,fault=fault);assert result['code']==CHILD,(off,value,result)
        assert applied;corpus.record('child_contract_refusal',wire,result,False,{'footer_offset':off,'value':value})
    for phase in [1,2,3,4]:
        for offset,value in [(0,0),(8,7),(24,U64)]:
            applied=[]
            def fault(state,phase=phase,offset=offset,value=value):
                if state['phase']==phase and not applied:state['put'](state['destination']+offset,value);applied.append(1)
            result=native.invoke(wire,4096,fault=fault);assert applied and result['code']==CHILD,(phase,offset,result)
            corpus.record('child_result_refusal',wire,result,False,{'phase':phase,'offset':offset,'value':value})

def large(native,corpus):
    maximum=5<<20
    for mode in ['plain','stale']:
        content='x'*maximum if mode=='plain' else '😀'*(maximum//4)
        raw=content.encode();value=verify_reference.hashed(raw)
        target=1 if mode=='plain' else '1:'+('00' if value!='00' else '01')
        operations=[{'operation':'replace','start':target,'end':target,'content':''} for _ in range(50)]
        wire=packet(operations,lines=[content])
        if mode=='plain':
            prefix=b'No operations were applied: 50 of 50 are malformed:\n'
            hint=f' — line 1 is currently `1:{value}` containing: '.encode()
            def body_parts():
                yield prefix
                for index in range(50):
                    if index:yield b'\n'
                    yield f'  op {index}: Invalid line target: replace targets must be line ids like "12:a3" from view output, not plain numbers'.encode()
                    yield hint;yield raw;yield hint;yield raw
        else:
            diagnostic=verify_reference.reference(1,1,expected=target.split(':')[1],lines=[content])[40:]
            prefix=b'No operations were applied to file.txt: 50 of 50 have stale or invalid targets:\n'
            def body_parts():
                yield prefix
                for index in range(50):
                    if index:yield b'\n---\n'
                    yield f'op {index}: '.encode();yield diagnostic;yield b'\n';yield diagnostic
        size=sum(len(piece) for piece in body_parts())
        header=struct.pack('<8s5Q',b'HBPLR001',1,0,size,0,0)
        expected=hashlib.sha256(header)
        for piece in body_parts():expected.update(piece)
        result=native.invoke(wire,size+48,sink=corpus.outputs)
        assert result['code']==size+48 and result['output_sha256']==expected.hexdigest() and result['prefix']==header
        assert sum(t['target']==2 for t in result['trace'])==100
        assert sum(t['target']==3 for t in result['trace'])==(0 if mode=='plain' else 1)
        corpus.record('maximum_50_double_'+mode,wire,result,extra={'file_bytes':maximum,'operations':50,'endpoint_diagnostic_copies':100,'calculated_body_bytes':size,'expected_sha256':expected.hexdigest()})
        refusal=native.invoke(wire,1024);assert refusal['code']==CAPACITY
        corpus.record('maximum_output_capacity_refusal',wire,refusal,False,{'kind':mode})
        print(json.dumps({'phase':'maximum_'+mode,'status':'PASS','output_bytes':result['output_bytes'],'workspace_bytes':result['workspace_capacity']}),flush=True)
    count=maximum
    target=f'{count}:{verify_reference.hashed("")}'
    base=packet([{'operation':'replace','start':target,'content':''}],path='p')
    wire=struct.pack('<8s9Q',b'HBPLAN01',1,1,count,1,1,count,len(base)-81,0,0)+b'p'+bytes(count)+base[81:]
    expected=response(0,struct.pack('<6Q',0,2,2,count,count,0),1)
    result=native.invoke(wire,len(expected));assert result['output']==expected
    corpus.record('maximum_empty_lines',wire,result,extra={'line_count':count})
    for category,case in [
        ('maximum_insert_content',{'operations':[{'operation':'insert','start':0,'content':'😀'*(maximum//4)}]}),
        ('maximum_endpoint_text',{'operations':[{'operation':'replace','start':'0'*(maximum-3)+':qq','content':''}]}),
        ('maximum_operation_text',{'operations':[{'operation':'x'*maximum,'start':0,'content':''}]})]:
        wire=packet(**case);expected=reference(**case);result=native.invoke(wire,len(expected))
        assert result['output']==expected;corpus.record(category,wire,result)

def actual_elf(manifest,corpus):
    metadata=json.loads(Path(manifest).read_bytes());exe=Path(manifest).parent/metadata['executable']
    assert sha(exe.read_bytes())==metadata['executable_sha256']
    cases=list(initial_cases())[:16]+[next((name,case) for name,case in initial_cases() if name==category) for category in ['ordered_malformed','endpoint_order','resolved_plans','full_operation_count']]
    frames=[packet(**case).hex().encode() for _,case in cases]
    bounded=packet([{'operation':'replace','start':1,'end':1,'content':''} for _ in range(50)],lines=['x'*(32768)])
    frames.append(bounded.hex().encode())
    result=subprocess.run([str(exe),'--local-read-profile','/batch-plan-fixture'],input=b'\n'.join(frames)+b'\n',capture_output=True,timeout=30)
    assert result.returncode==0,(result.returncode,result.stderr)
    outputs=result.stdout.splitlines();assert len(outputs)==len(cases)+1
    observations=[]
    for (category,case),frame,output in zip(cases,frames[:-1],outputs[:-1],strict=True):
        code,payload=output.split(b':');actual=bytes.fromhex(payload.decode());expected=reference(**case)
        assert int(code,16)==len(expected) and actual==expected
        observations.append({'category':category,'input_hex':frame.decode(),'wire_output':output.decode(),'output_sha256':sha(actual),'reference':True})
    code,payload=outputs[-1].split(b':');assert int(code,16)==CAPACITY and payload==b''
    observations.append({'category':'static_adapter_capacity','input_hex':frames[-1].decode(),'wire_output':outputs[-1].decode(),'output_sha256':sha(b''),'reference':False})
    raw=(json.dumps({'schema':'hepta.runtime.batch-plan.elf-observation.v1','status':'PASS','processes':1,'requests':len(frames),'reference_requests':len(cases),'exit_code':result.returncode,'stderr_hex':result.stderr.hex(),'manifest_sha256':sha(Path(manifest).read_bytes()),'executable_sha256':sha(exe.read_bytes()),'rows':observations},sort_keys=True,indent=2)+'\n').encode()
    (corpus.directory/'elf-observation.json').write_bytes(raw)
    return {'requests':len(frames),'reference_requests':len(cases),'processes':1,'observation_sha256':sha(raw)}

def run(args):
    bundle_sha=None
    if args.bundle is not None:
        from hia_native_batch_plan_build import inspect_bundle
        bundle=inspect_bundle(args.bundle,source_root=ROOT,reference_root=REFERENCE)
        args.manifest,args.endpoint_manifest,args.verify_manifest=(bundle['manifests'][i] for i in (1,2,3))
        args.elf_manifest=bundle['elf_manifest'];bundle_sha=bundle['manifest_sha256']
    elif not args.small_only:
        raise AssertionError('complete qualification requires the source-bound build bundle')
    manifests={1:args.manifest,2:args.endpoint_manifest,3:args.verify_manifest}
    native=NativePlan(manifests,source_root=ROOT,reference_root=REFERENCE)
    corpus=Corpus(args.corpus);started=time.monotonic();status='FAIL';elf={}
    try:
        ordinary(native,corpus)
        controls(native,corpus)
        if not args.small_only:
            large(native,corpus)
            if args.elf_manifest is None:raise AssertionError('complete qualification requires the actual composed ELF')
            elf=actual_elf(args.elf_manifest,corpus)
        status='PASS'
    finally:
        corpus.close();native.close()
        report={'schema':'hepta.runtime.batch-plan.native-tests.v1','status':status,'complete_domain':not args.small_only,'counts':native.counts,'reference_rows':corpus.rows,'control_rows':corpus.controls,'domains':dict(sorted(corpus.domains.items())),'actual_elf':elf,'loaded_artifacts':native.loaded,'bundle_manifest_sha256':bundle_sha,'seconds':time.monotonic()-started}
        proof=json.loads((ROOT/'native/batch_plan_composition.json').read_bytes())
        from hia_native_batch_plan_qualification import SOURCE_FILES,REFERENCE_FILES
        sources={name:sha((ROOT/name).read_bytes()) for name in SOURCE_FILES}
        reference_sources={name:sha((REFERENCE/name).read_bytes()) for name in REFERENCE_FILES}
        metadata={'schema':'hepta.runtime.batch-plan.native-corpus.v1','report':report,'sources':sources,'reference_sources':reference_sources,'original_sources':proof['original_sources'],'requests':file_record(corpus.directory/'requests.bin.gz'),'native_output':file_record(corpus.directory/'native-output.bin.gz'),'history':file_record(corpus.directory/'history.jsonl.gz')}
        (corpus.directory/'native-corpus.json').write_text(json.dumps(metadata,sort_keys=True,indent=2)+'\n')
        print(json.dumps(report,sort_keys=True),flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,default=os.environ.get('HIA_BATCH_PLAN_BUNDLE'))
    parser.add_argument('--manifest',type=Path,default=os.environ.get('HIA_BATCH_PLAN_MANIFEST'))
    parser.add_argument('--endpoint-manifest',type=Path,default=os.environ.get('HIA_BATCH_ENDPOINT_MANIFEST'))
    parser.add_argument('--verify-manifest',type=Path,default=os.environ.get('HIA_BATCH_VERIFY_MANIFEST'))
    parser.add_argument('--elf-manifest',type=Path,default=os.environ.get('HIA_BATCH_PLAN_ELF_MANIFEST'))
    parser.add_argument('--corpus',type=Path,default=os.environ.get('HIA_BATCH_PLAN_CORPUS_DIR'))
    parser.add_argument('--small-only',action='store_true',help='development only; cannot satisfy full qualification')
    args=parser.parse_args()
    if not args.corpus or (not args.bundle and not all((args.manifest,args.endpoint_manifest,args.verify_manifest))):parser.error('a qualified build bundle (or explicit development images) and absent corpus directory are required')
    run(args)
