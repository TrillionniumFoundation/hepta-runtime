"""Read every caller buffer and original byte without launching semantic code."""
from __future__ import annotations
import argparse,functools,hashlib,io,json,math,re,struct,sys,tarfile,tomllib
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
from caller_worker_evidence import verify_process,packets
from bridge_check import admit_bridge
B3='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
TIME=re.compile(rb'("native_operation_wall_seconds":)(-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)(?=[,}])')
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def get(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def read(path):return json.loads(path.read_bytes())
def source(package):
    manifest=read(package/'package-manifest.json');actual={p.relative_to(package).as_posix() for p in package.rglob('*') if p.is_file()}
    assert actual==set(manifest['files'])|{'package-manifest.json'}
    for name,expected in manifest['files'].items():
        p=package/name;assert not p.is_symlink() and pin(p.read_bytes())==expected,name
    return pin((package/'package-manifest.json').read_bytes())
def normalized(raw):
    value=json.loads(raw);assert len(value)==36 and math.isfinite(value['native_operation_wall_seconds']) and value['native_operation_wall_seconds']>=0
    matches=list(TIME.finditer(raw));assert len(matches)==1;m=matches[0]
    return raw[:m.start(2)]+b'0'+raw[m.end(2):]
def build_check(package,build):
    report=read(build/'build.json');assert report['status']=='BUILD_PASS' and report['fresh_components']==3 and report['reused_components']==0
    assert set(report['files'])=={'bellman_call','bellman_params_callable','bellman_diagnostic_callable'}
    complete={}
    for p in build.rglob('*'):
        assert not p.is_symlink()
        if p.is_file():complete[p.relative_to(build).as_posix()]=pin(p.read_bytes())
    for name in ('B1.image.bin','B2.image.bin','B3.image.bin'):
        assert complete['bootstrap/'+name]==dict(bytes=673413,sha256=B3)
    for name,row in report['files'].items():
        root=build/'modules'/name;raw=(root/'manifest.json').read_bytes();assert pin(raw)['sha256']==row['sha256'];m=json.loads(raw)
        assert m['buffer_profile']=='batch-plan.v1' and m['compiler_sha256']==B3 and m['standalone'] is None
        original=(package/'source/native'/(name+'.hepta')).read_bytes();image=(root/m['image']).read_bytes()
        assert (root/m['source']).read_bytes()==original==(root/'module.input.bin').read_bytes()
        assert pin(original)['sha256']==row['source_sha256']==m['source_sha256']
        assert pin(image)['sha256']==row['image_sha256']==m['image_sha256']
        receipt=read(root/'module.receipt.json');output=(root/'module.output.bin').read_bytes()
        assert receipt['status']=='returned' and receipt['result_u64']==receipt['core_u32']==len(image)
        assert receipt['source_sha256']==receipt['input_sha256']==m['source_sha256']
        assert receipt['produced_sha256']==m['image_sha256'] and receipt['image_sha256']==B3
        assert receipt['output_sha256']==pin(output)['sha256'] and output[:len(image)]==image
        assert receipt['source_unchanged'] is True and not (root/'module.stderr.log').read_bytes()
    return dict(files=len(complete),logical_bytes=sum(p['bytes'] for p in complete.values()),fresh_images=3)

class Blobs:
    def __init__(self,path,rows,actions):
        self.path=path;self.wanted={}
        def visit(value):
            if isinstance(value,dict):
                if set(value)=={'bytes','sha256'}:
                    digest=value['sha256'];assert len(digest)==64 and all(c in '0123456789abcdef' for c in digest)
                    assert digest not in self.wanted or self.wanted[digest]==value;self.wanted[digest]=value
                else:
                    for child in value.values():visit(child)
            elif isinstance(value,list):
                for child in value:visit(child)
        visit(rows);visit(actions)
    def finish(self):
        actual={p.name for p in self.path.iterdir()};assert actual==set(self.wanted),(len(actual),len(self.wanted),actual-set(self.wanted))
        for name,expected in self.wanted.items():
            p=self.path/name;assert p.is_file() and not p.is_symlink() and pin(p.read_bytes())==expected
    @functools.lru_cache(maxsize=128)
    def fetch(self,digest):return (self.path/digest).read_bytes()
    def __call__(self,identity):
        assert self.wanted[identity['sha256']]==identity
        return self.fetch(identity['sha256'])

def verify_group(package,output,component):
    report=read(output/'report.json');assert report['status']=='COMPOSITION_PASS_REQUIRES_FRESH_ORIGINAL'
    assert report['source_manifest']==source(package)
    group=report['group'];domain=read(package/'domain.json');expected=[(i,r) for i,r in enumerate(domain['cases']) if r['group']==group]
    assert report['case_count']==len(report['cases'])==len(expected)==(680 if group=='ordinary' else 3)
    assert report['timeout_seconds']==domain[group+'_deadline_seconds'] and 0<=report['wall_seconds']<=report['timeout_seconds']
    assert report['whole_runtime_replaced'] is False and report['public_handler_qualified'] is False and report['full_original_handler_compared'] is False
    calls=[json.loads(l) for l in (output/'calls.jsonl').read_bytes().splitlines()]
    actions=[json.loads(l) for l in (output/'actions.jsonl').read_bytes().splitlines()]
    assert pin((output/'calls.jsonl').read_bytes())==report['calls'] and pin((output/'actions.jsonl').read_bytes())==report['actions']
    assert [x['index'] for x in calls]==list(range(report['actual_calls']))
    assert [x['index'] for x in actions]==list(range(report['actual_actions']))
    blobs=Blobs(output/'blobs',[calls,report['cases'],report['commands']],actions);used_calls=set();used_actions=set();used_commands=set();results={}
    for (index,declared),case in zip(expected,report['cases']):
        assert (case['index'],case['name'],case['group'],case['parameter_status'])==(index,declared['name'],group,declared['status'])
        request=blobs(case['request']);assert request[:8]==b'HBLCLQ01' and get(request,8)==1 and get(request,16)==index+1
        assert get(request,24)==len(request)-64 and request[32:64]==bytes(32) and pin(request[64:])==declared['canonical']
        assert case['expected_typed']==declared['body']
        result=blobs(case['result']);status=get(result,8);assert result[:8]==b'HBLCLR01' and len(result)==64+get(result,32) and result[40:64]==bytes(24)
        assert get(result,16)==index+1 and status==case['result_status']
        assert not used_calls.intersection(case['calls']) and not used_actions.intersection(case['actions']) and not used_commands.intersection(case['commands'])
        used_calls.update(case['calls']);used_actions.update(case['actions']);used_commands.update(case['commands'])
        for ci in case['calls']:
            row=calls[ci];assert row['case']==case['name']
            assert row['output_capacity']==row['output']['bytes']==row['before_output']['bytes']
            assert row['workspace_capacity']==row['workspace']['bytes']==row['before_workspace']['bytes']
        sequences={};command_position=0;seen_case_actions=[];seen_case_calls=[];completed_turn=None
        for turn,transition in enumerate(case['transitions']):
            action_position=0;previous=None if completed_turn is None else (*completed_turn,0,0)
            wanted=request if turn==0 else b'HBLCLQ01'+struct.pack('<7Q',2,index+1,0,0,0,0,0)
            for position,ci in enumerate(transition['calls']):
                row=calls[ci];assert row['role']=='bellman_call' and blobs(row['input'])==wanted
                seen_case_calls.append(ci);out=blobs(row['output']);work=blobs(row['workspace']);code=row['code']
                if previous:
                    before_out=blobs(row['before_output']);before_work=blobs(row['before_workspace']);old_out,old_work,kind,required=previous
                    if kind==1:assert len(before_work)>=required and len(before_work)>len(old_work) and before_work[:len(old_work)]==old_work and before_work[len(old_work):]==bytes(len(before_work)-len(old_work)) and before_out==old_out
                    elif kind==2:assert len(before_out)>=required and len(before_out)>len(old_out) and before_out[:len(old_out)]==old_out and before_out[len(old_out):]==bytes(len(before_out)-len(old_out)) and before_work==old_work
                    else:assert before_out==old_out and before_work==old_work
                if code==0xffffffd0:
                    assert out[:8]==b'HGRWS002' and get(out,24)==0
                    previous=(out,work,get(out,8),get(out,16));continue
                if code==0xfffffff0:
                    ai=transition['actions'][action_position];action_position+=1;action=actions[ai];seen_case_actions.append(ai)
                    assert action['case']==case['name'] and blobs(action['whole_workspace_before'])==work and blobs(action['descriptor'])==work[256:368]
                    seq,target,mode,offset,size,dst,capacity=struct.unpack_from('<7Q',work,264)
                    assert (seq,target,mode)==(action['sequence'],action['target'],action['mode'])
                    child=blobs(action['request']);reply=blobs(action['reply']);assert work[offset:offset+size]==child
                    if mode==0:assert seq not in sequences;sequences[seq]=(target,child,reply)
                    else:assert mode==1 and sequences[seq]==(target,child,reply)
                    patched=bytearray(work);outcome=0xffffffcd if len(reply)>capacity else len(reply)
                    assert outcome==action['outcome'];struct.pack_into('<Q',patched,320,seq);struct.pack_into('<Q',patched,328,outcome);struct.pack_into('<Q',patched,352,len(reply))
                    if outcome!=0xffffffcd:patched[dst:dst+len(reply)]=reply
                    assert blobs(action['whole_workspace_after'])==patched
                    if target==2 and mode==0:
                        command=report['commands'][case['commands'][command_position]];command_position+=1
                        assert blobs(command['input'])==child and blobs(command['output'])==reply and command['hold']==0
                    if target==0:
                        assert child[:8]==b'HBLPAR01' and child[64:]==request[64:]
                        if declared['status']==0:assert reply[128:]==blobs(case['expected_typed'])
                    if target==1:assert declared['status']==1 and reply[:8]==b'HBLPDR01' and reply[64:]==blobs(case['expected_typed'])
                    assert position+1<len(transition['calls'])
                    descendants=list(range(ci+1,transition['calls'][position+1]));seen_case_calls.extend(descendants)
                    if target==2 or mode==1:assert not descendants
                    else:
                        assert 1<=len(descendants)<=8
                        outcap=128 if target==0 else 64;workcap=65536
                        role=('bellman_params_callable','bellman_diagnostic_callable')[target]
                        for di,descendant in enumerate(descendants):
                            observed=calls[descendant];assert observed['role']==role and blobs(observed['input'])==child
                            assert observed['output_capacity']==outcap and observed['workspace_capacity']==workcap
                            assert blobs(observed['before_output'])==b'\xcc'*outcap and blobs(observed['before_workspace'])==bytes(workcap)
                            produced=blobs(observed['output']);returned=observed['code']
                            if returned==0xffffffd0:
                                assert di+1<len(descendants) and produced[:8]==b'HGRWS002' and get(produced,24)==0
                                kind,required=get(produced,8),get(produced,16)
                                if kind==1:assert required>workcap;workcap=required
                                else:assert kind==2 and required>outcap;outcap=required
                            else:assert di==len(descendants)-1 and returned==len(reply) and produced[:returned]==reply
                    previous=(out,bytes(patched),0,0);continue
                assert code==64 and position==len(transition['calls'])-1
                value=out[:64+get(out,32)];assert value[:8]==b'HBLCLR01'
                if turn==len(case['transitions'])-1:assert value==result
                else:assert get(value,8)==3 and len(value)==64
                completed_turn=(out,work);previous=None
            assert action_position==len(transition['actions'])
        assert seen_case_actions==case['actions']
        assert seen_case_calls==case['calls']
        assert command_position==len(case['commands'])
        if declared['status']==1:
            assert status==1 and result[64:]==b'failed to deserialize parameters: '+blobs(case['expected_typed']) and not case['commands']
        else:
            assert status in (0,2) and [report['commands'][i]['command'] for i in case['commands']]==[1,2,4]
            command=report['commands'][case['commands'][0]];assert blobs(command['input'])[64:]==blobs(case['expected_typed'])
            taken=blobs(report['commands'][case['commands'][-1]]['output']);assert get(taken,32)==get(result,24)
            if status==0:
                body=taken[192:];start=96+get(body,16)+get(body,24);assert result[64:]==body[start+64:] and get(taken,40)==0
        results[index]=(status,result[64:])
    assert used_calls==set(range(len(calls))) and used_actions==set(range(len(actions))) and used_commands==set(range(len(report['commands'])))
    actual_requests=packets((output/'worker/stdin.bin').read_bytes());actual_replies=[r for r in packets((output/'worker/stdout.bin').read_bytes()) if get(r,16)==1]
    assert len(actual_requests)==len(actual_replies)==len(report['commands'])
    for request,response,row in zip(actual_requests,actual_replies,report['commands']):assert blobs(row['input'])==request and blobs(row['output'])==response
    blobs.finish();worker=verify_process(output/'worker',component,timeout_seconds=domain[group+'_deadline_seconds'])
    assert worker['jobs']==report['worker_ready_events']==sum(r['status']==0 for _,r in expected)
    return dict(cases=len(results),calls=len(calls),actions=len(actions),physical_blobs=len(blobs.wanted),blob_bytes=sum(v['bytes'] for v in blobs.wanted.values()),worker=worker),results

def verify_original(package,original,native_results):
    report=read(original/'original.json');assert report['status']=='ACTUAL_ORIGINAL_HANDLER_OBSERVED' and report['case_count']==683
    assert report['source_manifest']==source(package)
    assert report['original_source_sha256']=='254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7'
    assert report['native_executed'] is False and report['whole_runtime_replaced'] is False and report['public_handler_qualified'] is False
    for p in (package/'reference').rglob('*'):
        if p.is_file():assert p.read_bytes()==(original/'reference'/p.relative_to(package/'reference')).read_bytes()
    assert source(original/'recipe-source')==source(package)
    assert pin((original/'original-plan').read_bytes())==report['binary']
    for name,limit in [('rustc-version',30),('cargo-version',30),('cargo-build',300),('cargo-metadata',120),('params-original',60),('original',60)]:
        process=read(original/'processes'/(name+'.json'))
        assert process['started'] is True and process['timed_out'] is False and process['returncode']==0
        assert process['pid']==process['pgid'] and process['pid']>0 and process['parent_pid']>0
        assert process['timeout_seconds']==limit and 0<=process['elapsed_ns']<=(limit+1)*1000000000
        for suffix in ('stdout','stderr'):
            raw=(original/'processes'/(name+'.'+suffix)).read_bytes();assert pin(raw)=={key:process[suffix][key] for key in ('bytes','sha256')}
    assert (original/'processes/rustc-version.stdout').read_bytes().startswith(b'rustc 1.95.0 ')
    lock=tomllib.loads((original/'reference/full_plan/Cargo.lock').read_text())
    locked={(p['name'],p['version']):p for p in lock['package'] if 'source' in p};registry=read(original/'registry.json')
    metadata=read(original/'processes/cargo-metadata.stdout');seen=set();total_source_files=0
    for package_row in metadata['packages']:
        if package_row['source'] is None:assert package_row['name']=='hia-bellman-call-reference';continue
        key=package_row['name'],package_row['version'];assert key not in seen;seen.add(key)
        item=locked[key];name=key[0]+'-'+key[1];raw=(original/'registry'/(name+'.crate')).read_bytes()
        assert pin(raw)==registry[name]['archive'] and pin(raw)['sha256']==item['checksum'] and package_row['source']==item['source']
        expected=read(original/'registry'/(name+'.source.json'));actual={}
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as t:
            for member in t:
                if member.isdir():continue
                assert member.isfile() and member.name.startswith(name+'/')
                relative=member.name[len(name)+1:];assert relative not in actual and '..' not in Path(relative).parts
                actual[relative]=pin(t.extractfile(member).read())
        assert actual==expected and len(actual)==registry[name]['actual_source_files'];total_source_files+=len(actual)
    assert seen==set(locked) and len(registry)==report['registry_packages']==132
    inputs=(original/'original.stdin').read_bytes();assert pin(inputs)==report['complete_input']
    raw_inputs=packets(inputs);frozen_inputs=read(package/'reference/params/corpus-domain.json')['cases'];assert len(raw_inputs)==len(frozen_inputs)==683
    for raw,frozen in zip(raw_inputs,frozen_inputs):assert pin(raw)=={key:frozen[key] for key in ('bytes','sha256')}
    typed_report=read(original/'typed/original.json')
    assert typed_report['status']=='ORIGINAL_OBSERVED_NATIVE_REQUIRED' and typed_report['case_count']==683
    assert typed_report['successful_typed']==401 and typed_report['typed_errors']==282
    assert typed_report['source_manifest']==source(package) and typed_report['original_source_sha256']==report['original_source_sha256']
    assert typed_report['native_qualified'] is False and typed_report['whole_runtime_replaced'] is False and typed_report['public_handler_qualified'] is False
    assert pin((original/'original-params').read_bytes())==typed_report['binary']
    typed=(original/'typed/original.stdout').read_bytes();assert typed==(original/'processes/params-original.stdout').read_bytes()
    assert pin(typed)==typed_report['complete_output']==read(package/'domain.json')['original_output']
    assert (original/'typed/original.stdin').read_bytes()==inputs and pin(inputs)==typed_report['complete_input']
    typed_records=packets(typed);domain_rows=read(package/'domain.json')['cases']
    assert len(typed_records)==len(typed_report['cases'])==len(domain_rows)==683
    for frame,row,declared,raw_input in zip(typed_records,typed_report['cases'],domain_rows,raw_inputs):
        assert frame[:8]==b'HBPOR001'
        status,canonical_length,body_length,count,r0,r1,r2=struct.unpack_from('<7Q',frame,8)
        assert (r0,r1,r2)==(0,0,0) and len(frame)==64+canonical_length+body_length
        canonical=frame[64:64+canonical_length];body=frame[64+canonical_length:]
        assert status==row['status']==declared['status'] and count==row['states']==declared['states']
        assert (row['group'],row['name'])==(declared['group'],declared['name'])
        assert pin(raw_input)==row['raw'] and pin(canonical)==row['canonical']==declared['canonical'] and pin(body)==row['body']==declared['body']
    baseline=(package/'reference/params_observer_baseline.rs').read_text()
    params=(package/'reference/full_plan/params.rs').read_text()
    assert params[params.index('fn word('):]==baseline[baseline.index('fn word('):]
    assert '#[path = "../weight_bellman.rs"]\nmod original;\nuse original::{BellmanAction, BellmanPlanParams};' in params
    data=(original/'processes/original.stdout').read_bytes();assert pin(data)==report['complete_output']
    records=packets(data);domain=read(package/'domain.json');assert len(records)==len(report['cases'])==len(domain['cases'])==683
    counts={0:0,1:0,2:0}
    for index,(frame,row,declared) in enumerate(zip(records,report['cases'],domain['cases'])):
        assert frame[:8]==b'HBCOR001' and get(frame,48)==index and get(frame,56)==0
        status,canonical_length,text_length,before,after=struct.unpack_from('<5Q',frame,8)
        assert len(frame)==64+canonical_length+text_length and before<=after
        canonical=frame[64:64+canonical_length];text=frame[64+canonical_length:]
        assert (row['index'],row['group'],row['name'])==(index,declared['group'],declared['name'])
        assert pin(canonical)==declared['canonical']==row['canonical'] and pin(text)==row['text']
        assert status==row['status'] and row['before_ns']==before and row['after_ns']==after
        observed_status,observed=native_results[index];assert status==observed_status,(index,row['name'],'status')
        if status==0:
            value=json.loads(text);assert 0<=value['native_operation_wall_seconds']<=(after-before)/1e9
            assert normalized(text)==normalized(observed),(index,row['name'],'complete JSON bytes excluding actual elapsed only')
        else:assert text==observed,(index,row['name'],'complete error bytes')
        counts[status]+=1
    assert counts=={0:301,1:282,2:100}
    return dict(cases=683,success_json=301,typed_errors=282,business_errors=100,registry_packages=132,
        complete_registry_source_files=total_source_files,complete_original_typed_cases=683,complete_typed_output=typed_report['complete_output'],only_normalized_field='native_operation_wall_seconds',
        original_complete_output=report['complete_output'],full_error_bytes_compared=True)

def verify_controls(package,output,component):
    report=read(output/'report.json');assert report['status']=='PRIVATE_CALLER_CONTROL_LIFECYCLE_PASS' and report['source_manifest']==source(package)
    domain=read(package/'domain.json');assert report['control_count']==domain['private_controls']==60
    assert report['lifecycle_groups']==domain['lifecycle_groups']==7 and report['actual_worker_instances']==1
    assert report['timeout_seconds']==domain['lifecycle_deadline_seconds']==120 and report['wall_seconds']<=120
    calls=[json.loads(l) for l in (output/'calls.jsonl').read_bytes().splitlines()];actions=[json.loads(l) for l in (output/'actions.jsonl').read_bytes().splitlines()]
    assert [r['index'] for r in calls]==list(range(report['calls'])) and [r['index'] for r in actions]==list(range(report['actions']))
    blobs=Blobs(output/'blobs',[calls,report['groups'],report['commands']],actions)
    for row in calls:
        assert row['output_capacity']==row['before_output']['bytes']==row['output']['bytes']
        assert row['workspace_capacity']==row['before_workspace']['bytes']==row['workspace']['bytes']
    controls=set()
    for control in report['controls']:
        ci=control['call'];assert ci not in controls;controls.add(ci);row=calls[ci]
        assert row['role']=='private-control' and row['case']==control['name'] and row['code']==control['expected']
        if control['atomic']:assert row['before_output']==row['output'] and row['before_workspace']==row['workspace']
        else:
            before=blobs(row['before_output']);old=blobs(row['before_workspace']);out=blobs(row['output']);work=blobs(row['workspace'])
            assert row['code']==0xffffffd0 and out[:8]==b'HGRWS002' and get(out,24)==0 and out[32:]==before[32:]
            if get(out,8)==1:assert get(out,16)==4096 and work==old
            else:
                assert get(out,8)==2 and get(out,16)==64;expected=bytearray(old);struct.pack_into('<Q',expected,392,64);struct.pack_into('<Q',expected,400,2);assert work==expected
    assert len(controls)==60
    for action in actions:
        before=blobs(action['whole_workspace_before']);after=blobs(action['whole_workspace_after']);descriptor=blobs(action['descriptor']);request=blobs(action['request']);reply=blobs(action['reply'])
        assert before[256:368]==descriptor and descriptor[:8]==b'HBLCAC01'
        seq,target,mode,offset,size,dst,capacity=struct.unpack_from('<7Q',descriptor,8)
        assert (seq,target,mode)==(action['sequence'],action['target'],action['mode']) and before[offset:offset+size]==request
        code=0xffffffcd if len(reply)>capacity else len(reply);assert action['outcome']==code
        wanted=bytearray(before);struct.pack_into('<Q',wanted,320,seq);struct.pack_into('<Q',wanted,328,code);struct.pack_into('<Q',wanted,352,len(reply))
        if code!=0xffffffcd:wanted[dst:dst+len(reply)]=reply
        assert after==wanted
    names=[r['name'] for r in report['groups']]
    assert names==['same-context-valid-invalid-valid','invalid-before-admission','empty-valid-while-busy','valid-while-busy',
        'cancelled-worker-still-occupies-permit','own-cancel-and-reuse-with-held-real-worker','eof-with-actual-pending-worker']
    first=report['groups'][0];assert [get(blobs(r['result']),8) for r in first['results']]==[0,1,0]
    assert [r['tag'] for r in first['results']]==[20001,20002,20003]
    for group in report['groups'][2:5]:assert get(blobs(group['result']),8)==2 and blobs(group['result'])[64:]==b'native Bellman planning capacity exhausted; no work admitted'
    own=report['groups'][5];stop=own['stopped'];status=blobs(stop['actual_status'])
    assert stop['first_clock_observed'] is True and stop['hold_wire_unchanged'] is True
    assert any(line.startswith(b'State:') and b'T' in line for line in status.splitlines())
    assert any(line==b'Pid:\t'+str(stop['pid']).encode() for line in status.splitlines())
    assert get(blobs(own['cancelled']),8)==4 and len(blobs(own['cancelled']))==64 and get(blobs(own['reused']),8)==0
    assert get(blobs(report['groups'][-1]['pending']),8)==3
    requests=packets((output/'worker/stdin.bin').read_bytes());responses=[r for r in packets((output/'worker/stdout.bin').read_bytes()) if get(r,16)==1]
    assert len(requests)==len(responses)==len(report['commands'])
    for request,response,command in zip(requests,responses,report['commands']):assert blobs(command['input'])==request and blobs(command['output'])==response
    assert sum(c['hold']==1 for c in report['commands'])==2
    for c in report['commands']:
        if c['hold']:assert c['case']=='fill-two-real-worker-permits'
    worker=verify_process(output/'worker',component,timeout_seconds=120)
    assert worker['jobs']==domain['lifecycle_actual_jobs']==7 and worker['held_jobs']==2
    blobs.finish()
    return dict(controls=60,lifecycle_groups=7,calls=len(calls),actions=len(actions),worker=worker,physical_blobs=len(blobs.wanted))

def parse_arguments():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('package','build','ordinary','unicode','original-package','original','controls-package','controls','bridge'):p.add_argument('--'+name,type=Path,required=True)
    return p.parse_args()
def verify_all(a):
    component,worker_build=admit_bridge(a.bridge)
    built=build_check(a.package,a.build);ordinary,results=verify_group(a.package,a.ordinary,component)
    unicode,more=verify_group(a.package,a.unicode,component);assert not set(results).intersection(more);results.update(more)
    original=verify_original(a.original_package,a.original,results);controls=verify_controls(a.controls_package,a.controls,component)
    return dict(status='READ_ONLY_CALLER683_AND_FRESH_ORIGINAL_PASS',worker_build=worker_build,build=built,ordinary=ordinary,unicode=unicode,original=original,controls=controls,
        native_processes_started=0,original_processes_started=0,public_handler_qualified=False,whole_runtime_replaced=False)
if __name__=='__main__':print(json.dumps(verify_all(parse_arguments()),sort_keys=True))
