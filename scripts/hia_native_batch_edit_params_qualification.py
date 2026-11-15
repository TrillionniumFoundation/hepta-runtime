"""Read complete typed-projection execution records; never execute an owner.

Native admission does not read original output. The separate comparison binds
the unchanged Rust deserializer and the actual SDK extractor observations.
"""
from pathlib import Path
from collections import Counter
import gzip
import hashlib
import importlib.util
import json
import math
import argparse
import ast
import struct
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from hia_native_view_call_qualification import Evidence,_module,canonical,digest,exact_read,integer,json_value,same

MAX=(1<<64)-1
INVALID,CAPACITY=0xffffffff,0xfffffffe
OWNER_SOURCE={1:'native/serde_json_span.hepta',2:'native/batch_edit_params.hepta'}
CONTROL_COUNTS={'malformed-private-frame':15,'short-output':4,'output-boundary':12,'workspace-growth':12,'dirty-prior-state':6}
SOURCES=('scripts/hia_native_batch_edit_params_build.py','scripts/hia_native_batch_edit_params_qualification.py',
         'scripts/hia_native_view_call_qualification.py','scripts/hia_native_build.py','scripts/hia_native_loader.py',
         'tests/hia_native/test_batch_edit_params.py','tests/hia_native/batch_edit_params_oracle/cases.py',
         'native/batch_edit_params_abi.md','native/batch_edit_params_composition.json')

def require(ok,message):
    if not ok:raise ValueError('batch params qualification: '+message)

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj);return obj

def word(raw,at):return struct.unpack_from('<Q',raw,at)[0]

def _duration(row):
    require(type(row.get('exit_code')) is int and row['exit_code']==0,'process did not return exact zero')
    require(row.get('timed_out') is False,'process timed out or omitted observation')
    require(type(row.get('timeout_seconds')) is int and row['timeout_seconds']==180,'process deadline changed')
    elapsed=row.get('elapsed_seconds')
    require(type(elapsed) in (int,float) and math.isfinite(elapsed) and 0<=elapsed<180,'invalid process duration')

def _suite(e,report,completed,summary):
    name='test_batch_edit_params.py'
    if completed is not None:
        check,actual=completed(e.output,report,name)
        same(actual,{**summary,'skipped':0,'errors':0,'failures':0},'completed parameter suite')
        folder=e.path(report.get('check_artifact_directories',{}).get(name,'.'))
        streams={kind:folder/(name+'.'+kind) for kind in ('stdout','stderr')}
        pins={kind:{'bytes':check[kind+'_bytes'],'sha256':check[kind+'_sha256']} for kind in streams}
    else:
        records=json_value((e.output/'processes.json').read_bytes())
        rows=[r for r in records if r.get('name')=='native']
        require(len(rows)==1,'missing unique native process')
        check=rows[0]
        streams={kind:e.path(check[kind]['path']) for kind in ('stdout','stderr')}
        pins={kind:{k:check[kind][k] for k in ('bytes','sha256')} for kind in streams}
    _duration(check)
    command=check.get('command')
    python=summary.get('python')
    require(type(python) is str and Path(python).is_absolute(),'actual native interpreter path')
    require(type(command) is list and len(command)==4 and command[:3]==[python,'-I','-B'],'native command identity')
    suffix=Path('tests/hia_native')/name
    recorded=Path(command[3])
    require(recorded.is_absolute() and recorded.parts[-3:]==suffix.parts,'executed another native suite')
    origin=recorded.parent.parent.parent
    require(check.get('cwd')==str(origin),'native cwd differs from executed source')
    e.old_roots.append((origin,e.root))
    for kind,path in streams.items():
        raw=e.raw(path);same({'bytes':len(raw),'sha256':digest(raw)},pins[kind],'complete native '+kind)
        if kind=='stdout':same(json_value(raw),{**summary,'skipped':0,'errors':0,'failures':0},'native stdout')
        else:
            require(b'Ran 3 tests in ' in raw and raw.endswith(b'\nOK\n'),'actual unittest completion')
    return check,origin

def _response(code,out,owner):
    header=32 if owner==1 else 64
    require(code==header and len(out)>=header,'native return/header extent')
    require(out[:8]==(b'HJSVR002' if owner==1 else b'HBPRR002'),'native response magic')
    status=word(out,8)
    if owner==1:
        n,needed=word(out,16),word(out,24)
        require(status in (0,1,2,3,4),'Value status')
        require((status==0 and needed==0) or (status!=0 and n==0),'Value span header')
        size=header+n
    else:
        plen,nlen,count,dlen,needed,reserved=struct.unpack_from('<6Q',out,16)
        require(status in (0,1,2,3,4) and reserved==0,'typed response flags')
        if status==0:require(dlen==needed==0,'typed success fields')
        elif status==1:require(plen==nlen==count==needed==0,'typed error fields')
        else:require(plen==nlen==count==dlen==0,'growth contains a partial result')
        size=header+plen+nlen+dlen
    require(size<=len(out) and out[size:]==b'\xa5'*(len(out)-size),'output tail or response extent')
    if status in (2,3):require(needed>0,'nonprogressing growth')
    elif status!=4:require(needed==0,'terminal growth extent')
    return status,needed,out[:size]

def _read_calls(e,capture,summary,semantic,controls,profiles):
    indices=e.rows(capture/'calls.jsonl')
    same(len(indices),2200,'complete call count')
    same(summary['native_calls'],len(indices),'reported native call count')
    same(Counter(r['owner'] for r in indices),Counter({1:1250,2:950}),'Value/typed call split')
    requested={}
    for row in semantic:
        for owner,key in [(1,'value_calls'),(2,'projection_calls')]:
            require(type(row[key]) is list and row[key] and all(type(n) is int for n in row[key]),'missing actual semantic calls')
            for n in row[key]:
                require(n not in requested,'native call counted twice')
                requested[n]=(owner,row['case_id'],n==row[key][-1])
    control_by_call={}
    for row in controls:
        require(row['call'] not in control_by_call,'duplicate private control')
        control_by_call[row['call']]=row
    e.file(capture/'calls.bin.gz')
    observations={};control_observations={};offset=0;previous={};final_by_wire={}
    with gzip.open(capture/'calls.bin.gz','rb') as stream:
        for idx in indices:
            header=exact_read(stream,64)
            call,owner,cid,code,ilen,ocap,wcap,reserved=struct.unpack('<8Q',header)
            require(owner in (1,2) and reserved==0,'call owner or reserved data')
            profile=profiles[owner]
            require(ilen<=profile['input_capacity'] and ocap<=profile['output_capacity'] and wcap<=profile['workspace_capacity'],'call exceeds admitted buffers')
            same((call,owner,cid,code,ilen,ocap,wcap),(idx['call'],idx['owner'],idx['case_id'],idx['return_code'],idx['input_bytes'],idx['output_capacity'],idx['workspace_capacity']),'call header/index')
            require(call==len(previous)+1,'nonconsecutive native call stream')
            require(64+ilen+2*ocap+2*wcap==idx['bytes'] and idx['bytes']<=471425394-offset,'record extent outside complete capture')
            wire=exact_read(stream,ilen);before=exact_read(stream,wcap);output_before=exact_read(stream,ocap)
            out=exact_read(stream,ocap);after=exact_read(stream,wcap)
            raw=header+wire+before+output_before+out+after
            same({'offset':offset,'bytes':len(raw),'record_sha256':digest(raw)},
                 {k:idx[k] for k in ('offset','bytes','record_sha256')},'complete physical call')
            for name,data in [('input',wire),('before',before),('output_before',output_before),('output',out),('after',after)]:
                require(idx[name+'_sha256']==digest(data),'full '+name+' buffer hash')
            require(output_before==b'\xa5'*ocap,'caller output initial bytes')
            offset+=len(raw)
            response=None;status=None;needed=None
            if code in (INVALID,CAPACITY):
                require(call in control_by_call,'unexpected refusal in semantic calls')
                require(out==output_before,'refusal changed output')
                if code==CAPACITY:require(after==before,'short output changed private state')
            else:
                status,needed,response=_response(code,out,owner)
                if status==2:require(needed>wcap,'workspace growth is not strict')
                if status==3:require(needed>ocap,'output growth is not strict')
            if call in requested:
                expected_owner,expected_case,terminal=requested[call]
                require((owner,cid,idx['label'])==(expected_owner,expected_case,'semantic'),'semantic call attribution')
                if terminal:
                    require(status in ((0,) if owner==1 else (0,1)),'semantic terminal status')
                    observations.setdefault(cid,{})['value' if owner==1 else 'typed']=(wire,response)
                else:require(status in (2,3),'nonterminal semantic call did not request growth')
            if status in (0,1):final_by_wire[(owner,digest(wire))]=response
            if call in control_by_call:
                row=control_by_call[call];kind=row['kind']
                require(owner==2 and idx['label']==kind,'private control attribution')
                if kind=='malformed-private-frame':require(code==INVALID,'malformed frame accepted')
                elif kind=='short-output':require(code==CAPACITY and ocap in (0,1,31,63),'short output accepted')
                elif kind=='workspace-growth':require(status==2 and wcap in (0,1,32767,32768),'scratch growth changed')
                elif kind=='output-boundary':require(status in (0,1,3),'output boundary did not preserve result domain')
                elif kind=='dirty-prior-state':require(status in (0,1),'prior scratch bytes changed domain')
                else:raise ValueError('unknown private control')
                control_observations[call]=(wire,code,response,status,needed)
            previous[call]=(owner,cid,digest(wire),status,needed,ocap,wcap,digest(after))
        require(stream.read()==b'','trailing unindexed native bytes')
    same(offset,471425394,'complete invocation stream byte extent')
    same(offset,summary['full_stream_bytes'],'reported invocation stream extent')
    for row in semantic:
        for owner,key in [(1,'value_calls'),(2,'projection_calls')]:
            calls=row[key]
            for a,b in zip(calls,calls[1:]):
                left,right=previous[a],previous[b]
                require(left[:3]==right[:3] and b==a+1,'growth replay changed owner/case/input')
                if left[3]==2:require(right[6]==left[4] and right[5]==left[5],'workspace retry capacity')
                else:require(left[3]==3 and right[5]==left[4] and right[6]==left[6],'output retry capacity')
    for row in controls:
        wire,code,response,status,needed=control_observations[row['call']]
        if row['kind'] in ('output-boundary','workspace-growth','dirty-prior-state'):
            full=final_by_wire.get((2,digest(wire)))
            require(full is not None and digest(full)==row['expected_response_sha256'],'control was not tied to complete native result')
            if status in (0,1):require(response==full,'capacity/prior-state changed complete result')
            if status==3:require(needed==len(full),'output capacity request not exact')
            if row['kind']=='workspace-growth':
                calls=row['resume_calls'];require(calls and all(n in previous for n in calls),'missing actual scratch retry')
                require(all(previous[n][2]==digest(wire) for n in calls),'scratch retry changed input')
                require(previous[calls[-1]][3] in (0,1),'scratch retry never completed')
    return observations

def native_evidence(root,output,report=None,completed=None,*,_bodies=None):
    e=Evidence(root,output)
    descriptor=(report or {}).get('batch_edit_params',{})
    capture=e.path(descriptor.get('corpus','native'))
    bundle_path=e.path(descriptor.get('manifest','build/batch-edit-params.json'))
    summary=e.json(capture/'result.json')
    require(summary.get('status')=='PASS' and summary.get('test_groups')==3,'native suite incomplete')
    same({k:summary.get(k) for k in ('semantic_cases','native_calls','value_calls','projection_calls','controls')},
         dict(semantic_cases=417,native_calls=2200,value_calls=1250,projection_calls=950,controls=49),'native corpus counts')
    require(summary.get('original_reference_status')=='NOT_RUN','native producer claimed original parity')
    for key in ('original_batch_handler_executed','effects_executed','public_route_replaced'):
        require(summary.get(key) is False,'native qualification scope inflated')
    check,old_root=_suite(e,report,completed,summary)
    recorded_manifest=Path(summary['manifest'])
    require(recorded_manifest.is_absolute(),'module origin missing')
    old_output=recorded_manifest.parents[3]
    require(recorded_manifest==old_output/'build/modules/batch-edit-projection/manifest.json','typed module origin suffix')
    require(summary['value_manifest']==str(old_output/'build/modules/batch-edit-value/manifest.json'),'Value module origin differs')
    e.old_roots.append((old_output,e.output))
    e.pins(summary['source_sha256']);e.pins(summary['artifact_sha256'])
    require(set(summary['source_sha256'])=={str(old_root/p) for p in ('tests/hia_native/test_batch_edit_params.py','tests/hia_native/batch_edit_params_oracle/cases.py','scripts/hia_native_loader.py')},'producer source closure')
    for relative in SOURCES:e.source(relative)
    composition=json_value((e.root/'native/batch_edit_params_composition.json').read_bytes())
    require(composition['schema']=='hepta.runtime.batch-edit-params-composition.v1','typed source composition schema')
    require(composition['source_sha256']==e.source(OWNER_SOURCE[2])['sha256'],'typed composition/source binding')
    for item in composition['imports']:
        require(item['source_sha256']==e.source(item['source'])['sha256'],'imported helper source changed')
    bundle=e.json(bundle_path)
    require(bundle.get('schema')=='hepta.runtime.batch-edit-params-build.v1' and set(bundle['members'])=={'projection','value'},'native build members')
    require(bundle.get('public_route_replaced') is False and bundle.get('whole_runtime_replaced') is False,'build scope inflated')
    profiles={}
    for owner,key in ((1,'value'),(2,'projection')):
        member=bundle['members'][key]
        path=e.path(member['manifest'],bundle_path.parent)
        require(path==e.rebase(summary['value_manifest' if owner==1 else 'manifest']),'executed a different module')
        metadata,_=_module(e,path,OWNER_SOURCE[owner],expected=member)
        require(metadata.get('buffer_profile')=='history.v1' and metadata.get('standalone') is None,'typed owner execution profile')
        profiles[owner]=metadata
    semantic=e.rows(capture/'native-cases.jsonl');controls=e.rows(capture/'controls.jsonl')
    generator=load('_batch_params_admission_inputs',e.root/'tests/hia_native/batch_edit_params_oracle/cases.py')
    expected=[r for r in list(generator.iter_cases())+list(generator.extra_cases()) if r['domain']=='typed-object']
    same([(r['case_id'],r['name'],r['domain']) for r in semantic],[(r['case_id'],r['name'],r['domain']) for r in expected],'complete generated native domain')
    same(Counter(r['kind'] for r in controls),Counter(CONTROL_COUNTS),'private control domain')
    observations=_read_calls(e,capture,summary,semantic,controls,profiles)
    canonical_bytes=response_bytes=0
    for row,case in zip(semantic,expected):
        observation=observations[row['case_id']]
        raw=case['raw_json'].encode() if 'raw_json' in case else json.dumps(case['value'],ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
        wire,value=observation['value'];typed_wire,response=observation['typed']
        require(wire==b'HJSVS002'+struct.pack('<2Q',1,len(raw))+raw,'native Value input differs from independent input generator')
        canonical_value=value[32:]
        require(typed_wire==b'HBPRQ002'+struct.pack('<2Q',len(canonical_value),0)+canonical_value,'typed owner did not consume actual native canonical bytes')
        same((len(raw),digest(raw),len(canonical_value),digest(canonical_value),len(response),digest(response),word(response,8)),
             tuple(row[k] for k in ('input_bytes','input_sha256','canonical_bytes','canonical_sha256','response_bytes','response_sha256','status')),'native semantic row/body binding')
        canonical_bytes+=len(canonical_value);response_bytes+=len(response)
    if _bodies is not None:_bodies.update(observations)
    return {'schema':'hepta.runtime.batch-edit-params-native-evidence.v1','status':'PASS','test_groups':3,
            'semantic_cases':417,'native_calls':2200,'controls':49,'canonical_bytes':canonical_bytes,'response_bytes':response_bytes,
            'sources':sorted(e.sources),'source_sha256':dict(sorted(e.sources.items())),
            'artifacts':sorted(e.artifacts),'artifact_sha256':dict(sorted(e.artifacts.items())),
            'manifest':str(bundle_path.relative_to(e.output)),'corpus':str(capture.relative_to(e.output)),
            'native_process':check,'original_reference_status':'NOT_RUN','public_route_replaced':False}


def original_evidence(root,output,report=None,completed=None,*,native=None):
    bodies={}
    actual_native=native_evidence(root,output,report,completed,_bodies=bodies)
    if native is not None:same(actual_native,native,'previous native admission')
    e=Evidence(root,output)
    e.artifacts.update(actual_native['artifact_sha256']);e.sources.update(actual_native['source_sha256'])
    original=e.path((report or {}).get('batch_edit_params',{}).get('original','original'))
    harness=e.root/'tests/hia_native/batch_edit_params_oracle'
    verify=load('_batch_original_source_verify',harness/'verify_sources.py')
    try:
        source_manifest=verify.verify(e.root,harness)
    except AssertionError as error:
        raise ValueError('batch params qualification: unchanged original source verification failed') from error
    result=e.json(original/'result.json')
    require(result.get('status')=='PASS','original did not complete')
    same(result['source_manifest'],source_manifest,'unchanged original source slice')
    same({key:result.get(key) for key in ('cases','typed_object_cases','private_raw_value_cases','actual_sdk_cases','actual_processes')},
         dict(cases=447,typed_object_cases=417,private_raw_value_cases=8,actual_sdk_cases=22,actual_processes=3),'full original domain')
    require(result.get('original_batch_handler_executed') is False and result.get('effects_executed') is False,'original scope inflated')
    expected_harness={'Cargo.toml','Cargo.lock','cases.py','run.py','source_manifest.json','src/main.rs','src/original.rs','verify_sources.py'}
    require(set(result['harness_sources'])==expected_harness,'original source closure incomplete')
    for relative,expected in result['harness_sources'].items():
        same(e.source(str((harness/relative).relative_to(e.root))),expected,'compiled original harness source')
    require(e.source(source_manifest['source'])['sha256']==source_manifest['source_sha256'],'original runtime source changed')
    receipts=e.json(original/'process-receipts.json')
    require(type(receipts) is list and [r.get('name') for r in receipts]==['rustc-version','cargo-build','original'],'actual original process sequence')
    toolchain=result.get('toolchain')
    require(type(toolchain) is dict and set(toolchain)=={'rustc','cargo'},'complete executed toolchain identity')
    for name,identity in toolchain.items():
        require(set(identity)=={'path','bytes','sha256'} and type(identity['path']) is str and
                Path(identity['path']).is_absolute() and Path(identity['path']).name==name and
                type(identity['bytes']) is int and identity['bytes']>0 and
                type(identity['sha256']) is str and len(identity['sha256'])==64 and
                all(c in '0123456789abcdef' for c in identity['sha256']),'executed toolchain bytes')
    rust_bin=Path(toolchain['rustc']['path']).parent
    require(toolchain['cargo']['path']==str(rust_bin/'cargo'),'same selected compiler toolchain')
    original_harness=Path(receipts[0]['cwd'])
    require(original_harness.is_absolute() and original_harness.parts[-3:]==('tests','hia_native','batch_edit_params_oracle'),'actual original source root')
    origin_source=original_harness.parent.parent.parent
    native_source=Path(actual_native['native_process']['command'][3]).parent.parent.parent
    require(origin_source==native_source,'original and native executed different source roots')
    original_binary=Path(receipts[2]['command'][0])
    origin_output=original_binary.parent.parent.parent
    require(original_binary==origin_output/'target/release/hepta-batch-edit-params-original-oracle','actual original executable path')
    native_summary=json_value((e.output/actual_native['corpus']/'result.json').read_bytes())
    native_output=Path(native_summary['manifest']).parents[3]
    require(origin_output==native_output/str(original.relative_to(e.output)),'original and native executed different output roots')
    expected_commands=[[str(rust_bin/'rustc'),'--version'],
                       [str(rust_bin/'cargo'),'build','--release','--locked','--manifest-path',str(original_harness/'Cargo.toml')],
                       [str(original_binary)]]
    input_identity=e.file(original/'input.jsonl');same(input_identity,result['input'],'complete original input')
    output_identity=e.file(original/'original.stdout');same(output_identity,result['output'],'complete original stdout')
    binary_identity=e.file(original/'target/release/hepta-batch-edit-params-original-oracle');same(binary_identity,result['binary'],'actual fresh original binary')
    for i,row in enumerate(receipts):
        _duration(row);same(row.get('command'),expected_commands[i],'actual original command')
        require(row.get('cwd')==str(original_harness),'original cwd changed')
        environment=row.get('controlled_env')
        same(environment,{'PATH':str(rust_bin)+':/usr/bin:/bin','RUSTC':str(rust_bin/'rustc'),
                          'CARGO_BUILD_JOBS':'2','LC_ALL':'C','CARGO_TARGET_DIR':str(origin_output/'target')},'original compiler/target environment')
        same(row.get('stdin'),input_identity if i==2 else None,'original process input binding')
        for kind in ('stdout','stderr'):
            expected=row[kind]
            require(expected['path']==row['name']+'.'+kind,'original process stream path')
            same(e.file(original/expected['path']),{key:expected[key] for key in ('bytes','sha256')},'complete original process '+kind)
    require(e.raw(original/'rustc-version.stdout')==b'rustc 1.95.0 (59807616e 2026-04-14)\n','actual Rust version')
    require(e.raw(original/'original.stderr')==b'','original replay stderr')
    generator=load('_batch_original_input_check',harness/'cases.py')
    input_rows=list(generator.iter_cases())+list(generator.extra_cases())+list(generator.sdk_cases())
    generated=generator.encode(input_rows)
    same({'bytes':len(generated),'sha256':digest(generated)},input_identity,'original input differs from fixed generator')
    require(e.raw(original/'input.jsonl')==generated,'complete original input bytes')
    canonical_bytes=response_bytes=0;typed_cases=private_cases=0;sdk_rows=[];by_name={};comparisons=[]
    with (original/'original.stdout').open('rb') as stream:
        for expected_input in input_rows:
            line=stream.readline();require(line.endswith(b'\n'),'incomplete original row')
            row=json_value(line)
            same((row['case_id'],row['name'],row['domain']),tuple(expected_input[k] for k in ('case_id','name','domain')),'original row identity/order')
            value=row['result']
            if row['domain']=='actual-sdk':sdk_rows.append(row);continue
            if row['domain']=='private-raw-value':private_cases+=1;continue
            require(row['domain']=='typed-object','unknown original semantic domain')
            observation=bodies.pop(row['case_id'])
            canonical_value=value['canonical'].encode()
            require(observation['value'][1][32:]==canonical_value,'native canonical JSON differs from Rust Value')
            if value['ok'] is True:
                path=value['path'].encode();normalized=value['normalized_json'].encode()
                expected=b'HBPRR002'+struct.pack('<7Q',0,len(path),len(normalized),value['operation_count'],0,0,0)+path+normalized
            else:
                require(value['ok'] is False,'original result boolean')
                error=value['error'].encode()
                expected=b'HBPRR002'+struct.pack('<7Q',1,0,0,0,len(error),0,0)+error
            require(observation['typed'][1]==expected,'complete typed result differs from Rust for '+row['name'])
            typed_cases+=1;canonical_bytes+=len(canonical_value);response_bytes+=len(expected)
            comparisons.append({'case_id':row['case_id'],'name':row['name'],'bytes':len(expected),'sha256':digest(expected)})
            if row['case_id']<398:by_name[row['name']]=value
        require(stream.read()==b'','unindexed original result')
    require(not bodies and (typed_cases,private_cases,len(sdk_rows))==(417,8,22),'incomplete original/native matching')
    sdk_observations=[]
    for row in sdk_rows:
        expected=by_name[row['name'].rsplit('-',1)[0]];actual=row['result']
        require(actual['outer_entries']==1 and actual['actual_parameters_extractor'] is True and actual['actual_method_adapter'] is True,'SDK extractor/method adapter missing')
        require(actual['original_batch_handler_executed'] is False and actual['effects_executed'] is False,'SDK fixture claimed original effects')
        seen=actual['handler_observations'];reply=actual['responses'][-1]
        if expected['ok']:
            require(len(seen)==1 and seen[0]['normalized']==expected['normalized'],'SDK typed body projection differs')
            require(reply['result']['isError'] is False and json_value(reply['result']['content'][0]['text'].encode())==seen[0],'SDK complete successful response')
        else:
            require(seen==[] and reply['error']['code']==-32602 and reply['error']['message']=='failed to deserialize parameters: '+expected['error'],'typed SDK error entered body or changed diagnostic')
        sdk_observations.append({'case_id':row['case_id'],'body_entries':len(seen)})
    return {'schema':'hepta.runtime.batch-edit-params-original-evidence.v1','status':'PASS','typed_cases':typed_cases,
            'sdk_cases':22,'private_raw_value_cases_not_claimed':8,'actual_original_processes':3,
            'canonical_bytes':canonical_bytes,'response_bytes':response_bytes,'full_byte_comparisons':comparisons,
            'sdk_observations':sdk_observations,'original_batch_handler_executed':False,'public_route_replaced':False,
            'native_evidence_sha256':digest(canonical(actual_native)),
            'artifacts':sorted(e.artifacts),'artifact_sha256':dict(sorted(e.artifacts.items())),
            'sources':sorted(e.sources),'source_sha256':dict(sorted(e.sources.items())),
            'replay_adds_native_calls':0,'replay_adds_original_processes':0}


def qualification_evidence(root,output,report=None,completed=None,*,native=None):
    """Admit the actual post-original refusal/relocation suite as well as parity."""
    original=original_evidence(root,output,report,completed,native=native)
    e=Evidence(root,output)
    e.sources.update(original['source_sha256']);e.artifacts.update(original['artifact_sha256'])
    descriptor=(report or {}).get('batch_edit_params',{})
    capture=e.path(descriptor.get('controls','controls'))
    name='test_batch_edit_params_original_evidence.py'
    source='tests/hia_native/'+name
    test_pin=e.source(source)['sha256']
    reader_pin=e.source('scripts/hia_native_batch_edit_params_qualification.py')['sha256']
    expected={'status':'PASS','test_groups':2,'refusal_controls':12,'relocations':2,'completed_controls':14,
              'skipped':0,'errors':0,'failures':0,'test_sha256':test_pin,'reader_sha256':reader_pin,
              'baseline_sha256':digest(canonical(original)),'native_cases_added_by_replay':0,
              'original_processes_added_by_replay':0,'original_paths_removed':False,'old_path_reads_forbidden':True}
    same(e.json(capture/'result.json'),expected,'complete post-original qualification')
    same(e.json(capture/'baseline.json'),original,'control baseline differs from complete original admission')
    if completed is not None:
        native_process,_=completed(e.output,report,'test_batch_edit_params.py')
    else:
        native_process=next(row for row in json_value((e.output/'processes.json').read_bytes()) if row.get('name')=='native')
    origin_source=Path(native_process['command'][3]).parent.parent.parent
    native_summary=e.json(e.path(descriptor.get('corpus','native'))/'result.json')
    origin_output=Path(native_summary['manifest']).parents[3]
    if completed is not None:
        check,summary=completed(e.output,report,name)
        same(summary,expected,'completed post-original summary')
        folder=e.path(report.get('check_artifact_directories',{}).get(name,'.'))
        streams={kind:folder/(name+'.'+kind) for kind in ('stdout','stderr')}
        stream_pins={kind:{'bytes':check[kind+'_bytes'],'sha256':check[kind+'_sha256']} for kind in streams}
    else:
        check=e.json(e.path(descriptor.get('controls_receipt','controls.process.json')))
        streams={kind:e.path(check[kind]['path']) for kind in ('stdout','stderr')}
        stream_pins={kind:{k:check[kind][k] for k in ('bytes','sha256')} for kind in streams}
        same(check['source_before'],check['source_after'],'control sources changed during execution')
        same(check['source_before'],{'scripts/hia_native_batch_edit_params_qualification.py':reader_pin,source:test_pin},'control actual source closure')
        same(check['controlled_env'],{'HIA_BATCH_EDIT_PARAMS_QUALIFICATION_OUTPUT':str(origin_output),
             'HIA_BATCH_EDIT_PARAMS_EVIDENCE_CAPTURE_DIR':str(origin_output/capture.relative_to(e.output))},'actual control input paths')
    _duration(check)
    same(check['command'],[native_process['command'][0],'-I','-B',str(origin_source/source)],'actual post-original command')
    same(check['cwd'],str(origin_source),'actual post-original cwd')
    for kind,path in streams.items():
        raw=e.raw(path);same({'bytes':len(raw),'sha256':digest(raw)},stream_pins[kind],'complete qualification '+kind)
        if kind=='stdout':same(json_value(raw),expected,'actual qualification stdout')
        else:require(b'Ran 2 tests in ' in raw and raw.endswith(b'\nOK\n'),'post-original unittest completion')
    controls=e.json(capture/'controls.json')
    names=['boolean-exit','timeout','deadline','wrong-command','missing-semantic-case','image-bytes','missing-call',
           'resigned-refusal-output','resigned-growth-extent','resigned-original-body','original-source-bytes','missing-rust-process']
    require(type(controls) is list and len(controls)==14,'missing refusal/relocation control')
    for row,label in zip(controls[:12],names):
        require(set(row)=={'name','rejected','error_type','error'} and row['name']==label and row['rejected'] is True,
                'physical or re-signed mutation accepted')
        require(row['error_type'] in ('ValueError','AssertionError','OSError','KeyError','TypeError') and type(row['error']) is str and row['error'],
                'missing actual refusal observation')
    assignments=[node for node in ast.parse((e.root/source).read_bytes()).body if isinstance(node,ast.Assign)
                 and any(isinstance(target,ast.Name) and target.id=='WORKER' for target in node.targets)]
    require(len(assignments)==1,'missing unique source-owned relocation worker')
    worker=e.raw(capture/'worker.py')
    require(worker==ast.literal_eval(assignments[0].value).encode(),'relocation worker differs from source-owned isolation guard')
    receipts=e.json(capture/'processes.json')
    require(type(receipts) is list and len(receipts)==2,'missing actual relocated reader processes')
    for index,row in enumerate(receipts):
        _duration(row);same(row['name'],'relocated-'+str(index),'relocation process identity')
        command=row.get('command')
        require(type(command) is list and len(command)==9 and command[:3]==[native_process['command'][0],'-I','-B'],'relocated reader command')
        folder=Path(command[3]).parent
        require(folder.is_absolute() and folder.name.startswith('batch-params-relocated-'),'relocation was not isolated')
        same(command[3:],[str(folder/'worker.py'),str(folder/'source'),str(folder/'output'),str(origin_source),str(origin_output),str(folder/'result.json')],
             'actual relocated source/output bindings')
        same(row['cwd'],str(folder/'source'),'relocated reader cwd')
        same(row['worker_sha256'],digest(worker),'actual relocation worker identity')
        for kind in ('stdout','stderr','evidence'):
            item=row[kind]
            expected_name=str(index)+('.result.json' if kind=='evidence' else '.'+kind)
            same(item['path'],expected_name,'relocation stream path')
            raw=e.raw(capture/expected_name)
            same({'bytes':len(raw),'sha256':digest(raw)},{k:item[k] for k in ('bytes','sha256')},'complete relocated '+kind)
            if kind=='evidence':same(json_value(raw),original,'relocated complete evidence differs')
            elif kind=='stderr':require(raw==b'','relocated reader stderr')
            else:same(json_value(raw),{'status':'PASS','source':str(folder/'source'),'output':str(folder/'output'),
                 'old_path_reads_forbidden':True,'semantic_execution_forbidden':True,'new_native_calls':0,'new_rust_processes':0},'actual isolated-reader result')
        same(controls[12+index],{'name':'relocated-'+str(index),'same_complete_object':True,'old_path_reads_forbidden':True,
             'new_native_calls':0,'new_rust_processes':0},'complete relocated-reader observation')
    return {'schema':'hepta.runtime.batch-edit-params-qualified-evidence.v1','status':'PASS','test_groups':2,
            'refusal_controls':12,'relocations':2,'typed_cases':417,'sdk_cases':22,'actual_original_processes':3,
            'original_evidence_sha256':digest(canonical(original)),'native_evidence_sha256':original['native_evidence_sha256'],
            'sources':sorted(e.sources),'source_sha256':dict(sorted(e.sources.items())),
            'artifacts':sorted(e.artifacts),'artifact_sha256':dict(sorted(e.artifacts.items())),
            'readback_adds_native_calls':0,'readback_adds_original_processes':0,'public_route_replaced':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--repo',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--original',action='store_true')
    parser.add_argument('--result',type=Path,required=True);args=parser.parse_args()
    result=original_evidence(args.repo,args.output) if args.original else native_evidence(args.repo,args.output)
    args.result.parent.mkdir(parents=True,exist_ok=True)
    args.result.write_bytes(canonical(result))
    print(json.dumps({key:value for key,value in result.items() if key not in ('artifacts','artifact_sha256','sources','source_sha256','full_byte_comparisons','sdk_observations','native_process')},sort_keys=True))
