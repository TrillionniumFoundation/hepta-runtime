"""Pure full-byte evidence reader for the native batch Planner input bridge."""
from pathlib import Path
from collections import Counter
import argparse
import ast
import gzip
import hashlib
import importlib.util
import json
import math
import struct
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from hia_native_view_call_qualification import Evidence,_producer,canonical,digest,exact_read,inside,json_value,pin,same as json_same

COMMIT='d3e2c90173cf733e42b299d0c4274df4b593a12f'
COMPILER='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
SOURCE_PROFILE='37913829c74e6efe3128dd1e7da8685b3458fb6eb2a9632efc1a05a4be0e673f'
INVALID,CAPACITY,CALL=0xffffffff,0xfffffffe,0xffffffe0
OWNERS={1:('value','serde_json_span'),2:('params','batch_edit_params'),3:('editable','editable_content'),
        4:('input','batch_plan_input'),5:('plan','batch_plan'),6:('endpoint','line_endpoint'),7:('verify','line_verify')}
COUNTS={'editable':203,'endpoint':117,'input':2486,'params':2617,'plan':214,'value':1388,'verify':2}
def need(condition,message):
    if not condition:raise ValueError('batch input qualification: '+message)
def same(left,right,label):
    if type(left)in(bytes,set) or type(right)in(bytes,set):need(type(left)is type(right) and left==right,label+' differs')
    else:json_same(left,right,label)
def word(raw,offset):return struct.unpack_from('<Q',raw,offset)[0]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def duration(row):
    need(type(row.get('exit_code'))is int and row['exit_code']==0,'nonzero/missing process exit')
    need(row.get('timed_out')is False and row.get('timeout_seconds')==180,'actual process deadline')
    need(type(row.get('pid'))is int and row['pid']>0,'actual process PID')
    value=row.get('elapsed_seconds');need(type(value)in(int,float) and math.isfinite(value) and 0<value<180,'actual process duration')
def streams(e,folder,row):
    result={}
    for kind in ('stdout','stderr'):
        path=inside(folder,row[kind]['path']);actual=e.file(path)
        same(actual,{k:row[kind][k] for k in ('bytes','sha256')},'complete process '+kind)
        result[kind]=path
    return result


def build_evidence(e,summary):
    e.old_roots=[(Path(summary['execution_source_root']),e.root),(Path(summary['execution_output_root']),e.output)]
    pins=json_value((e.root/'native/batch_plan_input_sources.json').read_bytes())
    same(e.source('native/batch_plan_input_sources.json')['sha256'],SOURCE_PROFILE,'closed source profile')
    for name,expected in pins.items():same(e.source(name)['sha256'],expected,'fixed source '+name)
    for name in ['scripts/hia_native_batch_plan_input_qualification.py','scripts/hia_native_batch_plan_input_build.py',
                 'scripts/hia_native_view_call_qualification.py','scripts/hia_native_build.py','native/batch_plan_input_abi.md',
                 'tests/hia_native/test_batch_plan_input_original_evidence.py']:
        e.source(name)
    e.pins(summary['source_sha256']);e.pins(summary['artifact_sha256'])
    same(set(summary['source_sha256']),{str(Path(summary['execution_source_root'])/name) for name in (
        'scripts/hia_native_loader.py','tests/hia_native/batch_plan_harness.py','tests/hia_native/test_batch_plan_input.py',
        'tests/hia_native/batch_plan_input_cases.py','tests/hia_native/batch_edit_params_oracle/cases.py')},'actual native producer closure')
    composition=json_value((e.root/'native/batch_plan_input_composition.json').read_bytes())
    same(composition['schema'],'hepta.runtime.batch-plan-input-composition.v1','composition schema')
    same(composition['source_sha256'],e.source('native/batch_plan_input.hepta')['sha256'],'native source composition')
    for row in composition['imports']:same(row['source_sha256'],e.source(row['source'])['sha256'],'closed imported source')
    bundle=e.json(e.rebase(summary['members']));same(set(bundle['members']),{name for name,_ in OWNERS.values()},'seven member graph')
    same({key:bundle.get(key) for key in ['schema','compiler_commit','compiler_sha256','fresh_images','fresh_cold','public_route_replaced']},
         {'schema':'hepta.runtime.batch-plan-input-build.v1','compiler_commit':COMMIT,'compiler_sha256':COMPILER,'fresh_images':7,'fresh_cold':False,'public_route_replaced':False},'build scope')
    build=e.output/'build';bootstrap=e.json(build/'bootstrap/bootstrap.json')
    same([bootstrap['dependency']['commit'],bootstrap['dependency']['tree'],bootstrap['generation_sha256'],bootstrap['qualification'],bootstrap['matching_source_cold_qualified']],
         [COMMIT,'8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49',COMPILER,'development_fixed_point',False],'pinned reused bootstrap')
    same(bootstrap['compiler_source_sha256'],'388b182e42675f11435867dd99520e9452a4ff48e23c0766a3952b662acc7627','compiler source')
    for name in ('B1','B2','B3'):same(e.file(build/'bootstrap'/(name+'.image.bin'))['sha256'],COMPILER,'native fixed point')
    profiles={}
    for owner,(name,source) in OWNERS.items():
        member=bundle['members'][name];path=e.rebase(member['manifest']);same(e.file(path)['sha256'],member['manifest_sha256'],'actual member manifest')
        metadata=e.json(path);profile='history.v1' if owner in (1,2) else 'batch-plan.v1'
        capacities=(128<<20,128<<20,256<<20) if owner in (1,2) else (512<<20,1024<<20,1152<<20)
        same([metadata[k] for k in ('schema','abi','target','compiler_commit','compiler_sha256','buffer_profile','standalone')],
             ['hepta.runtime.native-module.v1','hepta.runtime.borrowed-bytes.linux-x86_64.v1','linux-x86_64',COMMIT,COMPILER,profile,None],'native member ABI')
        same([metadata[k] for k in ('input_capacity','output_capacity','workspace_capacity')],list(capacities),'admitted carrier profile');profiles[owner]=capacities
        same(member['source'],source,'member source name')
        for key in ('source','image'):
            data=e.raw(inside(path.parent,metadata[key]));same(digest(data),metadata[key+'_sha256'],'full member '+key)
            same(member[key+'_sha256'],metadata[key+'_sha256'],'declared member '+key)
        same(metadata['source_sha256'],e.source('native/'+source+'.hepta')['sha256'],'executed HIA source')
        _producer(e,path.parent,metadata,e.raw(inside(path.parent,metadata['image'])),bootstrap)
    return bundle,profiles


def response(owner,code,out):
    if owner==3:
        need(code<0xffff0000 and 80<=code<=len(out) and out[:8]==b'HEDRES01','complete Editable frame')
        same(word(out,8),0,'Editable status');same(out[code:],b'\xa5'*(len(out)-code),'Editable tail');return 0,0,out[:code]
    header=32 if owner==1 else 64
    need(code==header and len(out)>=header,'native response fixed return')
    same(out[:8],{1:b'HJSVR002',2:b'HBPRR002',4:b'HBPIR002'}[owner],'native response magic')
    status=word(out,8);needed=word(out,{1:24,2:48,4:40}[owner]);need(status in (0,1,2,3,4),'response status')
    if owner==1:
        size=32+word(out,16)
        if status:need(size==32,'non-success Value body')
    elif owner==2:
        p,n,c,d,_,reserved=struct.unpack_from('<6Q',out,16);same(reserved,0,'typed reserved')
        if status==0:need(d==needed==0,'typed success fields')
        elif status==1:need(p==n==c==needed==0,'typed diagnostic fields')
        else:need(p==n==c==d==0,'typed growth body')
        size=64+p+n+d
    else:
        size=64+word(out,16);same(out[48:64],bytes(16),'bridge reserved')
        if status:need(out[16:40]==bytes(24),'bridge growth partial body')
    need(size<=len(out),'response exceeds borrowed output');same(out[size:],b'\xa5'*(len(out)-size),'untouched output tail')
    if status in (2,3):need(needed>0,'non-progressing growth')
    else:need(needed==0,'terminal resource field')
    return status,needed,out[:size]


def bindings(rows,controls):
    groups=[];claimed={}
    def add(ids,owner,cid,label):
        need(type(ids)is list and ids,'empty actual call sequence')
        group=len(groups);groups.append({'ids':ids,'owner':owner,'cid':cid,'label':label})
        for step,index in enumerate(ids):
            need(type(index)is int and index not in claimed,'call omitted or counted twice');claimed[index]=(group,step)
    for row in rows:
        cid=row['case_id'];add(row['value_calls'],1,cid,'semantic');add(row['projection_calls'],2,cid,'semantic')
        for mode in row['modes']:
            for key,owner in [('editable_calls',3),('bridge_calls',4)]:
                if mode[key]:add(mode[key],owner,cid,'semantic')
            if mode['planner'] is not None:add(mode['planner']['calls'],None,cid,'planner')
    for control in controls:
        if control['kind']=='setup':add(control['calls'],None,None,None)
        else:
            add([control['call']],4,None,None)
            if 'resume_calls'in control:add(control['resume_calls'],4,None,'growth-resume')
    same(len(claimed),7027,'complete declared call closure');same(set(claimed),set(range(1,7028)),'no missing call indices')
    return groups,claimed


def read_calls(e,summary,rows,controls,profiles):
    indices=e.rows(e.output/'native/calls.jsonl');same(len(indices),7027,'complete call count')
    same({OWNERS[owner][0]:count for owner,count in Counter(row['owner'] for row in indices).items()},COUNTS,'actual owner call distribution')
    groups,claimed=bindings(rows,controls);terminal={};wire_by_group={};progress={};plans={};offset=0
    resumed={row['resume_calls'][0]:row['call'] for row in controls if 'resume_calls'in row}
    path=e.output/'native/calls.bin.gz';e.file(path)
    with gzip.open(path,'rb') as stream:
        for index,row in enumerate(indices,1):
            header=exact_read(stream,64);call,owner,cid,code,n,cap,wcap,reserved=struct.unpack('<8Q',header)
            same([call,reserved,row['call'],row['offset']],[index,0,index,offset],'complete stream record header')
            need(owner in OWNERS,'native owner slot');limits=profiles[owner]
            need(n<=limits[0] and cap<=limits[1] and wcap<=limits[2],'borrowed spans exceed module profile')
            wire,before,old,out,after=[exact_read(stream,size) for size in (n,wcap,cap,cap,wcap)]
            digestor=hashlib.sha256();size=0
            for value in [header,wire,before,old,out,after]:digestor.update(value);size+=len(value)
            expected={'call':index,'owner':owner,'case_id':cid,'label':row['label'],'offset':offset,'bytes':size,'return_code':code,
                      'input_bytes':n,'output_capacity':cap,'workspace_capacity':wcap,'input_sha256':digest(wire),'before_sha256':digest(before),
                      'output_before_sha256':digest(old),'output_sha256':digest(out),'after_sha256':digest(after),'record_sha256':digestor.hexdigest()}
            same(row,expected,'complete native record and index');offset+=size
            group,step=claimed[index];binding=groups[group]
            if binding['owner'] is not None:same(owner,binding['owner'],'declared owner')
            if binding['cid'] is not None:same(cid,binding['cid'],'declared input identity')
            if binding['label'] is not None:same(row['label'],binding['label'],'declared call purpose')
            last=step==len(binding['ids'])-1
            if owner<=4:
                same(old,b'\xa5'*cap,'borrowed initial output')
                if step==0 and row['label']=='semantic':
                    same(before,bytes(wcap),'fresh native semantic workspace')
                    if owner!=3:same([cap,wcap],[32 if owner==1 else 64,16512 if owner==1 else 32768],'native initial capacities')
                if index in resumed:
                    previous=terminal[resumed[index]];same(wire,previous['wire'],'actual growth control input')
                    same(wcap,previous['needed'],'actual growth control exact workspace')
                    same(digest(before[:previous['workspace']]),previous['after'],'actual control workspace prefix')
                    same(before[previous['workspace']:],bytes(wcap-previous['workspace']),'actual control workspace extension')
                if code in (INVALID,CAPACITY):
                    same(out,old,'private refusal output');need(last,'refusal cannot continue as semantic success')
                    if code==CAPACITY:same(after,before,'short output workspace preservation')
                    status,needed,body=None,0,b''
                else:status,needed,body=response(owner,code,out)
                if step:
                    previous=progress[group];same(digest(wire),previous['input'],'growth input changed')
                    need(previous['status']in(2,3),'continued a terminal native response')
                    if previous['status']==2:
                        same(wcap,previous['needed'],'exact workspace growth');same(cap,previous['cap'],'workspace growth output capacity')
                        same(digest(before[:previous['wcap']]),previous['after'],'workspace prefix retained');same(before[previous['wcap']:],bytes(wcap-previous['wcap']),'workspace extension cleared')
                    else:
                        same(cap,previous['needed'],'exact output growth');same(wcap,previous['wcap'],'output growth workspace extent');same(digest(before),previous['after'],'output growth retained workspace')
                if status in (2,3):need(needed>(wcap if status==2 else cap),'strict capacity progress')
                progress[group]={'status':status,'needed':needed,'cap':cap,'wcap':wcap,'after':digest(after),'input':digest(wire)}
                if last:
                    terminal[index]={'owner':owner,'code':code,'status':status,'needed':needed,'body':body,'wire':wire,
                                     'before':digest(before),'after':digest(after),'capacity':cap,'workspace':wcap}
                wire_by_group.setdefault(group,digest(wire))
            else:
                state=plans.setdefault(group,{'controller':None,'leaf':None,'sequence':0,'attempts':[],'input':None})
                if owner==5:
                    if state['controller'] is None:
                        same(old,b'\xa5'*cap,'Planner initial output');initial=bytearray(b'\x5a'*wcap);footer=wcap-256
                        initial[footer:]=bytes(256);struct.pack_into('<Q',initial,0,0)
                        for at,value in [(120,3),(128,1),(136,1)]:struct.pack_into('<Q',initial,footer+at,value)
                        same(before,bytes(initial),'Planner initial workspace');state['sequence']=0;state['leaf_work']={};state['trace']=[]
                        if state['input']is None:state['input']=wire
                        else:same(wire,state['input'],'Planner retry input')
                    else:
                        previous=state['controller'];leaf=state['leaf'];need(leaf is not None,'Planner resumes without actual child')
                        same(wire,state['input'],'Planner continuation input');same(old,previous['out'],'Planner output continuation')
                        expected=bytearray(previous['after']);footer=len(expected)-256;start=word(expected,footer+56)
                        expected[start:start+len(leaf['out'])]=leaf['out']
                        for at,value in [(80,leaf['code']),(88,state['sequence']),(96,1)]:struct.pack_into('<Q',expected,footer+at,value)
                        same(before,bytes(expected),'actual child result and acknowledgement continuation')
                    if code==CALL:
                        footer=wcap-256;fields=struct.unpack_from('<14Q',after,footer)
                        magic,seq,target,region,start,size,oregion,out_at,out_size,r,result,ack,done,status=fields
                        same(magic,int.from_bytes(b'HIACAL01','little'),'Planner private request magic');same(seq,state['sequence']+1,'Planner sequence')
                        need(target in (2,3) and region==oregion==2 and r==result==ack==done==status==0,'Planner private call flags')
                        need(start+size<=footer and out_at+out_size<=footer and (start+size<=out_at or out_at+out_size<=start),'Planner child spans')
                        state.update(controller={'after':after,'out':out,'target':target+4,'input':after[start:start+size],
                                                 'old':after[out_at:out_at+out_size]},leaf=None,sequence=seq)
                    else:
                        size=0 if code>=0xffff0000 else code;need(size<=cap,'Planner result extent');same(out[size:],bytes([0xa5])*(cap-size),'Planner untouched output tail')
                        need(code==CAPACITY or (code<0xffff0000 and out[:8]==b'HBPLR001'),'Planner terminal code')
                        tail=after[:wcap-256].lstrip(b'\0');same(tail,b'\x5a'*len(tail),'Planner cleared private scratch')
                        state['attempts'].append({'code':code,'body':out[:size],'capacity':cap,'workspace':wcap,'trace':state['trace']});state['controller']=None;state['leaf']=None
                else:
                    request=state['controller'];need(request is not None and state['leaf']is None,'orphan or duplicate native child')
                    same(owner,request['target'],'actual child target');same(wire,request['input'],'actual child complete input');same(old,request['old'],'actual child output before')
                    same(wcap,8 if owner==6 else 192,'actual child workspace extent')
                    same(digest(before),state['leaf_work'].get(owner,digest(bytes(wcap))),'actual persistent child workspace')
                    size=0 if code>=0xffff0000 else code;need(size<=cap,'actual child result extent');same(out[size:],old[size:],'child untouched output tail')
                    state['leaf_work'][owner]=digest(after)
                    state['trace'].append({'phase':word(request['after'],0),'target':owner-4,'code':code,'input_sha256':digest(wire),
                                           'input_bytes':len(wire),'output_sha256':digest(out[:size])})
                    state['leaf']={'out':out,'code':code}
                if last:
                    need(owner==5 and code<0xffff0000 and state['controller']is None,'unfinished Planner continuation')
                    terminal[index]={'owner':owner,'code':code,'status':word(out,8),'body':out[:code],'wire':wire,'attempts':state['attempts']}
        need(stream.read(1)==b'','unclaimed trailing bytes or gzip members')
    need(stream.closed,'complete compressed capture closed')
    same(offset,summary['full_stream_bytes'],'full captured byte count');same(offset,3208052725,'qualified complete record extent')
    return groups,claimed,terminal,indices


def native_evidence(root,output,*,original=False):
    e=Evidence(root,output);summary=e.json(e.output/'native/result.json')
    same({k:summary.get(k)for k in ('schema','status','test_groups','semantic_inputs','semantic_records','successful_inputs','native_calls','controls','owner_calls')},
         {'schema':'hepta.runtime.batch-plan-input-native.v1','status':'PASS','test_groups':3,'semantic_inputs':463,'semantic_records':926,'successful_inputs':202,'native_calls':7027,'controls':64,'owner_calls':COUNTS},'native suite scope/counts')
    for key in ('effects_executed','original_batch_handler_executed','public_route_replaced'):same(summary[key],False,'native scope '+key)
    same(summary['original_reference_status'],'NOT_RUN','native-first producer');bundle,profiles=build_evidence(e,summary)
    same(summary['planner_counts'],{'requests':95,'native_controller_calls':214,'native_endpoint_calls':117,'native_verify_calls':2},'native Planner invocation counts')
    native=[e.json(e.output/'native.process.json')];same(native[0].get('name'),'native','one actual native process')
    row=native[0];duration(row);same(row['pid'],summary['pid'],'native actual PID')
    same(row['cwd'],summary['execution_source_root'],'native cwd');same(row['command'],[summary['python'],'-I','-B',summary['execution_source_root']+'/tests/hia_native/test_batch_plan_input.py'],'native command')
    logs=streams(e,e.output,row);same(json_value(logs['stdout'].read_bytes()),{**summary,'skipped':0,'errors':0,'failures':0},'complete native stdout')
    stderr=logs['stderr'].read_bytes();need(b'Ran 3 tests in 'in stderr and stderr.endswith(b'\nOK\n'),'actual native unittest completion')
    compiled=[e.json(e.output/'compile.process.json')];same(compiled[0].get('name'),'compile','one actual compile process');duration(compiled[0]);logs=streams(e,e.output,compiled[0])
    same(compiled[0]['cwd'],summary['execution_source_root'],'actual compile cwd')
    command=compiled[0]['command'];need(type(command)is list and Path(command[0]).is_absolute(),'actual build interpreter')
    same(command[1:5],['-I','-B',summary['execution_source_root']+'/scripts/hia_native_batch_plan_input_build.py','--worker'],'actual native build worker')
    same(command[5], '--hepta','actual compiler argument');need(Path(command[6]).is_absolute(),'actual compiler checkout path')
    same(command[7:],['--build',summary['execution_output_root']+'/build','--source',summary['execution_source_root']],'actual native build roots')
    same(json_value(logs['stdout'].read_bytes()),bundle,'complete compile stdout');same(logs['stderr'].read_bytes(),b'','compile stderr')
    original_summary=None
    if original:original_summary=original_evidence(e,summary)
    rows=e.rows(e.output/'native/native-cases.jsonl');controls=e.rows(e.output/'native/controls.jsonl')
    same(len(rows),463,'complete input case list');same(len(controls),64,'complete private controls')
    same(Counter(row['kind']for row in controls),Counter({'setup':6,'invalid':32,'short-output':4,'output-boundary':8,'workspace-growth':8,'dirty-reuse':6}),'private control coverage')
    groups,claimed,terminal,indices=read_calls(e,summary,rows,controls,profiles)
    cases=load('_batch_input_evidence_cases',e.root/'tests/hia_native/batch_plan_input_cases.py').cases
    inputs=e.output/'native/original-input.jsonl';results=e.output/'native/native-results.bin';e.file(inputs);e.file(results)
    body_comparisons=[];planner_requests=0
    with inputs.open('rb') as source,results.open('rb') as produced:
        expected_cases=list(cases());same(len(expected_cases),463,'source-defined input corpus')
        for cid,(expected,row) in enumerate(zip(expected_cases,rows)):
            same(row['case_id'],cid,'ordered case identity');same(row['name'],expected['name'],'source-defined case name')
            raw=expected['raw_json'].encode();original_raw=expected['original_raw'].encode()
            same([row['input_bytes'],row['input_sha256'],row['original_bytes'],row['original_sha256']],
                 [len(raw),digest(raw),len(original_raw),digest(original_raw)],'complete source-defined public/raw input')
            value=terminal[row['value_calls'][-1]];params=terminal[row['projection_calls'][-1]]
            same(value['wire'],b'HJSVS002'+struct.pack('<2Q',1,len(raw))+raw,'actual native Value request')
            same(params['wire'],b'HBPRQ002'+struct.pack('<2Q',len(value['body'])-32,0)+value['body'][32:],'actual Value-to-typed handoff')
            same(row['typed_status'],params['status'],'actual typed outcome');need(params['status']in(0,1),'typed terminal outcome')
            same([mode['mode']for mode in row['modes']],[0,1],'both input modes')
            for mode in row['modes']:
                number=mode['mode'];same(json_value(source.readline()),{'case_id':cid,'mode':number,'raw_json':expected['raw_json'],'original_raw':expected['original_raw']},'retained original input')
                if params['status']==1:
                    need(mode['editable_calls']==mode['bridge_calls']==[] and mode['planner']is None,'typed error must precede the bridge');kind=1;body=params['body'][64:]
                else:
                    editable=b''
                    if number:
                        ed=terminal[mode['editable_calls'][-1]];same(ed['wire'],b'HEDIT001'+struct.pack('<5Q',1,len(original_raw),0,0,0)+original_raw,'actual raw-to-Editable handoff');editable=ed['body']
                    else:same(mode['editable_calls'],[],'preflight does not normalize a file')
                    bridge=terminal[mode['bridge_calls'][-1]];p=params['body']
                    same(bridge['wire'],b'HBPIQ002'+struct.pack('<7Q',number,len(p),len(editable),0,0,0,0)+p+editable,'actual complete bridge inputs')
                    need(bridge['status']==0,'bridge terminal success');body=bridge['body'];kind=0
                    if expected['planner']:
                        plan=mode['planner'];need(type(plan)is dict,'missing actual Planner consumer');observed=terminal[plan['calls'][-1]]
                        same(observed['wire'],body[64:],'actual bridge-to-Planner full handoff')
                        same([plan['response_bytes'],plan['response_sha256']],[len(observed['body']),digest(observed['body'])],'complete Planner result')
                        same(len(plan['attempts']),len(observed['attempts']),'complete Planner resource attempts')
                        for attempt,actual in zip(plan['attempts'],observed['attempts']):
                            same([attempt['code'],attempt['output_bytes'],attempt['output_sha256'],attempt['output_capacity']],
                                 [actual['code'],len(actual['body']),digest(actual['body']),actual['capacity']],'Planner result attempt')
                            same([attempt['workspace_capacity'],attempt['trace']],[actual['workspace'],actual['trace']],'complete actual Planner child trace')
                        planner_requests+=len(plan['attempts'])
                    else:need(mode['planner']is None,'unexpected Planner consumer')
                same([mode['kind'],mode['body_bytes'],mode['body_sha256']],[kind,len(body),digest(body)],'complete native result binding')
                same(exact_read(produced,32),struct.pack('<4Q',cid,number,kind,len(body)),'native binary row header');same(exact_read(produced,len(body)),body,'native binary result bytes')
                body_comparisons.append({'case_id':cid,'mode':number,'kind':kind,'bytes':len(body),'sha256':digest(body)})
        need(source.read()==b'' and produced.read()==b'','unclaimed native inputs/results')
    same(planner_requests,95,'all actual Planner attempts')
    for control in controls:
        if control['kind']=='setup':same(digest(terminal[control['calls'][-1]]['body']),control['response_sha256'],'control setup actual response');continue
        observed=terminal[control['call']];kind=control['kind']
        if kind in ('invalid','short-output'):same(observed['code'],control['expected_code'],'actual private refusal')
        elif kind=='workspace-growth':
            same(observed['status'],2,'actual workspace growth');need(observed['needed']>observed['workspace'],'strict workspace increase')
            same(digest(terminal[control['resume_calls'][-1]]['body']),control['expected_response_sha256'],'actual resumed complete response')
        elif kind=='output-boundary':
            if observed['capacity']<control['required_capacity']:same([observed['status'],observed['needed']],[3,control['required_capacity']],'exact output growth')
            else:same(digest(observed['body']),control['expected_response_sha256'],'exact/oversized output')
        else:same(digest(observed['body']),control['expected_response_sha256'],'dirty workspace complete response')
    return {'schema':'hepta.runtime.batch-plan-input-qualified.v1' if original else 'hepta.runtime.batch-plan-input-native-evidence.v1',
            'status':'PASS','semantic_inputs':463,'semantic_records':926,'native_calls':7027,'controls':64,'fresh_images':7,
            'fresh_cold':False,'full_native_capture_bytes':summary['full_stream_bytes'],'complete_result_comparisons':body_comparisons,
            'source_sha256':dict(sorted(e.sources.items())),'artifact_sha256':dict(sorted(e.artifacts.items())),
            'native_process':native[0],'original':original_summary,'fresh_original_comparison_complete':original,
            'public_route_replaced':False,'whole_runtime_replaced':False,'new_native_calls':0,'new_rust_processes':0}


def original_evidence(e,native):
    folder=e.output/'original';summary=e.json(folder/'result.json')
    same([summary['schema'],summary['status'],summary['semantic_inputs'],summary['semantic_records'],summary['full_compared_bytes'],summary['actual_processes']],
         ['hepta.runtime.batch-plan-input-original.v1','PASS',463,926,100386031,4],'complete original scope')
    for key in ('native_before_original','fresh_target_directory'):same(summary[key],True,'original recipe '+key)
    for key in ('original_batch_handler_executed','effects_executed','public_route_replaced'):same(summary[key],False,'original scope '+key)
    source_names={str(path.relative_to(e.root)) for path in (e.root/'tests/hia_native/batch_plan_input_oracle').rglob('*') if path.is_file()}
    expected_names=source_names|{'src/mcp/server.rs','src/mcp/fs/text_editing.rs',*[ 'tests/hia_native/batch_edit_params_oracle/'+name for name in ('source_manifest.json','verify_sources.py','src/original.rs','Cargo.toml','Cargo.lock')]}
    same(set(summary['source_sha256']),expected_names,'complete original source closure')
    for name,expected in summary['source_sha256'].items():same(e.source(name)['sha256'],expected,'executed original source')
    here=e.root/'tests/hia_native/batch_plan_input_oracle';verifier=load('_batch_input_original_verifier',here/'run.py')
    same(verifier.verify(e.root,here),summary['source_manifest'],'unchanged original source extraction')
    for name,expected in summary['native_artifacts_before_and_after'].items():same(e.file(e.output/'native'/name),expected,'native evidence existed before and remained after original')
    same(set(summary['native_artifacts_before_and_after']),{'result.json','calls.jsonl','calls.bin.gz','native-cases.jsonl','controls.jsonl','native-results.bin','original-input.jsonl'},'complete native-first bindings')
    rows=e.json(folder/'processes.json');same([row['name']for row in rows],['rustc-version','cargo-version','cargo-build','original'],'fresh actual original process sequence')
    old_source=Path(native['execution_source_root']);old_output=Path(native['execution_output_root']);old_here=old_source/'tests/hia_native/batch_plan_input_oracle'
    tools=summary['toolchain_before_and_after'];same(set(tools),{'rustc','cargo'},'selected actual Rust tools')
    same({name:{k:tools[name][k]for k in ('bytes','sha256')}for name in tools},
         {'rustc':{'bytes':644784,'sha256':'bff349e72704ff70bc08a234a3847338e797065bbedde5e556808bc87b7bf7c6'},
          'cargo':{'bytes':42185192,'sha256':'841072d1d92f9e841d9ba5b0814182a0adf064acf4527cd120967b7bc49dcb66'}},'actual selected Rust executables before and after')
    rust=Path(tools['rustc']['path']);cargo=Path(tools['cargo']['path']);need(rust.is_absolute() and cargo.parent==rust.parent,'selected Rust paths')
    need(rust.parent.name=='bin' and '1.95.0'in str(rust.parent),'pinned Rust 1.95.0 paths')
    binary=e.rebase(summary['binary']['path']);same(e.file(binary),{k:summary['binary'][k]for k in ('bytes','sha256')},'actual original binary')
    expected_commands=[[str(rust),'--version'],[str(cargo),'--version'],[str(cargo),'build','--release','--locked','--manifest-path',str(old_here/'Cargo.toml')],[summary['binary']['path']]]
    for row,command in zip(rows,expected_commands):
        duration(row);same(row['command'],command,'actual original command');same(row['cwd'],str(old_here),'actual original cwd')
        env=row['controlled_env'];same(env,{'PATH':str(rust.parent)+':/usr/bin:/bin','RUSTC':str(rust),'CARGO_BUILD_JOBS':'2','LC_ALL':'C','CARGO_TARGET_DIR':str(old_output/'original/target')},'actual isolated original environment')
        logs=streams(e,folder,row)
        if row['name']=='rustc-version':same(logs['stdout'].read_bytes(),b'rustc 1.95.0 (59807616e 2026-04-14)\n','actual pinned compiler version')
        if row['name']=='cargo-version':need(logs['stdout'].read_bytes().startswith(b'cargo 1.95.0 '),'actual cargo version')
        if row['name']=='original':
            same(row['stdin'],{'path':str(old_output/'native/original-input.jsonl'),**summary['input']},'actual original stdin')
            same(e.file(logs['stdout']),summary['output'],'complete original output');same(logs['stderr'].read_bytes(),b'','original execution stderr')
        else:need(row['stdin']is None,'unexpected tool stdin')
    same(e.file(e.output/'native/original-input.jsonl'),summary['input'],'full original input')
    same(summary['output'],{'bytes':100386031,'sha256':'31b32dbcdc6c1a60af6d001b02ada0b791d2428d146b866506cb244421fa7708'},'complete independent original corpus')
    same(e.file(e.output/'native/native-results.bin'),summary['output'],'complete native/original equality')
    with (folder/'original.stdout').open('rb') as left,(e.output/'native/native-results.bin').open('rb') as right:
        while True:
            a,b=left.read(1<<20),right.read(1<<20);same(a,b,'fresh original/native complete bytes')
            if not a:break
    outer=[e.json(e.output/'original.process.json')];same(outer[0].get('name'),'original','one actual original recipe')
    row=outer[0];duration(row);same(row['cwd'],str(old_source),'outer original cwd')
    same(row['command'],[native['python'],'-I','-B',str(old_here/'run.py'),'--runtime',str(old_source),'--output',str(old_output/'original'),'--native',str(old_output/'native'),'--rust-bin',str(rust.parent)],'outer original command')
    logs=streams(e,e.output,row);same(json_value(logs['stdout'].read_bytes()),summary,'complete original recipe stdout');same(logs['stderr'].read_bytes(),b'','original recipe stderr')
    return summary


def qualification_evidence(root,output,*,native=None):
    """Admit the actual refusal and relocation processes after fresh comparison."""
    full=native_evidence(root,output,original=True)
    if native is not None:
        for key,value in native.items():
            if key in ('schema','original','fresh_original_comparison_complete'):continue
            if key in ('source_sha256','artifact_sha256'):
                same({name:full[key].get(name)for name in value},value,'unchanged native '+key)
            else:same(full[key],value,'unchanged native '+key)
        same(native['schema'],'hepta.runtime.batch-plan-input-native-evidence.v1','native phase schema')
        same(native['original'],None,'no original work before native seal')
        same(native['fresh_original_comparison_complete'],False,'native phase boundary')
    e=Evidence(root,output)
    e.sources.update(full['source_sha256']);e.artifacts.update(full['artifact_sha256'])
    capture=e.output/'controls';summary=e.json(capture/'result.json')
    expected={'schema':'hepta.runtime.batch-plan-input-controls.v1','status':'PASS','test_groups':2,'controls':12,
              'physical_relocations':2,'actual_reader_processes':2,'original_paths_blocked':True,
              'first_relocation_unavailable_during_second':True,'actual_second_venv':True,'complete_objects_equal':True,
              'source_and_artifacts_unchanged':True,'new_native_calls':0,'new_rust_processes':0,
              'public_route_replaced':False,'whole_runtime_replaced':False}
    same({key:summary.get(key)for key in expected},expected,'actual physical control scope')
    need(type(summary.get('original_roots_actually_absent'))is bool,'physical origin availability was recorded')
    origin_source=Path(summary['execution_source_root']);origin_output=Path(summary['execution_output_root'])
    origin_capture=Path(summary['execution_capture_root'])
    need(origin_source.is_absolute() and origin_output.is_absolute(),'absolute control execution roots')
    same(str(origin_capture),str(origin_output/'controls'),'registered control capture folder')
    native_summary=e.json(e.output/'native/result.json')
    same([str(origin_source),str(origin_output)],[native_summary['execution_source_root'],native_summary['execution_output_root']],
         'controls consume this execution source and output')
    baseline=e.json(capture/'baseline.json');same(baseline,full,'complete controls baseline object')
    same(e.file(capture/'baseline.json'),summary['baseline'],'complete baseline bytes')
    same([summary['source_files'],summary['artifact_files']],[len(full['source_sha256']),len(full['artifact_sha256'])],
         'complete baseline source/artifact counts')
    events=e.json(capture/'refusals.json');same(events,summary['events'],'all actual refusal events')
    names=['missing-native-index','changed-native-result','truncated-original-output','changed-owner-source','changed-image',
           'changed-compiler-output-tail','changed-native-deadline','changed-locked-original-command','resigned-missing-case',
           'resigned-duplicate-call','resigned-native-output-magic','resigned-original-input']
    same([row.get('name')for row in events],names,'all physical and re-signed refusals')
    for row in events:
        same(row.get('status'),'REJECTED','altered evidence was refused')
        need(row.get('type')in ('ValueError','AssertionError','FileNotFoundError','EOFError') and
             type(row.get('message'))is str and row['message'],'actual refusal exception')
        elapsed=row.get('elapsed_seconds');need(type(elapsed)in(int,float) and math.isfinite(elapsed) and 0<elapsed<180,'actual refusal duration')
    row=e.json(e.output/'controls.process.json');duration(row)
    same(row['name'],'controls','actual outer control process')
    same(row['pid'],summary['pid'],'actual control PID');same(row['cwd'],str(origin_source),'actual control cwd')
    source='tests/hia_native/test_batch_plan_input_original_evidence.py'
    same(row['command'],[summary['python'],'-I','-B',str(origin_source/source)],'actual control command')
    same(summary['python'],native_summary['python'],'same selected main interpreter')
    controlled={'HIA_BATCH_PLAN_INPUT_QUALIFICATION_OUTPUT':str(origin_output),
                'HIA_BATCH_PLAN_INPUT_EVIDENCE_CAPTURE_DIR':str(origin_capture)}
    same(row['controlled_env'],controlled,'actual controlled evidence environment')
    pins={name:e.source(name)['sha256']for name in ('scripts/hia_native_batch_plan_input_qualification.py',source)}
    same(row['source_before'],pins,'control sources before execution');same(row['source_after'],pins,'control sources after execution')
    logs=streams(e,e.output,row);same(json_value(logs['stdout'].read_bytes()),summary,'complete actual control stdout')
    same(logs['stderr'].read_bytes(),b'','actual control stderr')
    elapsed=summary['elapsed_seconds'];need(type(elapsed)in(int,float) and 0<elapsed<=row['elapsed_seconds'],'actual child control duration')
    syntax=ast.parse((e.root/source).read_bytes());children=[node for node in syntax.body if isinstance(node,ast.Assign) and
        any(isinstance(target,ast.Name) and target.id=='CHILD'for target in node.targets)]
    same(len(children),1,'one source-owned independent reader program');child=ast.literal_eval(children[0].value)
    rows=e.json(capture/'reader-processes.json');same(len(rows),2,'two actual independent reader processes')
    blocked=list(dict.fromkeys([str(origin_source),str(origin_output),native_summary['execution_source_root'],native_summary['execution_output_root']]))
    qpath=capture/'independent-python/pyvenv.cfg';e.file(qpath)
    need(b'include-system-site-packages = false' in qpath.read_bytes(),'isolated second interpreter configuration')
    for index,row in enumerate(rows):
        duration(row);label='relocated-one' if index==0 else 'relocated-two'
        selected=summary['python'] if index==0 else str(origin_capture/'independent-python/bin/python')
        relocated_source=origin_capture/label/'source';relocated_output=origin_capture/label/'output'
        emitted=origin_capture/('reader-'+str(index+1))/'EVIDENCE.json'
        command=[selected,'-I','-B','-c',child,str(relocated_source),str(relocated_output),json.dumps(blocked),str(emitted)]
        same(row['command'],command,'source-owned complete independent reader command')
        same(row['cwd'],str(relocated_source),'actual independent reader cwd')
        logs=streams(e,capture,row);same(logs['stderr'].read_bytes(),b'','independent reader stderr')
        observed=json_value(logs['stdout'].read_bytes());result_path=capture/('reader-'+str(index+1))/'EVIDENCE.json'
        same(e.json(result_path),full,'every field of the independent reader object')
        same(observed['complete_evidence'],e.file(result_path),'complete independent reader bytes')
        same({key:observed.get(key)for key in ('status','python','pid','new_native_calls','new_rust_processes')},
             {'status':'PASS','python':selected,'pid':row['pid'],'new_native_calls':0,'new_rust_processes':0},'actual pure reader identity')
        same(observed['actual_open_denials'],blocked,'actual forbidden original/cross-copy open probes')
        availability=observed['blocked_roots'];same([item['path']for item in availability],blocked,'all actual original root observations')
        need(all(type(item['absent'])is bool for item in availability),'actual root availability types')
        same(observed['all_blocked_roots_absent'],all(item['absent']for item in availability),'complete root availability')
        if summary['original_roots_actually_absent']:need(observed['all_blocked_roots_absent'],'actual original roots were absent')
        if index:
            need(all(item['absent']for item in availability[-2:]),'first copy actually unavailable to second reader')
        else:blocked.extend([str(relocated_source),str(relocated_output)])
    return {'schema':'hepta.runtime.batch-plan-input-qualification.v1','status':'PASS','native_original':full,
            'controls':summary,'actual_control_process':e.json(e.output/'controls.process.json'),
            'actual_reader_processes':rows,'refusal_controls':12,'physical_relocations':2,
            'actual_original_processes':4,'fresh_original_comparison_complete':True,
            'source_sha256':dict(sorted(e.sources.items())),'artifact_sha256':dict(sorted(e.artifacts.items())),
            'public_route_replaced':False,'whole_runtime_replaced':False,'new_native_calls':0,'new_rust_processes':0}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--original',action='store_true');parser.add_argument('--emit',type=Path)
    args=parser.parse_args();result=native_evidence(args.root,args.output,original=args.original)
    if args.emit:args.emit.write_bytes(canonical(result))
    print(json.dumps({k:v for k,v in result.items()if k not in ('source_sha256','artifact_sha256','complete_result_comparisons','original','native_process')},sort_keys=True))
