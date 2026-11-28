"""Offline admission of the complete native batch-diff and original Rust streams."""
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

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from hia_native_view_call_qualification import Evidence,canonical,digest,exact_read,integer,json_value,same,_producer

MEMBERS={
    'diff':('native/batch_diff.hepta','c65bc5ba0c150bfb5be54e20c54f926a7f496f9cdf2e740128de7053270e1435','c53179870716dbd4a137ade777354bf658e0860af1088800a9b7cb93cdf7495e'),
    'apply':('native/batch_apply.hepta','d94768091c596264e9b297705409cc8e3252315423a0b1aa7d19604cc7d66ae9','0ddbc6819af2dc3b238d59ced4fbe7dad428c0022277e7b5c4576c2e201cad59'),
    'editable':('native/editable_content.hepta','3ca1dd3fe69191dae3eb4a6df0cc103cf8cb7e6000148bfa95f31c957be0cedd','d05451fd67cc26f7bfcdec5a14f2f7cd345b4a4853a91602d23a1d4df2b3caf5'),
}
NATIVE_SOURCES=(
    'native/batch_diff.hepta','native/batch_diff_abi.md','native/batch_diff_composition.json',
    'native/batch_apply.hepta','native/editable_content.hepta','native/text_budget.hepta','native/result_publication.hepta',
    'scripts/hia_native_build.py','scripts/hia_native_loader.py','scripts/hia_native_batch_diff_build.py',
    'tests/hia_native/batch_apply_harness.py','tests/hia_native/batch_diff_harness.py',
    'tests/hia_native/test_batch_diff.py','tests/hia_native/batch_diff_oracle/cases.py',
)
COUNTS=dict(case_count=804,native_diff_calls=2451,independent_editable_calls=804,
            apply_calls=dict(requests=804,native_controller_calls=3212,native_editable_calls=2408),
            captured_records=6467,captured_raw_bytes=510553873,successful_native_diff_cases=802,native_apply_errors=2,
            complete_diff_bytes=17261188,over8mib_results=2,private_controls=45,
            input_bytes=20653794,input_sha256='31a9ca2a3629bec95457bc4fa64efc3ea0e281c32863de044b79e9b7c93325f0',
            output_bytes=74495241,output_sha256='749e0023b8ccf37dd7e19e35a93d4e3be14fd0e342b8a52919ce01e6d5b32bd6')


def require(ok,message):
    if not ok:raise ValueError('batch diff qualification: '+message)


def load(name,path):
    spec=importlib.util.spec_from_file_location('_batch_diff_'+name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def word(raw,at):return struct.unpack_from('<Q',raw,at)[0]


def _duration(row):
    require(type(row.get('exit_code')) is int and row['exit_code']==0,'process exit was not exact zero')
    require(row.get('timed_out') is False,'process timed out or omitted observation')
    require(type(row.get('timeout_seconds')) is int and row['timeout_seconds']==180,'process deadline changed')
    value=row.get('elapsed_seconds')
    require(type(value) in (int,float) and math.isfinite(value) and 0<=value<180,'invalid process duration')


def _descriptor(report):
    return (report or {}).get('batch_diff',{'manifest':'build/batch-diff.json','corpus':'batch-diff','original':'batch-diff-original'})


def _process(e,report,completed,label,source,expected,execution,*,development_name,unittest_groups=None):
    if completed is not None:
        row,summary=completed(e.output,report,label);same(summary,expected,'completed '+label)
        folder=e.path((report or {}).get('check_artifact_directories',{}).get(label,'.'))
        paths={kind:folder/(label+'.'+kind) for kind in ('stdout','stderr')}
        pins={kind:{'bytes':row[kind+'_bytes'],'sha256':row[kind+'_sha256']} for kind in paths}
    else:
        row=e.json(e.output/(development_name+'.process.json'))
        same(row.get('name'),development_name,'actual process identity')
        paths={kind:e.output/(development_name+'.'+kind) for kind in ('stdout','stderr')}
        pins={kind:{k:row[kind][k] for k in ('bytes','sha256')} for kind in paths}
    _duration(row)
    require(row.get('start_error') is None,'process failed to start')
    command=row.get('command');same(command,execution['command'],'actual '+label+' command')
    require(type(command) is list and len(command)>=4 and command[1:3]==['-I','-B'],'isolated Python command')
    require(command[0]==execution['python'] and Path(command[0]).is_absolute(),'actual Python identity')
    old_root=Path(execution['source_root']);require(old_root.is_absolute(),'absolute source origin')
    require(command[3]==str(old_root/source) and row.get('cwd')==str(old_root),'source/cwd origin differs')
    for kind,path in paths.items():
        raw=e.raw(path);same(dict(bytes=len(raw),sha256=digest(raw)),pins[kind],'complete '+label+' '+kind)
        if kind=='stdout':same(json_value(raw),expected,'actual '+label+' summary')
        elif unittest_groups is None:require(raw==b'','unexpected '+label+' stderr')
        else:
            require(('Ran '+str(unittest_groups)+' tests in ').encode() in raw and raw.endswith(b'\nOK\n'),
                    'actual '+label+' unittest completion')
    return row


def _modules(e,bundle_path):
    bundle=e.json(bundle_path)
    require(bundle.get('schema')=='hepta.runtime.batch-diff-build.v1','bundle schema')
    require(bundle.get('public_batch_route_replaced') is False and bundle.get('filesystem_effects_replaced') is False,'bundle scope')
    require(set(bundle['members'])==set(MEMBERS),'fixed three-image graph')
    base=bundle_path.parent;bootstrap=e.json(base/'bootstrap/bootstrap.json')
    require(bootstrap.get('schema')=='hepta.runtime.native-bootstrap.v1' and bootstrap.get('qualification')=='development_fixed_point','bootstrap qualification')
    require(bootstrap.get('matching_source_cold_qualified') is False,'development build claimed cold qualification')
    require(bootstrap['dependency']['commit']=='d3e2c90173cf733e42b299d0c4274df4b593a12f' and bootstrap['dependency']['tree']=='8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49','compiler source identity')
    require(bootstrap['compiler_source_sha256']=='388b182e42675f11435867dd99520e9452a4ff48e23c0766a3952b662acc7627','compiler source bytes')
    compiler='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
    require(bootstrap['generation_sha256']==compiler,'compiler fixed point')
    for label in ('B1','B2','B3'):require(e.file(base/'bootstrap'/(label+'.image.bin'))['sha256']==compiler,'actual compiler generation')
    for key,(source,source_sha,image_sha) in MEMBERS.items():
        item=bundle['members'][key];path=e.path(item['manifest'],base)
        same(item['source'],source,'member source name');metadata=e.json(path)
        require(e.file(path)['sha256']==item['manifest_sha256'],'member manifest identity')
        require(metadata.get('schema')=='hepta.runtime.native-module.v1' and metadata.get('abi')=='hepta.runtime.borrowed-bytes.linux-x86_64.v1','module ABI')
        require(metadata.get('target')=='linux-x86_64' and metadata.get('standalone') is None and metadata.get('buffer_profile')=='batch-plan.v1','module profile')
        same([metadata[k] for k in ('input_capacity','output_capacity','workspace_capacity')],[512<<20,1024<<20,1152<<20],'module capacities')
        require(metadata['compiler_commit']=='d3e2c90173cf733e42b299d0c4274df4b593a12f' and metadata['compiler_sha256']==compiler,'module compiler')
        require(metadata['source_sha256']==item['source_sha256']==e.source(source)['sha256']==source_sha,'exact owner source')
        require(metadata['image_sha256']==item['image_sha256']==image_sha,'exact owner image')
        require(e.file(e.path(metadata['source'],path.parent))['sha256']==source_sha,'complete compiled source')
        image=e.raw(e.path(metadata['image'],path.parent));require(digest(image)==image_sha,'complete machine image')
        _producer(e,path.parent,metadata,image,bootstrap)
        request=e.json(path.parent/'module.request.json')
        require(e.rebase(request['source'])==path.parent/'module.input.bin','compiler input origin')
        require(e.rebase(request['output'])==path.parent/'module.output.bin','compiler output origin')
        require(e.rebase(request['image'])==base/'bootstrap/B3.image.bin','compiler image origin')
    return bundle


def _native_record(raw):
    require(len(raw)>=72 and raw[:8]==b'HBDICO01','native result envelope')
    words=struct.unpack_from('<8Q',raw,8);require(words[0] in (0,1) and words[-1]==0,'native result flags')
    parts=[];at=72
    for size in words[1:7]:
        require(size<=len(raw)-at,'result payload extent');parts.append(raw[at:at+size]);at+=size
    require(at==len(raw),'result trailing payload')
    return words[0],parts


def _diff_response(code,out):
    require(code==64 and len(out)>=64 and out[:8]==b'HBDIFR02','diff return/header')
    values=struct.unpack_from('<7Q',out,8);status,size,count,old,new,needed,reserved=values
    require(status in (0,2,3,4) and reserved==0,'diff status/reserved')
    extent=64+size if status==0 else 64
    require(extent<=len(out) and out[extent:]==b'\xa5'*(len(out)-extent),'diff output extent/tail')
    return values


def _native_streams(e,capture,summary,cases):
    rows=e.rows(capture/'cases.jsonl');indices=e.rows(capture/'calls.jsonl')
    require(len(rows)==849 and len(indices)==6467,'complete case/call indices')
    for name in ('requests.bin.gz','native-output.bin.gz','calls.bin.gz'):e.file(capture/name)
    row_iter=iter(rows);index_iter=iter(indices);offset=0;serial=0;kind_counts=Counter();first_wire=None;first_needed=0
    requests_hash=hashlib.sha256(b'HBDIQ001');results_hash=hashlib.sha256(b'HBDIO001');request_bytes=8;result_bytes=8
    def call(stream,cid,kind):
        nonlocal offset,serial
        idx=next(index_iter);raw=exact_read(stream,64)
        ordinal,case_id,actual_kind,code,ilen,olen,wlen,reserved=struct.unpack('<8Q',raw)
        require(ordinal==serial+1 and case_id==cid and actual_kind==kind and reserved==0,'call order/ownership')
        require(ilen<=512<<20 and olen<=1024<<20 and wlen<=1152<<20 and 64+ilen+olen+wlen<=510553873-offset,'call extents')
        wire=exact_read(stream,ilen);out=exact_read(stream,olen);state=exact_read(stream,wlen)
        expected=dict(call=ordinal,case_id=cid,kind=kind,stream_offset=offset,input_bytes=ilen,input_sha256=digest(wire),
                      output_bytes=olen,output_sha256=digest(out),workspace_bytes=wlen,workspace_sha256=digest(state))
        expected['return']=code;same(idx,expected,'complete physical call/index')
        offset+=64+ilen+olen+wlen;serial+=1;kind_counts[kind]+=1
        return code,wire,out,state
    with gzip.open(capture/'requests.bin.gz','rb') as inputs,gzip.open(capture/'native-output.bin.gz','rb') as outputs,gzip.open(capture/'calls.bin.gz','rb') as calls:
        require(exact_read(inputs,8)==b'HBDIQ001' and exact_read(outputs,8)==b'HBDIO001','stream magics')
        for case in cases.iter_cases():
            cid=case['case_id'];row=next(row_iter)
            same((row['case_id'],row['name'],row['domain']),(cid,case['name'],case['domain']),'generated case identity')
            req_prefix=exact_read(inputs,8);wire=exact_read(inputs,word(req_prefix,0));require(wire==cases.encode(case),'complete native request differs from source corpus')
            requests_hash.update(req_prefix);requests_hash.update(wire);request_bytes+=8+len(wire)
            out_prefix=exact_read(outputs,8);result=exact_read(outputs,word(out_prefix,0));status,parts=_native_record(result)
            results_hash.update(out_prefix);results_hash.update(result);result_bytes+=8+len(result)
            old,new,rendered,plan,body,error=parts
            require(plan==cases.plan(case['operations']) and row['input_sha256']==digest(wire),'case input')
            same(row['status'],status,'case status type')
            same((row['output_bytes'],row['output_sha256']),(len(result),digest(result)),'complete case output')
            require(row['first_call']==serial+1,'case first call')
            raw=case['original'].encode();identity=struct.pack('<8s5Q',b'HEDIT001',1,len(raw),0,0,0)+raw
            code,observed,out,state=call(calls,cid,10)
            require(observed==identity and code==80+len(old) and out[:8]==b'HEDRES01','actual normalization input/return')
            require(word(out,8)==word(out,16)==word(out,72)==0 and word(out,48)==word(out,64)==len(old),'normalization header')
            require(out[80:code]==old and out[code:]==b'\xa5'*(len(out)-code),'normalization full bytes/tail')
            trace=[];observed_children=[];child_outputs=[];child_inputs=[]
            for phase in range(1,2 if status else 4):
                code,child_in,child_out,child_state=call(calls,cid,12)
                require(not child_state and 80<=code<=len(child_out) and child_in[:8]==b'HEDIT001' and child_out[:8]==b'HEDRES01','actual Editable child span')
                trace.append(dict(phase=phase,target=5,code=code,input_sha256=digest(child_in),input_bytes=len(child_in),output_sha256=digest(child_out[:code])))
                observed_children.append(dict(phase=phase,input_bytes=len(child_in),input_sha256=digest(child_in),
                                              output_bytes=len(child_out),output_sha256=digest(child_out),**{'return':code}))
                child_outputs.append(child_out[:code]);child_inputs.append(child_in)
            require(child_inputs[0]==identity and child_outputs[0][80:]==old,'same original normalization child')
            code,observed,applied,empty=call(calls,cid,11)
            require(observed==wire and not empty and code==len(applied) and applied[:8]==b'HBAPLR01','actual Apply completion')
            require(word(applied,8)==status,'Apply outcome')
            same(row['apply']['apply']['trace'],trace,'complete fixed-child call trace')
            same(row['apply']['child_calls'],observed_children,'complete borrowed child observation')
            same({k:row['apply']['apply'][k] for k in ('code','output_bytes','output_sha256')},
                 dict(code=code,output_bytes=len(applied),output_sha256=digest(applied)),'complete Apply result observation')
            for key in ('input_unchanged','output_tail_unchanged','guards_unchanged'):require(row['apply']['apply'][key] is True,'Apply borrowed boundary')
            if status:
                require(not new and not rendered and not body and error and applied[80:]==error and word(applied,64)==0,'complete original apply error')
                require(row['error_bytes']==len(error) and row['error_sha256']==digest(error),'error index')
            else:
                require(not error and word(applied,48)==len(new) and word(applied,56)==len(rendered) and applied[80:]==new+rendered,'complete Apply text')
                require(child_outputs[1][80:]==new and child_outputs[2][80:]==rendered,'actual final child bytes')
                require(child_inputs[1][:8]+child_inputs[1][16:]==child_inputs[2][:8]+child_inputs[2][16:] and word(child_inputs[1],8)==1 and word(child_inputs[2],8)==0,'same Editable program in both result modes')
                request=struct.pack('<8s7Q',b'HBDFQ002',0,len(old),len(new),len(plan),0,0,0)+old+new+plan
                expected_old=old.count(b'\n')+int(bool(old) and not old.endswith(b'\n'))
                expected_new=new.count(b'\n')+int(bool(new) and not new.endswith(b'\n'))
                required=512+len(case['operations'])*144+(expected_old+expected_new)*16
                for phase in (1,2,3):
                    code,incoming,out,state=call(calls,cid,phase);require(incoming==request,'growth retry changed input')
                    values=_diff_response(code,out);same(values[2:5],(len(case['operations']),expected_old,expected_new),'diff semantic metadata')
                    if phase==1:
                        require(values[0]==2 and values[1]==0 and values[5]==required and not state and len(out)==96,'workspace growth contract')
                    else:
                        require(state[:required]==bytes(required) and state[required:]==b'\x7b'*17,'complete owned scratch cleanup/tail')
                        require(values[1]==len(body) and values[5]==64+len(body),'exact complete output extent')
                        if phase==2:require(values[0]==(3 if body else 0) and len(out)==64,'exact output growth')
                        else:require(values[0]==0 and out[64:64+len(body)]==body and len(out)==64+len(body)+29,'complete rendered body')
                require(row['body_bytes']==len(body) and row['body_sha256']==digest(body) and row['diff_request_sha256']==digest(request),'diff complete row identity')
                require(row['workspace_required']==required and row['old_lines']==expected_old and row['new_lines']==expected_new,'row resource metadata')
                if first_wire is None:first_wire=request;first_needed=required
            require(row['last_call']==serial,'case final call')
        for ordinal,(name,wire,oc,wc,expected) in enumerate(cases.private_frames(first_wire)):
            cid=100000+ordinal;row=next(row_iter);code,incoming,out,state=call(calls,cid,4)
            require(incoming==wire and code==expected and out==b'\xa5'*oc and state==b'\x7b'*wc,'physical refusal changed input/output/workspace domain')
            same(row,dict(case_id=cid,name=name,domain='private-framing-capacity',first_call=serial,last_call=serial,**{'return':code}),'private control index')
        row=next(row_iter);code,wire,out,state=call(calls,200000,5);values=_diff_response(code,out)
        require(wire==first_wire and values[0]==2 and values[5]==first_needed and len(out)==96 and state==b'\x7b'*(first_needed-1),'exact workspace-boundary control')
        same(row,dict(case_id=200000,name='exact-workspace-growth',domain='private-growth',first_call=serial,last_call=serial,**{'return':code}),'workspace control index')
        require(next(row_iter,None) is None and next(index_iter,None) is None,'unaccounted indexed call/case')
        require(inputs.read(1)==outputs.read(1)==calls.read(1)==b'','unindexed stream tail')
    same(kind_counts,Counter({1:802,2:802,3:802,4:44,5:1,10:804,11:804,12:2408}),'complete call split')
    require(offset==510553873 and serial==6467,'complete raw call extent')
    same((request_bytes,requests_hash.hexdigest()),(summary['input_bytes'],summary['input_sha256']),'complete request stream')
    same((result_bytes,results_hash.hexdigest()),(summary['output_bytes'],summary['output_sha256']),'complete result stream')


def native_evidence(root,output,report=None,completed=None):
    e=Evidence(root,output);descriptor=_descriptor(report)
    capture=e.path(descriptor['corpus']);bundle_path=e.path(descriptor['manifest'])
    summary=e.json(capture/'result.json')
    same({k:summary.get(k) for k in COUNTS},COUNTS,'complete native counts')
    require(summary.get('status')=='PASS' and summary.get('reference')=='NOT_RUN' and summary.get('test_groups')==3,'native producer status')
    for key in ('public_batch_route_executed','filesystem_effects_executed'):require(summary.get(key) is False,'native scope inflated')
    for key in ('skipped','errors','failures'):same(summary.get(key),0,'native '+key)
    same(e.json(capture/'failures.json'),[],'native failures')
    execution=e.json(capture/'execution.json');require(execution.get('schema')=='hepta.runtime.batch-diff-native-execution.v1','execution schema')
    old_source=Path(execution['source_root']);old_capture=Path(execution['capture_root'])
    require(old_source.is_absolute() and old_capture.is_absolute(),'missing execution origins')
    old_output=old_capture
    for _ in capture.relative_to(e.output).parts:old_output=old_output.parent
    require(old_output/capture.relative_to(e.output)==old_capture,'capture origin suffix')
    require(execution['bundle_path']==str(old_output/bundle_path.relative_to(e.output)),'shared build origin')
    require(execution['cwd']==str(old_source),'execution cwd')
    command=execution['command'];require(len(command) in (4,8),'native command argument count')
    if len(command)==8:same(command[4:],['--bundle',execution['bundle_path'],'--capture',str(old_capture)],'native argument spans')
    check=_process(e,report,completed,'test_batch_diff.py',Path('tests/hia_native/test_batch_diff.py'),summary,execution,development_name='native')
    e.old_roots.extend([(old_source,e.root),(old_output,e.output)])
    require(set(execution['sources'])==set(NATIVE_SOURCES),'complete native source closure')
    for source,sha in execution['sources'].items():require(e.source(source)['sha256']==sha,'native source changed '+source)
    require(e.file(bundle_path)['sha256']==execution['bundle_sha256'],'actual bundle changed')
    _modules(e,bundle_path)
    cases=load('cases',e.root/'tests/hia_native/batch_diff_oracle/cases.py')
    _native_streams(e,capture,summary,cases)
    for name in ('scripts/hia_native_batch_diff_qualification.py','scripts/hia_native_view_call_qualification.py'):e.source(name)
    return {'schema':'hepta.runtime.batch-diff-native-evidence.v1','status':'PASS','counts':COUNTS,
            'native_process':check,'execution':execution,'source_sha256':dict(sorted(e.sources.items())),
            'artifacts':sorted(e.artifacts),'artifact_sha256':dict(sorted(e.artifacts.items())),
            'public_batch_route_executed':False,'filesystem_effects_executed':False,'native_cases_added_by_readback':0}


def original_evidence(root,output,report=None,completed=None,*,native=None):
    admitted=native_evidence(root,output,report,completed)
    if native is not None:same(native,admitted,'previous native admission')
    e=Evidence(root,output);e.sources.update(admitted['source_sha256']);e.artifacts.update(admitted['artifact_sha256'])
    descriptor=_descriptor(report);folder=e.path(descriptor.get('original','batch-diff-original'))
    native_folder=e.path(descriptor['corpus']);record=e.json(folder/'result.json')
    require(record.get('schema')=='hepta.runtime.batch-diff-original-result.v1' and record.get('status')=='PASS','original result')
    same({k:record.get(k) for k in ('cases','successful_diff_cases','actual_processes')},dict(cases=804,successful_diff_cases=802,actual_processes=3),'original counts')
    for key in ('public_batch_route_executed','filesystem_effects_executed'):require(record.get(key) is False,'original scope inflated')
    execution=record['execution'];origin=Path(execution['source_root']);old_folder=Path(record['output_root'])
    require(origin.is_absolute() and old_folder.is_absolute() and record['runtime_root']==str(origin),'original source/output origins')
    old_output=old_folder
    for _ in folder.relative_to(e.output).parts:old_output=old_output.parent
    require(old_output/folder.relative_to(e.output)==old_folder and record['native_origin']==str(old_output/native_folder.relative_to(e.output)),'original complete output origin')
    original_sources=('assemble.py','cases.py','run.py','src/carrier.rs')
    for name in original_sources:
        source='tests/hia_native/batch_diff_oracle/'+name
        require(e.source(source)['sha256']==record['harness_sources'][name],'original harness source '+name)
    require(set(record['harness_sources'])==set(original_sources),'complete original harness')
    assembly=load('assembly',e.root/'tests/hia_native/batch_diff_oracle/assemble.py')
    expected_source,expected_manifest=assembly.assemble(e.root,None);expected_manifest['runtime_root']=str(origin)
    for source in assembly.ORIGINAL_SOURCES:e.source(source)
    require(e.raw(folder/'generated/main.rs')==expected_source.encode(),'complete unchanged original Rust carrier')
    same(e.json(folder/'generated/source-manifest.json'),expected_manifest,'exact original source slices')
    same(record['source_manifest'],expected_manifest,'original source/result binding')
    receipts=e.json(folder/'process-receipts.json');require(type(receipts) is list and len(receipts)==3,'original process count')
    rustc=receipts[0]['command'][0];require(Path(rustc).is_absolute(),'actual Rust compiler path')
    same(execution['command'][4:],['--runtime',str(origin),'--native',record['native_origin'],'--output',str(old_folder),'--rustc',rustc],'original wrapper arguments')
    wrapper=_process(e,report,completed,'batch_diff_original',Path('tests/hia_native/batch_diff_oracle/run.py'),record,execution,development_name='original')
    commands=[[rustc,'-Vv'],[rustc,'-O','--edition=2024',str(old_folder/'generated/main.rs'),'-o',str(old_folder/'original-batch-diff')],[str(old_folder/'original-batch-diff')]]
    names=['rustc-version','rustc-build','original']
    for index,row in enumerate(receipts):
        _duration(row);same(row.get('name'),names[index],'original process name');same(row.get('command'),commands[index],'original command')
        require(row.get('cwd')==str(origin/'tests/hia_native/batch_diff_oracle'),'original cwd')
        same(row.get('controlled_env'),dict(PATH=str(Path(rustc).parent)+':/usr/bin:/bin',RUSTC=rustc,LC_ALL='C'),'actual Rust environment')
        for kind in ('stdout','stderr'):
            require(row[kind]['path']==names[index]+'.'+kind,'original stream path')
            same(e.file(folder/row[kind]['path']),{k:row[kind][k] for k in ('bytes','sha256')},'complete original '+kind)
        if index<2:require(row['stdin'] is None,'unexpected original compiler input')
        else:same(row['stdin'],dict(path='input.bin',bytes=record['input_bytes'],sha256=record['input_sha256']),'complete original replay input')
    require(e.raw(folder/'rustc-version.stdout').startswith(b'rustc 1.95.0 (59807616e 2026-04-14)\n'),'unqualified Rust version')
    require(e.raw(folder/'rustc-version.stderr')==e.raw(folder/'rustc-build.stdout')==e.raw(folder/'rustc-build.stderr')==b'','Rust version/build stream')
    same(e.json(folder/'original.stderr'),dict(status='PASS',original_cases=804,successful_diff_cases=802,output_body_bytes=74488801),'actual original replay completion')
    require(e.file(folder/'original-batch-diff')['sha256']==record['binary_sha256'] and (folder/'original-batch-diff').stat().st_size==record['binary_bytes'],'original compiled binary')
    for native_name,original_name,bytes_key,sha_key in [('requests.bin.gz','input.bin','input_bytes','input_sha256'),('native-output.bin.gz','original.stdout','original_stdout_bytes','original_stdout_sha256')]:
        pin=e.file(folder/original_name);same(pin,dict(bytes=record[bytes_key],sha256=record[sha_key]),'original full '+original_name)
        with gzip.open(native_folder/native_name,'rb') as actual,(folder/original_name).open('rb') as original:
            while True:
                part=original.read(1<<20);require(actual.read(len(part))==part,'full original/native byte comparison')
                if not part:break
            require(actual.read(1)==b'','extra native bytes')
    require(record['native_result_sha256']==e.file(native_folder/'result.json')['sha256'],'original compared another native capture')
    return {'schema':'hepta.runtime.batch-diff-original-evidence.v1','status':'PASS','native':admitted,
            'actual_original_processes':3,'original_process':wrapper,'original_cases':804,'successful_diff_cases':802,'complete_diff_bytes':17261188,
            'source_sha256':dict(sorted(e.sources.items())),'artifacts':sorted(e.artifacts),'artifact_sha256':dict(sorted(e.artifacts.items())),
            'native_cases_added_by_readback':0,'original_cases_added_by_readback':0,'public_batch_route_executed':False,'filesystem_effects_executed':False}


def qualification_evidence(root,output,report=None,completed=None,*,native=None):
    """Admit the actual post-original controls without running native/Rust code."""
    original=original_evidence(root,output,report,completed,native=native)
    e=Evidence(root,output);e.sources.update(original['source_sha256']);e.artifacts.update(original['artifact_sha256'])
    descriptor=_descriptor(report);capture=e.path(descriptor.get('controls','batch-diff-controls'))
    source='tests/hia_native/test_batch_diff_original_evidence.py';label=Path(source).name
    reader='scripts/hia_native_batch_diff_qualification.py'
    test_pin=e.source(source)['sha256'];reader_pin=e.source(reader)['sha256']
    expected={'status':'PASS','test_groups':2,'refusal_controls':12,'relocations':2,'completed_controls':14,
              'skipped':0,'errors':0,'failures':0,'test_sha256':test_pin,'reader_sha256':reader_pin,
              'baseline_sha256':digest(canonical(original)),'native_cases_added_by_replay':0,
              'original_processes_added_by_replay':0,'original_paths_removed':False,'old_path_reads_forbidden':True}
    same(e.json(capture/'result.json'),expected,'complete evidence controls')
    same(e.json(capture/'baseline.json'),original,'controls admitted another baseline')
    execution=e.json(capture/'execution.json');origin=Path(execution['source_root']);old_output=Path(execution['output_root'])
    require(origin.is_absolute() and old_output.is_absolute(),'control absolute origins')
    same(execution['capture_root'],str(old_output/capture.relative_to(e.output)),'control capture origin')
    same(execution['sources'],{source:test_pin,reader:reader_pin},'executed control sources')
    same(execution['command'],[execution['python'],'-I','-B',str(origin/source)],'control command')
    check=_process(e,report,completed,label,Path(source),expected,execution,development_name='controls',unittest_groups=2)
    if completed is None:
        same(check.get('controlled_env'),{'HIA_BATCH_DIFF_QUALIFICATION_OUTPUT':str(old_output),
             'HIA_BATCH_DIFF_EVIDENCE_CAPTURE_DIR':str(old_output/capture.relative_to(e.output))},'actual control environment')
    rows=e.json(capture/'controls.json')
    names=['boolean-exit','timeout','deadline','wrong-command','missing-semantic-case','image-bytes','missing-call',
           'resigned-refusal-output','resigned-growth-extent','resigned-original-body','original-source-bytes','missing-rust-process']
    require(type(rows) is list and len(rows)==14,'missing physical refusal/relocation result')
    for row,name in zip(rows[:12],names):
        require(set(row)=={'name','rejected','error_type','error'} and row['name']==name and row['rejected'] is True,'control was not rejected')
        require(row['error_type'] in ('ValueError','AssertionError','OSError','KeyError','TypeError') and type(row['error']) is str and row['error'],
                'missing actual rejection observation')
    assignments=[node for node in ast.parse((e.root/source).read_bytes()).body if isinstance(node,ast.Assign)
                 and any(isinstance(target,ast.Name) and target.id=='WORKER' for target in node.targets)]
    require(len(assignments)==1,'missing unique source-owned isolation worker')
    worker=e.raw(capture/'worker.py');require(worker==ast.literal_eval(assignments[0].value).encode(),'isolation worker source')
    receipts=e.json(capture/'processes.json');require(type(receipts) is list and len(receipts)==2,'relocation process count')
    for index,row in enumerate(receipts):
        _duration(row);same(row.get('name'),'relocated-'+str(index),'actual relocated process identity')
        command=row.get('command')
        require(type(command) is list and len(command)==9 and command[:3]==[execution['python'],'-I','-B'],'isolated reader command')
        folder=Path(command[3]).parent
        require(folder.is_absolute() and folder.name.startswith('batch-diff-relocated-'),'private relocation root')
        same(command[3:],[str(folder/'worker.py'),str(folder/'source'),str(folder/'output'),str(origin),str(old_output),str(folder/'result.json')],
             'actual relocation origins')
        same(row.get('cwd'),str(folder/'source'),'actual relocated cwd');same(row.get('worker_sha256'),digest(worker),'executed relocation worker')
        for kind in ('stdout','stderr','evidence'):
            item=row[kind];name=str(index)+('.result.json' if kind=='evidence' else '.'+kind)
            same(item['path'],name,'relocated stream path');raw=e.raw(capture/name)
            same(dict(bytes=len(raw),sha256=digest(raw)),{k:item[k] for k in ('bytes','sha256')},'complete relocated '+kind)
            if kind=='evidence':same(json_value(raw),original,'relocated complete evidence changed')
            elif kind=='stderr':require(raw==b'','relocated reader stderr')
            else:same(json_value(raw),dict(status='PASS',source=str(folder/'source'),output=str(folder/'output'),old_path_reads_forbidden=True,
                      semantic_execution_forbidden=True,new_native_calls=0,new_rust_processes=0),'actual isolated-reader summary')
        same(rows[12+index],dict(name='relocated-'+str(index),same_complete_object=True,old_path_reads_forbidden=True,
                               new_native_calls=0,new_rust_processes=0),'relocated complete-object observation')
    return {'schema':'hepta.runtime.batch-diff-qualified-evidence.v1','status':'PASS','native_counts':COUNTS,
            'actual_original_processes':3,'original_cases':804,'successful_diff_cases':802,
            'test_groups':2,'refusal_controls':12,'relocations':2,
            'native_evidence_sha256':digest(canonical(original['native'])),'original_evidence_sha256':digest(canonical(original)),
            'sources':sorted(e.sources),'source_sha256':dict(sorted(e.sources.items())),
            'artifacts':sorted(e.artifacts),'artifact_sha256':dict(sorted(e.artifacts.items())),
            'native_cases_added_by_readback':0,'original_cases_added_by_readback':0,'public_batch_route_executed':False,'filesystem_effects_executed':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--original',action='store_true');parser.add_argument('--qualified',action='store_true');args=parser.parse_args()
    result=(qualification_evidence if args.qualified else original_evidence if args.original else native_evidence)(args.root,args.output)
    print(json.dumps(result,sort_keys=True))
