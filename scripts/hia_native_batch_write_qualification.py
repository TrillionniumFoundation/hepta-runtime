"""Inspect full Local batch artifacts and retained invocation evidence.

Inspection executes no semantic owner and is not a replacement for a completed
native subprocess, the mandatory fresh original Rust recipe, or the cold gate.
"""
from __future__ import annotations
import collections
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
for path in (ROOT/'scripts',ROOT/'tests/hia_native'):
    if str(path) not in sys.path:sys.path.insert(0,str(path))
import hia_native_batch_write_build as build
import prepare_batch_body_original as original
import prepare_batch_render_original as render_original
from hia_native_batch_write_build import exact,require,read,obj,sha,canonical,file_record

NATIVE_SUITES=('test_batch_write_controller.py','test_batch_render.py','test_utf8_probe.py',
              'test_batch_write_files.py','test_batch_write_kernel.py',
              'test_batch_write_concurrency.py','test_batch_write_wide.py')
SUITES=(*NATIVE_SUITES,'test_batch_write_evidence.py')
SOURCE_NAMES=(
    'scripts/hia_native_batch_write_qualification.py','scripts/hia_native_batch_write_pipeline.py',
    'scripts/prepare_batch_body_original.py','scripts/prepare_batch_render_original.py',
    *('tests/hia_native/'+name for name in SUITES),
    *('tests/hia_native/'+name for name in (
       'batch_write_harness.py','batch_render_reference.py','batch_write_supervisor.py',
       'batch_write_trace_common.py','compare_batch_write_files.py','compare_batch_write_original.py',
       'oracle_batch_write.rs','oracle_batch_render.rs','batch_write_file_plan.json',
       'compare_batch_write_wide_retained.py','test_batch_write_retained_wide.py',
       'test_batch_plan.py','batch_plan_harness.py','batch_apply_harness.py','batch_apply_reference.py',
       'test_line_endpoint.py','test_line_verify.py','test_editable_content.py','rust_debug_properties.json')),
    *original.QUALIFICATION_PINS,
)
DIRECT_DOMAINS=dict(early_admission=16,original_endings=232,ordered_validation=260,
                   resolved_conflict_apply=400,all_fifty=1)
FILE_DOMAINS=dict(DIRECT_DOMAINS,existing_mode=7,full_five_mib_content=1,full_five_mib_file=1,
    missing_path=3,read_directory=1,strict_invalid_utf8=1,symlink_replaced_after_followed_read=1,
    temporary_is_directory=1,temporary_name_too_long=1)
CONTROLLER_COUNTS=dict(actual_filesystem_effects=0,buffer_growths=1037,native_leaf_calls=33419,
    native_root_calls=14903,requests=984,synthetic_canonical_completions=1819,
    synthetic_filesystem_completions=3188)
CONTROLLER_TARGETS={7:3629,3:459,5:912,0:14903,9:1823,1:8163,8:905,12:649,13:455}
CONTROLLER_STREAMS={
    'calls.jsonl.gz':dict(bytes=101833658,sha256='a04111e21888d4c8e8e9999296f58b8a993215d6162fc7055bf0668eb3023d72'),
    'cases.jsonl.gz':dict(bytes=2448451,sha256='6f347bd917480ee77bcb3bcb32cb5c88167574ee07531409897834cd1cb65be8')}
CONTROLLER_CONTROLS=['first_exists_missing','first_read_error_wrapper','second_read_error_unwrapped',
    'read_cancel_releases_guard','write_cancel_releases_guard','write_error_releases_guard',
    'history_uses_fresh_second_read','separate_cache_get_set_with_second_normalize',
    'no_context_still_computes_fresh_key','cancel_before_first_dispatch',
    'truncated_outer_frame_64_cases','short_workspace_no_output']
RENDER_STREAMS={
    'requests.gz':dict(bytes=50024901,sha256='5f269b526f7d07113b41df273196cc7181e1c458ac36d5b67eabab351d5036cb'),
    'native-output.gz':dict(bytes=12229698,sha256='cad5777439761a1e620cd211db6dbc9e7a6240a50b130f034ec111a9d2f1ee01')}
WIDE_OUTPUT=dict(bytes=1279265842,sha256='fd40fe3f57a05a06f0b8f34d13f719cc07dc473b45422e97ed1d955f52cb94a9')
WIDE_FILE=dict(bytes=262144100,sha256='cc7277b1b9d647eabe1979c77ccbc7b8765108064b4e941175ae999fcc0941f6')
FILE_PLAN_SHA='460eaefefdd14703a841d11a56398eb91db2def2019aa7bb0a9bf4789e710c5f'


def duration(value,reason):
    require(type(value)in(int,float) and math.isfinite(value) and 0<=value<=180,reason)


def pins(root=ROOT):
    root=Path(root);result=build.source_pins(root)
    exact(read(root/'scripts/hia_native_batch_write_qualification.py'),read(__file__),'loaded batch evidence inspector differs')
    for name,module in [('prepare_batch_body_original',original),('prepare_batch_render_original',render_original)]:
        exact(read(root/'scripts'/(name+'.py')),read(module.__file__),'loaded batch original extractor differs')
    for name in SOURCE_NAMES:result[name]=file_record(root/name)
    for name,digest in {**original.PINS,**original.QUALIFICATION_PINS}.items():
        exact(result[name]['sha256'],digest,'batch original dependency differs: '+name)
    exact(result['tests/hia_native/batch_write_file_plan.json']['sha256'],FILE_PLAN_SHA,'batch original file domain plan changed')
    return result


def process_stdout(path,expected):
    exact(obj(path),expected,'batch completed stdout differs')
    return file_record(path)


def sequence(path):
    value=json.loads(read(path),object_pairs_hook=atomic_pairs)
    require(type(value)is list,'batch retained JSON sequence differs')
    return value


def stream_record(path,compressed=False):
    digest=hashlib.sha256();size=0
    with (gzip.open(path,'rb') if compressed else Path(path).open('rb')) as handle:
        while raw:=handle.read(1<<20):digest.update(raw);size+=len(raw)
    return dict(bytes=size,sha256=digest.hexdigest())


def take(handle,count):
    raw=handle.read(count);require(len(raw)==count,'batch retained stream is truncated');return raw


def framed(handle,header,limit):
    while raw:=handle.read(header):
        require(len(raw)==header,'batch retained frame header is truncated')
        size=struct.unpack_from('<Q',raw)[0]
        require(size<=limit,'batch retained frame exceeds its exact qualified domain')
        yield raw,take(handle,size)


def original_project_evidence(folder,root=ROOT,render=False):
    folder,root=Path(folder),Path(root)
    expected,record=(render_original if render else original).inputs(root,root)
    exact({str(p.relative_to(folder)) for p in folder.rglob('*') if p.is_file()},set(expected),
          'batch original source file set differs')
    for name,raw in expected.items():exact(read(folder/name),raw,'batch actual original project differs: '+name)
    return dict(inputs=record,files={name:file_record(folder/name) for name in expected})


def module_id(folder,kind):
    path=Path(folder)/(kind+'.json');document=obj(path)
    return dict(manifest_sha256=sha(read(path)),source_sha256=document['source_sha256'],
                image_sha256=document['image_sha256'])


def controller_evidence(folder,manifest,stdout,root=ROOT):
    folder,manifest,root=Path(folder),Path(manifest),Path(root);report=obj(folder/'result.json')
    expected=dict(schema='hepta.runtime.batch-write-controller-observation.v1',status='PASS',
        completed_cases=909,actual_filesystem_effects=0,original_rust_body_replay='PENDING',
        domains=DIRECT_DOMAINS,counts=CONTROLLER_COUNTS,controls=CONTROLLER_CONTROLS,
        test_sha256=sha(read(root/'tests/hia_native/test_batch_write_controller.py')),
        harness_sha256=sha(read(root/'tests/hia_native/batch_write_harness.py')))
    for key,value in expected.items():exact(report.get(key),value,'batch direct controller evidence differs: '+key)
    require(type(report['source_root'])is str and Path(report['source_root']).is_absolute(),'batch controller source root missing')
    duration(report['elapsed_seconds'],'batch controller deadline exceeded')
    exact(report['loaded_modules'],[dict(id=i,**module_id(manifest.parent,build.ORDER[i]))
          for i in (0,1,3,5,7,8,9,10,11,12,13)],'batch direct test loaded another image')
    streams={}
    for name,wanted in CONTROLLER_STREAMS.items():
        exact(report[name],file_record(folder/name),'batch direct capture changed')
        raw=stream_record(folder/name,True);exact(raw,wanted,'batch complete direct trace differs')
        streams[name]=dict(gzip=file_record(folder/name),raw=raw)
    targets=collections.Counter();root_calls=leaf_calls=0
    with gzip.open(folder/'calls.jsonl.gz','rb') as incoming:
        for raw in incoming:
            row=json.loads(raw);target=row['target'];targets[target]+=1
            if 'nested_actual_calls'in row:
                require(target in(9,12) and type(row['nested_actual_calls'])is int and row['nested_actual_calls']>0,
                        'batch nested owner invocation count invalid')
                leaf_calls+=row['nested_actual_calls']
                exact(len(bytes.fromhex(row['output_hex'])),row['result']['code'] if row['result']['code']<0xffff0000 else 0,
                      'batch nested owner output truncated')
            else:
                root_calls+=int(target==0);leaf_calls+=int(target!=0)
                output=bytes.fromhex(row['output_hex'])
                exact(len(output),row['code'] if row['code']<0xffff0000 else 0,'batch direct owner output truncated')
                require(len(bytes.fromhex(row['workspace_prefix_hex']))==min(1024,row['workspace_bytes']),
                        'batch direct workspace prefix omitted')
    exact(dict(targets),CONTROLLER_TARGETS,'batch direct target domain omitted')
    exact((root_calls,leaf_calls),(14903,33419),'batch real direct/native nested counts differ')
    rows=[]
    with gzip.open(folder/'cases.jsonl.gz','rb') as incoming:
        for raw in incoming:
            row=json.loads(raw);exact(row['ordinal'],len(rows),'batch direct case ordinal differs');rows.append(row)
    exact(dict(collections.Counter(row['domain'] for row in rows)),DIRECT_DOMAINS,'batch direct semantic domain omitted')
    return dict(result=file_record(folder/'result.json'),stdout=process_stdout(stdout,report),streams=streams,
                counts=CONTROLLER_COUNTS,actual_filesystem_effects=0)


def render_evidence(folder,manifest,stdout,root=ROOT):
    folder,manifest=Path(folder),Path(manifest);report=obj(folder/'result.json')
    expected=dict(schema='hepta.runtime.batch-render-native.v1',status='PASS',cases=6738,controls=214,native_calls=6952,
        **module_id(manifest.parent,'batch_render'),production_activated=False,whole_runtime_replaced=False,
        requests_bytes=50024901,requests_sha256=RENDER_STREAMS['requests.gz']['sha256'],
        native_output_bytes=12229698,native_output_sha256=RENDER_STREAMS['native-output.gz']['sha256'])
    exact(set(report),set(expected)|{'seconds'},'batch renderer result shape differs')
    for key,value in expected.items():exact(report[key],value,'batch renderer evidence differs: '+key)
    duration(report['seconds'],'batch renderer deadline exceeded')
    streams={}
    for name,wanted in RENDER_STREAMS.items():
        observed=stream_record(folder/name,True);exact(observed,wanted,'batch complete renderer corpus differs')
        streams[name]=dict(gzip=file_record(folder/name),raw=observed)
    cases=sequence(folder/'cases.json');controls=sequence(folder/'controls.json')
    exact(len(cases),6738,'batch renderer case domain omitted');exact(len(controls),214,'batch renderer controls omitted')
    with gzip.open(folder/'requests.gz','rb') as requests,gzip.open(folder/'native-output.gz','rb') as responses:
        for index,row in enumerate(cases):
            wire=take(requests,struct.unpack('<Q',take(requests,8))[0]);output=take(responses,struct.unpack('<Q',take(responses,8))[0])
            for key,value in dict(ordinal=index,input_bytes=len(wire),input_sha256=sha(wire),output_bytes=len(output),output_sha256=sha(output)).items():
                exact(row[key],value,'batch renderer retained row differs')
        exact(requests.read(1)+responses.read(1),b'','batch renderer unexpected corpus suffix')
    exact(collections.Counter(row['kind'] for row in controls),collections.Counter(invalid=206,output_capacity=6,workspace_capacity=2),
          'batch renderer invalid/capacity domain differs')
    return dict(result=file_record(folder/'result.json'),stdout=process_stdout(stdout,report),streams=streams,
        cases=file_record(folder/'cases.json'),controls=file_record(folder/'controls.json'),actual_native_calls=6952)


def utf8_evidence(folder,manifest,stdout,root=ROOT):
    folder,manifest,root=Path(folder),Path(manifest),Path(root);report=obj(folder/'result.json')
    expected=dict(schema='hepta.private.batch-utf8-probe-result.v1',status='PASS',compared_inputs=78451,
        actual_native_calls=156922,input_sha256='089782dbe69d241acf310fa1634b3def2819cf787f2fba315e52ea92119dc8c3',
        expected_sha256='de5fbae5f629a2eb0ef4086a4f3f9ae984027aa94faf37349f9f7ef120864fe2',
        composition_sha256=sha(read(root/'tests/hia_native/batch_utf8_composition.json')),
        test_sha256=sha(read(root/'tests/hia_native/test_utf8_probe.py')),
        exact_same_relocated_production_closure=True,original_rust_execution=False,
        modules={name:module_id(manifest.parent,'utf8_'+name) for name in ('new','original')})
    exact(set(report),set(expected)|{'correctness_seconds','seconds','timing_rows'},'batch UTF8 result shape differs')
    for key,value in expected.items():exact(report[key],value,'batch UTF8 evidence differs: '+key)
    duration(report['seconds'],'batch UTF8 deadline exceeded');duration(report['correctness_seconds'],'batch UTF8 correctness deadline exceeded')
    rows=report['timing_rows'];exact(len(rows),6,'batch UTF8 full ASCII timing domain omitted')
    for row,(size,variant) in zip(rows,((size,name) for size in(1<<20,5<<20,32<<20) for name in('original','new')),strict=True):
        exact(row['bytes'],size,'batch UTF8 large input omitted');exact(row['variant'],variant,'batch UTF8 variant omitted')
        exact(row['source_sha256'],expected['modules'][variant]['source_sha256'],'batch UTF8 timing ran another source')
        require(len(row['samples_ns'])==3 and all(type(n)is int and n>=0 for n in row['samples_ns']),'batch UTF8 timing calls omitted')
        exact(row['median_ns'],sorted(row['samples_ns'])[1],'batch UTF8 timing projection differs')
    sources=stream_record(folder/'requests.bin.gz',True);a=stream_record(folder/'new.bin.gz',True);b=stream_record(folder/'original.bin.gz',True)
    exact(sources['sha256'],expected['input_sha256'],'batch UTF8 complete input changed')
    exact(a,dict(bytes=78451,sha256=expected['expected_sha256']),'batch UTF8 actual candidate output changed');exact(b,a,'batch UTF8 actual original HIA output differs')
    count=0
    with gzip.open(folder/'requests.bin.gz','rb') as requests,gzip.open(folder/'new.bin.gz','rb') as new,gzip.open(folder/'original.bin.gz','rb') as old:
        for _,wire in framed(requests,8,4096):
            try:wire.decode('utf-8');value=b'\1'
            except UnicodeDecodeError:value=b'\0'
            exact(take(new,1),value,'batch UTF8 Python differential changed');exact(take(old,1),value,'batch UTF8 original HIA differential changed');count+=1
        exact(new.read(1)+old.read(1),b'','batch UTF8 output suffix')
    exact(count,78451,'batch UTF8 exact discrete domain omitted')
    return dict(result=file_record(folder/'result.json'),stdout=process_stdout(stdout,report),
        captures={name:file_record(folder/(name+'.bin.gz')) for name in ('requests','new','original')},
        input=sources,new=a,original=b,actual_native_calls=156922)


def request_fields(wire):
    require(len(wire)>=64 and wire[:8]==b'HFBWT001','batch request identity differs')
    context,plen,dlen,count,rlen,present,zero=struct.unpack_from('<7Q',wire,8)
    require(context in(1,2) and present in(0,1) and zero==0 and 64+plen+dlen+rlen==len(wire),'batch request extent differs')
    return context,wire[64:64+plen],wire[64+plen:64+plen+dlen],count,wire[64+plen+dlen:],present


def canonical_case(wire,output,base):
    context,path,display,count,records,present=request_fields(wire)
    path=path.replace(base,b'/fixture');display=display.replace(base,b'/fixture')
    canonical_input=b'HFBWT001'+struct.pack('<7Q',context,len(path),len(display),count,len(records),present,0)+path+display+records
    require(output[:8]==b'HFBWR001' and len(output)>=32,'batch response identity differs')
    kind,size,zero=struct.unpack_from('<3Q',output,8)
    require(kind in(0,1) and size==len(output)-32 and zero==0,'batch response extent differs')
    body=output[32:].replace(base,b'/fixture');canonical_output=b'HFBWR001'+struct.pack('<3Q',kind,len(body),0)+body
    return dict(input_bytes=len(canonical_input),input_sha256=sha(canonical_input),
                output_bytes=len(canonical_output),output_sha256=sha(canonical_output),outcome=kind)


def body_projection(inventory):
    return [{key:row[key] for key in ('path_hex','kind','bytes','sha256','read_errno','link_hex') if key in row}
            for row in inventory]


def requests(raw):
    rows=[];cancellations=[];at=0
    while at<len(raw):
        require(len(raw)-at>=16,'batch request transport header truncated')
        size,tag=struct.unpack_from('<QQ',raw,at);at+=16
        if size==(1<<64)-1:cancellations.append(tag);continue
        require(64<=size<=len(raw)-at,'batch request transport body truncated')
        wire=raw[at:at+size];at+=size;request_fields(wire)
        rows.append(dict(tag=tag,input_hex=wire.hex()))
    exact([row['tag'] for row in rows],list(range(1,len(rows)+1)),'batch request IDs incomplete')
    return rows,cancellations


def responses(raw,count,ordered):
    rows=[];at=0;normalized=bytearray()
    while at<len(raw):
        require(len(raw)-at>=20,'batch response transport header truncated')
        tag,tid,code=struct.unpack_from('<QQI',raw,at);at+=20
        require(tid>0 and (32<=code<0xffff0000 or code==0xfffffff7),'batch response code differs')
        size=code if code<0xffff0000 else 0;require(size<=len(raw)-at,'batch response transport body truncated')
        output=raw[at:at+size];at+=size
        if size:
            require(output[:8]==b'HFBWR001','batch response magic differs')
            kind,length,zero=struct.unpack_from('<3Q',output,8)
            require(kind in(0,1) and length==len(output)-32 and zero==0,'batch response extent differs')
        rows.append(dict(tag=tag,tid=tid,code=code,output_hex=output.hex()))
        normalized.extend(struct.pack('<QI',tag,code)+output)
    tags=[row['tag'] for row in rows]
    exact(tags if ordered else sorted(tags),list(range(1,count+1)),'batch response IDs incomplete')
    return rows,bytes(normalized)


def file_process_evidence(folder,binary_sha,root=ROOT,original_side=False):
    folder,root=Path(folder),Path(root);report=obj(folder/'result.json')
    expected=dict(schema='hepta.runtime.batch-write-files.v1',status='PASS',binary_sha256=binary_sha,
        requests=926,domains=FILE_DOMAINS,outcomes=dict(success=461,original_error=465),
        observed_file_bytes=10528942,inherits_outer_process_group=True,outer_timeout_seconds=180,exit_code=0)
    for key,value in expected.items():exact(report.get(key),value,'batch complete file process differs: '+key)
    duration(report['elapsed_seconds'],'batch file process deadline exceeded')
    require(type(report['effective_uid'])is int and report['effective_uid']>0,'batch qualification permission domain requires an unprivileged execution account')
    require(type(report['process_id'])is int and report['process_id']>0 and type(report['process_group'])is int and report['process_group']>0,
            'batch file process identity missing')
    require(type(report['fixture'])is str and Path(report['fixture']).is_absolute(),'batch file fixture identity missing')
    base=os.fsencode(report['fixture'])
    names=('requests.bin.gz','stdout.bin.gz','normalized.bin.gz','filesystem.bin.gz','events.jsonl.gz','stderr.bin')
    for name in names:exact(report[name],file_record(folder/name),'batch complete file capture changed')
    plan=obj(root/'tests/hia_native/batch_write_file_plan.json')
    exact(plan['execution_evidence'],False,'batch static file plan cannot claim an execution')
    exact(plan['test_sha256'],sha(read(root/'tests/hia_native/test_batch_write_files.py')),'batch file plan source differs')
    exact(len(plan['rows']),926,'batch file semantic domain omitted')
    inventories=[];domains=collections.Counter();outcomes=collections.Counter()
    with gzip.open(folder/'requests.bin.gz','rb') as incoming,gzip.open(folder/'stdout.bin.gz','rb') as outgoing,\
         gzip.open(folder/'normalized.bin.gz','rb') as normalized,gzip.open(folder/'events.jsonl.gz','rb') as events:
        for ordinal,wanted in enumerate(plan['rows'],1):
            size,tag=struct.unpack('<QQ',take(incoming,16));require(64<=size<=32<<20,'batch file request exceeds fixed domain')
            exact(tag,ordinal,'batch file request order differs');wire=take(incoming,size)
            tag,tid,code=struct.unpack('<QQI',take(outgoing,20));require(32<=code<=32<<20 and tid>0,'batch file response extent differs')
            exact(tag,ordinal,'batch file response order differs');output=take(outgoing,code)
            exact(take(normalized,12+code),struct.pack('<QI',tag,code)+output,'batch normalization changed more than TID')
            raw=events.readline();require(raw.endswith(b'\n'),'batch file event truncated');event=json.loads(raw,object_pairs_hook=atomic_pairs)
            actual=canonical_case(wire,output,base)
            exact({key:wanted[key] for key in actual},actual,'batch complete file domain differs from fixed original cases')
            expected_event=dict(ordinal=ordinal,domain=wanted['domain'],request_sha256=sha(wire),request_bytes=len(wire),
                response_sha256=sha(output),response_bytes=len(output),outcome=actual['outcome'],filesystem=event['filesystem'])
            exact(event,expected_event,'batch file event detached from actual bytes')
            exact(body_projection(event['filesystem']),wanted['filesystem'],'batch full file content domain differs')
            if wanted['domain']=='existing_mode':
                target=next(row for row in event['filesystem'] if row['path_hex']==b'target'.hex())
                exact(target['mode'],wanted['mode'],'batch original permission bits were not preserved')
            inventories.append(event['filesystem']);domains[wanted['domain']]+=1;outcomes[actual['outcome']]+=1
        exact(incoming.read(1)+outgoing.read(1)+normalized.read(1)+events.read(1),b'','batch file capture contains an unexpected suffix')
    exact(dict(domains),FILE_DOMAINS,'batch file domain counts differ');exact(dict(outcomes),{0:461,1:465},'batch original file outcomes differ')
    filesystem=filesystem_evidence(folder/'filesystem.bin.gz',inventories)
    exact(filesystem['observed_file_bytes'],10528942,'batch large full file domain shortened')
    if original_side:exact(obj(folder/'stderr.bin'),dict(status='PASS',original_owner_calls=926,responses=926,canceled=0),'batch original file summary differs')
    else:exact(read(folder/'stderr.bin'),b'','batch native file process emitted diagnostics')
    return dict(result=file_record(folder/'result.json'),captures={name:file_record(folder/name) for name in names},
                filesystem=filesystem,actual_requests=926,actual_processes=1,domains=FILE_DOMAINS)


def files_evidence(folder,stdout,root=ROOT,original_sha=None):
    folder=Path(folder);native=file_process_evidence(folder/'native',build.ELF_SHA,root)
    if original_sha is None:
        return dict(stdout=process_stdout(stdout,obj(folder/'native/result.json')),native=native,original=None)
    reference=file_process_evidence(folder/'original',original_sha,root,True);report=obj(folder/'result.json')
    from batch_write_trace_common import equal_streams
    compared={name:equal_streams(folder/'native'/name,folder/'original'/name,True)
              for name in ('requests.bin.gz','normalized.bin.gz','filesystem.bin.gz','events.jsonl.gz')}
    for key,value in dict(schema='hepta.runtime.batch-write-files-comparison.v1',status='PASS',
        native_sha256=build.ELF_SHA,original_sha256=original_sha,required_outer_timeout_seconds=180,
        actual_original_calls=926,actual_native_calls=926,compared=compared,file_bytes_per_side=10528942,
        domains=FILE_DOMAINS,outcomes=dict(success=461,original_error=465),
        native_result_sha256=native['result']['sha256'],original_result_sha256=reference['result']['sha256'],
        original_summary=obj(folder/'original/stderr.bin')).items():exact(report[key],value,'batch actual original file comparison differs: '+key)
    exact(report['native_fixture_retirement'],dict(path=obj(folder/'native/result.json')['fixture'],
        complete_capture_verified_before_removal=True,verified_evidence_sha256=sha(canonical(native)+b'\n')),
        'batch file fixture retired before complete evidence validation')
    duration(report['elapsed_seconds'],'batch original file comparison deadline exceeded')
    return dict(result=file_record(folder/'result.json'),stdout=process_stdout(stdout,report),native=native,original=reference,compared=compared)


def filesystem_evidence(path, inventories, ordinals=None):
    """Read every retained content byte, then reconstruct every snapshot row."""
    digest = hashlib.sha256(); total = body_total = 0; completed = []; current = []
    ordinals = list(range(1, len(inventories) + 1)) if ordinals is None else ordinals
    exact(len(ordinals), len(inventories), 'batch-write snapshot ordinal domain differs')
    with gzip.open(path, 'rb') as incoming:
        def take(count):
            nonlocal total
            raw = incoming.read(count)
            require(len(raw) == count, 'batch-write full filesystem observation is truncated')
            digest.update(raw); total += len(raw); return raw
        while True:
            header = incoming.read(16)
            if not header: break
            require(len(header) == 16, 'batch-write snapshot header is truncated')
            digest.update(header); total += 16
            size, count = struct.unpack('<QQ', header)
            if size == 0:
                require(len(completed) < len(ordinals) and count == ordinals[len(completed)], 'batch-write snapshot ordinal differs')
                exact(current, inventories[len(completed)], 'batch-write complete filesystem state differs from captured inventory')
                completed.append(count); current = []; continue
            require(size <= 65536, 'batch-write retained filesystem header exceeds the fixture domain')
            row = json.loads(take(size), object_pairs_hook=atomic_pairs)
            require(len(completed) < len(ordinals), 'batch-write extra snapshot after completion')
            exact(row.pop('ordinal'), ordinals[len(completed)], 'batch-write snapshot row ordinal differs')
            body = hashlib.sha256(); left = count
            while left:
                raw = take(min(left, 1 << 20)); body.update(raw); left -= len(raw)
            if row.get('kind') == 0o100000 and 'read_errno' not in row:
                exact(row['bytes'], count, 'batch-write full file body size differs')
                row['sha256'] = body.hexdigest(); body_total += count
            else: exact(count, 0, 'batch-write non-file observation contains hidden data')
            current.append(row)
    exact(len(completed), len(inventories), 'batch-write complete snapshot domain omitted')
    exact(current, [], 'batch-write unterminated final snapshot')
    return dict(bytes=total, sha256=digest.hexdigest(), observed_file_bytes=body_total, snapshots=len(completed))


def atomic_pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, 'duplicate batch-write retained JSON field'); value[key] = item
    return value



def kernel_process_evidence(folder, config, binary_sha, *, original_side=False, concurrent=False):
    folder = Path(folder); report = obj(folder / 'result.json')
    for key, wanted in dict(schema='hepta.runtime.batch-write-kernel-process.v1', status='PASS', failure=None,
            binary_sha256=binary_sha, config=config, exit_code=0, actual_requests=len(config['steps'])).items():
        exact(report.get(key), wanted, 'batch-write actual kernel process differs: ' + key)
    duration(report['elapsed_seconds'], 'batch-write kernel process exceeded its deadline')
    names = ('requests.bin', 'stdout.bin', 'stderr.bin', 'normalized.bin')
    for name in names: exact(report[name], file_record(folder / name), 'batch-write complete kernel process bytes differ')
    incoming, cancels = requests(read(folder / 'requests.bin'))
    base = os.fsencode(report['fixture'])
    from batch_write_trace_common import packet
    expected = [dict(tag=i+1,input_hex=packet(step,base+b'/'+bytes.fromhex(step.get('path_hex',b'target'.hex()))).hex())
                for i,step in enumerate(config['steps'])]
    exact(incoming,expected,'batch complete kernel request domain differs')
    cancel_tag = config.get('cancel', {}).get('tag')
    if concurrent: cancel_tag = config['parallel'].get('cancel_tag')
    exact(cancels, [cancel_tag] if cancel_tag is not None else [], 'batch-write actual cancel input differs')
    outgoing, normalized = responses(read(folder / 'stdout.bin'), len(incoming), ordered=not concurrent)
    exact(outgoing, report['frames'], 'batch-write kernel report omitted actual returned bytes')
    exact(read(folder / 'normalized.bin'), normalized, 'batch-write kernel normalization changed more than TIDs')
    events, raw = report['events'], report['raw_events']; require(events and raw, 'batch-write kernel trace is empty')
    roots = {row['pid'] for row in raw}; require(len(roots) == 1 and all(type(x) is int and x > 0 for x in roots), 'batch-write raw process identity differs')
    root_pid = next(iter(roots)); tree = report['verified_process_tree']
    for tid, identity in tree.items():
        require(str(int(tid)) == tid and (identity['tgid'] == root_pid or identity['ppid'] == root_pid), 'batch-write kernel process escaped the owned tree')
    controlled = {}
    for event in events:
        require(type(event['raw_index']) is int and 0 <= event['raw_index'] < len(raw), 'batch-write owner trace lost its original syscall')
        syscall = raw[event['raw_index']]
        for key in ('pid', 'tid', 'ip', 'args'): exact(event[key], syscall[key], 'batch-write normalized event detached from its raw syscall')
        exact({key: event[key] for key in ('tgid', 'ppid')}, tree[str(event['tid'])], 'batch-write owner trace identity differs')
        if 'control_index' in event:
            index = event['control_index']; require(index not in controlled, 'batch-write completion control executed twice'); controlled[index] = event
            control = event['control']
            exact(event['kind'], control['kind'], 'batch-write actual effect control kind differs')
            if control['type'] == 'fault':
                exact(syscall['completion'], dict(value=0, error=-control.get('errno', 0), flags=0, held=False), 'batch-write actual injected completion differs')
            else: exact(syscall['completion']['held'], True, 'batch-write cancellation did not hold a real syscall')
    controls = [dict(type='fault', **row) for row in config.get('faults', [])]
    if config.get('cancel'): controls.append(dict(type='cancel', **config['cancel']))
    if concurrent: controls.append(dict(type='hold', **config['parallel']['hold']))
    exact(set(controlled), set(range(len(controls))), 'batch-write required real kernel controls omitted')
    for index, control in enumerate(controls): exact(controlled[index]['control'], control, 'batch-write kernel control domain differs')
    from batch_write_supervisor import normalized as normalized_events
    exact(report['normalized_events'], normalized_events(events), 'batch-write syscall normalization changed its declared domain')
    exact(report['injected_completions'], len(config.get('faults', [])), 'batch-write injected effects mislabeled')
    exact(report['actual_kernel_effects'], len(events) - len(config.get('faults', [])), 'batch-write kernel effect count differs')
    if config.get('cancel'):
        held = controlled[len(controls) - 1]; cancel = config['cancel']; ack = report['cancel_ack']
        exact(ack['effect_still_held'], True, 'batch-write cancel was not observed against a held syscall')
        if cancel.get('synchronous'):
            exact(ack['no_early_response'], True, 'batch-write synchronous section was interrupted')
            exact(held['release_reason'], 'synchronous-section-must-finish', 'batch-write synchronous cancellation order differs')
            require(held['held_seconds'] >= 0.05, 'batch-write synchronous hold was shortened')
        else:
            exact(ack['code'], 0xfffffff7, 'batch-write actual cancellation did not finish')
            exact(held['release_reason'], 'completed-response-' + str(cancel['release_after_tag']), 'batch-write guard/drop completion order differs')
            exact(held['cancellation_ack_before_effect_release'], True, 'batch-write cancellation waited for the blocked I/O')
    if concurrent:
        held = controlled[len(controls) - 1]; parallel = config['parallel']; mode = parallel['mode']
        if mode == 'serialized':
            exact(held['release_reason'], 'all-other-callers-reached-held-lock', 'batch-write shared lock was not exercised')
            require(held['queued_key_completions'] >= 3 and held['held_seconds'] >= 0.05, 'batch-write simultaneous caller domain shortened')
        elif mode == 'queued-cancel':
            exact(held['release_reason'], 'canceled-waiter-removed-before-guard-release', 'batch-write concurrent cancel ordering differs')
            exact(held['queued_cancel_sent'], parallel['cancel_tag'], 'batch-write canceled another request')
            exact(held['queued_cancel_ack'], parallel['cancel_tag'], 'batch-write concurrent cancellation did not finish')
            require(held['held_seconds'] >= 0.10 and report['cancel_ack']['effect_still_held'] is True,
                    'batch-write canceled caller did not finish before releasing the held guard')
        else:
            exact(mode,'independent','batch undefined concurrent domain')
            exact(held['release_reason'],'independent-file-complete','batch independent file did not progress')
            exact(held['other_request_completed_before_release'],2,'batch independent caller did not complete before guard release')
    filesystem = filesystem_evidence(folder / 'filesystem.bin.gz', [report['final_files']], [len(incoming)])
    # The supervisor's final snapshot uses the total request ordinal, unlike
    # the serial suite's one snapshot after each request.
    if original_side:
        summary = obj(folder / 'stderr.bin')
        expected_canceled = sum(row['code'] == 0xfffffff7 for row in outgoing)
        exact(summary, dict(status='PASS', original_owner_calls=len(incoming), responses=len(incoming), canceled=expected_canceled),
              'batch-write actual original kernel owner summary differs')
    else: exact(read(folder / 'stderr.bin'), b'', 'batch-write native kernel process emitted diagnostics')
    return dict(result=file_record(folder / 'result.json'), captures={name: file_record(folder / name) for name in names},
        filesystem=dict(gzip=file_record(folder / 'filesystem.bin.gz'), raw=filesystem),
        requests=len(incoming), kernel_effects=report['actual_kernel_effects'], injected_completions=report['injected_completions'])


def kernel_evidence(folder,stdout,root=ROOT,original_sha=None,concurrent=False):
    folder,root=Path(folder),Path(root)
    if concurrent:
        from test_batch_write_concurrency import cases,response_domain
        name,schema,count,request_count='test_batch_write_concurrency.py','hepta.runtime.batch-write-concurrency.v1',4,13
    else:
        from test_batch_write_kernel import cases
        name,schema,count,request_count='test_batch_write_kernel.py','hepta.runtime.batch-write-kernel-comparison.v1',77,231
    domain=cases();report=obj(folder/'result.json');exact(len(domain),count,'batch kernel declared domain differs')
    exact(sequence(folder/'cases.json'),domain,'batch kernel complete case definitions differ')
    expected=dict(schema=schema,status='PASS' if original_sha else 'NATIVE_PASS',original_status='PASS' if original_sha else 'PENDING',
        native_sha256=build.ELF_SHA,original_sha256=original_sha,cases=count,declared_cases=count,
        native_processes=count,original_processes=count if original_sha else 0,
        native_requests=request_count,original_requests=request_count if original_sha else 0)
    expected['source_inputs' if concurrent else 'sources']={name:sha(read(root/'tests/hia_native'/name)) for name in (name,'batch_write_supervisor.py','batch_write_trace_common.py')}
    for key,value in expected.items():exact(report.get(key),value,'batch complete kernel suite differs: '+key)
    duration(report['elapsed_seconds'],'batch kernel suite exceeded unchanged deadline')
    if concurrent:
        exact(report['concurrent_response_order_claimed'],False,'batch invented deterministic concurrent scheduling')
        exact(report['public_session_dispatch_qualified'],False,'batch internal caller overclaimed public dispatch')
    else:
        exact(report['exact_trace_comparisons'],58 if original_sha else 0,'batch original exact syscall domain omitted')
        exact(report['cancellation_partial_order_comparisons'],19 if original_sha else 0,'batch original cancellation domain omitted')
    exact(len(report['observations']),count,'batch kernel observations omitted')
    from batch_write_trace_common import equal_streams
    observations=[]
    for index,(config,captured) in enumerate(zip(domain,report['observations'],strict=True)):
        entry=folder/(('%02d-' if concurrent else '%03d-')%index+config['name'])
        native=kernel_process_evidence(entry/'native',config,build.ELF_SHA,concurrent=concurrent)
        exact(captured['name'],config['name'],'batch kernel observation case differs')
        exact(captured['native_result_sha256'],native['result']['sha256'],'batch native kernel report changed')
        n=obj(entry/'native/result.json');reference=None;compared={}
        if concurrent:
            response=response_domain(n,config['parallel']['mode'])
            exact(captured['comparison'],config['comparison'],'batch concurrent comparison domain differs')
            exact(captured['complete_response_bytes'],len(response),'batch complete concurrent response omitted')
            exact(captured['complete_response_sha256'],sha(response),'batch complete concurrent response changed')
            if config['parallel']['mode']=='serialized':
                exact(sorted(struct.unpack_from('<Q',bytes.fromhex(row['output_hex']),8)[0] for row in n['frames']),[0,0,1,1],
                      'batch original duplicate-line rejection under shared lock omitted')
        else:
            exact(captured['native_effects'],n['actual_kernel_effects'],'batch native effect count differs')
            exact(captured['injected_completions'],n['injected_completions'],'batch kernel injection accounting differs')
        if original_sha:
            reference=kernel_process_evidence(entry/'original',config,original_sha,original_side=True,concurrent=concurrent)
            exact(captured['original_result_sha256'],reference['result']['sha256'],'batch original kernel report changed')
            r=obj(entry/'original/result.json')
            exact(captured['original_summary'],obj(entry/'original/stderr.bin'),'batch actual original stderr differs')
            if concurrent:
                exact(response,response_domain(r,config['parallel']['mode']),'batch complete original concurrent outcome differs')
                compared['request']=equal_streams(entry/'native/requests.bin',entry/'original/requests.bin')
                compared['files']=equal_streams(entry/'native/filesystem.bin.gz',entry/'original/filesystem.bin.gz',True)
            else:
                for name in('requests.bin','normalized.bin','filesystem.bin.gz'):
                    compared[name]=equal_streams(entry/'native'/name,entry/'original'/name,name.endswith('.gz'))
                if 'cancel' not in config:exact(n['normalized_events'],r['normalized_events'],'batch complete original syscall trace differs')
                exact(captured['original_effects'],r['actual_kernel_effects'],'batch original effect count differs')
            exact(n['final_files'],r['final_files'],'batch complete original final filesystem differs')
        else:
            exact(captured['original_summary'],None,'batch native kernel report invented original execution')
            exact(captured['original_result_sha256'],None,'batch native kernel report invented original result')
            if not concurrent:exact(captured['original_effects'],0,'batch native kernel report invented original effects')
        exact(captured['compared'],compared,'batch complete original kernel byte comparison differs')
        observations.append(dict(name=config['name'],native=native,original=reference,compared=compared))
    return dict(result=file_record(folder/'result.json'),cases=file_record(folder/'cases.json'),
        stdout=process_stdout(stdout,{key:value for key,value in report.items() if key!='observations'}),
        observations=observations,actual_native_requests=request_count,actual_original_requests=request_count if original_sha else 0)


def wide_process_evidence(folder,binary_sha,root=ROOT,original_side=False):
    from test_batch_write_wide import headers,request_segments,Expected
    folder,root=Path(folder),Path(root);report=obj(folder/'result.json')
    expected=dict(schema='hepta.runtime.batch-write-wide.v1',status=('ORIGINAL' if original_side else 'NATIVE')+'_RESPONSE_AND_FULL_FILE_PASS',
        native_or_original_binary_sha256=binary_sha,requests=1,binary_role='original' if original_side else 'native',
        operations=50,content_bytes_per_operation=5242880,expected_output_bytes=1279265830,full_content_lines_in_diff=244,
        original_rust_comparison='PENDING',outer_timeout_seconds=180,inherits_outer_process_group=True,exit_code=0,
        test_sha256=sha(read(root/'tests/hia_native/test_batch_write_wide.py')))
    for key,value in expected.items():exact(report.get(key),value,'batch full wide process differs: '+key)
    duration(report['elapsed_seconds'],'batch full wide process exceeded unchanged deadline')
    require(type(report['process_id'])is int and report['process_id']>0 and type(report['process_group'])is int and report['process_group']>0,
            'batch wide process identity missing')
    target=Path(report['fixture_target']);require(target.is_absolute() and target.name=='target','batch wide target identity differs')
    exact(report['input_bytes'],headers(target)[2],'batch full wide request extent differs')
    exact(set(report['streams']),{'request','stdout','normalized','file'},'batch full wide stream set differs')
    captures={}
    for name,row in report['streams'].items():
        path=folder/(name+'.bin.gz');compressed=file_record(path);raw=stream_record(path,True)
        exact(row,dict(gzip_bytes=compressed['bytes'],gzip_sha256=compressed['sha256'],raw_bytes=raw['bytes'],raw_sha256=raw['sha256']),
              'batch full wide retained bytes differ: '+name)
        captures[name]=dict(gzip=compressed,raw=raw)
    exact(captures['normalized']['raw'],WIDE_OUTPUT,'batch complete 1.279 GB response domain changed')
    exact(captures['file']['raw'],WIDE_FILE,'batch complete 250 MiB final file domain changed')
    exact(captures['request']['raw']['bytes'],report['input_bytes']+16,'batch full wide input truncated')
    with gzip.open(folder/'request.bin.gz','rb') as incoming:
        exact(take(incoming,16),struct.pack('<QQ',report['input_bytes'],1),'batch wide transport input differs')
        checker=Expected(request_segments(target))
        while raw:=incoming.read(1<<20):checker.consume(raw)
        checker.finish()
    with gzip.open(folder/'stdout.bin.gz','rb') as raw,gzip.open(folder/'normalized.bin.gz','rb') as normalized:
        tag,tid,code=struct.unpack('<QQI',take(raw,20))
        require(tag==1 and tid>0 and code==1279265830,'batch wide real output header differs')
        exact(take(normalized,12),struct.pack('<QI',tag,code),'batch wide normalized header differs')
        left=code
        while left:
            count=min(1<<20,left);exact(take(raw,count),take(normalized,count),'batch wide normalization changed more than TID');left-=count
        exact(raw.read(1)+normalized.read(1),b'','batch wide output suffix')
    exact(report['stderr'],file_record(folder/'stderr.bin'),'batch wide stderr changed')
    if original_side:exact(obj(folder/'stderr.bin'),dict(status='PASS',original_owner_calls=1,responses=1,canceled=0),'batch actual wide original owner summary differs')
    else:exact(read(folder/'stderr.bin'),b'','batch native wide process emitted diagnostics')
    return dict(result=file_record(folder/'result.json'),captures=captures,stderr=file_record(folder/'stderr.bin'),
                actual_requests=1,complete_file_bytes=262144100,complete_response_bytes=1279265830)


def wide_evidence(folder,stdout,root=ROOT,original_sha=None):
    folder,root=Path(folder),Path(root)
    native=wide_process_evidence(folder/'native',build.ELF_SHA,root)
    controls=obj(folder/'algorithm-controls.json')
    exact(controls,dict(status='PASS',independent_uniform_hash_controls=2304,
        test_sha256=sha(read(root/'tests/hia_native/test_batch_write_wide.py'))),'batch wide independent hash controls omitted')
    if original_sha is None:
        return dict(native=native,original=None,stdout=process_stdout(stdout,obj(folder/'native/result.json')),
                    controls=file_record(folder/'algorithm-controls.json'))
    from test_batch_write_wide import compare_streams
    reference=wide_process_evidence(folder/'original',original_sha,root,True);report=obj(folder/'result.json')
    compared={name:compare_streams(folder/'native'/(name+'.bin.gz'),folder/'original'/(name+'.bin.gz')) for name in('request','normalized','file')}
    n,r=obj(folder/'native/result.json'),obj(folder/'original/result.json')
    exact(n['fixture_target'],r['fixture_target'],'batch wide original was not given the same actual path')
    for key,value in dict(schema='hepta.runtime.batch-write-wide-original.v1',status='PASS',actual_native_requests=1,actual_original_requests=1,
        outer_timeout_seconds=180,test_sha256=sha(read(root/'tests/hia_native/test_batch_write_wide.py')),
        native_binary_sha256=build.ELF_SHA,original_binary_sha256=original_sha,compared=compared,
        original_summary=obj(folder/'original/stderr.bin'),native_result_sha256=native['result']['sha256'],
        original_result_sha256=reference['result']['sha256'],native_elapsed_seconds=n['elapsed_seconds'],
        original_elapsed_seconds=r['elapsed_seconds'],exact_same_fixture_path=True,operations=50,content_bytes_per_operation=5242880).items():
        exact(report.get(key),value,'batch actual wide original comparison differs: '+key)
    duration(report['elapsed_seconds'],'batch full paired wide comparison deadline exceeded')
    retirement=obj(folder/'native-fixture-retirement.json')
    exact(retirement,dict(raw_path=n['fixture_target'],**n['streams']['file'],
        complete_bytes_verified_before_unlink=True,retained_gzip=str(Path(n['fixture_target']).parent.parent/'native/file.bin.gz')),
        'batch wide native fixture retirement is not bound to complete retained bytes')
    return dict(native=native,original=reference,compared=compared,result=file_record(folder/'result.json'),
        stdout=process_stdout(stdout,report),controls=file_record(folder/'algorithm-controls.json'),
        retirement=file_record(folder/'native-fixture-retirement.json'))


def native_evidence(manifest,corpus,stdout_dir,root=ROOT):
    manifest,corpus,stdout_dir,root=map(Path,(manifest,corpus,stdout_dir,root))
    before=pins(root);artifact=build.inspect_bundle(manifest,source_root=root)
    domains=dict(
      controller=controller_evidence(corpus/'controller',manifest,stdout_dir/'test_batch_write_controller.py.stdout',root),
      render=render_evidence(corpus/'render',manifest,stdout_dir/'test_batch_render.py.stdout',root),
      utf8=utf8_evidence(corpus/'utf8',manifest,stdout_dir/'test_utf8_probe.py.stdout',root),
      files=files_evidence(corpus/'files',stdout_dir/'test_batch_write_files.py.stdout',root),
      kernel=kernel_evidence(corpus/'kernel',stdout_dir/'test_batch_write_kernel.py.stdout',root),
      concurrency=kernel_evidence(corpus/'concurrency',stdout_dir/'test_batch_write_concurrency.py.stdout',root,concurrent=True),
      wide=wide_evidence(corpus/'wide',stdout_dir/'test_batch_write_wide.py.stdout',root))
    exact(pins(root),before,'batch source closure changed during complete evidence inspection')
    return dict(schema='hepta.runtime.batch-write-native-evidence.v1',status='PASS',source_files=before,artifact=artifact,domains=domains,
        actual_borrowed_calls=212196,actual_elf_processes=83,actual_elf_requests=1171,
        direct_synthetic_filesystem_completions=3188,direct_synthetic_canonical_completions=1819,
        actual_native_filesystem_domains=True,shared_cache_positive_branch_actual_elf=False,
        original_rust_execution='PENDING',production_activated=False,whole_runtime_replaced=False)



def controls_evidence(folder, native, stdout, *, root=ROOT):
    """Inspect the actual negative-control process; execute no semantic owner."""
    from test_batch_write_evidence import CONTROLS
    folder, root = Path(folder), Path(root)
    report = obj(folder / 'result.json')
    expected = dict(schema='hepta.runtime.batch-write-evidence-controls.v1', status='PASS',
        source_files=pins(root), native_evidence_sha256=sha(build.canonical(native)),
        accepted_controls=2, rejected_controls=len(CONTROLS), new_native_calls=0,
        new_original_calls=0, production_activated=False)
    exact(set(report), set(expected) | {'controls', 'elapsed_seconds'}, 'batch-write controls result shape differs')
    for key, value in expected.items(): exact(report.get(key), value, 'batch-write actual control evidence differs: ' + key)
    duration(report['elapsed_seconds'], 'batch-write evidence control process exceeded its deadline')
    exact(len(report['controls']), len(CONTROLS), 'batch-write control domain omitted')
    for row, (name, reason) in zip(report['controls'], CONTROLS):
        exact(set(row), {'name', 'status', 'error', 'changed_files'}, 'batch-write refusal result shape differs')
        exact(row['name'], name, 'batch-write control domain differs')
        exact(row['status'], 'REJECTED', 'batch-write required refusal was not observed')
        exact(row['error'], reason, 'batch-write control did not reach its declared guard')
        require(type(row['changed_files']) is dict and row['changed_files'], 'batch-write control did not alter actual retained files')
        for path, change in row['changed_files'].items():
            require(type(path) is str and not Path(path).is_absolute() and '..' not in Path(path).parts,
                    'batch-write control mutation escaped its private snapshot')
            exact(set(change), {'before', 'after'}, 'batch-write mutation identity is incomplete')
            require(change['before'] != change['after'], 'batch-write control mutation was empty')
            for record in change.values():
                require(set(record) == {'bytes', 'sha256'} and type(record['bytes']) is int and record['bytes'] >= 0
                        and type(record['sha256']) is str and len(bytes.fromhex(record['sha256'])) == 32,
                        'batch-write mutation file identity differs')
    summary = {key: value for key, value in report.items() if key not in ('source_files', 'controls')}
    summary['result'] = file_record(folder / 'result.json')
    return dict(schema='hepta.runtime.batch-write-controls-evidence.v1', status='PASS',
        result=file_record(folder / 'result.json'), stdout=process_stdout(stdout, summary),
        accepted_controls=2, rejected_controls=len(CONTROLS), new_native_calls=0, new_original_calls=0,
        retained_inspection_only=True)


def original_evidence(folder,manifest,native_corpus,native_stdout_dir,stdout,*,root=ROOT):
    """Recheck a completed original recipe without executing any owner."""
    from compare_batch_write_original import CLEARED,cleared,SUMMARY
    folder,manifest,native_corpus,root=map(Path,(folder,manifest,native_corpus,root))
    report=obj(folder/'result.json')
    expected=dict(schema='hepta.runtime.batch-write-original-comparison.v1',status='PASS',
        source_files=pins(root),artifacts=build.inspect_bundle(manifest,source_root=root),
        native=native_evidence(manifest,native_corpus,native_stdout_dir,root=root),
        original_build_is_fresh=True,original_replay_is_fresh=True,outer_timeout_seconds=180,
        native_wide_mode='completed-current-qualification',native_wide_processes_added=0,retained_native_wide_requests=1,
        inherits_outer_process_group=True,original_processes=84,original_requests=7909,
        body_processes=83,body_requests=1171,renderer_processes=1,renderer_requests=6738,
        exact_trace_comparisons=58,cancellation_partial_order_comparisons=19,concurrent_cases=4,
        full_file_observation_bytes_per_side=272673042,wide_response_bytes=1279265830,
        production_activated=False,whole_runtime_replaced=False,remote_sftp_closed=False)
    for key,value in expected.items():exact(report.get(key),value,'batch retained original recipe differs: '+key)
    duration(report['elapsed_seconds'],'batch actual original recipe exceeded unchanged deadline')
    for key in ('source_root','directory','manifest','native_corpus','native_stdout_dir'):
        require(type(report[key])is str and Path(report[key]).is_absolute(),'batch original path identity missing')
    actual_root,actual_output=Path(report['source_root']),Path(report['directory'])
    projects={name:original_project_evidence(folder/(name+'-project'),root,render=name=='render') for name in ('body','render')}
    exact(report['projects'],projects,'batch actual compiled original projects differ')
    tools=report['tools'];exact(set(tools),{'rustc','cargo','rustfmt'},'batch selected compiler tool set differs')
    for entry in [*tools.values(),report['python']]:
        require(set(entry)=={'path','resolved_path','bytes','sha256'}
            and all(type(entry[key])is str and Path(entry[key]).is_absolute() for key in ('path','resolved_path'))
            and type(entry['bytes'])is int and entry['bytes']>0
            and type(entry['sha256'])is str and len(bytes.fromhex(entry['sha256']))==32,
            'batch retained compiler/interpreter identity is incomplete')
    policy=report['environment_policy']
    exact(set(policy),{'cleared_names','clear_hia_prefix','clear_target_rustflags','selected','removed_names'},'batch build environment envelope differs')
    exact(policy['cleared_names'],list(CLEARED),'batch original compiler environment policy differs')
    exact(policy['clear_hia_prefix'],True,'batch original inherited a development override')
    exact(policy['clear_target_rustflags'],True,'batch original inherited target flag overrides')
    require(type(policy['removed_names'])is list and policy['removed_names']==sorted(set(policy['removed_names']))
        and all(type(name)is str and cleared(name) for name in policy['removed_names']),'batch environment clearing record differs')
    exact(policy['selected'],dict(RUSTC=tools['rustc']['path'],CARGO_TARGET_DIR=str(actual_output/'target'),
        TMPDIR=str(actual_output/'tmp')),'batch selected original build environment differs')
    binaries=report['original_binaries'];exact(set(binaries),{'body','render'},'batch original binary owner set differs')
    relative_binaries=dict(body='target/release/hia-batch-write-body-original',render='original-renderer')
    for name,relative in relative_binaries.items():
        exact(set(binaries[name]),{'path','bytes','sha256'},'batch original binary identity incomplete')
        exact(binaries[name]['path'],str(actual_output/relative),'batch executed original binary path differs')
        exact({key:binaries[name][key] for key in ('bytes','sha256')},file_record(folder/relative),'batch complete executed original binary changed')
    commands={
        'rustc-version':[tools['rustc']['path'],'-Vv'],
        'cargo-build':[tools['cargo']['path'],'build','--release','--locked','--manifest-path',str(actual_output/'body-project/Cargo.toml')],
        'render-build':[tools['rustc']['path'],'-O','--edition=2024','-C','overflow-checks=off',
            str(actual_output/'render-project/oracle_batch_render.rs'),'-o',binaries['render']['path']],
        'render-replay':[binaries['render']['path']],
    }
    for name,oracle in [('body','oracle_batch_write.rs'),('render','oracle_batch_render.rs')]:
        commands[name+'-format']=[tools['rustfmt']['path'],'--check','--edition=2024','--config','hard_tabs=true,max_width=100',str(actual_root/'tests/hia_native'/oracle)]
    for name in ('files','kernel','concurrency','wide'):
        if name=='wide':
            commands[name]=[report['python']['path'],'-I','-B',str(actual_root/'tests/hia_native/compare_batch_write_wide_retained.py'),
                '--root',str(actual_root),'--bundle',report['manifest'],'--native-corpus',report['native_corpus'],
                '--native-stdout-dir',report['native_stdout_dir'],'--admission',report['wide_admission_path'],
                '--admission-sha256',report['wide_admission_sha256'],'--invocation',report['wide_invocation'],
                '--original',binaries['body']['path'],'--output',str(actual_output/name)]
        else:
            script='compare_batch_write_files.py' if name=='files' else 'test_batch_write_'+name+'.py'
            commands[name]=[report['python']['path'],'-I','-B',str(actual_root/'tests/hia_native'/script),
                '--native',str(Path(report['manifest']).parent/'batch-write.elf'),'--original',binaries['body']['path'],
                '--output',str(actual_output/name)]+(['--reference',str(actual_root)] if name=='files' else [])
    commands['wide-admission-controls']=[report['python']['path'],'-I','-B',str(actual_root/'tests/hia_native/test_batch_write_retained_wide.py'),
        '--root',str(actual_root),'--bundle',report['manifest'],'--native-corpus',report['native_corpus'],
        '--native-stdout-dir',report['native_stdout_dir'],'--admission',report['wide_admission_path'],
        '--invocation',report['wide_invocation'],'--output',str(actual_output/'wide-admission-controls')]
    names=['rustc-version','body-format','render-format','cargo-build','render-build','render-replay','files','kernel','concurrency','wide','wide-admission-controls']
    exact([row['name'] for row in report['records']],names,'batch actual fresh compile/replay stages omitted')
    require(type(report['outer_process_group'])is int and report['outer_process_group']>0,'batch original outer process group missing')
    for row in report['records']:
        name=row['name'];command=commands[name]
        if name=='cargo-build' and row['command'][-1:]==['--offline']:command=command+['--offline']
        exact(row['command'],command,'batch actual original command differs')
        exact(row['cwd'],str(actual_output/('body-project' if name=='cargo-build' else 'empty-cwd')),'batch actual original cwd differs')
        stdin=RENDER_STREAMS['requests.gz'] if name=='render-replay' else dict(bytes=0,sha256=sha(b''))
        for key,value in dict(exit_code=0,reaped=True,inherits_outer_process_group=True,outer_timeout_seconds=180,
            process_group=report['outer_process_group'],stdin=stdin).items():
            exact(row.get(key),value,'batch original subprocess did not complete in owned group')
        require(type(row['pid'])is int and row['pid']>0,'batch actual original process identity missing')
        duration(row['elapsed_seconds'],'batch actual original child exceeded unchanged deadline')
        for channel in ('stdout','stderr'):
            path=folder/(name+'.'+channel+('.gz' if name=='render-replay' and channel=='stdout' else ''))
            exact(row[channel],file_record(path),'batch actual original subprocess stream changed')
        if name=='render-replay':
            exact(row['input_capture'],file_record(native_corpus/'render/requests.gz'),'batch renderer input capture changed')
            exact(row['stdout_raw'],RENDER_STREAMS['native-output.gz'],'batch actual renderer raw output changed')
    version=read(folder/'rustc-version.stdout')
    require(version.startswith(b'rustc 1.95.0 ') and b'release: 1.95.0\n' in version
        and b'commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n' in version,'batch actual original compiler version differs')
    for name in ('rustc-version.stderr','body-format.stdout','body-format.stderr','render-format.stdout','render-format.stderr',
                 'files.stderr','kernel.stderr','concurrency.stderr','wide.stderr','wide-admission-controls.stderr'):
        exact(read(folder/name),b'','batch original qualification emitted unexpected diagnostics')
    renderer_summary=dict(status='PASS',cases=6738,input_bytes=50024901,output_bytes=12229698)
    exact(obj(folder/'render-replay.stderr'),renderer_summary,'batch actual original renderer summary changed')
    from batch_write_trace_common import equal_streams
    renderer_stream=equal_streams(native_corpus/'render/native-output.gz',folder/'render-replay.stdout.gz',True)
    exact(stream_record(folder/'render-replay.stdout.gz',True),RENDER_STREAMS['native-output.gz'],'batch complete original renderer output domain omitted')
    from compare_batch_write_wide_retained import evidence as retained_wide_evidence, admit_native, ADMISSION
    admitted=admit_native(Path(native_stdout_dir)/ADMISSION,report['wide_admission_sha256'],report['wide_invocation'],
        root,manifest,native_corpus,native_stdout_dir)
    exact(report['wide_admission_before'],admitted,'batch native wide pre-recipe admission changed')
    exact(report['wide_admission_after'],admitted,'batch native wide post-recipe admission changed')
    comparisons=dict(
        files=files_evidence(folder/'files',folder/'files.stdout',root=root,original_sha=binaries['body']['sha256']),
        kernel=kernel_evidence(folder/'kernel',folder/'kernel.stdout',root=root,original_sha=binaries['body']['sha256']),
        concurrency=kernel_evidence(folder/'concurrency',folder/'concurrency.stdout',root=root,original_sha=binaries['body']['sha256'],concurrent=True),
        wide=retained_wide_evidence(folder/'wide',manifest,native_corpus,native_stdout_dir,folder/'wide.stdout',
            root=root,original_sha=binaries['body']['sha256']))
    exact(report['comparisons'],comparisons,'batch complete original comparisons changed')
    import test_batch_write_retained_wide as retained_controls
    controls=retained_controls.evidence(folder/'wide-admission-controls',folder/'wide-admission-controls.stdout',
        Path(native_stdout_dir)/ADMISSION,report['wide_invocation'],root=root)
    exact(report['wide_admission_controls'],controls,'batch current-native wide refusal controls changed')
    summary={key:report[key] for key in SUMMARY};summary['result']=file_record(folder/'result.json')
    return dict(schema='hepta.runtime.batch-write-original-evidence.v1',status='PASS',result=file_record(folder/'result.json'),
        stdout=process_stdout(stdout,summary),tools=tools,original_binaries={name:{key:value[key] for key in ('bytes','sha256')} for name,value in binaries.items()},
        actual_projects=projects,records=report['records'],comparisons=comparisons,retained_wide_controls=controls,
        renderer=dict(summary=renderer_summary,complete_output=renderer_stream,stderr=file_record(folder/'render-replay.stderr')),
        original_processes=84,original_requests=7909,body_processes=83,body_requests=1171,renderer_processes=1,renderer_requests=6738,
        retained_inspection_only=True,new_native_calls=0,new_original_calls=0,production_activated=False,whole_runtime_replaced=False)

