"""Full original, source, compilation, native-buffer and process custody.

Every function in this file only reads. No summaries substitute retained
native buffers or the actual current-target and locked-SDK output streams.
"""
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import static_common as c
import read_static
import reference_projection
from run_recipe import PROCESSES
ORIGINAL_READER=c.BASE.reference_module(ROOT/'pipeline/policy_base')

def process(reader,name,limit,command,cwd,*,parent=None,stdin=None):
    row=reader.document('processes/'+name+'.process.json')
    assert row['name']==name and row['command']==command and row['cwd']==str(cwd)
    assert row['timeout_seconds']==limit and row['exit_code']==0
    assert row['timed_out'] is False and row['start_error'] is None
    assert type(row['pid'])is int and row['pid']==row['pgid'] and row['pid']>0
    assert type(row['parent_pid'])is int and row['parent_pid']>0
    if parent is not None:assert row['parent_pid']==parent
    assert type(row['started_ns'])is int and type(row['finished_ns'])is int
    assert 0<=row['finished_ns']-row['started_ns']<=(limit+1)*1_000_000_000
    assert row['stdin']==stdin
    for stream in ('stdout','stderr'):reader.raw('processes/'+name+'.'+stream,row[stream])
    return row

def verify_sdk(output,source,original,projection_native,*,producer,parent):
    r=c.BASE.Reader(output);report=r.document('result.json')
    assert report['schema']=='hepta.runtime.catalog-eleven-sdk-original.v1' and report['status']=='PASS'
    assert report['rows']==432 and report['actual_original_contexts']==216
    assert report['original_manifest']==c.pin((original/'source.json').read_bytes())
    assert r.raw('projection_oracle.rs')==(source/'projection_oracle.rs').read_bytes()
    assert report['source']==c.pin(r.raw('projection_oracle.rs'))
    r.raw('projection.elf',report['binary'])
    p=Path(producer);target=Path(report['target_root'])
    assert report['original_root']==str(p/'original') and report['projection_root']==str(p/'sdk-original')
    assert report['environment']=={'RUSTUP_TOOLCHAIN':'1.95.0','CARGO_TARGET_DIR':str(p/'original/cargo-target'),
        'CARGO_BUILD_JOBS':'2','CARGO_INCREMENTAL':'0','CARGO_PROFILE_DEV_DEBUG':'0',
        'CARGO_ENCODED_RUSTFLAGS':'','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'}
    build=process(r,'sdk-build',180,['cargo','build','--locked','--example','hia_eleven_sdk_projection'],target,parent=parent)
    replay=process(r,'sdk-replay',60,[str(p/'original/cargo-target/debug/examples/hia_eleven_sdk_projection')],
        target,parent=parent,stdin=report['input'])
    assert build['finished_ns']<=replay['started_ns']
    assert replay['stderr']==c.pin(b'')
    wire=r.raw('input.bin',report['input']);index=r.document('input-index.json')
    observed=r.raw('processes/sdk-replay.stdout');at=0;offset=0;rows=[]
    for number,((case,request),entry)in enumerate(zip(reference_projection.inputs(original),index,strict=True)):
        assert case['sequence']==number and entry=={**case,'offset':offset,**c.pin(request)}
        assert wire[offset:offset+len(request)]==request;offset+=len(request)
        assert len(observed)-at>=64 and observed[at:at+8]==b'HCATSD01'
        seq,flags,modern,policy,count,size,zero=struct.unpack_from('<7Q',observed,at+8)
        assert (seq,flags,modern,policy,zero)==(number,case['flags'],case['modern'],case['policy'],0)
        assert count==(11 if flags else 7) and size<=len(observed)-at-64
        body=observed[at+64:at+64+size];at+=64+size
        shape=(0 if flags==0 else ((flags>>1)+1))*2+modern
        native=(projection_native/f'shape-{shape:02d}-sdk-{policy}.json').read_bytes()
        assert body==native,('complete actual SDK wire differs',case)
        rows.append({**case,'tool_count':count,'output':c.pin(body)})
    assert len(rows)==432 and at==len(observed) and offset==len(wire)
    return {'status':'ACTUAL_CURRENT_SDK_COMPLETE_WIRE_PARITY_PASS','rows':rows,'processes':[build,replay],
        'files':r.files,'tool_body_calls':0,'protocol_contexts':216,'native_and_original_wire_bytes_equal':True}

def verify(output,*,controls=True):
    output=Path(output).resolve(strict=True);r=c.BASE.Reader(output)
    report=r.document('result.json')
    assert report['schema']=='hepta.runtime.catalog-eleven-recipe.v1' and report['status']=='PASS'
    assert report['processes']==[list(x)for x in PROCESSES]
    for flag in ('public_all_configuration_qualified','whole_runtime_replaced','production_activated'):assert report[flag]is False
    source=output/'source';sources,proof=c.source_check(source)
    assert report['source_profile']==c.pin((source/'source-profile.json').read_bytes())
    start=r.document('recipe-start.json');assert {**start,'status':'PASS'}==report
    p=Path(report['producer_root']);target=Path(report['target_root']);hepta=Path(report['hepta_root'])
    assert p.is_absolute()and target.is_absolute()and hepta.is_absolute()
    commands={
        'original-capture':['pipeline/policy_base/reference/capture.py','--target',str(target),'--output',str(p/'original')],
        'projection-build':['pipeline/build_projection.py','--hepta',str(hepta),'--output',str(p/'projection-build')],
        'projection-native':['pipeline/capture_projection.py','--build',str(p/'projection-build'),'--output',str(p/'projection-native')],
        'static-build':['build_static.py','--hepta',str(hepta),'--projection-build',str(p/'projection-build'),
            '--projection-capture',str(p/'projection-native'),'--bootstrap',str(p/'projection-build/bootstrap'),'--output',str(p/'static-build')],
        'static-native':['capture_static.py','--build',str(p/'static-build'),'--output',str(p/'static-native')],
        'sdk-projection':['reference_projection.py','--target',str(target),'--original',str(p/'original'),'--output',str(p/'sdk-original')],
        'evidence-controls':['evidence_controls.py','--output',str(p),'--controls',str(p/'evidence-controls')],
    }
    processes=[];last=0
    for name,limit in PROCESSES:
        args=commands[name]
        row=process(r,name,limit,[report['python'],'-I','-B',str(p/'source'/args[0]),*args[1:]],p,parent=report['producer_pid'])
        assert row['started_ns']>=last;last=row['finished_ns'];assert row['stderr']==c.pin(b'')
        processes.append(row)
    original=ORIGINAL_READER.verify(output/'original')
    sys.path.insert(0,str(source/'pipeline'))
    import read_projection
    projection=read_projection.verify(source/'pipeline',output/'projection-build',output/'projection-native')
    native=read_static.verify(source,output/'static-build',output/'static-native')
    sdk=verify_sdk(output/'sdk-original',source,output/'original',output/'projection-native',
        producer=p,parent=next(x['pid']for x in processes if x['name']=='sdk-projection'))
    reproduced=c.BASE.Reader(output/'static-build/reproduced')
    for name in ('runtime_mcp_catalog_eleven.hepta','catalog_eleven.pseudo','catalog-mode-0.bin','catalog-mode-1.bin','catalog-common.lzss'):
        assert reproduced.raw(name)==(source/'native'/name).read_bytes()
    author=reproduced.document('catalog-eleven-composition.json')
    assert {k:v for k,v in author.items()if k!='pipeline_result_sha256'}=={k:v for k,v in proof.items()if k!='pipeline_result_sha256'}
    assert author['pipeline_result_sha256']==c.sha((output/'projection-native/result.json').read_bytes())
    for index,mode,policy in ((2,0,1),(3,1,2)):
        body=(output/'projection-native'/f'shape-{index:02d}-sdk-{policy}.json').read_bytes()
        assert (source/f'native/catalog-mode-{mode}.bin').read_bytes()==b',"result":'+body+b'}'
    control_result=None
    if controls:
        from evidence_controls import verify as verify_controls
        control_result=verify_controls(output,output/'evidence-controls')
    return {'status':'COMPLETE_ELEVEN_CATALOG_QUALIFICATION_PASS','native_pipeline_calls':108,
        'static_native_cases':87,'static_native_calls':144,'current_original_contexts':216,'current_sdk_wires':432,
        'fixed_runtime_enabled_tools':11,'disabled_policy_projection_tools':7,'retained_non_list_operations':18,
        'source_files':sources.files,'processes':processes,'original':original,'projection':projection,
        'static':native,'sdk':sdk,'controls':control_result,'readonly_semantic_processes':0,
        'public_all_configuration_qualified':False,'public_async_qualified':False,'whole_runtime_replaced':False}
