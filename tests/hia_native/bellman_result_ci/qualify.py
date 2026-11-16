"""Build, observe and independently read complete private Bellman result evidence."""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode=True
PACKAGE=Path(__file__).resolve().parent
sys.path.insert(0,str(PACKAGE))
from cases import corpus, malformed

B3_SHA='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
TARGET_SHA='254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7'
LIMIT=8<<20
SCOPE='complete private result JSON serialization; public parsing, clock/deadline, permit lifetime and routing excluded'
REQUIRED_KEYS=('action_names','branch_count','canonical_request_byte_budget','checkpoint_verified',
 'continuing_action_count','environment_law_verified','exact_tie_state_count','gradient_steps',
 'implementation_source_sha256','independent_holdout_verified','legal_action_count',
 'maximum_probability_sum_error_f64','maximum_self_consistency_residual_f64','method',
 'minimum_relative_action_gap_f64','native_operation_wall_seconds','near_tie_relative_threshold',
 'near_tie_state_count','operation_budget_units','operation_charged_units','plan_id',
 'probability_sum_tolerance','production_eligible','real_arithmetic_optimality_certified',
 'recurrence','request_bytes','request_commitment_encoding','request_sha256','schema','scope',
 'self_consistency_is_numerical_error_bound','semantics_version','state_count','states',
 'training_targets_used','zero_probability_branch_count')

def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def read_pin(path):
    return pin(path.read_bytes())

def write_json(path,value):
    with path.open('x') as stream:json.dump(value,stream,indent=2,sort_keys=True);stream.write('\n')

def source_check(package=PACKAGE):
    manifest=json.loads((package/'package-manifest.json').read_bytes())
    for name,expected in manifest['files'].items():
        path=package/name
        assert path.is_file() and not path.is_symlink() and path.resolve()==path
        assert read_pin(path)==expected,('source changed',name)
    return read_pin(package/'package-manifest.json')

def record(stream,raw):
    stream.write(struct.pack('<Q',len(raw)));stream.write(raw)

def records(path):
    with path.open('rb') as stream:
        while True:
            header=stream.read(8)
            if not header:return
            assert len(header)==8,('record header truncated',path)
            length=struct.unpack('<Q',header)[0]
            assert length<=64<<20,('record unbounded',path,length)
            raw=stream.read(length)
            assert len(raw)==length,('record body truncated',path)
            yield raw

def u64(raw,at):
    return struct.unpack_from('<Q',raw,at)[0]

def make_wire(core,commitment,elapsed):
    return b'HBLMRQ01'+struct.pack('<7Q',1,len(core),len(commitment),elapsed,0,0,0)+core+commitment

def response_header(status,size=0,required=0):
    return b'HBLMRS01'+struct.pack('<7Q',status,size,required,0,0,0,0)

def control_cases(base,base_output):
    required=20480+u64(base,72)*256
    for name,wire in malformed(base):yield name,wire,8192,required,'refuse'
    for size in (0,1,63):yield 'short-output-'+str(size),base,size,required,'short-output'
    for size in (0,1,required-1):yield 'short-workspace-'+str(size),base,8192,size,'grow-workspace'
    for size in (64,len(base_output)-1):yield 'short-result-'+str(size),base,size,required,'grow-output'
    yield 'exact-capacities',base,len(base_output),required,'success'
    yield 'invalid-before-capacity',b'',0,0,'refuse'

def build(args):
    source_check()
    sys.path.insert(0,str(PACKAGE/'source/scripts'))
    from hia_native_build import NativeBuild
    root=args.output/'build'
    if args.bootstrap_cache is not None:
        cache=args.bootstrap_cache.resolve(strict=True)
        for name in ('B1.image.bin','B2.image.bin','B3.image.bin'):
            assert read_pin(cache/name)=={'bytes':673413,'sha256':B3_SHA}
        shutil.copytree(cache,root/'bootstrap')
    else:
        assert os.environ.get('GITHUB_ACTIONS')=='true', 'local bootstrap is forbidden; provide the verified cache'
    builder=NativeBuild(args.hepta,root)
    manifests={}
    for name in ('bellman_core','bellman_commitment','bellman_result'):
        manifest=builder.compile(name,PACKAGE/'source/native'/f'{name}.hepta',
                                 standalone=None,buffer_profile='serde-json.v1')
        metadata=json.loads(manifest.read_bytes())
        assert metadata['compiler_sha256']==B3_SHA
        manifests[name]={'manifest':str(manifest.relative_to(args.output)),
                         'manifest_pin':read_pin(manifest),
                         'source_sha256':metadata['source_sha256'],
                         'image_sha256':metadata['image_sha256']}
    result={'status':'PASS','source_manifest':source_check(),'compiler_sha256':B3_SHA,
            'fresh_native_components':3,'reused_native_components':0,'manifests':manifests}
    write_json(args.output/'build.json',result)
    print(json.dumps(result),flush=True)

def read_build(output):
    data=json.loads((output/'build.json').read_bytes())
    assert data['status']=='PASS' and data['source_manifest']==source_check()
    assert data['fresh_native_components']==3 and data['reused_native_components']==0
    assert data['compiler_sha256']==B3_SHA
    assert set(data['manifests'])=={'bellman_core','bellman_commitment','bellman_result'}
    for name,row in data['manifests'].items():
        path=output/row['manifest']
        assert read_pin(path)==row['manifest_pin']
        meta=json.loads(path.read_bytes())
        for field in ('source','image'):
            raw=(path.parent/meta[field]).read_bytes()
            assert hashlib.sha256(raw).hexdigest()==meta[field+'_sha256']==row[field+'_sha256']
        assert (path.parent/meta['source']).read_bytes()==(PACKAGE/'source/native'/f'{name}.hepta').read_bytes()
        assert meta['compiler_sha256']==B3_SHA and meta['standalone'] is None
    return data

def native(args):
    data=read_build(args.output)
    sys.path.insert(0,str(PACKAGE/'source/scripts'))
    from hia_native_loader import NativeModule
    folder=args.output/'native';folder.mkdir()
    names=('graphs.bin','core.bin','commitment.bin','inputs.bin','outputs.bin')
    rows=[];started=time.monotonic()
    with contextlib.ExitStack() as stack:
        modules={name:stack.enter_context(NativeModule(args.output/row['manifest'],
                     manifest_sha256=row['manifest_pin']['sha256'])) for name,row in data['manifests'].items()}
        core_session=stack.enter_context(modules['bellman_core'].session(output_capacity=295040,workspace_capacity=295040))
        commit_session=stack.enter_context(modules['bellman_commitment'].session(output_capacity=LIMIT+128,workspace_capacity=LIMIT+16384))
        streams={name:stack.enter_context((folder/name).open('xb')) for name in names}
        base=base_output=None
        for name,graph,elapsed in corpus(PACKAGE/'source'):
            count=u64(graph,8)
            core=core_session.invoke(graph)
            assert len(core)==128+count*72 and core[:8]==b'HIABPLN1'
            commitment=commit_session.invoke(b'HBCMT001'+bytes.fromhex(TARGET_SHA)+graph)
            assert commitment[:8]==b'HBCMTRES' and len(commitment)==128+u64(commitment,8)
            assert commitment[16:48]==hashlib.sha256(commitment[128:]).digest()
            assert commitment[48:80]==bytes.fromhex(TARGET_SHA)
            wire=make_wire(core,commitment,elapsed)
            capacity=20480+count*256
            result=modules['bellman_result'].invoke(wire,output_capacity=capacity,workspace_capacity=capacity)
            assert result[:64]==response_header(0,len(result)-64)
            value=json.loads(result[64:])
            assert tuple(value)==REQUIRED_KEYS and len(value['states'])==count
            assert value['implementation_source_sha256']==TARGET_SHA
            assert value['request_sha256']==commitment[16:48].hex()
            assert value['plan_id']=='wb1_'+commitment[80:112].hex()
            assert value['request_bytes']==u64(commitment,8)
            assert all(value[key] is False for key in ('production_eligible','checkpoint_verified','environment_law_verified',
                       'independent_holdout_verified','training_targets_used','real_arithmetic_optimality_certified'))
            for key,raw in zip(names,(graph,core,commitment,wire,result)):record(streams[key],raw)
            rows.append({'name':name,'states':count,'elapsed_bits':elapsed,'input':pin(wire),'output':pin(result)})
            if base is None:base,base_output=wire,result
        controls=[]
        with (folder/'controls.inputs.bin').open('xb') as input_stream,\
             (folder/'controls.outputs.bin').open('xb') as output_stream,\
             (folder/'controls.workspace.bin').open('xb') as work_stream:
            def observe(name,wire,outcap,workcap,expectation):
                code,out,work=modules['bellman_result'].invoke_raw(wire,output_capacity=outcap,
                     workspace_capacity=workcap,output_fill=0xcc,workspace_fill=0xa7)
                row={'name':name,'output_capacity':outcap,'workspace_capacity':workcap,'code':code,
                     'expectation':expectation,'input':pin(wire),'output':pin(out),'workspace':pin(work)}
                verify_control(row,wire,out,work,base_output)
                controls.append(row)
                record(input_stream,wire);record(output_stream,out);record(work_stream,work)
            required=20480+u64(base,72)*256
            for case in control_cases(base,base_output):observe(*case)
        # A real reused session must recover after a refused request.
        with modules['bellman_result'].session(output_capacity=8192,workspace_capacity=required) as session:
            code1,out1,work1=session.invoke_raw(base)
            code2,out2,work2=session.invoke_raw(b'')
            code3,out3,work3=session.invoke_raw(base)
            assert code1==code3==len(base_output) and code2==0xffffffff
            assert out1==out2==out3 and work1==work2==work3
            with (folder/'session.outputs.bin').open('xb') as outputs,(folder/'session.workspace.bin').open('xb') as works:
                for raw in (out1,out2,out3):record(outputs,raw)
                for raw in (work1,work2,work3):record(works,raw)
        recovery={'codes':[code1,code2,code3],'output_capacity':8192,'workspace_capacity':required}
    report={'status':'NATIVE_PASS_REFERENCE_REQUIRED','source_manifest':source_check(),
            'cases':rows,'case_count':len(rows),'controls':controls,'control_count':len(controls),
            'same_session_refusal_recovery':recovery,'wall_seconds':time.monotonic()-started,
            'scope':SCOPE,'public_handler_qualified':False,'whole_runtime_replaced':False,
            'files':{path.name:read_pin(path) for path in sorted(folder.iterdir())}}
    write_json(folder/'report.json',report)
    print(json.dumps({key:report[key] for key in ('status','case_count','control_count','wall_seconds')}),flush=True)

def verify_control(row,wire,out,work,valid):
    for key,raw in (('input',wire),('output',out),('workspace',work)):assert pin(raw)==row[key]
    outcap=row['output_capacity'];workcap=row['workspace_capacity'];kind=row['expectation']
    assert len(out)==outcap and len(work)==workcap
    if kind in ('refuse','short-output'):
        assert row['code']==(0xffffffff if kind=='refuse' else 0xfffffffe)
        assert out==b'\xcc'*outcap and work==b'\xa7'*workcap
    elif kind=='grow-workspace':
        assert row['code']==64 and out[:64]==response_header(2,required=20480+u64(wire,72)*256)
        assert out[64:]==b'\xcc'*(outcap-64) and work==b'\xa7'*workcap
    elif kind=='grow-output':
        assert row['code']==64 and out[:64]==response_header(3,required=len(valid))
        assert out[64:]==b'\xcc'*(outcap-64)
    else:
        assert kind=='success' and row['code']==len(valid) and out==valid

def capture(command,cwd,folder,stem,timeout,stdin=b''):
    folder.mkdir(parents=True,exist_ok=True)
    before=time.monotonic();deadline=False
    try:
        completed=subprocess.run(command,cwd=cwd,input=stdin,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
        status=completed.returncode;stdout=completed.stdout;stderr=completed.stderr
    except subprocess.TimeoutExpired as error:
        status=None;stdout=error.stdout or b'';stderr=error.stderr or b'';deadline=True
    for suffix,raw in (('stdin',stdin),('stdout',stdout),('stderr',stderr)):(folder/(stem+'.'+suffix)).write_bytes(raw)
    receipt={'command':command,'cwd':str(cwd),'timeout_seconds':timeout,'timed_out':deadline,
             'returncode':status,'wall_seconds':time.monotonic()-before,
             'streams':{suffix:pin(raw) for suffix,raw in (('stdin',stdin),('stdout',stdout),('stderr',stderr))}}
    write_json(folder/(stem+'.process.json'),receipt)
    assert status==0 and not deadline,(stem,receipt)
    return stdout

def original(args):
    assert os.environ.get('GITHUB_ACTIONS')=='true','Rust execution is restricted to CI'
    source_check();read_build(args.output)
    folder=args.output/'original';folder.mkdir()
    version=capture(['rustc','--version'],PACKAGE,folder,'rust-version',15)
    assert version.startswith(b'rustc 1.95.0 ')
    reference=PACKAGE/'reference'
    target=args.output/'original-build'
    capture(['cargo','build','--locked','--release','--manifest-path',str(reference/'Cargo.toml'),
             '--target-dir',str(target)],reference,folder,'build',180)
    source_check()
    executable=target/'release/hia-bellman-result-reference'
    raw=(args.output/'native/inputs.bin').read_bytes()
    output=capture([str(executable)],reference,folder,'replay',60,raw)
    write_json(folder/'report.json',{'status':'PASS','source_manifest':source_check(),
        'executable':str(executable.relative_to(args.output)),'executable_pin':read_pin(executable),
        'input':pin(raw),'output':pin(output),'elapsed_is_explicit_observation_fixture':True,
        'public_handler_qualified':False,'whole_runtime_replaced':False})
    print(json.dumps({'status':'ORIGINAL_SERIALIZER_PASS','output':pin(output)}),flush=True)

def verify(args):
    source_check();build_data=read_build(args.output)
    folder=args.output/'native';report=json.loads((folder/'report.json').read_bytes())
    assert report['status']=='NATIVE_PASS_REFERENCE_REQUIRED' and report['source_manifest']==source_check()
    assert report['scope']==SCOPE and report['public_handler_qualified'] is False and report['whole_runtime_replaced'] is False
    for name,expected in report['files'].items():assert read_pin(folder/name)==expected,(name,'native file differs')
    expected=list(corpus(PACKAGE/'source'))
    domain=json.loads((PACKAGE/'corpus-domain.json').read_bytes())
    assert domain['case_count']==len(expected)==486
    assert domain['source_sha256']==read_pin(PACKAGE/'cases.py')['sha256']
    assert domain['cases']==[{'name':name,'input_bytes':len(raw),'graph_sha256':hashlib.sha256(raw).hexdigest(),
                             'elapsed_bits':elapsed} for name,raw,elapsed in expected]
    bundles=[list(records(folder/name)) for name in ('graphs.bin','core.bin','commitment.bin','inputs.bin','outputs.bin')]
    assert all(len(bundle)==len(expected)==len(report['cases'])==report['case_count'] for bundle in bundles)
    for case,observed,row in zip(expected,zip(*bundles),report['cases']):
        name,graph,elapsed=case;actual_graph,core,commitment,wire,result=observed
        assert actual_graph==graph and row['name']==name and row['elapsed_bits']==elapsed
        assert row['states']==u64(graph,8) and core[:8]==b'HIABPLN1' and len(core)==128+72*row['states']
        assert commitment[:8]==b'HBCMTRES' and len(commitment)==128+u64(commitment,8)
        assert commitment[16:48]==hashlib.sha256(commitment[128:]).digest()
        assert commitment[48:80]==bytes.fromhex(TARGET_SHA)
        assert wire==make_wire(core,commitment,elapsed) and pin(wire)==row['input']
        assert result[:64]==response_header(0,len(result)-64) and pin(result)==row['output']
        value=json.loads(result[64:]);assert tuple(value)==REQUIRED_KEYS
        assert len(value['states'])==row['states']
    base=bundles[3][0];base_output=bundles[4][0]
    control_bundles=[list(records(folder/name)) for name in ('controls.inputs.bin','controls.outputs.bin','controls.workspace.bin')]
    assert all(len(bundle)==report['control_count']==len(report['controls']) for bundle in control_bundles)
    expected_controls=list(control_cases(base,base_output))
    assert report['control_count']==len(expected_controls)
    for planned,row,(wire,out,work) in zip(expected_controls,report['controls'],zip(*control_bundles)):
        verify_control(row,wire,out,work,base_output)
        assert planned==(row['name'],wire,row['output_capacity'],row['workspace_capacity'],row['expectation'])
    recovery=report['same_session_refusal_recovery']
    assert recovery['codes']==[len(base_output),0xffffffff,len(base_output)]
    output_buffers=list(records(folder/'session.outputs.bin'));work_buffers=list(records(folder/'session.workspace.bin'))
    assert len(output_buffers)==len(work_buffers)==3
    assert output_buffers[0]==output_buffers[1]==output_buffers[2]
    assert work_buffers[0]==work_buffers[1]==work_buffers[2]
    assert output_buffers[0][:len(base_output)]==base_output
    native_only=args.native_only
    if not native_only:
        original_folder=args.output/'original'
        original_report=json.loads((original_folder/'report.json').read_bytes())
        assert original_report['status']=='PASS' and original_report['source_manifest']==source_check()
        assert original_report['elapsed_is_explicit_observation_fixture'] is True
        assert original_report['public_handler_qualified'] is False and original_report['whole_runtime_replaced'] is False
        assert read_pin(args.output/original_report['executable'])==original_report['executable_pin']
        for name in ('rust-version','build','replay'):
            receipt=json.loads((original_folder/(name+'.process.json')).read_bytes())
            assert receipt['returncode']==0 and receipt['timed_out'] is False
            for suffix,expected_pin in receipt['streams'].items():
                assert read_pin(original_folder/(name+'.'+suffix))==expected_pin
        assert (original_folder/'rust-version.stdout').read_bytes().startswith(b'rustc 1.95.0 ')
        assert (original_folder/'replay.stdin').read_bytes()==(folder/'inputs.bin').read_bytes()
        assert read_pin(original_folder/'replay.stdin')==original_report['input']
        assert read_pin(original_folder/'replay.stdout')==original_report['output']
        originals=list(records(original_folder/'replay.stdout'))
        assert len(originals)==len(expected)
        for row,native_bytes,original_bytes in zip(report['cases'],bundles[4],originals):
            assert native_bytes[64:]==original_bytes,('whole original body differs',row['name'],pin(native_bytes[64:]),pin(original_bytes))
    return {'status':'NATIVE_READER_PASS_REFERENCE_REQUIRED' if native_only else 'PASS',
            'source_manifest':source_check(),'cases':len(expected),'controls':report['control_count'],
            'fresh_native_components':build_data['fresh_native_components'],'complete_original_bytes_compared':not native_only,
            'public_handler_qualified':False,'whole_runtime_replaced':False,'scope':SCOPE}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase',choices=('build','native','original','verify','all'),required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--hepta',type=Path)
    p.add_argument('--bootstrap-cache',type=Path)
    p.add_argument('--native-only',action='store_true')
    args=p.parse_args();args.output=args.output.resolve()
    if args.phase=='all':
        assert os.environ.get('GITHUB_ACTIONS')=='true'
        args.output.mkdir(parents=True)
        shutil.copytree(PACKAGE,args.output/'recipe-source')
        for phase in ('build','native','original'):
            command=[sys.executable,'-I','-B',str(PACKAGE/'qualify.py'),'--phase',phase,'--output',str(args.output)]
            if phase=='build':command+=['--hepta',str(args.hepta.resolve())]
            capture(command,PACKAGE,args.output/'processes',phase,240 if phase=='original' else 180)
        result=verify(args);write_json(args.output/'result.json',result);print(json.dumps(result))
    elif args.phase=='verify':print(json.dumps(verify(args)),flush=True)
    elif args.phase=='build':args.output.mkdir(parents=True,exist_ok=True);build(args)
    elif args.phase=='native':native(args)
    else:original(args)

if __name__=='__main__':main()
