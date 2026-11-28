"""Read complete fixed Local Create state/build captures without execution."""
from __future__ import annotations
import gzip,hashlib,importlib.util,io,json
from pathlib import Path,PurePosixPath
import hia_native_local_create_qualification as base
import hia_native_local_create_spec_build as build
ROOT=Path(__file__).resolve().parents[1]
FOLDER='local-create-spec'
DRIVERS='tests/hia_native/local_create/spec'
TESTS=('test_local_create_spec_build.py','test_local_create_spec_state.py')
PIN_SHA='30004d289e3066d4d9b40dc7e7a9db7fd2f107a4863dea3de1d1deb52c759019'
SCOPE=dict(build.SCOPE)
BUILD_COUNTS=dict(actual_assembler_processes=4,complete_adapter_comparisons=1,
    actual_packer_calls=37,artifact_refusals=33,source_refusals=11,valid_artifact_admissions=1)
STATE_COUNTS=dict(caller_calls=2239,path_calls=108,cache_calls=229,caller_cases=111,
    continuation_refusals=266,awaiter_calls=17631,complete_native_calls=20207)
BUILD_ARTIFACTS=('manifest.json',*(role+suffix for role in build.MEMBERS for suffix in('.json','.hepta','.image.bin')),
    'pack.input.bin','pack.output.bin','pack.workspace.bin','pack.receipt.json','local-create-spec.elf')
SOURCE_FILES=tuple(sorted(set((*build.SOURCE_FILES,
    'scripts/hia_native_local_create_spec_build.py',
    'scripts/hia_native_local_create_spec_state_qualification.py',
    'scripts/hia_native_local_create_qualification.py','scripts/hia_native_local_create_build.py',
    'scripts/hia_native_build.py','scripts/hia_native_loader.py',
    *('tests/hia_native/'+name for name in TESTS),
    *(DRIVERS+'/'+name for name in('state_caller.py','state_await.py','build_cases.py','state_corpus_pins.json'))))))
sha=base.sha;pin=base.pin;compact=base.compact;decode=base.decode;exact=base.exact
require=base.require;finite=base.finite;U=base.U;Q=base.Q

def owned(root,name):
    path=base.owned(root,name);build.read(path);return path

class Evidence(base.Evidence):
    def read(self,name):
        raw=build.read(base.owned(self.output,name));self.artifact_sha256[name]=sha(raw);return raw

def source_evidence(root=ROOT):
    root=Path(root).resolve(strict=True);component=build.source_evidence(root)
    files={name:pin(build.read(owned(root,name)))for name in SOURCE_FILES}
    require(files[DRIVERS+'/state_corpus_pins.json']['sha256']==PIN_SHA,'Local state frozen corpus changed')
    pins=decode(build.read(owned(root,DRIVERS+'/state_corpus_pins.json')))
    require(pins['source_sha256']==component['source_sha256'][build.MEMBERS['caller']]
        and pins['image_sha256']==component['image_sha256']['caller'],'Local state corpus owner differs')
    for name,want in pins['drivers'].items():exact(files[DRIVERS+'/'+name],want,'Local state driver changed')
    return dict(schema='hepta.runtime.local-create-spec-state-source.v1',files=files,component=component,**SCOPE)

def cases(root=ROOT):
    path=owned(root,DRIVERS+'/build_cases.py')
    spec=importlib.util.spec_from_file_location('_local_spec_build_cases',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

class Arrays:
    def __init__(self,raw):
        self.stream=gzip.GzipFile(fileobj=io.BytesIO(raw));self.digest=hashlib.sha256();self.total=0
    def read(self,size):
        head=self.stream.read(8);require(len(head)==8 and U(head,0)==size,'Local complete array extent differs')
        raw=self.stream.read(size);require(len(raw)==size,'Local complete array is truncated')
        self.digest.update(head);self.digest.update(raw);self.total+=8+size;return raw
    def finish(self):
        require(self.stream.read(1)==b'','Local complete array has trailing bytes');self.stream.close()
        return dict(bytes=self.total,sha256=self.digest.hexdigest())

def state_capture(evidence,folder,label,root,manifest,origin):
    frozen=decode(build.read(owned(root,DRIVERS+'/state_corpus_pins.json')))[label]
    prefix=folder+'/'+label;summary=evidence.object(prefix+'/result.json')
    scalar=dict(status='PASS',actual_kernel_operations=False,
        manifest=str(Path(origin['manifest']).parent/'caller.json'),manifest_sha256=sha(build.read(manifest.parent/'caller.json')),
        calls=frozen['calls'],schema='hepta.runtime.local-create-spec-'+label+'-capture.v1')
    scalar['typed_filesystem_completions_only'if label=='caller'else'typed_completions_only']=True
    exact({key:summary.get(key)for key in scalar},scalar,'Local typed state completion differs')
    require(finite(summary.get('elapsed_seconds'),180),'Local typed state deadline differs')
    if label=='caller':
        exact([summary.get('cases'),summary.get('continuation_refusals')],[111,266],'Local caller domain changed')
        exact(pin(evidence.read(prefix+'/cases.json')),frozen['case_rows'],'Local caller fixed cases changed')
    else:exact(summary.get('cases'),frozen['cases'],'Local awaiter transition domain changed')
    rows_raw=evidence.read(prefix+'/rows.json');exact(pin(rows_raw),frozen['rows'],'Local complete typed rows changed')
    rows=decode(rows_raw);require(len(rows)==frozen['calls'],'Local typed row count changed')
    archive='complete-arrays.bin.gz'if label=='caller'else'arrays.bin.gz'
    stream=Arrays(evidence.read(prefix+'/'+archive));guard=32 if label=='caller'else 16
    refusals=0
    for index,row in enumerate(rows,1):
        require(type(row.get('number'))is int and row['number']==index,'Local typed call order changed')
        arrays=[stream.read(n+2*guard)for n in row['capacities']*2]
        for raw in arrays:require(raw[:guard]==b'G'*guard and raw[-guard:]==b'g'*guard,'Local typed borrowed guard changed')
        before,after=arrays[:3],arrays[3:];require(before[0]==after[0],'Local typed input changed')
        code=row['code'];body=after[1][guard:-guard];prior=before[1][guard:-guard]
        if code in(0xffffffff,0xfffffffe):
            require(before[1:]==after[1:],'Local typed refusal wrote borrowed arrays');refusals+=1
        elif label=='await':
            require(code in(32,128)and body[:8]==(b'HSHMKR01'if code==32 else b'HLCASR01'),'Local awaiter output differs')
            require(body[code:]==prior[code:]and after[2][guard+512:]==before[2][guard+512:],'Local awaiter tail changed')
            if code==128:require(row['action']==U(body,16),'Local awaiter action differs')
        elif row['role']=='path':
            require(code==80 and body[:8]==b'HSHCPR01'and 80<=U(body,16)<=len(body),'Local parent projection changed')
            require(body[U(body,16):]==prior[U(body,16):],'Local parent projection tail changed')
        elif row['role']=='cache':
            require(32<=code<len(body)+1 and body[:8]==b'HVCAR001'and body[code:]==prior[code:],'Local actual cache result differs')
        elif code==0xffffffe0:
            require(body[:8]==b'HLCSPFX1'and 64<=U(body,8)<=len(body),'Local caller child frame changed')
            require(body[U(body,8):]==prior[U(body,8):],'Local caller effect tail changed')
        elif code<0xffff0000:
            require(32<=code<=len(body)and body[:8]==b'HLCSPR01'and U(body,24)==code-32 and body[code:]==prior[code:],
                'Local caller complete result differs')
        else:require(code in(0xfffffff7,0xffffffef,0xffffffee)and body==prior,'Local caller private output changed')
    complete=stream.finish();exact(complete,frozen['arrays'],'Local full borrowed corpus differs')
    if label=='caller':
        expected={name:pin(evidence.read(prefix+'/'+name))for name in('rows.json','cases.json',archive)}
        exact(summary.get('artifacts'),expected,'Local caller retained artifact inventory differs')
    return dict(calls=len(rows),refusals=refusals,complete_arrays=complete,rows=frozen['rows'])

def driver_capture(evidence,label,root,manifest,origin):
    prefix=FOLDER+'/state';record=evidence.object(prefix+'/'+label+'.process.json')
    stdout=evidence.read(prefix+'/'+label+'.stdout');stderr=evidence.read(prefix+'/'+label+'.stderr')
    command=[origin['python'],'-I','-B',str(Path(origin['source_root'])/DRIVERS/('state_'+label+'.py')),
        '--manifest',str(Path(origin['manifest']).parent/'caller.json'),
        '--output',str(Path(origin['output'])/prefix/label)]
    expected=dict(command=command,timeout_seconds=180,exit_code=0,timed_out=False,stdout=pin(stdout),stderr=pin(stderr))
    exact({k:record.get(k)for k in expected},expected,'Local typed driver actual process differs')
    require(stderr==b''and finite(record.get('elapsed_seconds'),180),'Local typed driver failed or exceeded deadline')
    exact(decode(stdout),evidence.object(prefix+'/'+label+'/result.json'),'Local typed driver stdout differs')
    return state_capture(evidence,prefix,label,root,manifest,origin)

def capture_state(output,manifest,*,source_root=ROOT,execution):
    root=Path(source_root).resolve(strict=True);manifest=Path(manifest).resolve(strict=True)
    build.verify_build(manifest,source_root=root);source=source_evidence(root)
    evidence=Evidence(output)
    require(set(execution)=={'source_root','manifest','output','python'},'Local state process origin absent')
    require(all(type(v)is str and Path(v).is_absolute()and'..'not in Path(v).parts for v in execution.values()),
        'Local state process origin is not absolute')
    relative=manifest.relative_to(evidence.output).as_posix()
    exact(execution['manifest'],str(Path(execution['output'])/relative),'Local state manifest origin changed')
    captured={label:driver_capture(evidence,label,root,manifest,execution)for label in('caller','await')}
    exact(source_evidence(root),source,'Local state source changed during readback')
    return dict(schema='hepta.runtime.local-create-spec-state-capture.v1',status='PASS',
        counts=STATE_COUNTS,source_inputs=source,captures=captured,execution=execution,
        artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),**SCOPE)

def module_evidence(evidence,report,root):
    row=report['modules']['local_create_spec'];relative=row['manifest'];raw=evidence.read(relative)
    exact({k:row.get(k)for k in('source','builder','sha256')},
        dict(source=build.MEMBERS['caller'],builder='local_create_spec',sha256=sha(raw)),'Local state registered module differs')
    manifest=owned(evidence.output,relative);metadata=build.verify_build(manifest,source_root=root)
    folder=PurePosixPath(relative).parent
    for name in BUILD_ARTIFACTS:evidence.read(str(folder/name))
    compiler=evidence.read('build/bootstrap/B3.image.bin');evidence.read('build/bootstrap/bootstrap.json')
    require(sha(compiler)==metadata['compiler_sha256']==report['compiler_image_sha256']
        and metadata['compiler_commit']==report['compiler_commit'],'Local state compiler custody differs')
    return manifest,dict(manifest=relative,manifest_sha256=sha(raw),executable=str(folder/'local-create-spec.elf'),
        executable_identity=pin(evidence.read(str(folder/'local-create-spec.elf'))))

def build_capture(evidence,root,manifest,origin):
    component=build.source_evidence(root);definitions=cases(root);folder=FOLDER+'/build-controls'
    process_rows=evidence.object(folder+'/assembler-processes.json');require(len(process_rows)==4,'Local prefix process count differs')
    directory=Path(origin['output'])/folder
    commands=[['as','--64','-o',str(directory/'adapter.o'),str(Path(origin['source_root'])/'scripts/local_create_spec_adapter.S')],
        ['ld','-nostdlib','-Ttext=0','-e','_start','-o',str(directory/'adapter.elf'),str(directory/'adapter.o')],
        ['objcopy','-O','binary','--only-section=.text',str(directory/'adapter.elf'),str(directory/'adapter.bin')],
        ['readelf','-r',str(directory/'adapter.elf')]]
    for index,(row,command)in enumerate(zip(process_rows,commands,strict=True)):
        stdout=evidence.read(folder+'/'+str(index)+'.stdout');stderr=evidence.read(folder+'/'+str(index)+'.stderr')
        expected=dict(command=command,timeout_seconds=30,exit_code=0,stdout=pin(stdout),stderr=pin(stderr))
        exact({k:row.get(k)for k in expected},expected,'Local prefix actual assembler completion differs')
        require(stderr==b''and finite(row.get('elapsed_seconds'),30),'Local prefix assembler failed')
    require(b'There are no relocations'in stdout,'Local prefix has unresolved relocations')
    require(evidence.read(folder+'/adapter.bin')==bytes.fromhex(component['prefix_hex'])[176:],'Local complete native prefix differs')
    evidence.read(folder+'/adapter.o');evidence.read(folder+'/adapter.elf')
    rows=evidence.object(folder+'/packer-calls.json')
    wire=build.read(manifest.parent/'pack.input.bin');definition=definitions.packer_cases(wire,component['executable_bytes'])
    require(len(rows)==len(definition)==37,'Local packer control domain changed')
    archive=Arrays(evidence.read(folder+'/packer-arrays.bin.gz'))
    for row,(label,request,capacity,code)in zip(rows,definition,strict=True):
        capacities=[len(request),capacity,64]
        exact(row,dict(name=label,code=code,capacities=capacities),'Local actual packer result differs')
        arrays=[archive.read(n+32)for n in capacities*2];before,after=arrays[:3],arrays[3:]
        require(before==[b'G'*16+value+b'g'*16 for value in(request,b'\xa7'*capacity,b'\x5a'*64)],
            'Local complete packer inputs differ')
        require(after[0]==before[0]and after[2]==before[2],'Local packer changed input/workspace')
        expected=definitions.packed(component,request)+b'\xa7'*(capacity-code)if code<0xffff0000 else b'\xa7'*capacity
        require(after[1]==b'G'*16+expected+b'g'*16,'Local complete packed bytes/tail differ')
    packed_arrays=archive.finish()
    edits=[(category,*item)for category,items in(
        ('artifact',definitions.artifact_mutations(build.MEMBERS)),
        ('source',definitions.source_mutations(build.SOURCE_FILES)))for item in items]
    records=evidence.object(folder+'/refusals.json');require(len(records)==len(edits)==44,'Local refusal domain changed')
    archive=Arrays(evidence.read(folder+'/mutation-bytes.bin.gz'))
    for row,(category,label,relative,operation,field,value)in zip(records,edits,strict=True):
        path=manifest.parent/relative if category=='artifact'else owned(root,relative)
        before=build.read(path);after=definitions.mutated(before,operation,field,value)
        expected=dict(category=category,name=label,relative=relative,operation=operation,field=field,value=value,
            before=pin(before),after=pin(after))
        exact({key:row.get(key)for key in expected},expected,'Local exact mutation domain differs')
        require(row.get('exception')in('ValueError','KeyError','TypeError','JSONDecodeError')
            and type(row.get('message'))is str and row['message'],'Local mutation refusal observation missing')
        require(archive.read(len(before))==before and archive.read(len(after))==after and before!=after,
            'Local complete mutation bytes differ')
    mutation_arrays=archive.finish()
    return dict(counts=BUILD_COUNTS,packer_arrays=packed_arrays,mutation_arrays=mutation_arrays)

def suite_summary(evidence,report,test,root,groups,folder):
    retained=evidence.object(folder+'/summary.json');origin=retained.get('execution')
    require(type(origin)is dict and all(type(v)is str and Path(v).is_absolute()and'..'not in Path(v).parts for v in origin.values()),
        'Local state/build actual origin absent')
    summary=base.process(evidence,report,test,base.suite_command(report,test,origin['source_root']),'native_components',groups=groups)
    exact(summary,retained,'Local state/build retained suite summary differs')
    return summary,origin

def native_evidence(output,report,*,source_root=ROOT):
    root=Path(source_root).resolve(strict=True);source=source_evidence(root);evidence=Evidence(output)
    manifest,module=module_evidence(evidence,report,root)
    build_summary,build_origin=suite_summary(evidence,report,TESTS[0],root,3,FOLDER+'/build-controls')
    require(set(build_origin)=={'source_root','manifest','output'},'Local build origin fields changed')
    exact(build_origin['manifest'],str(Path(build_origin['output'])/module['manifest']),'Local build manifest origin differs')
    fixed=dict(status='PASS',failures=0,errors=0,skipped=0,expected_failures=0,unexpected_successes=0,
        source_inputs=source,manifest_sha256=module['manifest_sha256'],**SCOPE)
    expected={**fixed,'schema':'hepta.runtime.local-create-spec-build-suite.v1','tests_run':3,'expected_tests':3,
        'counts':BUILD_COUNTS,'execution':build_origin}
    exact(build_summary,expected,'Local build suite source/domain/completion differs')
    built=build_capture(evidence,root,manifest,build_origin)
    state_summary,state_origin=suite_summary(evidence,report,TESTS[1],root,2,FOLDER+'/state')
    captured=capture_state(output,manifest,source_root=root,execution=state_origin)
    expected={**fixed,'schema':'hepta.runtime.local-create-spec-state-suite.v1','tests_run':2,'expected_tests':2,
        'counts':STATE_COUNTS,'execution':state_origin,'capture_sha256':sha(compact(captured)),'sources_unchanged':True}
    exact(state_summary,expected,'Local state suite source/domain/completion differs')
    evidence.artifact_sha256.update(captured['artifact_sha256'])
    exact(source_evidence(root),source,'Local state/build source changed during readback')
    return dict(schema='hepta.runtime.local-create-spec-state-evidence.v1',status='PASS',
        counts=STATE_COUNTS,build_controls=built,source_inputs=source,module=module,
        state_capture_sha256=sha(compact(captured)),artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),**SCOPE)
