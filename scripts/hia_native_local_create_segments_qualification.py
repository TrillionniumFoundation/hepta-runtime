"""Strict readback for the same-owner segmented Create entry; no execution."""
from __future__ import annotations
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import hia_native_local_create_qualification as core

ROOT=Path(__file__).resolve().parents[1]
FOLDER='local-create-segments'
DRIVERS=core.DRIVERS
TESTS=('test_local_create_segments.py','test_local_create_segments_evidence.py')
SCOPE=dict(core.SCOPE)
COUNTS=dict(actual_native_typed_calls=17885,ordinary_kernel_cases=285,race_pairs=32,
            actual_fault_cases=8,ordinary_root_processes=357,initial_frame_processes=101,
            initial_frame_refusals=98,accepted_generations=3)
CONTROL_COUNTS=dict(actual_captures=2,process_refusals=6,source_refusals=3,artifact_refusals=8)
PIN_SHA='577baea54643db760787fdab198d4b07559b480fa01c79701c633abaaa66a9b3'
SOURCE_FILES=tuple(dict.fromkeys((*core.SOURCE_FILES,
    'native/local_create_file_async_abi.md',
    'scripts/hia_native_local_create_segments_qualification.py',
    *('tests/hia_native/'+name for name in TESTS),
    *(DRIVERS+'/'+name for name in ('segment_cases.py','segment_native_cases.py',
                                   'segment_admission_cases.py','segment_corpus_pins.json')))))
sha=core.sha
pin=core.pin
compact=core.compact
exact=core.exact
require=core.require
owned=core.owned
Q=core.Q
U=core.U


def source_evidence(root=ROOT):
    root=Path(root).resolve(strict=True)
    original=core.source_evidence(root)
    files={name:pin(owned(root,name).read_bytes())for name in SOURCE_FILES}
    require(files[DRIVERS+'/segment_corpus_pins.json']['sha256']==PIN_SHA,'segmented corpus pin changed')
    corpus=core.decode(owned(root,DRIVERS+'/segment_corpus_pins.json').read_bytes())
    component=original['component']
    require(corpus['source_sha256']==component['source_sha256']['native/local_create_file.hepta']
            and corpus['image_sha256']==component['owner_image_sha256'],'segmented owner/image differs from its complete corpus')
    return dict(schema='hepta.runtime.local-create-segments-source.v1',files=files,
                component=component,reference=original['reference_registry'],**SCOPE)


def driver(root,name):return core.driver(root,name)


def check_typed(evidence,base,root,module,origin):
    summary=evidence.object(base+'/result.json')
    pins=core.decode(owned(root,DRIVERS+'/segment_corpus_pins.json').read_bytes())
    want=dict(schema='hepta.runtime.create-async-segment-probe.v1',status='PASS',error=None,
        cases=pins['cases'],calls=17885,actual_kernel_effects=0,typed_completions_only=True,
        async_original_comparison_performed=False,public_handler_qualified=False,whole_runtime_replaced=False)
    exact({k:summary.get(k)for k in want},want,'segmented typed corpus domain/status differs')
    require(core.finite(summary.get('elapsed_seconds'),180),'segmented typed corpus deadline differs')
    owner=str(Path(module['manifest']).parent/'owner.json')
    manifest=evidence.read(owner)
    exact(summary.get('manifest'),str(Path(origin)/owner),'segmented typed owner manifest path differs')
    exact(summary.get('manifest_sha256'),sha(manifest),'segmented typed owner manifest hash differs')
    raw=evidence.read(base+'/rows.json');exact(pin(raw),pins['rows'],'segmented call declarations changed')
    rows=core.decode(raw);require(len(rows)==17885,'segmented typed call count changed')
    stream=gzip.GzipFile(fileobj=io.BytesIO(evidence.read(base+'/arrays.bin.gz')))
    digest=hashlib.sha256();total=0;refusals=0
    for number,row in enumerate(rows,1):
        require(row.get('number')==number and type(row['number'])is int,'segmented call order changed')
        capacities=row['capacities'];require(len(capacities)==3 and all(type(n)is int and n>=0 for n in capacities),'segmented capacities changed')
        arrays=[]
        for size in capacities*2:
            head=stream.read(8);require(len(head)==8 and U(head,0)==size+32,'segmented complete array framing differs')
            raw=stream.read(size+32);require(len(raw)==size+32,'segmented complete array truncated')
            require(raw[:16]==b'G'*16 and raw[-16:]==b'g'*16,'segmented borrowed guard changed')
            digest.update(head);digest.update(raw);total+=len(head)+len(raw);arrays.append(raw)
        before,after=arrays[:3],arrays[3:];require(before[0]==after[0],'segmented input changed')
        wire=before[0][16:-16];require(wire[:8]==b'HLCARQ01'and len(wire)==64+U(wire,16)+U(wire,24),'segmented request framing changed')
        exact([U(wire,n)for n in (8,32,40,56)],[row[k]for k in ('operation','generation','sequence','cancel')],
              'segmented typed command differs from captured input')
        code=row['code'];require(type(code)is int and code in(48,128,0xffffffff,0xfffffffe),'segmented return domain changed')
        if code in(0xffffffff,0xfffffffe):
            require(before[1:]==after[1:],'segmented refusal changed complete borrowed arrays');refusals+=1
        elif code==128:
            body=after[1][16:144];require(body[:8]==b'HLCASR01'and U(body,8)==128 and U(body,120)==0,'segmented control framing differs')
            require(row['action']==U(body,16)and after[1][144:]==before[1][144:],'segmented control output tail changed')
        else:
            core.result_body(after[1][16:64],False)
            require(after[1][64:]==before[1][64:],'segmented result output tail changed')
        meta=(513+U(wire,16)+U(wire,24)+7)&~7
        require(after[2][16+meta+256:]==before[2][16+meta+256:],'segmented workspace tail changed')
    require(stream.read(1)==b'','segmented complete arrays have trailing bytes');stream.close()
    exact(dict(bytes=total,sha256=digest.hexdigest()),pins['arrays'],'segmented complete array corpus changed')
    return dict(calls=len(rows),refusals=refusals,cases=len(pins['cases']),arrays=pins['arrays'],rows=pins['rows'])


def captured_process(evidence,base,row,stdin,binary,cwd,*,umask=0o022):
    stdout,stderr=core.execution_streams(evidence,base,row,stdin,binary,cwd,umask=umask)
    require(row.get('timed_out',False)is False,'segmented native process timed out')
    return stdout,stderr


def read_mixed(evidence,base,row,stdin,binary,cwd,path,data,root,*,umask=0o022):
    stdout,stderr=captured_process(evidence,base,row['execution'],stdin,binary,cwd,umask=umask)
    parsed=driver(root,'segment_native_cases.py').parse_streams(stdout,stderr,path,data)
    for name in ('kind','errno','written','effects','journals'):exact(row.get(name),parsed[name],'segmented complete native stream differs: '+name)
    exact(evidence.object(base+'/execution.json'),row['execution'],'segmented process receipt copy differs')
    return parsed,stdout[8:]


def check_ordinary(evidence,base,root,module,origin,sources):
    native=driver(root,'segment_native_cases.py')
    fixtures=driver(root,'kernel_cases.py')
    faults=driver(root,'fault_cases.py')
    summary=evidence.object(base+'/result.json')
    binary=str(Path(origin)/module['executable'])
    want=dict(schema='hepta.runtime.local-create-segment-native-capture.v1',status='CAPTURED',
        source_root=str(root),output=str(Path(origin)/base),
        executable=dict(path=binary,bytes=sources['component']['executable_bytes'],
                        sha256=module['executable_sha256']),component=sources['component'],
        cancellation_signals_sent=0,injected_completions=False,actual_kernel_operations=True,
        original_rust_execution_performed=False,kernel_cases=285,race_pairs=32,fault_cases=8,
        actual_native_root_processes=357,timeout_seconds_per_process=60,
        driver=pin(owned(root,DRIVERS+'/segment_native_cases.py').read_bytes()),
        source_pins=native.SOURCE_PINS,**SCOPE)
    # A safe snapshot can move the source tree while retaining the actual
    # execution origin. The source bytes are admitted independently above.
    want['source_root']=summary['source_root']
    require(Path(want['source_root']).is_absolute()and'..'not in Path(want['source_root']).parts,'native source origin differs')
    exact({k:summary.get(k)for k in want},want,'ordinary async capture identity/domain differs')
    require(core.finite(summary.get('elapsed_seconds'),180),'ordinary async corpus exceeded deadline')
    request_hash=hashlib.sha256();result_hash=hashlib.sha256();request_bytes=result_bytes=effects=journals=0
    for index,spec in enumerate(fixtures.cases()):
        prefix=base+'/kernel/'+str(index);row=evidence.object(prefix+'/result.json')
        require(row.get('name')==spec['name'],'ordinary async case order differs')
        stdin=native.wire(spec['path'],spec['data'])
        parsed,body=read_mixed(evidence,prefix,row,stdin,binary,str(Path(origin)/prefix/'files'),
                               spec['path'],spec['data'],root,umask=spec['umask'])
        normalized=fixtures.frame(spec['path'],spec['data']);normalized=Q(len(normalized))+normalized
        request_hash.update(normalized);request_bytes+=len(normalized)
        result_hash.update(body);result_bytes+=len(body)
        require(parsed['written']==(len(spec['data'])if parsed['kind']==0 else 0),'ordinary async result progress differs')
        core.check_snapshot(evidence,prefix+'/before',row['before'],core.fixture_rows(spec,False))
        core.check_snapshot(evidence,prefix+'/after',row['after'],core.fixture_rows(spec,parsed['kind']==0))
        effects+=len(parsed['effects']);journals+=len(parsed['journals'])
    frozen=core.corpus(root)
    exact(dict(bytes=request_bytes,sha256=request_hash.hexdigest()),frozen['kernel_requests'],'ordinary request domain changed')
    exact(dict(bytes=result_bytes,sha256=result_hash.hexdigest()),frozen['kernel_results'],'ordinary result domain changed')
    for index,(limit,size)in enumerate(faults.cases()):
        prefix=base+'/fault/'+str(index);row=evidence.object(prefix+'/result.json');data=faults.payload(size)
        parsed,_=read_mixed(evidence,prefix,row,native.wire(b'created',data),binary,
            str(Path(origin)/prefix/'files'),b'created',data,root)
        exact([row.get('index'),row.get('limit'),row.get('input_bytes')],[index,limit,size],'fault input domain changed')
        exact([parsed['kind'],parsed['errno']],([1,27]if size>limit else[0,0]),'fault error order changed')
        require(parsed['written']==min(limit,size),'fault complete progress changed')
        execution=row['execution']
        exact([execution.get('rlimit_fsize'),execution.get('sigxfsz')],[[limit,limit],'ignored'],'fault kernel limit changed')
        actual=evidence.read(prefix+'/created.bin');require(actual==data[:min(size,limit)],'fault complete file prefix changed')
        exact(row.get('file'),pin(actual),'fault file receipt differs')
        effects+=len(parsed['effects']);journals+=len(parsed['journals'])
    payloads=[b'first caller bytes',b'second caller bytes']
    for number in range(32):
        prefix=base+'/race/'+str(number);row=evidence.object(prefix+'/result.json')
        require(row.get('number')==number and row.get('both_processes_live_before_input_release')is True,'race admission differs')
        require(len(row['processes'])==2,'race process count differs')
        parsed_rows=[];pids=[]
        for index,process in enumerate(row['processes']):
            part=prefix+'/'+str(index)
            raw=evidence.compressed(part+'.stdin.bin.gz');stdout=evidence.read(part+'.stdout.bin');stderr=evidence.read(part+'.stderr.bin')
            require(raw==native.wire(b'created',payloads[index]),'race complete native input differs')
            execution=process['execution'];exact(evidence.object(part+'.execution.json'),execution,'race receipt copy differs')
            want=dict(command=[binary],cwd=str(Path(origin)/prefix/'files'),environment={'PATH':'','LC_ALL':'C'},
                timeout_seconds=60,exit_code=0,umask=0o022,stdin=pin(raw),stdout=pin(stdout),stderr=pin(stderr))
            exact({k:execution.get(k)for k in want},want,'race actual process/streams differ')
            require(core.finite(execution.get('elapsed_seconds'),60)and execution.get('timed_out',False)is False,'race process deadline differs')
            require(type(execution.get('pid'))is int and execution['pid']>0,'race PID missing');pids.append(execution['pid'])
            parsed=native.parse_streams(stdout,stderr,b'created',payloads[index])
            for name in ('kind','errno','written','effects','journals'):exact(process.get(name),parsed[name],'race complete parsed stream differs')
            parsed_rows.append([parsed['kind'],parsed['errno']]);effects+=len(parsed['effects']);journals+=len(parsed['journals'])
        require(len(set(pids))==2 and sorted(parsed_rows)==[[0,0],[1,17]],'race did not reserve exactly one pathname')
        winner=parsed_rows.index([0,0]);require(row.get('winner')==winner,'race winner changed')
        actual=evidence.read(prefix+'/created.bin');require(actual==payloads[winner],'race complete winner file changed')
        exact(row.get('final_file'),pin(actual),'race final bytes receipt differs')
    pending=[kind+'/'+str(i)+'/files'for kind,count in(('kernel',285),('fault',8),('race',32))for i in range(count)]
    exact(summary.get('pending_fixture_directories'),pending,'ordinary owned fixture directory domain differs')
    exact([summary.get('actual_effects'),summary.get('complete_control_journals')],[effects,journals],'ordinary full trace counts differ')
    artifacts={name[len(base)+1:]:digest for name,digest in evidence.artifact_sha256.items()
               if name.startswith(base+'/')and name!=base+'/result.json'}
    exact(summary.get('artifact_sha256'),dict(sorted(artifacts.items())),'ordinary complete artifact inventory differs')
    return dict(kernel_cases=285,race_pairs=32,fault_cases=8,actual_processes=357,
        kernel_effects=effects,control_journals=journals,requests=frozen['kernel_requests'],results=frozen['kernel_results'])


def check_admission(evidence,base,root,module,origin,sources):
    controls=driver(root,'segment_admission_cases.py');native=driver(root,'segment_native_cases.py')
    summary=evidence.object(base+'/result.json');cases=controls.cases()
    require(len(cases)==101 and len(summary.get('cases',[]))==101,'initial async frame domain changed')
    binary=str(Path(origin)/module['executable'])
    want=dict(schema='hepta.runtime.local-create-async-admission-controls.v1',status='CAPTURED',
        output=str(Path(origin)/base),component=sources['component'],
        executable=dict(path=binary,bytes=sources['component']['executable_bytes'],sha256=module['executable_sha256']),
        actual_processes=101,refusals=98,accepted_generations=3,timeout_seconds_per_process=60,
        driver=pin(owned(root,DRIVERS+'/segment_admission_cases.py').read_bytes()),
        async_cancellation_qualified=False,public_handler_qualified=False,whole_runtime_replaced=False)
    exact({k:summary.get(k)for k in want},want,'initial async frame capture identity differs')
    require(core.finite(summary.get('elapsed_seconds'),180),'initial async frame corpus deadline differs')
    for index,((name,frame,accepted),row)in enumerate(zip(cases,summary['cases'],strict=True)):
        prefix=base+'/'+str(index);stdin=Q(len(frame))+frame
        require(evidence.read(prefix+'/stdin.bin')==stdin,'initial async frame complete input differs')
        stdout=evidence.read(prefix+'/stdout.bin');stderr=evidence.read(prefix+'/stderr.bin')
        execution=evidence.object(prefix+'/execution.json')
        want=dict(name=name,accepted=accepted,command=[binary],cwd=str(Path(origin)/prefix/'files'),
            environment={'PATH':'','LC_ALL':'C'},umask=0o022,timeout_seconds=60,exit_code=0,
            stdin=pin(stdin),stdout=pin(stdout),stderr=pin(stderr))
        exact({k:execution.get(k)for k in want},want,'initial async frame actual process differs')
        require(core.finite(execution.get('elapsed_seconds'),60),'initial async frame process deadline differs')
        exact({k:row.get(k)for k in execution},execution,'initial async frame execution receipt copy differs')
        exact(evidence.object(prefix+'/result.json'),row,'initial async frame result receipt copy differs')
        if accepted:
            parsed=native.parse_streams(stdout,stderr,b'created',b'abc',expected_generation=U(frame,32))
            require(evidence.read(prefix+'/created.bin')==b'abc','accepted generation file bytes differ')
            require(parsed['kind']==0 and parsed['written']==3,'accepted generation completion differs')
            exact([row.get('actual_effect_records'),row.get('complete_journal_records')],
                  [len(parsed['effects']),len(parsed['journals'])],'accepted generation full trace counts differ')
        else:
            require(stdout==Q(0xffffffff)and stderr==b'','initial async private command unexpectedly admitted')
            exact([row.get('actual_effect_records'),row.get('complete_journal_records')],[0,0],'refused frame has effects')
    retained=evidence.object(base+'/summary.json')
    expected={k:v for k,v in summary.items()if k not in('cases','component')}
    expected['result_sha256']=sha(evidence.read(base+'/result.json'))
    exact(retained,expected,'initial frame summary copy differs')
    return dict(actual_processes=101,refusals=98,accepted_generations=3)


def fixture_directories():
    ordinary=[FOLDER+'/native/ordinary/'+kind+'/'+str(i)+'/files'
              for kind,count in(('kernel',285),('fault',8),('race',32))for i in range(count)]
    return ordinary+[FOLDER+'/native/admission/'+str(i)+'/files'for i in range(101)]


def retire_fixtures(output,capture,*,create=False):
    output=Path(output).resolve();paths=fixture_directories()
    expected=dict(schema='hepta.runtime.local-create-segments-retirement.v1',status='PASS',
        capture_sha256=sha(compact(capture)),directories=paths,retired_directories=426,
        native_or_original_reexecuted=False)
    destination=output/FOLDER/'native/retirement.json'
    if create:
        require(not destination.exists(),'segmented fixture retirement already exists')
        for name in paths:
            path=output/name
            require(path.is_dir()and not path.is_symlink()and path.resolve()==path.absolute(),
                    'segmented owned fixture directory changed before retirement')
        for name in paths:shutil.rmtree(output/name)
        destination.write_bytes(compact(expected)+bytes([10]))
    evidence=core.Evidence(output)
    exact(evidence.object(FOLDER+'/native/retirement.json'),expected,'segmented retirement receipt changed')
    require(all(not(output/name).exists()and not(output/name).is_symlink()for name in paths),
            'segmented live fixture remains in aggregate artifacts')
    return evidence.artifact_sha256


def check_driver(evidence,label,root,execution,module):
    base=FOLDER+'/native/'+label
    scripts={'state':'segment_cases.py','ordinary':'segment_native_cases.py','admission':'segment_admission_cases.py'}
    command=[execution['python'],'-I','-B',str(Path(execution['source_root'])/DRIVERS/scripts[label])]
    if label=='state':command+=['--manifest',str(Path(execution['manifest']).parent/'owner.json')]
    else:command+=['--binary',str(Path(execution['output'])/module['executable'])]
    command+=['--output',str(Path(execution['output'])/base)]
    receipt=evidence.object(FOLDER+'/native/'+label+'.driver.process.json')
    stdout=evidence.read(FOLDER+'/native/'+label+'.driver.stdout')
    stderr=evidence.read(FOLDER+'/native/'+label+'.driver.stderr')
    want=dict(command=command,timeout_seconds=180,exit_code=0,timed_out=False,
              stdout=pin(stdout),stderr=pin(stderr))
    exact({k:receipt.get(k)for k in want},want,'segmented actual driver execution differs')
    require(core.finite(receipt.get('elapsed_seconds'),180)and stderr==b'','segmented driver failed or exceeded deadline')
    summary=evidence.object(base+'/result.json')
    if label=='state':expected=summary
    elif label=='ordinary':expected={k:v for k,v in summary.items()if k not in('component','artifact_sha256','pending_fixture_directories')}
    else:expected=evidence.object(base+'/summary.json')
    exact(core.decode(stdout),expected,'segmented driver complete stdout differs')
    if label!='state':exact(summary.get('source_root'),execution['source_root'],'segmented inner source origin differs')


def capture_native(output,manifest_path,*,source_root=ROOT,execution=None):
    output=Path(output).resolve();root=Path(source_root).resolve();manifest_path=Path(manifest_path).resolve()
    source=source_evidence(root);component=source['component'];evidence=core.Evidence(output)
    relative=manifest_path.relative_to(output).as_posix()
    report=dict(compiler_commit=component['compiler_commit'],compiler_image_sha256=component['compiler_sha256'],
        modules={'local_create_file':dict(manifest=relative,sha256=sha(manifest_path.read_bytes()),
            source='native/local_create_file.hepta',builder='local_create')})
    module=core.module_evidence(evidence,report,root)
    require(type(execution)is dict and set(execution)=={'source_root','output','manifest','python'},'segmented execution origin missing')
    require(all(type(x)is str and Path(x).is_absolute()and'..'not in Path(x).parts for x in execution.values()),'segmented execution origin must be absolute')
    exact(execution['manifest'],str(Path(execution['output'])/relative),'segmented manifest origin changed')
    require(Path(execution['python']).name.startswith('python'),'segmented driver interpreter differs')
    for label in('state','ordinary','admission'):check_driver(evidence,label,root,execution,module)
    typed=check_typed(evidence,FOLDER+'/native/state',root,module,execution['output'])
    ordinary=check_ordinary(evidence,FOLDER+'/native/ordinary',root,module,execution['output'],source)
    admission=check_admission(evidence,FOLDER+'/native/admission',root,module,execution['output'],source)
    exact(source_evidence(root),source,'segmented source changed during complete readback')
    return dict(schema='hepta.runtime.local-create-segments-capture.v1',status='PASS',
        counts=COUNTS,source_inputs=source,module=module,execution=execution,typed=typed,ordinary=ordinary,
        admission=admission,artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),**SCOPE)


def core_evidence(output,report,*,source_root=ROOT):
    output=Path(output).resolve();evidence=core.Evidence(output)
    stored=evidence.object(FOLDER+'/native/summary.json');execution=stored.get('execution')
    require(type(execution)is dict,'segmented actual execution origin absent')
    summary=core.process(evidence,report,TESTS[0],core.suite_command(report,TESTS[0],execution['source_root']),
                         'native_components',groups=3)
    exact(summary,stored,'segmented outer native summary differs')
    module=core.module_evidence(evidence,report,source_root)
    capture=capture_native(output,owned(output,module['manifest']),source_root=source_root,execution=execution)
    expected=dict(schema='hepta.runtime.local-create-segments-native-suite.v1',status='PASS',
        tests_run=3,expected_tests=3,failures=0,errors=0,skipped=0,expected_failures=0,unexpected_successes=0,
        counts=COUNTS,source_inputs=source_evidence(source_root),execution=execution,
        manifest_sha256=module['manifest_sha256'],capture_sha256=sha(compact(capture)),sources_unchanged=True,**SCOPE)
    exact(summary,expected,'segmented native suite domain/source/completion differs')
    evidence.artifact_sha256.update(capture['artifact_sha256'])
    evidence.artifact_sha256.update(retire_fixtures(output,capture))
    return dict(schema='hepta.runtime.local-create-segments-core-evidence.v1',status='PASS',
        counts=COUNTS,source_inputs=capture['source_inputs'],module=module,native_capture_sha256=sha(compact(capture)),
        artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),**SCOPE)


def native_evidence(output,report,*,source_root=ROOT):
    result=core_evidence(output,report,source_root=source_root);evidence=core.Evidence(output)
    origin=evidence.object(FOLDER+'/native/summary.json')['execution']['source_root']
    summary=core.process(evidence,report,TESTS[1],core.suite_command(report,TESTS[1],origin),
                         'native_components',groups=4)
    exact(evidence.object(FOLDER+'/evidence-controls.json'),summary,'segmented evidence control stdout differs')
    expected=dict(schema='hepta.runtime.local-create-segments-evidence-controls.v1',status='PASS',
        tests_run=4,expected_tests=4,failures=0,errors=0,skipped=0,expected_failures=0,unexpected_successes=0,
        counts=CONTROL_COUNTS,source_inputs=source_evidence(source_root),native_evidence_sha256=sha(compact(result)),
        new_native_calls=0,synthetic_receipt_controls=True,**SCOPE)
    exact(summary,expected,'segmented evidence control domain/source differs')
    result['evidence_controls']=CONTROL_COUNTS
    result['artifact_sha256'].update(evidence.artifact_sha256)
    result['artifact_sha256']=dict(sorted(result['artifact_sha256'].items()))
    return result


def original_evidence(output,report,rustc):
    native=native_evidence(output,report)
    exact(report.get('local_create_segments_evidence'),native,'segmented native capture changed before original comparison')
    original=core.original_evidence(output,report,rustc)
    evidence=core.Evidence(Path(output).resolve());compared=0;bytes_compared=0
    for index in range(285):
        left=FOLDER+'/native/ordinary/kernel/'+str(index);right=core.FOLDER+'/original/kernel/'+str(index)
        a=evidence.object(left+'/result.json');b=evidence.object(right+'/result.json')
        for key in('name','kind','errno','before','after'):exact(a[key],b[key],'segmented/original filesystem result differs')
        if a['kind']==0:exact(a['written'],b['written'],'segmented/original successful count differs')
        for phase in('before','after'):
            for item in a[phase]:
                if item['kind']=='file':
                    x=evidence.compressed(left+'/'+phase+'/'+item['content']);y=evidence.compressed(right+'/'+phase+'/'+item['content'])
                    require(x==y,'segmented/original complete file bytes differ');compared+=1;bytes_compared+=len(x)
    for index in range(8):
        left=FOLDER+'/native/ordinary/fault/'+str(index);right=core.FOLDER+'/original/fault/'+str(index)
        a=evidence.object(left+'/result.json');b=evidence.object(right+'/result.json')
        exact([a['kind'],a['errno']],[b['kind'],b['errno']],'segmented/original fault classification differs')
        if a['kind']==0:exact(a['written'],b['written_field'],'segmented/original successful fault count differs')
        x=evidence.read(left+'/created.bin');y=evidence.read(right+'/created.bin')
        require(x==y,'segmented/original actual partial-file prefix differs');compared+=1;bytes_compared+=len(x)
    # Independent races retain and check their own actual winner. Neither reader
    # relabels a winner to force equality between separately scheduled races.
    return dict(schema='hepta.runtime.local-create-segments-original.v1',status='PASS',
        native_capture_sha256=native['native_capture_sha256'],source_inputs=source_evidence(),
        same_recipe_fresh_original_capture_sha256=sha(compact(original)),same_recipe_fresh_original_processes_verified=357,
        new_original_processes_executed=0,kernel_cases=285,race_pairs=32,fault_cases=8,
        complete_file_comparisons=compared,complete_compared_bytes=bytes_compared,
        artifact_sha256=dict(sorted({**native['artifact_sha256'],**original['artifact_sha256'],**evidence.artifact_sha256}.items())),**SCOPE)
