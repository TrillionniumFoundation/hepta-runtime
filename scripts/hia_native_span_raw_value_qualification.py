"""Admit full-span Value/Map, typed SDK boundaries, and complete native wires.

The old public suite and its original reference remain separate and unchanged.
This reader never starts a native process. The two new locked reference builds
are started only by compare_original; retained_original only reads evidence.
"""
from __future__ import annotations
import gzip,hashlib,importlib.util,json,math,os,re,struct,sys
from pathlib import Path
from hia_native_runtime_mcp_evidence import (
    Evidence,compact,decode,exact,finite,owned,require,sha,source_identity,
    completed_suite,native_evidence as public_native_evidence)

FOLDER='runtime-mcp-raw-value'
TEST='test_runtime_mcp_raw_value.py'
CONTROL_TEST='test_runtime_mcp_raw_value_evidence.py'
CONTROL_REPORT='runtime-mcp-raw-value-evidence.json'
GROUPS=3
CONTROL_GROUPS=4
LEAF_CASES=4847
CAPACITY_CASES=37
SDK_CASES=94
COUNTS=dict(actual_native_calls=4884,full_span_cases=4847,capacity_and_recovery_controls=37,
    actual_public_elf_processes=94,actual_public_elf_responses=243,actual_sdk_input_cases=94)
LEAF_IDENTITY={'requests.hex':dict(bytes=17778409,sha256='0130363a8cabb3c07c03ea45957f8a9c56b19ea4a718074fb425dab1e5ea3dfc'),
    'native-output.txt':dict(bytes=540126,sha256='b6de313d11f502ac4d1e9e153cc520ca1ab3c626e2ce4b04e59c588512ca30e5')}
SDK_REQUEST_IDENTITY=dict(bytes=25564,sha256='2d2989fed66d6dc638615d4770ea6cd96a0c2a7c6dc7a286b0d306d206cd7e2a')
SDK_FIXTURE_SHA='1d4446a9351933ab39b5cff1156fad3ae61b48406786056b43b87c7f6fea66f9'
SOURCE_FILES=(
    'scripts/hia_native_span_raw_value_qualification.py','scripts/hia_native_loader.py',
    'scripts/hia_native_runtime_mcp_evidence.py','scripts/hia_native_runtime_mcp_build.py',
    'tests/hia_native/span_raw_value_cases.py','tests/hia_native/span_sdk_cases.json',
    'tests/hia_native/span_json_oracle.rs','tests/hia_native/span_sdk_oracle.rs',
    'tests/hia_native/'+TEST,'tests/hia_native/'+CONTROL_TEST,
    'tests/hia_native/evidence_snapshot.py',
    'tests/hia_native/runtime_mcp_public_capture.py',
    'tests/hia_native/serde_json_oracle/Cargo.toml','tests/hia_native/serde_json_oracle/Cargo.lock',
    'tests/hia_native/workdir_oracle/Cargo.toml','tests/hia_native/workdir_oracle/Cargo.lock')
CONTROL_COUNTS=dict(actual_capture=2,process_refusals=10,source_refusals=4,corpus_refusals=16)
FALSE_FLAGS=('complete_sdk_frontend','whole_runtime_replaced','original_view_body_compared','production_activated')

def pin(raw):return dict(bytes=len(raw),sha256=sha(raw))

def sources(root):
    return dict(public_source_binding=source_identity(root),
        files={name:pin(owned(root,name).read_bytes()) for name in SOURCE_FILES})

def cases_module(root):
    path=owned(root,'tests/hia_native/span_raw_value_cases.py')
    spec=importlib.util.spec_from_file_location('_span_raw_value_cases',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def sdk_cases(root):
    raw=owned(root,'tests/hia_native/span_sdk_cases.json').read_bytes()
    exact(sha(raw),SDK_FIXTURE_SHA,'complete SDK typed-boundary fixture changed')
    rows=decode(raw);require(type(rows) is list and len(rows)==SDK_CASES,'SDK domain count differs')
    require(len({row['name'] for row in rows})==SDK_CASES,'SDK names repeat')
    wire=b''.join(row['request_hex'].encode()+b'\n' for row in rows)
    exact(pin(wire),SDK_REQUEST_IDENTITY,'complete SDK wire domain differs')
    return rows

def initialization():
    return compact(dict(jsonrpc='2.0',id=0,method='initialize',params=dict(protocolVersion='2025-03-26',
        capabilities={},clientInfo=dict(name='raw-span-probe',version='1'))))+b'\n'

def notification():return b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'

def following():
    return compact(dict(jsonrpc='2.0',id=101,method='tools/call',params=dict(name='view',arguments=dict(path='file'))))+b'\n'

def expected_capacity_output(row):
    prefix=b'' if row['code']>=0xfffffffc else row['header']+row['body']
    require(len(prefix)<=row['output_capacity'],'invalid private control expectation')
    return prefix+b'\xa5'*(row['output_capacity']-len(prefix))

def check_leaf(root,evidence):
    prefix=FOLDER+'/';streams={name:evidence.read(prefix+name) for name in LEAF_IDENTITY}
    for name,expected in LEAF_IDENTITY.items():exact(pin(streams[name]),expected,'full Value/Map stream differs: '+name)
    inputs=streams['requests.hex'].splitlines();outputs=streams['native-output.txt'].splitlines()
    require(len(inputs)==len(outputs)==LEAF_CASES,'full Value/Map case count differs')
    rows=evidence.rows(prefix+'calls.jsonl');require(len(rows)==LEAF_CASES,'native call inventory differs')
    generator=cases_module(root);categories={};expected_wire=[]
    cases=list(generator.leaf_cases())+list(generator.large_cases())
    require(len(cases)==LEAF_CASES,'current Value/Map generator count differs')
    for index,((category,wire,status,expected),encoded,line,row) in enumerate(zip(cases,inputs,outputs,rows,strict=True)):
        exact(encoded,wire.hex().encode(),'Value/Map request is not the declared case')
        require(re.fullmatch(b'[0-9a-f]{8}:[0-9a-f]*',line) is not None,'normalized native output is malformed')
        head,body_hex=line.split(b':');code=int(head,16);body=bytes.fromhex(body_hex.decode())
        require(code==0xffffffff or code==len(body),'normalized native result length differs')
        actual_status=0 if code!=0xffffffff else (1 if status is None else status)
        if status is not None:
            exact(actual_status,status,'known Value/Map semantic status differs')
            exact(body,expected,'known Value/Map semantic bytes differ')
        header=b'HJSVR002'+struct.pack('<QQQ',actual_status,len(body),0)
        exact(row,dict(number=index,category=category,request_sha256=sha(wire),header_hex=header.hex(),
            body_sha256=sha(body),output_capacity=1<<20,workspace_capacity=64<<20 if category=='raw-above-8MiB' else 16<<20),
            'native Value/Map header, source or capacity differs')
        categories[category]=categories.get(category,0)+1
    return categories

def check_capacity(root,evidence):
    expected=list(cases_module(root).capacity_cases());rows=evidence.rows(FOLDER+'/capacity.jsonl')
    require(len(rows)==len(expected)==CAPACITY_CASES,'private capacity domain differs')
    for index,(spec,row) in enumerate(zip(expected,rows,strict=True)):
        name='capacity/'+str(index)+'.output.bin.gz';raw=expected_capacity_output(spec)
        actual=evidence.stream(FOLDER,row['output'],name)
        exact(actual,raw,'complete private output or refusal tail differs')
        fields=dict(number=index,session_group=spec['group'],input_hex=spec['wire'].hex(),
            output_capacity=spec['output_capacity'],workspace_capacity=spec['workspace_capacity'],
            return_code=spec['code'],output=dict(path=name,**pin(raw)))
        exact(row,fields,'private request/growth/recovery declaration differs')

def public_projection(case,reply):
    mode=case['native_projection'];reference=case['expected_response']
    if mode=='sdk-error':exact(reply,reference,'complete typed SDK error differs');return
    require(mode in ('view','typed-view-error'),'silent case unexpectedly published a response')
    exact(reply.get('id'),reference['id'],'typed RequestId value differs')
    exact(reply.get('jsonrpc'),'2.0','public JSON-RPC version differs')
    if mode=='typed-view-error':
        require(reply.get('error',{}).get('code')==-32602,'missing-path original View parameter route differs');return
    result=reply.get('result');require(type(result) is dict and result.get('isError') is False,'public actual View failed')
    content=result.get('content');require(type(content) is list and len(content)==1 and content[0].get('type')=='text',
        'public actual View content shape differs')
    text=content[0].get('text');require(type(text) is str and 'alpha' in text and 'beta' in text,
        'expanded argument did not reach the owned actual file')

def check_public(root,evidence,capture):
    cases=sdk_cases(root);rows=evidence.rows(FOLDER+'/public-cases.jsonl')
    require(len(rows)==SDK_CASES,'public SDK boundary case count differs')
    origin=capture['execution'];exe=str(Path(origin['manifest_path']).parent/'runtime-mcp.elf')
    cwd=str(Path(origin['corpus_root'])/'files');responses=0
    for index,(case,row) in enumerate(zip(cases,rows,strict=True)):
        exact((row['number'],row['name']),(index,case['name']),'public case identity differs')
        stem='sessions/'+str(index)+'/'
        record=evidence.object(FOLDER+'/'+stem+'capture-process.json')
        exact(record,row['process'],'actual public process receipt differs')
        fields=dict(command=[exe],cwd=cwd,environment={'PATH':'','LC_ALL':'C'},timeout_seconds=60,exit_code=0,
            timed_out=False,failure_cleanup_requested=False,unconsumed_stdout_bytes=0,exchanges=3)
        exact({key:record.get(key) for key in fields},fields,'public process or original request deadline differs')
        require(finite(record.get('elapsed_seconds'),180),'public process elapsed is not actual')
        streams={key:evidence.stream(FOLDER,dict(path=stem+key+'.bin.gz',**record[key]),stem+key+'.bin.gz')
                 for key in ('stdin','stdout','stderr')}
        request=bytes.fromhex(case['request_hex'])+b'\n'+following()
        batches=[initialization(),notification(),request]
        exact(streams['stdin'],b''.join(batches),'public exact typed-boundary request sequence differs')
        exact(streams['stderr'],b'','public process leaked diagnostics')
        require(streams['stdout'].endswith(b'\n'),'public complete output is missing its final newline')
        lines=streams['stdout'][:-1].split(b'\n');replies=[decode(line) for line in lines]
        count=2+(case['expected_response'] is not None)
        require(len(replies)==count,'public extra/missing response, including silent discard')
        require(replies[0].get('id')==0 and 'result' in replies[0],'public initialization failed')
        require(replies[-1].get('id')==101 and 'result' in replies[-1],'following request did not retain a usable transport')
        if count==3:public_projection(case,replies[1])
        exchanges=evidence.object(FOLDER+'/'+stem+'exchange-summary.json')['exchanges']
        exact(exchanges,decode(evidence.read(FOLDER+'/'+stem+'exchanges.json')),'exchange retained copy differs')
        require(type(exchanges) is list and len(exchanges)==3,'actual exchange inventory differs')
        cursor=0
        for number,(batch,size) in enumerate(zip(batches,[1,0,count-1],strict=True)):
            exchange=exchanges[number];selected=lines[cursor:cursor+size];cursor+=size
            expected=dict(number=number,timeout_seconds=60,requested_bytes=len(batch),written_bytes=len(batch),
                request_sha256=sha(batch),responses=[pin(line) for line in selected],error=None)
            exact({key:exchange.get(key) for key in expected},expected,'actual request write/read or deadline differs')
            require(finite(exchange.get('elapsed_seconds'),60),'actual public exchange exceeded its deadline')
        responses+=count
    exact(responses,COUNTS['actual_public_elf_responses'],'public response domain differs')
    wire=evidence.read(FOLDER+'/sdk-requests.hex');exact(pin(wire),SDK_REQUEST_IDENTITY,'SDK reference input changed')
    exact(wire,b''.join(case['request_hex'].encode()+b'\n' for case in cases),'SDK replay requests are not actual public cases')

def native_evidence(root,output,report,completed):
    root=Path(root).resolve(strict=True);output=Path(output).resolve(strict=True)
    identities=sources(root);check,summary=completed_suite(root,output,report,completed,TEST,GROUPS)
    evidence=Evidence(output);capture=evidence.object(FOLDER+'/result.json')
    owner=report['modules']['runtime_mcp'];manifest=evidence.read(owner['manifest'])
    exact(sha(manifest),owner['sha256'],'span shared public manifest changed')
    exact(summary,capture,'span native stdout differs from actual retained capture')
    expected=dict(schema='hepta.runtime.span-raw-value.native.v1',status='PASS',groups=GROUPS,
        counts=COUNTS,source_inputs=identities,manifest_sha256=owner['sha256'],
        leaf_identity=LEAF_IDENTITY,sdk_requests=SDK_REQUEST_IDENTITY,sources_unchanged=True,
        live_fixture_reads_required=False,**{flag:False for flag in FALSE_FLAGS})
    exact({key:capture.get(key) for key in expected},expected,'span capture domain/source/scope differs')
    require(finite(capture.get('elapsed_seconds'),180),'span actual capture time differs')
    base=evidence.object('runtime-mcp/result.json')['execution']
    exact(capture.get('execution'),dict(runtime_root=base['runtime_root'],manifest_path=base['manifest_path'],
        corpus_root=str(Path(base['corpus_root']).parent/FOLDER)),'span execution origin differs')
    categories=check_leaf(root,evidence);exact(capture.get('leaf_categories'),categories,'span category counts differ')
    check_capacity(root,evidence);check_public(root,evidence,capture)
    for suffix in ('stdout','stderr'):evidence.read(TEST+'.'+suffix)
    public=public_native_evidence(root,output,report,completed)
    exact(capture['manifest_sha256'],public['composition']['manifest_sha256'],'span public owner custody differs')
    exact(sources(root),identities,'span sources changed during complete readback')
    return dict(schema='hepta.runtime.span-raw-value.native-evidence.v1',status='PASS',counts=COUNTS,
        source_inputs=identities,public_manifest_sha256=capture['manifest_sha256'],
        leaf_identity=LEAF_IDENTITY,sdk_requests=SDK_REQUEST_IDENTITY,
        artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),
        artifacts=[evidence.artifacts[name] for name in sorted(evidence.artifacts)],
        public_owner_artifacts=public['artifact_sha256'],new_native_calls=0,new_original_processes=0,
        **{flag:False for flag in FALSE_FLAGS})

def qualification_evidence(root,output,report,completed):
    result=native_evidence(root,output,report,completed)
    check,summary=completed_suite(root,output,report,completed,CONTROL_TEST,CONTROL_GROUPS)
    evidence=Evidence(output);stored=evidence.object(CONTROL_REPORT)
    expected=dict(schema='hepta.runtime.span-raw-value.evidence-controls.v1',status='PASS',
        counts=CONTROL_COUNTS,source_inputs=sources(root),native_evidence_sha256=sha(compact(result)),
        synthetic_receipt_controls=True,new_native_calls=0)
    exact(summary,stored,'span evidence-control stdout differs');exact(summary,expected,'span controls incomplete')
    for suffix in ('stdout','stderr'):evidence.read(CONTROL_TEST+'.'+suffix)
    result['evidence_controls']=CONTROL_COUNTS
    result['artifact_sha256'].update(evidence.artifact_sha256)
    result['artifacts'] += [evidence.artifacts[name] for name in sorted(evidence.artifacts)]
    return result

REFERENCE_KEY='span_raw_value_reference_builds'
SDK_OUTPUT_IDENTITY=dict(bytes=151462,sha256='e47695ce2389817d2e38d63a025ce3cb39c40f70cc889836cdb895de0884fd6d')

def reference_files(key):
    template='serde_json_oracle' if key=='value' else 'workdir_oracle'
    driver='oracle.rs' if key=='value' else 'src/main.rs'
    source='span_json_oracle.rs' if key=='value' else 'span_sdk_oracle.rs'
    return {'Cargo.toml':'tests/hia_native/'+template+'/Cargo.toml',
        'Cargo.lock':'tests/hia_native/'+template+'/Cargo.lock',driver:'tests/hia_native/'+source}

def reference_process(output,report,evidence,name,command):
    from hia_native_json_qualification import completed_reference_process
    row,stdout,stderr=completed_reference_process(output,report,name)
    exact(row.get('command'),command,'locked span reference command differs')
    require(type(row.get('timeout_seconds')) is int and row['timeout_seconds']==180
        and finite(row.get('elapsed_seconds'),180),'locked span reference changed its deadline')
    for suffix in ('stdout','stderr'):evidence.read(name+'.'+suffix)
    return row,stdout,stderr

def retained_original(root,output,report,completed):
    from hia_native_runtime_mcp_original import CLEARED,RUSTC_SHA,CARGO_SHA,RUST_VERSION,tool_path
    root=Path(root).resolve(strict=True);output=Path(output).resolve(strict=True)
    native=qualification_evidence(root,output,report,completed)
    exact(native,report['runtime_mcp_evidence']['span_raw_value'],'span native evidence changed before reference admission')
    state=report.get(REFERENCE_KEY);require(type(state) is dict,'fresh locked span references absent')
    evidence=Evidence(output)
    expected=dict(schema='hepta.runtime.span-raw-value.reference-builds.v1',source_inputs=sources(root),
        native_evidence_sha256=sha(compact(native)),cleared_environment=list(CLEARED))
    exact({key:state.get(key) for key in expected},expected,'span reference source or environment policy differs')
    origin=state.get('execution');require(type(origin) is dict and set(origin)=={'runtime_root','output_root'},'span reference origin absent')
    for path in origin.values():
        require(type(path) is str and Path(path).is_absolute() and str(Path(path))==path and '..' not in Path(path).parts,
            'span reference execution origin is not canonical')
    rustc=tool_path(state['rustc']['invocation'],'rustc');cargo=tool_path(state['cargo']['invocation'],'cargo')
    exact(state['rustc']['sha256'],RUSTC_SHA,'locked span rustc bytes differ')
    exact(state['cargo']['sha256'],CARGO_SHA,'locked span cargo bytes differ')
    require(state.get('removed_environment')==[key for key in CLEARED if key in state.get('removed_environment',[])],
        'span inherited environment declaration differs')
    _,version,stderr=reference_process(output,report,evidence,'span-raw-value-rustc-version',[rustc,'--version'])
    exact(version,RUST_VERSION,'actual span rustc version differs')
    exact(stderr,b'','actual span rustc version wrote diagnostics')
    results={}
    for key in ('value','sdk'):
        base=FOLDER+'/original/'+key;origin_base=str(Path(origin['output_root'])/base)
        files=reference_files(key);build=state['builds'][key]
        materialized={}
        for name,source in files.items():
            raw=evidence.read(base+'/'+name);exact(raw,owned(root,source).read_bytes(),'materialized reference source differs')
            materialized[name]=pin(raw)
        exact(build['sources'],materialized,'reference materialization inventory differs')
        compile_command=[cargo,'build','--locked','--release','--manifest-path',origin_base+'/Cargo.toml','--target-dir',origin_base+'/target']
        compile_row,_,_=reference_process(output,report,evidence,'span-'+key+'-rust-compile',compile_command)
        binary_name='hia-serde-json-reference' if key=='value' else 'hepta-workdir-original-oracle'
        executable=base+'/target/release/'+binary_name;binary=evidence.read(executable)
        require(binary.startswith(b'\x7fELF'),'span reference binary is not ELF')
        exact(build['executable'],executable,'span executable owner differs');exact(build['binary'],pin(binary),'span reference executable bytes differ')
        exact(build['compile_stdout_sha256'],compile_row['stdout_sha256'],'span compiler stdout changed')
        exact(build['compile_stderr_sha256'],compile_row['stderr_sha256'],'span compiler stderr changed')
        input_name='requests.hex' if key=='value' else 'sdk-requests.hex'
        wire=evidence.read(FOLDER+'/'+input_name)
        check,stdout,stderr=reference_process(output,report,evidence,'span-'+key+'-rust-replay',
            [str(Path(origin['output_root'])/executable)])
        exact(stderr,b'','span locked reference wrote replay diagnostics')
        exact(dict(bytes=check.get('stdin_bytes'),sha256=check.get('stdin_sha256')),pin(wire),'span replay input bytes differ')
        if key=='value':
            exact(stdout,evidence.read(FOLDER+'/native-output.txt'),'complete full-span Value/Map Rust stream differs')
            count=LEAF_CASES
        else:
            exact(pin(stdout),SDK_OUTPUT_IDENTITY,'complete current locked SDK output differs')
            rows=[decode(line) for line in stdout.splitlines()];cases=sdk_cases(root);require(len(rows)==len(cases),'SDK replay domain differs')
            for case,row in zip(cases,rows,strict=True):
                exact(row['request_hex'],case['request_hex'],'SDK original request differs from actual native wire')
                expected=[] if case['expected_response'] is None else [case['expected_response']]
                exact(row['case_responses'],expected,'actual SDK response or silent discard differs')
                exact(row['handler_observations'],case['expected_arguments'],'actual typed JsonObject/Value boundary differs')
                exact([reply['id'] for reply in row['following_responses']],[101,102],'SDK transport did not recover')
                full=[decode(line) for line in bytes.fromhex(row['response_stream_hex']).splitlines()]
                exact(full,row['case_responses']+row['following_responses'],'SDK response projection is not the complete observed stream')
                require(row['typed_sdk_handler_fixture'] is True and row['original_view_body_compared'] is False,
                    'SDK fixture exceeded its reference scope')
            count=SDK_CASES
        results[key]=dict(cases=count,input=pin(wire),output=pin(stdout),executable=executable,binary=pin(binary))
    result=dict(schema='hepta.runtime.span-raw-value.original-comparison.v1',status='PASS',
        source_inputs=sources(root),native_evidence_sha256=sha(compact(native)),references=results,
        actual_fresh_rust_builds=2,actual_rust_replays=2,actual_compiler_version_processes=1,
        native_cases_added_by_replay=0,typed_sdk_handler_fixture=True,**{flag:False for flag in FALSE_FLAGS},
        artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),
        artifacts=[evidence.artifacts[name] for name in sorted(evidence.artifacts)])
    stored=decode(owned(output,FOLDER+'/rust-comparison.json').read_bytes())
    exact(stored,result,'retained span original comparison copy differs')
    return result

def compare_original(root,output,report,rustc,record_check,completed,environment):
    from hia_native_runtime_mcp_original import CLEARED,RUSTC_SHA,CARGO_SHA,RUST_VERSION,tool_path
    root=Path(root).resolve(strict=True);output=Path(output).resolve(strict=True)
    if rustc is None or REFERENCE_KEY in report:return retained_original(root,output,report,completed)
    native=qualification_evidence(root,output,report,completed)
    exact(native,report['runtime_mcp_evidence']['span_raw_value'],'span native evidence changed before fresh reference')
    rustc=Path(rustc);cargo=rustc.with_name('cargo');tool_path(str(rustc),'rustc');tool_path(str(cargo),'cargo')
    exact(sha(rustc.resolve().read_bytes()),RUSTC_SHA,'fresh span Rust compiler bytes differ')
    exact(sha(cargo.resolve().read_bytes()),CARGO_SHA,'fresh span Cargo bytes differ')
    env=dict(environment);removed=[key for key in CLEARED if key in env]
    for key in CLEARED:env.pop(key,None)
    env['RUSTC']=str(rustc)
    state=dict(schema='hepta.runtime.span-raw-value.reference-builds.v1',source_inputs=sources(root),
        native_evidence_sha256=sha(compact(native)),cleared_environment=list(CLEARED),removed_environment=removed,
        rustc=dict(invocation=str(rustc),sha256=RUSTC_SHA),cargo=dict(invocation=str(cargo),sha256=CARGO_SHA),
        execution=dict(runtime_root=str(root),output_root=str(output)),builds={})
    evidence=Evidence(output)
    record_check(output,report,name='span-raw-value-rustc-version',command=[str(rustc),'--version'],env=env,timeout=180)
    _,version,stderr=reference_process(output,report,evidence,'span-raw-value-rustc-version',[str(rustc),'--version'])
    exact(version,RUST_VERSION,'fresh span Rust version differs')
    exact(stderr,b'','fresh span Rust version wrote diagnostics')
    results={}
    for key in ('value','sdk'):
        folder=output/FOLDER/'original'/key;folder.mkdir(parents=True,exist_ok=False)
        materialized={}
        for name,source in reference_files(key).items():
            raw=owned(root,source).read_bytes();path=folder/name;path.parent.mkdir(parents=True,exist_ok=True)
            with path.open('xb') as stream:stream.write(raw)
            materialized[name]=pin(raw);evidence.read(str(path.relative_to(output)))
        command=[str(cargo),'build','--locked','--release','--manifest-path',str(folder/'Cargo.toml'),'--target-dir',str(folder/'target')]
        record_check(output,report,name='span-'+key+'-rust-compile',command=command,env=env,timeout=180)
        check,_,_=reference_process(output,report,evidence,'span-'+key+'-rust-compile',command)
        binary=folder/'target/release'/('hia-serde-json-reference' if key=='value' else 'hepta-workdir-original-oracle')
        executable=str(binary.relative_to(output));raw=evidence.read(executable)
        state['builds'][key]=dict(sources=materialized,executable=executable,binary=pin(raw),
            compile_stdout_sha256=check['stdout_sha256'],compile_stderr_sha256=check['stderr_sha256'])
        name='span-'+key+'-rust-replay';input_name='requests.hex' if key=='value' else 'sdk-requests.hex'
        wire=evidence.read(FOLDER+'/'+input_name)
        record_check(output,report,name=name,command=[str(binary)],input_bytes=wire,env=env,timeout=180)
        check,stdout,stderr=reference_process(output,report,evidence,name,[str(binary)])
        check.update(stdin_bytes=len(wire),stdin_sha256=sha(wire));exact(stderr,b'','span reference replay diagnostics')
        if key=='value':exact(stdout,evidence.read(FOLDER+'/native-output.txt'),'actual wide serde bytes differ')
        else:exact(pin(stdout),SDK_OUTPUT_IDENTITY,'actual current typed SDK bytes differ')
        results[key]=dict(cases=LEAF_CASES if key=='value' else SDK_CASES,input=pin(wire),output=pin(stdout),
            executable=executable,binary=pin(raw))
    exact(sources(root),state['source_inputs'],'span source changed while original references ran')
    exact(qualification_evidence(root,output,report,completed),native,'span native evidence changed while references ran')
    report[REFERENCE_KEY]=state
    result=dict(schema='hepta.runtime.span-raw-value.original-comparison.v1',status='PASS',
        source_inputs=sources(root),native_evidence_sha256=sha(compact(native)),references=results,
        actual_fresh_rust_builds=2,actual_rust_replays=2,actual_compiler_version_processes=1,
        native_cases_added_by_replay=0,typed_sdk_handler_fixture=True,**{flag:False for flag in FALSE_FLAGS},
        artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),
        artifacts=[evidence.artifacts[name] for name in sorted(evidence.artifacts)])
    with (output/FOLDER/'rust-comparison.json').open('xb') as stream:stream.write(compact(result)+b'\n')
    return retained_original(root,output,report,completed)
