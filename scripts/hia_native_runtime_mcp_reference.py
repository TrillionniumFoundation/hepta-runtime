"""Compare public native captures with the shared, freshly executed Rust oracle.

This reader reopens both shared original builds and all 43 supplemental
replays. It starts no process and never reads live filesystem fixtures. SDK
fixture bodies and the empty tools-list fixture retain explicit projections;
ordinary View bodies and actual Workdir replies are compared in full.
"""
from __future__ import annotations
import io
import struct
import sys
from pathlib import Path

from hia_native_runtime_mcp_evidence import (
    Evidence, VIEW_IDS, compact, content, decode,
    exact, generators, inspect_corpus, require, sha,
)

from hia_native_runtime_mcp_original import (CLEARED,view_reference,workdir_reference,pin)
TYPED_ERRORS={0,1,2,3,11,12,13,14,15,16,17,20,200,201,202,203,206,207,208}
META_ERRORS={32,33,34,35,101,103,105,209,210}


def referenced(evidence, original, result, filename, descriptor):
    raw=evidence.read(str((original/filename).relative_to(evidence.output)))
    exact(dict(bytes=len(raw),sha256=sha(raw)),descriptor,'original complete retained stream differs: '+filename)
    return raw


def compare_reference(root: Path, native_corpus: Path, original_output: Path, *,
                      workdir_original_output: Path | None = None,
                      supplemental_output: Path | None = None) -> dict:
    root=root.resolve(); native_corpus=native_corpus.resolve(); original_output=original_output.resolve()
    require(native_corpus.parent==original_output.parent,'public and original corpus must share the admitted output root')
    evidence=Evidence(native_corpus.parent)
    native=inspect_corpus(root,native_corpus,evidence)
    relative=str(original_output.relative_to(evidence.output))
    view_admission=view_reference(root,original_output,evidence)
    result=view_admission['normalized']
    workdir_original_output=(native_corpus.parent/'workdir-original' if workdir_original_output is None
                             else workdir_original_output.resolve())
    supplemental_output=(native_corpus.parent/'runtime-mcp-original' if supplemental_output is None
                         else supplemental_output.resolve())
    require(workdir_original_output.parent==native_corpus.parent and supplemental_output.parent==native_corpus.parent,
            'supplement and shared references must share the admitted output owner')
    workdir_admission=workdir_reference(root,workdir_original_output,evidence)
    modules=generators(root); counts={}
    for name,generator in [('router',modules['router_sdk_cases'].iter_router_sdk_cases),
                            ('info',modules['info_sdk_cases'].iter_info_sdk_cases)]:
        inputs=referenced(evidence,original_output,result,name+'-input.jsonl',result['additional_inputs'][name+'-input.jsonl'])
        expected_inputs=list(generator())
        exact(inputs,b''.join(compact(row)+b'\n' for row in expected_inputs),'complete independent '+name+' input differs')
        raw=referenced(evidence,original_output,result,name+'.stdout',result['additional_outputs'][name+'.stdout'])
        require(raw.endswith(b'\n'),'original SDK output is not complete JSONL')
        original_rows=[decode(line) for line in raw[:-1].split(b'\n')]
        require(len(original_rows)==len(expected_inputs),'original SDK case count differs')
        totals=dict(cases=len(original_rows),responses=0,complete_error_objects=0,
                    complete_initialize_results=0,complete_discover_results=0,
                    projected_initialize_results=0,projected_tool_results=0,projected_list_results=0)
        for original,input_case,native_row in zip(original_rows,expected_inputs,native['rows'][name]):
            ident=input_case['case_id']; exact((original['case_id'],original['name']),(ident,input_case['name']),'original SDK case identity differs')
            actual=native['sessions'][native_row['session']]['replies']; expected=original['responses']
            requests=[message for message in input_case['messages'] if 'id' in message]
            require(len(actual)==len(expected)==len(requests),'original/native SDK response counts differ')
            require(original.get('original_view_body_executed') is False,'fixture SDK reference unexpectedly claimed original view execution')
            if name=='router':
                require(original.get('actual_sdk_parameters_extractor') is True
                        and original.get('actual_sdk_async_method_adapter') is True
                        and original.get('ensure_session_method_executed') is False,
                        'router reference did not execute the actual SDK extraction boundary')
            else:
                require(original.get('actual_original_get_info') is True
                        and original.get('actual_original_cache_hint_predicate') is True
                        and original.get('empty_tool_list_fixture') is True
                        and original.get('original_full_list_tools_executed') is False,
                        'info reference scope differs')
            for request,observed,reference in zip(requests,actual,expected):
                totals['responses']+=1
                if 'error' in reference:
                    exact(observed,reference,'complete SDK protocol error differs')
                    totals['complete_error_objects']+=1
                    continue
                require('result' in observed,'native rejected a reference-admitted SDK request')
                exact({key:observed[key] for key in ('jsonrpc','id')},
                      {key:reference[key] for key in ('jsonrpc','id')},'SDK response envelope differs')
                if name=='router' and request['method']=='initialize':
                    keys=('protocolVersion','serverInfo')
                    exact({key:observed['result'][key] for key in keys},{key:reference['result'][key] for key in keys},
                          'SDK initialization projection differs')
                    totals['projected_initialize_results']+=1
                elif name=='router':
                    require(request['method']=='tools/call','unexpected router fixture method')
                    native_result,_=content(observed); original_result,_=content(reference)
                    # The actual file operation may return a different String
                    # outcome from the fixture body. Only the SDK envelope and
                    # field/type shape are common to these two executions.
                    fields=lambda value:{key:item for key,item in value.items() if key not in ('content','isError')}
                    exact(fields(native_result),fields(original_result),'SDK tool-result metadata projection differs')
                    exact(sorted(native_result),sorted(original_result),'SDK tool-result field inventory differs')
                    totals['projected_tool_results']+=1
                elif request['method']=='tools/list':
                    require(reference['result']['tools']==[],'original list-tools fixture is not empty')
                    fields=lambda value:{key:item for key,item in value.items() if key!='tools'}
                    exact(fields(observed['result']),fields(reference['result']),'original list-tools cache/result metadata differs')
                    totals['projected_list_results']+=1
                else:
                    exact(observed,reference,'complete original get_info/discover result differs')
                    key='complete_initialize_results' if request['method']=='initialize' else 'complete_discover_results'
                    require(request['method'] in {'initialize','server/discover'},'unexpected info reference method')
                    totals[key]+=1
        if name=='router':
            require(totals['cases']==54 and totals['responses']==95 and totals['complete_error_objects']==28,
                    'router comparison domain differs')
            observed_typed=set(); observed_meta=set()
            for original in original_rows:
                last=original['responses'][-1]
                if 'error' not in last:continue
                message=last['error']['message']
                if message.startswith('failed to deserialize parameters: '):observed_typed.add(original['case_id'])
                else:observed_meta.add(original['case_id'])
            exact(sorted(observed_typed),sorted(TYPED_ERRORS),'typed extraction reference domain differs')
            exact(sorted(observed_meta),sorted(META_ERRORS),'metadata precedence reference domain differs')
            totals.update(typed_protocol_errors=19,metadata_protocol_errors=9,
                          fixture_body_text_compared=False,fixture_body_error_boolean_compared=False,
                          initialize_projection_fields=['id','jsonrpc','result.protocolVersion','result.serverInfo'],
                          tool_projection_fields=['id','jsonrpc','result.resultType (when present)','result field inventory','content: one text item','isError: bool type'],
                          original_view_body_executed=False,original_ensure_session_method_executed=False)
        else:
            require(totals['cases']==13 and totals['responses']==22,'info comparison domain differs')
            totals.update(list_projection_excluded_fields=['result.tools'],original_full_list_tools_executed=False,
                          original_get_info_executed=True,original_cache_hint_predicate_executed=True)
        counts[name]=totals

    schema_output=referenced(evidence,original_output,result,'public-schema.stdout',result['additional_outputs']['public-schema.stdout'])
    lines=schema_output.split(b'\n');require(len(lines)==3 and lines[-1]==b'','original schema output framing differs')
    raw_schema,published_schema=(line+b'\n' for line in lines[:2])
    require(len(raw_schema)==2398 and sha(raw_schema)=='a27462bcf7b1274a9eb91b0e3462f6b2feb41e65a98a39182a83b4a16add900b',
            'actual raw ViewParams schema differs')
    require(len(published_schema)==2077 and sha(published_schema)=='5ccee76a373db641f89469860f0b495a84ee53efced81c67bcd1259e611eff27',
            'actual publicly cleaned ViewParams schema differs')
    exact((root/'native/view_input_schema.json').read_bytes(),published_schema,'installed catalog uses a different schema asset')
    schema=decode(published_schema); advertised=0
    workdir_schema=(root/'native/workdir_input_schema.json').read_bytes()
    require(len(workdir_schema)==354 and sha(workdir_schema)=='2da0641cd9d25944e9475d04bccad6a18f1a618cb91d82afb7de62d891c500a4',
            'independently qualified Workdir schema asset differs')
    for row in native['rows']['info']:
        for reply in native['sessions'][row['session']]['replies']:
            if 'result' not in reply or 'tools' not in reply['result']:continue
            tools=reply['result']['tools'];exact([tool['name'] for tool in tools],['host_list','effective_config','execution_shadow_admit','view','workdir'],'limited public catalog differs')
            exact(tools[-2]['inputSchema'],schema,'actual tools/list did not publish original cleaned schema')
            exact(tools[-1]['inputSchema'],decode(workdir_schema),'actual tools/list Workdir schema differs');advertised+=1
    counts['schema']=dict(raw_bytes=len(raw_schema),raw_sha256=sha(raw_schema),public_bytes=len(published_schema),
                          public_sha256=sha(published_schema),actual_native_tools_list_responses=advertised,
                          original_schema_and_two_cleanup_functions_executed=True,
                          full_original_125_tool_catalog_compared=False,advertisement_used_as_parameter_admission=False,
                          workdir_public_schema=pin(workdir_schema),workdir_schema_new_original_processes=0)

    original_input=referenced(evidence,original_output,result,'input.bin',result['independent_input'])
    input_rows=list(modules['cases'].read_records(io.BytesIO(original_input),modules['cases'].INPUT_MAGIC))
    require(len(input_rows)==58,'original ordinary-file input inventory differs')
    inputs_by_id={row['metadata']['case_id']:row for row in input_rows};require(len(inputs_by_id)==58,'duplicate original ordinary-file case')
    original_stdout=referenced(evidence,original_output,result,'original.stdout',result['original_output'])
    outcomes={};seen=set()
    total_rows=0
    for row in modules['cases'].read_records(io.BytesIO(original_stdout),modules['cases'].OUTPUT_MAGIC):
        total_rows+=1;ident=row['metadata']['case_id']
        require(ident not in seen,'duplicate ordinary-file original result');seen.add(ident)
        if ident in VIEW_IDS:outcomes[ident]=row
    require(total_rows==58 and seen==set(range(58)) and set(outcomes)==set(VIEW_IDS),'ordinary original result inventory differs')
    body_bytes=0;successful=0;errors=0
    for row in native['rows']['view']:
        ident=row['case_id']; original=outcomes[ident]; meta=original['metadata']; outcome=meta['outcome']
        require(type(outcome.get('ok')) is bool and not outcome.get('cancelled'), 'selected public reference is not an actual completed view')
        native_input=evidence.stream(str(native_corpus.relative_to(evidence.output)),row['original_input'])
        exact(native_input,modules['cases'].encode_cases([inputs_by_id[ident]]),'native view input differs from actual Rust stdin')
        body=original['blobs'][outcome['blob']];require(len(body)==outcome['bytes'],'original body length differs')
        actual=evidence.stream(str(native_corpus.relative_to(evidence.output)),row['actual_body'])
        exact(actual,body,'complete actual original/native public view body differs, case '+str(ident))
        exact(row['is_error'],not outcome['ok'],'original/native String outcome differs')
        body_bytes+=len(body);successful+=outcome['ok'];errors+=not outcome['ok']
    counts['ordinary_view']=dict(cases=31,case_ids=list(VIEW_IDS),same_session_cache_cases=6,same_session_case_ids=list(range(45,51)),
                                complete_body_bytes=body_bytes,successful=successful,errors=errors,
                                original_actual_filesystem_and_task_context=True,
                                raw_path_cases=0,hook_interleaving_cases=0,cancel_fixture_cases=0,
                                original_outer_server_view_method_executed=False)
    wide_input=referenced(evidence,original_output,result,'wide-input.bin',result['additional_inputs']['wide-input.bin'])
    exact(wide_input,modules['wide_endpoint_case'].original_input(),'wide original stdin differs')
    wide_stdout=referenced(evidence,original_output,result,'wide.stdout',result['additional_outputs']['wide.stdout'])
    rows=list(modules['cases'].read_records(io.BytesIO(wide_stdout),modules['cases'].OUTPUT_MAGIC));require(len(rows)==1,'wide original result inventory differs')
    original=rows[0];meta=original['metadata'];outcome=meta['outcome'];require(meta['case_id']==1000 and outcome['ok'] is False,'wide original outcome differs')
    body=original['blobs'][outcome['blob']];require(len(body)==outcome['bytes']==19000091,'wide original error text was shortened')
    actual=evidence.stream(str(native_corpus.relative_to(evidence.output)),native['rows']['wide']['actual_body'])
    exact(actual,body,'complete wide original error differs from actual published text')
    counts['wide_error']=dict(cases=1,case_id=1000,complete_body_bytes=len(body),complete_body_sha256=sha(body),
                             original_actual_filesystem=True,successful_body_limit_applied=False,
                             original_outer_server_view_method_executed=False)
    counts.update(compare_supplement(root,native_corpus,native,supplemental_output,evidence,
                                     view_admission,workdir_admission))
    return dict(schema='hepta.runtime.mcp-view-original-comparison.v2',status='PASS',counts=counts,
                shared_original_processes=view_admission['processes']+workdir_admission['processes'],
                shared_view_original_processes=view_admission['processes'],shared_workdir_original_processes=workdir_admission['processes'],
                supplemental_actual_original_replays=43,new_original_processes=0,new_native_calls=0,
                native_processes=152,native_responses=572,all_native_responses_compared_as_complete_original_server_replies=False,
                added_regex_controls_compared_to_original_view=False,
                whole_view_replaced=False,whole_runtime_replaced=False,complete_sdk_frontend=False,
                full_original_tool_catalog_compared=False,response_storage_globally_unbounded=False,
                artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),
                artifacts=[evidence.artifacts[key] for key in sorted(evidence.artifacts)])


def workdir_records(raw):
    stream=io.BytesIO(raw);require(stream.read(8)==b'HWDRO001','actual original Workdir framing differs')
    while stream.tell()<len(raw):
        header=stream.read(16);require(len(header)==16,'truncated original Workdir header')
        size,count=struct.unpack('<QQ',header)
        require(size<=len(raw)-stream.tell(),'original Workdir metadata beyond stream')
        metadata=decode(stream.read(size));blobs=[]
        require(type(metadata) is dict and count<=(len(raw)-stream.tell())//8,'original Workdir metadata/count differs')
        for _ in range(count):
            header=stream.read(8);require(len(header)==8,'truncated original Workdir blob length')
            size,=struct.unpack('<Q',header);require(size<=len(raw)-stream.tell(),'original Workdir blob beyond stream')
            blobs.append(stream.read(size))
        yield metadata,blobs
    require(stream.tell()==len(raw),'original Workdir output suffix')


def compare_supplement(root,native_corpus,native,output,evidence,view,workdir):
    from hia_native_runtime_mcp_evidence import finite,workdir_inputs
    relative=str(output.relative_to(evidence.output));folder=str(native_corpus.relative_to(evidence.output))
    report=evidence.object(relative+'/result.json')
    exact(report.get('schema'),'hepta.runtime.mcp-original-supplement.v1','supplement schema differs')
    exact(report.get('status'),'REFERENCE_READY','supplement did not finish actual replays')
    require(finite(report.get('elapsed_seconds'),180),'supplement elapsed exceeds original outer budget')
    expected_sources={name:pin((root/name).read_bytes()) for name in ('scripts/hia_native_runtime_mcp_original.py',
        'tests/hia_native/runtime_mcp_oracle/run.py')}
    exact(report.get('source_pins'),expected_sources,'supplement executing source differs')
    exact(evidence.object(relative+'/source-pins.json'),expected_sources,'supplement source pin copy differs')
    exact(report.get('native_source_binding'),native['report']['source_binding'],'supplement native source owner differs')
    for name,value in {'actual_original_replays':43,'new_rust_builds':0,'new_native_calls':0,
                      'shared_view_processes':view['processes'],'shared_workdir_processes':workdir['processes']}.items():
        exact(report.get(name),value,'supplement real process count differs: '+name)
    for name,value in {'whole_view_handler_original_executed':False,'whole_runtime_original_executed':False,
        'original_workdir_handler_executed':True,'configuration_loader_original_executed':False,
        'full_native_public_comparison_executed':False}.items():
        require(report.get(name) is value,'supplement original domain differs: '+name)
    origin=native['report']['execution'];execution=report.get('execution')
    exact(execution,dict(runtime_root=origin['runtime_root'],output_root=str(Path(origin['corpus_root']).parent/output.name),
                        native_output_root=str(Path(origin['corpus_root']).parent)), 'supplement did not run at the exact native origin')
    actual_output=Path(execution['output_root']);actual_parent=actual_output.parent
    shared=evidence.object(relative+'/shared-originals.json')
    exact(shared,dict(view=view,workdir=workdir,
        view_original_result=pin(evidence.read(str((native_corpus.parent/'view-call-original/result.json').relative_to(evidence.output)))),
        workdir_original_result=pin(evidence.read(str((native_corpus.parent/'workdir-original/result.json').relative_to(evidence.output))))),
        'shared original source/binary admission changed')
    termination=evidence.object(relative+'/native-process-terminal.json')
    exact(termination.get('executable'),str(Path(origin['manifest_path']).parent/'runtime-mcp.elf'),'terminal native executable differs')
    exact(termination.get('matching_pids'),[],'native process remained live during fixture reconstruction')
    require(type(termination.get('readable_executable_links')) is int and termination['readable_executable_links']>0,
            'no actual process inventory observation')
    exact(termination.get('terminal_process_receipts'),152,'native terminal receipt count differs')
    require(termination.get('all_capture_processes_waited') is True,'native processes not waited')
    before=decode(evidence.read(relative+'/fixture-before.json'));after=decode(evidence.read(relative+'/fixture-after.json'))
    exact(after,before,'original fixture complete restoration differs')
    require(before is None or (type(before) is list and len(before)>42),'native fixture inventory missing')
    if before:
        names=set()
        for row in before:
            name=bytes.fromhex(row['name_hex']);require(name not in names and not name.startswith(b'/') and b'..' not in name.split(b'/'),
                'native fixture raw name escaped owner');names.add(name)
            require(type(row.get('inode')) is int and row['inode']>0 and type(row.get('device')) is int,
                    'fixture inode identity absent')
            require(type(row.get('mode')) is int and type(row.get('uid')) is int and type(row.get('gid')) is int,
                    'fixture permissions/owner absent')
            if row['kind']=='file':bytes.fromhex(row['data_hex'])
            elif row['kind']=='symlink':bytes.fromhex(row['target_hex'])
            else:require(row['kind'] in {'directory','fifo'},'unexpected fixture special object')
    journal=evidence.object(relative+'/fixture-journal.json')
    fixture=Path(origin['corpus_root'])/'files/workdir'
    exact(journal.get('fixture'),str(fixture),'fixture restore path escaped native owner')
    exact(journal.get('held'),str(fixture.parent/('workdir-held-'+output.name)),'fixture hold path differs')
    exact(journal.get('original_present'),before is not None,'fixture original presence differs')
    require(journal.get('state')=='RESTORED' and journal.get('temporary_tree_removed') is True
            and journal.get('original_tree_restored') is True,'native fixture was not restored')
    require(type(journal.get('fresh_identity')) is list and len(journal['fresh_identity'])==2
            and all(type(value) is int for value in journal['fresh_identity']),'temporary fixture inode identity absent')
    modules=generators(root);inputs=workdir_inputs(root,origin['corpus_root'])
    for name,value in inputs['policies'].items():
        exact(evidence.read(relative+'/policies/'+name+'.json'),compact(value)+b'\n','original Workdir policy input differs')
    records=decode(evidence.read(relative+'/process-receipts.json'));exact(records,report['processes'],'supplement receipt copy differs')
    require(len(records)==43,'not all original replays retained')
    plans=[('over64',[str(actual_parent/'view-call-original/target/release/hepta-view-call-original-oracle'),str(actual_output/'over64-files')],
            Path(origin['runtime_root']),modules['cases'].encode_cases([modules['span_inputs'].large_view_case()]),
            view['binary_pins']['hepta-view-call-original-oracle'],None)]
    for scenario in inputs['scenarios']:
        cwd=Path(__import__('os').fsdecode(bytes.fromhex(scenario['sessions'][0]['root_hex'])))
        plans.append(('workdir-'+str(scenario['scenario_id']),
            [str(actual_parent/'workdir-original/target/release/hepta-workdir-original-oracle'),str(fixture),str(actual_output/'policies'/(scenario['policy_id']+'.json'))],
            cwd,compact(scenario)+b'\n',workdir['binary_pin'],scenario))
    cases=0;body_bytes=0;statuses=dict(success=0,**{'string-error':0,'protocol-error':0});large=None
    for record,(name,command,cwd,incoming,binary_pin,scenario) in zip(records,plans):
        actual=evidence.object(relative+'/'+name+'/process.json');exact(actual,record,'complete actual replay receipt differs')
        exact(sorted(actual),sorted(['name','command','cwd','timeout_seconds','elapsed_seconds','exit_code','timed_out',
            'start_error','executable','environment','stdin','stdout','stderr']),'replay receipt fields differ')
        exact(actual['name'],name,'actual replay identity differs');exact(actual['command'],command,'actual replay command differs')
        exact(actual['cwd'],str(cwd),'original and native actual cwd differ')
        exact(actual['timeout_seconds'],60,'original replay deadline differs')
        require(type(actual['exit_code']) is int and actual['exit_code']==0 and actual['timed_out'] is False
                and actual['start_error'] is None and finite(actual['elapsed_seconds'],60),'actual replay failed or exceeded deadline')
        exact(actual['executable'],binary_pin,'actual replay executable identity differs')
        exact(actual['environment'],dict(RUSTC=view['rustc'],LC_ALL='C',TZ='UTC',cleared=list(CLEARED)),'actual replay environment differs')
        streams={key:evidence.stream(relative+'/'+name,actual[key],key+'.bin.gz') for key in ('stdin','stdout','stderr')}
        exact(streams['stdin'],incoming,'full actual original replay input differs')
        exact(streams['stderr'],b'','actual original replay wrote stderr')
        if scenario is None:
            values=list(modules['cases'].read_records(io.BytesIO(streams['stdout']),modules['cases'].OUTPUT_MAGIC))
            require(len(values)==1 and values[0]['metadata']['case_id']==1001,'over64 actual original result identity differs')
            outcome=values[0]['metadata']['outcome'];require(outcome['ok'] is False,'over64 original outcome differs')
            body=values[0]['blobs'][outcome['blob']];require(len(body)==outcome['bytes']==67108977,'over64 original complete extent differs')
            exact(evidence.stream(folder,native['rows']['span']['over64']['actual_body']),body,'complete over64 actual original text differs')
            large=dict(cases=1,complete_body=pin(body),actual_original_filesystem=True,
                       original_outer_server_view_method_executed=False,original_sdk_transport_executed=False)
            continue
        original={};all_ids=set()
        for metadata,blobs in workdir_records(streams['stdout']):
            if metadata.get('kind')!='case':continue
            ident=metadata['case_id'];require(type(ident) is int and ident not in all_ids,'duplicate original Workdir step')
            all_ids.add(ident);original[ident]=(metadata,blobs)
        exact(sorted(all_ids),sorted(step['case_id'] for step in scenario['steps']),'actual original Workdir step inventory differs')
        native_session=native['sessions'][name];initial=sum('id' in msg for msg in scenario['sessions'][0]['initial_messages'])
        index=0
        for step in scenario['steps']:
            if step['action']['kind']!='public':continue
            metadata,blobs=original[step['case_id']]
            exact((metadata.get('scenario_id'),metadata.get('name'),metadata.get('domain'),metadata.get('session')),
                  (scenario['scenario_id'],step['name'],step['domain'],step['session']),'actual original Workdir step identity differs')
            exchange=metadata['result']
            require(type(exchange.get('request_blob')) is int and 0<=exchange['request_blob']<len(blobs)
                    and type(exchange.get('response_blob')) is int and 0<=exchange['response_blob']<len(blobs),
                    'actual original Workdir exchange blob index differs')
            request_wire=blobs[exchange['request_blob']]
            require(request_wire.endswith(b'\n'),'actual original SDK request is incomplete')
            # serde_json emits 1e-7 while Python emits 1e-07. The retained
            # complete original wire is hash-bound above; compare its full
            # JSON value with the independently generated input here.
            exact(decode(request_wire),step['action']['message'],'actual original SDK written input differs')
            wire=blobs[exchange['response_blob']];require(wire.endswith(b'\n'),'actual original SDK response is incomplete')
            exact(exchange.get('response_bytes'),len(wire),'actual original SDK response extent differs')
            reference=decode(wire)
            actual=native_session['replies'][initial+index];index+=1
            exact(actual,reference,'complete actual original/native Workdir reply differs: '+str(step['case_id']))
            if 'error' in reference:body=reference['error']['message'].encode();status='protocol-error'
            else:
                tool,body=content(reference);status='string-error' if tool['isError'] else 'success'
            native_row=next(row for row in native['rows']['span']['workdir'] if row['case_id']==step['case_id'])
            exact(evidence.stream(folder,native_row['actual_body']),body,'complete actual Workdir text differs')
            cases+=1;body_bytes+=len(body);statuses[status]+=1
    exact(cases,336,'Workdir original comparison count differs')
    exact(statuses,dict(success=153,**{'string-error':152,'protocol-error':31}),'Workdir comparison status inventory differs')
    return dict(over64_error=large,workdir=dict(scenarios=42,complete_reply_values=cases,complete_text_bytes=body_bytes,
        statuses=statuses,same_real_process_cwd=True,original_sdk_parameters_and_method_adapter=True,
        original_workdir_handler_and_actual_local_io=True,original_configuration_loader=False,
        native_private_state_compared=False,remote_io_executed=False,
        complete_original_stdout_retained=True,native_fixture_full_bytes_permissions_and_inode_restored=True))


def qualification_reference(root: Path, output: Path, report: dict, completed) -> dict:
    """Require the actual four-group original-evidence gate after full comparison.

    The aggregator owns the shared fresh builds and supplemental replay runner.
    This function starts no process and admits the post-reference test receipt
    using the same recorded native source/output origin as the native reader.
    """
    from hia_native_runtime_mcp_evidence import completed_suite,finite
    root=root.resolve();output=output.resolve()
    result=compare_reference(root,output/'runtime-mcp',output/'view-call-original')
    replay_name='runtime-mcp-original-replay'
    rows=[row for row in report['checks'] if row.get('name')==replay_name]
    require(len(rows)==1,'one actual supplementary replay wrapper required')
    replay_receipt=rows[0]
    supplement=decode((output/'runtime-mcp-original/result.json').read_bytes())
    shared=decode((output/'runtime-mcp-original/shared-originals.json').read_bytes())
    execution=supplement['execution'];origin_root=Path(execution['runtime_root'])
    command=[sys.executable,'-I','-B',str(origin_root/'tests/hia_native/runtime_mcp_oracle/run.py'),
        '--runtime-root',str(origin_root),'--native-output',execution['native_output_root'],
        '--view-original',shared['view']['original_execution_root'],
        '--workdir-original',shared['workdir']['original_execution_root'],
        '--output',execution['output_root']]
    exact(replay_receipt.get('command'),command,'actual supplementary wrapper command differs')
    require(type(replay_receipt.get('exit_code')) is int and replay_receipt['exit_code']==0
            and replay_receipt.get('timed_out') is False and not replay_receipt.get('start_error')
            and type(replay_receipt.get('timeout_seconds')) is int and replay_receipt['timeout_seconds']==180
            and finite(replay_receipt.get('elapsed_seconds'),180),'actual supplementary wrapper did not complete within 180 seconds')
    for suffix in ('stdout','stderr'):
        raw=(output/(replay_name+'.'+suffix)).read_bytes()
        exact(dict(bytes=replay_receipt.get(suffix+'_bytes'),sha256=replay_receipt.get(suffix+'_sha256')),
              pin(raw),'supplementary wrapper complete stream differs')
        if suffix=='stderr':exact(raw,b'','supplementary wrapper wrote stderr')
        else:
            summary=decode(raw)
            exact(summary,{key:value for key,value in supplement.items() if key not in ('processes','native_source_binding','source_pins')},
                  'actual supplementary wrapper summary differs from complete captured result')
            exact(replay_receipt.get('summary'),summary,'recorded supplementary wrapper summary differs')
    name='test_runtime_mcp_original_evidence.py'
    receipt,summary=completed_suite(root,output,report,completed,name,4)
    exact(summary.get('schema'),'hepta.runtime.mcp-original-evidence-tests.v1','original evidence suite schema differs')
    exact(summary.get('status'),'PASS','original evidence suite did not pass')
    exact(summary.get('groups'),4,'original evidence group count differs')
    require(finite(summary.get('elapsed_seconds'),180),'original evidence suite elapsed differs')
    counts=summary.get('counts');require(type(counts) is dict,'original evidence counts absent')
    exact(sorted(counts),sorted({'groups','physical_refusals','two_new_roots_positive','no_live_fixture_copied',
        'new_rust_processes','new_native_processes','portable_artifacts','portable_source_files'}),
        'original evidence count fields differ')
    for key,expected in {'groups':4,'physical_refusals':12,'two_new_roots_positive':1,
                         'new_rust_processes':0,'new_native_processes':0}.items():
        exact(counts[key],expected,'original evidence count differs: '+key)
    require(counts['no_live_fixture_copied'] is True,'positive relocation copied live fixtures')
    require(type(counts['portable_artifacts']) is int and counts['portable_artifacts']>=len(result['artifacts'])
            and type(counts['portable_source_files']) is int and counts['portable_source_files']>79,
            'original relocation did not retain complete source/artifact closure')
    artifacts={row['path']:row for row in result['artifacts']}
    for process_name in (name,replay_name):
        for suffix in ('stdout','stderr'):
            path=process_name+'.'+suffix;raw=(output/path).read_bytes()
            artifacts[path]=dict(path=path,bytes=len(raw),sha256=sha(raw))
    result['original_replay_wrapper']=replay_receipt
    result['original_evidence_tests']=dict(groups=4,physical_refusals=12,two_new_roots_positive=1,
        no_live_fixture_copied=True,actual_process_receipt=receipt,
        test_source_sha256=sha((root/'tests/hia_native'/name).read_bytes()),
        reader_source_sha256=sha((root/'scripts/hia_native_runtime_mcp_reference.py').read_bytes()))
    result['artifact_sha256']={name:row['sha256'] for name,row in sorted(artifacts.items())}
    result['artifacts']=[row for _,row in sorted(artifacts.items())]
    return result
