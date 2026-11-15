"""Compare public native captures with the shared, freshly executed Rust oracle.

The caller must first admit view_call_original's nine real process receipts,
current extracted source, locked dependencies and binaries. This reader starts
no process. SDK fixture bodies and the empty list-tools fixture are explicitly
projected; only the ordinary-file and wide-error bodies are compared in full.
"""
from __future__ import annotations
import io
from pathlib import Path

from hia_native_runtime_mcp_evidence import (
    Evidence, VIEW_IDS, TYPED_ERRORS, META_ERRORS, compact, content, decode,
    exact, generators, inspect_corpus, require, sha,
)


def referenced(evidence, original, result, filename, descriptor):
    raw=evidence.read(str((original/filename).relative_to(evidence.output)))
    exact(dict(bytes=len(raw),sha256=sha(raw)),descriptor,'original complete retained stream differs: '+filename)
    return raw


def compare_reference(root: Path, native_corpus: Path, original_output: Path) -> dict:
    root=root.resolve(); native_corpus=native_corpus.resolve(); original_output=original_output.resolve()
    require(native_corpus.parent==original_output.parent,'public and original corpus must share the admitted output root')
    evidence=Evidence(native_corpus.parent)
    native=inspect_corpus(root,native_corpus,evidence)
    relative=str(original_output.relative_to(evidence.output))
    result=evidence.object(relative+'/result.json')
    require(result.get('schema')=='hepta.runtime.view-call-original-reference.v1'
            and result.get('status') in {'REFERENCE_READY','PASS'}
            and result.get('harness_unchanged') is True
            and result.get('whole_view_migrated') is False and result.get('whole_runtime_replaced') is False,
            'shared original result contract differs')
    receipts=decode(evidence.read(relative+'/process-receipts.json'))
    exact(receipts,result['processes'],'original process receipt copy differs')
    exact([row['name'] for row in receipts],['rust-version','build','original','sdk','parameter','wide','router','public-schema','info'],
          'shared original process inventory differs')
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
    for row in native['rows']['info']:
        for reply in native['sessions'][row['session']]['replies']:
            if 'result' not in reply or 'tools' not in reply['result']:continue
            tools=reply['result']['tools'];exact([tool['name'] for tool in tools],['host_list','effective_config','execution_shadow_admit','view'],'limited public catalog differs')
            exact(tools[-1]['inputSchema'],schema,'actual tools/list did not publish original cleaned schema');advertised+=1
    counts['schema']=dict(raw_bytes=len(raw_schema),raw_sha256=sha(raw_schema),public_bytes=len(published_schema),
                          public_sha256=sha(published_schema),actual_native_tools_list_responses=advertised,
                          original_schema_and_two_cleanup_functions_executed=True,
                          full_original_125_tool_catalog_compared=False,advertisement_used_as_parameter_admission=False)

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
    return dict(schema='hepta.runtime.mcp-view-original-comparison.v1',status='PASS',counts=counts,
                shared_original_processes=9,new_original_processes=0,new_native_calls=0,
                native_processes=109,native_responses=222,all_native_responses_compared_as_complete_original_server_replies=False,
                added_regex_controls_compared_to_original_view=False,
                whole_view_replaced=False,whole_runtime_replaced=False,complete_sdk_frontend=False,
                full_original_tool_catalog_compared=False,response_storage_globally_unbounded=False,
                artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),
                artifacts=[evidence.artifacts[key] for key in sorted(evidence.artifacts)])
