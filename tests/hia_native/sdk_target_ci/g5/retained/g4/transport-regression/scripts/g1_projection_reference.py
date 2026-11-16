#!/usr/bin/env python3
"""Native G1 normal model projection against actual target SDK observations."""
from pathlib import Path
import argparse,collections,hashlib,json,struct,sys,time,traceback
ROOT=Path(__file__).resolve().parents[1]
sha=lambda raw:hashlib.sha256(raw).hexdigest()
U=lambda raw,at:struct.unpack_from('<Q',raw,at)[0]
VARIANTS={name:i+1 for i,name in enumerate(['PingRequest','InitializeRequest','DiscoverRequest',
    'CompleteRequest','SetLevelRequest','GetPromptRequest','ListPromptsRequest','ListResourcesRequest',
    'ListResourceTemplatesRequest','ReadResourceRequest','SubscriptionsListenRequest','SubscribeRequest',
    'UnsubscribeRequest','CallToolRequest','ListToolsRequest','GetTaskRequest','UpdateTaskRequest','CancelTaskRequest','CustomRequest'])}
VARIANTS.update(ListSkillsRequest=20,GetSkillRequest=21,ReadResourceDirectoryRequest=22)
VARIANTS.update({name:i+101 for i,name in enumerate(['CancelledNotification','ProgressNotification',
    'InitializedNotification','RootsListChangedNotification','CustomNotification'])})

def pair(raw,index):
    at,size=struct.unpack_from('<QQ',raw,64+index*16)
    if at==0:
        assert size==0
        return None
    assert 256<=at<=at+size<=len(raw)
    return raw[at:at+size]

def compare(case,raw,reference,projection):
    assert projection[:8]==b'HRCJR001' and len(projection)>=256
    expected={'request':1,'notification':2,'response':3,'error':4}[reference['kind']]
    assert U(projection,8)==expected,('disposition',U(projection,8),expected)
    parts=[pair(projection,i) for i in range(10)]
    original=json.loads(raw)
    if reference['kind'] in ['request','notification']:
        assert U(projection,16)==VARIANTS[reference['variant']],('variant',U(projection,16),reference['variant'])
        assert parts[0].decode()==reference['message']['method']
        assert parts[2]==reference['meta_wire'].encode(),('metadata bytes',parts[2],reference['meta_wire'])
        if reference['kind']=='request':
            missing=reference['missing']
            flags=int('io.modelcontextprotocol/protocolVersion' in missing)|(int('io.modelcontextprotocol/clientCapabilities' in missing)<<1)
            assert U(projection,24)==flags
        if 'params' in reference['message']:
            assert parts[7] is not None
            assert json.loads(parts[7])==reference['message']['params'],('typed params',parts[7],reference['message'])
            if reference['variant'] not in ['CustomRequest','CustomNotification']:
                expected_params=reference['message_wire'].split(',"params":',1)[1][:-1].encode()
                assert parts[7]==expected_params,('typed param bytes',parts[7],expected_params)
        else:
            assert parts[7] is None or json.loads(parts[7]) in [{},None]
        params=original.get('params') or {}
        assert U(projection,32)==int(isinstance(params.get('_meta'),dict))
        version=reference['meta'].get('io.modelcontextprotocol/protocolVersion')
        if isinstance(version,str):assert parts[3]==version.encode()
        else:assert parts[3] is None
    else:
        assert parts[9]==raw,'complete original peer response/error bytes'
        if reference['kind']=='error':
            assert parts[7]==reference['error_wire'].encode(),('error bytes',parts[7],reference['error_wire'])
        else:
            assert json.loads(parts[7])==original['result'],'raw Value result projection'
    identifier=reference.get('id')
    if reference['kind']=='notification' or identifier is None:
        assert U(projection,40)==0
        assert parts[1] is None
    else:
        assert parts[1]==reference['id_wire'].encode(),('canonical ID bytes',parts[1],reference['id_wire'])
        if isinstance(identifier,str):
            assert U(projection,40)==2
        else:
            assert type(identifier) is int
            assert U(projection,40)==1
            assert struct.unpack_from('<q',projection,48)[0]==identifier

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-name',default='normal-v1')
    args=parser.parse_args()
    assert args.run_name.replace('-','').isalnum()
    out=ROOT/'evidence'/args.run_name
    out.mkdir()
    counts={'cases':0,'native_calls':0,'canonical_id_checks':0,'typed_parameter_byte_checks':0,'raw_peer_records':0}
    summary={'schema':'hepta.g1.target-normal-qualification.v1','status':'RUNNING','counts':counts,
        'target_sdk':'rmcp 3.9.0','normal_domain_only':True,'actual_target_oracle':True,
        'historical_pass_reused':False,'G1_full_codec_qualified':False,'G2_qualified_by_this_suite':False,
        'G3_async_transport_qualified':False,'G4_cache_handlers_qualified':False,
        'client_result_typed_normalization_qualified':False,'production_activated':False,
        'old_path_removed':False,'full_target_qualified':False,'fresh_cold_qualified':False,
        'qualifier_sha256':sha(Path(__file__).read_bytes())}
    started=time.monotonic()
    def save():(out/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    save()
    try:
        case_raw=(ROOT/'cases/normal.jsonl').read_bytes()
        ref_raw=(ROOT/'evidence/oracle-normal.jsonl').read_bytes()
        manifest=json.loads((ROOT/'cases/manifest.json').read_bytes())
        assert sha(case_raw)==manifest['sha256']
        build=json.loads((ROOT/'evidence/oracle-build.json').read_bytes())
        assert build['actual_target_sdk_executed'] and build['cases_sha256']==sha(case_raw)
        assert build['observations_sha256']==sha(ref_raw)
        assert json.loads((ROOT/'evidence/target-lock-subset.json').read_bytes())['all_retained_exactly_match_target']
        module=json.loads((ROOT/'evidence/hia-modules.json').read_bytes())['members']['message']
        path=ROOT/module['path']
        assert sha(path.read_bytes())==module['sha256']
        assert module['source_sha256']==sha((ROOT/'native/sdk_message.hepta').read_bytes())
        sys.path.insert(0,str(ROOT/'scripts'))
        from hia_native_loader import NativeModule
        cases=[json.loads(line) for line in case_raw.splitlines()]
        references=[json.loads(line) for line in ref_raw.splitlines()]
        variants=collections.Counter()
        kinds=collections.Counter()
        with NativeModule(path,manifest_sha256=module['sha256']) as component:
            with component.session(output_capacity=1<<20,workspace_capacity=2<<20) as decoder:
                with (out/'native-events.jsonl').open('w') as events:
                    for case,reference in zip(cases,references,strict=True):
                        assert case['label']==reference['label'] and reference['accepted']
                        raw=case['wire'].encode()
                        projection=decoder(b'HRCJQ001'+struct.pack('<QQ',1,len(raw))+raw)
                        counts['native_calls']+=1
                        events.write(json.dumps({'label':case['label'],'projection_hex':projection.hex()},sort_keys=True,separators=(',',':'))+'\n')
                        events.flush()
                        try:compare(case,raw,reference,projection)
                        except BaseException as error:
                            raise AssertionError(case['label'],str(error)) from error
                        counts['cases']+=1
                        kinds[reference['kind']]+=1
                        if 'variant' in reference:variants[reference['variant']]+=1
                        if reference.get('id') is not None:counts['canonical_id_checks']+=1
                        if reference['kind'] in ['response','error']:counts['raw_peer_records']+=1
                        if reference.get('variant') not in [None,'CustomRequest','CustomNotification'] and 'params' in reference.get('message',{}):counts['typed_parameter_byte_checks']+=1
        assert counts['cases']==manifest['cases']
        assert set(variants)==set(VARIANTS),(sorted(set(VARIANTS)-set(variants)))
        summary.update(status='PASS',cases_sha256=sha(case_raw),oracle_sha256=sha(ref_raw),
            native_events_sha256=sha((out/'native-events.jsonl').read_bytes()),
            source_overlay_sha256=sha((ROOT/'source_overlay.json').read_bytes()),
            module=module,kinds=dict(kinds),variants=dict(variants),
            matched_boundaries=['ordinary four top-level message shapes','precise integral floating NumberOrString IDs and tokens',
                'canonical signed ID header and JSON bytes','22 request variants including stable CustomRequest 19',
                'five notification variants','typed normal parameter and metadata bytes','complete raw peer-message preservation'])
    except BaseException:
        summary.update(status='FAIL',failure=traceback.format_exc())
        raise
    finally:
        summary['elapsed_seconds']=time.monotonic()-started
        save()
    print(json.dumps(summary,sort_keys=True))

if __name__=='__main__':main()
