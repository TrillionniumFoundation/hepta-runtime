"""All nine target configuration states, eight contexts, and three cursors."""
import json
VERSIONS=(None,'2024-11-05','2025-03-26','2025-06-18','2025-11-25','2026-07-27','2026-07-28','2026-08-01')
SUPPORTED=('2024-11-05','2025-03-26','2025-06-18','2025-11-25','2026-07-28')
FLAGS=(0,1,3,5,7,9,11,13,15)
HIA_CATALOG_SHA256='6ec74dddbffeef5270c5eebb0638c87a8f7a540f8f38b8703ef8e471af582393'
HIA_DIGEST_ORIGINAL={'commit':'64fcde73d82ba13e92bf06943432bd11f981be08','path':'original/processes/profile-disabled.stdout','bytes':1236951,'sha256':'c9ff4c9282e406de911119c2287093165d3829c333be43da06ac14f75edf295d'}

def initialization(profile_index):
    request={'jsonrpc':'2.0','id':'catalog-init-'+str(profile_index),'method':'initialize',
        'params':{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'configured-catalog-observer','version':'1'}}}
    return (json.dumps(request,separators=(',',':')).encode()+b'\n',b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')

def unsupported_wire(case):
    assert case['protocol_version'] not in (None,*SUPPORTED)
    response={'jsonrpc':'2.0','id':case['sequence'],'error':{'code':-32022,'message':'Unsupported protocol version',
        'data':{'requested':case['protocol_version'],'supported':list(SUPPORTED)}}}
    return json.dumps(response,separators=(',',':'),ensure_ascii=False).encode()

def rows():
    result=[]
    for profile_index,flags in enumerate(FLAGS):
        for version_index,version in enumerate(VERSIONS):
            for cursor in range(3):
                sequence=len(result)
                request={'jsonrpc':'2.0','id':sequence,'method':'tools/list'}
                params=None if cursor==0 else ({} if cursor==1 else {'cursor':'qualification-cursor-\0-λ'})
                if version is not None:
                    if params is None:params={}
                    params['_meta']={'io.modelcontextprotocol/protocolVersion':version,'io.modelcontextprotocol/clientCapabilities':{}}
                if params is not None:request['params']=params
                wire=json.dumps(request,ensure_ascii=False,separators=(',',':')).encode()+b'\n'
                result.append({'sequence':sequence,'profile_index':profile_index,'flags':flags,'protocol_version':version,
                    'modern':int(version in ('2026-07-28','2026-08-01')),'cursor_case':cursor,
                    'connection_accepts':version is None or version in SUPPORTED,'wire':wire})
    assert len(result)==216
    return result

def domain():
    return {'schema':'hepta.runtime.configured-catalog-public-domain.v1','config_flags':list(FLAGS),
        'protocol_versions':list(VERSIONS),'cursor_variants':3,'public_processes':9,'public_catalog_exchanges':216,
        'public_total_exchanges':234,'public_response_frames':225,'initialize_calls':9,'initialized_notifications':9,
        'current_sdk_supported_versions':list(SUPPORTED),'actual_list_results':162,'unsupported_version_errors':54,
        'unsupported_error_model_source':{'g2_source_sha256':'a3e6353b4d8e98682e6605e711bc19c533d8d524c2eb1b55c788709974a234f2',
            'sdk_model_git_blob':'5a493d45e4a7e95f3ce2a477cb4d7f5180342f6e','sdk_model_sha256':'ac438543401b6b9d60021fc044dcf27b446df9539e837c6fecdf16a670091b9a',
            'fresh_public_original_comparison_pending':True},
        'initialized_peer_version':'2024-11-05','metadata_none_resolves_to_initialized_peer':True,
        'public_request_deadline_seconds':60,'native_domain_deadline_seconds':180,
        'installed_mask':1,'configured_tool_count':10,'unconfigured_tool_count':7,
        'metadata_case_note':'The public None row omits request metadata and uses the initialized legacy peer; the independent 216 original-handler and private 391-case domains retain true None. A metadata-bearing request needs params, so original None and empty params share the same cursor-free wire shape; the original handler ignores its request parameter. Direct RequestContext accepts arbitrary ProtocolVersion strings, while current public G2 rejects the two unsupported versions before the list handler; all original 216 input rows remain present.',
        'no_worker_execution':True,'bellman_advertised':False,'full_public_configuration_qualified':False,
        'rows':[{**{k:v for k,v in row.items() if k!='wire'},'wire_hex':row['wire'].hex()} for row in rows()]}
