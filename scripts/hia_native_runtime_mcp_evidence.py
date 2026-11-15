"""Admit actual wide public MCP streams, HIA compiler/linker/packer bytes.

This reader runs no native or Rust process. Recorded absolute execution paths
remain unchanged; artifacts are read only under the supplied source/output
roots. Full original-method comparisons are a separate reference consumer.
"""
from __future__ import annotations
import gzip,hashlib,importlib.util,io,json,math,os,re,stat,struct,sys
from pathlib import Path
from hia_native_build import HEPTA_COMMIT,HEPTA_TREE,BUFFER_PROFILES,json_bytes
from hia_native_runtime_mcp_build import MEMBERS,BASE,BOUNDARIES,TRANSPORT,EXTRA,VIEW,CONFIG,CONFIG_SYMBOLS,FALSE_FLAGS,adapter_source,source_check
FOLDER='runtime-mcp'
NATIVE_SUITE='test_runtime_mcp.py'
EVIDENCE_SUITE='test_runtime_mcp_evidence.py'
NATIVE_GROUPS=10
EVIDENCE_GROUPS=5
SOURCE_MANIFEST_SHA256='c615a9254139b2f012074d2a0f1629ec7c08a640b8af12a1bc1a13b79caecefb'
LINKER_SOURCE_SHA256='66063b0e8d9b244a8ccec27a31554fe8e77f309ac1fc981286e63befa7559cef'
COMPILER_SHA256='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
EVIDENCE_CONTROLS=57
COUNTS=dict(actual_elf_processes=152,actual_elf_responses=572,actual_embedded_hia_images=46,
    actual_policy_and_shared_config_controls=7,actual_public_ordinary_view_cases=31,
    large_error_body_bytes=19000091,large_error_publication_cases=1,observable_session_latch_controls=3,
    over64_body_bytes=67108977,over64_input_bytes=67108978,over64_public_cases=1,over64_response_bytes=67109070,
    public_node_count_controls=1,public_workdir_calls=336,public_workdir_scenarios=42,
    public_workdir_string_errors=152,public_workdir_successes=153,public_workdir_typed_errors=31,
    regex_actual_first_error_controls=2,regex_actual_installed_configs=5,regex_actual_mcp_view_results=5,
    regex_actual_startup_refusals=4,same_session_cache_cases=6,sdk_info_input_cases=13,
    sdk_metadata_error_controls=9,sdk_router_input_cases=54,sdk_typed_protocol_error_controls=19,
    private_frame_refusals=20,actual_private_hia_calls=27,real_child_positive_continuations=1,
    actual_protocol_child_calls=2,exact_needed_protocol_controls=1,delivery_only_controls=1,exact_needed_endpoint_controls=1)
NATIVE_FALSE_FLAGS=('complete_sdk_frontend','complete_original_tool_catalog',
    'directory_content_remote_background_routes_replaced','whole_view_replaced',
    'response_storage_globally_unbounded','full_http_dispatcher_replaced',
    'current_protocol_error_reference_compared','current_original_view_reference_compared')
VIEW_IDS=tuple([*range(19),26,28,29,30,35,36,*range(45,51)])
REGEX_PLANS=[('valid',pattern) for pattern in ['a',r'[a-z]+',r'\p{Greek}+',r')|foo(?:','a{327674}']]
REGEX_PLANS += [('invalid',pattern) for pattern in ['(',r'\w{500}','a{327675}',r'(?-u:\xFF)']]
REGEX_PLANS += [('first-error-late','('),('first-error-early','(')]
sha=lambda raw:hashlib.sha256(raw).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError('runtime MCP evidence: ' + message)

def compact(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def exact(actual, expected, message):
    if isinstance(actual, bytes) or isinstance(expected, bytes):
        require(type(actual) is bytes and type(expected) is bytes and actual == expected, message)
    else:
        strict = lambda value: json.dumps(value, ensure_ascii=True, sort_keys=True,
                                          separators=(',', ':'), allow_nan=False).encode()
        require(strict(actual) == strict(expected), message)


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('runtime MCP evidence: nonfinite JSON number')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)

def owned(root, name):
    require(type(name) is str, 'artifact name is not text')
    relative = Path(name)
    require(not relative.is_absolute() and bool(relative.parts) and '..' not in relative.parts
            and relative.as_posix() == name, 'artifact escaped its owner')
    path = root / relative
    require(path.resolve() == path.absolute() and stat.S_ISREG(path.lstat().st_mode),
            'artifact is not an owned regular file')
    return path

def finite(value, maximum):
    return type(value) in (float, int) and math.isfinite(value) and 0 < value < maximum

class Evidence:
    def __init__(self, output):
        self.output = output
        self.artifact_sha256 = {}
        self.artifacts = {}

    def read(self, name):
        raw = owned(self.output, name).read_bytes()
        self.artifact_sha256[name] = sha(raw)
        self.artifacts[name] = dict(path=name, bytes=len(raw), sha256=sha(raw))
        return raw

    def object(self, name):
        value = decode(self.read(name))
        require(type(value) is dict, 'expected object: ' + name)
        return value

    def rows(self, name):
        raw = self.read(name)
        require(raw.endswith(b'\n'), 'JSONL final newline absent')
        return [decode(row) for row in raw[:-1].split(b'\n')]

    def stream(self, folder, descriptor, expected_path=None):
        exact(sorted(descriptor), ['bytes', 'path', 'sha256'], 'stream descriptor fields differ')
        require(type(descriptor['bytes']) is int and 0 <= descriptor['bytes'] <= sys.maxsize,
                'stream byte length is not a supported integer')
        if expected_path is not None:
            exact(descriptor['path'], expected_path, 'stream path differs from its case')
        packed = self.read(folder + '/' + descriptor['path'])
        with gzip.GzipFile(fileobj=io.BytesIO(packed)) as handle:
            raw = handle.read(descriptor['bytes'] + 1)
            require(len(raw) == descriptor['bytes'] and handle.read(1) == b'', 'complete gzip length differs')
        require(sha(raw) == descriptor['sha256'], 'complete gzip bytes differ')
        return raw

def generators(root):
    result = {}
    for name in ('cases', 'sdk_cases', 'router_sdk_cases', 'info_sdk_cases', 'wide_endpoint_case'):
        path = root / 'tests/hia_native/view_call_oracle' / (name + '.py')
        spec = importlib.util.spec_from_file_location('_runtime_mcp_reader_' + name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result[name] = module
    for name,path in [('span_inputs',root/'tests/hia_native/runtime_mcp_span_inputs.py'),
                      ('workdir_inputs',root/'tests/hia_native/workdir_oracle/cases.py')]:
        spec=importlib.util.spec_from_file_location('_runtime_mcp_reader_'+name,path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);result[name]=module
    return result

def source_identity(root):
    raw=owned(root,'native/runtime_mcp_sources.json').read_bytes()
    require(type(SOURCE_MANIFEST_SHA256) is str and sha(raw)==SOURCE_MANIFEST_SHA256,
            'final source manifest changed or was not frozen')
    proof=decode(raw);exact(sorted(proof),['schema','sources'],'source manifest fields differ')
    exact(proof['schema'],'hepta.runtime.public-source-closure.v2','source manifest schema differs')
    require(type(proof['sources']) is dict and proof['sources'],'source closure absent')
    for name,expected in proof['sources'].items():
        data=owned(root,name).read_bytes()
        exact(dict(bytes=len(data),sha256=sha(data)),expected,'source changed: '+name)
    binding=source_check(root)
    exact(binding,dict(manifest_sha256=sha(raw),files=proof['sources']),'builder source closure differs')
    return binding

def native_header(report,binding):
    exact(report.get('schema'),'hepta.runtime.mcp-view-native-tests.v2','native schema differs')
    exact(report.get('status'),'PASS','native suite did not pass')
    exact(report.get('groups'),NATIVE_GROUPS,'native group count differs')
    exact(report.get('counts'),COUNTS,'native count inventory differs')
    require(finite(report.get('elapsed_seconds'),180),'native elapsed differs')
    exact(report.get('source_binding'),binding,'executed source closure differs')
    require(report.get('sources_unchanged') is True,'native source changed')
    for flag in NATIVE_FALSE_FLAGS:require(report.get(flag) is False,'unqualified native claim: '+flag)
    exact(report.get('implemented_catalog_names'),['host_list','effective_config','execution_shadow_admit','view','workdir'],
          'implemented tool inventory differs')
    exact(report.get('original_tool_count'),125,'original tool inventory differs')

def execution_origin(report):
    origin=report.get('execution');require(type(origin) is dict,'execution origin absent')
    exact(sorted(origin),['corpus_root','manifest_path','runtime_root'],'execution origin fields differ')
    for value in origin.values():
        require(type(value) is str and Path(value).is_absolute() and '..' not in Path(value).parts
                and str(Path(value))==value,'execution origin is not a canonical absolute path')
    require(Path(origin['corpus_root']).name==FOLDER,'native corpus origin differs')
    return origin

def workdir_inputs(root,origin):
    modules=generators(root);inputs=modules['workdir_inputs'].materialized(Path(origin)/'files/workdir')
    selected=[row for row in inputs['scenarios'] if modules['span_inputs'].workdir_selected(row)]
    require(len(selected)==42,'selected original Workdir input domain differs')
    return dict(scenarios=selected,policies=inputs['policies'])

def session_streams(evidence,folder,report):
    origin=execution_origin(report);exe=str(Path(origin['manifest_path']).parent/'runtime-mcp.elf')
    files=Path(origin['corpus_root'])/'files';workdir=workdir_inputs(evidence.source_root,origin['corpus_root'])
    scenarios={'workdir-'+str(row['scenario_id']):row for row in workdir['scenarios']}
    sessions={}
    for record in report['processes']:
        name=record.get('session')
        require(type(name) is str and re.fullmatch('[a-z0-9-]+',name) and name not in sessions,'session identity differs')
        expected=('session','command','cwd','environment','timeout_seconds','elapsed_seconds','exit_code','timed_out',
                  'failure_cleanup_requested','unconsumed_stdout_bytes','exchanges','stdin','stdout','stderr')
        exact(sorted(record),sorted(expected),'session receipt fields differ')
        cwd=files;config=None
        if name.startswith('ordinary-'):cwd/=name
        elif name=='wide-error':cwd/='wide'
        elif name=='over64':cwd/='over64'
        elif name in {'typed-before-latch','legacy-invalid-whole-cap-fallback','first-empty-cap-consumes-latch'}:cwd/='session-a'
        elif name=='installed-policy':cwd/='allowed';config=files/'runtime-config.json'
        elif name.startswith('regex-'):
            require(name in {'regex-'+str(i) for i in range(len(REGEX_PLANS))},'unknown regex case')
            cwd/=name;config=cwd/'runtime-config.json'
        elif name in scenarios:
            scenario=scenarios[name];cwd=Path(os.fsdecode(bytes.fromhex(scenario['sessions'][0]['root_hex'])))
            if workdir['policies'][scenario['policy_id']] is not None:
                config=files/'workdir'/('policy-'+scenario['policy_id']+'.json')
        else:require(name.startswith('router-') or name.startswith('info-'),'unexpected session')
        exact(record['cwd'],str(cwd),'session did not use the recorded initial process directory')
        exact(record['command'],[exe]+([] if config is None else ['--runtime-config',str(config)]),'session argv differs')
        exact(record['environment'],{'PATH':'','LC_ALL':'C'},'session inherited unexpected environment')
        refused=name.startswith('regex-') and REGEX_PLANS[int(name[6:])][0]!='valid'
        require(type(record['exit_code']) is int and record['exit_code']==(78 if refused else 0)
                and type(record['timeout_seconds']) is int and record['timeout_seconds']==60
                and finite(record['elapsed_seconds'],180) and record['timed_out'] is False
                and record['failure_cleanup_requested'] is False and type(record['unconsumed_stdout_bytes']) is int
                and record['unconsumed_stdout_bytes']==0 and type(record['exchanges']) is int and record['exchanges']>=0,
                'session did not complete under its actual deadline')
        stem=folder+'/sessions/'+name+'/'
        exact(evidence.object(stem+'process.json'),record,'public process copy differs')
        capture={k:v for k,v in record.items() if k!='session'}
        for key in ('stdin','stdout','stderr'):capture[key]={k:v for k,v in record[key].items() if k!='path'}
        exact(evidence.object(stem+'capture-process.json'),capture,'transport process copy differs')
        streams={key:evidence.stream(folder,record[key],'sessions/'+name+'/'+key+'.bin.gz') for key in ('stdin','stdout','stderr')}
        if refused:
            _,_,diagnostic=regex_configuration(origin['corpus_root'],int(name[6:]))
            for key,value in dict(stdin=b'',stdout=b'',stderr=diagnostic).items():
                exact(streams[key],value,'startup refusal full streams differ: '+key)
            exact(record['exchanges'],0,'startup refusal accepted public input');requests=[];replies=[];lines=[]
            require(not (evidence.output/stem/'exchanges.json').exists(),'startup refusal produced an exchange')
        else:
            require(streams['stderr']==b'' and streams['stdin'].endswith(b'\n') and streams['stdout'].endswith(b'\n'),
                    'production wire incomplete or private diagnostics leaked')
            input_lines=streams['stdin'][:-1].split(b'\n');lines=streams['stdout'][:-1].split(b'\n')
            requests=[decode(row) for row in input_lines];replies=[decode(row) for row in lines]
            exchanges=decode(evidence.read(stem+'exchanges.json'))
            require(type(exchanges) is list and len(exchanges)==record['exchanges']==len(requests),'exchange count differs')
            reply_index=0
            for index,(exchange,raw,request) in enumerate(zip(exchanges,input_lines,requests)):
                exact(sorted(exchange),['elapsed_seconds','error','number','request_sha256','requested_bytes','responses','timeout_seconds','written_bytes'],
                      'exchange fields differ')
                require(type(request) is dict,'public request not an object')
                expected=dict(number=index,timeout_seconds=60,requested_bytes=len(raw)+1,written_bytes=len(raw)+1,
                              request_sha256=sha(raw+b'\n'),error=None)
                exact({k:exchange[k] for k in expected},expected,'actual request write or deadline differs')
                require(finite(exchange['elapsed_seconds'],60),'actual request exceeded deadline')
                count=int('id' in request);expected_rows=lines[reply_index:reply_index+count]
                require(len(expected_rows)==count,'actual response missing')
                exact(exchange['responses'],[dict(bytes=len(row),sha256=sha(row)) for row in expected_rows],
                      'complete actual response differs from exchange')
                if count:
                    reply=replies[reply_index]
                    exact(reply.get('jsonrpc'),'2.0','response version differs');exact(reply.get('id'),request['id'],'reply correlation differs')
                    require(('result' in reply)!=('error' in reply),'ambiguous public outcome')
                reply_index+=count
            require(reply_index==len(replies),'extra public response bytes')
        sessions[name]=dict(record=record,streams=streams,requests=requests,replies=replies,reply_lines=lines)
    require(len(sessions)==152 and sum(len(row['replies']) for row in sessions.values())==572,'complete public inventory differs')
    return sessions

def span_public_cases(root,evidence,folder,report,sessions):
    modules=generators(root);span=modules['span_inputs'];case=span.large_view_case()
    row=evidence.object(folder+'/over64-case.json')
    exact(sorted(row),['actual_body','actual_request','actual_response','case_id','original_body_compared',
                      'original_input','session','unrestricted_response_domain_claimed'],'wide public case fields differ')
    exact((row['case_id'],row['session'],row['original_body_compared'],row['unrestricted_response_domain_claimed']),
          (1001,'over64',False,False),'wide case identity/claim differs')
    exact(evidence.stream(folder,row['original_input'],'over64/input.bin.gz'),modules['cases'].encode_cases([case]),
          'over64 independent input bytes differ')
    request=(b'{"jsonrpc":"2.0","id":1001,"method":"tools/call","params":{"name":"view","arguments":{"path":"file","start":"'
             +b'x'*span.LARGE_SIZE+b'"}}}')
    exact(evidence.stream(folder,row['actual_request'],'over64/request.bin.gz'),request,'over64 public input differs')
    nodes=b'{"jsonrpc":"2.0","id":1002,"method":"ping","unknown":['+b'0,'*262145+b'0]}'
    session=sessions['over64']
    exact(session['streams']['stdin'],compact(modules['sdk_cases'].initialization({}))+b'\n'+request+b'\n'+nodes+b'\n',
          'complete over64 session input differs')
    require(len(session['replies'])==3,'over64 session response count differs')
    result,body=content(session['replies'][1]);require(result['isError'] is True,'over64 result is not a String error')
    exact(evidence.stream(folder,row['actual_response'],'over64/response.bin.gz'),session['reply_lines'][1],
          'over64 full response is not actual stdout')
    exact(evidence.stream(folder,row['actual_body'],'over64/body.bin.gz'),body,'over64 full body differs')
    require(len(request)==67108978 and len(body)==67108977 and len(session['reply_lines'][1])==67109070,
            'over64 actual byte extents differ')
    exact(session['replies'][2],dict(jsonrpc='2.0',id=1002,result={}),'node-count public control differs')
    expected_inputs=workdir_inputs(root,report['execution']['corpus_root'])
    exact(gzip.decompress(evidence.read(folder+'/workdir/inputs.json.gz')),compact(expected_inputs),
          'complete Workdir input generator differs')
    rows=evidence.rows(folder+'/workdir-cases.jsonl');require(len(rows)==336,'Workdir public row count differs')
    used=['over64'];at=0;statuses={'success':0,'string-error':0,'protocol-error':0};body_bytes=0
    for scenario in expected_inputs['scenarios']:
        name='workdir-'+str(scenario['scenario_id']);used.append(name);session=sessions[name]
        steps=[step for step in scenario['steps'] if step['action']['kind']=='public']
        messages=scenario['sessions'][0]['initial_messages']+[step['action']['message'] for step in steps]
        exact(session['streams']['stdin'],b''.join(compact(message)+b'\n' for message in messages),
              'Workdir request sequence differs from original scenario')
        initial=sum('id' in message for message in scenario['sessions'][0]['initial_messages'])
        for index,step in enumerate(steps):
            item=rows[at];at+=1;ident=str(step['case_id'])
            exact(sorted(item),['actual_body','actual_response','case_id','name','native_private_state_queried',
                                'original_reply_compared','scenario_id','session','status'],'Workdir case fields differ')
            exact((item['case_id'],item['scenario_id'],item['name'],item['session']),
                  (step['case_id'],scenario['scenario_id'],step['name'],name),'Workdir input identity differs')
            require(item['original_reply_compared'] is False and item['native_private_state_queried'] is False,
                    'native Workdir producer made an original/private-state claim')
            reply=session['replies'][initial+index];wire=session['reply_lines'][initial+index]
            if 'error' in reply:
                exact(reply['error']['code'],-32602,'Workdir typed error code differs')
                require(type(reply['error']['message']) is str,'Workdir protocol error message is not text')
                text=reply['error']['message'].encode();status='protocol-error'
            else:
                tool,text=content(reply);status='string-error' if tool['isError'] else 'success'
            exact(item['status'],status,'Workdir observed result status differs')
            exact(evidence.stream(folder,item['actual_response'],'workdir/'+ident+'.response.bin.gz'),wire,
                  'Workdir complete response is not actual stdout')
            exact(evidence.stream(folder,item['actual_body'],'workdir/'+ident+'.body.bin.gz'),text,
                  'Workdir complete text differs')
            statuses[status]+=1;body_bytes+=len(text)
    exact(statuses,{'success':153,'string-error':152,'protocol-error':31},'Workdir actual outcome inventory differs')
    require(at==len(rows),'unconsumed Workdir observations')
    return dict(over64=row,workdir=rows,used_sessions=used,workdir_body_bytes=body_bytes)

def content(reply):
    result = reply['result']
    require(type(result['isError']) is bool and type(result['content']) is list
            and len(result['content']) == 1, 'tool result shape differs')
    item = result['content'][0]
    exact(sorted(item), ['text', 'type'], 'text content fields differ')
    require(item['type'] == 'text' and type(item['text']) is str, 'text content differs')
    return result, item['text'].encode()

def regex_configuration(origin, index):
    kind,pattern=REGEX_PLANS[index]
    directory=Path(origin)/'files'/('regex-'+str(index))
    action=dict(executable='/echo',allow_extra_args=True,extra_arg_patterns=[pattern])
    value=dict(state_dir=str(directory/'controller-state'),controller_workspace_roots=[str(directory)],
               hosts={'h':dict(ssh_target='private-target',remote_state_dir='/private-state',privileged_actions={'inspect':action})})
    error=b'host `h` privileged action `inspect` has invalid argument regex\n'
    if kind.startswith('first-error-'):
        action['extra_arg_patterns']=['a',pattern]
        value['hosts']['h']['privileged_actions']={'middle':action,'zlast':{'executable':'relative'}}
        error=b'host `h` privileged action `middle` has invalid argument regex\n'
        if kind=='first-error-early':
            value['hosts']['h']['privileged_actions']['afirst']={'executable':'relative'}
            error=b'host `h` has invalid privileged action `afirst`\n'
    initial=compact(value)
    rewritten=None
    if kind=='valid':
        action['extra_arg_patterns']=['(']
        rewritten=compact(value)
    return initial,rewritten,error

def regex_cases(root,evidence,folder,report,sessions):
    rows=decode(evidence.read(folder+'/regex-cases.json'))
    require(type(rows) is list and len(rows)==len(REGEX_PLANS),'regex installation corpus differs')
    modules=generators(root)
    for index,(row,(kind,pattern)) in enumerate(zip(rows,REGEX_PLANS)):
        name='regex-'+str(index)
        exact(sorted(row),['case_id','initial_config','kind','pattern','rewritten_config','session','state_directory_exists_after'],
              'regex case fields differ')
        exact((row['case_id'],row['kind'],row['pattern'],row['session']),(index,kind,pattern,name),'regex case identity differs')
        require(type(row['state_directory_exists_after']) is bool and row['state_directory_exists_after']==(kind=='valid'),
                'regex state admission observation differs')
        initial,rewritten,error=regex_configuration(report['execution']['corpus_root'],index)
        exact(evidence.stream(folder,row['initial_config'],'regex/'+str(index)+'.initial-config.json.gz'),initial,
              'regex startup configuration bytes differ')
        session=sessions[name]
        if kind!='valid':
            require(row['rewritten_config'] is None,'refused regex was installed or rewritten')
            for key,expected in dict(stdin=b'',stdout=b'',stderr=error).items():
                exact(session['streams'][key],expected,'regex complete refusal differs: '+key)
            continue
        exact(evidence.stream(folder,row['rewritten_config'],'regex/'+str(index)+'.rewritten-config.json.gz'),rewritten,
              'post-installation config mutation differs')
        request=lambda ident,tool:dict(jsonrpc='2.0',id=ident,method='tools/call',params=dict(name=tool,arguments={}))
        expected=[modules['sdk_cases'].initialization({}),request(2,'host_list'),request(3,'effective_config'),
                  modules['sdk_cases'].call(4,{'path':'file'}),request(5,'host_list'),request(6,'effective_config')]
        exact(session['streams']['stdin'],b''.join(compact(v)+b'\n' for v in expected),'regex installed request sequence differs')
        replies=session['replies'];require(len(replies)==6,'regex installed replies differ')
        first,text=content(replies[1]);effective,projection=content(replies[2]);view,body=content(replies[3])
        require(not first['isError'] and not effective['isError'] and not view['isError'],'valid regex configuration failed')
        require(b'inspect' in text and b'inspect' not in projection and body.endswith(b'|regex installed'),
                'regex configuration did not reach the actual public view and publisher')
        exact(decode(projection)['hosts'][0]['named_privileged_action_count'],1,'regex redacted projection differs')
        exact(replies[4]['result'],first,'installed host list changed after config-file rewrite')
        exact(replies[5]['result'],effective,'installed redacted config changed after config-file rewrite')
    return rows

def public_cases(root, evidence, folder, report, sessions):
    modules = generators(root)
    all_cases = {row['metadata']['case_id']: row for row in modules['cases'].iter_cases()}
    used = set()
    rows_by_kind = {}
    for kind, generator, count in [('router', modules['router_sdk_cases'].iter_router_sdk_cases, 54),
                                    ('info', modules['info_sdk_cases'].iter_info_sdk_cases, 13)]:
        rows = evidence.rows(folder + '/' + kind + '-cases.jsonl')
        inputs = list(generator())
        require(len(rows) == len(inputs) == count, 'SDK input domain count differs')
        for row, original in zip(rows, inputs):
            ident = original['case_id']; name = kind + '-' + str(ident)
            exact((row['case_id'], row['name'], row['session']), (ident, original['name'], name), 'SDK case identity differs')
            exact(evidence.stream(folder, row['input_case'], kind + '/' + str(ident) + '.input.json.gz'),
                  compact(original), 'SDK input bytes differ')
            actual = decode(evidence.stream(folder, row['responses'], kind + '/' + str(ident) + '.responses.json.gz'))
            session = sessions[name]; used.add(name)
            exact(session['streams']['stdin'], b''.join(compact(m) + b'\n' for m in original['messages']),
                  'SDK case did not send the independent input bytes')
            exact(actual, session['replies'], 'SDK projection is not the actual complete stdout')
            flag = 'original_fixture_body_text_compared' if kind == 'router' else 'full_original_tool_catalog_compared'
            require(row.get(flag) is False, 'SDK fixture projection claimed full handler equivalence')
        rows_by_kind[kind] = rows
    view_rows = evidence.rows(folder + '/view-cases.jsonl')
    exact([row['case_id'] for row in view_rows], list(VIEW_IDS), 'ordinary view domain differs')
    for row in view_rows:
        request = all_cases[row['case_id']]; meta = request['metadata']; ident = str(meta['case_id'])
        exact((row['name'], row['session']), (meta['name'], 'ordinary-' + str(meta['session'])), 'view case identity differs')
        require(row.get('private_hooks_used') is False and meta['context'] is True and not meta['hooks']
                and not meta['cancel_after_render'] and not meta['raw_path'], 'private fixture used as public view')
        exact(evidence.stream(folder, row['original_input'], 'view/' + ident + '.input.bin.gz'),
              modules['cases'].encode_cases([request]), 'ordinary view original input differs')
        session = sessions[row['session']]; used.add(row['session'])
        indexes = [i for i, reply in enumerate(session['replies']) if reply['id'] == meta['case_id'] + 2]
        require(len(indexes) == 1, 'ordinary view response absent or duplicated'); index = indexes[0]
        reply = session['replies'][index]; actual_wire = evidence.stream(folder, row['actual_response'], 'view/' + ident + '.response.bin.gz')
        exact(actual_wire, session['reply_lines'][index], 'retained view response is not actual stdout')
        result, body = content(reply)
        exact(evidence.stream(folder, row['actual_body'], 'view/' + ident + '.body.bin.gz'), body, 'retained view body differs')
        exact(row['is_error'], result['isError'], 'retained error flag differs')
        arguments = dict(path=bytes.fromhex(meta['path_hex']).decode(), **meta['params'])
        expected = modules['sdk_cases'].call(meta['case_id'] + 2, arguments)
        requests = [message for message in session['requests'] if message.get('id') == meta['case_id'] + 2]
        exact(requests, [expected], 'public view arguments differ from original case')
    wide = evidence.object(folder + '/wide-case.json'); generator = modules['wide_endpoint_case']
    exact(wide['case_id'], generator.CASE_ID, 'wide error case differs')
    require(wide.get('original_success_body_limit_applied_to_error') is False
            and wide.get('unrestricted_response_domain_claimed') is False, 'wide error raised an invalid closure claim')
    exact(evidence.stream(folder, wide['original_input'], 'wide/input.bin.gz'), generator.original_input(), 'wide original input differs')
    session = sessions['wide-error']; used.add('wide-error')
    result, body = content(session['replies'][1]); require(result['isError'] is True, 'wide case is not a String error')
    exact(evidence.stream(folder, wide['actual_body'], 'wide/body.bin.gz'), body, 'wide retained text differs')
    exact(evidence.stream(folder, wide['actual_response'], 'wide/response.bin.gz'), session['reply_lines'][1], 'wide publication differs')
    require(len(body) == 19000091, 'wide error body was shortened')
    expected_request = b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"view","arguments":' + generator.arguments() + b'}}'
    exact(session['streams']['stdin'].split(b'\n')[1], expected_request, 'wide public input bytes differ')
    regex=regex_cases(root,evidence,folder,report,sessions)
    used.update('regex-'+str(i) for i in range(len(REGEX_PLANS)))
    span_rows = span_public_cases(root, evidence, folder, report, sessions)
    used.update(span_rows["used_sessions"])
    remaining = set(sessions) - used
    exact(sorted(remaining), ['first-empty-cap-consumes-latch', 'installed-policy', 'legacy-invalid-whole-cap-fallback', 'typed-before-latch'], 'behavioral control sessions differ')
    first = sessions['typed-before-latch']['replies']
    require(first[1]['error']['code'] == -32602 and content(first[2])[1].endswith(b'|second directory'), 'typed error consumed the workdir latch')
    require(content(sessions['legacy-invalid-whole-cap-fallback']['replies'][1])[1].endswith(b'|second directory'), 'bad complete capabilities did not fall back')
    empty = sessions['first-empty-cap-consumes-latch']['replies']
    require(content(empty[1])[1] == content(empty[2])[1] and content(empty[1])[1].endswith(b'|first directory'), 'valid empty capabilities did not consume the first latch')
    policy = sessions['installed-policy']['replies']
    require(content(policy[1])[1].endswith(b'|allowed') and content(policy[1])[0]['isError'] is False, 'allowed path failed')
    for index, expected in [(2,b'outside configured controller workspaces'),(3,b'Octofs background resources are disabled in runtime mode'),(4,b'path must not contain an empty root'),(5,b'outside configured controller workspaces')]:
        result, text = content(policy[index]); require(result['isError'] is True and expected in text, 'installed policy or same authority control differs')
    require(all(content(policy[i])[0]['isError'] is False for i in (6,7)), 'configuration tools stopped using the installed authority')
    return dict(router=rows_by_kind['router'], info=rows_by_kind['info'], view=view_rows, wide=wide,regex=regex,span=span_rows)

def mapped_manifest(build_root, recorded, origin_build_root):
    require(type(recorded) is str, 'member manifest path is not text')
    path = Path(recorded)
    require(path.is_absolute() and path.parent.parent.parent == origin_build_root
            and '..' not in path.parts and len(path.parts) >= 3 and path.parts[-3] == 'modules'
            and path.name == 'manifest.json' and re.fullmatch('[a-z0-9-]+', path.parts[-2]),
            'member manifest is outside a fixed build module')
    return build_root / Path(*path.parts[-3:])

def compilation(evidence, folder, source, image, compiler, dependency,origin_folder=None,compiler_origin=None):
    stem = str(folder.relative_to(evidence.output)) + '/'
    receipt = evidence.object(stem + 'module.receipt.json')
    output = evidence.read(stem + 'module.output.bin')
    built = evidence.object(stem + 'build.json')
    fields = dict(status='returned', abi_status=0, core_u32=len(image), result_u64=len(image),
                  source_unchanged=True, input_bytes=len(source), input_sha256=sha(source),
                  source_sha256=sha(source), artifact_sha256=sha(compiler), image_sha256=sha(compiler),
                  output_sha256=sha(output), forbidden_compiler_modules_loaded=[],
                  produced_bytes=len(image), produced_sha256=sha(image))
    exact({name:receipt.get(name) for name in fields}, fields, 'actual native compiler receipt differs')
    require(output[:len(image)] == image and 0 < len(image) <= 1 << 20, 'native compiler output differs')
    exact(evidence.read(stem+'module.input.bin'), source, 'actual compiler input is not current HIA source')
    exact(evidence.read(stem+'module.image.bin'), image, 'actual compiled image differs')
    exact(built.get('compile_receipt'), receipt, 'compile receipt copy differs')
    exact(built.get('compiler_dependency'), dependency, 'compiler dependency differs')
    require(type(receipt.get('wall_elapsed_ns')) is int and 0<receipt['wall_elapsed_ns']<20_000_000_000
            and type(receipt.get('native_elapsed_ns')) is int and 0<receipt['native_elapsed_ns']<=receipt['wall_elapsed_ns'],
            'native compiler actual time differs')
    require(receipt.get('runner_sha256')==dependency['files'].get('tools/hia_selfhost_child.py'),
            'native compiler child source differs')
    raw=evidence.read(stem+'module.stdout.log');child=decode(raw)
    require(type(child) is dict and child,'native compiler raw stdout absent')
    exact({key:receipt.get(key) for key in child},child,'native compiler stdout projection differs')
    exact(evidence.read(stem+'module.stderr.log'),b'','native compiler emitted a diagnostic')
    request=evidence.object(stem+'module.request.json')
    require(origin_folder is not None and compiler_origin is not None,'native compiler origin binding absent')
    expected=dict(format='flat-x86-64',image=str(compiler_origin),image_sha256=sha(compiler),
        source=str(origin_folder/'module.input.bin'),source_sha256=sha(source),capacity=1<<20,
        workspace_size=1<<20,workspace_fill=0,output=str(origin_folder/'module.output.bin'))
    exact(request,expected,'native compiler complete request differs')
    exact(receipt.get('produced_image'),str(origin_folder/'module.image.bin'),'native compiler publication path differs')

def object_text(obj):
    require(len(obj)>=64 and obj[:16]==b'\x7fELF\x02\x01\x01'+bytes(9),'assembler object identity differs')
    h=struct.unpack_from('<HHIQQQIHHHHHH',obj,16)
    require(h[:5]==(1,62,1,0,0) and h[6:]==(0,64,0,0,64,8,7),'assembler object header differs')
    shoff=h[5];require(shoff+8*64==len(obj),'assembler section table extent differs')
    sections=[struct.unpack_from('<IIQQQQIIQQ',obj,shoff+i*64) for i in range(8)]
    def data(index):
        row=sections[index];require(row[4]+row[5]<=len(obj),'assembler section escaped object')
        return obj[row[4]:row[4]+row[5]]
    names=data(7)
    def cstring(raw,at):
        require(type(at) is int and 0<=at<len(raw),'ELF name offset differs');end=raw.find(b'\0',at)
        require(end>=at,'ELF name incomplete');return raw[at:end].decode('ascii')
    named={cstring(names,row[0]):i for i,row in enumerate(sections) if row[0]}
    exact(sorted(named),['.bss','.data','.note.GNU-stack','.shstrtab','.strtab','.symtab','.text'],
          'assembler has unexpected sections or unresolved relocations')
    ti=named['.text'];text=data(ti)
    require(sections[ti][1:3]==(1,6) and len(text)>0,'assembler text profile differs')
    for index,row in enumerate(sections):
        if index!=ti and row[2]&2:require(row[5]==0,'unexpected allocated object payload')
    sym=sections[named['.symtab']]
    require(sym[1]==2 and sym[6]==named['.strtab'] and sym[9]==24 and sym[5]%24==0,'symbol table shape differs')
    symbol_names=data(sym[6]);symbols={}
    for at in range(sym[4],sym[4]+sym[5],24):
        name,info,other,section,value,size=struct.unpack_from('<IBBHQQ',obj,at)
        if section==ti:
            key=cstring(symbol_names,name);require(key not in symbols and value<=len(text),'duplicate/out-of-range symbol')
            symbols[key]=value
    require('_start' in symbols,'actual assembler entry absent')
    return text,symbols

def link_plan(obj,images):
    text,symbols=object_text(obj);extent=256+len(text);rounded=(extent+4095)&~4095
    prefix=bytearray(rounded);prefix[:16]=b'\x7fELF\x02\x01\x01'+bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH',prefix,16,2,62,1,0x4000e8,64,0,0,64,56,3,0,0,0)
    struct.pack_into('<IIQQQQQQ',prefix,64,1,5,0,0x400000,0x400000,extent,extent,4096)
    struct.pack_into('<IIQQQQQQ',prefix,120,1,6,rounded,0x400000+rounded,0x400000+rounded,0,0,4096)
    struct.pack_into('<IIQQQQQQ',prefix,176,0x6474e551,6,0,0,0,0,0,16)
    prefix[232:256]=bytes.fromhex('31ed4883e4f0e8000000004889c7b83c0000000f050f0b00')
    struct.pack_into('<i',prefix,239,13+symbols['_start']);prefix[256:extent]=text
    order=['owner','execution']
    for slot,name in enumerate(EXTRA):
        if name is not None and slot not in (11,20) and name not in order:order.append(name)
    for name in CONFIG+[row[0] for row in MEMBERS[35:]]:
        if name not in order:order.append(name)
    require(len(order)==len(images)==46 and set(order)==set(images),'physical member graph differs')
    patches=[]
    for symbol,name in zip(CONFIG_SYMBOLS,CONFIG):patches.append((2,256+symbols[symbol+'_call_displacement'],order.index(name)))
    extra_slots=[11,20]+[slot for slot,name in enumerate(EXTRA) if name is not None and slot not in (11,20)]
    for slot in extra_slots:patches.append((1,256+symbols['grow_fixture_images']+slot*8,order.index(EXTRA[slot])))
    for slot,name in enumerate(VIEW):patches.append((1,256+symbols['runtime_grow_view_images']+slot*8,order.index(name)))
    require(len(patches)==56 and len({at for _,at,_ in patches})==56,'fixed image address patch inventory differs')
    for kind,at,index in patches:
        require(256<=at and at+(8 if kind==1 else 4)<=extent and 0<=index<46,'image patch escaped actual prefix')
    raw_images=[images[name] for name in order]
    packed=(b'HIAIMG02'+struct.pack('<4Q',len(prefix),46,len(patches),0)+prefix
            +b''.join(struct.pack('<Q',len(image)) for image in raw_images)
            +b''.join(struct.pack('<3Q',*patch) for patch in patches)+b''.join(raw_images))
    expected=bytearray(prefix);positions=[]
    for image in raw_images:
        expected+=bytes((-len(expected))%16);positions.append(len(expected));expected+=image
    text_end=len(expected);expected+=bytes((-len(expected))%4096)
    for kind,at,index in patches:
        if kind==1:struct.pack_into('<Q',expected,at,0x400000+positions[index])
        else:struct.pack_into('<i',expected,at,positions[index]-at-4)
    struct.pack_into('<QQ',expected,96,text_end,text_end)
    struct.pack_into('<QQQ',expected,128,len(expected),0x400000+len(expected),0x400000+len(expected))
    return dict(prefix=bytes(prefix),input=bytes(packed),elf=bytes(expected),order=order,
                patches=patches,positions=positions,text_end=text_end)

def elf_structure(elf,obj,images):
    plan=link_plan(obj,images);exact(elf,plan['elf'],'complete HIA-produced ELF differs from object and fixed member bytes')
    return dict(bytes=len(elf),sha256=sha(elf),entry=0x4000e8,
        program_headers=['PT_LOAD_RX','PT_LOAD_RW_EMPTY','PT_GNU_STACK_RW'],interpreter=None,libc=False,
        fixed_child_address_patches=56,embedded_images=46,actual_hia_stages=2)

def admitted_module(evidence,build_root,origin_build_root,row,source,compiler,dependency,*,profile,name):
    path=mapped_manifest(build_root,row['manifest'],origin_build_root);stem=str(path.parent.relative_to(evidence.output))+'/'
    raw=evidence.read(str(path.relative_to(evidence.output)));module=decode(raw)
    require(sha(raw)==row['manifest_sha256'],'compiled module manifest changed')
    exact(path.parent.name,name,'compiled module belongs to another invocation')
    for label in ('source','image'):
        require(type(module.get(label)) is str and Path(module[label]).name==module[label],'module artifact is not a basename')
    source_raw=evidence.read(stem+module['source']);image=evidence.read(stem+module['image'])
    exact(source_raw,source,'complete compiler input source differs')
    exact((module.get('schema'),module.get('abi'),module.get('target'),module.get('standalone'),module.get('name')),
          ('hepta.runtime.native-module.v1','hepta.runtime.borrowed-bytes.linux-x86_64.v1','linux-x86_64',None,name),
          'compiled module ABI/profile differs')
    exact((module.get('compiler_commit'),module.get('compiler_sha256'),module.get('buffer_profile','standard')),
          (HEPTA_COMMIT,COMPILER_SHA256,profile),'compiled module compiler/profile differs')
    exact([module.get(k) for k in ('input_capacity','output_capacity','workspace_capacity')],
          list(BUFFER_PROFILES[profile]),'declared image profile differs')
    exact(module.get('qualification'),'development_fixed_point','module overclaimed cold qualification')
    require(sha(source_raw)==module['source_sha256'] and sha(image)==module['image_sha256'],'module complete bytes differ')
    compilation(evidence,path.parent,source_raw,image,compiler,dependency,Path(row['manifest']).parent,
                origin_build_root/'bootstrap/B3.image.bin')
    return module,image

def build_evidence(root,output,report,evidence,capture):
    owner=report.get('modules',{}).get('runtime_mcp')
    require(type(owner) is dict and owner.get('builder')=='runtime_mcp' and owner.get('source')=='native/runtime_mcp.hepta',
            'public module registration differs')
    exact(owner.get('manifest'),'build/runtime_mcp-bundle/runtime-mcp/manifest.json','public build owner differs')
    path=owned(output,owner['manifest']);raw=evidence.read(owner['manifest']);bundle=decode(raw)
    require(sha(raw)==owner.get('sha256')==capture.get('manifest_sha256'),'actual public bundle identity differs')
    folder=path.parent;build_root=folder.parent;stem=str(folder.relative_to(output))+'/'
    origin=execution_origin(capture);origin_manifest=Path(origin['manifest_path']);origin_build_root=origin_manifest.parent.parent
    exact(str(origin_manifest),str(Path(origin['corpus_root']).parent/owner['manifest']),'execution manifest owner differs')
    exact([bundle.get(k) for k in ('source_root','build_root','manifest_path')],
          [origin['runtime_root'],str(origin_build_root),str(origin_manifest)],'build/capture origin differs')
    exact(bundle.get('schema'),'hepta.runtime.mcp-view-build.v2','public build schema differs')
    exact(bundle.get('status'),'PASS','public build failed')
    require(finite(bundle.get('elapsed_seconds'),180),'public build elapsed time differs')
    exact([bundle.get('compiler_commit'),report.get('compiler_commit')],[HEPTA_COMMIT]*2,'pinned compiler commit differs')
    exact([bundle.get('compiler_image_sha256'),report.get('compiler_image_sha256')],[COMPILER_SHA256]*2,'compiler image differs')
    binding=source_identity(root);exact(bundle.get('source_binding'),binding,'built source closure differs')
    bootstrap=evidence.object(str((build_root/'bootstrap/bootstrap.json').relative_to(output)))
    require(bootstrap.get('schema')=='hepta.runtime.native-bootstrap.v1' and bootstrap.get('generation_sha256')==COMPILER_SHA256
            and bootstrap.get('qualification')=='development_fixed_point' and bootstrap.get('matching_source_cold_qualified') is False,
            'actual compiler dependency scope differs')
    dependency=bootstrap['dependency']
    require(dependency.get('commit')==HEPTA_COMMIT and dependency.get('tree')==HEPTA_TREE
            and dependency.get('files',{}).get('examples/hia_bootstrap/elf_static_linker.hepta')==LINKER_SOURCE_SHA256,
            'compiler dependency or linker source pin differs')
    compiler=None
    for generation in ('B1','B2','B3'):
        image=evidence.read(str((build_root/'bootstrap'/(generation+'.image.bin')).relative_to(output)))
        require(sha(image)==COMPILER_SHA256,'compiler fixed-point image changed')
        if compiler is None:compiler=image
        else:exact(image,compiler,'compiler generation bytes differ')
    rows=bundle.get('members');require(type(rows) is list,'actual image inventory absent')
    exact([row.get('name') for row in rows],[r[0] for r in MEMBERS],'fixed image inventory differs')
    images={};original_images={};fresh=0
    for row,(key,source,profile) in zip(rows,MEMBERS):
        exact(sorted(row),['buffer_profile','fresh_compile','image_bytes','image_sha256','manifest','manifest_sha256',
                          'name','source','source_sha256'],'member declaration fields differ')
        require(type(row['fresh_compile']) is bool,'fresh compiler claim is not boolean');fresh+=row['fresh_compile']
        exact((row['source'],row['buffer_profile']),('native/'+source+'.hepta',profile),'member source interface differs')
        source_raw=owned(root,row['source']).read_bytes()
        module,image=admitted_module(evidence,build_root,origin_build_root,row,source_raw,compiler,dependency,
                                     profile=profile,name='runtime-mcp-'+key.replace('_','-'))
        exact((row['source_sha256'],row['image_sha256'],row['image_bytes']),(sha(source_raw),sha(image),len(image)),
              'member declaration differs from complete bytes')
        images[key]=image;original_images[key]=str(Path(row['manifest']).parent/module['image'])
    private=decode(evidence.read(FOLDER+'/private/calls.json'))
    for row in private:
        member=next((item for item in rows if item['name']==row['owner']),None)
        require(member is not None and row['member_manifest_sha256']==member['manifest_sha256'],
                'actual private control used a different compiled child')
    exact(bundle.get('config_table'),CONFIG,'installed configuration table differs')
    exact(bundle.get('extra_table'),EXTRA,'public private child table differs')
    exact(bundle.get('view_table'),VIEW,'actual View child table differs')
    expected_boundaries={name:sha(owned(root,name).read_bytes()) for name in (BASE,TRANSPORT,*BOUNDARIES)}
    exact(bundle.get('boundary_sources'),expected_boundaries,'mechanical boundary source differs')
    combined=evidence.read(stem+'combined.S')
    exact(combined,adapter_source(root).encode(),'actual boundary composition differs')
    require(sha(combined)==bundle.get('assembled_source_sha256'),'assembled source identity differs')
    obj=evidence.read(stem+'bridge.o');require(sha(obj)==bundle.get('object_sha256'),'actual assembler object differs')
    plan=link_plan(obj,images)
    exact(bundle.get('physical_image_members'),plan['order'],'physical/private image mapping differs')
    exact(bundle.get('physical_images'),46,'physical image count differs')
    link=bundle.get('link');packed=bundle.get('pack')
    require(type(link) is dict and type(packed) is dict,'actual two-stage receipts absent')
    link_source_path=mapped_manifest(build_root,link['manifest'],origin_build_root)
    linker_meta=decode(evidence.read(str(link_source_path.relative_to(output))))
    linker_source=evidence.read(str((link_source_path.parent/linker_meta['source']).relative_to(output)))
    require(sha(linker_source)==LINKER_SOURCE_SHA256,'actual upstream linker source differs')
    admitted_module(evidence,build_root,origin_build_root,link,linker_source,compiler,dependency,profile='standard',name='wide-elf-linker')
    admitted_module(evidence,build_root,origin_build_root,packed,owned(root,'native/runtime_mcp_image_packer.hepta').read_bytes(),
                    compiler,dependency,profile='history.v1',name='wide-image-pack')
    require(link.get('fresh_compile') is True and packed.get('fresh_compile') is True,'two HIA build stages were not freshly compiled')
    wire=evidence.read(stem+'link.input.bin')
    exact(wire,b'HIALNK01'+struct.pack('<3Q',1,6,0)+b'_start'+struct.pack('<Q',len(obj))+obj,'actual linker input bytes differ')
    prefix=evidence.read(stem+'linked-prefix.elf');exact(prefix,plan['prefix'],'complete HIA-linked prefix differs')
    exact(evidence.object(stem+'link.receipt.json'),link,'actual linker receipt copy differs')
    require(finite(link.get('elapsed_seconds'),180),'actual linker time differs')
    fields=dict(actual_return=len(prefix),fresh_compile=True,input_bytes=len(wire),input_sha256=sha(wire),
                output_bytes=len(prefix),output_sha256=sha(prefix),output_capacity=8<<20,workspace_capacity=32<<20,
                pinned_linker_source_unchanged=True)
    exact({k:link.get(k) for k in fields},fields,'actual native prefix linker return differs')
    pack_input=evidence.read(stem+'pack.input.bin');exact(pack_input,plan['input'],'all image appends and patches differ')
    elf=evidence.read(stem+'runtime-mcp.elf');exact(elf,plan['elf'],'complete native HIA packed ELF differs')
    exact((bundle.get('elf'),bundle.get('elf_bytes'),bundle.get('elf_sha256')),('runtime-mcp.elf',len(elf),sha(elf)),
          'public ELF declaration differs')
    pack_output=evidence.read(stem+'pack.output.bin')
    exact(pack_output,b'HIAIMR02'+struct.pack('<3Q',0,len(elf),0)+elf,'complete HIA packer output differs')
    workcap=(64+46*8+4095)&~4095;workspace=bytearray(workcap)
    struct.pack_into('<QQ',workspace,8,plan['text_end'],len(elf))
    for index,offset in enumerate(plan['positions']):struct.pack_into('<Q',workspace,64+8*index,offset)
    exact(evidence.read(stem+'pack.workspace.bin'),bytes(workspace),'complete packer private workspace differs')
    exact(evidence.object(stem+'pack.receipt.json'),packed,'actual packer receipt copy differs')
    require(finite(packed.get('elapsed_seconds'),180),'actual packer elapsed differs')
    fields=dict(fresh_compile=True,input_bytes=len(pack_input),input_sha256=sha(pack_input),output_bytes=len(pack_output),
        output_sha256=sha(pack_output),actual_return=32,output_capacity=len(pack_output),workspace_capacity=workcap,
        prefix_text_offset=256,fixed_patches=[list(row) for row in plan['patches']],image_offsets=plan['positions'],
        image_sources=[original_images[name] for name in plan['order']])
    exact({k:packed.get(k) for k in fields},fields,'actual packer invocation differs')
    return finish_build_evidence(root,output,evidence,bundle,capture,stem,elf,obj,images,fresh,owner,raw)

def finish_build_evidence(root,output,evidence,bundle,capture,stem,elf,obj,images,fresh,owner,raw):
    origin=execution_origin(capture);folder=Path(origin['manifest_path']).parent
    commands={'assemble':['as','--64','-o',str(folder/'bridge.o'),str(folder/'combined.S')],
              'relocations':['readelf','-r',str(folder/'bridge.o')],
              'readelf':['readelf','-lW',str(folder/'runtime-mcp.elf')]}
    processes=bundle.get('boundary_processes');require(type(processes) is list,'boundary process inventory absent')
    exact([p.get('name') for p in processes],list(commands),'boundary processes differ')
    for process in processes:
        name=process['name'];timeout=60 if name=='assemble' else 30
        exact(sorted(process),['command','cwd','elapsed_seconds','exit_code','name','stderr','stdout','timed_out','timeout_seconds'],
              'actual boundary receipt fields differ')
        exact(process['command'],commands[name],'actual boundary command differs')
        exact(process['cwd'],origin['runtime_root'],'actual boundary source origin differs')
        require(type(process['exit_code']) is int and process['exit_code']==0 and process['timed_out'] is False
                and type(process['timeout_seconds']) is int and process['timeout_seconds']==timeout
                and finite(process['elapsed_seconds'],timeout),'actual boundary process failed/timed out')
        exact(evidence.object(stem+name+'.process.json'),process,'boundary receipt copy differs')
        streams={}
        for key in ('stdout','stderr'):
            data=evidence.read(stem+name+'.'+key);streams[key]=data
            exact(process[key],dict(bytes=len(data),sha256=sha(data)),'complete boundary stream differs')
            if key=='stderr' or name=='assemble':exact(data,b'','unexpected boundary diagnostics')
        if name=='relocations':exact(streams['stdout'],b'\nThere are no relocations in this file.\n','flat boundary retained unresolved relocations')
        if name=='readelf':
            data=streams['stdout']
            require(b'INTERP' not in data and b'RWE' not in data and data.count(b'GNU_STACK')==1
                    and data.count(b'LOAD')==2 and b'0x4000e8' in data,'actual ELF inspection differs')
    for flag in (*FALSE_FLAGS,'public_configuration_from_stdin','public_private_instance_selectors','runtime_host_semantics'):
        require(bundle.get(flag) is False,'unqualified build claim: '+flag)
    exact({k:bundle.get(k) for k in ('shared_session_slot','shared_installed_config_owner_slot','public_frontend_slot','protocol_slot',
                                   'frontend_transport_fixed_input_limit','frontend_reply_fixed_byte_limit','json_nesting_depth_policy',
                                   'result_publication_grows','semantic_qualification')},
          dict(shared_session_slot=6,shared_installed_config_owner_slot=11,public_frontend_slot=18,protocol_slot=19,
               frontend_transport_fixed_input_limit=None,frontend_reply_fixed_byte_limit=None,json_nesting_depth_policy=128,
               result_publication_grows=True,semantic_qualification='NOT_RUN'),'build slot/profile declaration differs')
    structure=elf_structure(elf,obj,images)
    return dict(manifest=owner['manifest'],manifest_sha256=sha(raw),elf=structure,member_count=46,
        fresh_member_compiles=fresh,all_members_freshly_compiled=fresh==46,fresh_linker_compiles=1,fresh_packer_compiles=1,
        compiler_commit=HEPTA_COMMIT,compiler_image_sha256=COMPILER_SHA256,fresh_cold_qualified=False,
        config_execution_capacity_closed=False,unconstrained_regex_resources_closed=False)

def native_evidence(root:Path,output:Path,report:dict,completed)->dict:
    root=Path(root).resolve(strict=True);output=Path(output).resolve(strict=True)
    sources=source_identity(root);_,summary=completed_suite(root,output,report,completed,NATIVE_SUITE,NATIVE_GROUPS)
    evidence=Evidence(output);capture=inspect_corpus(root,output/FOLDER,evidence)
    exact(summary,{key:value for key,value in capture['report'].items() if key!='processes'},
          'native stdout differs from complete actual report')
    build=build_evidence(root,output,report,evidence,capture['report'])
    for suffix in ('stdout','stderr'):evidence.read(NATIVE_SUITE+'.'+suffix)
    exact(source_identity(root),sources,'source closure changed during complete readback')
    return dict(schema='hepta.runtime.mcp-view-native-evidence.v2',status='PASS',counts=COUNTS,
        source_binding=sources,composition=build,artifact_sha256=dict(sorted(evidence.artifact_sha256.items())),
        artifacts=[evidence.artifacts[name] for name in sorted(evidence.artifacts)],
        original_processes=0,new_native_calls=0,complete_sdk_frontend=False,whole_view_replaced=False,
        whole_runtime_replaced=False,response_storage_globally_unbounded=False,config_execution_capacity_closed=False,
        full_http_dispatcher_replaced=False)

def qualification_evidence(root:Path,output:Path,report:dict,completed)->dict:
    native=native_evidence(root,output,report,completed)
    require(native['composition']['all_members_freshly_compiled'] is True,'formal qualification requires 46 fresh native image compiles')
    check,summary=completed_suite(root,output,report,completed,EVIDENCE_SUITE,EVIDENCE_GROUPS)
    expected=dict(schema='hepta.runtime.mcp-view-evidence-tests.v2',status='PASS',groups=EVIDENCE_GROUPS,
        refusal_controls=EVIDENCE_CONTROLS,failures=0,errors=0,skipped=0,new_native_calls=0,new_original_processes=0,
        whole_view_replaced=False,whole_runtime_replaced=False,source_and_output_relocation=True,
        live_fixture_reads_required=False,native_evidence_sha256=sha(json_bytes(native)),
        reader_sha256=sha(owned(root,'scripts/hia_native_runtime_mcp_evidence.py').read_bytes()),
        test_sha256=sha(owned(root,'tests/hia_native/'+EVIDENCE_SUITE).read_bytes()))
    exact({k:summary.get(k) for k in expected},expected,'physical evidence controls used another baseline')
    controls=summary.get('controls')
    require(type(controls) is list and len(controls)==EVIDENCE_CONTROLS and controls==sorted(set(controls)),
            'physical evidence refusal inventory differs')
    for suffix in ('stdout','stderr'):
        name=EVIDENCE_SUITE+'.'+suffix;raw=owned(output,name).read_bytes();native['artifact_sha256'][name]=sha(raw)
        native['artifacts'].append(dict(path=name,bytes=len(raw),sha256=sha(raw)))
    native['evidence_controls']=dict(groups=EVIDENCE_GROUPS,refusals=EVIDENCE_CONTROLS,controls=controls,
        stdout_sha256=check['stdout_sha256'],stderr_sha256=check['stderr_sha256'])
    from hia_native_span_raw_value_qualification import qualification_evidence as span_evidence
    extension=span_evidence(root,output,report,completed)
    existing={row['path']:row for row in native['artifacts']}
    for row in extension['artifacts']:
        if row['path'] in existing:exact(existing[row['path']],row,'span artifact overlaps with different bytes')
        existing[row['path']]=row
    native['artifact_sha256'].update(extension['artifact_sha256'])
    native['artifacts']=[existing[name] for name in sorted(existing)]
    native['span_raw_value']=extension
    return native

def private_refusals(evidence,folder):
    rows=decode(evidence.read(folder+'/private/calls.json'))
    require(type(rows) is list and len(rows)==27,'private actual call inventory differs')
    expected_summary=dict(actual_native_calls=27,invalid_controls=20,actual_protocol_child_calls=2,
        actual_protocol_output_growth_retries=1,real_child_positive_continuations=1,delivery_only_calls=1,
        exact_needed_output_controls=1,new_original_processes=0,concurrent_scheduler_qualification=False)
    exact(evidence.object(folder+'/private/result.json'),expected_summary,'private qualification scope differs')
    buffers=[]
    for index,row in enumerate(rows):
        exact(sorted(row),['input','kind','member_manifest_sha256','number','output','output_capacity','owner','return_code',
                          'workspace_after','workspace_before','workspace_capacity'],'private call fields differ')
        exact(row['number'],index,'private call sequence differs')
        for key in ('return_code','output_capacity','workspace_capacity'):
            require(type(row[key]) is int and 0<=row[key]<1<<64,'private call integer differs')
        require(row['return_code']<=0xffffffff and re.fullmatch('[0-9a-f]{64}',row['member_manifest_sha256']),
                'private ABI return or member identity differs')
        values={}
        for key,suffix in [('input','input'),('workspace_before','before'),('workspace_after','after'),('output','output')]:
            values[key]=evidence.stream(folder,row[key],'private/'+str(index)+'.'+suffix+'.bin.gz')
        exact(len(values['output']),row['output_capacity'],'private full borrowed output differs')
        exact([len(values[key]) for key in ('workspace_before','workspace_after')],[row['workspace_capacity']]*2,
              'private full workspace differs')
        buffers.append(values)
    word=lambda raw,at:struct.unpack_from('<Q',raw,at)[0]
    pack=lambda *v:struct.pack('<'+'Q'*len(v),*v)
    request=b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
    def check(index,owner,kind,wire,before,capacity,code):
        row=rows[index];value=buffers[index]
        exact((row['owner'],row['kind'],row['output_capacity'],row['return_code']),
              (owner,kind,capacity,code),'private actual operation differs')
        exact(value['input'],wire,'private input bytes differ');exact(value['workspace_before'],before,'private caller state differs')
        return value['output'],value['workspace_after']
    raw,waiting=check(0,'mcp','initial-actual-call',request,bytes(8192),512,0xfffffff0)
    exact(raw,b'\xa5'*512,'initial CALL modified public output')
    require(waiting[:8]==b'HRMCFS02' and waiting[256:264]==b'HRMCFA02' and word(waiting,272)==0
            and word(waiting,280)==0 and word(waiting,264)==1,'initial fixed protocol child binding differs')
    sequence=word(waiting,264)
    for index,offset in enumerate((0,8,16,24,32,40,48,56,64,80,88,104),1):
        before=bytearray(waiting);struct.pack_into('<Q',before,320,sequence)
        struct.pack_into('<Q',before,256+offset,word(before,256+offset)^(1<<63));before=bytes(before)
        out,after=check(index,'mcp','refuse-action-'+str(offset),request,before,512,0xffffffff)
        exact(after,before,'rejected action changed private state');exact(out,b'\xa5'*512,'rejected action changed output')
    for index,size in enumerate((0,1,31,63),13):
        out,after=check(index,'mcp','refuse-short-output',request,bytes(8192),size,0xfffffffe)
        exact(after,bytes(8192),'short output changed state');exact(out,b'\xa5'*size,'short output changed borrow')
    start,length=word(waiting,288),word(waiting,296);wire=waiting[start:start+length]
    exact(wire,b'HRJPRQ02'+pack(0,len(request),0)+request,'actual child input does not bind the public request')
    out,after=check(17,'protocol','actual-protocol-output-growth',wire,bytes(16384),512,0xffffffd0)
    exact(out,b'HGRWS002'+pack(2,6320,0)+b'\xa5'*480,'protocol exact needed capacity differs')
    exact(after,bytes(16384),'protocol growth modified workspace')
    child,child_after=check(18,'protocol','actual-protocol-child',wire,after,6320,192)
    header=bytearray(192);header[:8]=b'HRJPRR02'
    for at,value in ((16,2),(40,3),(48,1),(144,40)):struct.pack_into('<Q',header,at,value)
    exact(child,bytes(header)+b'1'+b'\xa5'*(6320-193),'complete protocol child output differs')
    delivery=bytearray(waiting)
    for at,value in ((320,sequence),(328,0xffffffcd),(352,193)):struct.pack_into('<Q',delivery,at,value)
    out,ready=check(19,'mcp','actual-delivery-only',request,bytes(delivery),512,0xfffffff0)
    exact(out,b'\xa5'*512,'delivery-only yielded public output')
    require(ready[256:264]==b'HRMCFA02' and word(ready,264)==sequence and word(ready,280)==1
            and word(ready,272)==0 and word(ready,312)>=193,'completed child was re-executed instead of delivered')
    ready=bytearray(ready);at=word(ready,304);ready[at:at+193]=child[:193]
    for offset,value in ((320,sequence),(328,192),(352,193)):struct.pack_into('<Q',ready,offset,value)
    out,after=check(20,'mcp','complete-retained-child',request,bytes(ready),512,64)
    expected=b'HRCMFR02'+pack(1,0,36,0,0,1,0)+b'{"jsonrpc":"2.0","id":1,"result":{}}'
    exact(out,expected+b'\xa5'*(512-len(expected)),'retained actual child did not reach the complete public result')
    wire=b'HIAEP002'+pack(2,1,0)+b'x'
    full,after=check(21,'endpoint','complete-wide-endpoint',wire,bytes(4096),256,32)
    diagnostic=b'invalid line value \'x\': pass a line id like "12:a3" (from view output) or an integer line number'
    exact(full,b'HIAEPR02'+pack(0,6,len(diagnostic))+diagnostic+b'\xa5'*(224-len(diagnostic)),
          'wide endpoint complete diagnostic bytes differ')
    out,short_after=check(22,'endpoint','exact-needed-output',wire,bytes(4096),32,0xffffffd0)
    exact(out,b'HGRWS002'+pack(2,32+len(diagnostic),0),'endpoint precise output growth differs')
    exact(short_after,after,'endpoint output growth changed state')
    bads=(wire[:31],b'BADMAGIC'+wire[8:],b'HIAEP002'+pack(2,1,0)+b'\xff',b'HIAEP002'+pack(2,(1<<64)-1,0))
    for index,bad in enumerate(bads,23):
        out,after=check(index,'endpoint','refuse-invalid-endpoint',bad,bytes(4096),256,0xffffffff)
        exact(out,b'\xa5'*256,'invalid endpoint changed output');exact(after,bytes(4096),'invalid endpoint changed state')
    return rows

def inspect_corpus(root,corpus,evidence=None):
    evidence=Evidence(corpus.parent) if evidence is None else evidence;evidence.source_root=root
    folder=str(corpus.relative_to(evidence.output));sources=source_identity(root)
    report=evidence.object(folder+'/result.json');native_header(report,sources)
    sessions=session_streams(evidence,folder,report)
    rows=public_cases(root,evidence,folder,report,sessions);private=private_refusals(evidence,folder)
    return dict(report=report,sessions=sessions,rows=rows,private=private,evidence=evidence)


def completed_suite(root, output, report, completed, name, groups):
    rows = [row for row in report['checks'] if row.get('name') == name]
    require(len(rows) == 1, 'one actual process receipt required: ' + name)
    row = rows[0]
    # Source/output directories may move after capture. The retained source
    # root belongs to the complete native capture, whose exact current source
    # closure is checked here; it is never used for reading a file.
    capture = decode(owned(output, FOLDER + '/result.json').read_bytes())
    native_header(capture, source_identity(root))
    origin = capture.get('execution')
    require(type(origin) is dict, 'native execution origin is missing')
    exact(sorted(origin), ['corpus_root', 'manifest_path', 'runtime_root'],
          'native execution origin fields differ')
    for value in origin.values():
        require(type(value) is str and Path(value).is_absolute()
                and '..' not in Path(value).parts and str(Path(value)) == value,
                'native execution origin is not canonical')
    origin_root = Path(origin['runtime_root'])
    origin_corpus = Path(origin['corpus_root'])
    require(origin_corpus.name == FOLDER, 'native corpus origin differs')
    owner = report.get('modules', {}).get('runtime_mcp')
    require(type(owner) is dict and type(owner.get('manifest')) is str
            and not Path(owner['manifest']).is_absolute()
            and '..' not in Path(owner['manifest']).parts,
            'native manifest owner is not relative')
    exact(origin['manifest_path'], str(origin_corpus.parent / owner['manifest']),
          'native manifest origin differs from the retained build owner')
    exact(row.get('command'), [sys.executable, '-I', '-B', str(origin_root / 'tests/hia_native' / name)],
          'suite command differs from its complete native origin')
    require(type(row.get('exit_code')) is int and row['exit_code'] == 0
            and row.get('timed_out') is False and not row.get('start_error')
            and type(row.get('timeout_seconds')) is int and row['timeout_seconds'] == 180
            and finite(row.get('elapsed_seconds'), 180), 'suite did not complete within 180 seconds')
    streams = {}
    for suffix in ('stdout', 'stderr'):
        streams[suffix] = owned(output, name + '.' + suffix).read_bytes()
        exact(dict(bytes=row.get(suffix + '_bytes'), sha256=row.get(suffix + '_sha256')),
              dict(bytes=len(streams[suffix]), sha256=sha(streams[suffix])), 'suite raw stream differs')
    summary = decode(streams['stdout'])
    exact(summary, row.get('summary'), 'stored suite summary differs')
    observed = completed(output, report, name)
    exact(list(observed), [row, summary], 'completed callback selected different evidence')
    stderr = streams['stderr'].decode()
    require(len(re.findall(r'\.\.\. ok\n', stderr)) == groups and
            re.search(r'\nRan ' + str(groups) + r' tests in [0-9.]+s\n\nOK\n\Z', stderr),
            'not every suite group executed')
    return row, summary
