"""Actual dynamic MCP/View/Workdir ELF, retaining complete public wire bytes.

SDK fixtures provide inputs only. The separate original-reference reader
compares complete original protocol errors/headers and selected view text.
"""
from __future__ import annotations
import argparse, collections, ctypes, gzip, hashlib, importlib.util, json
import mmap, os, select, struct, subprocess, sys, time, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_loader import NativeModule, NativeRejected
MANIFEST=OUTPUT=None
COUNTS=collections.Counter(); RECORDS=[]
sha=lambda raw:hashlib.sha256(raw).hexdigest()
def compact(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def sibling(name):
    path=ROOT/'tests/hia_native/view_call_oracle'/(name+'.py')
    spec=importlib.util.spec_from_file_location('_runtime_mcp_inputs_'+name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
cases,sdk,router,info,wide=(sibling(name) for name in ('cases','sdk_cases','router_sdk_cases','info_sdk_cases','wide_endpoint_case'))
def local_module(name,path=None):
    path=ROOT/'tests/hia_native'/(name+'.py') if path is None else path
    spec=importlib.util.spec_from_file_location('_public_span_'+name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
public_capture=local_module('runtime_mcp_public_capture')
span_controls=local_module('runtime_mcp_span_controls')
span_inputs=local_module('runtime_mcp_span_inputs')
workdir_cases=local_module('workdir_inputs',ROOT/'tests/hia_native/workdir_oracle/cases.py')

VIEW_IDS=tuple([*range(19),26,28,29,30,35,36,*range(45,51)])
TYPED_ERRORS={0,1,2,3,11,12,13,14,15,16,17,20,200,201,202,203,206,207,208}
META_ERRORS={32,33,34,35,101,103,105,209,210}
CAPS='io.modelcontextprotocol/clientCapabilities';VERSION='io.modelcontextprotocol/protocolVersion'
def save(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(gzip.compress(raw,mtime=0))
    return dict(path=str(path.relative_to(OUTPUT)),bytes=len(raw),sha256=sha(raw))
def source_identity():
    from hia_native_runtime_mcp_build import source_check
    return source_check(ROOT)

def setup_files(folder,row):
    for action in row['metadata']['setup']:
        path=folder/os.fsdecode(bytes.fromhex(action['path_hex']));path.parent.mkdir(parents=True,exist_ok=True)
        if action['kind']=='write':path.write_bytes(row['blobs'][action['blob']])
        elif action['kind']=='symlink':path.symlink_to(os.fsdecode(bytes.fromhex(action['target_hex'])))
        elif action['kind']=='hardlink':os.link(folder/os.fsdecode(bytes.fromhex(action['target_hex'])),path)
        else:raise AssertionError('selected public case has an unsupported setup action')

class Session:
    def __init__(self,name,root,*,config=None,expected_exit=0,expected_stderr=b''):
        self.name=name;self.folder=OUTPUT/'sessions'/name;self.closed=False
        self.client=public_capture.Public(self.folder,NativeRuntime.exe,root,config,
            expected_exit=expected_exit,expected_stderr=expected_stderr)
    def send(self,wire):
        self.client.exchange(wire+b'\n',0)
    def call(self,value):
        wire=value if isinstance(value,bytes) else compact(value)
        rows=self.client.exchange(wire+b'\n');COUNTS['actual_elf_responses']+=len(rows)
        return json.loads(rows[0]),rows[0]
    def ready(self,capabilities=None):return self.call(sdk.initialization({} if capabilities is None else capabilities))
    def finish(self,error=False):
        if self.closed:return
        self.closed=True;raw=self.client.close(error)
        record=dict(session=self.name,**raw)
        for key in ('stdin','stdout','stderr'):
            record[key]={**record[key],'path':str((self.folder/(key+'.bin.gz')).relative_to(OUTPUT))}
        (self.folder/'process.json').write_bytes(json.dumps(record,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()+b'\n')
        RECORDS.append(record);COUNTS['actual_elf_processes']+=1
    def __enter__(self):return self
    def __exit__(self,kind,value,traceback):self.finish(error=kind is not None)




class NativeRuntime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hia_native_runtime_mcp_build import MEMBERS
        cls.manifest=json.loads(MANIFEST.read_bytes());cls.exe=MANIFEST.parent/cls.manifest['elf'];elf=cls.exe.read_bytes()
        assert sha(elf)==cls.manifest['elf_sha256'] and len(elf)==cls.manifest['elf_bytes']
        cls.members={row['name']:row for row in cls.manifest['members']}
        assert list(cls.members)==[row[0] for row in MEMBERS] and len(cls.members)==46
        for row in cls.members.values():
            path=Path(row['manifest']);data=json.loads(path.read_bytes());image=(path.parent/data['image']).read_bytes()
            assert sha(path.read_bytes())==row['manifest_sha256'] and sha(image)==row['image_sha256']
            assert (path.parent/data['source']).read_bytes()==(ROOT/row['source']).read_bytes()
            assert sha((ROOT/row['source']).read_bytes())==row['source_sha256'] and elf.count(image)==1
        for path,digest in cls.manifest['boundary_sources'].items():assert sha((ROOT/path).read_bytes())==digest
        cls.files=OUTPUT/'files';cls.files.mkdir();(cls.files/'file').write_bytes(b'alpha\n')
        COUNTS['actual_embedded_hia_images']=46

    def view(self,session,arguments,*,identifier=2,metadata=None):
        response,raw=session.call(sdk.call(identifier,arguments,metadata));self.assertEqual(response['id'],identifier);result=response['result']
        self.assertIs(type(result['isError']),bool);self.assertEqual(len(result['content']),1);self.assertEqual(result['content'][0]['type'],'text')
        return result,result['content'][0]['text'].encode(),raw
    def test_01_actual_sdk_router_input_domain(self):
        rows=list(router.iter_router_sdk_cases());self.assertEqual(len(rows),54);records=[]
        for row in rows:
            with Session('router-'+str(row['case_id']),self.files) as session:
                replies=[]
                for message in row['messages']:
                    if 'id' in message:response,_=session.call(message);replies.append(response)
                    else:session.send(compact(message))
                self.assertEqual(len(replies),sum('id' in m for m in row['messages']));last=replies[-1]
                if row['case_id'] in TYPED_ERRORS|META_ERRORS:
                    self.assertEqual(last['error']['code'],-32602)
                    prefix='failed to deserialize parameters: ' if row['case_id'] in TYPED_ERRORS else 'request _meta is missing or has malformed required fields: '
                    self.assertTrue(last['error']['message'].startswith(prefix))
                else:self.assertIn('content',last['result'])
                for message,response in zip((m for m in row['messages'] if 'id' in m),replies):
                    if message['method']=='tools/call' and 'result' in response:
                        modern=message['params'].get('_meta',{}).get(VERSION)=='2026-07-28';self.assertEqual('resultType' in response['result'],modern)
                        if modern:self.assertEqual(response['result']['resultType'],'complete')
                records.append(dict(case_id=row['case_id'],name=row['name'],session=session.name,
                    input_case=save(OUTPUT/'router'/(str(row['case_id'])+'.input.json.gz'),compact(row)),
                    responses=save(OUTPUT/'router'/(str(row['case_id'])+'.responses.json.gz'),compact(replies)),original_fixture_body_text_compared=False))
        (OUTPUT/'router-cases.jsonl').write_bytes(b''.join(compact(row)+b'\n' for row in records));COUNTS['sdk_router_input_cases']=54;COUNTS['sdk_typed_protocol_error_controls']=19;COUNTS['sdk_metadata_error_controls']=9
    def test_02_actual_info_and_public_schema(self):
        server=json.loads((ROOT/'native/runtime_server_info.json').read_bytes());schema=json.loads((ROOT/'native/view_input_schema.json').read_bytes());records=[]
        for row in info.iter_info_sdk_cases():
            with Session('info-'+str(row['case_id']),self.files) as session:
                replies=[]
                for message in row['messages']:
                    if 'id' not in message:session.send(compact(message));continue
                    reply,_=session.call(message);replies.append(reply)
                    if 'error' in reply:self.assertEqual(reply['error']['code'],-32602);continue
                    result=reply['result']
                    if message['method']=='initialize':
                        version=message['params']['protocolVersion']
                        if version not in {'2024-11-05','2025-03-26','2025-06-18','2025-11-25'}:version='2025-11-25'
                        self.assertEqual(result,dict(protocolVersion=version,**server['initialize']))
                    elif message['method']=='tools/list':
                        self.assertEqual([tool['name'] for tool in result['tools']],['host_list','effective_config','execution_shadow_admit','view','workdir']);self.assertEqual(result['tools'][3]['inputSchema'],schema);self.assertEqual(result['tools'][4]['inputSchema'],json.loads((ROOT/'native/workdir_input_schema.json').read_bytes()))
                        header={k:v for k,v in result.items() if k!='tools'};modern=message['params'].get('_meta',{}).get(VERSION)=='2026-07-28';self.assertEqual(header,server['modern_tools_list'] if modern else {})
                    else:self.assertEqual(message['method'],'server/discover');self.assertEqual(result,server['discover'])
                records.append(dict(case_id=row['case_id'],name=row['name'],session=session.name,
                    input_case=save(OUTPUT/'info'/(str(row['case_id'])+'.input.json.gz'),compact(row)),
                    responses=save(OUTPUT/'info'/(str(row['case_id'])+'.responses.json.gz'),compact(replies)),full_original_tool_catalog_compared=False))
        (OUTPUT/'info-cases.jsonl').write_bytes(b''.join(compact(row)+b'\n' for row in records));COUNTS['sdk_info_input_cases']=13
    def test_03_typed_gate_and_first_session_latch(self):
        a,b=self.files/'session-a',self.files/'session-b';a.mkdir();b.mkdir();(a/'file').write_bytes(b'first directory\n');(b/'file').write_bytes(b'second directory\n')
        cap=lambda path:{'experimental':{'session':{'workdir':str(path)}}}
        with Session('typed-before-latch',a) as session:
            session.ready();response,_=session.call(sdk.call(2,{'path':3},{CAPS:cap(a)}));self.assertEqual(response['error']['code'],-32602)
            result,body,_=self.view(session,{'path':'file'},identifier=3,metadata={CAPS:cap(b)});self.assertFalse(result['isError']);self.assertTrue(body.endswith(b'|second directory'))
        with Session('legacy-invalid-whole-cap-fallback',a) as session:
            session.ready(cap(b));result,body,_=self.view(session,{'path':'file'},metadata={CAPS:{**cap(a),'roots':True}});self.assertFalse(result['isError']);self.assertTrue(body.endswith(b'|second directory'))
        with Session('first-empty-cap-consumes-latch',a) as session:
            session.ready(cap(b));_,first,_=self.view(session,{'path':'file'},metadata={CAPS:{}});_,second,_=self.view(session,{'path':'file','full':True},identifier=3,metadata={CAPS:cap(b)})
            self.assertEqual(first,second);self.assertTrue(first.endswith(b'|first directory'))
        COUNTS['observable_session_latch_controls']=3
    def test_04_same_installed_policy_before_file_scope(self):
        allowed,blocked=self.files/'allowed',self.files/'blocked';allowed.mkdir();blocked.mkdir();(allowed/'file').write_bytes(b'allowed\n');(blocked/'file').write_bytes(b'blocked\n')
        config=self.files/'runtime-config.json';value=dict(state_dir=str(self.files/'controller-state'),controller_workspace_roots=[str(allowed)],hosts={'h':{'ssh_target':'private-target','remote_state_dir':'/private-state'}});config.write_bytes(compact(value))
        with Session('installed-policy',allowed,config=config) as session:
            session.ready();result,body,_=self.view(session,{'path':'file'});self.assertFalse(result['isError']);self.assertTrue(body.endswith(b'|allowed'))
            for ident,path,expected in [(3,str(blocked/'file'),'outside configured controller workspaces'),(4,'octofs://background/x','Octofs background resources are disabled in runtime mode'),(5,'file|','path must not contain an empty root')]:
                result,body,_=self.view(session,{'path':path},identifier=ident);self.assertTrue(result['isError']);self.assertIn(expected.encode(),body)
            value['controller_workspace_roots']=[str(blocked)];config.write_bytes(compact(value));result,body,_=self.view(session,{'path':str(blocked/'file')},identifier=6)
            self.assertTrue(result['isError']);self.assertIn(b'outside configured controller workspaces',body)
            for ident,name in [(7,'host_list'),(8,'effective_config')]:
                reply,_=session.call(dict(jsonrpc='2.0',id=ident,method='tools/call',params=dict(name=name,arguments={})));self.assertFalse(reply['result']['isError'])
        COUNTS['actual_policy_and_shared_config_controls']=7
    def test_05_public_ordinary_file_reference_domain(self):
        selected=[row for row in cases.iter_cases() if row['metadata']['case_id'] in VIEW_IDS];self.assertEqual(len(selected),31);records=[];session=None;previous=None
        try:
            for row in selected:
                meta=row['metadata'];assert meta['context'] and not meta['hooks'] and not meta['cancel_after_render'] and not meta['raw_path']
                if meta['session']!=previous:
                    if session is not None:session.finish()
                    folder=self.files/('ordinary-'+str(meta['session']));folder.mkdir();session=Session('ordinary-'+str(meta['session']),folder);session.ready();previous=meta['session']
                setup_files(folder,row);arguments=dict(path=bytes.fromhex(meta['path_hex']).decode(),**meta['params']);result,body,wire=self.view(session,arguments,identifier=meta['case_id']+2)
                self.assertEqual(result['isError'],meta['case_id'] in {13,14,15,16,29,30})
                if meta['case_id']==9:self.assertEqual(body.count('⚠️ '.encode()),2)
                index=str(meta['case_id']);records.append(dict(case_id=meta['case_id'],name=meta['name'],session=session.name,
                    original_input=save(OUTPUT/'view'/(index+'.input.bin.gz'),cases.encode_cases([row])),actual_body=save(OUTPUT/'view'/(index+'.body.bin.gz'),body),
                    actual_response=save(OUTPUT/'view'/(index+'.response.bin.gz'),wire),is_error=result['isError'],private_hooks_used=False))
            session.finish();session=None
        finally:
            if session is not None:session.finish(error=True)
        (OUTPUT/'view-cases.jsonl').write_bytes(b''.join(compact(row)+b'\n' for row in records));COUNTS['actual_public_ordinary_view_cases']=31;COUNTS['same_session_cache_cases']=6
    def test_06_large_original_error_through_publisher(self):
        folder=self.files/'wide';folder.mkdir();(folder/'file').write_bytes(b'a\n');arguments=wide.arguments();self.assertLess(len(arguments),8<<20)
        request=b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"view","arguments":'+arguments+b'}}'
        with Session('wide-error',folder) as session:
            session.ready();response,wire=session.call(request);result=response['result'];self.assertIs(result['isError'],True);body=result['content'][0]['text'].encode()
            self.assertGreater(len(body),16<<20);self.assertTrue(body.startswith(b"Invalid 'start':"))
            record=dict(case_id=wide.CASE_ID,session=session.name,original_input=save(OUTPUT/'wide/input.bin.gz',wide.original_input()),actual_body=save(OUTPUT/'wide/body.bin.gz',body),
                actual_response=save(OUTPUT/'wide/response.bin.gz',wire),original_success_body_limit_applied_to_error=False,unrestricted_response_domain_claimed=False)
        (OUTPUT/'wide-case.json').write_bytes(compact(record)+b'\n');COUNTS['large_error_publication_cases']=1;COUNTS['large_error_body_bytes']=len(body)
    def test_07_wide_continuation_and_exact_needed_controls(self):
        result=span_controls.run(MANIFEST,OUTPUT/'private',save)
        self.assertEqual(result['actual_native_calls'],27)
        (OUTPUT/'private/result.json').write_bytes(compact(result)+b'\n')
        COUNTS.update(private_frame_refusals=result['invalid_controls'],
            actual_private_hia_calls=result['actual_native_calls'],
            real_child_positive_continuations=result['real_child_positive_continuations'],
            actual_protocol_child_calls=result['actual_protocol_child_calls'],
            exact_needed_protocol_controls=result['actual_protocol_output_growth_retries'],
            delivery_only_controls=result['delivery_only_calls'],
            exact_needed_endpoint_controls=result['exact_needed_output_controls'])


    def test_08_regex_installation_and_original_error_order(self):
        plans=[('valid',pattern) for pattern in ['a',r'[a-z]+',r'\p{Greek}+',r')|foo(?:','a{327674}']]
        plans += [('invalid',pattern) for pattern in ['(',r'\w{500}','a{327675}',r'(?-u:\xFF)']]
        plans += [('first-error-late','('),('first-error-early','(')]
        rows=[]
        for index,(kind,pattern) in enumerate(plans):
            name='regex-'+str(index);folder=self.files/name;folder.mkdir();(folder/'file').write_bytes(b'regex installed\n')
            state=folder/'controller-state';config=folder/'runtime-config.json'
            action=dict(executable='/echo',allow_extra_args=True,extra_arg_patterns=[pattern])
            value=dict(state_dir=str(state),controller_workspace_roots=[str(folder)],
                hosts={'h':dict(ssh_target='private-target',remote_state_dir='/private-state',privileged_actions={'inspect':action})})
            diagnostic=b'host `h` privileged action `inspect` has invalid argument regex\n'
            if kind.startswith('first-error-'):
                action['extra_arg_patterns']=['a',pattern]
                value['hosts']['h']['privileged_actions']={'middle':action,'zlast':{'executable':'relative'}}
                diagnostic=b'host `h` privileged action `middle` has invalid argument regex\n'
                if kind=='first-error-early':
                    value['hosts']['h']['privileged_actions']['afirst']={'executable':'relative'}
                    diagnostic=b'host `h` has invalid privileged action `afirst`\n'
            initial=compact(value);config.write_bytes(initial)
            row=dict(case_id=index,kind=kind,pattern=pattern,session=name,
                initial_config=save(OUTPUT/'regex'/(str(index)+'.initial-config.json.gz'),initial),
                rewritten_config=None,state_directory_exists_after=False)
            if kind=='valid':
                with Session(name,folder,config=config) as session:
                    session.ready()
                    request=lambda ident,tool:dict(jsonrpc='2.0',id=ident,method='tools/call',params=dict(name=tool,arguments={}))
                    first,_=session.call(request(2,'host_list'));effective,_=session.call(request(3,'effective_config'))
                    first_text=first['result']['content'][0]['text'];effective_text=effective['result']['content'][0]['text']
                    self.assertFalse(first['result']['isError']);self.assertFalse(effective['result']['isError'])
                    self.assertIn('inspect',first_text);self.assertNotIn('inspect',effective_text)
                    self.assertEqual(json.loads(effective_text)['hosts'][0]['named_privileged_action_count'],1)
                    result,body,_=self.view(session,{'path':'file'},identifier=4)
                    self.assertFalse(result['isError']);self.assertTrue(body.endswith(b'|regex installed'))
                    action['extra_arg_patterns']=['('];rewritten=compact(value);config.write_bytes(rewritten)
                    row['rewritten_config']=save(OUTPUT/'regex'/(str(index)+'.rewritten-config.json.gz'),rewritten)
                    after,_=session.call(request(5,'host_list'));after_effective,_=session.call(request(6,'effective_config'))
                    self.assertEqual(after['result'],first['result']);self.assertEqual(after_effective['result'],effective['result'])
            else:
                with Session(name,folder,config=config,expected_exit=78,expected_stderr=diagnostic):pass
            row['state_directory_exists_after']=state.exists()
            self.assertEqual(row['state_directory_exists_after'],kind=='valid');rows.append(row)
        (OUTPUT/'regex-cases.json').write_bytes(compact(rows)+b'\n')
        COUNTS.update(regex_actual_installed_configs=5,regex_actual_startup_refusals=4,
                       regex_actual_first_error_controls=2,regex_actual_mcp_view_results=5)

    def test_09_public_input_and_output_cross_old_window(self):
        row=span_inputs.large_view_case();folder=self.files/'over64';folder.mkdir();setup_files(folder,row)
        request=b'{"jsonrpc":"2.0","id":1001,"method":"tools/call","params":{"name":"view","arguments":{"path":"file","start":"'+b'x'*span_inputs.LARGE_SIZE+b'"}}}'
        with Session('over64',folder) as session:
            session.ready();response,wire=session.call(request)
            result=response['result'];self.assertIs(result['isError'],True)
            body=result['content'][0]['text'].encode();self.assertGreater(len(body),64<<20)
            self.assertTrue(body.startswith(b"Invalid 'start':"))
            record=dict(case_id=1001,session=session.name,
                original_input=save(OUTPUT/'over64/input.bin.gz',cases.encode_cases([row])),
                actual_request=save(OUTPUT/'over64/request.bin.gz',request),
                actual_response=save(OUTPUT/'over64/response.bin.gz',wire),
                actual_body=save(OUTPUT/'over64/body.bin.gz',body),
                original_body_compared=False,unrestricted_response_domain_claimed=False)
            nodes=b'{"jsonrpc":"2.0","id":1002,"method":"ping","unknown":['+b'0,'*262145+b'0]}'
            reply,_=session.call(nodes);self.assertEqual(reply,dict(jsonrpc='2.0',id=1002,result={}))
        (OUTPUT/'over64-case.json').write_bytes(compact(record)+b'\n')
        COUNTS.update(over64_public_cases=1,over64_input_bytes=len(request),over64_body_bytes=len(body),
            over64_response_bytes=len(wire),public_node_count_controls=1)

    def test_10_public_workdir_actual_files_and_same_session(self):
        fixture=self.files/'workdir';fixture.mkdir()
        inputs=workdir_cases.materialized(fixture)
        selected=[row for row in inputs['scenarios'] if span_inputs.workdir_selected(row)]
        self.assertEqual(len(selected),42)
        input_record=dict(scenarios=selected,policies=inputs['policies'])
        save(OUTPUT/'workdir/inputs.json.gz',compact(input_record))
        policies={}
        for name,value in inputs['policies'].items():
            path=fixture/('policy-'+name+'.json');path.write_bytes(compact(value));policies[name]=path
        records=[]
        for scenario in selected:
            span_inputs.setup_workdir(scenario,fixture)
            item=scenario['sessions'][0];cwd=Path(os.fsdecode(bytes.fromhex(item['root_hex'])))
            config=None if inputs['policies'][scenario['policy_id']] is None else policies[scenario['policy_id']]
            name='workdir-'+str(scenario['scenario_id'])
            with Session(name,cwd,config=config) as session:
                for message in item['initial_messages']:
                    if 'id' in message:session.call(message)
                    else:session.send(compact(message))
                for step in scenario['steps']:
                    if step['action']['kind']!='public':continue
                    request=step['action']['message'];reply,wire=session.call(request)
                    self.assertEqual(reply['id'],step['case_id']);self.assertEqual(reply['jsonrpc'],'2.0')
                    if 'error' in reply:
                        self.assertEqual(reply['error']['code'],-32602);body=reply['error']['message'].encode();status='protocol-error'
                    else:
                        result=reply['result'];self.assertIs(type(result['isError']),bool)
                        self.assertEqual(len(result['content']),1);self.assertEqual(result['content'][0]['type'],'text')
                        body=result['content'][0]['text'].encode();status='string-error' if result['isError'] else 'success'
                    ident=str(step['case_id'])
                    records.append(dict(case_id=step['case_id'],scenario_id=scenario['scenario_id'],name=step['name'],session=name,
                        actual_response=save(OUTPUT/'workdir'/(ident+'.response.bin.gz'),wire),
                        actual_body=save(OUTPUT/'workdir'/(ident+'.body.bin.gz'),body),status=status,
                        original_reply_compared=False,native_private_state_queried=False))
        self.assertEqual(len(records),336)
        (OUTPUT/'workdir-cases.jsonl').write_bytes(b''.join(compact(row)+b'\n' for row in records))
        COUNTS.update(public_workdir_scenarios=42,public_workdir_calls=336,
            public_workdir_successes=sum(row['status']=='success' for row in records),
            public_workdir_string_errors=sum(row['status']=='string-error' for row in records),
            public_workdir_typed_errors=sum(row['status']=='protocol-error' for row in records))

def main():
    global MANIFEST,OUTPUT
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--manifest',type=Path,default=os.environ.get('HIA_RUNTIME_MCP_MANIFEST'));parser.add_argument('--output',type=Path,default=os.environ.get('HIA_RUNTIME_MCP_CORPUS_DIR'));args=parser.parse_args()
    if args.manifest is None or args.output is None:parser.error('actual manifest and output are required')
    MANIFEST=args.manifest.resolve(strict=True);OUTPUT=args.output.resolve();OUTPUT.mkdir(parents=True,exist_ok=False);start=time.monotonic();sources=source_identity()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeRuntime))
    sources_after=source_identity();assert sources_after==sources
    report=dict(schema='hepta.runtime.mcp-view-native-tests.v2',status='PASS' if result.wasSuccessful() else 'FAIL',groups=result.testsRun,elapsed_seconds=time.monotonic()-start,counts=dict(COUNTS),manifest_sha256=sha(MANIFEST.read_bytes()),processes=RECORDS,source_binding=sources,sources_unchanged=True,
        execution=dict(runtime_root=str(ROOT),corpus_root=str(OUTPUT),manifest_path=str(MANIFEST)),
        complete_sdk_frontend=False,complete_original_tool_catalog=False,original_tool_count=125,implemented_catalog_names=['host_list','effective_config','execution_shadow_admit','view','workdir'],
        directory_content_remote_background_routes_replaced=False,whole_view_replaced=False,response_storage_globally_unbounded=False,full_http_dispatcher_replaced=False,
        current_protocol_error_reference_compared=False,current_original_view_reference_compared=False)
    (OUTPUT/'result.json').write_bytes(json.dumps(report,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()+b'\n');print(json.dumps({k:v for k,v in report.items() if k!='processes'},sort_keys=True));raise SystemExit(0 if result.wasSuccessful() else 1)
if __name__=='__main__':main()
