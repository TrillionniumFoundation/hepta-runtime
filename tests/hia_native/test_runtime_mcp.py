"""Actual MCP/view ELF and private-frame controls, retaining all wire bytes.

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
VIEW_IDS=tuple([*range(19),26,28,29,30,35,36,*range(45,51)])
TYPED_ERRORS={0,1,2,3,11,12,13,14,15,16,17,20,200,201,202,203,206,207,208}
META_ERRORS={32,33,34,35,101,103,105,209,210}
CAPS='io.modelcontextprotocol/clientCapabilities';VERSION='io.modelcontextprotocol/protocolVersion'
def save(path,raw):
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(gzip.compress(raw,mtime=0))
    return dict(path=str(path.relative_to(OUTPUT)),bytes=len(raw),sha256=sha(raw))
def source_identity():
    path=ROOT/'native/runtime_mcp_sources.json'; raw=path.read_bytes(); spec=json.loads(raw)
    identities={name:dict(bytes=(ROOT/name).stat().st_size,sha256=sha((ROOT/name).read_bytes())) for name in spec['sources']}
    assert identities==spec['sources']
    return dict(manifest_sha256=sha(raw),files=identities)
def setup_files(folder,row):
    for action in row['metadata']['setup']:
        path=folder/os.fsdecode(bytes.fromhex(action['path_hex']));path.parent.mkdir(parents=True,exist_ok=True)
        if action['kind']=='write':path.write_bytes(row['blobs'][action['blob']])
        elif action['kind']=='symlink':path.symlink_to(os.fsdecode(bytes.fromhex(action['target_hex'])))
        elif action['kind']=='hardlink':os.link(folder/os.fsdecode(bytes.fromhex(action['target_hex'])),path)
        else:raise AssertionError('selected public case has an unsupported setup action')

class Session:
    def __init__(self,name,root,*,config=None):
        self.name=name;self.folder=OUTPUT/'sessions'/name;self.folder.mkdir(parents=True,exist_ok=False)
        self.command=[str(NativeRuntime.exe)]
        if config is not None:self.command+=['--runtime-config',str(config)]
        self.command+=['--session-root',str(root)];self.start=time.monotonic()
        self.process=subprocess.Popen(self.command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'','LC_ALL':'C'})
        self.input=bytearray();self.output=bytearray();self.pending=bytearray();self.closed=False
    def send(self,wire):
        self.input+=wire+b'\n';self.process.stdin.write(wire+b'\n');self.process.stdin.flush()
    def read(self):
        deadline=time.monotonic()+60
        while b'\n' not in self.pending:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([self.process.stdout],[],[],remaining)[0]:raise AssertionError('actual native MCP response timeout')
            piece=os.read(self.process.stdout.fileno(),65536)
            if not piece:raise AssertionError(('actual native MCP EOF',self.process.poll()))
            self.pending.extend(piece)
        wire,_,rest=self.pending.partition(b'\n');self.pending=bytearray(rest);self.output+=wire+b'\n'
        COUNTS['actual_elf_responses']+=1;return json.loads(wire),bytes(wire)
    def call(self,value):self.send(value if isinstance(value,bytes) else compact(value));return self.read()
    def ready(self,capabilities=None):return self.call(sdk.initialization({} if capabilities is None else capabilities))
    def finish(self,error=False):
        if self.closed:return
        self.closed=True;self.process.stdin.close()
        if error and self.process.poll() is None:self.process.kill()
        self.process.wait(timeout=60);remaining=self.process.stdout.read();stderr=self.process.stderr.read();self.output+=self.pending+remaining
        record=dict(session=self.name,command=self.command,environment={'PATH':'','LC_ALL':'C'},timeout_seconds=60,
            exit_code=self.process.returncode,elapsed_seconds=time.monotonic()-self.start,
            stdin=save(self.folder/'stdin.bin.gz',bytes(self.input)),stdout=save(self.folder/'stdout.bin.gz',bytes(self.output)),stderr=save(self.folder/'stderr.bin.gz',stderr))
        (self.folder/'process.json').write_bytes(compact(record)+b'\n');RECORDS.append(record);COUNTS['actual_elf_processes']+=1
        if not error:assert (self.process.returncode,stderr,self.pending,remaining)==(0,b'',b'',b'')
    def __enter__(self):return self
    def __exit__(self,kind,value,traceback):self.finish(error=kind is not None)

class SparseState:
    def __init__(self,module,capacity=256<<20,output=512):
        self.module,self.capacity,self.output_capacity=module,capacity,output
        self.maps=[mmap.mmap(-1,n+4096) for n in (capacity,output)]
        self.workspace=(ctypes.c_char*(capacity+16)).from_buffer(self.maps[0]);self.output=(ctypes.c_char*(output+16)).from_buffer(self.maps[1]);ctypes.memset(self.output,0xA5,output)
    def read(self,offset,count):return ctypes.string_at(ctypes.addressof(self.workspace)+offset,count)
    def write(self,offset,raw):ctypes.memmove(ctypes.addressof(self.workspace)+offset,raw,len(raw))
    def invoke(self,wire):
        try:
            out=self.module._invoke_buffers(wire,self.output,self.workspace,self.output_capacity,self.capacity);return len(out),out
        except NativeRejected as error:return error.code,None
    def identity(self):return sha(memoryview(self.maps[0])[:self.capacity]),bytes(self.output[:self.output_capacity])
    def sparse(self):
        chunks=[];block=1<<20
        for offset in range(0,self.capacity,block):
            raw=self.read(offset,min(block,self.capacity-offset))
            if raw.count(0)!=len(raw):chunks.append((offset,raw))
        return b'HRMCS001'+struct.pack('<3Q',self.capacity,block,len(chunks))+b''.join(struct.pack('<2Q',offset,len(raw))+raw for offset,raw in chunks)
    def close(self):
        self.workspace=self.output=None
        for mapping in self.maps:mapping.close()

class NativeRuntime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest=json.loads(MANIFEST.read_bytes());cls.exe=MANIFEST.parent/cls.manifest['elf'];elf=cls.exe.read_bytes()
        assert sha(elf)==cls.manifest['elf_sha256'] and len(elf)==cls.manifest['elf_bytes']
        cls.members={row['name']:row for row in cls.manifest['members']};assert len(cls.members)==31
        for row in cls.members.values():
            path=Path(row['manifest']);data=json.loads(path.read_bytes());image=(path.parent/data['image']).read_bytes()
            assert sha(path.read_bytes())==row['manifest_sha256'] and sha(image)==row['image_sha256']
            assert (path.parent/data['source']).read_bytes()==(ROOT/row['source']).read_bytes()
            assert sha((ROOT/row['source']).read_bytes())==row['source_sha256'] and elf.count(image)==1
        for path,digest in cls.manifest['boundary_sources'].items():assert sha((ROOT/path).read_bytes())==digest
        cls.files=OUTPUT/'files';cls.files.mkdir();(cls.files/'file').write_bytes(b'alpha\n');COUNTS['actual_embedded_hia_images']=31
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
                        self.assertEqual([tool['name'] for tool in result['tools']],['host_list','effective_config','execution_shadow_admit','view']);self.assertEqual(result['tools'][-1]['inputSchema'],schema)
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
    def test_07_private_frame_and_continuation_refusals(self):
        records=[];positives=[]
        for name,request in [('gateway',b'HVMGWQ01'+struct.pack('<4Q',2,0,0,0)+b'{}'),('admission',b'HCMADQ01'+struct.pack('<3Q',2,2,0)+b'{}')]:
            row=self.members[name];manifest=Path(row['manifest'])
            with NativeModule(manifest,manifest_sha256=row['manifest_sha256']) as module:
                state=SparseState(module)
                try:
                    zero=save(OUTPUT/'private'/(name+'-zero.bin.gz'),state.sparse())
                    def record(label,wire,before,after,baseline,footer_before,footer_after,code):
                        index=str(len(records));records.append(dict(owner=name,control=label,return_code=code,buffers_unchanged=True,
                            input=save(OUTPUT/'private'/(index+'.input.bin.gz'),wire),baseline=baseline,
                            workspace_capacity=state.capacity,output_capacity=state.output_capacity,
                            workspace_before_sha256=before[0],workspace_after_sha256=after[0],
                            footer_before=save(OUTPUT/'private'/(index+'.footer-before.bin.gz'),footer_before),
                            footer_after=save(OUTPUT/'private'/(index+'.footer-after.bin.gz'),footer_after),
                            output_before=save(OUTPUT/'private'/(index+'.output-before.bin.gz'),before[1]),
                            output_after=save(OUTPUT/'private'/(index+'.output-after.bin.gz'),after[1])))
                    for label,wire in [('empty',b''),('short',request[:7]),('magic',b'BADMAGIC'+request[8:]),('length',request+b'x')]:
                        before=state.identity();footer_before=state.read(state.capacity-256,256);code,_=state.invoke(wire);after=state.identity();self.assertEqual(code,0xffffffff);self.assertEqual(after,before)
                        record(label,wire,before,after,zero,footer_before,state.read(state.capacity-256,256),code)
                    code,_=state.invoke(request);self.assertEqual(code,0xffffffe0);footer=state.capacity-256;yielded_footer=state.read(footer,112)
                    if name=='gateway':child_row=self.members['params'];child_wire=b'HVPRQ001'+struct.pack('<2Q',2,0)+b'{}'
                    else:child_row=self.members['value'];child_wire=b'HSJVAL01'+struct.pack('<2Q',1,2)+b'{}'
                    with NativeModule(Path(child_row['manifest']),manifest_sha256=child_row['manifest_sha256']) as child:
                        response=child.invoke(child_wire,output_capacity=512,workspace_capacity=32<<20 if name=='gateway' else 256<<20)
                    state.write(67117056,response);sequence=struct.unpack('<Q',state.read(footer+8,8))[0];state.write(footer+80,struct.pack('<3Q',len(response),sequence,1));original=state.read(footer,112)
                    ready=save(OUTPUT/'private'/(name+'-ready.bin.gz'),state.sparse())
                    for offset in (0,8,16,24,32,40,48,56,64,72,88,96,104):
                        state.write(footer,original);value,=struct.unpack('<Q',original[offset:offset+8]);state.write(footer+offset,struct.pack('<Q',value^0x8000000000000000));before=state.identity();footer_before=state.read(footer,256);code,_=state.invoke(request);after=state.identity()
                        self.assertEqual(code,0xffffffff);self.assertEqual(after,before);record('continuation-word-'+str(offset),request,before,after,ready,footer_before,state.read(footer,256),code)
                    state.write(footer,original);code,returned=state.invoke(request);self.assertEqual(code,52 if name=='gateway' else 0xffffffe0);COUNTS['real_child_positive_continuations']+=1
                    positives.append(dict(owner=name,child=child_row['name'],child_manifest_sha256=child_row['manifest_sha256'],return_code=code,
                        request=save(OUTPUT/'private'/(name+'.request.bin.gz'),request),
                        yielded_footer=save(OUTPUT/'private'/(name+'.yielded-footer.bin.gz'),yielded_footer),
                        child_input=save(OUTPUT/'private'/(name+'.child-input.bin.gz'),child_wire),
                        actual_child_response=save(OUTPUT/'private'/(name+'.child-response.bin.gz'),response),
                        completion_footer=save(OUTPUT/'private'/(name+'.completion-footer.bin.gz'),original),
                        actual_output=save(OUTPUT/'private'/(name+'.positive-output.bin.gz'),bytes(state.output[:state.output_capacity])),
                        returned_bytes=None if returned is None else len(returned)))
                finally:state.close()
        self.assertEqual(len(records),34);(OUTPUT/'private-refusals.json').write_bytes(compact(records)+b'\n');(OUTPUT/'private-positives.json').write_bytes(compact(positives)+b'\n');COUNTS['private_frame_refusals']=34

def main():
    global MANIFEST,OUTPUT
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--manifest',type=Path,default=os.environ.get('HIA_RUNTIME_MCP_MANIFEST'));parser.add_argument('--output',type=Path,default=os.environ.get('HIA_RUNTIME_MCP_CORPUS_DIR'));args=parser.parse_args()
    if args.manifest is None or args.output is None:parser.error('actual manifest and output are required')
    MANIFEST=args.manifest.resolve(strict=True);OUTPUT=args.output.resolve();OUTPUT.mkdir(parents=True,exist_ok=False);start=time.monotonic();sources=source_identity()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeRuntime))
    sources_after=source_identity();assert sources_after==sources
    report=dict(schema='hepta.runtime.mcp-view-native-tests.v1',status='PASS' if result.wasSuccessful() else 'FAIL',groups=result.testsRun,elapsed_seconds=time.monotonic()-start,counts=dict(COUNTS),manifest_sha256=sha(MANIFEST.read_bytes()),processes=RECORDS,source_binding=sources,sources_unchanged=True,
        execution=dict(runtime_root=str(ROOT),corpus_root=str(OUTPUT),manifest_path=str(MANIFEST)),
        complete_sdk_frontend=False,complete_original_tool_catalog=False,original_tool_count=125,implemented_catalog_names=['host_list','effective_config','execution_shadow_admit','view'],
        directory_content_remote_background_routes_replaced=False,whole_view_replaced=False,response_storage_globally_unbounded=False,full_http_dispatcher_replaced=False,
        current_protocol_error_reference_compared=False,current_original_view_reference_compared=False)
    (OUTPUT/'result.json').write_bytes(compact(report)+b'\n');print(json.dumps({k:v for k,v in report.items() if k!='processes'},sort_keys=True));raise SystemExit(0 if result.wasSuccessful() else 1)
if __name__=='__main__':main()
