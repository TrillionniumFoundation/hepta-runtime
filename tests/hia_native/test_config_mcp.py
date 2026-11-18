"""Actual static sixteen-image MCP, administrator startup and immutable authority.

The original SDK result-byte replay is a separate Cargo-backed recipe. These
tests execute the same fixed ELF, with no interpreter or subprocess fallback.
"""
from pathlib import Path
import argparse,collections,copy,fcntl,hashlib,json,os,select,subprocess,tempfile,time,unittest

ROOT=Path(__file__).resolve().parents[2]
MANIFEST=None;OUTPUT=None;COUNTS=collections.Counter();TRANSCRIPT=[]
sha=lambda b:hashlib.sha256(b).hexdigest()
NAMES=['owner','fs','json','validation','identity','mcp','execution','execution_json','execution_core','value','regex_syntax','regex_unicode_data','regex_hir','regex_nfa','regex_match','regex_controller']
SOURCES={**{name:'config_'+name for name in NAMES[:6]},'execution':'execution_controller','execution_json':'execution_json','execution_core':'execution_shadow','value':'serde_json',**{name:name for name in NAMES[10:]}}

def compact(value):return json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
def request(name,args=b'{}',ident=1):
    fields=b'"name":'+compact(name)
    if args is not None:fields+=b',"arguments":'+args
    return b'{"jsonrpc":"2.0","id":'+compact(ident)+b',"method":"tools/call","params":{'+fields+b'}}'
def fixture(host='h'):
    return {'record':{'kind':'execution_intent','record':{'binding':{'schema_version':1,'run_id':'run-1','turn_id':'turn-1','cell_id':'cell-1','organ_id':None,'operation_id':'op-1','principal':'principal-1','objective_digest':'1'*64,'policy_digest':'2'*64,'candidate_digest':'3'*64,'host':host,'generation':1,'idempotency_key':'key-1','predecessor':None,'currentness':'current','final_use':{'state':'not_granted'},'rollback_reference':None},'class':'file_read','payload_digest':'4'*64}}}
def config(state):return {'state_dir':str(state),'hosts':{'h':{'ssh_target':'private-target','remote_state_dir':'/private-state'}}}
def lock_is_free(path):
    fd=os.open(path,os.O_RDWR)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);return True
        except BlockingIOError:return False
    finally:os.close(fd)

class Session:
    def __init__(self,exe,path,*,env=None):
        self.process=subprocess.Popen([str(exe),'--runtime-config',str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'','LC_ALL':'C',**(env or {})})
        self.pending=bytearray()
    def send(self,raw):self.process.stdin.write(raw+b'\n');self.process.stdin.flush()
    def read(self):
        end=time.monotonic()+30
        while b'\n' not in self.pending:
            wait=end-time.monotonic()
            if wait<=0 or not select.select([self.process.stdout],[],[],wait)[0]:raise AssertionError('native MCP response timeout')
            piece=os.read(self.process.stdout.fileno(),65536)
            if not piece:raise AssertionError(('native MCP EOF',self.process.poll(),self.process.stderr.read()))
            self.pending.extend(piece)
        result,_,rest=self.pending.partition(b'\n');self.pending=bytearray(rest);COUNTS['actual_elf_responses']+=1;return bytes(result)
    def call(self,raw):
        self.send(raw);out=self.read();TRANSCRIPT.append({'request_sha256':sha(raw),'response_sha256':sha(out),'request_bytes':len(raw),'response_bytes':len(out)})
        return json.loads(out),out
    def ready(self):
        raw=compact({'jsonrpc':'2.0','id':0,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'native-fixture','version':'1'}}})
        parsed,_=self.call(raw);assert parsed['result']['protocolVersion']=='2025-06-18'
        self.send(b'{"jsonrpc":"2.0","method":"notifications/initialized"}')
    def close(self):
        self.process.stdin.close();self.process.wait(timeout=30)
        assert (self.process.returncode,self.process.stderr.read(),bytes(self.pending))==(0,b'',b'')
    def __enter__(self):return self
    def __exit__(self,*error):
        if error[0]:self.process.kill();self.process.wait(timeout=15)
        else:self.close()

class NativeConfigMCP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.metadata=json.loads(MANIFEST.read_bytes());cls.exe=MANIFEST.parent/cls.metadata['executable'];elf=cls.exe.read_bytes()
        assert sha(elf)==cls.metadata['elf_sha256'] and len(elf)==cls.metadata['elf_bytes']
        assert sha((ROOT/'scripts/config_mcp_adapter.S').read_bytes())==cls.metadata['adapter_source_sha256']
        assert [m['id'] for m in cls.metadata['members']]==list(range(16))
        for name,m in zip(NAMES,cls.metadata['members'],strict=True):
            assert m['name']==name
            assert sha((ROOT/'native'/(SOURCES[name]+'.hepta')).read_bytes())==m['source_sha256']
            path=Path(m['manifest']);data=json.loads(path.read_bytes());image=(path.parent/data['image']).read_bytes()
            assert sha(path.read_bytes())==m['manifest_sha256'] and sha(image)==m['image_sha256']
            assert elf[m['offset']:m['offset']+len(image)]==image
        COUNTS['embedded_images_verified']=16
    def tool(self,s,name,args=b'{}',ident=1,error=False):
        value,wire=s.call(request(name,args,ident));self.assertEqual(value['id'],ident)
        self.assertEqual(set(value['result']),{'content','isError'});self.assertEqual(value['result']['isError'],error)
        content=value['result']['content'];self.assertEqual(len(content),1);self.assertEqual(content[0]['type'],'text')
        return content[0]['text'],wire
    def test_01_catalog_and_summaries(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-mcp-') as td:
            root=Path(td);path=root/'config';path.write_bytes(compact(config(root/'state')))
            with Session(self.exe,path) as s:
                s.ready();result,_=s.call(b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
                self.assertEqual([v['name'] for v in result['result']['tools']],['host_list','effective_config','execution_shadow_admit'])
                self.assertEqual(result['result']['tools'][2]['inputSchema'],json.loads((ROOT/'native/config_execution_schema.json').read_bytes()))
                for name in ['host_list','effective_config']:
                    first,_=self.tool(s,name)
                    for args in [None,b'null',b' {} ',b'{ }']:self.assertEqual(self.tool(s,name,args)[0],first)
                    self.assertNotIn('private-target',first);self.assertNotIn('/private-state',first)
                    COUNTS['missing_null_empty_default_controls']+=4
    def test_02_real_value_duplicate_sort_and_escape(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-mcp-') as td:
            root=Path(td);path=root/'config';path.write_bytes(compact(config(root/'state')))
            with Session(self.exe,path) as s:
                s.ready()
                for args,key in [(b'{"z":null,"a":true}','a'),(b'{"x":1,"x":2}','x'),(b'{"\\u0078":false,"x":[]}','x'),(b'{"z":{"a":1,"a":2},"a":-0}','a'),(compact({'中':1,'\x00':None}),'\x00'),(compact({'`\\\n\t"😀':{}}),'`\\\n\t"😀')]:
                    text,_=self.tool(s,'host_list',args,error=True)
                    self.assertEqual(text,'failed to deserialize parameters: unknown field `'+key+'`, there are no fields')
                    COUNTS['actual_value_controls']+=1
                text,_=self.tool(s,'host_list',b'{"x":['+b','.join([b'0']*300000)+b']}',error=True)
                self.assertIn('unknown field `x`',text);COUNTS['above_old_protocol_node_limit']=1
                for token in [b'-0',b'1e-9999',b'18446744073709551616',b'1.7976931348623157e308']:
                    self.assertIn('unknown field `x`',self.tool(s,'host_list',b'{"x":'+token+b'}',error=True)[0]);COUNTS['native_number_controls']+=1
                # Invalid overwritten values still fail native Value admission.
                result,_=s.call(request('host_list',b'{"x":1e9999,"x":0}'))
                self.assertEqual((result['id'],result['error']['code']),(None,-32700))
                result,_=s.call(request('host_list',b'{"x":0}',ident='\n\t"😀'))
                self.assertEqual(result['id'],'\n\t"😀')
    def test_03_installed_host_before_record_validation(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-mcp-') as td:
            root=Path(td);path=root/'config';path.write_bytes(compact(config(root/'state')))
            with Session(self.exe,path) as s:
                s.ready();first,_=self.tool(s,'execution_shadow_admit',compact(fixture()))
                value=json.loads(first);self.assertFalse(value['executable']);self.assertEqual(value['status'],'shadow_only')
                for host in ['private-target','missing','H']:
                    args=fixture(host);args['record']['record']['binding']['schema_version']=0
                    text,_=self.tool(s,'execution_shadow_admit',compact(args),error=True)
                    self.assertEqual(text,'unknown host `'+host+'`; call host_list for configured names')
                    COUNTS['exact_installed_host_controls']+=1
                bad=fixture();bad['record']['record']['binding']['schema_version']=0
                self.assertEqual(self.tool(s,'execution_shadow_admit',compact(bad),error=True)[0],'execution v1 schema or generation invalid')
                self.assertEqual(self.tool(s,'execution_shadow_admit',error=True)[0],'failed to deserialize parameters: missing field `record`')
                # Value last-wins precedes the exact execution typed decoder.
                args=compact(fixture());dupe=b'{"record":null,'+args[1:]
                self.assertEqual(self.tool(s,'execution_shadow_admit',dupe)[0],first)
                args=fixture();args['record']['record']['binding']['generation']=1.0
                self.assertIn('floating point `1.0`',self.tool(s,'execution_shadow_admit',compact(args),error=True)[0])
                COUNTS['actual_execution_chain_controls']+=4
    def test_04_no_caller_configuration_and_retained_locks(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-mcp-') as td:
            root=Path(td);path=root/'config';path.write_bytes(compact(config(root/'state')))
            with Session(self.exe,path) as s:
                s.ready();before,_=self.tool(s,'host_list');count=len(list(Path(f'/proc/{s.process.pid}/fd').iterdir()))
                self.assertFalse(lock_is_free(root/'state/controller.owner.lock'));self.assertFalse(lock_is_free(root/'state/controller.lock'))
                path.write_bytes(compact({'state_dir':str(root/'attacker'),'hosts':{}}));path.unlink()
                for args in [compact({'config':{'hosts':{}}}),compact({'runtime_config':str(path)}),compact({'state_dir':str(root/'attacker')}),compact({'host':'private-target'})]:
                    self.tool(s,'host_list',args,error=True)
                    self.assertEqual(self.tool(s,'host_list')[0],before);self.assertEqual(len(list(Path(f'/proc/{s.process.pid}/fd').iterdir())),count)
                    COUNTS['immutable_authority_controls']+=1
                self.assertFalse((root/'attacker').exists())
                for _ in range(3):self.tool(s,'execution_shadow_admit',compact(fixture()))
            self.assertTrue(lock_is_free(root/'state/controller.owner.lock'));self.assertTrue(lock_is_free(root/'state/controller.lock'))
            COUNTS['lock_custody_controls']+=4
    def test_05_session_frames_and_refusals(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-mcp-') as td:
            root=Path(td);path=root/'config';path.write_bytes(compact(config(root/'state')))
            with Session(self.exe,path) as s:
                early,_=s.call(request('host_list'));self.assertIn('error',early)
                s.ready();self.tool(s,'host_list')
                for raw in [b'',b'{',b'{"jsonrpc":"2.0","id":9,"method":"ping","method":"ping"}',b'[{"jsonrpc":"2.0","id":9,"method":"ping"}]']:
                    parsed,_=s.call(raw);self.assertIn('error',parsed);COUNTS['protocol_profile_refusals']+=1
                parsed,_=s.call(b'{"jsonrpc":"2.0","id":10,"method":"ping"}\r');self.assertEqual(parsed['result'],{})
                s.send(b'{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}')
                self.tool(s,'host_list',ident=11)
                parsed,_=s.call(request('unimplemented',ident=12));self.assertEqual(parsed['error']['code'],-32602)
                parsed,_=s.call(b'{"jsonrpc":"2.0","id":13,"method":"unimplemented"}');self.assertEqual(parsed['error']['code'],-32601)
            # A last non-newline frame is a real frame, not an EOF notification.
            initial=compact({'jsonrpc':'2.0','id':0,'method':'initialize','params':{'protocolVersion':'unrecognized','capabilities':{},'clientInfo':{'name':'n','version':'1'}}})
            done=subprocess.run([str(self.exe),'--runtime-config',str(path)],input=initial,capture_output=True,timeout=30,env={'PATH':'','LC_ALL':'C'})
            self.assertEqual((done.returncode,done.stderr),(0,b''));self.assertEqual(json.loads(done.stdout)['result']['protocolVersion'],'2025-06-18')
            COUNTS['actual_elf_responses']+=1;COUNTS['final_eof_frame_controls']=1

    def test_06_regex_installation_before_state_effects(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-regex-mcp-') as td:
            root=Path(td);path=root/'config'
            for i,pattern in enumerate(['a',r'[a-z]+',r'\p{Greek}+',r')|foo(?:','a{327674}']):
                state=root/('valid-'+str(i));value=config(state)
                value['hosts']['h']['privileged_actions']={'inspect':{'executable':'/echo','allow_extra_args':True,'extra_arg_patterns':[pattern]}}
                path.write_bytes(compact(value))
                with Session(self.exe,path) as s:
                    s.ready();first,_=self.tool(s,'host_list');effective,_=self.tool(s,'effective_config')
                    self.assertIn('inspect',first)
                    self.assertEqual(json.loads(effective)['hosts'][0]['named_privileged_action_count'],1)
                    self.assertNotIn('inspect',effective)
                    self.assertFalse(lock_is_free(state/'controller.owner.lock'))
                    value['hosts']['h']['privileged_actions']['inspect']['extra_arg_patterns']=['(']
                    path.write_bytes(compact(value))
                    self.assertEqual(self.tool(s,'host_list')[0],first)
                    self.assertEqual(self.tool(s,'effective_config')[0],effective)
                    self.tool(s,'execution_shadow_admit',compact(fixture()))
                self.assertTrue(lock_is_free(state/'controller.owner.lock'))
                COUNTS['regex_actual_installed_configs']+=1
            for i,pattern in enumerate(['(',r'\w{500}','a{327675}',r'(?-u:\xFF)']):
                state=root/('invalid-'+str(i));value=config(state)
                value['hosts']['h']['privileged_actions']={'inspect':{'executable':'/echo','allow_extra_args':True,'extra_arg_patterns':[pattern]}}
                path.write_bytes(compact(value))
                done=subprocess.run([str(self.exe),'--runtime-config',str(path)],input=b'',capture_output=True,timeout=30,env={'PATH':'','LC_ALL':'C'})
                self.assertEqual((done.returncode,done.stdout,done.stderr),(78,b'',b'host `h` privileged action `inspect` has invalid argument regex\n'))
                self.assertFalse(state.exists())
                COUNTS['regex_actual_startup_refusals']+=1

    def test_07_first_error_and_public_projection(self):
        with tempfile.TemporaryDirectory(prefix='hia-config-regex-order-') as td:
            root=Path(td);path=root/'config'
            for i,early in enumerate([False,True]):
                state=root/str(i);value=config(state)
                value['hosts']['h']['privileged_actions']={'middle':{'executable':'/echo','allow_extra_args':True,'extra_arg_patterns':['a','(']},'zlast':{'executable':'relative'}}
                if early:value['hosts']['h']['privileged_actions']['afirst']={'executable':'relative'}
                path.write_bytes(compact(value))
                done=subprocess.run([str(self.exe),'--runtime-config',str(path)],input=b'',capture_output=True,timeout=30,env={'PATH':'','LC_ALL':'C'})
                text=b'host `h` has invalid privileged action `afirst`\n'if early else b'host `h` privileged action `middle` has invalid argument regex\n'
                self.assertEqual((done.returncode,done.stdout,done.stderr),(78,b'',text));self.assertFalse(state.exists())
                COUNTS['regex_actual_first_error_controls']+=1

def main():
    global MANIFEST,OUTPUT
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    MANIFEST=a.manifest.resolve(strict=True);OUTPUT=a.output.resolve();OUTPUT.mkdir(parents=True,exist_ok=False)
    before=sha(MANIFEST.read_bytes());start=time.monotonic();result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(NativeConfigMCP))
    report={'schema':'hepta.runtime.config-mcp-native-tests.v1','status':'PASS' if result.wasSuccessful() else 'FAIL','groups':result.testsRun,'elapsed':time.monotonic()-start,'counts':dict(COUNTS),'manifest_sha256':before,'source_unchanged':sha(MANIFEST.read_bytes())==before,'transcript':TRANSCRIPT,'complete_runtime':False,'regex_compilation_closed':False}
    (OUTPUT/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='transcript'},sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() and report['source_unchanged'] else 1)

if __name__=='__main__':main()
