"""Native batch controller with explicitly synthetic IO completion fixtures.

This is not a filesystem or final MCP-executable comparison. Policy, codec,
stat formatting, JSON parsing and batch decisions execute actual HIA images.
The separate real-ELF suite is mandatory before service qualification.
"""
from pathlib import Path
import ast
import ctypes
import gzip
import hashlib
import json
import os
import random
import struct
import sys
import unittest

ROOT=Path(os.environ.get('HIA_REFERENCE_RUNTIME',Path(__file__).resolve().parents[2]))
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_loader import NativeModule
COUNTS={'requests':0,'native_controller_calls':0,'native_leaf_calls':0,'fixture_io_calls':0,
        'original_wire_size_calls':0,'actual_elf_requests':0,'original_rust_validation_cases':0}
REDACTED='multi-file read could not complete; verify configured read roots, regular single-link files, strict UTF-8 and byte budgets'
U64=(1<<64)-1
CALL=0xffffffe0
WIDTH=32<<20
OUTPUT=8<<20
B=WIDTH-256

def compact(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))

def request(arguments,identity='id"\n雪😀'):
    return compact({'jsonrpc':'2.0','method':'tools/call','id':identity,
                    'params':{'name':'read_multiple_files','arguments':arguments}}).encode()

def open_module(path):
    path=Path(path)
    return NativeModule(path,manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest())

def expected_file(path,data):
    return {'eof':True,'path':path,'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),
            'text':data.decode('utf-8'),'version':f'1:2:{len(data)}:3000000004:5000000006'}

def expected_result(files):
    return {'atomic_snapshot':False,'encoding':'utf-8','files':files,
            'snapshot_scope':'independent_file','truncated':False}

def validation_vectors():
    for count in [0,1,16,17]:
        for file_limit in [None,0,1,65536,65537,U64]:
            for response_limit in [None,0,1023,1024,262144,262145,U64]:
                yield [f'/path/{i}' for i in range(count)],file_limit,response_limit
    for path in ['','/','relative','//a','/a/','/a//b','/a/./b','/a/../b','/a\0b',
                 '/a\nb','/中😀','/'+('x'*4095),'/'+('x'*4096),'/'+('雪'*1365),
                 '/'+('雪'*1365)+'x','/.hidden','/...']:
        yield [path],None,None
    for paths in [['/a','/a'],['/雪😀','/雪😀'],['/a','/b'],['/a','/a//b']]:
        yield paths,None,None
    rng=random.Random(0x4d5256414c)
    for _ in range(1500):
        paths=[rng.choice(['/a','/b','/雪😀','/a/..','/a\0b','/a\nb','/',
                           '/'+str(rng.randrange(100))]) for _ in range(rng.randrange(19))]
        yield paths,rng.choice([None,0,1,16384,65536,65537,U64]),rng.choice([None,1023,1024,65536,262144,262145,U64])

def validation_packet(paths,file_limit,response_limit):
    out=b'HMRVAL01'+struct.pack('<5Q',int(file_limit is not None),file_limit or 0,
                             int(response_limit is not None),response_limit or 0,len(paths))
    for path in paths:
        raw=path.encode();out+=struct.pack('<Q',len(raw))+raw
    return out

class FixtureHarness:
    def __init__(self,module,leaves,root=b'/native-test'):
        self.module=module;self.leaves=leaves;self.root=root
        self.output=ctypes.create_string_buffer(OUTPUT+16)
        self.work=ctypes.create_string_buffer(WIDTH+16)
        self.address=ctypes.addressof(self.work)
        self.sequence=0;self.calls=[];self.fixtures={}
        self.put(B+120,3)
        assert self.run(root)==(0,b'')

    def put(self,offset,value):
        ctypes.memmove(self.address+offset,struct.pack('<Q',value),8)

    def native(self,raw):
        source=ctypes.create_string_buffer(raw,max(1,len(raw)))
        ctypes.memset(ctypes.addressof(self.output)+OUTPUT,0xa5,16)
        ctypes.memset(self.address+WIDTH,0x5a,16)
        code=self.module._entry(source,len(raw),self.output,OUTPUT,self.work,WIDTH)
        COUNTS['native_controller_calls']+=1
        assert source.raw==(raw or b'\0')
        assert ctypes.string_at(ctypes.addressof(self.output)+OUTPUT,16)==b'\xa5'*16
        assert ctypes.string_at(self.address+WIDTH,16)==b'\x5a'*16
        return code

    def fixture_io(self,frame):
        assert frame[:8]==b'HIARD001'
        rid,op,offset,limit,flag,*tail=struct.unpack('<13Q',frame[8:112])
        assert op==2 and offset==0 and flag==0 and tail[:7]==[0]*7
        assert tail[7]==len(frame)-112
        value=self.fixtures.get(frame[112:].decode(),3)
        status=value if type(value) is int else 0
        if status==0 and len(value)>limit:status=12
        if status:return b'HIARR001'+struct.pack('<15Q',rid,status,0,0,0,0,0,*(0,)*7,0)
        words=(1,2,len(value),3,4,5,6)
        return b'HIARR001'+struct.pack('<15Q',rid,0,0,len(value),0,len(value),1,*words,0)+value

    def run(self,raw):
        for _ in range(160):
            code=self.native(raw)
            if code!=CALL:
                if code>=0xffff0000:return code,None
                assert code<=OUTPUT
                return code,ctypes.string_at(self.output,code)
            words=struct.unpack('<14Q',ctypes.string_at(self.address+B,112))
            magic,seq,target,region,start,size,oregion,ostart,capacity,reserved,result,ack,done,denied=words
            assert magic==int.from_bytes(b'HIACAL01','little') and seq==self.sequence+1
            assert region==oregion==2 and target in (1,2,3,4)
            assert 0<=start<=WIDTH-size and 0<=ostart<=WIDTH-256-capacity
            assert start+size<=ostart or ostart+capacity<=start
            assert reserved==result==ack==done==denied==0
            self.sequence=seq
            frame=ctypes.string_at(self.address+start,size)
            self.calls.append((target,frame))
            if target==3:
                response=self.fixture_io(frame);returned=len(response);COUNTS['fixture_io_calls']+=1
            else:
                returned,response,_=self.leaves[target].invoke_raw(frame,output_capacity=capacity,
                    workspace_capacity={1:32768,2:1184,4:256}[target])
                response=response[:returned] if returned<0xffff0000 else b''
                COUNTS['native_leaf_calls']+=1
            assert len(response)<=capacity
            ctypes.memmove(self.address+ostart,response,len(response))
            self.put(B+80,returned);self.put(B+88,seq);self.put(B+96,1);self.put(B+104,0)
        raise AssertionError('unbounded continuation loop')

    def tool(self,args,identity='id"\n雪😀'):
        code,data=self.run(request(args,identity));COUNTS['requests']+=1
        assert code<0xffff0000,(hex(code),args)
        result=json.loads(data);assert result['id']==identity
        return result

class ControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module=open_module(os.environ['HIA_MULTI_READ_MANIFEST'])
        import copy
        sys.path.insert(0,os.environ['HIA_HEPTA_DIR'])
        from hepta.hia_agent_assembly import assemble_program
        source=ROOT/'native/multi_read_service.hepta'
        proof=json.loads(source.with_name('multi_read_service_composition.json').read_bytes())
        source_hash=hashlib.sha256(source.read_bytes()).hexdigest()
        assert source_hash==proof['native_source_sha256']==cls.module.metadata['source_sha256']
        protocol=ROOT/proof['protocol_source']
        assert hashlib.sha256(protocol.read_bytes()).hexdigest()==proof['protocol_source_sha256']
        before={f['name']:f for f in assemble_program(protocol.read_bytes()).as_dict()['functions']}
        after={f['name']:f for f in assemble_program(source.read_bytes()).as_dict()['functions']}
        for item in proof['parser_imports']:
            current=copy.deepcopy(after[item['destination_function']]);current['name']=item['original_function']
            for block in current['blocks']:
                for operation in block['ops']:
                    if operation['op']=='call':
                        operation['attrs']['function']=proof['function_relocation'][operation['attrs']['function']]
            assert current==before[item['original_function']]
            assert hashlib.sha256(json.dumps(current,sort_keys=True,separators=(',',':')).encode()).hexdigest()==item['function_sha256']
        for name,identity in proof['original_sources'].items():
            raw=(ROOT/name).read_bytes()
            assert hashlib.sha256(raw).hexdigest()==identity['sha256']
            assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==identity['blob']
        cls.leaves={key:open_module(os.environ[name]) for key,name in
                    [(1,'HIA_POLICY_MANIFEST'),(2,'HIA_CODEC_MANIFEST'),(4,'HIA_STAT_VERSION_MANIFEST')]}
        original=(ROOT/'src/mcp/runtime/multi_read_host.py').read_bytes()
        assert hashlib.sha256(original).hexdigest()=='6f83b3e1031642e9981310916181858941dec51bb1696a79087beeb60a6e3eb5'
        function=next(n for n in ast.parse(original).body if isinstance(n,ast.FunctionDef) and n.name=='_wire_size')
        namespace={'json':json}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'original_multi_read_host.py','exec'),namespace)
        cls.wire_size=staticmethod(namespace['_wire_size'])

    @classmethod
    def tearDownClass(cls):
        cls.module.close()
        for value in cls.leaves.values():value.close()

    def setUp(self):self.h=FixtureHarness(self.module,self.leaves)

    def good(self,paths,**kw):return {'host':'native-local','paths':paths,**kw}

    def error(self,args,message):
        result=self.h.tool(args)['result']
        self.assertEqual(result,{'content':[{'type':'text','text':message}],'isError':True})

    def test_parameter_and_original_validation_order(self):
        valid=self.good(['/native-test/a'])
        bad=[{},dict(valid,host=None),dict(valid,paths=None),dict(valid,paths=['a',1]),
             dict(valid,unknown=True),dict(valid,max_file_bytes=-1),dict(valid,max_file_bytes=True),
             dict(valid,max_file_bytes=1.0),dict(valid,max_file_bytes=1<<64),
             dict(valid,max_response_bytes='1024')]
        for args in bad:self.assertEqual(self.h.tool(args)['error']['code'],-32602)
        self.error(self.good([]),'read_multiple_files requires 1..16 paths')
        self.error(self.good(['/native-test/a']*17,max_file_bytes=0),'read_multiple_files requires 1..16 paths')
        for limit in [0,65537,U64]:
            self.error(dict(valid,max_file_bytes=limit,max_response_bytes=0),
                       'max_file_bytes must be 1..65536; larger files require binary_read')
        for limit in [0,1023,262145,U64]:
            self.error(dict(valid,max_response_bytes=limit),'max_response_bytes must be 1024..262144')
        for path in ['', '/', 'relative','//x','/a/','/a//b','/a/./b','/a/../b','/a\0b','/'+'x'*4096]:
            self.error(self.good([path]),'batch paths must be bounded absolute paths without empty, dot or traversal components')
        self.error(self.good(['/native-test/a']*2),'read_multiple_files paths must be distinct')
        self.error(dict(valid,host='ssh-other'),'unknown host `ssh-other`; call host_list for configured names')
        self.assertFalse(any(t==3 for t,_ in self.h.calls))

    def test_exact_inner_json_text_and_all_files_before_effects(self):
        fixtures={'/native-test/empty':b'', '/native-test/Unicode 雪😀':'é\n雪😀'.encode(),
                  '/native-test/control"\\\t':bytes(range(32))+b'"\\'}
        self.h.fixtures.update(fixtures)
        for paths in [[p] for p in fixtures]+[list(fixtures)]:
            before=len(self.h.calls)
            response=self.h.tool(self.good(paths))['result']
            expected=expected_result([expected_file(p,fixtures[p]) for p in paths])
            self.assertEqual(response,{'content':[{'type':'text','text':compact(expected)}],'isError':False})
            self.assertEqual([t for t,_ in self.h.calls[before:before+len(paths)]],[1]*len(paths))
        before=sum(t==3 for t,_ in self.h.calls)
        outside='/outside/last'
        self.error(self.good(['/native-test/empty',outside]),
                   f'path `{outside}` is outside configured read roots on host `native-local`')
        self.assertEqual(sum(t==3 for t,_ in self.h.calls),before)

    def test_strict_utf8_and_failure_never_publishes_prior_text(self):
        self.h.fixtures['/native-test/secret']=b'PRIVATE_FIRST_FILE_FRAGMENT'
        for value in [b'\xff',b'\xc0\x80',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',b'\xe2\x82',3,11,12,13,14]:
            self.h.fixtures['/native-test/last']=value
            response=self.h.tool(self.good(['/native-test/secret','/native-test/last']))
            self.assertEqual(response['result'],{'content':[{'type':'text','text':REDACTED}],'isError':True})
            self.assertNotIn('PRIVATE_FIRST_FILE_FRAGMENT',compact(response))
        self.h.fixtures['/native-test/last']='正常'.encode()
        self.assertFalse(self.h.tool(self.good(['/native-test/last']))['result']['isError'])

    def test_exact_original_double_escaped_mcp_byte_budget(self):
        path='/native-test/quote"\\'
        data=(b'\\"\x00\n\t'*300)+'雪😀'.encode()
        self.h.fixtures[path]=data
        expected=expected_result([expected_file(path,data)])
        needed=self.wire_size(expected);COUNTS['original_wire_size_calls']+=1
        self.assertGreater(needed,1024)
        self.error(self.good([path],max_response_bytes=needed-1),REDACTED)
        for limit in [needed,needed+1]:
            result=self.h.tool(self.good([path],max_response_bytes=limit))['result']
            self.assertFalse(result['isError']);self.assertEqual(result['content'][0]['text'],compact(expected))
        self.assertFalse(self.h.tool(self.good([path],max_file_bytes=None,max_response_bytes=None))['result']['isError'])

    def test_full_file_and_sixteen_file_limits(self):
        for index in range(16):self.h.fixtures[f'/native-test/{index}']=str(index).encode()
        paths=list(self.h.fixtures)
        result=self.h.tool(self.good(paths))['result']
        self.assertFalse(result['isError']);self.assertEqual(len(json.loads(result['content'][0]['text'])['files']),16)
        for size in [16384,16385,65536]:
            self.h.fixtures['/native-test/large']=b'a'*size
            if size<=16384:self.assertFalse(self.h.tool(self.good(['/native-test/large']))['result']['isError'])
            else:self.error(self.good(['/native-test/large']),REDACTED)
            self.assertFalse(self.h.tool(self.good(['/native-test/large'],max_file_bytes=65536,max_response_bytes=262144))['result']['isError'])

    def test_replayed_completion_is_not_admitted(self):
        raw=request(self.good(['/native-test/a']))
        self.assertEqual(self.h.native(raw),CALL)
        seq=struct.unpack('<Q',ctypes.string_at(self.h.address+B+8,8))[0]
        self.h.put(B+80,32);self.h.put(B+88,seq+1);self.h.put(B+96,1)
        self.assertEqual(self.h.native(raw),0xffffffff)

    def test_original_rust_validation_corpus(self):
        original=ROOT/'src/mcp/runtime/multi_read.rs'
        original_sha='c0728d40232f18ce6783098cff5a1897f78a4b22f5be0f3c6fec40916455deea'
        self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(),original_sha)
        original_text=original.read_text()
        original_body=original_text[original_text.index('fn validate('):original_text.index('\nfn serialize_result(')].strip()
        oracle=Path(__file__).with_name('oracle_multi_read.rs').read_text()
        self.assertEqual(oracle[oracle.index('fn validate('):oracle.index('\nfn word(')].strip(),original_body)
        unknown='__native_validation_reference__'
        accepted=f'unknown host `{unknown}`; call host_list for configured names'
        requests=[];native=[]
        for paths,file_limit,response_limit in validation_vectors():
            arguments={'host':unknown,'paths':paths,'max_file_bytes':file_limit,'max_response_bytes':response_limit}
            response=self.h.tool(arguments)['result']
            self.assertTrue(response['isError'])
            text=response['content'][0]['text']
            if text==accepted:
                line=f'OK {16384 if file_limit is None else file_limit} {65536 if response_limit is None else response_limit}'
            else:line='ERR '+text.encode().hex()
            requests.append(validation_packet(paths,file_limit,response_limit).hex()+'\n')
            native.append(line+'\n');COUNTS['original_rust_validation_cases']+=1
        self.assertEqual(self.h.calls,[],'typed validation corpus must never dispatch a leaf or IO effect')
        if os.environ.get('HIA_MULTI_READ_CORPUS_DIR'):
            folder=Path(os.environ['HIA_MULTI_READ_CORPUS_DIR']);folder.mkdir(parents=True,exist_ok=False)
            request_raw=''.join(requests).encode();native_raw=''.join(native).encode()
            for name,raw in [('requests.hex.gz',request_raw),('native-output.txt.gz',native_raw)]:
                (folder/name).write_bytes(gzip.compress(raw,mtime=0))
            metadata={'schema':'hepta.runtime.multi-read-validation-corpus.v1','cases':len(native),
                'original_source':'src/mcp/runtime/multi_read.rs','original_source_sha256':original_sha,
                'source_sha256':self.module.metadata['source_sha256'],'image_sha256':self.module.metadata['image_sha256'],
                'scope':'unchanged original validate() after typed parameter admission; accepted cases stop at unknown-host lookup',
                'request_raw_sha256':hashlib.sha256(request_raw).hexdigest(),
                'native_output_raw_sha256':hashlib.sha256(native_raw).hexdigest(),
                'native_output_bytes':len(native_raw),
                'artifacts':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.iterdir()}}
            (folder/'native-corpus.json').write_text(json.dumps(metadata,indent=2,sort_keys=True)+'\n')

if __name__=='__main__':
    result=unittest.main(exit=False,verbosity=2)
    print(json.dumps({'status':'PASS' if result.result.wasSuccessful() else 'FAIL',
                      'scope':'native controller with explicitly synthetic IO completions',
                      'counts':COUNTS},sort_keys=True))
    raise SystemExit(0 if result.result.wasSuccessful() else 1)
