#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual HIA file-info controller; IO completions are explicit test fixtures.

These tests qualify admission, continuation and exact formatting. They do not
claim filesystem reads or substitute for the required real-ELF original-helper
comparison in test_info_service.py.
"""
from pathlib import Path
import ast,ctypes,hashlib,json,os,struct,sys,unittest
ROOT=Path(os.environ.get('HIA_RUNTIME_REPO',Path(__file__).resolve().parents[2]))
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_loader import NativeModule
COUNTS={'requests':0,'native_controller_calls':0,'native_leaf_calls':0,'fixture_io_calls':0}
CALL=0xffffffe0
WIDTH=32<<20
OUTPUT=8<<20
B=WIDTH-256
METADATA_SHA='24b9df89816536db16dd35a74d6460b1a215981a00798393a00853da6077f5d3'

def compact(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))
def request(arguments,identity='id"\n雪😀'):
    return compact({'jsonrpc':'2.0','method':'tools/call','id':identity,
                    'params':{'name':'file_info','arguments':arguments}}).encode()
def open_module(path):
    path=Path(path)
    return NativeModule(path,manifest_sha256=hashlib.sha256(path.read_bytes()).hexdigest())

def info_frame(rid,data=b'abc',attrs=None,uid=34,gid=56,mode=0o640,nlink=2,initial_mode=0o6754):
    attrs={} if attrs is None else attrs
    payload=b'HIAINF01'+struct.pack('<7Q',uid,gid,mode,nlink,len(attrs),0,0)
    payload+=hashlib.sha256(data).digest()+hashlib.sha256(attrs.get('system.posix_acl_access',b'')).digest()
    for name,value in sorted(attrs.items()):
        raw=name.encode();payload+=struct.pack('<Q',len(raw))+raw+hashlib.sha256(value).digest()
    words=(1,2,len(data),3,4,5,6)
    return b'HIARR001'+struct.pack('<15Q',rid,0,0,len(payload),0,0,0,*words,initial_mode)+payload

class FixtureHarness:
    def __init__(self,module,leaves,root=b'/native-test',output_capacity=OUTPUT):
        self.module=module;self.leaves=leaves;self.root=root
        self.output_capacity=output_capacity
        self.output=ctypes.create_string_buffer(output_capacity+16)
        self.work=ctypes.create_string_buffer(WIDTH+16)
        self.address=ctypes.addressof(self.work)
        self.sequence=0;self.calls=[];self.fixtures={};self.response_override=None
        self.put(B+120,3)
        assert self.run(root)==(0,b'')

    def put(self,offset,value):
        ctypes.memmove(self.address+offset,struct.pack('<Q',value),8)

    def native(self,raw):
        source=ctypes.create_string_buffer(raw,max(1,len(raw)))
        ctypes.memset(ctypes.addressof(self.output)+self.output_capacity,0xa5,16)
        ctypes.memset(self.address+WIDTH,0x5a,16)
        code=self.module._entry(source,len(raw),self.output,self.output_capacity,self.work,WIDTH)
        COUNTS['native_controller_calls']+=1
        assert source.raw==(raw or b'\0')
        assert ctypes.string_at(ctypes.addressof(self.output)+self.output_capacity,16)==b'\xa5'*16
        assert ctypes.string_at(self.address+WIDTH,16)==b'\x5a'*16
        return code

    def fixture_io(self,frame):
        assert frame[:8]==b'HIARD001'
        rid,op,offset,limit,flag,*tail=struct.unpack('<13Q',frame[8:112])
        assert op==3 and offset==limit==flag==0 and tail[:7]==[0]*7
        assert tail[7]==len(frame)-112
        if self.response_override is not None:return self.response_override(rid)
        value=self.fixtures.get(frame[112:].decode())
        if value is None:return b'HIARR001'+struct.pack('<15Q',rid,3,2,*(0,)*12)
        return info_frame(rid,**value)

    def run(self,raw):
        for _ in range(20):
            code=self.native(raw)
            if code!=CALL:
                if code>=0xffff0000:return code,None
                assert code<=self.output_capacity
                return code,ctypes.string_at(self.output,code)
            words=struct.unpack('<14Q',ctypes.string_at(self.address+B,112))
            magic,seq,target,region,start,size,oregion,ostart,capacity,reserved,result,ack,done,denied=words
            assert magic==int.from_bytes(b'HIACAL01','little') and seq==self.sequence+1
            assert region==oregion==2 and target in (1,3,4)
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
                    workspace_capacity={1:32768,4:256}[target])
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
        cls.module=open_module(os.environ['HIA_FILE_INFO_MANIFEST'])
        cls.leaves={key:open_module(os.environ[name]) for key,name in
                    [(1,'HIA_POLICY_MANIFEST'),(4,'HIA_STAT_VERSION_MANIFEST')]}
        original=(ROOT/'src/mcp/runtime/file_metadata.py').read_bytes()
        assert hashlib.sha256(original).hexdigest()==METADATA_SHA
        function=next(n for n in ast.parse(original).body if isinstance(n,ast.FunctionDef) and n.name=='metadata_summary')
        namespace={'hashlib':hashlib,'sys':sys}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'original_file_metadata.py','exec'),namespace)
        cls.summary=staticmethod(namespace['metadata_summary'])

    @classmethod
    def tearDownClass(cls):
        cls.module.close()
        for value in cls.leaves.values():value.close()
        assert hashlib.sha256((ROOT/'src/mcp/runtime/file_metadata.py').read_bytes()).hexdigest()==METADATA_SHA

    def setUp(self):self.h=FixtureHarness(self.module,self.leaves)
    def good(self,path='/native-test/a'):return {'host':'native-local','path':path}

    def test_exact_original_summary_text_and_two_mode_snapshots(self):
        snapshots=[{}, {'user.z':b'last','user.a':b'', 'user.quote"\\\n\t雪😀':bytes(range(256))},
                   {'system.posix_acl_access':b'actual typed ACL bytes','user.binary':b'\0\xff'},
                   {f'user.item-{i:03}':str(i).encode() for i in range(256)}]
        for attrs in snapshots:
            path='/native-test/a';data=b'not necessarily UTF8\xff'
            self.h.fixtures[path]={'data':data,'attrs':attrs}
            expected={'path':path,'size':len(data),'version':f'1:2:{len(data)}:3000000004:5000000006',
                      'sha256':hashlib.sha256(data).hexdigest(),'mode':0o6754,
                      'metadata':self.summary({'uid':34,'gid':56,'mode':0o640,'nlink':2,'xattrs':attrs,'acl':None})}
            result=self.h.tool(self.good())['result']
            self.assertEqual(result,{'content':[{'type':'text','text':compact(expected)}],'isError':False})
            self.assertNotEqual(expected['mode'],expected['metadata']['mode'])

    def test_typed_admission_and_policy_before_io(self):
        args=self.good()
        bad=[{},dict(args,host=None),dict(args,path=None),dict(args,host=[]),dict(args,path=3),
             dict(args,offset=0),dict(args,root='/'),dict(args,expected_version='anything')]
        for value in bad:self.assertEqual(self.h.tool(value)['error']['code'],-32602)
        expected='unknown host `remote-alias`; call host_list for configured names'
        result=self.h.tool(dict(args,host='remote-alias',path='relative'))['result']
        self.assertEqual(result,{'content':[{'type':'text','text':expected}],'isError':True})
        self.assertEqual(self.h.calls,[])
        outside='/outside/a'
        result=self.h.tool(self.good(outside))['result']
        self.assertEqual(result['content'][0]['text'],f'path `{outside}` is outside configured read roots on host `native-local`')
        self.assertTrue(result['isError']);self.assertFalse(any(t==3 for t,_ in self.h.calls))

    def test_invalid_result_headers_and_name_records_fail_closed(self):
        def word(frame,offset,value):
            b=bytearray(frame);struct.pack_into('<Q',b,offset,value);return bytes(b)
        edits=[lambda f:word(f,8,999),lambda f:word(f,24,1),lambda f:word(f,32,len(f)-127),
               lambda f:word(f,40,1),lambda f:word(f,48,1),lambda f:word(f,56,1),
               lambda f:word(f,120,4096),lambda f:word(f,128,0),lambda f:word(f,136,1<<32),
               lambda f:word(f,144,1<<32),lambda f:word(f,152,4096),lambda f:word(f,168,257),
               lambda f:word(f,176,1),lambda f:word(f,184,1),lambda f:f+b'junk']
        for change in edits:
            h=FixtureHarness(self.module,self.leaves)
            h.response_override=lambda rid,change=change:change(info_frame(rid))
            self.assertEqual(h.run(request(self.good()))[0],0xffffffff)
        malformed=[{'user.\0name':b'x'},{'u'*256:b'x'}]
        for attrs in malformed:
            h=FixtureHarness(self.module,self.leaves)
            h.response_override=lambda rid,attrs=attrs:info_frame(rid,attrs=attrs)
            self.assertEqual(h.run(request(self.good()))[0],0xffffffff)
        def custom(rid,records,count):
            frame=bytearray(info_frame(rid));frame+=records
            struct.pack_into('<Q',frame,32,len(frame)-128);struct.pack_into('<Q',frame,168,count)
            return bytes(frame)
        record=lambda name:struct.pack('<Q',len(name))+name+b'\0'*32
        cases=[(record(b'user.b')+record(b'user.a'),2),(record(b'user.a')*2,2),
               (record(b'user.\xff'),1),(struct.pack('<Q',(1<<64)-1)+b'\0'*32,1)]
        for rows,count in cases:
            h=FixtureHarness(self.module,self.leaves)
            h.response_override=lambda rid,rows=rows,count=count:custom(rid,rows,count)
            self.assertEqual(h.run(request(self.good()))[0],0xffffffff)

    def test_replayed_completion_refuses(self):
        raw=request(self.good())
        self.assertEqual(self.h.native(raw),CALL)
        seq=struct.unpack('<Q',ctypes.string_at(self.h.address+B+8,8))[0]
        self.h.put(B+80,32);self.h.put(B+88,seq+1);self.h.put(B+96,1)
        self.assertEqual(self.h.native(raw),0xffffffff)

    def test_every_declared_info_error_and_capacity_recovery(self):
        messages={7:'file changed while hashing',13:'file changed during metadata inspection',
                  14:'native local extended attribute name is not valid UTF-8',
                  15:'native local file inspection deadline exceeded',
                  16:'native local extended attribute inspection failed (errno 61)',
                  17:'metadata budget exceeded',18:'source metadata changed during capture',
                  19:'native local deadline setup failed (errno 22)'}
        for status,message in messages.items():
            errno={16:61,19:22}.get(status,0)
            self.h.response_override=lambda rid,status=status,errno=errno:b'HIARR001'+struct.pack('<15Q',rid,status,errno,*(0,)*12)
            self.assertEqual(self.h.tool(self.good())['result'],{'content':[{'type':'text','text':message}],'isError':True})
        h=FixtureHarness(self.module,self.leaves,output_capacity=4<<20)
        h.fixtures['/native-test/a']={'data':b'capacity'}
        self.assertEqual(h.run(request(self.good(),identity='x'*(4<<20)))[0],0xfffffffe)
        self.assertFalse(h.tool(self.good())['result']['isError'])

    def test_source_composition(self):
        import copy
        sys.path.insert(0,os.environ['HIA_HEPTA_DIR'])
        from hepta.hia_agent_assembly import assemble_program
        source=Path(os.environ.get('HIA_INFO_SERVICE_SOURCE',ROOT/'native/file_info_service.hepta'))
        proof=json.loads(source.with_name('file_info_service_composition.json').read_bytes())
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),proof['native_source_sha256'])
        self.assertEqual(proof['native_source_sha256'],self.module.metadata['source_sha256'])
        original=ROOT/proof['protocol_source']
        self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(),proof['protocol_source_sha256'])
        before={f['name']:f for f in assemble_program(original.read_bytes()).as_dict()['functions']}
        after={f['name']:f for f in assemble_program(source.read_bytes()).as_dict()['functions']}
        for item in proof['parser_imports']:
            current=copy.deepcopy(after[item['destination_function']]);current['name']=item['original_function']
            for block in current['blocks']:
                for op in block['ops']:
                    if op['op']=='call':op['attrs']['function']=proof['function_relocation'][op['attrs']['function']]
            self.assertEqual(current,before[item['original_function']])
            self.assertEqual(hashlib.sha256(json.dumps(current,sort_keys=True,separators=(',',':')).encode()).hexdigest(),item['function_sha256'])
        for path,identity in proof['original_sources'].items():
            raw=(ROOT/path).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(),identity['sha256'])
            self.assertEqual(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),identity['blob'])

if __name__=='__main__':
    result=unittest.main(exit=False,verbosity=2)
    proof={'schema':'hepta.runtime.file-info-controller-test.v1',
           'status':'pass' if result.result.wasSuccessful() else 'fail','counts':COUNTS,
           'io_completions':'explicit synthetic fixtures, not filesystem observations',
           'original_metadata_sha256':METADATA_SHA}
    if hasattr(ControllerTests,'module'):
        proof.update(source_sha256=ControllerTests.module.metadata['source_sha256'],
                     image_sha256=ControllerTests.module.metadata['image_sha256'])
    if os.environ.get('HIA_FILE_INFO_RESULT'):Path(os.environ['HIA_FILE_INFO_RESULT']).write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n')
    print(json.dumps(proof,sort_keys=True));raise SystemExit(0 if result.result.wasSuccessful() else 1)
