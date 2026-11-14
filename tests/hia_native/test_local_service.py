#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual static-ELF MCP qualification; original Python is a test oracle only."""
from __future__ import annotations
import ctypes,hashlib,importlib.util,json,os,random,select,struct,subprocess,sys,tempfile,time,unittest
from pathlib import Path
ROOT=Path(os.environ.get('HIA_RUNTIME_REPO',Path(__file__).resolve().parents[2]))
sys.path.insert(0,str(ROOT/'scripts'))
COUNTS={'elf_requests':0,'original_read_comparisons':0,'protocol_errors':0,'domain_errors':0,'native_controller_calls':0}
ORIGINAL_SHA='c15e8900b0ab867b221ff08d5a10401c8b656c87676f57b478b9a21219f7fe12'
def compact(v):return json.dumps(v,ensure_ascii=False,separators=(',',':'))
def req(method,params=None,identity=1):
 v={'jsonrpc':'2.0','id':identity,'method':method}
 if params is not None:v['params']=params
 return compact(v).encode()
def init(identity=1):return req('initialize',{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'native-test','version':'1'}},identity)
class Session:
 def __init__(self,executable,root):
  self.proc=subprocess.Popen([str(executable),'--local-read-profile',str(root)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''});self.buffer=b''
 def send(self,raw,fragmented=False):
  raw+=b'\n';step=3 if fragmented else len(raw)
  for at in range(0,len(raw),step):self.proc.stdin.write(raw[at:at+step]);self.proc.stdin.flush()
 def receive(self):
  deadline=time.monotonic()+10
  while b'\n' not in self.buffer:
   left=deadline-time.monotonic()
   if left<=0 or not select.select([self.proc.stdout],[],[],left)[0]:raise AssertionError('service response timed out')
   part=os.read(self.proc.stdout.fileno(),65536)
   if not part:raise AssertionError(('early exit',self.proc.poll(),self.proc.stderr.read()))
   self.buffer+=part
  line,self.buffer=self.buffer.split(b'\n',1);COUNTS['elf_requests']+=1;return json.loads(line)
 def call(self,raw,**kw):self.send(raw,**kw);return self.receive()
 def ready(self):
  assert self.call(init())['result']['protocolVersion']=='2025-06-18'
  self.send(b'{"jsonrpc":"2.0","method":"notifications/initialized"}')
 def tool(self,name,arguments=None,identity=1,raw=False):
  params={'name':name}
  if arguments is not None:params['arguments']=arguments
  response=self.call(req('tools/call',params,identity))
  if raw:return response
  result=response['result'];assert set(result)=={'content','isError'} and len(result['content'])==1,result
  assert set(result['content'][0])=={'type','text'} and result['content'][0]['type']=='text',result
  return result['isError'],result['content'][0]['text']
 def close(self):
  self.proc.stdin.close();status=self.proc.wait(timeout=10)
  extra=self.buffer+self.proc.stdout.read();errors=self.proc.stderr.read()
  self.proc.stdout.close();self.proc.stderr.close()
  if status or extra or errors:raise AssertionError((status,extra,errors))
 def __enter__(self):return self
 def __exit__(self,kind,*rest):
  if kind:
   self.proc.kill();self.proc.wait(timeout=10)
   for stream in [self.proc.stdin,self.proc.stdout,self.proc.stderr]:stream.close()
  else:self.close()
class NativeServiceTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.manifest=Path(os.environ['HIA_SERVICE_MANIFEST']).resolve(strict=True);cls.metadata=json.loads(cls.manifest.read_bytes())
  cls.executable=cls.manifest.parent/cls.metadata['executable']
  assert hashlib.sha256(cls.executable.read_bytes()).hexdigest()==cls.metadata['executable_sha256']
  assert cls.executable.read_bytes()[:4]==b'\x7fELF'
  assert cls.metadata['runtime_python_required'] is False and cls.metadata['runtime_libc_required'] is False
  assert cls.metadata['inspection']['dynamic_loader'] is False
  for member in cls.metadata['members']:
   owner=cls.manifest.parent/member['manifest']
   assert hashlib.sha256(owner.read_bytes()).hexdigest()==member['manifest_sha256']
  cls.controller_manifest=cls.manifest.parent/cls.metadata['members'][0]['manifest']
  source=Path(os.environ.get('HIA_SERVICE_SOURCE',ROOT/'native/local_service.hepta'))
  assert hashlib.sha256(source.read_bytes()).hexdigest()==cls.metadata['members'][0]['source_sha256']
  original=ROOT/'src/mcp/runtime/binary_file.py';assert hashlib.sha256(original.read_bytes()).hexdigest()==ORIGINAL_SHA
  spec=importlib.util.spec_from_file_location('hia_local_service_original_read',original)
  cls.original=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.original)
 def test_source_composition(self):
  import copy
  sys.path.insert(0,os.environ['HIA_HEPTA_DIR'])
  from hepta.hia_agent_assembly import assemble_program
  source=Path(os.environ.get('HIA_SERVICE_SOURCE',ROOT/'native/local_service.hepta'))
  proof=json.loads(source.with_name('local_service_composition.json').read_bytes())
  self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),proof['source_sha256'])
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
  for name,identity in proof['original_sources'].items():
   raw=(ROOT/name).read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),identity['sha256'])
   self.assertEqual(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),identity['blob'])
 def test_protocol_and_host_list(self):
  with tempfile.TemporaryDirectory() as directory,Session(self.executable,directory) as service:
   self.assertEqual(service.call(req('tools/list'))['error']['code'],-32002);service.ready()
   catalog=service.call(req('tools/list'))['result']['tools'];self.assertEqual([v['name'] for v in catalog],['host_list','binary_read'])
   self.assertTrue(all(v['annotations']['readOnlyHint'] for v in catalog))
   error,text=service.tool('host_list',{})
   expected={'hosts':[{'name':'native-local','platform':'linux','execution_mode':'operator','operator_tools':True,'allow_execute':False,'allow_pty':False,'allow_write':False,'privileged_actions':[]}]}
   self.assertFalse(error);self.assertEqual(text,json.dumps(expected,ensure_ascii=False,sort_keys=True,indent=2))
   self.assertEqual(service.tool('host_list'),(error,text))
   self.assertEqual(service.call(req('tools/call',{'name':'host_list','arguments':None}))['result']['content'][0]['text'],text)
   for bad in [b'{',b'[]',b'{"jsonrpc":"2.0","id":8,"method":"ping","method":"ping"}',b'{"jsonrpc":"2.0","id":8,"method":"ping","params":[]}']:
    self.assertIn('error',service.call(bad));COUNTS['protocol_errors']+=1
   identity='quote" slash\\ tab\t newline\n null\0 雪😀';response=service.call(req('ping',identity=identity))
   self.assertEqual(response['id'],identity);self.assertEqual(response['result'],{})
   service.send(req('tools/call',{'name':'host_list','arguments':{}}));service.send(req('ping',identity=17))
   self.assertIn('result',service.receive());self.assertEqual(service.receive()['id'],17)
   self.assertEqual(service.call(init())['error']['code'],-32002)
 def compare_original(self,service,root,args):
  q={'op':'read','root':str(root),'path':args['path'],'offset':args.get('offset'),'limit':max(1,min(65536,32768 if args.get('limit') is None else args['limit'])),'expected_version':args.get('expected_version')}
  expected=self.original.main(q);error,text=service.tool('binary_read',args,identity='ID 雪"\n')
  self.assertFalse(error,text);self.assertEqual(json.loads(text),expected)
  self.assertEqual(text,json.dumps(expected,ensure_ascii=False,sort_keys=True,separators=(',',':')));COUNTS['original_read_comparisons']+=1
 def test_original_success_results(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);rng=random.Random(0x485341)
   samples=[b'',b'abc',bytes(range(256))*300,rng.randbytes(140003),b'zero\0\xffend'];paths=[]
   for name,data in zip(['empty','plain','all-bytes','large','quote"\\\n\t 雪😀'],samples):
    p=root/name;p.write_bytes(data);paths.append(p)
   with Session(self.executable,root) as service:
    service.ready()
    for path,data in zip(paths,samples):
     version=self.original.version(path.stat())
     for offset in sorted({0,len(data)//2,len(data)}):
      for limit in [None,0,1,3,32768,65536,65537,(1<<64)-1]:self.compare_original(service,root,{'host':'native-local','path':str(path),'offset':offset,'limit':limit,'expected_version':version})
     for optional in [{},{'offset':None,'limit':None,'expected_version':None}]:self.compare_original(service,root,{'host':'native-local','path':str(path),**optional})
     position=0
     while True:
      error,text=service.tool('binary_read',{'host':'native-local','path':str(path),'offset':position,'limit':4093,'expected_version':version})
      self.assertFalse(error);result=json.loads(text)
      import base64
      decoded=base64.b64decode(result['data_base64'],validate=True)
      self.assertEqual(decoded,data[position:position+4093]);self.assertEqual(result['chunk_sha256'],hashlib.sha256(decoded).hexdigest());self.assertEqual(result['version'],version)
      position=result['next_offset']
      if result['eof']:break
     self.assertEqual(position,len(data))
    link=root/'hardlink';os.link(paths[1],link)
    for path in [str(link),str(root)+'/./plain',str(root)+'//plain']:self.compare_original(service,root,{'host':'native-local','path':path})
 def test_parameters_errors_and_order(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);path=root/'file';path.write_bytes(b'abc');outside=str(root.parent/'outside-native-local-test');version=self.original.version(path.stat())
   with Session(self.executable,root) as service:
    service.ready();args={'host':'native-local','path':str(path)}
    invalid=[{},dict(args,unknown=1),dict(args,host=None),dict(args,path=1),dict(args,offset=-1),dict(args,offset=1.0),dict(args,offset=True),dict(args,offset=1<<64),dict(args,limit=-1),dict(args,limit=1.0),dict(args,limit=False),dict(args,expected_version=1),dict(args,expected_version=[])]
    for item in invalid:
     response=service.tool('binary_read',item,raw=True);self.assertEqual(response['error']['code'],-32602,response);COUNTS['protocol_errors']+=1
    for item in [[],{'wrong':True},'x']:
     response=service.tool('host_list',item,raw=True);self.assertEqual(response['error']['code'],-32602);COUNTS['protocol_errors']+=1
    def err(item,expected):
     failed,text=service.tool('binary_read',item);self.assertTrue(failed,text);self.assertEqual(text,expected);COUNTS['domain_errors']+=1
    err(dict(args,host='ssh-main',path='not-absolute'),'unknown host `ssh-main`; call host_list for configured names')
    err(dict(args,path='not-absolute'),'remote file access requires an absolute target path')
    err(dict(args,path=str(root)+'/../file'),'remote path traversal is not allowed')
    err(dict(args,path=outside),f'path `{outside}` is outside configured read roots on host `native-local`')
    err(dict(args,path=str(root)),'capability root and runtime sidecars are not file targets')
    err(dict(args,path=str(root/'.hepta-hidden')),'capability root and runtime sidecars are not file targets')
    err(dict(args,path=str(root/'null')+'\0suffix'),'embedded null byte')
    err(dict(args,path=str(root)+'/'+'a'*4096),'path exceeds the native-local 4095-byte limit')
    err(dict(args,offset=4),'read cursor outside file');err(dict(args,offset=(1<<64)-1),'read cursor outside file')
    for expected in ['',version+' ','0'+version,'+'+version,'x'*123,'雪\0😀',version.replace(':',':+',1)]:err(dict(args,expected_version=expected,offset=(1<<64)-1),'source version changed')
    err(dict(args,path=str(root/'missing'),expected_version='noncanonical',offset=(1<<64)-1),'native local open failed (errno 2)')
    symlink=root/'symlink';symlink.symlink_to(path)
    err(dict(args,path=str(symlink),expected_version='noncanonical'),'native local open failed (errno 40)')
    directory_target=root/'directory';directory_target.mkdir()
    err(dict(args,path=str(directory_target),expected_version='noncanonical'),'invalid regular file or private sidecar')
    changed=self.original.version(path.stat());path.write_bytes(b'changed-size');err(dict(args,expected_version=changed),'source version changed')
    self.compare_original(service,root,args)
 def test_root_custody_and_framing(self):
  with tempfile.TemporaryDirectory() as directory:
   parent=Path(directory);root=parent/'root';root.mkdir();(root/'value').write_bytes(b'old inode')
   with Session(self.executable,root) as service:
    service.ready();error,text=service.tool('binary_read',{'host':'native-local','path':str(root/'value')});self.assertFalse(error);first=json.loads(text)
    root.rename(parent/'retained');root.mkdir();(root/'value').write_bytes(b'replacement')
    error,text=service.tool('binary_read',{'host':'native-local','path':str(root/'value')});self.assertFalse(error);self.assertEqual(json.loads(text),first)
    self.assertEqual(service.call(req('ping',identity=33),fragmented=True)['id'],33)
   raw=init()+b'\n'+b'{"jsonrpc":"2.0","method":"notifications/initialized"}'+b'\n'+req('ping',identity=7)
   done=subprocess.run([str(self.executable),'--local-read-profile',str(root)],input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''},timeout=10)
   self.assertEqual(done.returncode,0,done.stderr);self.assertEqual([json.loads(x)['id'] for x in done.stdout.splitlines()],[1,7]);COUNTS['elf_requests']+=2
 def test_native_controller_capacity_and_ack(self):
  from hia_native_loader import NativeModule
  manifest=self.controller_manifest
  with NativeModule(manifest,manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest()) as module:
   with module.session(output_capacity=4<<20,workspace_capacity=32<<20) as session:
    b=(32<<20)-256;address=ctypes.addressof(session._workspace)
    def put(at,value):ctypes.memmove(address+at,struct.pack('<Q',value),8)
    def call(raw,kind):put(b+120,kind);COUNTS['native_controller_calls']+=1;return session.invoke_raw(raw)
    code,_,work=call(b'/tmp',0);self.assertEqual(code,0xffffffe0);seq=struct.unpack_from('<Q',work,b+8)[0]
    put(b+80,0);put(b+88,seq+1);put(b+96,1);self.assertEqual(call(b'/tmp',0)[0],0xffffffff)
    put(b+88,seq);self.assertEqual(call(b'/tmp',0)[0],0)
    # Declared synthetic startup completion isolates protocol state. This test
    # never claims a filesystem read or supplies a production runtime fallback.
    code,_,work=call(init('x'*(4<<20)),1);self.assertEqual(code,0xfffffffe)
    self.assertEqual(struct.unpack_from('<Q',work,(32<<20)-4096+520)[0],0)
    code,out,work=call(init(),1);self.assertLess(code,0xffff0000);self.assertIn('result',json.loads(out[:code]))
    self.assertEqual(struct.unpack_from('<Q',work,(32<<20)-4096+520)[0],1)
    self.assertEqual(call(b'{"jsonrpc":"2.0","method":"notifications/initialized"}',1)[0],0)
    code,out,_=call(req('tools/list'),1);self.assertEqual(len(json.loads(out[:code])['result']['tools']),2)

if __name__=='__main__':
 result=unittest.main(exit=False,verbosity=2)
 proof={'schema':'hepta.runtime.native-local-service-test.v1','counts':COUNTS,'status':'pass' if result.result.wasSuccessful() else 'fail','original_helper_sha256':ORIGINAL_SHA}
 if hasattr(NativeServiceTests,'metadata'):
  proof.update(manifest_sha256=hashlib.sha256(NativeServiceTests.manifest.read_bytes()).hexdigest(),executable_sha256=NativeServiceTests.metadata['executable_sha256'])
 if os.environ.get('HIA_SERVICE_RESULT'):Path(os.environ['HIA_SERVICE_RESULT']).write_text(json.dumps(proof,indent=2,sort_keys=True)+'\n')
 print(json.dumps(proof,sort_keys=True));raise SystemExit(0 if result.result.wasSuccessful() else 1)
