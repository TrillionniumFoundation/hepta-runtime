"""Independent oracle and adversarial checks of the emitted HIA protocol image."""
from __future__ import annotations
import argparse,ctypes,hashlib,importlib.util,json,os,random,struct,subprocess,sys,time
from pathlib import Path
PARSER=argparse.ArgumentParser()
PARSER.add_argument('--hepta',type=Path,default=os.environ.get('HIA_HEPTA_DIR'))
PARSER.add_argument('--source',type=Path,default=os.environ.get('HIA_PROTOCOL_SOURCE',Path(__file__).resolve().parents[2]/'native/runtime_protocol.hepta'))
PARSER.add_argument('--manifest',type=Path,default=os.environ.get('HIA_PROTOCOL_MANIFEST'))
PARSER.add_argument('--loader',type=Path,default=os.environ.get('HIA_NATIVE_LOADER',Path(__file__).resolve().parents[2]/'scripts/hia_native_loader.py'))
PARSER.add_argument('--vm-only',action='store_true')
ARGS=None
MAX_NODES=262144
MAX_DEPTH=128
NONE=(1<<64)-1
COUNTS={}
def count(kind):COUNTS[kind]=COUNTS.get(kind,0)+1

def sizes(n):
 bound=min(MAX_NODES,(n+1)//2+1)
 arena=max(128+(MAX_DEPTH+1)*32,64+bound*56+n)+4096
 keys=2
 while keys<min(MAX_NODES,n//4+1)*2:keys*=2
 return max(keys*8,128+(MAX_DEPTH+1)*48),arena

class VM:
 def __init__(self):
  from hepta.hia_agent_assembly import assemble_program
  self.checked=assemble_program(ARGS.source.read_bytes())
 def __call__(self,raw):
  from hepta.hia_program_runtime import _Machine,_Owner,_View
  output,scratch=sizes(len(raw))
  owners=[_Owner(-1,bytearray(raw)),_Owner(-2,bytearray(output)),_Owner(-3,bytearray(scratch))]
  machine=_Machine(self.checked,50_000_000,64<<20,None,128)
  code=machine.invoke(self.checked.as_dict()['functions'][0],[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
  assert code<0xffffff00,(raw,code)
  return bytes(owners[1].data[:code])

class Native:
 def __init__(self,manifest):
  spec=importlib.util.spec_from_file_location('hia_native_loader',ARGS.loader)
  loader=importlib.util.module_from_spec(spec);spec.loader.exec_module(loader)
  self.manifest=json.loads(manifest.read_bytes())
  assert self.manifest['source_sha256']==hashlib.sha256(ARGS.source.read_bytes()).hexdigest()
  self.loader=loader
  self.native=loader.NativeModule(manifest,manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest())
  self.session=None
  self.reset()
 def reset(self):
  if self.session:self.session.close()
  self.session=self.native.session(output_capacity=1<<20,workspace_capacity=8<<20)
 def raw(self,raw,output_size=None,scratch_size=None):
  output,scratch=sizes(len(raw))
  if output_size is not None:output=output_size
  if scratch_size is not None:scratch=scratch_size
  s=ctypes.create_string_buffer(raw,max(1,len(raw)))
  o=ctypes.create_string_buffer(b'\xa5'*output,output)
  w=ctypes.create_string_buffer(b'\x5a'*scratch,scratch)
  code=self.native._entry(s,len(raw),o,output,w,scratch)
  assert s.raw[:len(raw)]==raw
  return code,o.raw,w.raw
 def __call__(self,raw):
  return self.session.invoke(raw)

def request(method='ping',id=1,params=None,**kw):
 obj={'jsonrpc':'2.0','id':id,'method':method}
 if params is not None:obj['params']=params
 obj.update(kw)
 return json.dumps(obj,ensure_ascii=False,separators=(',',':')).encode()

def value(kernel,raw):
 data=kernel(raw)
 return json.loads(data) if data else None

def check_error(kernel,raw,code,id=None):
 answer=value(kernel,raw)
 assert answer and answer.get('jsonrpc')=='2.0' and answer.get('id')==id and answer.get('error',{}).get('code')==code,(raw,answer,code,id)
 count('error_cases')

def smoke(kernel):
 for id in [1,'abc',-1,'é😀\x00\n"\\']:
  answer=value(kernel,request(id=id))
  assert answer=={'jsonrpc':'2.0','id':id,'result':{}},answer
  count('smoke')
 check_error(kernel,b'{}',-32600)
 check_error(kernel,b'{',-32700)
 assert value(kernel,b'{"jsonrpc":"2.0","method":"notifications/initialized"}') is None
 count('smoke')

def init_params(protocol='2025-06-18'):
 return {'protocolVersion':protocol,'capabilities':{},'clientInfo':{'name':'tests','version':'1'}}

def ready(kernel):
 kernel.reset()
 assert 'result' in value(kernel,request('initialize',params=init_params()))
 assert kernel(b'{"jsonrpc":"2.0","method":"notifications/initialized"}')==b''

def native_checks(kernel):
 smoke(kernel)
 kernel.reset()
 check_error(kernel,request('tools/list'),-32002,1)
 assert kernel(b'{"jsonrpc":"2.0","method":"notifications/initialized"}')==b''
 check_error(kernel,request('tools/list'),-32002,1)
 assert 'result' in value(kernel,request('initialize',params=init_params()))
 check_error(kernel,request('tools/list'),-32002,1)
 assert kernel(b'{"jsonrpc":"2.0","method":"notifications/initialized","params":[]}')==b''
 check_error(kernel,request('tools/list'),-32002,1)
 assert kernel(b'{"jsonrpc":"2.0","method":"notifications/initialized"}')==b''
 assert 'result' in value(kernel,request('tools/list'))
 check_error(kernel,request('initialize',params=init_params()),-32002,1)
 count('session_lifecycle')
 for protocol in ['2024-11-05','2025-03-26','2025-06-18','unknown-future']:
  kernel.reset()
  params={'protocolVersion':protocol,'capabilities':{},'clientInfo':{'name':'tests','version':'1'}}
  answer=value(kernel,request('initialize',params=params))
  expected='2025-06-18'
  assert answer['result']['protocolVersion']==expected,answer
  assert answer['result']['capabilities']=={'tools':{}},answer
  count('initialize')
 for params in [{},{'protocolVersion':'2025-06-18'},{'protocolVersion':1,'capabilities':{},'clientInfo':{}},{'protocolVersion':'2025-06-18','capabilities':[],'clientInfo':{}},{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'n','version':None}}]:
  kernel.reset()
  check_error(kernel,request('initialize',params=params),-32602,1)
 kernel.reset()
 check_error(kernel,request('initialize'),-32602,1)
 ready(kernel)
 for method in ['ping','tools/list']:
  answer=value(kernel,request(method,params={}))
  assert 'result' in answer
  count('methods')
 catalog=value(kernel,request('tools/list'))['result']['tools']
 assert [t['name'] for t in catalog]==['runtime_native_info','runtime_line_hash'],catalog
 assert catalog[0]['inputSchema']['additionalProperties'] is False
 result=value(kernel,request('tools/call',params={'name':catalog[0]['name'],'arguments':{}}))['result']
 assert result['isError'] is False
 assert json.loads(result['content'][0]['text'])==result['structuredContent']
 assert result['structuredContent']['language']=='HIA'
 assert value(kernel,request('tools/call',params={'name':'runtime_native_info'}))['result']==result
 count('tool_results')
 def old_line_hash(text):
  h=2166136261
  for byte in text.encode('utf-8'):h=((h^byte)*16777619)&0xffffffff
  h=(h>>16)^(h&0xffff)
  return format((h>>8)^(h&0xff),'02x')
 for text in ['', 'hello', 'hello world', 'é😀漢', '\x00\n\"\\', *('x'*i for i in range(100))]:
  expected=old_line_hash(text)
  for escaped in [True,False]:
   obj={'jsonrpc':'2.0','id':'hash','method':'tools/call','params':{'name':'runtime_line_hash','arguments':{'text':text}}}
   raw=json.dumps(obj,ensure_ascii=escaped).encode()
   result=value(kernel,raw)['result']
   assert result=={'content':[{'type':'text','text':expected}],'structuredContent':{'lineHash':expected},'isError':False},(text,result)
   count('line_hash_cases')
 for arguments in [None,{},[],{'text':None},{'text':1},{'text':'a','extra':True}]:
  params={'name':'runtime_line_hash'}
  if arguments is not None:params['arguments']=arguments
  check_error(kernel,request('tools/call',params=params),-32602,1)
 for params in [{'name':'missing'},{'name':None}]:
  check_error(kernel,request('tools/call',params=params),-32602,1)
 for params in [[],{'name':'runtime_native_info','arguments':[]},{'name':'runtime_native_info','arguments':{'extra':True}},{}]:
  check_error(kernel,request('tools/call',params=params),-32602,1)
 check_error(kernel,request('tools/call'),-32602,1)
 check_error(kernel,request('tools/list',params={'cursor':'any'}),-32602,1)
 for method in ['unknown','tools/call/','Initialize','notifications/cancelled','notifications/initialized']:
  check_error(kernel,request(method),-32600 if method.startswith('notifications/') else -32601,1)
 for raw in [b'[]',b'null',b'1',b'"x"',b'[{"jsonrpc":"2.0","id":1,"method":"ping"}]',b'{"jsonrpc":"2.0","id":1}',b'{"jsonrpc":"1.0","method":"ping","id":1}',b'{"jsonrpc":"2.0","method":1,"id":1}']:
  check_error(kernel,raw,-32600)
 for id in [None,True,False,[],{},1.5]:
  check_error(kernel,request(id=id),-32600)
 for raw in [b'',b'{',b'{"x":}',b'{}{}',b'{}x',b'\xff',b'"\\ud800"',b'"\\udc00"',b'"\\uXXXX"',b'"\xc0\xaf"',b'"\xed\xa0\x80"',b'"\xf4\x90\x80\x80"',b'"\n"',b'{"x":NaN}',b'{"x":Infinity}',b'{"x":1.}',b'{"x":+1}',b'{"x":01}']:
  check_error(kernel,raw,-32700)
 check_error(kernel,b'['*129+b'0'+b']'*129,-32000)
 assert 'result' in value(kernel,request('tools/list'))
 for raw in [b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}',b'{"jsonrpc":"2.0","id":1,"\\u0069d":2,"method":"ping"}',b'{"jsonrpc":"2.0","method":"ping","id":1,"params":{"x":1,"x":2}}']:
  check_error(kernel,raw,-32600)
 for raw in [b'{"jsonrpc":"2.0","method":"ping"}',b'{"jsonrpc":"2.0","method":"unknown"}',b'{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}',b'{"jsonrpc":"2.0","method":"notifications/initialized"}']:
  assert kernel(raw)==b'',raw
  count('notifications')
 escaped=b'{"jsonrpc":"2.0","i\\u0064":"\\ud83d\\ude00","metho\\u0064":"p\\u0069ng"}'
 assert value(kernel,escaped)=={'jsonrpc':'2.0','id':'😀','result':{}}
 count('escaped_fields')
 # Existing envelope ignores unknown properties, but every nested value is still parsed.
 for number in ['0.0','-0.0','1e300','1e-300','1E+3','9999999999999999999999999999']:
  raw=b'{"jsonrpc":"2.0","id":7,"method":"ping","extra":'+number.encode()+b'}'
  assert value(kernel,raw)=={'jsonrpc':'2.0','id':7,'result':{}}
  count('number_lexemes')
 for id in [0,-2**63,2**64-1,2**200,'',*(chr(i) for i in range(32)),'é漢😀','a'*200000]:
  answer=value(kernel,request(id=id))
  assert answer=={'jsonrpc':'2.0','id':id,'result':{}},repr(id)[:100]
  count('id_echo')
 rng=random.Random(0x484941)
 for i in range(250):
  id=rng.choice([rng.randrange(-2**100,2**100),''.join(rng.choice('aé漢😀\x00\n"\\') for _ in range(rng.randrange(30)))])
  obj={'jsonrpc':'2.0','id':id,'method':'ping','extra':[rng.randrange(10000),{'x':None,'y':True,'z':'é😀'},1.25]}
  pairs=list(obj.items());rng.shuffle(pairs)
  raw=json.dumps(dict(pairs),ensure_ascii=bool(i&1),indent=1 if i%3==0 else None).encode()
  assert value(kernel,raw)=={'jsonrpc':'2.0','id':id,'result':{}},raw
  count('randomized_valid')
 # Capacity checks precede every buffer access and preserve both output buffers.
 raw=request()
 out,work=sizes(len(raw))
 for o,w in [(0,0),(1,work),(out-1,work),(out,work-1)]:
  code,output,scratch=kernel.raw(raw,o,w)
  assert code==0xfffffffe and output==b'\xa5'*o and scratch==b'\x5a'*w,(code,o,w)
  count('capacity')
 # The native output expansion must not acknowledge initialization on shortage.
 with kernel.native.session(output_capacity=4<<20,workspace_capacity=32<<20) as session:
  too_wide=request('initialize',id='\n'*800000,params=init_params())
  try:
   session.invoke(too_wide)
  except kernel.loader.NativeCapacityError:
   pass
  else:
   raise AssertionError('expanded ID should exceed the 4MiB output buffer')
  small=json.loads(session.invoke(request('initialize',id='recovery',params=init_params())))
  assert small['id']=='recovery' and 'result' in small,small
  assert session.invoke(b'{"jsonrpc":"2.0","method":"notifications/initialized"}')==b''
  assert 'result' in json.loads(session.invoke(request('tools/list')))
 count('output_shortage_preserves_fresh_session')
 # Parallel native calls use independent workspaces and no mutable image data.
 from concurrent.futures import ThreadPoolExecutor
 with ThreadPoolExecutor(max_workers=8) as pool:
  outputs=list(pool.map(lambda i:value(kernel,request(id=i)),range(64)))
 assert outputs==[{'jsonrpc':'2.0','id':i,'result':{}} for i in range(64)]
 count('concurrent_64_calls')

def executable_checks(manifest):
 data=json.loads(manifest.read_bytes())
 standalone=data.get('standalone')
 if not standalone:return
 executable=manifest.parent/standalone['path']
 assert hashlib.sha256(executable.read_bytes()).hexdigest()==standalone['sha256']
 requests=[request(id=1),b'{"jsonrpc":"2.0","method":"notifications/initialized"}',request('tools/list',id='two'),request('missing',id=3),b'{',request('tools/call',id=4,params={'name':'runtime_line_hash','arguments':{'text':'hello'}})]
 expected=[{'jsonrpc':'2.0','id':1,'result':{}},None,None,None]
 env={'PATH':'/does-not-exist','LANG':'C'}
 if standalone['transport']=='stdio':
  raw=b'\n'.join([request('initialize',id='init',params=init_params()),b'{"jsonrpc":"2.0","method":"notifications/initialized"}',*requests])+b'\n'
  proc=subprocess.run([str(executable)],input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=15)
  assert proc.returncode==0 and proc.stderr==b'',(proc.returncode,proc.stderr)
  lines=proc.stdout.splitlines()
  assert len(lines)==6,proc.stdout
  assert json.loads(lines[0])['id']=='init'
  values=[json.loads(line) for line in lines[1:]]
  assert [x['id'] for x in values]==[1,'two',3,None,4] and values[0]==expected[0]
  assert values[2]['error']['code']==-32601
  assert values[3]['error']['code']==-32700
  assert values[4]['result']['structuredContent']=={'lineHash':'57'}
  # Multiple writes deliberately split a Unicode scalar and an escaped method.
  payload=request(id='😀')+b'\n'
  with subprocess.Popen([str(executable)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env) as child:
   for ch in payload:
    child.stdin.write(bytes([ch]));child.stdin.flush()
   child.stdin.close()
   answer=child.stdout.read();stderr=child.stderr.read()
   assert child.wait(timeout=15)==0 and stderr==b''
   assert json.loads(answer)=={'jsonrpc':'2.0','id':'😀','result':{}}
  count('persistent_static_elf')
 else:
  proc=subprocess.run([str(executable)],input=request(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=15)
  assert proc.returncode==0 and proc.stderr==b'',(proc.returncode,proc.stderr)
  assert json.loads(proc.stdout)=={'jsonrpc':'2.0','id':1,'result':{}}
  count('static_elf')

def main():
 global ARGS
 ARGS=PARSER.parse_args()
 if ARGS.hepta:sys.path.insert(0,str(ARGS.hepta))
 started=time.monotonic()
 if ARGS.vm_only:
  smoke(VM())
 else:
  assert ARGS.manifest,'HIA_PROTOCOL_MANIFEST or --manifest required for native verification'
  native_checks(Native(ARGS.manifest))
  executable_checks(ARGS.manifest)
 print(json.dumps({'status':'passed','counts':COUNTS,'elapsed_seconds':time.monotonic()-started,'source_sha256':hashlib.sha256(ARGS.source.read_bytes()).hexdigest()},sort_keys=True))

if __name__=='__main__':
 main()
