from pathlib import Path
import json,subprocess,os,time,select,traceback,base64,hashlib,signal
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import load
P,R,O,build,elf,elf_sha=load('network')
root=O/'files';root.mkdir();deep=root/'deep';deep.mkdir();texts={}
for i in range(16):
 path=(root if i%2==0 else deep)/('file-%02d.txt'%i)
 value='file '+str(i)+' Ω\n';path.write_text(value);texts[str(path)]=value
budget=root/'budget.txt';budget.write_text(('"\t\\\n'*180)+'Ω');texts[str(budget)]=budget.read_text()
bad=root/'bad-utf8';bad.write_bytes(b'\xffbad')
empty=root/'empty';empty.write_bytes(b'');texts[str(empty)]=''
alias=O/'configured-link';alias.symlink_to(root,target_is_directory=True)
alias_path=alias/'deep/file-01.txt';texts[str(alias_path)]=texts[str(deep/'file-01.txt')]
cfg=O/'config.json';cfg.write_text(json.dumps({'state_dir':str(O/'state'),'controller_workspace_roots':[str(O)],'hosts':{'a':{'ssh_target':'local-native','remote_state_dir':str(O/'remote'),'execution_mode':'operator','allowed_read_path_prefixes':[str(root),str(deep),str(alias),str(alias/'deep')]},'isolated':{'ssh_target':'local-isolated','remote_state_dir':str(O/'isolated'),'execution_mode':'isolated','allowed_read_path_prefixes':[]}}})+'\n')
import sys,shlex,atexit
sys.path.insert(0,str(R/'tests/hia_native'))
from test_native_read_bootstrap import LoopbackSSH
server=LoopbackSSH(O)
atexit.register(server.close)
client_config=O/'ssh_client_config'
client_config.write_text('\n'.join(['Host local-native','  HostName 127.0.0.1','  Port '+str(server.port),'  User '+server.user,'  IdentityFile '+str(server.root/'client'),'  IdentitiesOnly yes','  UserKnownHostsFile '+str(server.known_hosts),'  GlobalKnownHostsFile /dev/null','  StrictHostKeyChecking yes','  BatchMode yes','  LogLevel ERROR','']))
shim=O/'bin';shim.mkdir();ssh=shim/'ssh'
ssh.write_text("#!/bin/sh\nprintf '%s\\000' \"$@\" >> "+shlex.quote(str(O/'original-ssh-arguments.bin'))+"\nexec "+shlex.quote(server.ssh)+" -F "+shlex.quote(str(client_config))+" \"$@\"\n");ssh.chmod(0o755)
env={'PATH':str(shim)+':/usr/bin:/bin','HOME':str(O),'LC_ALL':'C'}
err=(O/'stderr.bin').open('xb')
p=subprocess.Popen(['/usr/bin/strace','-ff','-s','100','-e','trace=process,prctl,getppid,openat,close','-o',str(O/'trace'),str(elf),'--runtime-config',str(cfg)],cwd=O,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,start_new_session=True)
started=time.monotonic();buffer=b'';responses=[];requests=[];cases=[];raw_responses=[]
report={'status':'RUNNING','actual_default_public_entrypoint':True,'actual_network_ssh':True,'elf_sha256':elf_sha,'public_routes_qualified':False,'isolated':__import__('sys').flags.isolated,'optimize':__import__('sys').flags.optimize}
REDACTED='multi-file read could not complete; verify configured read roots, regular single-link files, strict UTF-8 and byte budgets'
BUDGET='multi-file response exceeds serialized MCP result byte budget; narrow paths or file sizes'
def exchange(value):
 global buffer
 requests.append(value);p.stdin.write(json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()+b'\n');p.stdin.flush()
 if 'id'not in value:return
 deadline=time.monotonic()+60
 while b'\n'not in buffer:
  left=deadline-time.monotonic()
  if left<=0 or not select.select([p.stdout],[],[],left)[0]:raise AssertionError('60-second original exchange budget')
  got=os.read(p.stdout.fileno(),65536)
  if not got:raise AssertionError('public EOF '+str(p.poll()))
  buffer+=got
 line,buffer=buffer.split(b'\n',1);raw_responses.append(line+b'\n');reply=json.loads(line);responses.append(reply)
 if reply.get('id')!=value['id']:raise AssertionError(('reply id',reply))
 return reply
def call(label,args,expect='ok'):
 ident=100+len(cases);row={'label':label,'id':ident,'expected':expect};cases.append(row)
 reply=exchange({'jsonrpc':'2.0','id':ident,'method':'tools/call','params':{'name':'read_multiple_files','arguments':args}})
 if expect=='ok':
  if reply.get('result',{}).get('isError')is not False:raise AssertionError((label,reply))
  contents=reply['result']['content']
  if len(contents)!=1 or contents[0].get('type')!='text':raise AssertionError((label,reply))
  value=json.loads(contents[0]['text'])
  if [f['path']for f in value['files']]!=args['paths']:raise AssertionError(('ordered full paths',label,value))
  for f in value['files']:
   text=texts[f['path']]
   if f['text']!=text or f['sha256']!=hashlib.sha256(text.encode()).hexdigest()or not f['version']:raise AssertionError(('file value',label,f))
  row.update(status='PASS',files=len(value['files']),content_bytes=len(contents[0]['text'].encode()))
 elif expect in ('redacted','budget','mode'):
  wanted={'redacted':REDACTED,'budget':BUDGET,'mode':'read_multiple_files requires a configured operator host'}[expect]
  if reply.get('result',{}).get('isError')is not True or reply['result']['content']!=[{'type':'text','text':wanted}]:raise AssertionError((label,reply,wanted))
  row.update(status='PASS',error=wanted)
 elif expect=='typed17':
  if reply.get('error',{}).get('code')!=-32602 or 'expected a string'not in json.dumps(reply):raise AssertionError((label,reply))
  row.update(status='PASS',error=reply['error'])
 elif expect=='count17':
  if reply.get('result',{}).get('isError')is not True or '16'not in reply['result']['content'][0]['text']:raise AssertionError((label,reply))
  row.update(status='PASS',error=reply['result']['content'][0]['text'])
 else:raise AssertionError('unhandled exact case expectation')
 print('PUBLIC_MULTI_CASE',json.dumps(row,ensure_ascii=False,sort_keys=True),flush=True)
 return reply
try:
 hello=exchange({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'actual-multi-integration','version':'1'}}})
 if hello.get('result',{}).get('protocolVersion')!='2025-06-18':raise AssertionError(hello)
 exchange({'jsonrpc':'2.0','method':'notifications/initialized'})
 catalog=exchange({'jsonrpc':'2.0','id':2,'method':'tools/list'})
 report['actual_catalog_names']=[x['name']for x in catalog['result']['tools']]
 if len(report['actual_catalog_names'])!=113 or not {'file_info','binary_read','read_multiple_files'}<=set(report['actual_catalog_names']):raise AssertionError('complete configured catalog policy differs')
 source="__name__ = 'default_public_read_reference'\n"+'\n'.join((R/'src/mcp/runtime'/name).read_text()for name in ('file_metadata.py','inode_patch.py','binary_file.py'))
 namespace={};exec(compile(source,'complete-original-read-source','exec'),namespace)
 report['original_reference_sha256']=hashlib.sha256(source.encode()).hexdigest()
 binary=root/'binary-data';binary.write_bytes(bytes(range(256))*3+b'\0\xffend')
 report['read_and_info_cases']=[]
 for identity,(tool,path)in enumerate([(tool,path)for tool in('binary_read','file_info')for path in(binary,root/'missing',root/'nul\0name')],3):
  args={'host':'a','path':str(path)}
  query={'op':'read'if tool=='binary_read'else'info','root':str(root),'path':str(path)}
  if tool=='binary_read':
   args.update(offset=7,limit=11);query.update(offset=7,limit=11,expected_version=None)
  try:
   expected=namespace['main'](query);error=None
  except Exception as exc:
   expected=None;error=type(exc).__name__+': '+str(exc)
  response=exchange({'jsonrpc':'2.0','id':identity,'method':'tools/call','params':{'name':tool,'arguments':args}})
  result=response.get('result')
  if result is None or len(result.get('content',[]))!=1:raise AssertionError(('actual network read result',response))
  text=result['content'][0]['text']
  if error is None:
   if result['isError']or json.loads(text)!=expected or text!=json.dumps(expected,ensure_ascii=False,sort_keys=True,separators=(',',':')):raise AssertionError(('actual original network success',tool,response,expected))
  else:
   message='remote helper on local-native failed with 1\nstdout:\n\nstderr:\n'+error
   if result['isError']is not True or text!=message:raise AssertionError(('actual original remote error',tool,response,message))
  report['read_and_info_cases'].append({'tool':tool,'id':identity,'path':str(path),'success':error is None,'status':'PASS'})
  print('PUBLIC_NETWORK_CASE',tool,identity,'PASS',flush=True)
 names=list(texts)[:16]
 call('one',{'host':'a','paths':names[:1]})
 call('two',{'host':'a','paths':names[:2]})
 call('sixteen',{'host':'a','paths':names})
 call('different-longest-root',{'host':'a','paths':[names[0],str(deep/'file-01.txt')]})
 call('original-symlink-parent-refusal',{'host':'a','paths':[names[0],str(alias_path)]},'redacted')
 call('later-utf8-no-partial',{'host':'a','paths':[names[0],str(bad)]},'redacted')
 call('later-file-budget-no-partial',{'host':'a','paths':[str(empty),names[0]],'max_file_bytes':1},'redacted')
 call('later-response-budget-no-partial',{'host':'a','paths':[names[0],str(budget)],'max_response_bytes':1024},'redacted')
 call('operator-before-path-root',{'host':'isolated','paths':[names[0]]},'mode')
 call('type-every-vector-element',{'host':'a','paths':names+[17]},'typed17')
 call('count-after-all-types',{'host':'a','paths':names+[str(empty)]},'count17')
 base=call('outer-budget-value',{'host':'a','paths':[str(budget)]})
 output=base['result']['content'][0]['text']
 constructor={'resultType':'complete','content':[{'type':'text','text':output}],'isError':False}
 limit=len(json.dumps(constructor,ensure_ascii=False,separators=(',',':')).encode())
 if not 1024<limit<262144:raise AssertionError(('reachable public budget',limit))
 report['actual_constructor_boundary']=limit
 for delta in (-1,0,1):call('outer-budget-'+str(delta),{'host':'a','paths':[str(budget)],'max_response_bytes':limit+delta},'budget'if delta<0 else'ok')
 if len(cases)!=15 or len(responses)!=23 or any(x.get('status')!='PASS'for x in cases):raise AssertionError('complete fixed public case count differs')
 raw=(O/'original-ssh-arguments.bin').read_bytes()
 if not raw.endswith(b'\0'):raise AssertionError('actual SSH argv record incomplete')
 words=raw[:-1].split(b'\0')
 if len(words)!=18*11:raise AssertionError(('complete actual SSH invocation count',len(words)))
 fixed=[b'-T',b'-o',b'BatchMode=yes',b'-o',b'ConnectTimeout=8',b'-o',b'StrictHostKeyChecking=yes',b'-o',b'ForwardAgent=no']
 for index in range(18):
  argv=words[index*11:(index+1)*11]
  if argv[:9]!=fixed or argv[9]!=b'local-native' or not argv[10]:raise AssertionError(('actual original SSH argv',index,argv[:10]))
 report['actual_ssh_invocations']=18
 report['original_ssh_arguments_sha256']=hashlib.sha256(raw).hexdigest()
 report['transport_fixture']='owned loopback OpenSSH server; shim only supplies isolated -F client config and execs actual ssh with unchanged original arguments'
 p.stdin.close();code=p.wait(timeout=30)
 if code!=0 or buffer+p.stdout.read():raise AssertionError(('public close',code))
 report.update(status='PASS',public_cases=len(cases)+len(report['read_and_info_cases']),multi_cases=len(cases),read_info_cases=len(report['read_and_info_cases']),public_responses=len(responses),returncode=code)
except BaseException as exc:
 report.update(status='FAIL',error=repr(exc));traceback.print_exc()
finally:
 if p.poll()is None:
  os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=30)
 server.log.flush()
 (O/'sshd-session.log').write_bytes((server.root/'sshd.log').read_bytes())
 server.close()
 for f in(p.stdin,p.stdout,err):
  if not f.closed:f.close()
 for index,raw in enumerate(raw_responses):(O/('response-%03d.wire'%index)).write_bytes(raw)
 report.update(elapsed_seconds=time.monotonic()-started,returncode=p.returncode,cases=cases)
 for name,data in [('requests',requests),('responses',responses),('result',report)]:(O/(name+'.json')).write_text(json.dumps(data,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items()if k not in ('cases','actual_wires')},sort_keys=True),flush=True)
raise SystemExit(0 if report['status']=='PASS'else 1)
