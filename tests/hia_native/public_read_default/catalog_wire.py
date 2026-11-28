from pathlib import Path
import os,sys,json,hashlib,gzip,struct,subprocess,select,time,signal,traceback
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import load,pin,sha,source_check
P,R,O,status,elf,elf_sha=load('catalog_wire')
binding=source_check(R)
reference=P/'catalog_component';report_path=reference/'result.json';report_pin=pin(report_path);record=json.loads(report_path.read_bytes())
if record['status']!='PASS' or record['tests_run']!=6 or record['isolated']!=1 or any(record[k] for k in ('failures','errors','skipped','expected_failures','unexpected_successes','optimize')):raise ValueError('complete original pipeline gate admission differs')
original={}
reference_rows=[]
for flags in(0,1):
 for modern in(0,1):
  label='original-%02d-%d-sdk'%(flags,modern)
  found=[r for r in record['details']['calls']if r['label']==label]
  if len(found)!=1:raise ValueError('unique exact original SDK response absent')
  row=found[0];item=row['buffers']['output'];path=reference/item['path']
  if pin(path)!=item['compressed']:raise ValueError('complete original compressed response differs')
  raw=gzip.decompress(path.read_bytes())
  if len(raw)!=item['bytes'] or sha(raw)!=item['sha256'] or raw[:8]!=b'HRRPO001':raise ValueError('complete original response differs')
  kind,rflags,at,size,policy,z1,z2=struct.unpack_from('<7Q',raw,8)
  if (kind,rflags,at,policy,z1,z2)!=(4,0,64,0,0,0) or row['code']!=64+size:raise ValueError('original SDK typed extent differs')
  typed=raw[64:64+size]
  if len(json.loads(typed)['tools'])!=(113 if flags else 10):raise ValueError('original catalog policy count differs')
  original[(flags,modern)]=typed;reference_rows.append({'label':label,'complete_output':item,'typed':{'bytes':len(typed),'sha256':sha(typed)}})
cases=[];processes=[];started=time.monotonic();result={'status':'RUNNING','actual_default_public_entrypoint':True,'elf':str(elf),'elf_pin':pin(elf),'source_binding':binding['manifest_sha256'],'original_complete_suite':report_pin,'original_sdk_outputs':reference_rows,'isolated':sys.flags.isolated,'optimize':sys.flags.optimize,'supported_public_configuration_flags':[0,1],'full_136_handlers_qualified':False}
def compact(value):return json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
try:
 for flags in(0,1):
  for mode,modern,version in(('legacy',0,'2025-06-18'),('modern',1,'2026-07-28'),('future-initialize',0,'2026-07-28')):
   folder=O/('flags%d-%s'%(flags,mode));folder.mkdir()
   command=[str(elf)]
   if flags:
    cfg=folder/'config.json';cfg.write_bytes(compact({'state_dir':str(folder/'state'),'controller_workspace_roots':[str(folder)],'hosts':{'h':{'ssh_target':'unused-catalog-target','remote_state_dir':str(folder/'remote'),'execution_mode':'operator','allowed_read_path_prefixes':[str(folder)]}}})+b'\n')
    command+=['--runtime-config',str(cfg)]
   err=(folder/'stderr').open('xb')
   p=subprocess.Popen(command,cwd=folder,env={'PATH':'/usr/bin:/bin','HOME':str(folder),'LC_ALL':'C'},stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,start_new_session=True)
   processes.append((p,err));buffer=b''
   def exchange(value):
    nonlocal_dummy=None
    global buffer
    raw=compact(value)+b'\n';(folder/('request-%s.wire'%value.get('id','notification'))).write_bytes(raw);p.stdin.write(raw);p.stdin.flush()
    if 'id'not in value:return None
    end=time.monotonic()+60
    while b'\n'not in buffer:
     left=end-time.monotonic()
     if left<=0 or not select.select([p.stdout],[],[],left)[0]:raise AssertionError('original exchange budget')
     got=os.read(p.stdout.fileno(),65536)
     if not got:raise AssertionError(('public EOF',p.poll()))
     buffer+=got
    line,buffer=buffer.split(b'\n',1)
    (folder/('response-%s.wire'%value['id'])).write_bytes(line+b'\n')
    if json.loads(line).get('id')!=value['id']:raise AssertionError('exact response id differs')
    return line+b'\n'
   if mode!='modern':
    hello=exchange({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':version,'capabilities':{},'clientInfo':{'name':'complete-catalog-wire','version':'1'}}})
    negotiated='2025-11-25'if mode=='future-initialize'else version
    if json.loads(hello).get('result',{}).get('protocolVersion')!=negotiated:raise AssertionError(('original protocol negotiation',version,negotiated,hello[:250]))
    exchange({'jsonrpc':'2.0','method':'notifications/initialized'})
   for cursor_case,params in enumerate((None,{}, {'cursor':'qualification-cursor-\0-λ'})):
    ident=cursor_case+2;request={'jsonrpc':'2.0','id':ident,'method':'tools/list'}
    if params is not None:request['params']=dict(params)
    if mode=='modern':request.setdefault('params',{})['_meta']={'io.modelcontextprotocol/protocolVersion':version,'io.modelcontextprotocol/clientCapabilities':{}}
    raw=exchange(request);expected=b'{"jsonrpc":"2.0","id":'+str(ident).encode()+b',"result":'+original[(flags,modern)]+b'}\n'
    if raw!=expected:
     (folder/('expected-%s.wire'%ident)).write_bytes(expected)
     mismatch=next((i for i,(a,b)in enumerate(zip(raw,expected))if a!=b),min(len(raw),len(expected)))
     raise AssertionError(('full original catalog wire differs',flags,modern,cursor_case,len(raw),len(expected),mismatch,raw[mismatch:mismatch+80],expected[mismatch:mismatch+80]))
    cases.append({'mode':mode,'flags':flags,'modern':modern,'protocol_version':version,'cursor_case':cursor_case,'visible_tools':len(json.loads(raw)['result']['tools']),'wire_bytes':len(raw),'wire_sha256':sha(raw),'status':'PASS'})
   p.stdin.close();exit_code=p.wait(timeout=30)
   if exit_code!=0 or buffer+p.stdout.read():raise AssertionError('original EOF terminal differs')
   p.stdout.close();err.close()
   print('DEFAULT_CATALOG_WIRES',flags,modern,'PASS',flush=True)
 if len(cases)!=18 or len(processes)!=6:raise AssertionError('complete default catalog shape count')
 if pin(report_path)!=report_pin or pin(elf)!=result['elf_pin'] or source_check(R)!=binding:raise ValueError('catalog exact source/evidence changed')
 result['status']='PASS'
except BaseException as exc:
 result.update(status='FAIL',error=repr(exc));traceback.print_exc()
finally:
 for p,err in processes:
  if p.poll()is None:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=10)
  for f in(p.stdin,p.stdout,err):
   if not f.closed:f.close()
 result.update(cases=cases,process_returncodes=[p.returncode for p,_ in processes],seconds=time.monotonic()-started)
 (O/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items()if k not in('cases','original_sdk_outputs')},sort_keys=True),flush=True)
raise SystemExit(0 if result['status']=='PASS'else 1)
