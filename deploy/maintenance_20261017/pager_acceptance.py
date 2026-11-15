from pathlib import Path
import argparse,json,http.client,time,sys,concurrent.futures,hashlib,subprocess
p=argparse.ArgumentParser();p.add_argument('--port',type=int,required=True);p.add_argument('--output',required=True);p.add_argument('--restart-unit');opts=p.parse_args()
root=Path('/home/qian-qi/.local/state/hepta-runtime-optimization-20261017-0940')
release=json.loads((root/'pager-release-candidates.json').read_text())['candidate']['path']
sys.path.insert(0,release)
from chatgpt_full_operator import VERSION_KEY,CAPABILITIES_KEY,MODERN_VERSION
token=Path('/home/qian-qi/.local/share/hepta-computer-operator-v12-20261015/token').read_text().strip()
base={'X-Hepta-Runtime-Token':token,'Content-Type':'application/json','Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2025-11-25'}
report={'schema':'hepta-pager-acceptance-v2','port':opts.port,'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'passed':False,'steps':[]}
out=Path(opts.output)
def save():out.write_text(json.dumps(report,indent=2)+'\n')
def stage(label,fn):
 t=time.monotonic()
 try:
  result=fn();report['steps'].append({'label':label,'ok':True,'seconds':round(time.monotonic()-t,4)});save();return result
 except Exception as exc:
  report['steps'].append({'label':label,'ok':False,'seconds':round(time.monotonic()-t,4),'error':str(exc)[:1500]});save();raise
def request(method,params,ident,headers):
 body={'jsonrpc':'2.0','method':method,'params':params}
 if ident is not None:body['id']=ident
 c=http.client.HTTPConnection('127.0.0.1',opts.port,timeout=90)
 c.request('POST','/mcp',json.dumps(body),headers);r=c.getresponse();raw=r.read();sid=r.getheader('Mcp-Session-Id');code=r.status;c.close()
 if sid:headers['Mcp-Session-Id']=sid
 if code>=400:raise RuntimeError('HTTP '+str(code))
 if not raw:return None
 t=raw.decode();v=json.loads([x[5:].strip() for x in t.splitlines() if x.startswith('data:')][-1]) if t.startswith(('event:','data:')) else json.loads(t)
 if 'error' in v:raise RuntimeError(json.dumps(v['error']))
 return v.get('result',v)
def value(r):
 if r.get('isError'):raise RuntimeError(json.dumps(r))
 if r.get('structuredContent') is not None:return r['structuredContent']
 text='\n'.join(x['text'] for x in r.get('content',[]) if x.get('type')=='text')
 return json.loads(text) if text else r
def call(name,args,ident,headers,modern=False):
 params={'name':name,'arguments':args}
 if modern:params['_meta']={VERSION_KEY:MODERN_VERSION,CAPABILITIES_KEY:{}}
 return value(request('tools/call',params,ident,headers))
def first(label,headers,modern=False):
 for attempt in range(4):
  try:return stage(label+'_'+str(attempt+1),lambda:call('process_list_page',{'limit':128},20+attempt,headers,modern))
  except RuntimeError as exc:
   if 'Durable registry page unavailable or snapshot changed' not in str(exc) or attempt==3:raise
   time.sleep(.2)
try:
 headers=base.copy()
 stage('legacy_initialize',lambda:request('initialize',{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'hepta-runtime-pager-acceptance','version':'2'}},1,headers))
 report['legacy_sid_present']='Mcp-Session-Id' in headers
 request('notifications/initialized',{},None,headers)
 catalog=stage('catalog',lambda:request('tools/list',{},2,headers))
 report['catalog']={'count':len(catalog['tools']),'sha256':hashlib.sha256(json.dumps(catalog['tools'],sort_keys=True,separators=(',',':')).encode()).hexdigest()}
 assert report['catalog']['count']==110
 initial=first('legacy_initial',headers)
 second=stage('legacy_continuation',lambda:call('process_list_page',{'limit':128,'cursor':initial['next_cursor']},30,headers))
 repeat=stage('legacy_exact_repeat',lambda:call('process_list_page',{'limit':128,'cursor':initial['next_cursor']},31,headers))
 assert second==repeat and initial['snapshot_id']==second['snapshot_id']
 report['legacy_inventory']={'total':initial['total'],'returned':initial['returned'],'continuation_returned':second['returned'],'same_snapshot':True,'exact_repeat':True}
 modern_headers=base.copy()
 initial=first('modern_initial',modern_headers,True)
 report['modern_sid_present']='Mcp-Session-Id' in modern_headers;report['modern_meta_present']=True
 assert not report['modern_sid_present']
 with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
  hosts=stage('modern_host_list_c8_n16',lambda:list(pool.map(lambda i:call('host_list',{},100+i,modern_headers.copy(),True),range(16))))
 assert len(hosts)==16
 cursor_args={'limit':128,'cursor':initial['next_cursor']}
 second=stage('modern_continuation_after_burst',lambda:call('process_list_page',cursor_args,200,modern_headers,True))
 with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
  repeated=stage('modern_cursor_repeat_c8_n8',lambda:list(pool.map(lambda i:call('process_list_page',cursor_args,210+i,modern_headers.copy(),True),range(8))))
 assert all(item==second for item in repeated) and initial['snapshot_id']==second['snapshot_id']
 report['modern_inventory']={'total':initial['total'],'returned':initial['returned'],'continuation_returned':second['returned'],'same_snapshot':True,'exact_repeat_count':len(repeated)}
 original=stage('original_v4_job',lambda:call('process_status',{'host':'main','job_id':'1a1492acc63-1123a8-3625'},300,modern_headers,True))
 assert original['state']=='succeeded' and original['exit_code']==0
 report['original_job']={k:original.get(k) for k in ['job_id','state','exit_code','output_complete']}
 if opts.restart_unit:
  t=time.monotonic();subprocess.run(['systemctl','--user','restart',opts.restart_unit],check=True)
  for attempt in range(150):
   try:
    c=http.client.HTTPConnection('127.0.0.1',opts.port,timeout=2);c.request('GET','/health',headers=base);r=c.getresponse();raw=r.read();code=r.status;c.close()
    if code==200:break
   except OSError:pass
   time.sleep(.2)
  else:raise RuntimeError('listener did not recover after restart')
  report['restart_listener_seconds']=round(time.monotonic()-t,4)
 report['passed']=True
except Exception as exc:report['error']=str(exc)[:2000]
finally:
 report['finished_utc']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime());save();print(json.dumps(report),flush=True)
raise SystemExit(0 if report['passed'] else 1)
