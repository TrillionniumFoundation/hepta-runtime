#!/usr/bin/env python3
"""Ordinary G5 frontend continuations and actual target context comparison."""
from pathlib import Path
from collections import Counter
import argparse,hashlib,json,os,struct,subprocess,sys,time,traceback
OWN=Path(__file__).resolve().parents[1]
ROOT=Path(os.environ['G5_REFERENCE_ROOT']).resolve(strict=True)
sys.path.insert(0,str(ROOT/'scripts'))
from frontend_native import State,PendingTool,word,pack,sha
from controller_native import Engine
wire=lambda x:json.dumps(x,ensure_ascii=False,separators=(',',':')).encode()

def split_frames(raw):
 rows=[];at=0
 while at<len(raw):
  size=word(raw,at);at+=8;assert size>=32 and size<=len(raw)-at;rows.append(raw[at:at+size]);at+=size
 assert at==len(raw);return rows

def main():
 p=argparse.ArgumentParser();p.add_argument('--run-name',default='frontend-v1');a=p.parse_args();assert a.run_name.replace('-','').isalnum()
 out=OWN/'evidence'/a.run_name;out.mkdir();begin=time.monotonic();counts=Counter();engine=None
 report={'schema':'hepta.g5.actual-public-controller-qualification.v1','native_protocol_controller_executed':True,'status':'RUNNING','counts':counts,'actual_target_sdk_context':True,'normal_unique_field_domain_only':True,'tool_bodies_executed':False,'resource_uris_dereferenced':False,'full_public_graph_built':False,'full_sdk_qualified':False,'full_async_runtime_qualified':False,'native_task_registry_qualified':False,'native_future_cancellation_qualified':False,'production_activated':False,'old_path_removed':False,'fresh_cold_qualified':False,'qualifier_sha256':sha(Path(__file__).read_bytes())}
 def save():(out/'summary.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 save()
 try:
  normal=[json.loads(x) for x in (ROOT/'cases/normal.jsonl').read_bytes().splitlines()]
  refs={x['label']:x for x in map(json.loads,(ROOT/'evidence/oracle-normal.jsonl').read_bytes().splitlines())}
  ob=json.loads((ROOT/'evidence/context-oracle-build.json').read_bytes());binary=ROOT/ob['binary_relative_path'];assert sha(binary.read_bytes())==ob['binary_sha256']
  assert sha((ROOT/'context-oracle/main.rs').read_bytes())==ob['source_sha256']
  assert json.loads((ROOT/'evidence/context-target-lock-subset.json').read_bytes())['all_retained_exactly_match_target']
  context_rows=[json.loads(x) for x in (ROOT/'cases/context.jsonl').read_bytes().splitlines()]
  context_raw=(ROOT/'evidence/oracle-context.bin').read_bytes();assert sha(context_raw)==ob['observations_sha256']
  context_refs=dict(zip([x['label'] for x in context_rows],split_frames(context_raw),strict=True))
  proc=subprocess.run([str(binary),'--types'],input=(ROOT/'cases/context-types.jsonl').read_bytes(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
  (out/'context-types.stdout').write_bytes(proc.stdout);(out/'context-types.stderr').write_bytes(proc.stderr);assert proc.returncode==0 and not proc.stderr
  types=[json.loads(x) for x in proc.stdout.splitlines()];assert len(types)==11 and all(x['ok'] for x in types);counts['actual_sdk_normal_capability_types']=len(types);counts['actual_sdk_tasks_extension_present']=sum(x['supports_tasks'] for x in types)
  with (out/'native-events.jsonl').open('w') as events:
   def event(row):
    row['case']=report.get('current_case');events.write(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n');events.flush();counts['native_invocations']+=1
   engine=Engine(ROOT,event,OWN)
   for case in context_rows:
    report['current_case']=case['label']
    engine.states['client']=State('client',engine.modules['client'],event)
    code,raw=engine.run('client',bytes.fromhex(case['frame_hex']));assert code==32 and raw==context_refs[case['label']],(case['label'],raw,context_refs[case['label']])
    counts['context_cases']+=1
    if word(raw,8):counts['context_capabilities_some']+=1
    if word(raw,16):counts['context_experimental_some']+=1
   for case in normal:
    if case['mode']!='request' or case['type']!='call':continue
    label=case['label'];report['current_case']=label;ref=refs[label];original=case['wire'].encode()
    message=engine.run('message',b'HRCJQ001'+pack(1,len(original))+original)[1];request=engine.run('request',message)[1]
    code,raw=engine.run('bridge',b'HRQFB001'+pack(2,len(original),len(message),len(request))+original+message+request)
    assert code==192 and raw[:8]==b'HRJPRR02' and word(raw,16)==4 and word(raw,24)==0 and word(raw,32)==2
    actual=engine.run('protocol',b'HRJPRQ02'+pack(2,len(original),0)+original)
    assert actual==(code,raw),(case['label'],'native controller differs from frozen target bridge')
    counts['actual_native_controller_call_cases']+=1
    expected_id=ref['id'].encode() if isinstance(ref['id'],str) else ref['id_wire'].encode();name=ref['selector'].encode()
    assert raw[192:]==expected_id+name and word(raw,48)==len(expected_id) and word(raw,56)==len(name)
    assert word(raw,40)==(4 if isinstance(ref['id'],str) else 3) and word(raw,64)==0 and word(raw,72)==5
    if ref['arguments_wire'] is None:assert word(raw,80)==0 and word(raw,88)==word(raw,96)==0
    else:
     at,size=word(raw,88)-32,word(raw,96);assert word(raw,80)==7 and 0<=at<=len(original) and size<=len(original)-at
     assert json.loads(original[at:at+size])==json.loads(ref['arguments_wire'])
    if ref['flags']&1:
     at,size=word(raw,104)-32,word(raw,112);assert 0<=at<=len(original) and size<=len(original)-at
     assert json.loads(original[at:at+size])==json.loads(ref['meta_wire'])
    else:assert word(raw,104)==word(raw,112)==0
    assert word(raw,136)==1 and word(raw,144)==len(original);counts['bridge_call_cases']+=1
   for op,args in [(2,range(1,5)),(3,range(1,4)),(5,range(2)),(6,range(1,9))]:
    for arg in args:
     report['current_case']=f'retained-catalog-op{op}-arg{arg}';frame=b'HRMCD002'+pack(op,arg)
     assert engine.run('public_catalog',frame)==engine.run('baseline_catalog',frame);counts['retained_catalog_operations']+=1
   report['current_case']='retained-catalog-version-string';body=wire('2025-11-25');frame=b'HRMCD002'+pack(4,len(body))+body
   assert engine.run('public_catalog',frame)==engine.run('baseline_catalog',frame);counts['retained_catalog_operations']+=1
   for modern in (False,True):
    report['current_case']='public-catalog-overlay-'+str(int(modern));code,raw=engine.run('public_catalog',b'HRMCD002'+pack(1,int(modern)))
    ref=refs['public-eight-tools-policy'+str(2 if modern else 1)]
    assert code==32 and raw[32:]==b',"result":'+ref['wire'].encode()+b'}';counts['public_catalog_direct_cases']+=1
   full=json.loads((ROOT/'cases/context-full.json').read_bytes())
   def initialize(version):
    request=wire({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':version,'capabilities':full,'clientInfo':{'name':'g5-owned-frontend','version':'1'}}})
    code,raw=engine.run('frontend',request);assert code==64 and json.loads(raw[64:])['id']==1
    code,raw=engine.run('frontend',b'{"jsonrpc":"2.0","method":"notifications/initialized"}');assert code==64 and word(raw,8)==0
    counts['public_legacy_initializations']+=1
   for sequence,version in enumerate(['2024-11-05','2025-11-25',None]):
    engine.new_session()
    if version:initialize(version)
    metadata={'io.modelcontextprotocol/protocolVersion':'2026-07-28','io.modelcontextprotocol/clientCapabilities':full}
    variants=[None] if sequence==0 else ([None,metadata,None] if sequence==1 else [metadata,metadata])
    for index,meta in enumerate(variants):
     report['current_case']=f'public-tools-list-sequence{sequence}-request{index}'
     params={} if meta is None else {'_meta':meta};request=wire({'jsonrpc':'2.0','id':10+index,'method':'tools/list','params':params})
     code,raw=engine.run('frontend',request);assert code==64
     policy=1 if meta is None else 2;expected=b'{"jsonrpc":"2.0","id":'+str(10+index).encode()+b',"result":'+refs['public-eight-tools-policy'+str(policy)]['wire'].encode()+b'}'
     assert raw[64:]==expected,(report['current_case'],raw[64:160],expected[:96]);counts['public_tools_list_responses']+=1
   legacy_exp=context_refs['context-mode0-legacy1-2-meta0'];assert word(legacy_exp,16)==1
   for case in normal:
    if case['domain']!='public-eight-tool-request-metadata':continue
    engine.new_session();report['current_case']=case['label'];modern=case['modern']
    if not modern:initialize('2025-11-25')
    try:engine.run('frontend',case['wire'].encode(),protocol_bridge=True)
    except PendingTool as pending:
     tool=case['public_tool'];expected_child={'host_list':6,'effective_config':6,'execution_shadow_admit':7,'view':4,'workdir':5,'directory_create':8,'file_move':8,'directory_move':8}[tool]
     assert pending.child==expected_child,(tool,pending.child);raw=pending.wire;args=refs[case['label']]['arguments_wire'].encode();expected_exp=b'' if modern else legacy_exp[32:]
     if expected_child in (4,5):
      size=word(raw,8);assert size==len(args) and raw[40:40+size]==args
      assert word(raw,16)==int(bool(expected_exp)) and word(raw,24)==len(expected_exp) and raw[40+size:]==expected_exp
     elif expected_child==8:
      size=word(raw,16);assert size==len(args) and raw[48:48+size]==args
      assert word(raw,24)==int(bool(expected_exp)) and word(raw,32)==len(expected_exp) and raw[48+size:]==expected_exp
     elif expected_child==7:assert word(raw,16)==len(args) and raw[24:]==args
     else:assert len(raw)==24 and word(raw,8)==(1 if tool=='host_list' else 2)
     counts['public_tool_pending_routes']+=1
    else:raise AssertionError((case['label'],'ordinary registered tool did not reach its real pending body'))
   assert counts['actual_native_controller_call_cases']==80 and counts['context_cases']==104 and counts['bridge_call_cases']==80 and counts['retained_catalog_operations']==18 and counts['public_tool_pending_routes']==16 and counts['public_tools_list_responses']==6
  report.pop('current_case',None)
  report.update(status='PASS',modules=engine.members,controller_source_sha256=engine.controller_row['source_sha256'],controller_image_sha256=engine.controller_row['image_sha256'],context_oracle_binary_sha256=ob['binary_sha256'],context_observations_sha256=sha(context_raw),context_type_observations_sha256=sha(proc.stdout),native_events_sha256=sha((out/'native-events.jsonl').read_bytes()),request_bridge_abi='HRQFB001 -> HRJPRR02; original input span offsets retained',catalog_abi='HRMCD002 -> HRCATR02; existing fixed slot 0',public_tools=8,context_owner_output='effective ClientCapabilities.experimental only',public_handler_body_boundary='pending actual gateway/config/execution frame; no synthetic handler response')
 except BaseException:report.update(status='FAIL',failure=traceback.format_exc());raise
 finally:
  if engine:engine.close()
  report['elapsed_seconds']=time.monotonic()-begin;save()
 print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
