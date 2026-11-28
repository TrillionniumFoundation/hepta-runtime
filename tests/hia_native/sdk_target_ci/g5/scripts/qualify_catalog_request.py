#!/usr/bin/env python3
"""Ordinary native G5 catalog/request comparison with the exact target SDK."""
from pathlib import Path
from collections import Counter
import argparse,contextlib,hashlib,json,struct,sys,time,traceback
ROOT=Path(__file__).resolve().parents[1]
sha=lambda raw:hashlib.sha256(raw).hexdigest()
frame=lambda magic,op,body:magic+struct.pack('<QQ',op,len(body))+body
word=lambda raw,at:struct.unpack_from('<Q',raw,at)[0]
TYPES={'tools':4,'prompts':5,'resources':6,'templates':7,'skills':8}

def main():
 p=argparse.ArgumentParser();p.add_argument('--run-name',default='normal-v1');a=p.parse_args();assert a.run_name.replace('-','').isalnum()
 out=ROOT/'evidence'/a.run_name;out.mkdir();begin=time.monotonic();counts=Counter()
 report={'schema':'hepta.g5.ordinary-catalog-request-qualification.v1','status':'RUNNING','counts':counts,'target_sdk':'rmcp 3.9.0','actual_original_executed':True,'historical_pass_reused':False,'normal_unique_field_domain_only':True,'full_sdk_deserialization_qualified':False,'full_async_runtime_qualified':False,'native_task_registry_qualified':False,'native_future_cancellation_qualified':False,'full_target_qualified':False,'production_activated':False,'old_path_removed':False,'fresh_cold_qualified':False,'resource_uris_dereferenced':False,'tool_bodies_executed':False,'qualifier_sha256':sha(Path(__file__).read_bytes())}
 def save():(out/'summary.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 save()
 try:
  cr=(ROOT/'cases/normal.jsonl').read_bytes();rr=(ROOT/'evidence/oracle-normal.jsonl').read_bytes();cm=json.loads((ROOT/'cases/manifest.json').read_bytes());ob=json.loads((ROOT/'evidence/oracle-build.json').read_bytes())
  assert sha(cr)==cm['sha256']==ob['cases_sha256'] and sha(rr)==ob['observations_sha256']
  assert json.loads((ROOT/'evidence/target-lock-subset.json').read_bytes())['all_retained_exactly_match_target']
  modules=json.loads((ROOT/'evidence/hia-modules.json').read_bytes())['members'];sys.path.insert(0,str(ROOT/'scripts'));from hia_native_loader import NativeModule
  with contextlib.ExitStack() as stack:
   sessions={}
   for name,work in [('serde',32),('catalog',96),('request',96),('message',96)]:
    m=modules[name];path=ROOT/m['path'];assert sha(path.read_bytes())==m['sha256']
    module=stack.enter_context(NativeModule(path,manifest_sha256=m['sha256']))
    sessions[name]=stack.enter_context(module.session(output_capacity=1<<20,workspace_capacity=work<<20))
   with (out/'native-events.jsonl').open('w') as events:
    for case,ref in zip([json.loads(x) for x in cr.splitlines()],[json.loads(x) for x in rr.splitlines()],strict=True):
     label=case['label'];report['current_case']=label;assert label==ref['label'] and case['mode']==ref['mode'];mode=case['mode'];original=case['wire'].encode()
     row={'label':label,'mode':mode,'input_sha256':sha(original)}
     if mode=='request':
      source=sessions['message'](frame(b'HRCJQ001',1,original));counts['native_message_projections']+=1
      assert source[:8]==b'HRCJR001' and len(source)>=256 and word(source,8)==1
      assert word(source,16)==(14 if case['type']=='call' else 10)
      at,size=struct.unpack_from('<QQ',source,80);assert source[at:at+size]==ref['id_wire'].encode(),(label,'ID normalization')
      row['message_projection_hex']=source.hex();raw=sessions['request'](source)
     else:
      body=sessions['serde'](frame(b'HSJVAL01',1,original));counts['native_canonicalizations']+=1
      assert body==ref['canonical_input'].encode(),(label,'canonical input');row['canonical_input_hex']=body.hex()
      if mode=='catalog':raw=sessions['catalog'](frame(b'HRRSP001',TYPES[case['type']]|(case['policy']<<8),body))
      else:raw=sessions['request'](frame(b'HRQPR001',1 if case['type']=='call' else 2,body))
     row['projection_hex']=raw.hex();events.write(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n');events.flush()
     if mode=='catalog':
      assert raw[:8]==b'HRRPO001' and len(raw)>=64,(label,'catalog header');fields=struct.unpack('<7Q',raw[8:64]);flags=0
      assert fields[:2]==(ref['kind'],flags),(label,'kind/meta flags',fields)
      assert fields[2:]==(64,len(raw)-64,case['policy'],0,0)
      assert raw[64:]==ref['wire'].encode(),(label,raw[64:],ref['wire'])
      counts['catalog_cases']+=1;counts['catalog_'+case['type']]+=1
      if label.startswith('public-eight-tools-'):
       (out/('public-tools-policy'+str(case['policy'])+'.suffix.bin')).write_bytes(b',"result":'+raw[64:]+b'}');counts['pinned_public_catalog_cases']+=1
     else:
      assert raw[:8]==b'HRQPO001' and len(raw)>=160,(label,'request header')
      assert struct.unpack_from('<4Q',raw,8)==(ref['kind'],ref['flags'],ref['projection_mode'],len(raw)),(label,'request flags')
      assert raw[40:64]==bytes(24)
      expected=[ref['typed_params_wire'],ref['selector'],ref['arguments_wire'],ref['meta_wire'],ref['input_responses_wire'],ref['request_state']]
      for index,value in enumerate(expected):
       at,size=struct.unpack_from('<QQ',raw,64+index*16)
       if value is None:assert (at,size)==(0,0),(label,index,'None')
       else:
        assert 160<=at<=len(raw) and size<=len(raw)-at
        assert raw[at:at+size]==value.encode(),(label,index,raw[at:at+size],value)
      counts[mode+'_cases']+=1;counts[case['type']+'_projections']+=1
      if ref['request_state']=='':counts['present_empty_request_state']+=1
      if ref['input_responses_wire']=='{}':counts['present_empty_input_responses']+=1
     counts['total_cases']+=1;save()
  assert counts['total_cases']==654 and counts['catalog_cases']==318 and counts['params_cases']==240 and counts['request_cases']==96
  assert counts['native_canonicalizations']==558 and counts['native_message_projections']==96
  report.pop('current_case',None)
  report.update(status='PASS',modules={n:modules[n] for n in ('serde','catalog','request','message')},cases_sha256=sha(cr),oracle_sha256=sha(rr),original_oracle_binary_sha256=ob['binary_sha256'],native_events_sha256=sha((out/'native-events.jsonl').read_bytes()),boundaries=['five ordinary nonempty catalog result types','pinned eight-tool public schemas','typed CallTool and ReadResource parameter serialization and projection','actual envelope metadata extraction and numeric/string ID normalization','optional inputResponses and requestState data presence without task execution','legacy complete stripping and modern ttlMs/cacheScope defaults'])
 except BaseException:report.update(status='FAIL',failure=traceback.format_exc());raise
 finally:report['elapsed_seconds']=time.monotonic()-begin;save()
 print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
