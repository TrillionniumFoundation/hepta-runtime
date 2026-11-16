#!/usr/bin/env python3
"""Execute normal target result extraction and retained typed emitters natively."""
from pathlib import Path
import argparse,hashlib,json,struct,sys,time,traceback
ROOT=Path(__file__).resolve().parents[1]
sha=lambda raw:hashlib.sha256(raw).hexdigest()
frame=lambda magic,op,body:magic+struct.pack('<QQ',op,len(body))+body
TYPES={'auto':0,'call':1,'read':2,'tools':4,'prompts':5,'resources':6,'templates':7,'skills':8}
def main():
 p=argparse.ArgumentParser();p.add_argument('--run-name',default='normal-v1');a=p.parse_args();assert a.run_name.replace('-','').isalnum()
 out=ROOT/'evidence'/a.run_name;out.mkdir();start=time.monotonic()
 counts={'response_cases':0,'native_canonicalizations':0,'native_response_calls':0,'typed_emitter_cases':0,'meta_only_custom_results':0,'present_structured_null':0,'absent_structured':0,'read_resource_cases':0,'cache_list_cases':0}
 report={'schema':'hepta.g4.normal-response-qualification.v1','status':'RUNNING','counts':counts,'target_sdk':'rmcp 3.9.0','actual_original_executed':True,'historical_pass_reused':False,'normal_unique_field_domain_only':True,'full_sdk_deserialization_qualified':False,'nonempty_catalog_result_serialization_qualified':False,'full_async_runtime_qualified':False,'native_task_registry_qualified':False,'native_future_cancellation_qualified':False,'full_target_qualified':False,'production_activated':False,'old_path_removed':False,'fresh_cold_qualified':False,'qualifier_sha256':sha(Path(__file__).read_bytes())}
 def save():(out/'summary.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
 save()
 try:
  cr=(ROOT/'cases/normal.jsonl').read_bytes();rr=(ROOT/'evidence/oracle-normal.jsonl').read_bytes();cm=json.loads((ROOT/'cases/manifest.json').read_bytes());ob=json.loads((ROOT/'evidence/oracle-build.json').read_bytes())
  assert sha(cr)==cm['sha256']==ob['cases_sha256'] and sha(rr)==ob['observations_sha256']
  assert json.loads((ROOT/'evidence/target-lock-subset.json').read_bytes())['all_retained_exactly_match_target']
  modules=json.loads((ROOT/'evidence/hia-modules.json').read_bytes())['members'];sys.path.insert(0,str(ROOT/'scripts'));from hia_native_loader import NativeModule
  def module(name):
   m=modules[name];p=ROOT/m['path'];assert sha(p.read_bytes())==m['sha256'];return NativeModule(p,manifest_sha256=m['sha256'])
  with module('serde') as sm,module('response') as rm,module('typed') as tm:
   with sm.session(output_capacity=1<<20,workspace_capacity=32<<20) as canonical,rm.session(output_capacity=1<<20,workspace_capacity=96<<20) as response,tm.session(output_capacity=1<<20,workspace_capacity=96<<20) as typed:
    with (out/'native-events.jsonl').open('w') as events:
     for case,ref in zip([json.loads(x) for x in cr.splitlines()],[json.loads(x) for x in rr.splitlines()],strict=True):
      assert case['label']==ref['label'];mode=case['mode']
      if mode=='session':continue
      if mode=='typed-emitter':
       raw=typed(frame(b'HRTYP001',ref['tag'],ref['body'].encode()));expected=ref['typed_bytes'].encode()
       assert raw==expected,(case['label'],raw,expected);counts['typed_emitter_cases']+=1
       row={'label':case['label'],'mode':mode,'output_hex':raw.hex()}
      else:
       body=canonical(frame(b'HSJVAL01',1,case['wire'].encode()));counts['native_canonicalizations']+=1
       assert body==ref['canonical_input'].encode(),(case['label'],'canonical input')
       op=TYPES[case['type']]+(case['policy']<<8)
       raw=response(frame(b'HRRSP001',op,body));counts['native_response_calls']+=1
       row={'label':case['label'],'mode':mode,'canonical_input_hex':body.hex(),'projection_hex':raw.hex()}
       events.write(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n');events.flush()
       assert raw[:8]==b'HRRPO001' and len(raw)>=64,(case['label'],'header')
       fields=struct.unpack('<7Q',raw[8:64]);assert fields[0]==ref['kind'] and fields[1]==ref['flags'],(case['label'],'kind or presence',fields,ref)
       assert fields[2]==64 and fields[3]==len(raw)-64 and fields[4]==case['policy'] and fields[5:]==(0,0)
       assert raw[64:]==ref['wire'].encode(),(case['label'],raw[64:],ref['wire'])
       counts['response_cases']+=1
       if case['label'].startswith('meta-only-custom'):
        assert ref['kind']==3 and ref['direct_call_tool_accepted'] is False;counts['meta_only_custom_results']+=1
       if ref['kind']==1:
        if 'structuredContent' in ref['projection'] and ref['projection']['structuredContent'] is None:counts['present_structured_null']+=1
        if 'structuredContent' not in ref['projection']:counts['absent_structured']+=1
       if ref['kind']==2:counts['read_resource_cases']+=1
       if 4<=ref['kind']<=8:counts['cache_list_cases']+=1
       save();continue
      events.write(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n');events.flush()
  assert counts['response_cases']==215 and counts['typed_emitter_cases']==119 and counts['meta_only_custom_results']==3
  report.update(status='PASS',modules=modules,cases_sha256=sha(cr),oracle_sha256=sha(rr),native_events_sha256=sha((out/'native-events.jsonl').read_bytes()),response_composition_sha256=sha((ROOT/'native/sdk_response_composition.json').read_bytes()),typed_emitter_source_unchanged=True,boundaries=['CallTool structured null versus absence','_meta-only custom result','ordinary CallTool content types and annotation binary32 narrowing','ReadResource typed contents and optional fields','legacy complete resultType stripping','modern conservative cache defaults and explicit public/private retention','119 retained typed constructed value serialization cases'])
 except BaseException:report.update(status='FAIL',failure=traceback.format_exc());raise
 finally:report['elapsed_seconds']=time.monotonic()-start;save()
 print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
