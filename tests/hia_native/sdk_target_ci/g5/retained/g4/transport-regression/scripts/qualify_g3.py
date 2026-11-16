#!/usr/bin/env python3
"""Finite normal G3 reference/native checks; no external or malformed domain."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess,sys,time,traceback
ROOT=Path(__file__).resolve().parents[1]
sha=lambda raw:hashlib.sha256(raw).hexdigest()
put=lambda path,data:path.write_text(json.dumps(data,sort_keys=True,indent=2)+'\n')

def main():
 p=argparse.ArgumentParser();p.add_argument('--run-name',default='normal-v1');p.add_argument('--fixture-manifest',default='hia-build-v2/g3-target-v1-elf/manifest.json');a=p.parse_args()
 assert a.run_name.replace('-','').isalnum()
 out=ROOT/'evidence'/a.run_name;out.mkdir()
 counts={'target_reference_rows':0,'model_native_calls':0,'elf_transport_cases':0,'elf_response_records':0,'codec_eof_reference_cases':0,'sdk_cancelled_pending_receives':0,'native_shutdown_calls':0,'native_shutdown_traces':0}
 summary={'schema':'hepta.g3.target-normal-qualification.v1','status':'RUNNING','counts':counts,'target_sdk':'rmcp 3.9.0','normal_domain_only':True,'actual_target_oracle':True,'historical_pass_reused':False,'full_async_runtime_qualified':False,'native_future_cancellation_qualified':False,'native_task_registry_qualified':False,'native_configurable_cap_qualified':False,'pending_protocol_error_write_qualified':False,'codec_decode_eof_used_as_async_transport_oracle':False,'production_activated':False,'old_path_removed':False,'full_target_qualified':False,'fresh_cold_qualified':False,'qualifier_sha256':sha(Path(__file__).read_bytes())}
 start=time.monotonic()
 def save():put(out/'summary.json',summary)
 save()
 try:
  cases_raw=(ROOT/'cases/normal.jsonl').read_bytes();refs_raw=(ROOT/'evidence/oracle-normal.jsonl').read_bytes()
  manifest=json.loads((ROOT/'cases/manifest.json').read_bytes());assert manifest['sha256']==sha(cases_raw)
  oracle=json.loads((ROOT/'evidence/oracle-build.json').read_bytes())
  assert oracle['actual_target_sdk_executed'] and oracle['cases_sha256']==sha(cases_raw) and oracle['observations_sha256']==sha(refs_raw)
  assert json.loads((ROOT/'evidence/target-lock-subset.json').read_bytes())['all_retained_exactly_match_target']
  for rel,r in manifest['files'].items():
   raw=(ROOT/rel).read_bytes();assert len(raw)==r['bytes'] and sha(raw)==r['sha256'],rel
  modules=json.loads((ROOT/'evidence/hia-modules.json').read_bytes())['members']
  for name,m in modules.items():assert sha((ROOT/m['path']).read_bytes())==m['sha256'],name
  pairs=list(zip([json.loads(x) for x in cases_raw.splitlines()],[json.loads(x) for x in refs_raw.splitlines()],strict=True))
  assert all(c['label']==r['label'] for c,r in pairs);counts['target_reference_rows']=len(pairs)
  fixture_manifest=ROOT/a.fixture_manifest;fm=json.loads(fixture_manifest.read_bytes());binary=fixture_manifest.parent/fm['executable']
  assert sha(binary.read_bytes())==fm['elf_sha256'];assert [m['name'] for m in fm['members']]==['message','connection','fixture','shutdown']
  for m in fm['members']:assert m['image_sha256']==modules[m['name']]['image_sha256']
  sys.path.insert(0,str(ROOT/'scripts'))
  from hia_native_loader import NativeModule
  from g1_projection_reference import compare
  with (out/'elf-events.jsonl').open('w') as events:
   for case,ref in pairs:
    if case['mode']!='async':continue
    assert ref['mode']=='async' and ref['writer_closed'] and ref['poll_shutdown_calls']==0 and ref['default_max_line_length']==16777216
    if 'cancel_receive_after' in case:assert ref['cancelled_pending_receive'];counts['sdk_cancelled_pending_receives']+=1
    if 'max_line_length' in case:
     assert case['max_line_length']==128 and len(ref['messages'])==1
     continue
    raw=(ROOT/case['input_file']).read_bytes();begin=time.monotonic();chunk=case['chunk_size'];chunk_writes=0
    proc=subprocess.Popen([str(binary)],cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
     if len(raw)<65536 and chunk<len(raw):
      for at in range(0,len(raw),chunk):proc.stdin.write(raw[at:at+chunk]);proc.stdin.flush();chunk_writes+=1
      proc.stdin.close();proc.stdin=None;stdout,stderr=proc.communicate(timeout=180)
     else:stdout,stderr=proc.communicate(raw,timeout=180)
     record={'label':case['label'],'input_sha256':sha(raw),'input_bytes':len(raw),'returncode':proc.returncode,'stdout_hex':stdout.hex(),'stderr_hex':stderr.hex(),'expected_stdout_sha256':sha(ref['writer_bytes'].encode()),'elapsed_seconds':time.monotonic()-begin,'chunk_write_calls':chunk_writes,'native_receive_future_cancellation_observed':False}
     events.write(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n');events.flush()
     assert proc.returncode==0 and stderr==b'',(case['label'],proc.returncode,stderr)
     assert stdout==ref['writer_bytes'].encode(),(case['label'],stdout,ref['writer_bytes'])
    except BaseException:
     if proc.poll() is None:proc.kill();proc.communicate()
     raise
    counts['elf_transport_cases']+=1;counts['elf_response_records']+=stdout.count(b'\n');save()
  msg=modules['message']
  with NativeModule(ROOT/msg['path'],manifest_sha256=msg['sha256']) as component:
   with component.session(output_capacity=1<<20,workspace_capacity=2<<20) as decoder:
    with (out/'model-events.jsonl').open('w') as events:
     for case,ref in pairs:
      if case['mode']!='model':continue
      assert ref['accepted'];raw=case['wire'].encode();projection=decoder(b'HRCJQ001'+struct.pack('<QQ',1,len(raw))+raw)
      events.write(json.dumps({'label':case['label'],'projection_hex':projection.hex()},sort_keys=True,separators=(',',':'))+'\n');events.flush()
      compare(case,raw,ref,projection);counts['model_native_calls']+=1
  codec_rows=[]
  for case,ref in pairs:
   if case['mode']!='codec-eof':continue
   assert ref['mode']=='codec-eof' and ref['default_max_length']==18446744073709551615 and ref['remaining_bytes']==0
   expected=2 if 'full-then' in case['label'] else 1;assert len(ref['messages'])==expected
   async_ref=next(r for c,r in pairs if c['label']==case['label'].removeprefix('codec-'));assert len(async_ref['messages'])==expected-1
   codec_rows.append({'label':case['label'],'codec_delivered':expected,'async_delivered':expected-1,'same_input_file_sha256':sha((ROOT/case['input_file']).read_bytes())});counts['codec_eof_reference_cases']+=1
  put(out/'codec-vs-async-eof.json',codec_rows)
  shutdown=next(r for c,r in pairs if c['mode']=='shutdown');es=shutdown['events'];names=[e['event'] for e in es]
  assert names.index('read_eof')<names.index('ready_handler_return')<names.index('write')<names.index('writer_drop')
  drop=next(e for e in es if e['event']=='writer_drop');assert drop['children_cancelled']==[True,True] and drop['external_cancelled'] is False
  assert shutdown['external_before_waiting'] is False and shutdown['external_after_waiting'] is True
  assert shutdown['poll_shutdown_calls']==0 and shutdown['quit']=='Closed' and 'pending_handler_observed_cancel' in names
  assert shutdown['writer_bytes']=='{"jsonrpc":"2.0","id":"ready","result":{}}\n'
  # Trusted queue/send observations project the original SDK trace. This
  # policy component does not implement a scheduler or token registry.
  traces=[('immediate-empty-eof',[(1,0,0,0,0),(2,0,0,0,0),(4,0,0,0,0),(5,0,0,0,0),(6,0,0,0,0)],[(1,1,0,0,0),(2,2,0,0,0),(3,3,1,0,0),(4,4,1,0,1),(5,5,1,1,1)]),('ready-response-and-pending-handler',[(1,0,0,2,0),(2,1,0,1,0),(2,0,0,1,0),(3,0,0,1,5000),(4,0,0,0,5000),(5,0,0,0,5000),(6,0,0,0,5000)],[(1,1,0,0,0),(1,1,0,0,0),(1,1,0,0,0),(2,2,0,0,0),(3,3,1,0,0),(4,4,1,0,1),(5,5,1,1,1)])]
  sd=modules['shutdown'];trace_rows=[]
  with NativeModule(ROOT/sd['path'],manifest_sha256=sd['sha256']) as component:
   for label,steps,expected in traces:
    observed=[]
    with component.session(output_capacity=96,workspace_capacity=128) as owner:
     for inputs,want in zip(steps,expected,strict=True):
      raw=owner(b'HRSQ0001'+struct.pack('<7Q',*inputs,0,0));assert len(raw)==96 and raw[:8]==b'HRSS0001'
      fields=struct.unpack('<11Q',raw[8:]);assert fields[:5]==want,(label,inputs,fields,want)
      assert fields[5]==5000 and fields[6:10]==inputs[1:]
      observed.append({'input':inputs,'output_hex':raw.hex(),'phase_action_child_external_writer':fields[:5]});counts['native_shutdown_calls']+=1
    trace_rows.append({'label':label,'observations':observed});counts['native_shutdown_traces']+=1
  put(out/'shutdown-policy-traces.json',{'actual_target_shutdown':shutdown,'native_traces':trace_rows,'full_task_registry_qualified':False})
  baseline=(ROOT/'baseline/sdk_message.hepta').read_text();new=(ROOT/'native/sdk_message.hepta').read_text();anchor='  v17:u64 = const() {"value":8388632}'
  assert baseline.count(anchor)==1 and new==baseline.replace(anchor,'  v17:u64 = const() {"value":16777239}')
  assert counts['model_native_calls']==197 and counts['elf_transport_cases']==25 and counts['codec_eof_reference_cases']==4
  assert counts['sdk_cancelled_pending_receives']==3 and counts['native_shutdown_calls']==12
  summary.update(status='PASS',normal_framing_fixture_qualified=True,normal_shutdown_policy_qualified=True,source_overlay_sha256=sha((ROOT/'source_overlay.json').read_bytes()),fixture_manifest_sha256=sha(fixture_manifest.read_bytes()),elf_sha256=fm['elf_sha256'],modules=modules,cases_sha256=sha(cases_raw),oracle_sha256=sha(refs_raw),sdk_default_limit_including_delimiter=16777216,message_only_guard_changed_from_frozen_G1=True,bounded_normal_domain=['LF/CRLF/BOM/Unicode/empty lines','ordinary fragmented writes','16 MiB default limit including delimiter','discard to LF and resume','EOF unterminated tail discard','codec EOF recorded separately','response drain before child cancellation and writer drop','RunningService handle lifetime separate','197 G1 projections preserved'])
 except BaseException:summary.update(status='FAIL',failure=traceback.format_exc());raise
 finally:summary['elapsed_seconds']=time.monotonic()-start;save()
 print(json.dumps(summary,sort_keys=True),flush=True)
if __name__=='__main__':main()
