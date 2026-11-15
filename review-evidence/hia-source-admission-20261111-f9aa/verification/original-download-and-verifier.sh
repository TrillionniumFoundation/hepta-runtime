umask 077
python3 - <<'PY'
from pathlib import Path
from hashlib import sha256
from datetime import datetime, timezone
import base64, json, re, subprocess, zipfile
root=Path('/tmp/hia-runtime-evidence-f9aa-20261111')
root.mkdir(mode=0o700, exist_ok=False)
repo='TrillionniumFoundation/hepta-runtime'
runtime='7924a0c3545125f7a1c3c888adc63f6515668063'
hepta='7c20b6cfc792f0147b5418968f94734b8890fcca'
cases=[
 ('push',43016837973,130509912041,13854030779,64640752,'152676ded50e6fa9c6d0380f107ef88bd9f70135344b4a3f6b9afa1c3aba9721'),
 ('pr',43016939924,130510252525,13853837009,64675363,'d56dbb51331bbab23883c586aea29cdfa014d4676e429e1de82c27d29cac9645')]
def digest(raw): return sha256(raw).hexdigest()
def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def save(path,value): path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def api(endpoint):
 return json.loads(subprocess.check_output(['/usr/bin/gh','api',endpoint]))
def download(endpoint,path):
 with path.open('xb') as out, path.with_suffix(path.suffix+'.stderr.log').open('xb') as err:
  result=subprocess.run(['/usr/bin/gh','api',endpoint],stdout=out,stderr=err)
 if result.returncode: raise RuntimeError('GitHub download failed: '+str(path)+' exit '+str(result.returncode))
def get_raw(repository,path,ref):
 data=api('repos/'+repository+'/contents/'+path+'?ref='+ref)
 assert data.get('encoding')=='base64', path
 return base64.b64decode(data['content'])
runtime_commit=api('repos/'+repo+'/git/commits/'+runtime)
hepta_commit=api('repos/TrillionniumFoundation/Hepta/git/commits/'+hepta)
support_raw=get_raw('TrillionniumFoundation/Hepta','docs/HIA_SELFHOST_CORE_SUPPORT.json',hepta)
support=json.loads(support_raw)
sources={**support['source_identity']['files'],'docs/HIA_SELFHOST_CORE_SUPPORT.json':digest(support_raw)}
client_raw=get_raw(repo,'tests/hia_native_helper_mcp_integration.py',runtime)
catalog_raw=get_raw(repo,'src/mcp/hia_tool_catalog.json',runtime)
required_checks={'actual_identity_image_accept_and_reject','actual_request_profile_and_helper_bound_report_retained','actual_tools_list_and_frozen_family_contract_match','common_catalog_and_native_installation','eleven_tool_scripted_loop','fixed_candidate_source_preserved','native_lease_survives_rollback_and_release_refuses','old_operation_observed_through_native_owner','restart_exact_replay_without_new_job','wrong_pin_unknown_keeps_original_job_across_restart'}
custody={'schema':'hepta.runtime.hia-source-admission-evidence-custody.v1','status':'STARTED','created_at':datetime.now(timezone.utc).isoformat(),'download_idempotency_key':'hia-runtime-evidence-f9aa-download-20261111-v1','runtime_source':runtime,'runtime_tree':runtime_commit['tree']['sha'],'hepta_source':hepta,'hepta_tree':hepta_commit['tree']['sha'],'source_files':len(sources),'artifacts':[],'scope':{'production_activated':False,'whole_worker_native':False,'original_artifacts_modified':False,'new_native_run':False}}
save(root/'custody.json',custody)
for label,run_id,job_id,artifact_id,size,expected in cases:
 run=api('repos/'+repo+'/actions/runs/'+str(run_id))
 artifact=api('repos/'+repo+'/actions/artifacts/'+str(artifact_id))
 assert run['head_sha']==runtime and run['run_attempt']==1 and run['status']=='completed' and run['conclusion']=='success'
 assert artifact['size_in_bytes']==size and artifact['digest']=='sha256:'+expected and artifact['workflow_run']['id']==run_id
 save(root/(label+'-run.json'),run); save(root/(label+'-artifact.json'),artifact)
 archive=root/('joint-'+label+'-7924a0-attempt1.zip')
 download('repos/'+repo+'/actions/artifacts/'+str(artifact_id)+'/zip',archive)
 assert archive.stat().st_size==size and digest(archive.read_bytes())==expected, 'ZIP bytes differ'
 download('repos/'+repo+'/actions/jobs/'+str(job_id)+'/logs',root/(label+'-original-job.log'))
 with zipfile.ZipFile(archive) as z:
  names=z.namelist()
  assert len(names)==len(set(names)), 'duplicate archive names'
  assert z.testzip() is None, 'CRC mismatch'
  def member(suffix):
   candidates=[name for name in names if name==suffix or name.endswith('/'+suffix)]
   assert len(candidates)==1, (suffix,candidates)
   return z.read(candidates[0])
  def document(suffix): return json.loads(member(suffix))
  report=document('hia-common-native/report.json')
  cold_raw=member('hia-common-cold.json'); cold=json.loads(cold_raw)
  nested_raw=member('hia-common-cold.cold/qualification.json'); nested=json.loads(nested_raw)
  language=document('hia-common-language.json')
  stages=document('hia-common-stage/stage-outcomes.json')
  assert report['schema']=='hepta.runtime.hia-native-helper-integration.v1' and report['status']=='PASS'
  assert set(report['checks'])==required_checks and all(value is True for value in report['checks'].values())
  assert report['cleanup_errors']==[]
  expected_sources={'runtime':{'commit':runtime,'tree':runtime_commit['tree']['sha']},'hepta':{'commit':hepta,'tree':hepta_commit['tree']['sha']}}
  assert report['sources']==report['sources_after']==expected_sources
  assert report['client_sha256']==digest(client_raw)
  assert report['scope']['whole_worker_native'] is False and report['scope']['production_deployed'] is False
  assert cold['status']=='COLD_SELFHOST_REPLAY_PASS' and cold['returncode']==0
  assert len(cold['checks'])==11 and all(value is True for value in cold['checks'].values())
  assert cold['qualification_wall_limit_seconds']==180 and cold['cleanup_wall_limit_seconds']==3
  assert cold['profile']==nested['profile']==support['profile']
  assert cold['source_manifest']==nested['source_manifest']==sources
  assert digest(nested_raw)==cold['nested_report_sha256']
  assert nested['status']=='SELF_HOSTED_FIXED_CORE_PASS'
  for path,source_hash in sources.items():
   assert digest(member('hia-common-cold.cold/source/'+path))==source_hash,path
  compiler=cold['generation_sha256'][0]
  assert cold['generation_sha256']==[compiler]*3
  assert len(nested['generations'])==3 and all(row['produced_sha256']==compiler for row in nested['generations'])
  compiler_suffix=nested['generations'][-1]['produced_image'].split('/hia-common-cold.cold/',1)[1]
  assert digest(member('hia-common-cold.cold/'+compiler_suffix))==compiler
  binding=report['cold_source_binding']
  assert binding=={'profile':support['profile'],'source_manifest_sha256':digest(canonical(sources)),'support_contract_sha256':digest(support_raw),'compiler_sha256':compiler,'nested_report_sha256':digest(nested_raw)}
  assert report['cold_report_sha256']==digest(cold_raw)
  assert language['status']=='SELFHOST_LANGUAGE_COVERAGE_PASS' and language['counts']['checks_passed']==language['counts']['checks_total']==1242
  assert language['source_manifest']==sources and language['profile']==support['profile']
  assert stages['status']=='PASS' and all(value=='success' for value in stages['original_stage_outcomes'].values())
  assert stages['runtime_source']==runtime and stages['hepta_source']==hepta
  pins=report['installation']
  assert pins==document('hia-common-native/installation.stdout.json')
  assert pins['catalog_sha256']==digest(catalog_raw)
  assert digest(member('hia-common-native/native-helpers.json'))==pins['native_helpers_sha256']
  build=report['native_build']
  assert build==document('hia-common-native/native-helper/build.json')
  assert build['status']=='NATIVE_CANDIDATE_BUILT' and build['cold_report_sha256']==digest(cold_raw)
  assert build['manifest']['compiler_sha256']==compiler
  assert digest(member('hia-common-native/native-helper/'+build['manifest']['image_path']))==build['manifest']['image_sha256']
  assert build['native_compile_receipt']['produced_sha256']==build['manifest']['image_sha256']
  assert build['native_compile_receipt']['input_sha256']==build['manifest']['source_sha256']
  assert build['native_compile_receipt']['status']=='returned'
  retained=report['retained_original_worker_report']
  assert all(retained[key]==value for key,value in pins.items()) and retained['complete'] is True
  assert retained['response']==report['replayed_response']
  assert report['old_operation_observation']['job_id']==report['original_operation']['id']
  wrong=report['wrong_pin_original_failure']
  assert wrong['response']['operation']==wrong['repeat']['operation']==wrong['after_restart']['operation']
  assert all(wrong[key]['status']=='unknown' for key in ('response','repeat','after_restart'))
  assert wrong['owner_status']['exit_code']==2 and wrong['owner_status']['terminal_publication_confirmed'] is True
  logs=(root/(label+'-original-job.log')).read_text()
  assert re.search(r'Ran 20 tests in ',logs) and 'COLD_SELFHOST_REPLAY_PASS' in logs
  row={'event':label,'run_id':run_id,'job_id':job_id,'run_attempt':1,'artifact_id':artifact_id,'file':archive.name,'bytes':size,'sha256':expected,'zip_members':len(names),'crc':'PASS','all_archived_source_hashes_match_selected_git_contract':True,'source_files_checked':len(sources),'cold_checks':len(cold['checks']),'cold_wall_elapsed_ns':cold['wall_elapsed_ns'],'language_checks':1242,'joint_checks':len(report['checks']),'scripted_calls':len(report['calls']),'transport_sessions':len(report['transport_sessions']),'cold_sha256':digest(cold_raw),'joint_report_sha256':digest(member('hia-common-native/report.json')),'native_helper_bundle_sha256':pins['native_helpers_sha256'],'native_helper_image_sha256':build['manifest']['image_sha256'],'runtime_binary_sha256':report['runtime_binary_sha256'],'client_sha256':report['client_sha256'],'verification':'PASS'}
  custody['artifacts'].append(row)
  save(root/'custody.json',custody)
  print(json.dumps(row,sort_keys=True),flush=True)
custody['status']='PASS'
custody['completed_at']=datetime.now(timezone.utc).isoformat()
save(root/'custody.json',custody)
print(json.dumps({'status':'PASS','directory':str(root),'custody_sha256':digest((root/'custody.json').read_bytes())}),flush=True)
PY