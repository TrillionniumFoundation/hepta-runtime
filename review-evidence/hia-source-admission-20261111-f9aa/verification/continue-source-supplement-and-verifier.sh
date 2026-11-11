umask 077
python3 - <<'PY'
from pathlib import Path
from hashlib import sha256, sha1
from datetime import datetime, timezone
import base64, json, re, subprocess, zipfile
root=Path('/tmp/hia-runtime-evidence-f9aa-20261111')
assert root.is_dir()
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
 if path.exists():
  assert path.is_file() and path.stat().st_size > 0, path
  return
 with path.open('xb') as out, path.with_suffix(path.suffix+'.stderr.log').open('xb') as err:
  result=subprocess.run(['/usr/bin/gh','api',endpoint],stdout=out,stderr=err)
 if result.returncode: raise RuntimeError('GitHub download failed: '+str(path)+' exit '+str(result.returncode))
original_status={"at_unix_ms":1794400215130,"audit_recorded":True,"automatic_retry":False,"cancelled":False,"exit_code":1,"job_id":"1a1ca8bed31-2564-6b8","launch_nonce":"2210805d7195395f2d109506632bf16e","log_bytes":{"stderr":{"seen":208,"stored":208},"stdout":{"seen":0,"stored":0}},"log_errors":{"stderr":None,"stdout":None},"log_synced":{"stderr":True,"stdout":True},"log_truncated":{"stderr":False,"stdout":False},"output_complete":True,"output_durable":True,"state":"failed","terminal_publication_confirmed":True,"terminal_publication_protocol":1,"timed_out":False}
original_stderr="Traceback (most recent call last):\n  File \"<stdin>\", line 75, in <module>\n  File \"<stdin>\", line 52, in member\nAssertionError: ('hia-common-cold.cold/source/.github/workflows/hia-candidate-bindings.yml', [])\n"
save(root/'download-attempt1-status.json',original_status)
(root/'download-attempt1.stderr.log').write_text(original_stderr)
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
custody={'schema':'hepta.runtime.hia-source-admission-evidence-custody.v1','status':'STARTED','created_at':datetime.now(timezone.utc).isoformat(),'download_idempotency_key':'hia-runtime-evidence-f9aa-download-20261111-v1','continuation_idempotency_key':'hia-runtime-evidence-f9aa-download-supplement-20261111-v2','original_additional_archive_source_check':{'status':'FAIL','job_id':'1a1ca8bed31-2564-6b8','reason':'source_manifest contains hidden workflow sources absent from original artifact; original bytes retained','stderr_file':'download-attempt1.stderr.log','status_file':'download-attempt1-status.json'},'runtime_source':runtime,'runtime_tree':runtime_commit['tree']['sha'],'hepta_source':hepta,'hepta_tree':hepta_commit['tree']['sha'],'source_files':len(sources),'artifacts':[],'scope':{'production_activated':False,'whole_worker_native':False,'original_artifacts_modified':False,'new_native_run':False}}
save(root/'custody-complete.json',custody)
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
  coverage={'schema':'hepta.runtime.hia-original-archive-source-coverage.v1','event':label,'runtime_source':runtime,'hepta_source':hepta,'source_manifest_sha256':digest(canonical(sources)),'source_files':len(sources),'archive_present':[],'archive_absent':[],'supplement':[]}
  supplement_root=root/'source-supplement'
  for path,source_hash in sources.items():
   suffix='hia-common-cold.cold/source/'+path
   candidates=[name for name in names if name==suffix or name.endswith('/'+suffix)]
   if candidates:
    assert len(candidates)==1, (path,candidates)
    assert digest(z.read(candidates[0]))==source_hash,path
    coverage['archive_present'].append(path)
   else:
    coverage['archive_absent'].append(path)
    metadata=api('repos/TrillionniumFoundation/Hepta/contents/'+path+'?ref='+hepta)
    assert metadata['type']=='file' and metadata['encoding']=='base64',path
    raw=base64.b64decode(metadata['content'])
    assert digest(raw)==source_hash,path
    git_blob=sha1(b'blob '+str(len(raw)).encode()+bytes([0])+raw).hexdigest()
    assert git_blob==metadata['sha'],path
    target=supplement_root/path
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists():
     assert target.read_bytes()==raw,path
    else:
     target.write_bytes(raw)
    coverage['supplement'].append({'path':path,'git_blob':git_blob,'sha256':source_hash,'bytes':len(raw),'repository':'TrillionniumFoundation/Hepta','source_commit':hepta,'git_blob_url':metadata['git_url']})
  coverage['archive_present'].sort()
  coverage['archive_absent'].sort()
  assert set(coverage['archive_present']).isdisjoint(coverage['archive_absent'])
  assert set(coverage['archive_present']) | set(coverage['archive_absent']) == set(sources)
  coverage['archive_present_count']=len(coverage['archive_present'])
  coverage['archive_absent_count']=len(coverage['archive_absent'])
  coverage['original_archive_source_coverage']='COMPLETE' if not coverage['archive_absent'] else 'PARTIAL_HIDDEN_SOURCES_OMITTED'
  coverage['archived_sources_verified']=True
  coverage['missing_sources_verified_against_pinned_git_blobs']=True
  coverage_file=root/('source-coverage-'+label+'.json')
  save(coverage_file,coverage)
  save(supplement_root/'manifest.json',{'schema':'hepta.runtime.hia-pinned-source-supplement.v1','hepta_source':hepta,'original_artifacts_modified':False,'files':coverage['supplement']})
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
  row={'event':label,'run_id':run_id,'job_id':job_id,'run_attempt':1,'artifact_id':artifact_id,'file':archive.name,'bytes':size,'sha256':expected,'zip_members':len(names),'crc':'PASS','all_archived_source_hashes_match_selected_git_contract':True,'source_files_checked':len(sources),'source_archive_coverage':coverage['original_archive_source_coverage'],'archive_present_count':coverage['archive_present_count'],'archive_absent_count':coverage['archive_absent_count'],'source_coverage_file':coverage_file.name,'source_coverage_sha256':digest(coverage_file.read_bytes()),'archive_absent':coverage['archive_absent'],'cold_checks':len(cold['checks']),'cold_wall_elapsed_ns':cold['wall_elapsed_ns'],'language_checks':1242,'joint_checks':len(report['checks']),'scripted_calls':len(report['calls']),'transport_sessions':len(report['transport_sessions']),'cold_sha256':digest(cold_raw),'joint_report_sha256':digest(member('hia-common-native/report.json')),'native_helper_bundle_sha256':pins['native_helpers_sha256'],'native_helper_image_sha256':build['manifest']['image_sha256'],'runtime_binary_sha256':report['runtime_binary_sha256'],'client_sha256':report['client_sha256'],'verification':'PASS'}
  custody['artifacts'].append(row)
  save(root/'custody-complete.json',custody)
  print(json.dumps(row,sort_keys=True),flush=True)
custody['status']='PASS'
custody['completed_at']=datetime.now(timezone.utc).isoformat()
save(root/'custody-complete.json',custody)
print(json.dumps({'status':'PASS','directory':str(root),'custody_sha256':digest((root/'custody-complete.json').read_bytes())}),flush=True)
PY