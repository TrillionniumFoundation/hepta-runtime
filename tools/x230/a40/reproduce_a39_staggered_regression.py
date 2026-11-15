import pathlib,json,hashlib,subprocess,os,time
p=pathlib.Path('/home/qian/hepta-runtime-optimization-20261023');b=p/'a39-inherited-pipe-recovery-20261025-r01';out=b/'staggered-regression-r01';os.umask(0o077);out.mkdir(mode=0o700,exist_ok=False)
def raw(s,n):return s.split('const '+n+': &str = r#"',1)[1].split('"#;',1)[0]
def sha(v):return hashlib.sha256(v).hexdigest()
fp=b/'source/src/mcp/runtime/jobs_output_durability_tests.rs';fr=fp.read_bytes();fixture=raw(fr.decode(),'INHERITED_PIPE_FIXTURE')
old='    time.sleep(8)\n';new='    time.sleep(1.0)\n    os.close(1)\n    time.sleep(1.5)\n    os.close(2)\n';assert fixture.count(old)==1;fixture=fixture.replace(old,new)
(out/'fixture.py').write_text(fixture)
report={'schema':'hepta-staggered-output-compatibility-regression/v1','fixture_source_sha256':sha(fr),'modified_fixture_sha256':sha(fixture.encode()),'fixture_change':'One bounded original grandchild closes stdout at about 1 s and stderr at about 2.5 s instead of holding both for 8 s; no cancellation.','cases':[],'regression_reproduced':False}
try:
 for label,source in [('A38',p/'a38-integration-20261025-r01/source'),('A39',b/'source')]:
  file=source/'src/mcp/runtime/jobs.rs';data=file.read_bytes();s=data.decode();runner=raw(s,'PRIVATE_DIRECTORY_CODE')+'\n'+raw(s,'START_CODE').split("runner = r'''",1)[1].split("\n'''\nrunner_path",1)[0]+'\n';status=raw(s,'STATUS_CODE');fun='def final_status(exit_data):'+status.split('def final_status(exit_data):',1)[1].split('\ndef one_status():',1)[0]
  d=out/label;job=d/'state/jobs/inherited-pipe-durability';job.mkdir(mode=0o700,parents=True)
  q={'job':str(job),'runner':runner,'status_function':fun,'cancel_overlap':False,'ignore_term':True};(d/'input.json').write_text(json.dumps(q))
  began=time.monotonic();r=subprocess.run(['/usr/bin/python3','-I','-S','-c',fixture],input=json.dumps(q).encode(),capture_output=True,timeout=45)
  (d/'stdout.json').write_bytes(r.stdout);(d/'stderr.log').write_bytes(r.stderr)
  item={'label':label,'source_sha256':sha(data),'runner_sha256':sha(runner.encode()),'seconds':time.monotonic()-began,'fixture_exit_code':r.returncode,'stdout_sha256':sha(r.stdout),'stderr_sha256':sha(r.stderr)};report['cases'].append(item);assert r.returncode==0;item['observed']=json.loads(r.stdout);assert file.read_bytes()==data;assert item['observed']['cleanup']==[]
 a,c=[x['observed'] for x in report['cases']]
 report['regression_reproduced']=(a['receipt']['output_complete'] is True and a['receipt']['exit_code']==0 and a['signals']==[] and a['adopted'][0]['returncode']==0 and c['receipt']['effect_outcome']=='unknown' and c['receipt']['output_complete'] is False and c['adopted'][0]['returncode']==-9)
 assert report['regression_reproduced']
finally:
 (out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
