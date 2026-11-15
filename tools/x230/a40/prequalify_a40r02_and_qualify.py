import pathlib,json,hashlib,subprocess,os,time
p=pathlib.Path('/home/qian/hepta-runtime-optimization-20261023');b=p/'a40-staggered-output-recovery-20261025-r02';assert json.loads((b/'preparation.json').read_text())['phase']=='ready'
out=b/'prequalification-proofs-r01';os.umask(0o077);out.mkdir(mode=0o700,exist_ok=False)
def raw(s,n):return s.split('const '+n+': &str = r#"',1)[1].split('"#;',1)[0]
def sha(v):return hashlib.sha256(v).hexdigest()
fp=b/'source/src/mcp/runtime/jobs_output_durability_tests.rs';fr=fp.read_bytes();fixture=raw(fr.decode(),'INHERITED_PIPE_FIXTURE');(out/'fixture.py').write_text(fixture)
report={'schema':'hepta-a40-r02-original-fault-prequalification/v1','passed':False,'fixture_source_sha256':sha(fr),'fixture_sha256':sha(fixture.encode()),'cases':[]}
try:
 variants=[('A38-staggered',p/'a38-integration-20261025-r01/source',True,False,True,False,'natural'),('A39-staggered',p/'a39-inherited-pipe-recovery-20261025-r01/source',True,False,True,False,'unknown'),('A40-r01-read-fault',p/'a40-staggered-output-recovery-20261025-r01/source',False,False,True,True,'legacy_gap'),('A40-r02-staggered',b/'source',True,False,True,False,'natural'),('A40-r02-timeout',b/'source',False,False,True,False,'unknown'),('A40-r02-cancel-ignore',b/'source',False,True,True,False,'unknown'),('A40-r02-cancel-term',b/'source',False,True,False,False,'unknown'),('A40-r02-read-fault',b/'source',False,False,True,True,'unknown')]
 for label,source,staggered,cancel,ignore,read_fault,expected in variants:
  file=source/'src/mcp/runtime/jobs.rs';data=file.read_bytes();s=data.decode();runner=raw(s,'PRIVATE_DIRECTORY_CODE')+'\n'+raw(s,'START_CODE').split("runner = r'''",1)[1].split("\n'''\nrunner_path",1)[0]+'\n';status=raw(s,'STATUS_CODE');fun='def final_status(exit_data):'+status.split('def final_status(exit_data):',1)[1].split('\ndef one_status():',1)[0]
  d=out/label;job=d/'state/jobs/inherited-pipe-durability';job.mkdir(mode=0o700,parents=True)
  q={'job':str(job),'runner':runner,'status_function':fun,'cancel_overlap':cancel,'ignore_term':ignore,'staggered':staggered,'read_fault':read_fault};(d/'input.json').write_text(json.dumps(q))
  began=time.monotonic();r=subprocess.run(['/usr/bin/python3','-I','-S','-c',fixture],input=json.dumps(q).encode(),capture_output=True,timeout=45)
  (d/'stdout.json').write_bytes(r.stdout);(d/'stderr.log').write_bytes(r.stderr)
  item={'label':label,'source_sha256':sha(data),'runner_sha256':sha(runner.encode()),'seconds':time.monotonic()-began,'fixture_exit_code':r.returncode,'stdout_sha256':sha(r.stdout),'stderr_sha256':sha(r.stderr),'expected':expected};report['cases'].append(item);assert r.returncode==0;v=json.loads(r.stdout);item['observed']=v;assert file.read_bytes()==data;assert v['cleanup']==[];assert v['state']['runner_exception'] is None
  assert v['workload_popen_count']==1 and len(v['adopted'])==1
  if expected=='natural':
   assert v['receipt']['output_complete'] is True and v['receipt']['output_durable'] is True and v['state']['runner_exit']==0 and v['signals']==[] and v['adopted'][0]['returncode']==0
  elif expected=='legacy_gap':
   assert v['state']['runner_exit']==74 and v['signals']==[] and v['adopted'][0]['returncode']==0 and v['receipt'].get('effect_outcome')!='unknown'
  else:
   last=15 if cancel and not ignore else 9
   assert v['receipt']['effect_outcome']=='unknown' and v['receipt']['automatic_retry'] is False and v['receipt']['status_authoritative'] is False and v['receipt']['output_complete'] is False and v['receipt']['output_durable'] is False and v['adopted'][0]['returncode']==-last and v['state']['runner_exit']==125
   assert all(e['group']==v['workload_pid'] and e['original_child_unreaped'] and e['original_leader_exited'] and e['returned'] for e in v['signals'])
  if read_fault:
   assert v['state']['read_fault_calls']=={'stdout':1,'stderr':1}
   assert v['state']['log_eof_at_runner_return']=={'stdout':False,'stderr':False}
   assert v['receipt']['log_errors']=={'stdout':'read: injected stdout read1 failure','stderr':'read: injected stderr read1 failure'}
  assert v['state']['readers_alive_at_runner_return']==[False,False]
  assert v['witness']['exit_sha256']==v['originals']['exit.json']['sha256']
  assert v['witness']['job_id']==v['receipt']['job_id'] and v['witness']['launch_nonce']==v['receipt']['launch_nonce']
  item['expected_outcome_confirmed']=True
 report['passed']=True
finally:
 (out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
assert report['passed']
env=dict(os.environ,CARGO_HOME=str(p/'cargo-home-a32-a33-r02'),PATH='/home/qian/.cargo/bin:/usr/local/bin:/usr/bin:/bin')
for k in list(env):
 if k.startswith(('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_PROFILE_','CARGO_BUILD_','HEPTA_')):env.pop(k)
args=['/usr/bin/python3',str(b/'tools/qualify_runtime_candidate.py'),'--source',str(b/'source'),'--output',str(b/'qualification'),'--target-dir',str(b/'target'),'--cargo','/home/qian/.cargo/bin/cargo','--toolchain','1.95.0','--jobs','2']
os.execve(args[0],args,env)
