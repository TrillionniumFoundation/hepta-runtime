import datetime,json,os,pathlib,subprocess
root=pathlib.Path('/home/qian/hepta-runtime-optimization-20261106-r35')
job=pathlib.Path('/home/qian/.local/state/hepta-runtime-mac-worker/jobs/1a1af5e240e-fc05-67f8')
unit='hepta-runtime-job-1a1af5e240e-fc05-67f8'
out={'schema':'hepta-r35-unknown-package-install-readonly-reconciliation/v1','observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'original_job_id':'1a1af5e240e-fc05-67f8','root_exists':os.path.lexists(root),'job_directory_exists':os.path.lexists(job),'qualification_was_not_requested':True}
if os.path.lexists(root):
 out['root_is_directory']=root.is_dir() and not root.is_symlink()
 if out['root_is_directory']:
  out['top_level_entries']=sorted(p.name for p in root.iterdir())
r=subprocess.run(['/usr/bin/systemctl','--user','show',unit,'--property=LoadState,ActiveState,SubState,MainPID,ExecMainPID'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,check=False)
out['unit_query']={'returncode':r.returncode,'stdout':r.stdout.decode(),'stderr':r.stderr.decode()}
out['inputs_modified']=False;out['install_or_qualification_reexecuted']=False
print(json.dumps(out,sort_keys=True))
