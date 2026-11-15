from pathlib import Path
workspace=Path('/home/qian-qi/work/hepta-rea-jadx-operator-umask022-20261103-r1')
harness='tests/rea_java_external.py'
engine_arguments=['--java-home','/usr/lib/jvm/java-21-openjdk-amd64','--jadx-home','/home/qian-qi/work/hepta-rea-engines-20261103-r1/jadx']
from pathlib import Path
import os,sys,json,hashlib,subprocess,time,stat
repo=Path('/home/qian-qi/hepta-runtime-rea-full-20261103-r1')
runtime=Path('/home/qian-qi/work/hepta-rea-runtime-umask022-20261103-r1')
expected_runtime='290fa949b7744c85018f9f26b32fbdd1884cce1c31ff202a9f076bc3d6a89c63'
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as source:
  while block:=source.read(1048576):h.update(block)
 return h.hexdigest()
def status(pid):
 text=Path(f'/proc/{pid}/status').read_text()
 values=dict(line.split(':',1) for line in text.splitlines() if ':' in line)
 return {key:values.get(key,'').strip() for key in ('Name','Umask','Uid','NoNewPrivs','Seccomp','Seccomp_filters')}
def identity(pid):
 return Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19]
def record_private(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as out:
  json.dump(value,out,indent=2);out.write('\n');out.flush();os.fsync(out.fileno())
source_names=['Cargo.toml','Cargo.lock','src/mcp/runtime/config.rs','src/mcp/runtime/config_tests.rs','src/mcp/rea_provider.rs','src/mcp/rea_static.rs','src/mcp/rea_static_summary.rs','src/mcp/rea_engine.rs','src/mcp/rea_engine_profile.rs','src/mcp/rea_engine_ghidra.rs','src/mcp/rea_jadx_bridge.java','src/mcp/rea_ghidra_bridge.java','tests/rea_java_external.py','tests/rea_java_kernel_probe.py','tests/rea_ghidra_external.py']
expected_harnesses={'tests/rea_java_external.py':'39d0f80ff09b6647c030cab4a0a80afa43e91253c07b4e5eff701f50b4728e07','tests/rea_java_kernel_probe.py':'09676e856ede6109595bc4c30d9833117f161f0da188818a3ac924041ff9036c','tests/rea_ghidra_external.py':'06cab1fe063671d84a069b9c0ecc5e1aedf29d8d4cc21d8fdb5d2c6d1a201257'}
os.umask(0o022)
outer=status(os.getpid())
assert outer['Umask']=='0022',outer
assert not workspace.exists(),workspace
assert digest(runtime)==expected_runtime
source_before={name:digest(repo/name) for name in source_names}
assert source_before['src/mcp/runtime/config.rs'].startswith('836b9a85'),source_before['src/mcp/runtime/config.rs']
assert all(source_before[name]==value for name,value in expected_harnesses.items())
started=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
arguments=[sys.executable,'-u',str(repo/harness),'--runtime',str(runtime)]+engine_arguments+['--workspace',str(workspace),'--execution-mode','operator','--allow-local-ssh']
child=subprocess.Popen(arguments,cwd=repo,umask=0o022)
observations={}
harness_status=status(child.pid)
assert harness_status['Umask']=='0022',harness_status
deadline=time.monotonic()+550
try:
 while child.poll() is None:
  try:
   children=set()
   for entry in Path(f'/proc/{child.pid}/task').glob('*/children'):
    try:children.update(int(value) for value in entry.read_text().split())
    except OSError:pass
   for pid in sorted(children):
    try:
     executable=os.readlink(f'/proc/{pid}/exe')
     if executable!=str(workspace/'hepta-runtime-qualified'):continue
     cmdline=Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
     operation=cmdline[1].decode() if len(cmdline)>1 else ''
     if operation not in ('mcp','rea-static-worker'):continue
     begin=identity(pid);flags=status(pid)
     observations[(pid,begin)]={'pid':pid,'start_time':begin,'executable':executable,'operation':operation,**flags}
    except (OSError,IndexError,UnicodeDecodeError):pass
  except OSError:pass
  if time.monotonic()>deadline:raise TimeoutError('original qualification harness exceeded wrapper deadline')
  time.sleep(0.05)
 code=child.wait()
finally:
 if child.poll() is None:
  child.terminate()
  try:child.wait(timeout=10)
  except subprocess.TimeoutExpired:child.kill();child.wait()
 source_after={name:digest(repo/name) for name in source_names}
 modes={}
 for name in ('.','controller-state','authority','jobs','config.json','authority/.owner.lock','authority/.owner.json'):
  path=workspace/name
  if path.exists():modes[name]=format(stat.S_IMODE(path.stat().st_mode),'04o')
 receipt={'schema':'hepta.rea.explicit-umask-launch.v1','started_utc':started,'finished_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'requested_umask':'0022','outer_process_flags':outer,'harness_pid':child.pid,'harness_process_flags':harness_status,'runtime_sha256':expected_runtime,'harness_relative_path':harness,'harness_sha256':source_before[harness],'arguments':arguments,'harness_exit_code':child.returncode,'runtime_children_observed':list(observations.values()),'fixture_modes':modes,'source_before':source_before,'source_after':source_after,'source_unchanged':source_before==source_after,'build_job':'1a1a18da495-96a-6fb4','scope':'Explicit 0022 on outer wrapper, original unchanged harness, direct MCP controller and direct native worker. Remote SSH/systemd owner umask is not independently attested. Operator qualification, not GitHub CI or isolated-host qualification. Fixture precreates controller-state as0700; missing-root bootstrap is covered by separate focused runtime tests. config_tests.rs changed after this binary build and is recorded as test-only source context.'}
 if workspace.exists():record_private(workspace/'launch-environment.json',receipt)
assert code==0,code
assert source_before==source_after
assert {row['operation'] for row in observations.values()}=={'mcp','rea-static-worker'},observations
assert all(row['Umask']=='0022' for row in observations.values()),observations
assert all(modes[name]=='0700' for name in ('.','controller-state','authority','jobs')),modes
assert all(modes[name]=='0600' for name in ('config.json','authority/.owner.lock','authority/.owner.json')),modes
qualification=json.loads((workspace/'qualification.json').read_text())
assert qualification['qualified'] is True and qualification['runtime_sha256']==expected_runtime,qualification
print('REA_UMASK022_QUALIFICATION '+json.dumps({'workspace':str(workspace),'runtime_sha256':expected_runtime,'qualified':True,'observed_runtime_processes':len(observations),'config_rs_sha256':source_before['src/mcp/runtime/config.rs'],'qualification_sha256':digest(workspace/'qualification.json'),'launch_environment_sha256':digest(workspace/'launch-environment.json')},separators=(',',':')),flush=True)

