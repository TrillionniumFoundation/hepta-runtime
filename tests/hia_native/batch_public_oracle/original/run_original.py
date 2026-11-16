"""Run the unchanged Batch SDK/method only after full native-first admission."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,shutil,signal,stat,subprocess,sys,time
sys.dont_write_bytecode=True
def need(x,m):
 if not x:raise ValueError(m)
def pin(p):
 raw=p.read_bytes();return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def canonical(x):return (json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode()
def save(p,x):
 with p.open('xb')as f:f.write(canonical(x))
def module(p,n):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def source_files(root):return {str(p.relative_to(root)):pin(p)for p in sorted(root.rglob('*'))if p.is_file()}
def ident(p):
 s=p.stat();return {'device':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,'mode':s.st_mode}
class Processes:
 def __init__(self,out,env):self.out=out;self.env=env;self.rows=[]
 def run(self,name,command,cwd,stdin=None,environment=None):
  d=self.out/'processes'/name;d.mkdir(parents=True);start=time.monotonic_ns();p=None;timed=False;error=None;code=None
  try:
   with (d/'stdout.bin').open('xb')as so,(d/'stderr.bin').open('xb')as se,open(stdin if stdin else os.devnull,'rb')as si:
    p=subprocess.Popen(command,cwd=cwd,env=environment or self.env,stdin=si,stdout=so,stderr=se,start_new_session=True,umask=0o077)
    status=Path('/proc/'+str(p.pid)+'/status').read_bytes();(d/'proc-status-at-start.txt').write_bytes(status)
    need(b'Umask:\t0077\n'in status,'actual original process umask')
    try:code=p.wait(timeout=180)
    except subprocess.TimeoutExpired:timed=True;os.killpg(p.pid,signal.SIGKILL);code=p.wait(timeout=5)
  except BaseException as e:error=repr(e);raise
  finally:
   end=time.monotonic_ns();row={'name':name,'command':list(map(str,command)),'cwd':str(cwd),'pid':None if p is None else p.pid,'timeout_seconds':180,'started_monotonic_ns':start,'finished_monotonic_ns':end,'elapsed_seconds':(end-start)/1e9,'exit_code':code,'timed_out':timed,'start_error':error,'environment':environment or self.env,'umask':63,'stdout':pin(d/'stdout.bin'),'stderr':pin(d/'stderr.bin')}
   save(d/'PROCESS.json',row);self.rows.append(row);(self.out/'PROCESSES.json').write_bytes(canonical(self.rows))
  need(code==0 and not timed,'actual original process failed '+name);return d,row
def main():
 p=argparse.ArgumentParser()
 for n in ('source','native-source','native-output','native-receipt','graph','output','cargo','rustc','strace'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();a=argparse.Namespace(**{k:v.absolute()for k,v in vars(a).items()});a.output.mkdir(parents=True,exist_ok=False);os.umask(0o077)
 save(a.output/'remote-process.json',{'pid':os.getpid(),'cgroup':Path('/proc/self/cgroup').read_text(),'argv':sys.argv,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text()})
 before=source_files(a.source);save(a.output/'SOURCE-FILES.json',before)
 q=module(a.source/'native_predecessor.py','_batch_public_native_predecessor')
 native_request={'source':str(a.native_source),'output':str(a.native_output),'graph':str(a.graph),'receipt':str(a.native_receipt),'origins':[('/','/')]}
 native=q.native_evidence(**native_request);save(a.output/'NATIVE-REQUEST.json',native_request);save(a.output/'NATIVE-EVIDENCE.json',native)
 save(a.output/'NATIVE-ADMISSION.json',{'complete_native':pin(a.output/'NATIVE-EVIDENCE.json'),'native_artifact_sha256':native['artifact_sha256'],'admitted_monotonic_ns':time.monotonic_ns(),'original_started':False})
 verifier=module(a.source/'oracle/verify_sources.py','_unchanged_batch_sources');materialized,proof=verifier.assemble(a.source/'oracle')
 crate=a.output/'crate'
 for n,raw in materialized.items():f=crate/n;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(raw)
 save(a.output/'SOURCE.json',proof);target=a.output/'target'
 env={'HOME':str(Path.home()),'PATH':str(a.rustc.parent)+':/usr/bin:/bin','RUSTC':str(a.rustc),'CARGO_BUILD_JOBS':'2','CARGO_TARGET_DIR':str(target),'LC_ALL':'C'}
 processes=Processes(a.output,env);tools={}
 for n,path in (('cargo',a.cargo),('rustc',a.rustc),('strace',a.strace)):
  dest=a.output/('tool-'+n);shutil.copyfile(path,dest);need(pin(dest)==pin(path),'retained actual tool');tools[n]={'invocation':str(path),'resolved':str(path.resolve()),'retained':str(dest),**pin(path)}
 save(a.output/'TOOLS.json',tools)
 rv,_=processes.run('rustc-version',[str(a.rustc),'--version','--verbose'],a.source)
 need(b'\nrelease: 1.95.0\n'in(rv/'stdout.bin').read_bytes() and b'\nhost: x86_64-unknown-linux-gnu\n'in(rv/'stdout.bin').read_bytes(),'fixed actualRust1.95')
 cv,_=processes.run('cargo-version',[str(a.cargo),'--version','--verbose'],a.source);need((cv/'stdout.bin').read_bytes().startswith(b'cargo 1.95.0 '),'fixed actualCargo1.95')
 processes.run('strace-version',[str(a.strace),'-V'],a.source)
 processes.run('build',[str(a.cargo),'build','--locked','--release','--manifest-path',str(crate/'Cargo.toml')],a.source)
 need((crate/'Cargo.lock').read_bytes()==materialized['Cargo.lock'],'locked actual dependency closure')
 shutil.copyfile(target/'.rustc_info.json',a.output/'target.rustc_info.json');need('1.95.0'in(a.output/'target.rustc_info.json').read_text(),'actual fresh compiler identity')
 binary=a.output/'reference.elf';shutil.copyfile(target/'release/hepta-batch-call-original',binary);binary.chmod(0o500)
 save(a.output/'BUILD.json',{'binary':pin(binary),'fresh_locked':True,'native_predecessor':pin(a.output/'NATIVE-EVIDENCE.json'),'source':proof})
 data=json.loads((a.native_output/'INPUTS.json').read_bytes());installed=json.loads((a.native_output/'INSTALLED-POLICIES.json').read_bytes())
 cases=module(a.source/'public_cases.py','_batch_public_inputs');need(cases.materialized(a.native_output/'files')==data,'exact native full input generator')
 live=a.native_output/'files';kept=live.with_name('files.native-retained-for-original-v1');retired=a.output/'original-files-retired'
 need(live.is_dir() and not live.is_symlink() and live.stat().st_uid==os.getuid() and not os.path.lexists(kept) and not os.path.lexists(retired),'exclusive actual original fixture plan')
 old=ident(live);live.rename(kept);need(ident(kept)==old and not os.path.lexists(live),'native fixture retained with same identity')
 save(a.output/'NATIVE-FIXTURE-RENAME.json',{'original':str(live),'retained':str(kept),'identity_before':old,'identity_after':ident(kept),'origin_absent':True})
 live.mkdir(mode=0o700);original_identity=ident(live);captures=[]
 common=module(a.native_source/'capture_common.py','_actual_owned_fixture');fixture=common.OwnedFixture(live)
 scenarios=sorted((s for g in data['groups']for s in g['scenarios']),key=lambda s:s['scenario_id'])
 try:
  for scenario in scenarios:
   number=scenario['scenario_id'];folder=a.output/('scenario-%03d'%number);folder.mkdir()
   setup=fixture.actions(data['common_setup']);save(folder/'COMMON-SETUP.json',setup)
   input_file=folder/'input.jsonl';input_file.write_bytes(canonical(scenario));policy=folder/'policy.json';policy.write_bytes(canonical(installed[scenario['policy_id']]))
   trace=folder/'original.strace';runtime_env={'PATH':'/usr/bin:/bin','LC_ALL':'C',**data['fence_environments'][scenario['fence_id']]}
   trace_args=common.TRACE_ARGS
   command=[str(a.strace),*trace_args,'-o',str(trace),'--',str(binary),'--sdk',str(live),str(policy)]
   d,process=processes.run('sdk-%03d'%number,command,live,stdin=input_file,environment=runtime_env)
   need((d/'stderr.bin').read_bytes()==b'','unchanged original SDK unexpected stderr')
   need((d/'stdout.bin').read_bytes().startswith(b'HBCSO002'),'unchanged complete public output framing')
   row={'scenario_id':number,'input':{'path':str(input_file),**pin(input_file)},'policy':{'path':str(policy),**pin(policy)},'process':process,'process_root':str(d),'trace':{'path':str(trace),**pin(trace)},'final_files':fixture.snapshot(scenario['observed_roots'])}
   save(folder/'RESULT.json',row);captures.append(row);print(json.dumps({'stage':'unchanged-sdk','scenario_id':number,'steps':len(scenario['steps']),'status':'CAPTURED'}),flush=True)
  final_started=time.monotonic_ns();final_trees=fixture.snapshot([os.fsencode(live).hex()]);final_finished=time.monotonic_ns()
  save(a.output/'FINAL-FIXTURES.json',{'schema':'hepta.runtime.batch-public-final-fixture-observation.v1','stage':'original','producer_pid':os.getpid(),'started_monotonic_ns':final_started,'finished_monotonic_ns':final_finished,'trees':final_trees})
 finally:
  live.rename(retired);need(not os.path.lexists(live) and ident(retired)==original_identity,'actual original fixture retired without changes')
  save(a.output/'ORIGINAL-FIXTURE-RETIREMENT.json',{'original':str(live),'retired':str(retired),'identity_before':original_identity,'identity_after':ident(retired),'origin_absent':True})
 need(q.native_evidence(**native_request)==native,'native predecessor unchanged after exact-origin original replay')
 need(source_files(a.source)==before,'entire original source unchanged')
 save(a.output/'RESULT.json',{'schema':'hepta.runtime.batch-public-original-capture.v1','status':'CAPTURED','scenarios':len(captures),'steps':sum(len(s['steps'])for s in scenarios),'actual_processes':len(processes.rows),'fresh_locked_builds':1,'sdk_replay_processes':len(captures),'source_files':before,'native_evidence':pin(a.output/'NATIVE-EVIDENCE.json'),'captures':captures,'final_fixtures':{'path':str(a.output/'FINAL-FIXTURES.json'),**pin(a.output/'FINAL-FIXTURES.json')},'actual_original_batch_method':True,'actual_original_sdk':True,'actual_original_full_router':False,'actual_original_config_loader':False,'whole_runtime_replaced':False,'native_original_comparison_complete':False})
 print(json.dumps({'status':'CAPTURED','scenarios':len(captures),'steps':133,'actual_processes':len(processes.rows),'result':pin(a.output/'RESULT.json')},sort_keys=True),flush=True)
if __name__=='__main__':main()
