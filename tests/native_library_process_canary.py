#!/usr/bin/env python3
"""Real native-library controller + existing localhost SSH, isolated owned effects.
No mocked SSH, production service changes, arbitrary-PID signalling or lost-key retry.
"""
import argparse,hashlib,json,os,pathlib,selectors,signal,subprocess,sys,tempfile,time

WORKER = '''import os,pathlib,sys,time
root=pathlib.Path(sys.argv[1]); kind=sys.argv[2]
with (root/(kind+".attempts")).open("a") as attempts:
    attempts.write(str(os.getpid())+"\\n"); attempts.flush(); os.fsync(attempts.fileno())
with (root/(kind+".marker")).open("x") as stream:
    stream.write("one execution\\n"); stream.flush(); os.fsync(stream.fileno())
print("BEGIN "+kind,flush=True)
print("stderr "+kind,file=sys.stderr,flush=True)
deadline=time.monotonic()+40
while not (root/(kind+".release")).exists():
    if time.monotonic()>deadline: raise SystemExit(42)
    time.sleep(.05)
print("END "+kind,flush=True)
'''

def source_snapshot(root):
    """Record observed source inputs; binary/source correspondence needs a build log."""
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], timeout=15)
    tracked_and_new = git('ls-files', '-z', '--cached', '--others', '--exclude-standard')
    names = sorted(set(name.decode('utf-8') for name in tracked_and_new.split(b'\0') if name))
    selected = []
    for name in names:
        if name not in {'Cargo.toml', 'Cargo.lock', 'build.rs', 'rust-toolchain', 'rust-toolchain.toml'} and not name.startswith(('src/', 'examples/', 'tests/', '.cargo/')):
            continue
        path = root / name
        if path.is_symlink():
            selected.append({'path': name, 'kind': 'symlink', 'target': os.readlink(path)})
        elif path.is_file():
            selected.append({'path': name, 'kind': 'file', 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        else:
            selected.append({'path': name, 'kind': 'absent'})
    encoded = json.dumps(selected, sort_keys=True, separators=(',', ':')).encode()
    merge = subprocess.run(['git', '-C', str(root), 'rev-parse', '--verify', 'MERGE_HEAD'], capture_output=True, text=True, timeout=15)
    return {'root': str(root), 'head': git('rev-parse', 'HEAD').decode().strip(),
            'merge_head': merge.stdout.strip() if merge.returncode == 0 else None,
            'tracked_status': git('status', '--porcelain', '--untracked-files=no').decode(),
            'inputs_sha256': hashlib.sha256(encoded).hexdigest(), 'inputs': selected,
            'binary_source_match': 'must be established by the separate build log'}

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--driver',required=True); parser.add_argument('--ssh-target',default='localhost'); parser.add_argument('--evidence-root',default='/home/qian-qi/workspace/hepta-runtime-native-integration-evidence-20261024'); parser.add_argument('--source-root',default=str(pathlib.Path(__file__).resolve().parents[1])); a=parser.parse_args()
    binary=pathlib.Path(a.driver).resolve()
    if not binary.is_file(): raise RuntimeError('compiled driver missing')
    evidence=pathlib.Path(a.evidence_root); evidence.mkdir(parents=True,exist_ok=True,mode=0o700)
    root=pathlib.Path(tempfile.mkdtemp(prefix='native-process-',dir=evidence)); os.chmod(root,0o700)
    for name in ['state','target','work','requests']:
        (root/name).mkdir(mode=0o700)
    config={'state_dir':str(root/'state'),'controller_workspace_roots':[str(root/'work')],'hosts':{'native-local-test':{'ssh_target':a.ssh_target,'platform':'linux','execution_mode':'operator','remote_state_dir':str(root/'target'),'allow_execute':True,'allow_pty':False,'allow_write':False,'allow_job_network':True,'allow_detached_fallback':False}}}
    config_path=root/'config.json'; config_path.write_text(json.dumps(config)); config_path.chmod(0o600)
    script=root/'work'/'worker.py'; script.write_text(WORKER); script.chmod(0o600)
    report={'schema':'hepta-native-process-library-canary/v1','root':str(root),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'services_changed':False,'real_localhost_ssh':True,'shadow_intent_execution':False,'hepta_finaluse_qualification':False,'events':[],'passed':False,'scope':'owned temporary-directory jobs; native process boundary; not production owner transfer or host reboot'}
    counter=0; jobs=[]; held=None
    def request_file(value):
        nonlocal counter
        counter+=1; path=root/'requests'/f'{counter:03d}.json'; path.write_text(json.dumps(value)); path.chmod(0o600); return path
    def invoke(action,value,expect_success=True):
        path=request_file(value); started=time.monotonic()
        p=subprocess.run([str(binary),str(config_path),action,str(path)],capture_output=True,text=True,timeout=30)
        row={'action':action,'seconds':time.monotonic()-started,'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
        report['events'].append(row)
        if expect_success and p.returncode: raise RuntimeError(action+' failed: '+p.stderr[-1500:])
        if not expect_success:
            if p.returncode==0: raise RuntimeError('changed binding unexpectedly accepted')
            return row
        try: return json.loads(p.stdout)
        except ValueError as exc: raise RuntimeError('invalid native response; effect status unknown, preserve identity') from exc
    def wait_state(ref,expected,seconds=12):
        deadline=time.monotonic()+seconds
        while True:
            result=invoke('status',ref)
            if result.get('state') in expected:return result
            if time.monotonic()>=deadline:raise RuntimeError('original job did not reach expected state: '+json.dumps(result))
            time.sleep(.1)
    def start_params(kind):
        return {'host':'native-local-test','executable':'/usr/bin/python3','args':[str(script),str(root/'work'),kind],'cwd':str(root/'work'),'stdin':'native exact stdin\n','timeout_seconds':45,'idempotency_key':'native-library-'+root.name+'-'+kind,'nice':10}
    try:
        report['source_snapshot']=source_snapshot(pathlib.Path(a.source_root).resolve())
        check=subprocess.run(['/usr/bin/ssh','-o','BatchMode=yes','-o','ConnectTimeout=5',a.ssh_target,'true'],capture_output=True,text=True,timeout=10)
        report['ssh_preflight']={'exit':check.returncode,'stderr':check.stderr}
        if check.returncode:raise RuntimeError('existing SSH authority unavailable; no test process submitted')
        params=start_params('resume'); path=request_file(params)
        held=subprocess.Popen([str(binary),str(config_path),'start-hold',str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        selector=selectors.DefaultSelector();selector.register(held.stdout,selectors.EVENT_READ)
        body=b'';deadline=time.monotonic()+30;first=None
        while time.monotonic()<deadline:
            for key,_ in selector.select(.2):
                part=os.read(key.fileobj.fileno(),65536)
                if not part:break
                body+=part
                try:first=json.loads(body)
                except ValueError:continue
            if first is not None:break
            if held.poll() is not None:break
        selector.close()
        if first is None:raise RuntimeError('start-hold returned no complete receipt; original key retained')
        job=first.get('job',{});jid=job.get('id')
        if not jid:raise RuntimeError('native start missing original job id')
        ref={'host':'native-local-test','job_id':jid};jobs.append(ref)
        report['events'].append({'action':'start-hold','response':first,'controller_pid':held.pid})
        marker=root/'work'/'resume.marker';deadline=time.monotonic()+8
        while not marker.exists() and time.monotonic()<deadline:time.sleep(.05)
        if not marker.exists():raise RuntimeError('real workload never created its execution marker')
        marker_before=marker.stat();report['original_job_id']=jid
        held.send_signal(signal.SIGKILL);out,err=held.communicate(timeout=5)
        report['owned_controller_sigkill']={'exit':held.returncode,'stderr':err.decode(errors='replace')};held=None
        running=wait_state(ref,{'running'});report['running_after_controller_death']=running
        again=invoke('start',params)
        if again.get('job',{}).get('id')!=jid or not again.get('reused') or again.get('retried_launch') is not False:
            raise RuntimeError('same-key restart did not preserve original execution')
        report['same_key_reuse']=again
        changed=dict(params);changed['args']=params['args']+['different-payload']
        refused=invoke('start',changed,False)
        if 'different request' not in refused['stderr']:raise RuntimeError('changed binding failed for unrelated reason')
        (root/'work'/'resume.release').write_text('release original\n')
        finished=wait_state(ref,{'succeeded','failed'})
        if finished.get('state')!='succeeded':raise RuntimeError('original workload did not complete successfully')
        if finished.get('terminal_publication_confirmed') is not True:raise RuntimeError('new receipt has no terminal publication witness')
        logs=invoke('read',{**ref,'stdout_offset':0,'stderr_offset':0,'limit':16384})
        stdout=logs.get('stdout',{}).get('text');stderr=logs.get('stderr',{}).get('text')
        if stdout!='BEGIN resume\nEND resume\n' or stderr!='stderr resume\n':raise RuntimeError('original output mismatch')
        after=marker.stat()
        if (after.st_ino,after.st_mtime_ns)!=(marker_before.st_ino,marker_before.st_mtime_ns) or marker.read_text()!='one execution\n':raise RuntimeError('execution marker changed')
        attempts=(root/'work'/'resume.attempts').read_text().splitlines()
        if len(attempts)!=1 or not attempts[0].isdigit():raise RuntimeError('original worker was entered more than once')
        report['completed_original']=finished;report['output_sha256']={'stdout':hashlib.sha256(stdout.encode()).hexdigest(),'stderr':hashlib.sha256(stderr.encode()).hexdigest()};report['execution_count']=len(attempts);report['worker_attempt_pids']=attempts
        cancel_params=start_params('cancel');start=invoke('start',cancel_params)
        cancel_ref={'host':'native-local-test','job_id':start['job']['id']};jobs.append(cancel_ref)
        wait_state(cancel_ref,{'running'})
        cancel_marker=root/'work'/'cancel.marker';deadline=time.monotonic()+8
        while not cancel_marker.exists() and time.monotonic()<deadline:time.sleep(.05)
        if not cancel_marker.exists():raise RuntimeError('cancellation workload never executed')
        report['cancel_execution_marker']=cancel_marker.read_text()
        ack=invoke('cancel',{**cancel_ref,'grace_seconds':2});stopped=wait_state(cancel_ref,{'cancelled','failed','succeeded'},15)
        if stopped.get('state')!='cancelled':raise RuntimeError('cancel did not reach authoritative cancelled state')
        if stopped.get('terminal_publication_confirmed') is not True:raise RuntimeError('cancel terminal has no publication witness')
        cancel_attempts=(root/'work'/'cancel.attempts').read_text().splitlines()
        if len(cancel_attempts)!=1 or not cancel_attempts[0].isdigit():raise RuntimeError('cancellation worker was entered more than once')
        report['cancel_ack']=ack;report['cancel_terminal']=stopped;report['cancel_worker_attempt_pids']=cancel_attempts
        jobs=[];report['passed']=True
    except Exception as exc:
        report['error']=str(exc)
    finally:
        if held is not None and held.poll() is None:
            held.kill();held.communicate(timeout=5)
        for ref in jobs:
            try:report.setdefault('cleanup',[]).append(invoke('cancel',{**ref,'grace_seconds':2}))
            except Exception as exc:report.setdefault('cleanup_errors',[]).append(str(exc))
        (root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'passed':report['passed'],'report':str(root/'report.json'),'original_job_id':report.get('original_job_id'),'error':report.get('error'),'events':len(report['events'])},indent=2),flush=True)
    return 0 if report['passed'] else 1
if __name__=='__main__':sys.exit(main())
