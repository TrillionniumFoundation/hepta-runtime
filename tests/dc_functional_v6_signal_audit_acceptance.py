#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Six genuine targets: owned PID-pinned TERM + local audit/ACK fault injection.
A private ssh forwarding wrapper always executes real /usr/bin/ssh with the
native configured arguments. Faults occur only AFTER a genuine signal ACK, or
before native intent recording in this disposable controller's legacy audit.
No product policy, installed service, existing business process or credential is modified.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import secrets
import shutil
import stat
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from dc_parity_release_six_host_acceptance import HOSTS, digest, services
from runtime_http_acceptance import Client

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy'))
from mcp_tool_contract import ToolContract

TERMINAL={'succeeded','failed','cancelled','timed_out','launch_failed'}

CHILD_SOURCE="""import json,os,pathlib,signal,sys,time
root=pathlib.Path(sys.argv[1]);count=0
def save(name,value):
 p=root/name;t=root/(name+'.tmp')
 t.write_text(json.dumps(value));os.replace(t,p)
def term(signum,frame):
 global count
 count+=1
 save('counter',{'count':count,'pid':os.getpid(),'uid':os.geteuid()})
 print('TERM_COUNT='+str(count),flush=True)
signal.signal(signal.SIGTERM,term)
save('counter',{'count':0,'pid':os.getpid(),'uid':os.geteuid()})
save('ready',{'pid':os.getpid(),'uid':os.geteuid()})
print('READY',flush=True)
deadline=time.monotonic()+90
while not (root/'release').exists() and time.monotonic()<deadline:time.sleep(.05)
print('RELEASED',flush=True)
"""

BRIDGE_SOURCE="""#!/usr/bin/python3
import hashlib,json,os,pathlib,subprocess,sys
data=sys.stdin.buffer.read()
control=pathlib.Path(os.environ['HEPTA_SIGNAL_FAULT_CONTROL'])
events=pathlib.Path(os.environ['HEPTA_SIGNAL_BRIDGE_EVENTS'])
try:q=json.loads(data)
except (ValueError,UnicodeError):q={}
fault=json.loads(control.read_text()) if control.exists() else {'mode':'normal'}
is_signal=q.get('op')=='signal'
mode=fault.get('mode','normal') if is_signal else 'normal'
actual=subprocess.run(['/usr/bin/ssh',*sys.argv[1:]],input=data,capture_output=True)
if is_signal:
 try:ack=json.loads(actual.stdout)
 except (ValueError,UnicodeError):ack=None
 row={'mode':mode,'pid':q.get('pid'),'signal':q.get('signal'),
  'expected_identity':q.get('expected_identity'),'real_ssh_exit':actual.returncode,
  'real_ack':ack,'stdout_sha256':hashlib.sha256(actual.stdout).hexdigest(),
  'stderr_sha256':hashlib.sha256(actual.stderr).hexdigest()}
 with events.open('a',encoding='utf-8') as f:
  f.write(json.dumps(row,separators=(',',':'))+'\\n');f.flush();os.fsync(f.fileno())
 if actual.returncode==0 and mode=='completion_audit_failure':
  path=pathlib.Path(fault['audit_path']);backup=pathlib.Path(fault['backup_path'])
  if backup.exists() or not path.is_file() or path.is_symlink():raise RuntimeError('owned audit fault precondition')
  os.replace(path,backup);path.mkdir(mode=0o700)
 if actual.returncode==0 and mode=='lost_ack':
  raise SystemExit(255)
 if actual.returncode==0 and mode=='invalid_ack':
  sys.stdout.buffer.write(b'NOT_A_SIGNAL_ACK\\n');sys.stdout.buffer.flush()
  raise SystemExit(0)
sys.stdout.buffer.write(actual.stdout);sys.stdout.buffer.flush()
sys.stderr.buffer.write(actual.stderr);sys.stderr.buffer.flush()
raise SystemExit(actual.returncode)
"""



def source_identity():
    """Fingerprint compile inputs independently of HEAD and generated locks."""
    paths=set(ROOT.glob('src/**/*.rs'))|set(ROOT.glob('src/**/*.py'))
    paths.update([ROOT/'Cargo.toml',ROOT/'Cargo.lock'])
    entries={}
    for path in sorted(paths,key=lambda value:value.relative_to(ROOT).as_posix()):
        if path.is_symlink() or not path.is_file():
            raise ValueError('compile input must be a regular non-symlink file')
        raw=path.read_bytes()
        entries[path.relative_to(ROOT).as_posix()]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    head=subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip()
    dirty=subprocess.check_output(['git','-C',str(ROOT),'status','--porcelain','--untracked-files=all',
        '--',*entries],text=True)
    encoded=json.dumps(entries,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    return {'base_HEAD':head,'dirty_source':bool(dirty.strip()),
        'source_fingerprint_algorithm':'sha256(canonical sorted relative path -> byte-count and sha256 map)',
        'source_code_fingerprint':hashlib.sha256(encoded).hexdigest(),'source_files':entries}


def private_controller_directory():
    """Keep failed state outside the repository; never publish its auth token."""
    parent=pathlib.Path.home()/'.local/state/hepta-runtime-acceptance'
    parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    info=parent.lstat()
    if parent.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
        raise ValueError('private acceptance state directory identity/mode refused')
    return pathlib.Path(tempfile.mkdtemp(prefix='hepta-v6-signal-controller-',dir=parent)).resolve()


def save_private_json(path,value):
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(descriptor,'w',encoding='utf-8') as writer:
        json.dump(value,writer,ensure_ascii=False,indent=2);writer.write('\n');writer.flush();os.fsync(writer.fileno())


def target_python(ssh,source):
    p=subprocess.run(['/usr/bin/ssh','-o','BatchMode=yes','-o','ConnectTimeout=10',ssh,
        '/usr/bin/python3 -c '+shlex.quote(source)],capture_output=True,text=True,timeout=35,check=True)
    return json.loads(p.stdout) if p.stdout.strip() else None


def fixture(ssh):
    return target_python(ssh,"""
import json,os,pathlib,sys,tempfile
base=pathlib.Path(os.path.realpath(tempfile.mkdtemp(prefix='hepta-v6-signal-audit-')))
(base/'workspace').mkdir(mode=0o700);(base/'state').mkdir(mode=0o700)
print(json.dumps({'base':str(base),'root':str(base/'workspace'),'uid':os.geteuid(),
 'platform':'linux' if sys.platform=='linux' else 'macos'}))
""")


def owned_query(ssh,item,operation,want=None):
    return target_python(ssh,"""
import json,os,pathlib,shutil,time
base=pathlib.Path("""+repr(item['base'])+""")
if base.is_symlink() or not base.name.startswith('hepta-v6-signal-audit-') or base.stat().st_uid!=os.geteuid():
 raise ValueError('owned signal fixture identity refused')
if base.stat().st_uid!="""+str(item['uid'])+""":raise ValueError('fixture UID changed')
root=base/'workspace';op="""+repr(operation)+"""
if op=='remove':
 shutil.rmtree(base);result={'removed':True}
elif op=='release':
 (root/'release').write_text('owned release');result={'released':True}
else:
 name='ready' if op=='ready' else 'counter';deadline=time.monotonic()+5;result=None
 while time.monotonic()<deadline:
  try:result=json.loads((root/name).read_text())
  except FileNotFoundError:time.sleep(.025);continue
  if """+repr(want)+""" is None or result.get('count')=="""+repr(want)+""":break
  time.sleep(.025)
 if result is None:raise ValueError('owned child marker missing')
print(json.dumps(result))
""")


class OwnedClient(Client):
    def __init__(self,url,token,trace):
        self.trace=trace
        super().__init__(url,token)
    def call(self,name,args,denied=False):
        result=super().call(name,args,denied)
        # host_processes can return unrelated processes after a dead PID; its
        # response is recorded only after the caller verifies the owned PID.
        if name!='host_processes' and not self.trace.closed:
            self.trace.write(json.dumps({'tool':name,'arguments':args,'result':result},
                ensure_ascii=False,separators=(',',':'))+'\n');self.trace.flush()
        return result
    def owned_process_trace(self,args,row):
        self.trace.write(json.dumps({'tool':'host_processes','arguments':args,
            'verified_owned_process':row},separators=(',',':'))+'\n');self.trace.flush()


def set_fault(control,mode,**fields):
    temp=control.with_suffix('.tmp')
    temp.write_text(json.dumps({'mode':mode,**fields}));temp.chmod(0o600);os.replace(temp,control)


def bridge_rows(events):
    if not events.exists():return []
    return [json.loads(line) for line in events.read_text().splitlines() if line]


def restore_audit(path,backup):
    if path.is_dir():
        if path.is_symlink():raise RuntimeError('refusing audit symlink restoration')
        path.rmdir()
    if backup.exists():
        if path.exists():raise RuntimeError('owned audit destination changed during restoration')
        os.replace(backup,path)


def verify_ack(ack,pid,identity,uid):
    assert ack['pid']==pid and ack['signal']==15 and ack['identity']==identity
    assert ack['result']=='signal_sent' and ack['effective_uid']==uid
    assert ack['termination_confirmed'] is False
    assert isinstance(ack['atomic_identity'],bool)


def redacted(raw,token,base):
    text=raw.decode('utf-8',errors='backslashreplace')
    if token:text=text.replace(token,'[REDACTED_TOKEN]')
    text=text.replace(str(base),'[OWNED_CONTROLLER]')
    lines=[]
    for line in text.splitlines(keepends=True):
        if any(x in line.lower() for x in ('x-hepta-runtime-token','authorization:','mcp-session-id:')):
            lines.append('[REDACTED_HEADER_LINE]\n')
        else:lines.append(line)
    return ''.join(lines).encode()


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--binaryrelease','--binary',dest='binaryrelease',required=True)
    ap.add_argument('--contract',required=True)
    ap.add_argument('--receipt-dir',required=True)
    ap.add_argument('--out',required=True)
    ap.add_argument('--host',choices=[name for name,_ in HOSTS])
    ap.add_argument('--expected-head')
    ap.add_argument('--expected-source-fingerprint',help='Compile-input fingerprint sealed by the build, if available')
    args=ap.parse_args()
    binary=pathlib.Path(args.binaryrelease).resolve(strict=True)
    contract_path=pathlib.Path(args.contract).resolve(strict=True)
    contract_sha=digest(contract_path);contract=ToolContract.load(contract_path,contract_sha)
    assert {'process_start','process_status','process_wait','process_read','host_processes','host_signal'}<=set(contract.by_name)
    selected=[x for x in HOSTS if not args.host or x[0]==args.host]
    destination=pathlib.Path(args.receipt_dir).resolve();destination.mkdir(parents=True,exist_ok=False,mode=0o700)
    output=pathlib.Path(args.out)
    if output.exists():raise ValueError('receipt output must be absent')
    source_before=source_identity()
    if args.expected_head and source_before['base_HEAD']!=args.expected_head:
        raise ValueError('source HEAD differs from expected committed HEAD')
    if args.expected_source_fingerprint and source_before['source_code_fingerprint']!=args.expected_source_fingerprint:
        raise ValueError('compile-input fingerprint differs from supplied build pin')
    baseline=services()
    assert all(v.get('ActiveState')=='active' and v.get('MainPID')!='0' for v in baseline.values())
    report={'schema':'hepta-v6-real-signal-audit-faults-v1',
        'recorded_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source_head':source_before['base_HEAD'],'source_before':source_before,
        'source_head_is_compiled_code_claim':False,'expected_head':args.expected_head,
        'expected_compiled_source_fingerprint':args.expected_source_fingerprint,
        'compile_input_binding_scope':'observed compile inputs; a supplied build fingerprint is checked, not invented',
        'script_sha256':digest(pathlib.Path(__file__).resolve()),'binary_sha256':digest(binary),
        'operator_source_sha256':digest(ROOT/'src/mcp/runtime/operator.rs'),
        'process_helper_sha256':digest(ROOT/'src/mcp/runtime/process_ops.py'),
        'contract_sha256':contract_sha,'contract_catalog_sha256':contract.catalog_sha256,
        'tool_count':len(contract.tools),'origin':'local_native_real_ssh_with_owned_controller_fault_bridge',
        'chatgpt_originated':False,'native_session_only':True,'installed_service_changed':False,
        'DC_changed':False,'full_dc_replacement_qualified':False,
        'signal':15,'sudo_used':False,'target_processes':'only PID-and-identity verified disposable test children',
        'protected_services_before':baseline,
        'protected_service_identity_scope':'controller PROTECTED units; remote business service identities are not qualified',
        'selected_hosts':[x[0] for x in selected],
        'results':[],'cleanup':[],'complete':False}
    items={};jobs={};terminal={};owned_processes={};launch_attempted=set()
    controller=None;client=None;failure=None;token_value=''
    directory=private_controller_directory()
    base=pathlib.Path(directory).resolve();workspace=base/'workspace';workspace.mkdir(mode=0o700)
    state=base/'state';control=base/'fault.json';events=base/'bridge-events.jsonl';bin_dir=base/'bin';bin_dir.mkdir(mode=0o700)
    wrapper=bin_dir/'ssh';wrapper.write_text(BRIDGE_SOURCE);wrapper.chmod(0o700)
    legacy=state/'audit'/'events.jsonl';active_backup=None
    native_stdout=base/'native.stdout.raw';native_stderr=base/'native.stderr.raw'
    try:
        for name,ssh in selected:items[name]=fixture(ssh)
        host_config={name:{'ssh_target':ssh,'platform':items[name]['platform'],'execution_mode':'operator',
            'remote_state_dir':items[name]['base']+'/state','allow_execute':True,'allow_pty':False,
            'allow_write':True,'allow_job_network':True,'allow_detached_fallback':True,
            'allowed_read_path_prefixes':[items[name]['root']],'allowed_write_path_prefixes':[items[name]['root']]}
            for name,ssh in selected}
        config=base/'runtime.json';config.write_text(json.dumps({'state_dir':str(state),
            'controller_workspace_roots':[str(workspace)],'hosts':host_config}))
        token_value=secrets.token_hex(32);token=base/'token'
        descriptor=os.open(token,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        with os.fdopen(descriptor,'w',encoding='ascii') as writer:
            writer.write(token_value);writer.flush();os.fsync(writer.fileno())
        set_fault(control,'normal')
        env=dict(os.environ);env.update(PATH=str(bin_dir)+os.pathsep+env.get('PATH',''),
            HEPTA_SIGNAL_FAULT_CONTROL=str(control),HEPTA_SIGNAL_BRIDGE_EVENTS=str(events))
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        with native_stdout.open('wb') as nout,native_stderr.open('wb') as nerr,(destination/'owned-tools.jsonl').open('x',encoding='utf-8') as trace:
            controller=subprocess.Popen([str(binary),'mcp','--path',str(workspace),'--bind',f'127.0.0.1:{port}',
                '--runtime-config',str(config),'--auth-token-file',str(token)],stdin=subprocess.DEVNULL,
                stdout=nout,stderr=nerr,env=env)
            for _ in range(90):
                if controller.poll() is not None:raise RuntimeError('owned signal controller exited at startup')
                try:client=OwnedClient(f'http://127.0.0.1:{port}/mcp',token_value,trace);break
                except (OSError,RuntimeError):time.sleep(.1)
            else:raise TimeoutError('owned signal controller did not start')
            contract.verify(client.rpc('tools/list',{})['tools'])
            for name,ssh in selected:
                item=items[name];checks=[];phases=[]
                before_jobs=set(p.stem for p in (state/'jobs').glob('*.json'))
                try:
                    launch_attempted.add(name)
                    start=client.call('process_start',{'host':name,'executable':'/usr/bin/python3',
                        'args':['-u','-c',CHILD_SOURCE,item['root']],'cwd':item['root'],
                        'timeout_seconds':110,'idempotency_key':'owned-signal-'+uuid.uuid4().hex})
                    job=start['job']['id'];jobs[name]=job
                    assert start['reused'] is False and start['job']['launch_state']=='launched'
                    ready=owned_query(ssh,item,'ready')
                    pid=ready['pid'];uid=ready['uid'];assert uid==item['uid'] and 0<pid<2**31
                    listing_args={'host':name,'after_pid':pid-1,'limit':1}
                    listing=client.call('host_processes',listing_args)
                    candidates=[p for p in listing['processes'] if p['pid']==pid]
                    assert len(candidates)==1 and candidates[0]['uid']==uid
                    identity=candidates[0]['identity'];client.owned_process_trace(listing_args,candidates[0])
                    owned_processes[name]={'pid':pid,'uid':uid,'identity':identity}
                    checks.append('real owned child PID/UID and native start identity independently verified')
                    signal_args={'host':name,'pid':pid,'signal':15,'expected_identity':identity,'sudo':False}

                    for phase,mode,count in [('normal','normal',1),
                            ('completion_audit_failure','completion_audit_failure',2),
                            ('intent_audit_failure','intent_audit_failure',2),
                            ('lost_ack','lost_ack',3),('invalid_ack','invalid_ack',4)]:
                        prior=len(bridge_rows(events));backup=state/'audit'/('events-backup-'+name+'-'+phase+'.jsonl')
                        active_backup=backup
                        if mode=='intent_audit_failure':
                            assert legacy.is_file() and not legacy.is_symlink()
                            os.replace(legacy,backup);legacy.mkdir(mode=0o700)
                            set_fault(control,'normal')
                        elif mode=='completion_audit_failure':
                            set_fault(control,mode,audit_path=str(legacy),backup_path=str(backup))
                        else:set_fault(control,mode)
                        try:
                            if mode=='intent_audit_failure':
                                reply=client.call('host_signal',signal_args,denied=True)
                                assert 'no signal request dispatched' in reply
                                assert len(bridge_rows(events))==prior
                            else:
                                reply=client.call('host_signal',signal_args)
                                rows=bridge_rows(events);assert len(rows)==prior+1
                                real=rows[-1]
                                assert real['pid']==pid and real['expected_identity']==identity and real['signal']==15
                                assert real['real_ssh_exit']==0
                                verify_ack(real['real_ack'],pid,identity,uid)
                                assert reply['pid']==pid and reply['signal']==15
                                assert reply['automatic_retry'] is False
                                assert reply['termination_confirmed'] is False
                                if mode in ('lost_ack','invalid_ack'):
                                    assert reply['result']=='signal_outcome_unknown'
                                    assert reply['outcome']=='unknown' and reply['expected_identity']==identity
                                    assert 'reconcile_warning' in reply
                                else:
                                    verify_ack(reply,pid,identity,uid)
                                    assert reply['audit_recorded'] is (mode=='normal')
                                    if mode=='completion_audit_failure':assert 'audit_warning' in reply
                            text=json.dumps(reply,ensure_ascii=False)
                            assert str(base) not in text and token_value not in text
                            observed=owned_query(ssh,item,'counter',count)
                            assert observed=={'count':count,'pid':pid,'uid':uid}
                            phases.append({'phase':phase,'count':count,'signal_rpc_dispatches':len(bridge_rows(events))-prior,
                                'result':reply,'physical_effect_verified':True})
                            checks.append(phase+' retains correct owned identity/effect and prevents blind replay')
                        finally:
                            set_fault(control,'normal')
                            restore_audit(legacy,backup);active_backup=None
                    # The same child remains alive throughout all fault phases.
                    again=client.call('host_processes',listing_args)
                    same=[p for p in again['processes'] if p['pid']==pid]
                    assert len(same)==1 and same[0]['identity']==identity and same[0]['uid']==uid
                    client.owned_process_trace(listing_args,same[0])
                    owned_query(ssh,item,'release')
                    done=client.call('process_wait',{'host':name,'job_id':job,'timeout_seconds':25})
                    assert done['state']=='succeeded' and done['exit_code']==0 and done['output_complete'] is True
                    terminal[name]=True
                    stream=client.call('process_read',{'host':name,'job_id':job,'limit':16384})
                    stdout=bytes.fromhex(stream['stdout']['bytes_hex'])
                    assert stdout==b'READY\nTERM_COUNT=1\nTERM_COUNT=2\nTERM_COUNT=3\nTERM_COUNT=4\nRELEASED\n'
                    assert bytes.fromhex(stream['stderr']['bytes_hex'])==b''
                    checks.append('same child identity survives all phases, then owned release exits normally with exact count log')
                    report['results'].append({'host':name,'job_id':job,'pid':pid,'identity':identity,
                        'atomic_identity':phases[0]['result']['atomic_identity'],'phases':phases,
                        'passed':len(checks),'checks':checks,'stdout_sha256':hashlib.sha256(stdout).hexdigest(),'complete':True})
                    print('PASS',name,'signal-audit-real-faults',len(checks),flush=True)
                finally:
                    for p in (state/'jobs').glob('*.json'):
                        if p.stem not in before_jobs:
                            record=json.loads(p.read_text())
                            if record['host']==name:jobs[name]=record['id']
    except Exception as exc:
        failure=exc;report['error_type']=type(exc).__name__
        report['error']=redacted(str(exc).encode(),token_value,base).decode()[:2000]
    finally:
        try:
            set_fault(control,'normal')
            if active_backup is not None:restore_audit(legacy,active_backup)
        except Exception as exc:report['audit_restore_error_type']=type(exc).__name__
        for name,ssh in selected:
            if name not in items:continue
            try:
                if name in launch_attempted and name not in jobs:
                    raise RuntimeError('launch attempted without a retained job ID; fixture retained for reconciliation')
                if name in jobs and not terminal.get(name):
                    owned_query(ssh,items[name],'release')
                    if client is None:raise RuntimeError('owned job status unavailable')
                    status=client.call('process_status',{'host':name,'job_id':jobs[name]})
                    if status['state']=='running':
                        status=client.call('process_wait',{'host':name,'job_id':jobs[name],'timeout_seconds':25})
                    terminal[name]=status['state'] in TERMINAL and status.get('output_complete') is True
                if name in jobs and not terminal.get(name):raise RuntimeError('owned job not confirmed terminal; fixture retained')
                owned_query(ssh,items[name],'remove')
                report['cleanup'].append({'host':name,'job_id':jobs.get(name),'removed':True,
                    'job_terminal_confirmed':name not in jobs or terminal.get(name) is True})
            except Exception as exc:
                report['cleanup'].append({'host':name,'job_id':jobs.get(name),'removed':False,
                    'error_type':type(exc).__name__,'retained_owned_fixture':items[name]['base'],
                    'launch_attempted':name in launch_attempted,'owned_process':owned_processes.get(name)})
        try:
            if controller is not None and controller.poll() is None:
                controller.terminate()
                try:controller.wait(timeout=10)
                except subprocess.TimeoutExpired:controller.kill();controller.wait(timeout=5)
        except Exception as exc:report['controller_stop_error_type']=type(exc).__name__
        report['owned_controller_stopped']=controller is None or controller.poll() is not None
        logs={}
        for label,path in [('native-stdout',native_stdout),('native-stderr',native_stderr),('bridge-events',events)]:
            try:
                saved=destination/(label+'.log');saved.write_bytes(redacted(path.read_bytes() if path.exists() else b'',token_value,base))
                logs[label]={'bytes':saved.stat().st_size,'sha256':digest(saved),'redacted':True}
            except Exception as exc:
                report.setdefault('evidence_save_errors',[]).append({'label':label,'error_type':type(exc).__name__})
        trace=destination/'owned-tools.jsonl'
        try:
            if trace.exists():logs['owned-tools']={'bytes':trace.stat().st_size,'sha256':digest(trace),
                'content':'only test-owned requests/results; no tokens, headers or unrelated process-list output'}
        except Exception as exc:
            report.setdefault('evidence_save_errors',[]).append({'label':'owned-tools','error_type':type(exc).__name__})
        report['logs']=logs
        report['owned_jobs']=[{'host':name,'job_id':job,'terminal_confirmed':terminal.get(name) is True} for name,job in jobs.items()]
    try:
        report['protected_services_after']=services()
        report['service_identity_stable']=report['protected_services_after']==baseline
    except Exception as exc:
        report['service_identity_stable']=False;report['service_observation_error_type']=type(exc).__name__
    try:
        source_after=source_identity();report['source_after']=source_after
        report['source_fingerprint_stable']=source_before['source_code_fingerprint']==source_after['source_code_fingerprint']
        report['source_head_stable']=source_before['base_HEAD']==source_after['base_HEAD']
        report['compile_input_build_pin_verified']=(args.expected_source_fingerprint is not None
            and source_after['source_code_fingerprint']==args.expected_source_fingerprint)
        report['candidate_hashes_after']={'binary_sha256':digest(binary),
            'operator_source_sha256':digest(ROOT/'src/mcp/runtime/operator.rs'),
            'process_helper_sha256':digest(ROOT/'src/mcp/runtime/process_ops.py'),
            'script_sha256':digest(pathlib.Path(__file__).resolve()),'contract_sha256':digest(contract_path)}
        report['candidate_hashes_stable']=(all(report['candidate_hashes_after'][key]==report[key]
            for key in report['candidate_hashes_after']) and report['source_fingerprint_stable'] and report['source_head_stable'])
    except Exception as exc:
        report['candidate_hashes_stable']=False;report['source_observation_error_type']=type(exc).__name__
    report['selected_complete']=(failure is None and len(report['results'])==len(selected)
        and report.get('candidate_hashes_stable') is True and report['service_identity_stable']
        and 'audit_restore_error_type' not in report and report['owned_controller_stopped']
        and 'controller_stop_error_type' not in report and not report.get('evidence_save_errors')
        and len(report['cleanup'])==len(selected) and all(x['removed'] for x in report['cleanup']))
    report['complete']=report['selected_complete'] and len(selected)==len(HOSTS)
    if report['selected_complete']:
        try:
            shutil.rmtree(base)
            report['controller_cleanup']={'removed':True,'owned_controller_stopped':controller is None or controller.poll() is not None}
        except Exception as exc:
            report['selected_complete']=False;report['complete']=False
            report['controller_cleanup']={'removed':False,'error_type':type(exc).__name__}
    if not report['selected_complete']:
        # The 0700 parent/base and separately 0600 token stay local only. Receipts
        # contain references and no token value; this directory is never committed.
        recovery={'schema':'hepta-owned-signal-audit-recovery-v1','binary':str(binary),
            'binary_sha256':report['binary_sha256'],'contract':str(contract_path),
            'contract_sha256':contract_sha,'source_before':source_before,
            'controller_state_dir':str(state),'runtime_config':str(config) if 'config' in locals() else None,
            'controller_stopped':controller is None or controller.poll() is not None,
            'audit_path':str(legacy),'active_audit_backup':str(active_backup) if active_backup is not None else None,
            'automatic_retry':False,'credentials_in_metadata':False,
            'targets':[{'host':name,'ssh_target':ssh,'fixture':items.get(name),
                'job_id':jobs.get(name),'launch_attempted':name in launch_attempted,
                'terminal_confirmed':terminal.get(name) is True,'owned_process':owned_processes.get(name)}
                for name,ssh in selected]}
        recovery_path=base/'recovery.json'
        try:
            save_private_json(recovery_path,recovery)
            report['recovery']={'controller_directory':str(base),'metadata_path':str(recovery_path),
                'directory_mode':'0700','metadata_mode':'0600','auth_token_retained_private':token_value!='',
                'auth_token_not_in_receipts':True,'automatic_retry':False}
        except Exception as exc:
            report['recovery']={'controller_directory':str(base),'metadata_saved':False,'error_type':type(exc).__name__}
    with output.open('x',encoding='utf-8') as f:f.write(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print('SIGNAL_AUDIT_COMPLETE',report['complete'],'SELECTED_COMPLETE',report['selected_complete'],flush=True)
    if not report['selected_complete']:sys.exit(1)

if __name__=='__main__':
    main()
