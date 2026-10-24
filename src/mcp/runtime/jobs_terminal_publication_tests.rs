// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Execute the embedded supervisor and observer at the terminal publication boundary.
use super::*;
use std::os::unix::fs::PermissionsExt;

const RUNNER_FIXTURE: &str = r#"
import hashlib,io,json,os,pathlib,stat,subprocess,sys
q=json.load(sys.stdin)
job=pathlib.Path(q['job'])
req={'job_id':'terminal-publication','job_dir':str(job),'launch_nonce':'a'*32,
     'request_fingerprint':'original-full-request-binding','terminal_publication_protocol':1,
     'executable':sys.executable,'args':['-I','-S','-c',
     "import pathlib,sys;pathlib.Path('effect').write_bytes(b'once\\n');print('original output');print('original error',file=sys.stderr)"],
     'execution_mode':'operator','timeout_seconds':10,'env':{}}
(job/'request.json').write_text(json.dumps(req))
os.chmod(job/'request.json',0o600)
info=job.stat()
binding={'device':info.st_dev,'inode':info.st_ino,'job_id':req['job_id'],
         'launch_nonce':req['launch_nonce'],'request_fingerprint':req['request_fingerprint']}
real_open,real_fdopen,real_sync,real_replace,real_popen=os.open,os.fdopen,os.fsync,os.replace,subprocess.Popen
events,opened,spawned=[],{},[]
published=None
def opened_file(path,*args,**kwargs):
    fd=real_open(path,*args,**kwargs)
    opened[fd]=pathlib.Path(path).name
    return fd
class FailedWriter:
    def __init__(self,stream): self.stream=stream
    def __enter__(self): return self
    def __exit__(self,*args): return self.stream.__exit__(*args)
    def __getattr__(self,name): return getattr(self.stream,name)
    def write(self,data):
        events.append('failed:witness_write')
        raise OSError('injected witness write failure')
def fdopen(fd,*args,**kwargs):
    stream=real_fdopen(fd,*args,**kwargs)
    if q['case']=='witness_write' and opened.get(fd)=='exit.witness.json.tmp':
        return FailedWriter(stream)
    return stream
def sync(fd):
    current=os.fstat(fd)
    if stat.S_ISDIR(current.st_mode) and (current.st_dev,current.st_ino)==(info.st_dev,info.st_ino):
        name='directory_after_'+str(published)
    else:
        name=pathlib.Path(os.readlink('/proc/self/fd/'+str(fd))).name
    events.append('sync:'+name)
    faults={'exit_directory':'directory_after_exit.json',
            'witness_file_sync':'exit.witness.json.tmp',
            'witness_directory':'directory_after_exit.witness.json'}
    if faults.get(q['case'])==name:
        events.append('failed:'+name)
        raise OSError('injected terminal synchronization failure')
    result=real_sync(fd)
    events.append('synced:'+name)
    return result
def replace(source,target,*args,**kwargs):
    global published
    result=real_replace(source,target,*args,**kwargs)
    published=pathlib.Path(target).name
    events.append('renamed:'+published)
    return result
def popen(*args,**kwargs):
    child=real_popen(*args,**kwargs)
    spawned.append(child)
    return child
os.open,os.fdopen,os.fsync,os.replace,subprocess.Popen=opened_file,fdopen,sync,replace,popen
sys.argv=['-c',str(job),json.dumps(binding),'detached']
code,error=0,None
try:
    exec(q['runner'],{'__name__':'__main__'})
except SystemExit as stopped:
    code=stopped.code if isinstance(stopped.code,int) else 1
    if code: error=str(stopped.code)
except BaseException as failed:
    code,error=1,type(failed).__name__+': '+str(failed)
finally:
    os.open,os.fdopen,os.fsync,os.replace,subprocess.Popen=real_open,real_fdopen,real_sync,real_replace,real_popen
alive=[child.pid for child in spawned if child.poll() is None]
for child in spawned:
    if child.poll() is None:
        child.kill();child.wait(timeout=3)
def snapshot():
    return {p.name:p.read_bytes().hex() for p in job.iterdir() if p.is_file()}
before=snapshot()
sys.stdin=io.StringIO(json.dumps({'job_id':req['job_id'],'job_dir':str(job),'wait_seconds':0}))
captured,saved_stdout=io.StringIO(),sys.stdout
try:
    sys.stdout=captured
    exec(q['status'],{'__name__':'__main__'})
finally:
    sys.stdout=saved_stdout
raw=(job/'exit.json').read_bytes()
witness=json.loads((job/'exit.witness.json').read_bytes()) if (job/'exit.witness.json').exists() else None
print(json.dumps({'supervisor_code':code,'runner_error':error,'events':events,'spawn_count':len(spawned),
    'alive_after_runner':alive,'effect':(job/'effect').read_text(),'receipt':json.loads(raw),
    'witness':witness,'exit_sha256':hashlib.sha256(raw).hexdigest(),
    'status':json.loads(captured.getvalue()),'observation_changed_files':before!=snapshot()}))
"#;

const START_FIXTURE: &str = r#"
import io,json,os,pathlib,shutil,subprocess,sys
q=json.load(sys.stdin)
job=pathlib.Path(q['job'])
req={'job_id':'terminal-publication','job_dir':str(job),'launch_nonce':'a'*32,
     'request_fingerprint':'original-full-request-binding','terminal_publication_protocol':1,
     'executable':sys.executable,'args':['-I','-S','-c','raise SystemExit(99)'],
     'execution_mode':'operator','platform':'linux','unit':'hepta-publication-fixture',
     'allow_detached_fallback':False,'env':{}}
runner=q['case'].startswith('runner_')
if not runner: req.pop('terminal_publication_protocol')
artifact='exit.witness.json.tmp' if q['case'].endswith('_tmp') else 'exit.witness.json'
if q['case']!='normal':
    (job/artifact).write_bytes(b'original uncertain witness\n')
    os.chmod(job/artifact,0o600)
if runner:
    (job/'request.json').write_text(json.dumps(req))
    os.chmod(job/'request.json',0o600)
info=job.stat()
binding={'device':info.st_dev,'inode':info.st_ino,'job_id':req['job_id'],
         'launch_nonce':req['launch_nonce'],'request_fingerprint':req['request_fingerprint']}
launches=[]
def launch(args,*other,**kwargs):
    launches.append(args[0])
    assert q['case']=='normal' and args[0]=='systemd-run', 'unexpected workload submission'
    return subprocess.CompletedProcess(args,0,'','')
def popen(*args,**kwargs):
    launches.append('Popen')
    raise AssertionError('unexpected direct workload submission')
subprocess.run,subprocess.Popen=launch,popen
shutil.which=lambda name: '/usr/bin/systemd-run' if name=='systemd-run' else None
if runner:
    sys.argv=['-c',str(job),json.dumps(binding),'detached']
else:
    sys.stdin=io.StringIO(json.dumps(req))
captured,saved_stdout=io.StringIO(),sys.stdout
error=None
try:
    sys.stdout=captured
    exec(q['runner'] if runner else q['start'],{'__name__':'__main__'})
except BaseException as failed:
    error=type(failed).__name__+': '+str(failed)
finally:
    sys.stdout=saved_stdout
stored=json.loads((job/'request.json').read_bytes()) if (job/'request.json').exists() else None
print(json.dumps({'error':error,'launches':launches,'request':stored,
    'artifact_unchanged':q['case']=='normal' or (job/artifact).read_bytes()==b'original uncertain witness\n'}))
"#;

const STATUS_FIXTURE: &str = r#"
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

q = json.load(sys.stdin)
status = q['status']
compile(status, '<terminal-status>', 'exec')
job_id, nonce, invocation = 'peer-review-job', 'a' * 32, 'b' * 32
request = {'job_id': job_id, 'launch_nonce': nonce, 'terminal_publication_protocol': 1}
terminal = {'job_id': job_id, 'launch_nonce': nonce, 'terminal_publication_protocol': 1,
            'exit_code': 0, 'output_complete': True, 'output_durable': True,
            'cancelled': False, 'timed_out': False}


def raw(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def witness(encoded):
    return {'terminal_publication_protocol': 1, 'job_id': job_id, 'launch_nonce': nonce,
            'exit_sha256': hashlib.sha256(encoded).hexdigest()}


# The executor may expose a procfs mounted in an outer PID namespace. Use this
# process's procfs-visible identity, which is also what STATUS will inspect.
self_stat = Path('/proc/self/stat').read_text()
pid = int(self_stat.split(' ', 1)[0])
ticks = self_stat.rsplit(') ', 1)[1].split()[19]
boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
owner = {'job_id': job_id, 'launch_nonce': nonce, 'supervisor_pid': pid, 'supervisor_uid': os.getuid(),
         'supervisor_identity': {'kind': 'proc_start_ticks', 'value': boot + ':' + ticks},
         'invocation_id': invocation}
cases = []


def add(name, **kwargs):
    cases.append((name, kwargs))


add('new_valid', expect='succeeded')
add('missing_witness', wit=None, expect='finalizing')
add('corrupt_witness', wit=b'{broken', expect='finalizing')
add('wrong_digest', wit={**witness(raw(terminal)), 'exit_sha256': '0' * 64}, expect='finalizing')
add('wrong_nonce', wit={**witness(raw(terminal)), 'launch_nonce': 'c' * 32}, expect='finalizing')
add('wrong_job', wit={**witness(raw(terminal)), 'job_id': 'different'}, expect='finalizing')
add('bool_witness_protocol', wit={**witness(raw(terminal)), 'terminal_publication_protocol': True}, expect='finalizing')
add('bool_request_protocol', req={**request, 'terminal_publication_protocol': True}, expect='finalizing')
add('null_request_protocol', req={**request, 'terminal_publication_protocol': None}, expect='finalizing')
add('bool_exit_protocol', exit={**terminal, 'terminal_publication_protocol': True}, expect='finalizing')
add('unknown_exit_protocol', exit={**terminal, 'terminal_publication_protocol': 2}, expect='finalizing')
add('missing_exit_protocol', exit={key: value for key, value in terminal.items() if key != 'terminal_publication_protocol'}, expect='finalizing')
add('legacy_both_unmarked', req={key: value for key, value in request.items() if key != 'terminal_publication_protocol'},
    exit={key: value for key, value in terminal.items() if key != 'terminal_publication_protocol'}, wit=None, expect='succeeded')
add('legacy_request_new_exit', req={key: value for key, value in request.items() if key != 'terminal_publication_protocol'}, expect='succeeded')
add('effect_unknown', exit={**terminal, 'exit_code': 125, 'effect_outcome': 'unknown',
                           'status_authoritative': False, 'automatic_retry': False}, expect='effect_unknown')
add('live_new_job', exit=None, wit=None, launch={'backend': 'detached', 'launcher_pid': pid}, started=owner, expect='running')
add('gone_new_job', exit=None, wit=None, launch={'backend': 'detached', 'launcher_pid': pid},
    started={**owner, 'supervisor_identity': {'kind': 'proc_start_ticks', 'value': 'invalid'}}, expect='finalizing')
for active, sub in [('active', 'exited'), ('failed', 'failed'), ('inactive', 'dead')]:
    properties = (f'LoadState=loaded\nActiveState={active}\nSubState={sub}\nExecMainCode=1\nExecMainStatus=0\n'
                  f'InvocationID={invocation}\nDescription=Hepta Runtime job {job_id} {nonce}\n')
    add('systemd_' + active + '_' + sub, exit=None, wit=None, launch={'backend': 'systemd'},
        started=owner, systemd=properties, expect='finalizing')
properties = (f'LoadState=loaded\nActiveState=active\nSubState=running\n'
              f'InvocationID={invocation}\nDescription=Hepta Runtime job {job_id} {nonce}\n')
add('live_systemd_new_job', exit=None, wit=None, launch={'backend': 'systemd'}, started=owner,
    systemd=properties, expect='running')
properties = (f'LoadState=loaded\nActiveState=active\nSubState=exited\nExecMainCode=1\nExecMainStatus=0\n'
              f'InvocationID={invocation}\nDescription=Hepta Runtime job {job_id} {nonce}\n')
add('legacy_systemd_exited', req={key: value for key, value in request.items() if key != 'terminal_publication_protocol'},
    exit=None, wit=None, launch={'backend': 'systemd'}, started=owner, systemd=properties, expect='succeeded')
add('oversized_witness', wit=b' ' * 4097, expect='finalizing')
add('exit_symlink', link='exit.json', expect='finalizing')
add('witness_symlink', link='exit.witness.json', expect='finalizing')
add('witness_hardlink', hardlink=True, expect='finalizing')
add('raw_hash_not_reserialized', exit_raw=json.dumps(terminal, indent=2).encode(),
    wit=witness(raw(terminal)), expect='finalizing')

failures = []
with tempfile.TemporaryDirectory(prefix='terminal-status-', dir=q['job']) as temporary:
    root = Path(temporary).resolve()
    for index, (name, case) in enumerate(cases):
        state = root / str(index)
        job = state / 'jobs' / job_id
        job.mkdir(mode=0o700, parents=True)
        os.chmod(state, 0o700)
        os.chmod(job.parent, 0o700)
        values = {'request.json': case.get('req', request), 'exit.json': case.get('exit', terminal),
                  'launch.json': case.get('launch'), 'started.json': case.get('started')}
        exit_bytes = case.get('exit_raw', raw(values['exit.json'])) if values['exit.json'] is not None else None
        values['exit.json'] = exit_bytes
        values['exit.witness.json'] = case.get('wit', witness(exit_bytes) if exit_bytes is not None else None)
        for filename, value in values.items():
            if value is not None:
                (job / filename).write_bytes(value if isinstance(value, bytes) else raw(value))
                os.chmod(job / filename, 0o600)
        if case.get('link'):
            path, target = job / case['link'], state / 'receipt'
            path.rename(target)
            path.symlink_to(target)
        if case.get('hardlink'):
            os.link(job / 'exit.witness.json', state / 'duplicate-witness')
        def snapshot():
            return {p.name: ('link', os.readlink(p)) if p.is_symlink() else ('file', p.read_bytes()) for p in job.iterdir()}
        before = snapshot()
        prefix = ''
        if 'systemd' in case:
            prefix = ('import subprocess, types\nsubprocess.run = lambda *args, **kwargs: '
                      'types.SimpleNamespace(stdout=' + repr(case['systemd']) + ')\n')
        result = subprocess.run([sys.executable, '-I', '-S', '-c', prefix + status],
            input=raw({'job_id': job_id, 'job_dir': str(job), 'unit': 'hepta-test', 'wait_seconds': 0}),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        actual = json.loads(result.stdout) if result.returncode == 0 else {'state': 'RPC_ERROR', 'stderr': result.stderr.decode()}
        okay = actual['state'] == case['expect'] and before == snapshot()
        if case['expect'] == 'succeeded' and name not in ('legacy_both_unmarked', 'legacy_systemd_exited'):
            okay = okay and actual.get('terminal_publication_confirmed') is True
        if name == 'legacy_both_unmarked':
            okay = okay and 'terminal_publication_confirmed' not in actual
        if case['expect'] == 'finalizing':
            okay = okay and actual.get('terminal_publication_confirmed') is False and actual.get('status_authoritative') is False and actual.get('automatic_retry') is False
        if name == 'effect_unknown':
            okay = okay and actual.get('status_authoritative') is False and actual.get('terminal_publication_confirmed') is True
        if not okay:
            failures.append({'case': name, 'expected': case['expect'], 'actual': actual})
print(json.dumps({'reviewed_jobs_rs_sha256': hashlib.sha256(status.encode()).hexdigest(),
                  'cases': len(cases), 'passed': len(cases) - len(failures), 'failures': failures}, indent=2))

"#;

fn runner_source() -> String {
	let body = START_CODE
		.split_once("runner = r'''")
		.unwrap()
		.1
		.split_once("\n'''\nrunner_path")
		.unwrap()
		.0;
	format!("{PRIVATE_DIRECTORY_CODE}\n{body}\n")
}

fn exercise(fixture: &str, case: &str) -> Value {
	use std::process::{Command, Stdio};
	let temporary = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	let state = temporary.path().join("state");
	let job = state.join("jobs/terminal-publication");
	std::fs::create_dir_all(&job).unwrap();
	for directory in [&state, &state.join("jobs"), &job] {
		std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
	}
	let payload = json!({"job":job,"case":case,"runner":runner_source(),
		"status":private_remote_code(STATUS_CODE).unwrap(),"start":private_remote_code(START_CODE).unwrap()});
	let mut child = Command::new("python3")
		.args(["-I", "-S", "-c", fixture])
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	child
		.stdin
		.take()
		.unwrap()
		.write_all(&serde_json::to_vec(&payload).unwrap())
		.unwrap();
	let output = child.wait_with_output().unwrap();
	assert!(
		output.status.success(),
		"case {case}: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	serde_json::from_slice(&output.stdout).unwrap()
}

fn assert_pending(status: &Value) {
	assert_eq!(status["state"], "finalizing");
	assert_eq!(status["terminal_publication_confirmed"], false);
	assert_eq!(status["status_authoritative"], false);
	assert_eq!(status["automatic_retry"], false);
	assert!(status.get("exit_code").is_none());
}

#[test]
fn terminal_witness_proves_the_preceding_exit_barrier_not_its_own_directory_sync() {
	for case in ["normal", "witness_directory"] {
		let result = exercise(RUNNER_FIXTURE, case);
		assert_eq!(result["spawn_count"], 1);
		assert_eq!(result["effect"], "once\n");
		assert_eq!(result["alive_after_runner"], json!([]));
		assert_eq!(result["observation_changed_files"], false);
		assert_eq!(result["status"]["state"], "succeeded");
		assert_eq!(result["status"]["terminal_publication_confirmed"], true);
		assert_eq!(result["witness"]["exit_sha256"], result["exit_sha256"]);
		assert_eq!(result["witness"]["job_id"], result["receipt"]["job_id"]);
		assert_eq!(
			result["witness"]["launch_nonce"],
			result["receipt"]["launch_nonce"]
		);
		let events = result["events"].as_array().unwrap();
		let position = |name| events.iter().position(|value| value == name).unwrap();
		assert!(position("synced:exit.json.tmp") < position("renamed:exit.json"));
		assert!(position("renamed:exit.json") < position("synced:directory_after_exit.json"));
		assert!(
			position("synced:directory_after_exit.json") < position("sync:exit.witness.json.tmp")
		);
		assert!(position("synced:exit.witness.json.tmp") < position("renamed:exit.witness.json"));
		assert_eq!(
			result["supervisor_code"],
			if case == "normal" { 0 } else { 1 }
		);
	}
}

#[test]
fn visible_exit_is_not_success_after_directory_sync_or_witness_write_failure() {
	for case in ["exit_directory", "witness_write", "witness_file_sync"] {
		let result = exercise(RUNNER_FIXTURE, case);
		assert_eq!(result["supervisor_code"], 1);
		assert_eq!(result["spawn_count"], 1);
		assert_eq!(result["effect"], "once\n");
		assert_eq!(result["alive_after_runner"], json!([]));
		assert_eq!(result["receipt"]["exit_code"], 0);
		assert_eq!(result["receipt"]["output_durable"], true);
		assert_eq!(result["receipt"]["terminal_publication_protocol"], 1);
		assert!(result["witness"].is_null());
		assert_eq!(result["observation_changed_files"], false);
		assert_pending(&result["status"]);
	}
}

#[test]
fn new_requests_bind_the_protocol_and_orphan_witnesses_cannot_launch() {
	let normal = exercise(START_FIXTURE, "normal");
	assert!(normal["error"].is_null());
	assert_eq!(normal["launches"], json!(["systemd-run"]));
	assert_eq!(normal["request"]["terminal_publication_protocol"], 1);
	assert_eq!(
		normal["request"]["request_fingerprint"],
		"original-full-request-binding"
	);
	for case in ["start_witness", "start_tmp", "runner_witness", "runner_tmp"] {
		let result = exercise(START_FIXTURE, case);
		assert!(result["error"].as_str().unwrap().starts_with("SystemExit:"));
		assert_eq!(result["launches"], json!([]));
		assert_eq!(result["artifact_unchanged"], true);
		if case.starts_with("start_") {
			assert!(result["request"].is_null());
		} else {
			assert_eq!(
				result["request"]["request_fingerprint"],
				"original-full-request-binding"
			);
		}
	}
}

#[test]
fn terminal_status_requires_matching_witnesses_and_preserves_running_and_legacy_jobs() {
	let result = exercise(STATUS_FIXTURE, "all");
	assert_eq!(result["cases"], 27);
	assert_eq!(result["passed"], 27);
	assert_eq!(result["failures"], json!([]));
}
