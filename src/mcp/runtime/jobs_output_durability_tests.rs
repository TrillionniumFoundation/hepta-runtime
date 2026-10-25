// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exercise the real supervisor's output and post-spawn durability boundaries.
use super::*;
use std::os::unix::fs::PermissionsExt;

const FIXTURE: &str = r#"
import io,json,os,pathlib,subprocess,sys,time
q=json.load(sys.stdin)
job=pathlib.Path(q['job'])
req={'job_id':'output-durability','job_dir':str(job),'launch_nonce':'a'*32,
     'request_fingerprint':'durability-fixture','executable':sys.executable,
     'args':['-I','-S','-c',q['child']],'execution_mode':'operator',
     'timeout_seconds':10,'env':{}}
(job/'request.json').write_text(json.dumps(req))
os.chmod(job/'request.json',0o600)
info=job.stat()
binding={'device':info.st_dev,'inode':info.st_ino,'job_id':req['job_id'],
         'launch_nonce':req['launch_nonce'],'request_fingerprint':req['request_fingerprint']}
real_sync,real_popen=os.fsync,subprocess.Popen
events=[]
spawned=[]
def sync(fd):
    name=pathlib.Path(os.readlink('/proc/self/fd/'+str(fd))).name
    events.append(name)
    if name==q.get('fail'):
        raise OSError('injected durability failure')
    return real_sync(fd)
def popen(*args,**kwargs):
    child=real_popen(*args,**kwargs)
    spawned.append(child)
    if q.get('fail')=='child.json.tmp':
        deadline=time.monotonic()+3
        while not (job/'effect').exists() and time.monotonic()<deadline:
            time.sleep(.01)
        if not (job/'effect').exists():
            child.kill();child.wait()
            raise AssertionError('fixture child did not cross the effect boundary')
    return child
os.fsync,subprocess.Popen=sync,popen
sys.argv=['-c',str(job),json.dumps(binding),'detached']
code=0
try:
    exec(q['runner'],{'__name__':'__main__'})
except SystemExit as stopped:
    code=stopped.code if isinstance(stopped.code,int) else 1
finally:
    os.fsync,subprocess.Popen=real_sync,real_popen
receipt=json.loads((job/'exit.json').read_text())
alive=[p.pid for p in spawned if p.poll() is None]
for p in spawned:
    if p.poll() is None:
        os.killpg(p.pid,9);p.wait(timeout=3)
sys.stdin=io.StringIO(json.dumps({'job_id':req['job_id'],'job_dir':str(job),'wait_seconds':0}))
captured=io.StringIO()
saved_stdout=sys.stdout
try:
    sys.stdout=captured
    exec(q['status'],{'__name__':'__main__'})
finally:
    sys.stdout=saved_stdout
print(json.dumps({'supervisor_code':code,'receipt':receipt,'events':events,
                  'alive_after_runner':alive,'effect_exists':(job/'effect').exists(),
                  'status':json.loads(captured.getvalue()),
                  'stdout':(job/'stdout.log').read_text(),
                  'stderr':(job/'stderr.log').read_text()}))
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

fn python(code: &str, payload: &Value) -> Value {
	use std::process::{Command, Stdio};
	let mut child = Command::new("python3")
		.args(["-I", "-S", "-c", code])
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	child
		.stdin
		.take()
		.unwrap()
		.write_all(&serde_json::to_vec(payload).unwrap())
		.unwrap();
	let output = child.wait_with_output().unwrap();
	assert!(
		output.status.success(),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
	serde_json::from_slice(&output.stdout).unwrap()
}

fn exercise(fail: Option<&str>, child: &str) -> Value {
	let temporary = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	let state = temporary.path().join("state");
	let job = state.join("jobs/output-durability");
	std::fs::create_dir_all(&job).unwrap();
	for directory in [&state, &state.join("jobs"), &job] {
		std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
	}
	python(
		FIXTURE,
		&json!({"job":job,"fail":fail,"child":child,"runner":runner_source(),
			"status":private_remote_code(STATUS_CODE).unwrap()}),
	)
}

const OUTPUT_CHILD: &str =
	"import sys;sys.stdout.write('original stdout\\n');sys.stderr.write('original stderr\\n')";

#[test]
fn completed_output_is_synced_once_before_the_terminal_receipt() {
	let result = exercise(None, OUTPUT_CHILD);
	assert_eq!(result["supervisor_code"], 0);
	assert_eq!(result["receipt"]["output_complete"], true);
	assert_eq!(result["receipt"]["output_durable"], true);
	assert_eq!(result["status"]["state"], "succeeded");
	assert_eq!(result["stdout"], "original stdout\n");
	assert_eq!(result["stderr"], "original stderr\n");
	let events = result["events"].as_array().unwrap();
	let terminal = events.iter().position(|v| v == "exit.json.tmp").unwrap();
	for stream in ["stdout.log", "stderr.log"] {
		assert_eq!(events.iter().filter(|v| *v == stream).count(), 1);
		assert!(events.iter().position(|v| v == stream).unwrap() < terminal);
	}
}

#[test]
fn either_output_sync_failure_cannot_be_reported_as_success() {
	for stream in ["stdout", "stderr"] {
		let result = exercise(Some(&format!("{stream}.log")), OUTPUT_CHILD);
		assert_eq!(result["supervisor_code"], 74);
		assert_eq!(result["receipt"]["exit_code"], 0);
		assert_eq!(result["receipt"]["output_complete"], false);
		assert_eq!(result["receipt"]["output_durable"], false);
		assert_eq!(result["receipt"]["log_synced"][stream], false);
		assert!(result["receipt"]["log_errors"][stream]
			.as_str()
			.unwrap()
			.contains("sync: injected durability failure"));
		assert_eq!(result["status"]["state"], "failed");
	}
}

#[test]
fn post_spawn_receipt_failure_reaps_the_child_and_preserves_unknown_effect() {
	let result = exercise(
		Some("child.json.tmp"),
		"import pathlib,time;pathlib.Path('effect').write_text('already executed');time.sleep(30)",
	);
	assert_eq!(result["supervisor_code"], 125);
	assert_eq!(result["effect_exists"], true);
	assert_eq!(result["alive_after_runner"], json!([]));
	assert_eq!(result["receipt"]["child_reaped"], true);
	assert_eq!(result["receipt"]["child_spawned"], true);
	assert!(result["receipt"]["child_pid"].as_u64().unwrap() > 1);
	assert_eq!(result["receipt"]["child_exit_code"], -9);
	assert_eq!(result["receipt"]["effect_outcome"], "unknown");
	assert_eq!(result["receipt"]["automatic_retry"], false);
	assert_eq!(result["receipt"]["status_authoritative"], false);
	assert!(result["receipt"].get("launch_error").is_none());
	assert_eq!(result["status"]["state"], "effect_unknown");
}

// The fixture retains failed originals and separates supervisor waits from its
// own finally rescue. It contains one fixed local child and one startup fault.
const READER_START_FIXTURE: &str = r#"
"""One local, owned-child reader-start fault; no public API or remote access."""
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import sys
import threading
import time

q = json.load(sys.stdin)
job = pathlib.Path(q['job'])
started_at = time.monotonic()
req = {'job_id': 'reader-start-durability', 'job_dir': str(job),
       'launch_nonce': 'b' * 32, 'terminal_publication_protocol': 1,
       'request_fingerprint': 'second-reader-start-fixture',
       'executable': sys.executable,
       'args': ['-I', '-S', '-c',
                "import pathlib,time;pathlib.Path('effect').write_bytes(b'original child\\n');time.sleep(5)"],
       'execution_mode': 'operator', 'cwd': str(job), 'timeout_seconds': 10, 'env': {}}
(job / 'request.json').write_text(json.dumps(req))
os.chmod(job / 'request.json', 0o600)
info = job.stat()
binding = {'device': info.st_dev, 'inode': info.st_ino,
           'job_id': req['job_id'], 'launch_nonce': req['launch_nonce'],
           'request_fingerprint': req['request_fingerprint']}
real_popen = subprocess.Popen
real_start = threading.Thread.start
real_join = threading.Thread.join
spawned = []
threads = []
waits = []
starts = []
joins = []
cleanup = []
scope = {'__name__': '__main__'}
state = {'phase': 'runner', 'injected': False, 'child_receipt_before_fault': False,
         'effect_before_fault': False, 'runner_exception': None,
         'runner_system_exit': None, 'runner_wait_events': None}
PRIMARY = 'injected second output reader startup failure'


def problem(where, error):
    cleanup.append({'where': where, 'type': type(error).__name__, 'message': str(error)})


def popen(*args, **kwargs):
    if spawned:
        raise AssertionError('fixture permits exactly one workload Popen')
    child = real_popen(*args, **kwargs)
    spawned.append(child)
    real_wait = child.wait

    def wait(timeout=None):
        event = {'phase': state['phase'], 'timeout': timeout, 'returned': False,
                 'returncode': None, 'error': None}
        waits.append(event)
        try:
            value = real_wait(timeout=timeout)
            event['returned'] = True
            event['returncode'] = value
            return value
        except BaseException as error:
            event['error'] = {'type': type(error).__name__, 'message': str(error)}
            raise
    child.wait = wait
    return child


def start(thread, *args, **kwargs):
    index = len(starts) + 1
    event = {'call': index, 'returned': False, 'injected': False,
             'ident_after': None, 'error': None}
    starts.append(event)
    threads.append(thread)
    if index == 2:
        if len(spawned) != 1:
            raise AssertionError('fault must follow the original workload Popen')
        record = json.loads((job / 'child.json').read_bytes())
        state['child_receipt_before_fault'] = record['pid'] == spawned[0].pid
        if not state['child_receipt_before_fault']:
            raise AssertionError('fault must follow original child receipt publication')
        until = time.monotonic() + 3
        while not (job / 'effect').exists() and time.monotonic() < until:
            time.sleep(0.005)
        state['effect_before_fault'] = (job / 'effect').read_bytes() == b'original child\n'
        if not state['effect_before_fault']:
            raise AssertionError('original child execution marker is missing')
        event['injected'] = True
        event['error'] = {'type': 'RuntimeError', 'message': PRIMARY}
        state['injected'] = True
        raise RuntimeError(PRIMARY)
    try:
        value = real_start(thread, *args, **kwargs)
        event['returned'] = True
        event['ident_after'] = thread.ident
        return value
    except BaseException as error:
        event['error'] = {'type': type(error).__name__, 'message': str(error)}
        raise



def join(thread, *args, **kwargs):
    number = next((index + 1 for index, saved in enumerate(threads) if saved is thread), None)
    event = {'phase': state['phase'], 'reader_call': number, 'returned': False,
             'alive_after': None, 'error': None}
    joins.append(event)
    try:
        value = real_join(thread, *args, **kwargs)
        event['returned'] = True
        event['alive_after'] = thread.is_alive()
        return value
    except BaseException as error:
        event['error'] = {'type': type(error).__name__, 'message': str(error)}
        raise


def budget(_signum, _frame):
    raise TimeoutError('fixture original 30-second cleanup trigger')


# The fixed child sleeps only five seconds. The alarm leaves the outer original
# wrapper's 45-second budget for finally; it never renews the workload budget.
signal.signal(signal.SIGALRM, budget)
signal.setitimer(signal.ITIMER_REAL, 30)
subprocess.Popen = popen
threading.Thread.start = start
threading.Thread.join = join
sys.argv = ['-c', str(job), json.dumps(binding), 'detached']
try:
    exec(q['runner'], scope)
except SystemExit as stopped:
    state['runner_system_exit'] = stopped.code if isinstance(stopped.code, int) else 1
except BaseException as error:
    state['runner_exception'] = {'type': type(error).__name__, 'message': str(error),
                                 'cause': None if error.__cause__ is None else {
                                     'type': type(error.__cause__).__name__,
                                     'message': str(error.__cause__)}}
finally:
    signal.setitimer(signal.ITIMER_REAL, 0)
    subprocess.Popen = real_popen
    threading.Thread.start = real_start
    threading.Thread.join = real_join
    state['runner_wait_events'] = len(waits)
    state['phase'] = 'rescue'
    # No poll/try_wait before the last possible group signal: the original
    # unreaped child, rather than a saved or discovered PID, binds this group.
    for child in spawned:
        if child.returncode is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
                cleanup.append({'where': 'rescue_signal', 'submitted': True})
            except ProcessLookupError:
                cleanup.append({'where': 'rescue_signal', 'submitted': False, 'absent': True})
            except BaseException as error:
                problem('rescue_signal', error)
            try:
                child.wait(timeout=3)
            except BaseException as error:
                problem('rescue_wait', error)
    for index, thread in enumerate(threads):
        if thread.ident is not None:
            try:
                join(thread, timeout=2)
                if thread.is_alive():
                    raise RuntimeError('owned reader remains alive after rescue join')
            except BaseException as error:
                problem('rescue_reader_' + str(index + 1), error)
    for child in spawned:
        for label, stream in (('stdout', child.stdout), ('stderr', child.stderr)):
            if stream is None:
                continue
            # Never close a BufferedReader while a live reader can hold its lock.
            active = any(t.ident is not None and t.is_alive() for t in threads)
            if active:
                problem('rescue_close_' + label, RuntimeError('live reader still owns a pipe'))
                continue
            try:
                stream.close()
            except BaseException as error:
                problem('rescue_close_' + label, error)
    for name in ('out', 'err', 'stdin_handle'):
        stream = scope.get(name)
        if hasattr(stream, 'close'):
            try:
                stream.close()
            except BaseException as error:
                problem('close_' + name, error)
    if isinstance(scope.get('owner_fd'), int):
        try:
            os.close(scope['owner_fd'])
        except BaseException as error:
            problem('close_owner_fd', error)
    for fd in scope.get('_hepta_directory_pins', []):
        try:
            os.close(fd)
        except BaseException as error:
            problem('close_directory_fd', error)

# Evidence reads occur only after finally. A decode/assertion failure cannot
# bypass cleanup, and the retained original files remain independently readable.
originals = {}
for name in ('request.json', 'child.json', 'owner-intent.json', 'started.json',
             'exit.json', 'exit.witness.json', 'stdout.log', 'stderr.log', 'effect'):
    path = job / name
    if not path.exists():
        originals[name] = None
        continue
    raw = path.read_bytes()
    originals[name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                       'utf8': raw.decode('utf-8')}
receipt = None if originals['exit.json'] is None else json.loads(originals['exit.json']['utf8'])
witness = None if originals['exit.witness.json'] is None else json.loads(originals['exit.witness.json']['utf8'])
print(json.dumps({'schema': 'hepta-reader-start-fault-fixture/v1',
                  'elapsed_seconds': time.monotonic() - started_at,
                  'workload_popen_count': len(spawned),
                  'workload_returncodes': [p.returncode for p in spawned],
                  'all_workloads_reaped': bool(spawned) and all(p.returncode is not None for p in spawned),
                  'all_started_readers_joined': all(t.ident is None or any(
                      e['reader_call'] == i + 1 and e['returned'] and e['alive_after'] is False
                      for e in joins) for i, t in enumerate(threads)),
                  'reader_start_calls': starts, 'reader_join_events': joins, 'wait_events': waits,
                  'cleanup_events': cleanup, 'state': state,
                  'originals': originals, 'receipt': receipt, 'witness': witness},
                 sort_keys=True))
"#;

fn reader_start_fault() -> Value {
	use std::process::{Command, Stdio};
	use std::time::{Duration, Instant};
	let root = tempfile::Builder::new()
		.prefix("hepta-reader-start-fault-")
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap()
		.keep();
	let state = root.join("state");
	let jobs = state.join("jobs");
	let job = jobs.join("reader-start-durability");
	std::fs::create_dir_all(&job).unwrap();
	for directory in [&state, &jobs, &job] {
		std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
	}
	let input = root.join("input.json");
	let stdout = root.join("fixture.stdout");
	let stderr = root.join("fixture.stderr");
	std::fs::write(
		&input,
		serde_json::to_vec(&json!({"job":job,"runner":runner_source()})).unwrap(),
	)
	.unwrap();
	let mut child = Command::new("python3")
		.args(["-I", "-S", "-c", READER_START_FIXTURE])
		.stdin(Stdio::from(std::fs::File::open(&input).unwrap()))
		.stdout(Stdio::from(std::fs::File::create(&stdout).unwrap()))
		.stderr(Stdio::from(std::fs::File::create(&stderr).unwrap()))
		.spawn()
		.unwrap();
	let deadline = Instant::now() + Duration::from_secs(45);
	let status = loop {
		match child.try_wait() {
			Ok(Some(status)) => break status,
			Ok(None) if Instant::now() < deadline => {
				std::thread::sleep(Duration::from_millis(10));
			}
			outcome => {
				let killed = child.kill();
				let waited = child.wait();
				panic!(
					"reader fixture failed: {outcome:?}; kill={killed:?}; wait={waited:?}; retained={root:?}"
				);
			}
		}
	};
	assert!(
		status.success(),
		"reader fixture failed; retained={root:?}; stderr={}",
		std::fs::read_to_string(&stderr).unwrap_or_default()
	);
	serde_json::from_slice(&std::fs::read(stdout).unwrap()).unwrap()
}

#[test]
fn reader_start_failure_reaps_original_child_and_preserves_unknown_effect() {
	let result = reader_start_fault();
	assert_eq!(result["workload_popen_count"], 1);
	assert_eq!(result["state"]["injected"], true);
	assert_eq!(result["state"]["child_receipt_before_fault"], true);
	assert_eq!(result["state"]["effect_before_fault"], true);
	assert_eq!(result["state"]["runner_system_exit"], 125);
	assert!(result["state"]["runner_exception"].is_null());
	let starts = result["reader_start_calls"].as_array().unwrap();
	assert_eq!(starts.len(), 2);
	assert_eq!(starts[0]["returned"], true);
	assert_eq!(starts[1]["returned"], false);
	assert_eq!(starts[1]["injected"], true);
	let waits = result["wait_events"].as_array().unwrap();
	assert_eq!(waits.len(), 1, "fixture rescue must not supply the wait");
	assert_eq!(waits[0]["phase"], "runner");
	assert_eq!(waits[0]["returned"], true);
	assert_eq!(waits[0]["returncode"], -9);
	assert_eq!(result["all_workloads_reaped"], true);
	assert_eq!(result["all_started_readers_joined"], true);
	assert_eq!(result["cleanup_events"], json!([]));
	let joins = result["reader_join_events"].as_array().unwrap();
	assert!(joins.iter().any(|join| {
		join["phase"] == "runner"
			&& join["reader_call"] == 1
			&& join["returned"] == true
			&& join["alive_after"] == false
	}));
	let receipt = &result["receipt"];
	assert_eq!(receipt["exit_code"], 125);
	assert_eq!(receipt["child_reaped"], true);
	assert_eq!(receipt["child_exit_code"], -9);
	assert_eq!(receipt["effect_outcome"], "unknown");
	assert_eq!(receipt["automatic_retry"], false);
	assert_eq!(receipt["status_authoritative"], false);
	assert_eq!(receipt["output_complete"], false);
	assert_eq!(receipt["output_durable"], false);
	assert_eq!(receipt["supervisor_cleanup_errors"], json!([]));
	assert_eq!(
		receipt["supervisor_error"],
		"output reader startup failed after spawn: RuntimeError: injected second output reader startup failure"
	);
	assert!(receipt.get("launch_error").is_none());
	assert_eq!(result["witness"]["job_id"], receipt["job_id"]);
	assert_eq!(result["witness"]["launch_nonce"], receipt["launch_nonce"]);
	assert_eq!(
		result["witness"]["exit_sha256"],
		result["originals"]["exit.json"]["sha256"]
	);
}

#[test]
fn final_status_preserves_legacy_receipts_and_refuses_incomplete_output() {
	const CODE: &str = r#"
import json,sys
q=json.load(sys.stdin)
scope={}
exec(q['function'],scope)
print(json.dumps([scope['final_status'](v) for v in q['receipts']]))
"#;
	let function = STATUS_CODE
		.split_once("def final_status(exit_data):")
		.unwrap()
		.1
		.split_once("\ndef one_status():")
		.unwrap()
		.0;
	let result = python(
		CODE,
		&json!({"function":format!("def final_status(exit_data):{function}"),"receipts":[
			{"exit_code":0},
			{"exit_code":0,"output_complete":true},
			{"exit_code":0,"output_complete":false},
			{"exit_code":0,"output_complete":true,"output_durable":false,"state":"succeeded"},
			{"exit_code":0,"output_durable":null},
			{"exit_code":124,"timed_out":true,"output_durable":false},
			{"exit_code":0,"cancelled":true,"output_durable":false}
		]}),
	);
	let states: Vec<_> = result
		.as_array()
		.unwrap()
		.iter()
		.map(|value| value["state"].as_str().unwrap())
		.collect();
	assert_eq!(
		states,
		[
			"succeeded",
			"succeeded",
			"failed",
			"failed",
			"failed",
			"timed_out",
			"cancelled"
		]
	);
}

// The fixture becomes a Linux subreaper only to collect its own adopted
// grandchild after the real runner finishes. The fixed grandchild self-exits
// after eight seconds even when the product fails to terminate it; fixture
// rescue and product signals/waits are recorded separately.
const INHERITED_PIPE_FIXTURE: &str = r#"
import ctypes,hashlib,json,os,pathlib,signal,subprocess,sys,threading,time
q=json.load(sys.stdin)
job=pathlib.Path(q['job'])
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(36,1,0,0,0)!=0:
    raise OSError(ctypes.get_errno(),'fixture child-subreaper setup failed')
child_code='''import os,pathlib,signal,time
descendant=os.fork()
if descendant==0:
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    pathlib.Path('descendant').write_text(str(os.getpid()))
    time.sleep(8)
    os._exit(0)
until=time.monotonic()+2
while not pathlib.Path('descendant').exists() and time.monotonic()<until:
    time.sleep(.005)
if not pathlib.Path('descendant').exists():
    raise RuntimeError('original descendant did not start')
pathlib.Path('effect').write_bytes(b'original leader executed once\\n')
os._exit(0)
'''
if not q['ignore_term']:
    child_code=child_code.replace('signal.SIG_IGN','signal.SIG_DFL')
if q['staggered']:
    child_code=child_code.replace('    time.sleep(8)',
        "    os.write(1,b'original staggered stdout\\n')\n"
        "    os.write(2,b'original staggered stderr\\n')\n"
        "    time.sleep(1.0)\n"
        "    os.close(1)\n"
        "    time.sleep(1.5)\n"
        "    os.close(2)")
req={'job_id':'inherited-pipe-durability','job_dir':str(job),
     'launch_nonce':'c'*32,'terminal_publication_protocol':1,
     'request_fingerprint':'original-leader-exit-held-pipes',
     'executable':sys.executable,'args':['-I','-S','-c',child_code],
     'execution_mode':'operator','cwd':str(job),'timeout_seconds':10,'env':{}}
(job/'request.json').write_text(json.dumps(req))
os.chmod(job/'request.json',0o600)
info=job.stat()
binding={'device':info.st_dev,'inode':info.st_ino,'job_id':req['job_id'],
         'launch_nonce':req['launch_nonce'],'request_fingerprint':req['request_fingerprint']}
real_popen,real_killpg,real_waitid=subprocess.Popen,os.killpg,os.waitid
spawned,signals,waits,adopted,cleanup=[],[],[],[],[]
scope={'__name__':'__main__'}
state={'phase':'runner','runner_exit':None,'runner_exception':None,
       'cancel_delivered_during_drain':False,
       'read_fault_calls':{'stdout':0,'stderr':0}}

class FailedReader:
    def __init__(self,stream,label):
        self.stream,self.label=stream,label
    def read1(self,size):
        state['read_fault_calls'][self.label]+=1
        raise OSError('injected '+self.label+' read1 failure')
    def close(self):
        return self.stream.close()
    def __getattr__(self,name):
        return getattr(self.stream,name)

def popen(*args,**kwargs):
    if spawned:
        raise AssertionError('fixture permits exactly one workload Popen')
    child=real_popen(*args,**kwargs)
    spawned.append(child)
    if q['read_fault']:
        child.stdout=FailedReader(child.stdout,'stdout')
        child.stderr=FailedReader(child.stderr,'stderr')
    original_wait=child.wait
    def wait(timeout=None):
        event={'phase':state['phase'],'returned':False,'returncode':None}
        waits.append(event)
        result=original_wait(timeout=timeout)
        event.update(returned=True,returncode=result)
        return result
    child.wait=wait
    return child

def waitid(*args,**kwargs):
    result=real_waitid(*args,**kwargs)
    if (q['cancel_overlap'] and scope.get('leader_drain_until') is not None
            and not state['cancel_delivered_during_drain']):
        state['cancel_delivered_during_drain']=True
        os.kill(os.getpid(),signal.SIGTERM)
    return result

def killpg(group,signum):
    child=spawned[0]
    unreaped=child.returncode is None
    observed=real_waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) if unreaped else None
    event={'phase':state['phase'],'group':group,'signal':signum,
           'original_child_unreaped':unreaped,'returned':False,
           'original_leader_exited':observed is not None and observed.si_pid==child.pid,
           'leader_exit_code':None if observed is None else observed.si_status}
    signals.append(event)
    result=real_killpg(group,signum)
    event['returned']=True
    return result

def alarm(_signum,_frame):
    raise TimeoutError('fixture original 30-second cleanup trigger')

signal.signal(signal.SIGALRM,alarm)
signal.setitimer(signal.ITIMER_REAL,30)
subprocess.Popen,os.killpg,os.waitid=popen,killpg,waitid
sys.argv=['-c',str(job),json.dumps(binding),'detached']
try:
    exec(q['runner'],scope)
except SystemExit as stopped:
    state['runner_exit']=stopped.code if isinstance(stopped.code,int) else 1
except BaseException as error:
    state['runner_exception']=type(error).__name__+': '+str(error)
finally:
    signal.setitimer(signal.ITIMER_REAL,0)
    subprocess.Popen,os.killpg,os.waitid=real_popen,real_killpg,real_waitid
    readers=scope.get('readers') or []
    state['readers_alive_at_runner_return']=[r.is_alive() for r in readers]
    state['log_eof_at_runner_return']=dict(scope.get('log_eof',{}))
    state['normal_drain_window_present']=scope.get('leader_drain_until') is not None
    state['cancellation_deadline']=scope.get('stop_deadline')
    state['phase']='rescue'
    # No poll/wait before the last rescue group signal: only an unreaped
    # original child permits this cleanup signal. Never signal a saved PID.
    for child in spawned:
        if child.returncode is None:
            try:
                real_killpg(child.pid,signal.SIGKILL)
                cleanup.append('fixture submitted rescue group SIGKILL')
            except ProcessLookupError:
                cleanup.append('fixture rescue group was absent')
            except BaseException as error:
                cleanup.append('fixture rescue signal: '+str(error))
            try:
                child.wait(timeout=12)
            except BaseException as error:
                cleanup.append('fixture rescue wait: '+str(error))
    # Every possible fixture workload is fixed and bounded. Adopted-child
    # collection can therefore wait for the eight-second self-exit on a red
    # baseline; it never supplies a group signal after leader reap.
    while True:
        try:
            pid,status=os.waitpid(-1,0)
        except ChildProcessError:
            break
        adopted.append({'pid':pid,'returncode':os.waitstatus_to_exitcode(status)})
    for reader in readers:
        if reader.ident is not None:
            reader.join(timeout=2)
            if reader.is_alive():
                cleanup.append('fixture reader did not stop')
    if not any(r.is_alive() for r in readers):
        for child in spawned:
            for stream in (child.stdout,child.stderr):
                if stream is not None:
                    stream.close()
        for name in ('out','err','stdin_handle'):
            stream=scope.get(name)
            if hasattr(stream,'close'):
                stream.close()
    if isinstance(scope.get('owner_fd'),int):
        os.close(scope['owner_fd'])
    for fd in scope.get('_hepta_directory_pins',[]):
        os.close(fd)

originals={}
for name in ('request.json','child.json','exit.json','exit.witness.json',
             'stdout.log','stderr.log','effect','descendant'):
    path=job/name
    raw=path.read_bytes() if path.exists() else None
    originals[name]=None if raw is None else {
        'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'utf8':raw.decode('utf-8')}
receipt=None if originals['exit.json'] is None else json.loads(originals['exit.json']['utf8'])
witness=None if originals['exit.witness.json'] is None else json.loads(originals['exit.witness.json']['utf8'])
status_scope={}
exec(q['status_function'],status_scope)
print(json.dumps({'schema':'hepta-inherited-pipe-drain-fixture/v1','state':state,
                  'workload_popen_count':len(spawned),'workload_pid':None if not spawned else spawned[0].pid,
                  'signals':signals,'waits':waits,'adopted':adopted,'cleanup':cleanup,
                  'originals':originals,'receipt':receipt,'witness':witness,
                  'final_status':None if receipt is None else status_scope['final_status'](receipt)},sort_keys=True))
"#;

fn inherited_pipe_fault(
	cancel_overlap: bool,
	ignore_term: bool,
	staggered: bool,
	read_fault: bool,
) -> Value {
	use std::process::{Command, Stdio};
	use std::time::{Duration, Instant};
	let root = tempfile::Builder::new()
		.prefix("hepta-inherited-pipe-fault-")
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap()
		.keep();
	let state = root.join("state");
	let jobs = state.join("jobs");
	let job = jobs.join("inherited-pipe-durability");
	std::fs::create_dir_all(&job).unwrap();
	for directory in [&state, &jobs, &job] {
		std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
	}
	let status_function = STATUS_CODE
		.split_once("def final_status(exit_data):")
		.unwrap()
		.1
		.split_once("\ndef one_status():")
		.unwrap()
		.0;
	let input = root.join("input.json");
	let stdout = root.join("fixture.stdout");
	let stderr = root.join("fixture.stderr");
	std::fs::write(
		&input,
		serde_json::to_vec(
			&json!({"job":job,"runner":runner_source(),"cancel_overlap":cancel_overlap,
			"ignore_term":ignore_term,"staggered":staggered,"read_fault":read_fault,
			"status_function":format!("def final_status(exit_data):{status_function}")}),
		)
		.unwrap(),
	)
	.unwrap();
	let mut child = Command::new("python3")
		.args(["-I", "-S", "-c", INHERITED_PIPE_FIXTURE])
		.stdin(Stdio::from(std::fs::File::open(&input).unwrap()))
		.stdout(Stdio::from(std::fs::File::create(&stdout).unwrap()))
		.stderr(Stdio::from(std::fs::File::create(&stderr).unwrap()))
		.spawn()
		.unwrap();
	let deadline = Instant::now() + Duration::from_secs(45);
	let status = loop {
		match child.try_wait() {
			Ok(Some(status)) => break status,
			Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
			outcome => {
				let killed = child.kill();
				let waited = child.wait();
				panic!(
					"inherited-pipe fixture failed: {outcome:?}; kill={killed:?}; wait={waited:?}; retained={root:?}"
				);
			}
		}
	};
	assert!(
		status.success(),
		"inherited-pipe fixture failed; retained={root:?}; stderr={}",
		std::fs::read_to_string(&stderr).unwrap_or_default()
	);
	serde_json::from_slice(&std::fs::read(stdout).unwrap()).unwrap()
}

#[test]
fn inherited_pipe_timeout_keeps_original_group_identity_and_unknown_effect() {
	for (cancel_overlap, ignore_term) in [(false, true), (true, true), (true, false)] {
		let result = inherited_pipe_fault(cancel_overlap, ignore_term, false, false);
		assert_eq!(result["workload_popen_count"], 1);
		assert_eq!(result["state"]["runner_exit"], 125);
		assert!(result["state"]["runner_exception"].is_null());
		assert_eq!(result["state"]["normal_drain_window_present"], true);
		assert!(result["state"]["cancellation_deadline"].is_null());
		assert_eq!(
			result["state"]["cancel_delivered_during_drain"],
			cancel_overlap
		);
		assert_eq!(
			result["state"]["readers_alive_at_runner_return"],
			json!([false, false])
		);
		assert_eq!(
			result["cleanup"],
			json!([]),
			"fixture rescue must not supply product cleanup"
		);
		let waits = result["waits"].as_array().unwrap();
		assert_eq!(waits.len(), 1);
		assert_eq!(waits[0]["phase"], "runner");
		assert_eq!(waits[0]["returned"], true);
		assert_eq!(waits[0]["returncode"], 0);
		let signals = result["signals"].as_array().unwrap();
		assert_eq!(
			signals.len(),
			if cancel_overlap && ignore_term { 2 } else { 1 }
		);
		for event in signals {
			assert_eq!(event["phase"], "runner");
			assert_eq!(event["group"], result["workload_pid"]);
			assert_eq!(event["original_child_unreaped"], true);
			assert_eq!(event["original_leader_exited"], true);
			assert_eq!(event["leader_exit_code"], 0);
			assert_eq!(event["returned"], true);
		}
		let final_signal = if cancel_overlap && !ignore_term {
			15
		} else {
			9
		};
		assert_eq!(signals.last().unwrap()["signal"], final_signal);
		let adopted = result["adopted"].as_array().unwrap();
		assert_eq!(adopted.len(), 1);
		assert_eq!(adopted[0]["returncode"], -final_signal);
		assert_eq!(
			adopted[0]["pid"].as_u64().unwrap(),
			result["originals"]["descendant"]["utf8"]
				.as_str()
				.unwrap()
				.parse::<u64>()
				.unwrap()
		);
		assert_eq!(
			result["originals"]["effect"]["utf8"],
			"original leader executed once\n"
		);
		let receipt = &result["receipt"];
		assert_eq!(receipt["exit_code"], 125);
		assert_eq!(receipt["child_exit_code"], 0);
		assert_eq!(receipt["child_reaped"], true);
		assert_eq!(receipt["child_group_signal"], "submitted");
		assert_eq!(receipt["child_group_signal_number"], final_signal);
		assert_eq!(
			receipt["supervisor_error"],
			if cancel_overlap {
				"output drain cancelled after leader exit"
			} else {
				"output drain deadline exceeded after leader exit"
			}
		);
		assert_eq!(receipt["supervisor_cleanup_errors"], json!([]));
		assert_eq!(receipt["effect_outcome"], "unknown");
		assert_eq!(receipt["automatic_retry"], false);
		assert_eq!(receipt["status_authoritative"], false);
		assert_eq!(receipt["output_complete"], false);
		assert_eq!(receipt["output_durable"], false);
		assert_eq!(receipt["cancelled"], cancel_overlap);
		assert_eq!(receipt["timed_out"], false);
		assert_eq!(result["final_status"]["state"], "effect_unknown");
		assert_eq!(result["witness"]["job_id"], receipt["job_id"]);
		assert_eq!(result["witness"]["launch_nonce"], receipt["launch_nonce"]);
		assert_eq!(
			result["witness"]["exit_sha256"],
			result["originals"]["exit.json"]["sha256"]
		);
	}
}

#[test]
fn staggered_output_eof_preserves_each_original_reader_budget() {
	let result = inherited_pipe_fault(false, true, true, false);
	assert_eq!(result["workload_popen_count"], 1);
	assert_eq!(result["state"]["runner_exit"], 0);
	assert!(result["state"]["runner_exception"].is_null());
	assert_eq!(
		result["signals"],
		json!([]),
		"natural staggered output must not be interrupted"
	);
	assert_eq!(
		result["cleanup"],
		json!([]),
		"fixture rescue must not complete the product path"
	);
	assert_eq!(
		result["state"]["readers_alive_at_runner_return"],
		json!([false, false])
	);
	assert_eq!(result["state"]["cancel_delivered_during_drain"], false);
	let waits = result["waits"].as_array().unwrap();
	assert_eq!(waits.len(), 1);
	assert_eq!(waits[0]["phase"], "runner");
	assert_eq!(waits[0]["returned"], true);
	assert_eq!(waits[0]["returncode"], 0);
	let adopted = result["adopted"].as_array().unwrap();
	assert_eq!(adopted.len(), 1);
	assert_eq!(adopted[0]["returncode"], 0);
	assert_eq!(
		adopted[0]["pid"].as_u64().unwrap(),
		result["originals"]["descendant"]["utf8"]
			.as_str()
			.unwrap()
			.parse::<u64>()
			.unwrap()
	);
	assert_eq!(
		result["originals"]["effect"]["utf8"],
		"original leader executed once\n"
	);
	assert_eq!(
		result["originals"]["stdout.log"]["utf8"],
		"original staggered stdout\n"
	);
	assert_eq!(
		result["originals"]["stderr.log"]["utf8"],
		"original staggered stderr\n"
	);
	let receipt = &result["receipt"];
	assert_eq!(receipt["exit_code"], 0);
	assert_eq!(receipt["output_complete"], true);
	assert_eq!(receipt["output_durable"], true);
	assert_eq!(receipt["log_errors"], json!({"stdout":null,"stderr":null}));
	assert_eq!(receipt["log_synced"], json!({"stdout":true,"stderr":true}));
	assert_eq!(
		receipt["log_truncated"],
		json!({"stdout":false,"stderr":false})
	);
	assert_eq!(receipt["cancelled"], false);
	assert_eq!(receipt["timed_out"], false);
	assert_eq!(result["final_status"]["state"], "succeeded");
	assert!(receipt.get("effect_outcome").is_none());
	assert!(receipt.get("child_group_signal").is_none());
	assert_eq!(result["witness"]["job_id"], receipt["job_id"]);
	assert_eq!(result["witness"]["launch_nonce"], receipt["launch_nonce"]);
	assert_eq!(
		result["witness"]["exit_sha256"],
		result["originals"]["exit.json"]["sha256"]
	);
}

#[test]
fn inherited_pipe_read_failures_kill_original_group_before_reap() {
	let result = inherited_pipe_fault(false, true, false, true);
	assert_eq!(result["workload_popen_count"], 1);
	assert_eq!(result["state"]["runner_exit"], 125);
	assert!(result["state"]["runner_exception"].is_null());
	assert_eq!(result["state"]["normal_drain_window_present"], true);
	assert!(result["state"]["cancellation_deadline"].is_null());
	assert_eq!(result["state"]["cancel_delivered_during_drain"], false);
	assert_eq!(
		result["state"]["read_fault_calls"],
		json!({"stdout":1,"stderr":1})
	);
	assert_eq!(
		result["state"]["log_eof_at_runner_return"],
		json!({"stdout":false,"stderr":false})
	);
	assert_eq!(
		result["state"]["readers_alive_at_runner_return"],
		json!([false, false])
	);
	assert_eq!(
		result["cleanup"],
		json!([]),
		"fixture rescue must not supply product cleanup after read failure"
	);
	let signals = result["signals"].as_array().unwrap();
	assert_eq!(signals.len(), 1);
	let signal = &signals[0];
	assert_eq!(signal["phase"], "runner");
	assert_eq!(signal["group"], result["workload_pid"]);
	assert_eq!(signal["signal"], 9);
	assert_eq!(signal["original_child_unreaped"], true);
	assert_eq!(signal["original_leader_exited"], true);
	assert_eq!(signal["leader_exit_code"], 0);
	assert_eq!(signal["returned"], true);
	let waits = result["waits"].as_array().unwrap();
	assert_eq!(waits.len(), 1);
	assert_eq!(waits[0]["phase"], "runner");
	assert_eq!(waits[0]["returned"], true);
	assert_eq!(waits[0]["returncode"], 0);
	let adopted = result["adopted"].as_array().unwrap();
	assert_eq!(adopted.len(), 1);
	assert_eq!(adopted[0]["returncode"], -9);
	assert_eq!(
		adopted[0]["pid"].as_u64().unwrap(),
		result["originals"]["descendant"]["utf8"]
			.as_str()
			.unwrap()
			.parse::<u64>()
			.unwrap()
	);
	assert_eq!(
		result["originals"]["effect"]["utf8"],
		"original leader executed once\n"
	);
	assert_eq!(result["originals"]["stdout.log"]["utf8"], "");
	assert_eq!(result["originals"]["stderr.log"]["utf8"], "");
	let receipt = &result["receipt"];
	assert_eq!(receipt["exit_code"], 125);
	assert_eq!(receipt["child_pid"], result["workload_pid"]);
	assert_eq!(receipt["child_exit_code"], 0);
	assert_eq!(receipt["child_spawned"], true);
	assert_eq!(receipt["child_reaped"], true);
	assert_eq!(receipt["child_group_signal"], "submitted");
	assert_eq!(receipt["child_group_signal_number"], 9);
	assert_eq!(
		receipt["supervisor_error"],
		"output drain deadline exceeded after leader exit"
	);
	assert_eq!(receipt["supervisor_cleanup_errors"], json!([]));
	assert_eq!(receipt["effect_outcome"], "unknown");
	assert_eq!(receipt["automatic_retry"], false);
	assert_eq!(receipt["status_authoritative"], false);
	assert_eq!(receipt["output_complete"], false);
	assert_eq!(receipt["output_durable"], false);
	assert_eq!(receipt["cancelled"], false);
	assert_eq!(receipt["timed_out"], false);
	assert_eq!(
		receipt["log_errors"],
		json!({
			"stdout":"read: injected stdout read1 failure",
			"stderr":"read: injected stderr read1 failure"
		})
	);
	assert_eq!(receipt["log_synced"], json!({"stdout":true,"stderr":true}));
	assert_eq!(
		receipt["log_truncated"],
		json!({"stdout":false,"stderr":false})
	);
	assert_eq!(
		receipt["log_bytes"],
		json!({"stdout":{"seen":0,"stored":0},"stderr":{"seen":0,"stored":0}})
	);
	assert_eq!(result["final_status"]["state"], "effect_unknown");
	assert_eq!(result["witness"]["job_id"], receipt["job_id"]);
	assert_eq!(result["witness"]["launch_nonce"], receipt["launch_nonce"]);
	assert_eq!(
		result["witness"]["exit_sha256"],
		result["originals"]["exit.json"]["sha256"]
	);
}
