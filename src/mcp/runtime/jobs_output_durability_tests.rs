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
