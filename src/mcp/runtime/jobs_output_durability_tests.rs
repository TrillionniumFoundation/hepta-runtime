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
