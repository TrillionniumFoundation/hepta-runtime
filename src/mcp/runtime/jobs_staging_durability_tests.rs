// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Execute real prelaunch staging with only the remote launch boundary replaced.
use super::*;
use std::os::unix::fs::PermissionsExt;

const FIXTURE: &str = r#"
import io,json,os,pathlib,shutil,stat,subprocess,sys,types
q=json.load(sys.stdin)
job=pathlib.Path(q['job'])
original_cwd=os.getcwd()
events=[]
last_file=[None]
active_fault=[q.get('fault')]
launches=[]
real_sync=os.fsync
def sync(fd):
    info=os.fstat(fd)
    name=pathlib.Path(os.readlink('/proc/self/fd/'+str(fd))).name
    directory=stat.S_ISDIR(info.st_mode)
    events.append({'kind':'sync','name':name,'directory':directory,'mode':stat.S_IMODE(info.st_mode)})
    label=('directory_after_'+last_file[0]) if directory and last_file[0] else name
    if not directory:
        last_file[0]=name
    if label==active_fault[0]:
        raise OSError('injected staging synchronization failure')
    return real_sync(fd)
def launched(backend,args):
    launches.append(backend)
    events.append({'kind':'launch','backend':backend})
def run(args,**kwargs):
    launched('systemd',args)
    return subprocess.CompletedProcess(args,0,'','')
def popen(args,**kwargs):
    launched('detached',args)
    return types.SimpleNamespace(pid=4242)
os.fsync=sync
subprocess.run=run
subprocess.Popen=popen
shutil.which=lambda _: '/fixture/systemd-run'
req={'job_id':'staging-durability','job_dir':str(job),'unit':'never-start-staging-fixture',
     'request_fingerprint':'unchanged-staging-binding','platform':q['platform'],
     'execution_mode':'operator','executable':'/never/execute-this-fixture',
     'args':[],'env':{},'allow_job_network':True,
     'allow_detached_fallback':q['platform']=='macos','stdin':'original input 中文\n'}
def attempt():
    scope={'__name__':'__main__'}
    saved_stdout=sys.stdout
    sys.stdin=io.StringIO(json.dumps(req))
    sys.stdout=io.StringIO()
    answer={'error':None,'message':None}
    try:
        exec(q['helper'],scope)
    except BaseException as error:
        answer={'error':type(error).__name__,'message':str(error)}
    finally:
        sys.stdout=saved_stdout
        lock=scope.get('launch_lock')
        if lock is not None:
            lock.close()
        os.chdir(original_cwd)
        for fd in set(scope.get('_hepta_directory_pins',[])):
            os.close(fd)
    return answer
first=attempt()
first_events=list(events)
first_launches=list(launches)
first_files=sorted(p.name for p in job.iterdir())
second=None
if q.get('fault'):
    active_fault[0]=None
    second=attempt()
out={'first':first,'first_events':first_events,'first_launches':first_launches,
     'first_files':first_files,'second':second,'launches':launches,
     'stdin':(job/'stdin.bin').read_text() if (job/'stdin.bin').exists() else None,
     'runner_present':(job/'runner.py').is_file()}
if (job/'request.json').is_file():
    stored=json.loads((job/'request.json').read_text())
    out['request_fingerprint']=stored['request_fingerprint']
    out['stdin_path']=stored.get('stdin_path')
print(json.dumps(out))
"#;

fn exercise(platform: &str, fault: Option<&str>) -> Value {
	use std::process::{Command, Stdio};
	let temporary = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	let state = temporary.path().join("state");
	let job = state.join("jobs/staging-durability");
	std::fs::create_dir_all(&job).unwrap();
	for directory in [&state, &state.join("jobs"), &job] {
		std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
	}
	let payload = json!({"job":job,"platform":platform,"fault":fault,
		"helper":private_remote_code(START_CODE).unwrap()});
	let mut child = Command::new("python3")
		.args(["-I", "-S", "-c", FIXTURE])
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
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
	serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn staging_syncs_original_input_and_runner_before_either_launch_backend() {
	for (platform, backend) in [("linux", "systemd"), ("macos", "detached")] {
		let result = exercise(platform, None);
		assert!(result["first"]["error"].is_null());
		assert_eq!(result["launches"], json!([backend]));
		assert_eq!(result["stdin"], "original input 中文\n");
		assert_eq!(result["request_fingerprint"], "unchanged-staging-binding");
		assert_eq!(result["runner_present"], true);
		let events = result["first_events"].as_array().unwrap();
		let position = |name: &str| events.iter().position(|v| v["name"] == name).unwrap();
		let launch = events.iter().position(|v| v["kind"] == "launch").unwrap();
		let input = position("stdin.bin");
		let request = position("request.json");
		let runner = position("runner.py");
		assert!(input < request && request < runner && runner < launch);
		assert_eq!(events[input]["mode"], 0o600);
		assert_eq!(events[runner]["mode"], 0o700);
		assert_eq!(events[input + 1]["directory"], true);
		assert_eq!(events[runner + 1]["directory"], true);
		assert!(runner + 1 < launch);
	}
}

#[test]
fn input_staging_sync_failure_never_publishes_a_request_or_replays_partial_input() {
	for fault in ["stdin.bin", "directory_after_stdin.bin"] {
		for platform in ["linux", "macos"] {
			let result = exercise(platform, Some(fault));
			assert_eq!(result["first"]["error"], "OSError");
			assert_eq!(result["first_launches"], json!([]));
			assert_eq!(result["launches"], json!([]));
			let files = result["first_files"].as_array().unwrap();
			assert!(files.iter().any(|v| v == "stdin.bin"));
			assert!(!files.iter().any(|v| v == "request.json"));
			assert!(!files.iter().any(|v| v == "runner.py"));
			assert_eq!(result["second"]["error"], "SystemExit");
			assert!(result["second"]["message"]
				.as_str()
				.unwrap()
				.contains("prior or uncertain job artifacts"));
		}
	}
}

#[test]
fn runner_staging_sync_failure_never_dispatches_and_retains_original_request() {
	for fault in ["runner.py", "directory_after_runner.py"] {
		for platform in ["linux", "macos"] {
			let result = exercise(platform, Some(fault));
			assert_eq!(result["first"]["error"], "OSError");
			assert_eq!(result["first_launches"], json!([]));
			assert_eq!(result["launches"], json!([]));
			assert_eq!(result["request_fingerprint"], "unchanged-staging-binding");
			assert_eq!(result["stdin"], "original input 中文\n");
			assert_eq!(result["second"]["error"], "SystemExit");
			assert!(result["second"]["message"]
				.as_str()
				.unwrap()
				.contains("ambiguous prior launch"));
		}
	}
}
