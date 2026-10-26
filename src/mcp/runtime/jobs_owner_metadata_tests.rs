// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Torn private owner records remain observable without permitting replay.
use super::*;
use std::os::unix::fs::PermissionsExt;

const FIXTURE: &str = r#"
import hashlib,io,json,os,pathlib,stat,subprocess,sys,types
q=json.load(sys.stdin)
job=pathlib.Path(q['job'])
os.umask(0o077)
request={'job_id':'owner-metadata','job_dir':str(job),'unit':'unused-owner-metadata',
         'launch_nonce':'a'*32,'request_fingerprint':'original-owner-metadata',
         'terminal_publication_protocol':1,'execution_mode':'operator',
         'executable':'/must-not-execute-owner-metadata','args':[],'env':{}}
def raw(value):return (json.dumps(value,sort_keys=True)+'\n').encode()
def write(name,data,mode=0o600):
    fd=os.open(job/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    os.chmod(job/name,mode)
if q.get('legacy'):request.pop('terminal_publication_protocol')
write('request.json',raw(request))
payloads={'empty':b'','partial':b'{"job_id":','array':b'[]','scalar':b'17',
          'null':b'null','invalid_utf8':b'\xff','too_large':b' '*(16384+1)}
kind=q['kind'];target=q.get('target','started.json')
if kind in payloads:
    write(target,payloads[kind])
elif kind=='bad_mode':
    write(target,b'{',0o644)
elif kind=='symlink':
    write('untrusted-target',b'{')
    (job/target).symlink_to('untrusted-target')
elif kind=='hardlink':
    write('untrusted-target',b'{')
    os.link(job/'untrusted-target',job/target)
elif kind=='fifo':
    os.mkfifo(job/target,0o600)
elif kind=='vanished_after_open':
    write(target,b'{')
elif kind.startswith('identity_'):
    owner={'job_id':request['job_id'],'launch_nonce':request['launch_nonce'],
           'supervisor_pid':2,'supervisor_uid':os.geteuid(),
           'supervisor_identity':{'kind':'proc_start_ticks','value':'unobserved-fixture'}}
    if kind=='identity_job':owner['job_id']='other-owner'
    elif kind=='identity_nonce':owner['launch_nonce']='b'*32
    elif kind=='identity_pid':owner['supervisor_pid']='not-a-pid'
    elif kind=='identity_uid':owner['supervisor_uid']=os.geteuid()+1
    write(target,raw(owner))
elif kind!='missing':
    raise AssertionError('unknown fixture')
if q.get('terminal'):
    terminal={'exit_code':0,'output_complete':True,'output_durable':True}
    if not q.get('legacy'):
        terminal.update(terminal_publication_protocol=1,job_id=request['job_id'],
                        launch_nonce=request['launch_nonce'])
    encoded=raw(terminal)
    write('exit.json',encoded)
    if not q.get('legacy'):
        write('exit.witness.json',raw({'terminal_publication_protocol':1,
            'job_id':request['job_id'],'launch_nonce':request['launch_nonce'],
            'exit_sha256':hashlib.sha256(encoded).hexdigest()}))
if q.get('systemd'):
    write('launch.json',raw({'backend':'systemd'}))

def snapshot():
    rows={}
    for path in job.iterdir():
        info=path.lstat()
        body=('link',os.readlink(path)) if stat.S_ISLNK(info.st_mode) else (
             ('file',hashlib.sha256(path.read_bytes()).hexdigest()) if stat.S_ISREG(info.st_mode)
             else ('special',None))
        rows[path.name]={'content':body,'dev':info.st_dev,'ino':info.st_ino,
            'mode':info.st_mode,'uid':info.st_uid,'nlink':info.st_nlink,'size':info.st_size,
            'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns}
    return rows

backend_calls=[]
status_observations=[]
def forbidden(*args,**kwargs):
    backend_calls.append(str(args[0]) if args else 'unknown')
    raise AssertionError('no business or backend launch is allowed')
def status_systemctl(argv,*args,**kwargs):
    assert argv[:3]==['systemctl','--user','show']
    status_observations.append(argv)
    return types.SimpleNamespace(stdout='LoadState=not-found\nActiveState=inactive\n')

def execute(source,payload,phase):
    original_cwd=os.getcwd()
    old_in,old_out=sys.stdin,sys.stdout
    old_popen,old_run=subprocess.Popen,subprocess.run
    old_stat=os.stat
    capture=io.StringIO();scope={'__name__':'__main__'}
    answer={'error':None,'message':None,'value':None}
    try:
        sys.stdin=io.StringIO(json.dumps(payload));sys.stdout=capture
        subprocess.Popen=forbidden
        subprocess.run=status_systemctl if phase=='status' else forbidden
        if phase=='status' and kind=='vanished_after_open':
            def vanish(name,*args,**kwargs):
                if name=='started.json' and 'dir_fd' in kwargs:
                    os.unlink(name,dir_fd=kwargs['dir_fd'])
                return old_stat(name,*args,**kwargs)
            os.stat=vanish
        exec(source,scope)
    except SystemExit as error:
        if error.code not in (None,0):
            answer.update(error=type(error).__name__,message=str(error))
    except BaseException as error:
        answer.update(error=type(error).__name__,message=str(error))
    finally:
        subprocess.Popen,subprocess.run=old_popen,old_run
        os.stat=old_stat
        sys.stdin,sys.stdout=old_in,old_out
        for name in ('launch_lock',):
            stream=scope.get(name)
            if hasattr(stream,'close'):stream.close()
        os.chdir(original_cwd)
        for fd in set(scope.get('_hepta_directory_pins',[])):
            os.close(fd)
    if capture.getvalue():answer['value']=json.loads(capture.getvalue())
    return answer

before=snapshot()
status_result=execute(q['status'],{'job_id':request['job_id'],'job_dir':str(job),
                      'unit':request['unit'],'wait_seconds':0},'status')
after_status=snapshot()
restart=execute(q['start'],request,'restart')
after_restart=snapshot()
print(json.dumps({'status':status_result,'restart':restart,'backend_calls':backend_calls,
    'status_observations':status_observations,'status_read_only':before==after_status,
    'original_files_unchanged':all(after_restart.get(k)==v for k,v in before.items()),
    'new_restart_names':sorted(set(after_restart)-set(before))}))
"#;

fn exercise(kind: &str, target: &str, terminal: bool, legacy: bool, systemd: bool) -> Value {
	use std::process::{Command, Stdio};
	let temporary = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	let state = temporary.path().join("state");
	let job = state.join("jobs/owner-metadata");
	std::fs::create_dir_all(&job).unwrap();
	for directory in [&state, &state.join("jobs"), &job] {
		std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
	}
	let payload = json!({"job":job,"kind":kind,"target":target,"terminal":terminal,
		"legacy":legacy,"systemd":systemd,"status":private_remote_code(STATUS_CODE).unwrap(),
		"start":private_remote_code(START_CODE).unwrap()});
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
		"{kind}: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	serde_json::from_slice(&output.stdout).unwrap()
}

fn no_replay(result: &Value) {
	assert_eq!(result["backend_calls"], json!([]));
	assert_eq!(result["status_read_only"], true);
	assert_eq!(result["original_files_unchanged"], true);
	assert_eq!(result["new_restart_names"], json!(["launch.lock"]));
}

fn assert_unknown(result: &Value) {
	assert!(result["status"]["error"].is_null(), "{result}");
	let status = &result["status"]["value"];
	assert_eq!(status["job_id"], "owner-metadata");
	assert_eq!(status["state"], "owner_unknown");
	assert_eq!(status["status_authoritative"], false);
	assert_eq!(status["automatic_retry"], false);
	assert!(status.get("exit_code").is_none());
	assert!(
		result["restart"]["error"].is_string()
			|| result["restart"]["value"]["reused_remote"] == true
	);
	no_replay(result);
}

#[test]
fn stable_torn_owner_metadata_is_unknown_without_replaying_the_request() {
	for target in ["owner-intent.json", "started.json"] {
		for kind in [
			"missing",
			"empty",
			"partial",
			"array",
			"scalar",
			"null",
			"invalid_utf8",
		] {
			assert_unknown(&exercise(kind, target, false, false, false));
		}
	}
}

#[test]
fn systemd_torn_owner_metadata_remains_unknown_without_trusting_unit_state() {
	let result = exercise("partial", "started.json", false, false, true);
	assert_unknown(&result);
	assert_eq!(result["status_observations"].as_array().unwrap().len(), 1);
}

#[test]
fn unsafe_owner_files_still_fail_closed_before_decoding_tombstones() {
	for kind in ["bad_mode", "symlink", "hardlink", "fifo", "too_large"] {
		let result = exercise(kind, "started.json", false, false, false);
		assert!(result["status"]["error"].is_string(), "{kind}: {result}");
		assert!(result["status"]["value"].is_null());
		no_replay(&result);
	}
}

#[test]
fn disappearing_owner_file_after_open_is_an_integrity_error() {
	let result = exercise("vanished_after_open", "started.json", false, false, false);
	assert_eq!(result["status"]["error"], "FileNotFoundError");
	assert!(result["status"]["value"].is_null());
	assert_eq!(result["backend_calls"], json!([]));
	assert!(result["restart"]["error"].is_string());
	assert_eq!(result["new_restart_names"], json!(["launch.lock"]));
}

#[test]
fn invalid_owner_identity_cannot_become_running_or_trigger_a_restart() {
	for kind in [
		"identity_job",
		"identity_nonce",
		"identity_pid",
		"identity_uid",
	] {
		assert_unknown(&exercise(kind, "started.json", false, false, false));
	}
}

#[test]
fn confirmed_original_terminal_receipt_precedes_torn_owner_metadata() {
	let result = exercise("partial", "started.json", true, false, false);
	assert!(result["status"]["error"].is_null());
	assert_eq!(result["status"]["value"]["state"], "succeeded");
	assert_eq!(
		result["status"]["value"]["terminal_publication_confirmed"],
		true
	);
	assert_eq!(result["status"]["value"]["automatic_retry"], false);
	assert_eq!(result["status"]["value"]["job_id"], "owner-metadata");
	no_replay(&result);
}

#[test]
fn unmarked_legacy_terminal_receipts_keep_their_existing_status() {
	let result = exercise("missing", "started.json", true, true, false);
	assert!(result["status"]["error"].is_null());
	assert_eq!(result["status"]["value"]["state"], "succeeded");
	assert!(result["status"]["value"]
		.get("terminal_publication_confirmed")
		.is_none());
	no_replay(&result);
}
