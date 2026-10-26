// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Original owner-file failures must stop before the shared barrier and workload boundary.
use super::*;

const OWNER_FIXTURE: &str = r#"
import fcntl,hashlib,io,json,os,pathlib,signal,stat,subprocess,sys
q=json.load(sys.stdin)
job=pathlib.Path(q['job'])
original_cwd=os.getcwd()
os.umask(0o077)
names=('owner-intent.json','started.json')
if q.get('reuse'):
    req=json.loads((job/'request.json').read_text())
else:
    req={'job_id':'owner-publication','job_dir':str(job),'launch_nonce':'a'*32,
         'request_fingerprint':'owner-publication-original','executable':'/hepta-test-business-boundary',
         'args':[],'execution_mode':'operator','timeout_seconds':10,'env':{}}
    with open(job/'request.json','x',encoding='utf-8') as stream:
        json.dump(req,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
    if q.get('preexisting'):
        name,data=q['preexisting']
        with open(job/name,'x',encoding='utf-8') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
    fd=os.open(job,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
info=job.stat()
job_identity=(info.st_dev,info.st_ino)
binding={'device':info.st_dev,'inode':info.st_ino,'job_id':req['job_id'],
         'launch_nonce':req['launch_nonce'],'request_fingerprint':req['request_fingerprint']}
request_before=hashlib.sha256((job/'request.json').read_bytes()).hexdigest()
real_open,real_close,real_fdopen,real_sync=os.open,os.close,os.fdopen,os.fsync
real_popen,real_run=subprocess.Popen,subprocess.run
events,helpers,business,backend_calls,cleanup_errors=[],[],[],[],[]
owner_fds={}
state={'phase':'runner','injected':False,'cut_reached':False}
fault=q.get('fault')
held_lock=None
if q.get('hold_owner_lock'):
    held_lock=real_open(job/'owner.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    fcntl.flock(held_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)

class BusinessBoundary(BaseException):pass
class PublicationCut(BaseException):pass

def event(name,operation):
    value={'phase':state['phase'],'name':name,'operation':operation,'returned':False}
    events.append(value)
    return value

def failing(name,operation):
    if state['phase']=='runner' and not state['injected'] and fault==[name,operation]:
        state['injected']=True
        return True
    return False

def cut(label):
    if state['phase']=='runner' and not state['cut_reached'] and q.get('cut')==label:
        state['cut_reached']=True
        raise PublicationCut(label)

def opened(path,flags,*args,**kwargs):
    name=pathlib.Path(path).name
    owner=name in names and flags & os.O_CREAT and flags & os.O_EXCL
    row=event(name,'create') if owner else None
    if owner and failing(name,'create'):
        raise OSError('injected owner create failure')
    fd=real_open(path,flags,*args,**kwargs)
    owner_fds.pop(fd,None)
    if owner:
        owner_fds[fd]=name
        row['returned']=True
    return fd

class OwnerStream:
    def __init__(self,stream,name):self.stream,self.name=stream,name
    def __getattr__(self,name):return getattr(self.stream,name)
    def __enter__(self):return self
    def __exit__(self,*_):self.close();return False
    def write(self,data):
        row=event(self.name,'write')
        if failing(self.name,'write'):
            raise OSError('injected empty owner write failure')
        if failing(self.name,'partial_write'):
            self.stream.write(data[:max(1,min(len(data),2))])
            self.stream.flush()
            raise OSError('injected partial owner write failure')
        result=self.stream.write(data)
        row['returned']=True
        return result
    def flush(self):
        row=event(self.name,'flush')
        if failing(self.name,'flush'):
            raise OSError('injected owner flush failure')
        result=self.stream.flush()
        row['returned']=True
        return result
    def close(self):
        fd=self.stream.fileno()
        row=event(self.name,'close')
        try:
            self.stream.close()
        finally:
            owner_fds.pop(fd,None)
        if failing(self.name,'close'):
            raise OSError('injected owner close failure after descriptor release')
        row['returned']=True
        cut('after_'+self.name+'_close')

def fdopened(fd,*args,**kwargs):
    stream=real_fdopen(fd,*args,**kwargs)
    return OwnerStream(stream,owner_fds[fd]) if fd in owner_fds else stream

def synced(fd):
    info=os.fstat(fd)
    directory=stat.S_ISDIR(info.st_mode) and (info.st_dev,info.st_ino)==job_identity
    name='job-directory' if directory else owner_fds.get(fd)
    if name is None:
        return real_sync(fd)
    row=event(name,'fsync')
    if failing(name,'fsync'):
        raise OSError('injected owner publication synchronization failure')
    result=real_sync(fd)
    row['returned']=True
    if directory:
        cut('after_job_directory_fsync')
    return result

def identity_probe(argv):
    return argv==['ps','-p',str(os.getpid()),'-o','lstart=']

def popen(argv,*args,**kwargs):
    if identity_probe(argv):
        helpers.append({'phase':state['phase'],'argv':argv,'kind':'read_only_supervisor_identity'})
        return real_popen(argv,*args,**kwargs)
    if state['phase']=='runner' and argv==[req['executable'],*req['args']]:
        business.append({'argv':argv,'actual_spawned':False})
        row=event('workload','popen_boundary')
        row['returned']=True
        raise BusinessBoundary('original workload Popen reached; fixture does not execute it')
    backend_calls.append({'phase':state['phase'],'argv':argv})
    raise AssertionError('unexpected launcher or workload process boundary')

def run(argv,*args,**kwargs):
    if identity_probe(argv):
        return real_run(argv,*args,**kwargs)
    backend_calls.append({'phase':state['phase'],'argv':argv})
    raise AssertionError('same-key reconciliation must not launch a backend')

def cleanup(scope):
    for name in ('out','err','stdin_handle','launch_lock'):
        value=scope.get(name)
        if hasattr(value,'close'):
            try:value.close()
            except Exception as error:cleanup_errors.append(name+': '+str(error))
    if isinstance(scope.get('owner_fd'),int):
        try:real_close(scope['owner_fd'])
        except OSError as error:cleanup_errors.append('owner_fd: '+str(error))
    os.chdir(original_cwd)
    for fd in set(scope.get('_hepta_directory_pins',[])):
        try:real_close(fd)
        except OSError as error:cleanup_errors.append('directory pin: '+str(error))

def attempt(source,phase):
    state['phase']=phase
    scope={'__name__':'__main__'}
    old_argv,old_stdin,old_stdout=sys.argv,sys.stdin,sys.stdout
    old_signals={number:signal.getsignal(number) for number in (signal.SIGTERM,signal.SIGINT)}
    sys.argv=['-c',str(job),json.dumps(binding),'detached']
    sys.stdin=io.StringIO(json.dumps(req))
    sys.stdout=io.StringIO()
    answer={'error':None,'message':None}
    try:
        exec(source,scope)
    except BaseException as error:
        answer={'error':type(error).__name__,'message':str(error)}
    finally:
        sys.argv,sys.stdin,sys.stdout=old_argv,old_stdin,old_stdout
        for number,handler in old_signals.items():signal.signal(number,handler)
        cleanup(scope)
    return answer

os.open,os.fdopen,os.fsync=opened,fdopened,synced
subprocess.Popen,subprocess.run=popen,run
try:
    result=attempt(q['runner'],'runner')
    first_events=list(events)
    first_business=list(business)
    same_key=attempt(q['launcher'],'same_key_launcher')
finally:
    os.open,os.fdopen,os.fsync=real_open,real_fdopen,real_sync
    subprocess.Popen,subprocess.run=real_popen,real_run
    if held_lock is not None:real_close(held_lock)
files={name:(job/name).read_text() for name in names if os.path.lexists(job/name)}
print(json.dumps({'schema':'hepta-owner-publication-fixture/v1','platform':sys.platform,
    'fixture_pid':os.getpid(),'result':result,'same_key':same_key,'state':state,
    'events':first_events,'business_calls':first_business,'identity_helpers':helpers,
    'backend_calls':backend_calls,'actual_workload_spawns':0,'owner_files':files,
    'cleanup_errors':cleanup_errors,'request_unchanged':request_before==hashlib.sha256((job/'request.json').read_bytes()).hexdigest(),
    'runner_sha256':hashlib.sha256(q['runner'].encode()).hexdigest()}))
"#;

fn owner_publication_case(
	fault: Option<(&str, &str)>,
	cut: Option<&str>,
	preexisting: Option<(&str, &str)>,
	hold_owner_lock: bool,
) -> Value {
	let temporary = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	let state = temporary.path().join("state");
	let job = state.join("jobs/owner-publication");
	std::fs::create_dir_all(&job).unwrap();
	for directory in [&state, &state.join("jobs"), &job] {
		std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
	}
	let mut payload = json!({"job":job,"runner":runner_source(),
		"launcher":private_remote_code(START_CODE).unwrap(),"fault":fault,
		"cut":cut,"preexisting":preexisting,"hold_owner_lock":hold_owner_lock,"reuse":false});
	let first = python(OWNER_FIXTURE, &payload);
	// A fresh interpreter/process, with no copied runner globals or held locks,
	// retries only an actually surviving owner-file tombstone. A create failure
	// before any owner name exists is covered by the real same-key launcher.
	let second = if first["owner_files"].as_object().unwrap().is_empty() {
		Value::Null
	} else {
		payload["reuse"] = json!(true);
		payload["fault"] = Value::Null;
		payload["cut"] = Value::Null;
		payload["preexisting"] = Value::Null;
		payload["hold_owner_lock"] = json!(false);
		python(OWNER_FIXTURE, &payload)
	};
	json!({"first":first,"second":second})
}

fn assert_no_resubmission(result: &Value) {
	let first = &result["first"];
	assert_eq!(first["request_unchanged"], true);
	assert_eq!(first["backend_calls"], json!([]));
	assert_eq!(first["actual_workload_spawns"], 0);
	assert_eq!(first["cleanup_errors"], json!([]));
	assert!(!first["same_key"]["error"].is_null());
	if !result["second"].is_null() {
		let second = &result["second"];
		assert_eq!(second["result"]["error"], "SystemExit");
		assert!(second["result"]["message"]
			.as_str()
			.unwrap()
			.contains("workload must not be replayed"));
		assert_eq!(second["business_calls"], json!([]));
		assert_eq!(second["identity_helpers"], json!([]));
		assert_eq!(second["backend_calls"], json!([]));
		assert_eq!(second["actual_workload_spawns"], 0);
		assert_eq!(second["cleanup_errors"], json!([]));
		assert_eq!(second["owner_files"], first["owner_files"]);
		assert_eq!(second["request_unchanged"], true);
		assert_eq!(second["runner_sha256"], first["runner_sha256"]);
	}
}

#[test]
fn both_owner_files_are_synced_and_closed_before_one_directory_barrier_and_workload() {
	let result = owner_publication_case(None, None, None, false);
	assert_no_resubmission(&result);
	let first = &result["first"];
	assert_eq!(first["result"]["error"], "BusinessBoundary");
	assert_eq!(first["business_calls"].as_array().unwrap().len(), 1);
	// These Rust tests run on Linux. Native Mac uses the same fixture, where
	// the real readonly ps identity helper is recorded separately from work.
	assert_eq!(first["identity_helpers"], json!([]));
	let events = first["events"].as_array().unwrap();
	let position = |name: &str, operation: &str| {
		events
			.iter()
			.position(|event| event["name"] == name && event["operation"] == operation)
			.unwrap()
	};
	let barrier = position("job-directory", "fsync");
	let workload = position("workload", "popen_boundary");
	assert!(barrier < workload);
	assert_eq!(
		events
			.iter()
			.filter(|event| event["name"] == "job-directory" && event["operation"] == "fsync")
			.count(),
		1
	);
	let mut previous_close = None;
	for name in ["owner-intent.json", "started.json"] {
		let create = position(name, "create");
		let write = position(name, "write");
		let flush = position(name, "flush");
		let sync = position(name, "fsync");
		let close = position(name, "close");
		assert!(create < write && write < flush && flush < sync && sync < close && close < barrier);
		if let Some(previous) = previous_close {
			assert!(previous < create);
		}
		previous_close = Some(close);
		for operation in ["fsync", "close"] {
			assert_eq!(
				events
					.iter()
					.filter(|event| event["name"] == name && event["operation"] == operation)
					.count(),
				1
			);
		}
		let value: Value =
			serde_json::from_str(first["owner_files"][name].as_str().unwrap()).unwrap();
		assert_eq!(value["job_id"], "owner-publication");
		assert_eq!(value["launch_nonce"], "a".repeat(32));
		assert_eq!(value["supervisor_pid"], first["fixture_pid"]);
	}
	assert!(events.iter().all(|event| event["returned"] == true));
}

#[test]
fn every_owner_write_flush_file_sync_and_close_error_stops_before_the_shared_barrier() {
	for name in ["owner-intent.json", "started.json"] {
		for operation in ["write", "partial_write", "flush", "fsync", "close"] {
			let result = owner_publication_case(Some((name, operation)), None, None, false);
			assert_no_resubmission(&result);
			let first = &result["first"];
			assert_eq!(first["state"]["injected"], true);
			assert_eq!(first["result"]["error"], "OSError");
			assert_eq!(first["business_calls"], json!([]));
			assert!(first["owner_files"].get(name).is_some());
			assert!(!first["events"]
				.as_array()
				.unwrap()
				.iter()
				.any(|event| event["name"] == "job-directory"));
			if operation == "write" {
				assert_eq!(first["owner_files"][name], "");
			} else if operation == "partial_write" {
				let bytes = first["owner_files"][name].as_str().unwrap();
				assert!(!bytes.is_empty());
				assert!(serde_json::from_str::<Value>(bytes).is_err());
			}
		}
	}
}

#[test]
fn owner_create_errors_never_submit_work_and_an_existing_request_blocks_same_key_launch() {
	for name in ["owner-intent.json", "started.json"] {
		let result = owner_publication_case(Some((name, "create")), None, None, false);
		assert_no_resubmission(&result);
		let first = &result["first"];
		assert_eq!(first["state"]["injected"], true);
		assert_eq!(first["result"]["error"], "OSError");
		assert_eq!(first["business_calls"], json!([]));
		assert!(first["owner_files"].get(name).is_none());
		assert!(first["same_key"]["message"]
			.as_str()
			.unwrap()
			.contains("ambiguous prior launch"));
		if name == "owner-intent.json" {
			assert!(first["owner_files"].as_object().unwrap().is_empty());
			assert!(result["second"].is_null());
		} else {
			assert!(first["owner_files"].get("owner-intent.json").is_some());
		}
	}
}

#[test]
fn shared_owner_directory_sync_failure_preserves_both_tombstones_without_work() {
	let result = owner_publication_case(Some(("job-directory", "fsync")), None, None, false);
	assert_no_resubmission(&result);
	let first = &result["first"];
	assert_eq!(first["state"]["injected"], true);
	assert_eq!(first["result"]["error"], "OSError");
	assert_eq!(first["business_calls"], json!([]));
	assert_eq!(first["owner_files"].as_object().unwrap().len(), 2);
	let events = first["events"].as_array().unwrap();
	let barriers: Vec<_> = events
		.iter()
		.filter(|event| event["name"] == "job-directory")
		.collect();
	assert_eq!(barriers.len(), 1);
	assert_eq!(barriers[0]["returned"], false);
	for name in ["owner-intent.json", "started.json"] {
		for operation in ["fsync", "close"] {
			assert!(events.iter().any(|event| {
				event["name"] == name
					&& event["operation"] == operation
					&& event["returned"] == true
			}));
		}
	}
}

#[test]
fn interrupted_owner_publication_is_not_replayed_by_a_fresh_interpreter() {
	for cut in [
		"after_owner-intent.json_close",
		"after_started.json_close",
		"after_job_directory_fsync",
	] {
		let result = owner_publication_case(None, Some(cut), None, false);
		assert_no_resubmission(&result);
		let first = &result["first"];
		assert_eq!(first["state"]["cut_reached"], true);
		assert_eq!(first["result"]["error"], "PublicationCut");
		assert_eq!(first["business_calls"], json!([]));
		assert!(!result["second"].is_null());
		let barriers = first["events"]
			.as_array()
			.unwrap()
			.iter()
			.filter(|event| event["name"] == "job-directory" && event["returned"] == true)
			.count();
		assert_eq!(barriers, usize::from(cut == "after_job_directory_fsync"));
	}
}

#[test]
fn either_surviving_empty_or_partial_owner_name_blocks_a_new_owner() {
	for name in ["owner-intent.json", "started.json"] {
		for bytes in ["", "{"] {
			let result = owner_publication_case(None, None, Some((name, bytes)), false);
			assert_no_resubmission(&result);
			let first = &result["first"];
			assert_eq!(first["result"]["error"], "SystemExit");
			assert!(first["result"]["message"]
				.as_str()
				.unwrap()
				.contains("workload must not be replayed"));
			assert_eq!(first["events"], json!([]));
			assert_eq!(first["business_calls"], json!([]));
			assert_eq!(first["identity_helpers"], json!([]));
			assert_eq!(first["owner_files"][name], bytes);
		}
	}
}

#[test]
fn an_existing_owner_lock_blocks_publication_before_any_owner_file_is_created() {
	let result = owner_publication_case(None, None, None, true);
	assert_no_resubmission(&result);
	let first = &result["first"];
	assert_eq!(first["result"]["error"], "BlockingIOError");
	assert_eq!(first["events"], json!([]));
	assert_eq!(first["business_calls"], json!([]));
	assert_eq!(first["identity_helpers"], json!([]));
	assert!(first["owner_files"].as_object().unwrap().is_empty());
	assert!(result["second"].is_null());
}
