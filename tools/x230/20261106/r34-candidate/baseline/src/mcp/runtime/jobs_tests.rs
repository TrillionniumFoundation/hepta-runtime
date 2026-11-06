// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Regression tests for jobs.
use super::*;

#[test]
fn macos_detached_resource_bounds_reject_before_new_job_identity() {
	let mut params = ProcessStartParams {
		host: "mac".into(),
		executable: "/usr/bin/python3".into(),
		args: vec!["-c".into(), "print(42)".into()],
		cwd: None,
		env: BTreeMap::new(),
		stdin: None,
		timeout_seconds: Some(30),
		idempotency_key: Some("keep-original-identity".into()),
		nice: Some(5),
		cpu_quota_percent: None,
		memory_max_bytes: None,
	};
	assert!(validate_new_host_resource_limits(Platform::Macos, &params).is_ok());
	params.cpu_quota_percent = Some(25);
	let error = validate_new_host_resource_limits(Platform::Macos, &params)
		.unwrap_err()
		.to_string();
	assert!(error.contains("no new job identity"));
	assert!(error.contains("remote launch submitted"));
	assert!(validate_new_host_resource_limits(Platform::Linux, &params).is_ok());
	params.cpu_quota_percent = None;
	params.memory_max_bytes = Some(32 * 1024 * 1024);
	assert!(validate_new_host_resource_limits(Platform::Macos, &params).is_err());
	assert!(validate_new_host_resource_limits(Platform::Linux, &params).is_ok());
	params.cpu_quota_percent = Some(100);
	assert!(validate_new_host_resource_limits(Platform::Macos, &params).is_err());
	params.cpu_quota_percent = None;
	params.memory_max_bytes = None;
	assert!(validate_new_host_resource_limits(Platform::Macos, &params).is_ok());
	// Other user-provided params, including timeout/nice and exact key, are untouched.
	assert_eq!(
		params.idempotency_key.as_deref(),
		Some("keep-original-identity")
	);
	assert_eq!(params.nice, Some(5));
}

#[cfg(target_os = "linux")]
fn nice_fixture() -> (tempfile::TempDir, std::path::PathBuf, Value) {
	use std::os::unix::fs::PermissionsExt;
	let temporary = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	let state = temporary.path().join("private-state");
	let job = state.join("jobs/nice-fixture");
	std::fs::create_dir_all(&job).unwrap();
	for directory in [&state, &state.join("jobs"), &job] {
		std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
	}
	let request = json!({"job_id":"nice-fixture","job_dir":job,"unit":"never-submit-nice-fixture",
		"request_fingerprint":"unchanged-nice-binding","launch_nonce":"a".repeat(32),
		"platform":"macos","execution_mode":"operator","executable":"/usr/bin/python3",
		"args":["-I","-S","-c","import json,os;print(json.dumps({'nice':os.getpriority(os.PRIO_PROCESS,0)}))"],
		"env":{},"timeout_seconds":5,"allow_job_network":true,"allow_detached_fallback":false});
	(temporary, job, request)
}

#[cfg(target_os = "linux")]
fn inline_runner_source() -> String {
	let body = START_CODE
		.split_once("runner = r'''")
		.unwrap()
		.1
		.split_once("\n'''\nrunner_path")
		.unwrap()
		.0;
	format!("{PRIVATE_DIRECTORY_CODE}\n{body}\n")
}

#[cfg(target_os = "linux")]
fn python_nice_fixture(code: &str, payload: &Value) -> std::process::Output {
	use std::io::Write;
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
	child.wait_with_output().unwrap()
}

#[cfg(target_os = "linux")]
const NICE_RUNNER_FIXTURE: &str = r#"
import json,os,pathlib,sys
def exercise():
    q = json.load(sys.stdin)
    request = q['request']
    request['executable'] = sys.executable
    job = pathlib.Path(request['job_dir'])
    with (job / 'request.json').open('x') as stream:
        json.dump(request,stream)
    os.chmod(job / 'request.json',0o600)
    info = job.stat()
    binding = {'device':info.st_dev,'inode':info.st_ino,'job_id':request['job_id'],
               'launch_nonce':request['launch_nonce'],'request_fingerprint':request['request_fingerprint']}
    inherited = os.getpriority(os.PRIO_PROCESS,0)
    real_nice = os.nice
    if q['marker'] == 'systemd':
        # Emulate only inherited priority, using an unprivileged local child.
        # No service manager is contacted and the Rust test process is unchanged.
        real_nice(int(request.get('nice') or 0))
    launcher_nice = os.getpriority(os.PRIO_PROCESS,0)
    calls = []
    def observed_nice(delta):
        calls.append(delta)
        if q.get('deny_nice'):
            raise OSError('fixture priority adjustment refused')
        return real_nice(delta)
    os.nice = observed_nice
    sys.argv = ['-c',str(job),json.dumps(binding)]
    if q['marker'] is not None:
        sys.argv.append(q['marker'])
    if q.get('extra_argument'):
        sys.argv.append('unexpected')
    code = 0
    message = None
    try:
        exec(q['runner'],{'__name__':'__main__'})
    except SystemExit as stopped:
        if isinstance(stopped.code,int):
            code = stopped.code
        else:
            code,message = 1,str(stopped.code)
    finally:
        os.nice = real_nice
    print(json.dumps({'inherited_nice':inherited,'launcher_nice':launcher_nice,
                     'supervisor_nice':os.getpriority(os.PRIO_PROCESS,0),
                     'nice_calls':calls,'error':message}),flush=True)
    raise SystemExit(code)
exercise()
"#;

#[cfg(target_os = "linux")]
#[test]
fn inline_supervisor_applies_nice_once_for_each_backend_and_legacy_argv() {
	for marker in [Some("systemd"), Some("detached"), None] {
		for adjustment in [None, Some(0_u8), Some(1), Some(10), Some(19)] {
			let (_temporary, job, mut request) = nice_fixture();
			request["nice"] = json!(adjustment);
			let output = python_nice_fixture(
				NICE_RUNNER_FIXTURE,
				&json!({"request":request,"runner":inline_runner_source(),"marker":marker}),
			);
			assert!(
				output.status.success(),
				"marker={marker:?} adjustment={adjustment:?}: {}",
				String::from_utf8_lossy(&output.stderr)
			);
			let trace: Value = serde_json::from_slice(&output.stdout).unwrap();
			let inherited = trace["launcher_nice"].as_i64().unwrap();
			let delta = i64::from(adjustment.unwrap_or(0));
			let expected = if marker == Some("systemd") {
				inherited
			} else {
				(inherited + delta).min(19)
			};
			let expected_calls = if marker != Some("systemd") && delta != 0 {
				json!([delta])
			} else {
				json!([])
			};
			assert_eq!(trace["nice_calls"], expected_calls);
			assert_eq!(trace["supervisor_nice"], expected);
			let child: Value =
				serde_json::from_slice(&std::fs::read(job.join("stdout.log")).unwrap()).unwrap();
			assert_eq!(child["nice"], expected);
			let final_state: Value =
				serde_json::from_slice(&std::fs::read(job.join("exit.json")).unwrap()).unwrap();
			assert_eq!(final_state["exit_code"], 0);
			assert_eq!(final_state["output_complete"], true);
			let stored: Value =
				serde_json::from_slice(&std::fs::read(job.join("request.json")).unwrap()).unwrap();
			assert_eq!(stored["nice"], json!(adjustment));
			assert_eq!(stored["request_fingerprint"], "unchanged-nice-binding");
			assert!(stored.get("launch_backend").is_none());
		}
	}
}

#[cfg(target_os = "linux")]
#[test]
fn detached_supervisor_keeps_best_effort_nice_refusal_semantics() {
	let (_temporary, job, mut request) = nice_fixture();
	request["nice"] = json!(10);
	let output = python_nice_fixture(
		NICE_RUNNER_FIXTURE,
		&json!({"request":request,"runner":inline_runner_source(),"marker":"detached","deny_nice":true}),
	);
	assert!(
		output.status.success(),
		"{}",
		String::from_utf8_lossy(&output.stderr)
	);
	let trace: Value = serde_json::from_slice(&output.stdout).unwrap();
	assert_eq!(trace["nice_calls"], json!([10]));
	assert_eq!(trace["supervisor_nice"], trace["launcher_nice"]);
	let child: Value =
		serde_json::from_slice(&std::fs::read(job.join("stdout.log")).unwrap()).unwrap();
	assert_eq!(child["nice"], trace["launcher_nice"]);
}

#[cfg(target_os = "linux")]
#[test]
fn inline_supervisor_refuses_unknown_or_extra_backend_args_before_owner_intent() {
	for (marker, extra) in [
		("unknown", false),
		("SYSTEMD", false),
		("", false),
		("detached", true),
	] {
		let (_temporary, job, mut request) = nice_fixture();
		request["nice"] = json!(10);
		let output = python_nice_fixture(
			NICE_RUNNER_FIXTURE,
			&json!({"request":request,"runner":inline_runner_source(),"marker":marker,"extra_argument":extra}),
		);
		assert!(!output.status.success());
		let trace: Value = serde_json::from_slice(&output.stdout).unwrap();
		assert_eq!(trace["nice_calls"], json!([]));
		assert!(trace["error"]
			.as_str()
			.unwrap()
			.contains("invalid supervisor launch backend"));
		for artifact in [
			"owner-intent.json",
			"started.json",
			"child.json",
			"stdout.log",
			"exit.json",
		] {
			assert!(!job.join(artifact).exists(), "{artifact} must not exist");
		}
	}
}

#[cfg(target_os = "linux")]
#[test]
fn trusted_launcher_marks_both_backends_without_changing_the_request_binding() {
	const CODE: &str = r#"
import json,shutil,subprocess,sys,types
q = json.load(sys.stdin)
captured = []
def capture(argv):
    index = argv.index('-c') + 1
    captured.append({'runner_matches':argv[index] == q['runner'],
                     'tail':argv[index+1:], 'properties':[arg for arg in argv if arg.startswith('Nice=')]})
def systemd(argv,**kwargs):
    capture(argv)
    return subprocess.CompletedProcess(argv,0,'','')
def detached(argv,**kwargs):
    capture(argv)
    return types.SimpleNamespace(pid=4242)
subprocess.run = systemd
subprocess.Popen = detached
shutil.which = lambda _: '/mock/systemd-run'
sys.stdin = __import__('io').StringIO(json.dumps(q['request']))
exec(q['helper'],{'__name__':'__main__'})
print(json.dumps({'captured':captured}),flush=True)
"#;
	for backend in ["systemd", "detached"] {
		for adjustment in [None, Some(0_u8), Some(1), Some(10), Some(19)] {
			let (_temporary, job, mut request) = nice_fixture();
			request["nice"] = json!(adjustment);
			request["platform"] = json!(if backend == "systemd" {
				"linux"
			} else {
				"macos"
			});
			request["allow_detached_fallback"] = json!(backend == "detached");
			let output = python_nice_fixture(
				CODE,
				&json!({"request":request,"runner":inline_runner_source(),"helper":private_remote_code(START_CODE).unwrap()}),
			);
			assert!(
				output.status.success(),
				"{}",
				String::from_utf8_lossy(&output.stderr)
			);
			let last = std::str::from_utf8(&output.stdout)
				.unwrap()
				.lines()
				.next_back()
				.unwrap();
			let trace: Value = serde_json::from_str(last).unwrap();
			let calls = trace["captured"].as_array().unwrap();
			assert_eq!(calls.len(), 1);
			assert_eq!(calls[0]["runner_matches"], true);
			let tail = calls[0]["tail"].as_array().unwrap();
			assert_eq!(tail.len(), 3);
			assert_eq!(tail[0], job.to_string_lossy().as_ref());
			assert_eq!(tail[2], backend);
			let binding: Value = serde_json::from_str(tail[1].as_str().unwrap()).unwrap();
			let stored: Value =
				serde_json::from_slice(&std::fs::read(job.join("request.json")).unwrap()).unwrap();
			assert_eq!(binding["job_id"], stored["job_id"]);
			assert_eq!(binding["launch_nonce"], stored["launch_nonce"]);
			assert_eq!(
				binding["request_fingerprint"],
				stored["request_fingerprint"]
			);
			assert_eq!(binding.as_object().unwrap().len(), 5);
			assert_eq!(stored["nice"], json!(adjustment));
			assert!(stored.get("launch_backend").is_none());
			assert!(!job.join("owner-intent.json").exists());
			let expected_properties = match (backend, adjustment) {
				("systemd", Some(value)) if value != 0 => json!([format!("Nice={value}")]),
				_ => json!([]),
			};
			assert_eq!(calls[0]["properties"], expected_properties);
		}
	}
}

#[test]
fn large_job_inventory_is_complete_redacted_and_wire_bounded() {
	let records: Vec<JobRecord> = (0..3431)
		.map(|index| {
			let mut record = outcome_fixture(ExecutionMode::Operator, false, "launched");
			record.id = format!("owned-job-{index:06}");
			record.host = format!("configured-host-{}", index % 6);
			record.args = vec!["PRIVATE_ARG".repeat(400)];
			record.cwd = Some("/PRIVATE_CWD".to_owned());
			record.ssh_target = "PRIVATE_SSH".to_owned();
			record.remote_job_dir = "/PRIVATE_REMOTE_STATE".to_owned();
			record.executable = "/PRIVATE_EXECUTABLE".to_owned();
			record.env_keys = vec!["PRIVATE_ENV".to_owned()];
			record
		})
		.collect();
	let legacy = serde_json::to_string_pretty(&json!({"jobs":records})).unwrap();
	let legacy_wire = serde_json::to_vec(&rmcp::model::CallToolResult::success(vec![
		rmcp::model::ContentBlock::text(legacy),
	]))
	.unwrap();
	assert!(legacy_wire.len() > 8 * 1024 * 1024);
	let text = job_inventory_response(&records).unwrap();
	let wire = serde_json::to_vec(&rmcp::model::CallToolResult::success(vec![
		rmcp::model::ContentBlock::text(text.clone()),
	]))
	.unwrap();
	assert!(wire.len() <= 1024 * 1024);
	assert!(!text.contains("PRIVATE_"));
	let value: Value = serde_json::from_str(&text).unwrap();
	assert_eq!(value["inventory_complete"], true);
	assert_eq!(value["total"], 3431);
	assert_eq!(value["status_authoritative"], false);
	for (record, summary) in records.iter().zip(value["jobs"].as_array().unwrap()) {
		assert_eq!(summary["id"], record.id);
		assert_eq!(summary["host"], record.host);
		assert_eq!(summary.as_object().unwrap().len(), 5);
	}
}

#[test]
fn compact_inventory_preserves_complete_five_field_inventory_at_real_registry_scale() {
	for count in [4220_usize, 6000] {
		let hosts = ["main", "pocket4", "rog", "mac", "x230", "ai395"];
		let records: Vec<JobRecord> = (0..count)
			.map(|index| {
				let mode = if index.is_multiple_of(2) {
					ExecutionMode::Operator
				} else {
					ExecutionMode::Isolated
				};
				let state = if index.is_multiple_of(3) {
					"launched"
				} else {
					"pending"
				};
				let mut record = outcome_fixture(mode, false, state);
				record.id = format!("1a137800000-b2f-{index:x}");
				record.host = hosts[index % hosts.len()].to_string();
				record.created_unix_ms = 1_791_932_000_000;
				record.args = vec!["PRIVATE_ARG_DO_NOT_PUBLISH".into()];
				record.env_keys = vec!["PRIVATE_ENV_DO_NOT_PUBLISH".into()];
				record
			})
			.collect();
		let text = job_inventory_response(&records).unwrap();
		let value: Value = serde_json::from_str(&text).unwrap();
		let jobs = value["jobs"].as_array().unwrap();
		assert_eq!(value["total"], count);
		assert_eq!(value["inventory_complete"], true);
		assert_eq!(value["status_authoritative"], false);
		assert_eq!(jobs.len(), count);
		assert_eq!(
			value
				.as_object()
				.unwrap()
				.keys()
				.cloned()
				.collect::<std::collections::BTreeSet<_>>(),
			[
				"inventory_complete",
				"jobs",
				"status_authoritative",
				"total"
			]
			.into_iter()
			.map(str::to_string)
			.collect()
		);
		let expected_ids: std::collections::BTreeSet<_> =
			records.iter().map(|record| record.id.as_str()).collect();
		let actual_ids: std::collections::BTreeSet<_> =
			jobs.iter().map(|row| row["id"].as_str().unwrap()).collect();
		assert_eq!(actual_ids, expected_ids);
		for (record, row) in records.iter().zip(jobs) {
			assert_eq!(
				row.as_object()
					.unwrap()
					.keys()
					.cloned()
					.collect::<std::collections::BTreeSet<_>>(),
				[
					"created_unix_ms",
					"execution_mode",
					"host",
					"id",
					"launch_state"
				]
				.into_iter()
				.map(str::to_string)
				.collect()
			);
			assert_eq!(row["id"], record.id);
			assert_eq!(row["host"], record.host);
			assert_eq!(
				row["created_unix_ms"],
				serde_json::to_value(record.created_unix_ms).unwrap()
			);
			assert_eq!(
				row["execution_mode"],
				serde_json::to_value(record.execution_mode).unwrap()
			);
			assert_eq!(row["launch_state"], record.launch_state);
		}
		assert!(!text.contains("PRIVATE_"));
		assert!(!text.contains("configured-private-target"));
		assert!(!text.contains("/private-job-root/"));
		let wire = serde_json::to_vec(&rmcp::model::CallToolResult::success(vec![
			rmcp::model::ContentBlock::text(text.clone()),
		]))
		.unwrap();
		assert!(wire.len() <= 1024 * 1024);
		let original_pretty = serde_json::to_string_pretty(&value).unwrap();
		let original_wire = serde_json::to_vec(&rmcp::model::CallToolResult::success(vec![
			rmcp::model::ContentBlock::text(original_pretty),
		]))
		.unwrap();
		assert!(wire.len() < original_wire.len());
		if count == 6000 {
			assert!(original_wire.len() > 1024 * 1024);
		} else {
			assert!(original_wire.len() <= 1024 * 1024);
		}
	}
}

#[test]
fn inventory_overflow_refuses_the_whole_result_instead_of_silent_partial() {
	let records: Vec<JobRecord> = (0..10000)
		.map(|index| {
			let mut record = outcome_fixture(ExecutionMode::Operator, false, "pending");
			record.id = format!("owned-job-{index}");
			record.host = "bounded-configured-host".repeat(10);
			record
		})
		.collect();
	let error = job_inventory_response(&records).unwrap_err().to_string();
	assert!(error.contains("No partial inventory returned"));
	assert!(error.contains("host filter"));
}

#[test]
fn legacy_audit_failure_cannot_hide_existing_job_status_wait_or_output_cursors() {
	for observation in [
		json!({"state":"succeeded","exit_code":0,"output_complete":true}),
		json!({"state":"running","pid":1234}),
		json!({"stdout":{"text":"retained-output","offset":5,"next_offset":20,"eof":true},"stderr":{"text":"","offset":0,"next_offset":0,"eof":true}}),
	] {
		let retained = retain_observation_after_audit(
			observation.clone(),
			Err(anyhow::anyhow!("PRIVATE_AUDIT_SECRET")),
			"local-host",
			"local-job",
		);
		for (key, value) in observation.as_object().unwrap() {
			assert_eq!(&retained[key], value);
		}
		assert_eq!(retained["audit_recorded"], false);
		assert!(retained["audit_warning"]
			.as_str()
			.unwrap()
			.contains("No new job"));
		assert!(!retained.to_string().contains("PRIVATE_AUDIT_SECRET"));
	}
	let observed = retain_observation_after_audit(
		json!({"state":"succeeded"}),
		Ok(()),
		"local-host",
		"local-job",
	);
	assert_eq!(observed["audit_recorded"], true);
	assert!(observed.get("audit_warning").is_none());
}

#[test]
fn nonobject_observations_are_controlled_unknown_without_panic() {
	for value in [Value::Null, json!("UNTRUSTED_SECRET"), json!([1, 2])] {
		let result = retain_observation_after_audit(value, Ok(()), "local-host", "local-job");
		assert_eq!(result["outcome"], "unknown");
		assert_eq!(result["automatic_retry"], false);
		assert_eq!(result["host"], "local-host");
		assert_eq!(result["job_id"], "local-job");
		assert!(!result.to_string().contains("UNTRUSTED_SECRET"));
	}
}

#[test]
fn ids_are_valid_and_unique() {
	let a = next_job_id();
	let b = next_job_id();
	assert_ne!(a, b);
	assert!(valid_name(&a));
}

#[test]
fn fingerprint_binds_stdin_and_resource_limits() {
	let mut base = ProcessStartParams {
		host: "rog".into(),
		executable: "/usr/bin/printf".into(),
		args: vec!["ok".into()],
		cwd: Some("/tmp".into()),
		env: BTreeMap::new(),
		stdin: None,
		timeout_seconds: Some(10),
		idempotency_key: Some("key".into()),
		nice: Some(1),
		cpu_quota_percent: Some(20),
		memory_max_bytes: Some(134217728),
	};
	let digest = request_digest(&base).unwrap();
	assert_eq!(digest.len(), 64);
	// Freeze the original JSON/SHA256 representation and its legacy 64-bit prefix.
	assert_eq!(
		digest,
		"ca832d57a27411bc9e0a382fed917e42212140108bb0e7c94953dd8d30bc1411"
	);
	let original = fingerprint(&digest);
	assert_eq!(original, 0xca83_2d57_a274_11bc);
	base.stdin = Some("different".into());
	assert_ne!(original, fingerprint(&request_digest(&base).unwrap()));
	base.stdin = None;
	base.cpu_quota_percent = Some(21);
	assert_ne!(original, fingerprint(&request_digest(&base).unwrap()));
}

// Preserve the complete original Value/Vec algorithm independently of the
// borrowed streaming representation, including the old hexadecimal conversion.
fn legacy_request_binding_bytes(params: &ProcessStartParams) -> Vec<u8> {
	let binding = json!({
		"host": params.host,
		"executable": params.executable,
		"args": params.args,
		"cwd": params.cwd,
		"env": params.env,
		"stdin": params.stdin,
		"timeout_seconds": params.timeout_seconds,
		"nice": params.nice,
		"cpu_quota_percent": params.cpu_quota_percent,
		"memory_max_bytes": params.memory_max_bytes,
	});
	serde_json::to_vec(&binding).unwrap()
}
fn legacy_request_digest(params: &ProcessStartParams) -> String {
	let digest = Sha256::digest(legacy_request_binding_bytes(params));
	digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn streamed_request_binding_matches_legacy_json_bytes_and_full_digest() {
	let empty: ProcessStartParams =
		serde_json::from_value(json!({"host":"rog","executable":"/usr/bin/true"})).unwrap();
	let mut complete = empty.clone();
	complete.args = vec!["first".into(), "second".into()];
	complete.cwd = Some("/tmp/work".into());
	complete.env = BTreeMap::from([
		("Z_LAST".into(), "last".into()),
		("A_FIRST".into(), "first".into()),
		("M_MIDDLE".into(), "middle".into()),
	]);
	complete.stdin = Some(String::new());
	complete.timeout_seconds = Some(u64::MAX);
	complete.idempotency_key = Some("excluded-from-binding".into());
	complete.nice = Some(u8::MAX);
	complete.cpu_quota_percent = Some(u16::MAX);
	complete.memory_max_bytes = Some(u64::MAX);
	let mut escaped = complete.clone();
	escaped.host = "主机\"\\\0".into();
	escaped.executable = "/程序/🦀".into();
	escaped.args = vec![
		"quote\"slash\\".into(),
		"NUL\0\n\t\r".into(),
		"λ雪🦀".into(),
	];
	escaped.cwd = Some("/目录/\"\\\0".into());
	escaped.env.insert("Ω_KEY".into(), "值\0\"\\\n".into());
	escaped.env.insert("\0_KEY".into(), "tab\treturn\r".into());
	escaped.stdin = Some("Unicode λ雪🦀, quote\", slash\\, NUL\0, newline\n".into());
	let mut large = complete.clone();
	large.stdin = Some("x".repeat(MAX_STDIN_BYTES));
	let mut large_escaped = escaped.clone();
	large_escaped.stdin = Some("\"\\\0\n".repeat(MAX_STDIN_BYTES / 4));
	for (label, params) in [
		("none", empty),
		("all_options", complete),
		("unicode_and_escaping", escaped),
		("one_mib_stdin", large),
		("one_mib_escaped_stdin", large_escaped),
	] {
		let expected = legacy_request_binding_bytes(&params);
		let actual = serde_json::to_vec(&request_binding(&params)).unwrap();
		assert_eq!(actual, expected, "{label}");
		let digest = request_digest(&params).unwrap();
		assert_eq!(digest.len(), 64, "{label}");
		assert_eq!(digest, legacy_request_digest(&params), "{label}");
		let mut same_request = params;
		same_request.idempotency_key = Some("different-excluded-key".into());
		assert_eq!(request_digest(&same_request).unwrap(), digest, "{label}");
	}
}

#[test]
fn legacy_binding_does_not_silently_relaunch() {
	let params: ProcessStartParams =
		serde_json::from_value(json!({"host":"rog","executable":"/usr/bin/true"})).unwrap();
	let digest = request_digest(&params).unwrap();
	let mut record:JobRecord=serde_json::from_value(json!({"id":"fixture","host":"rog","ssh_target":"hepta-rog","unit":"fixture","remote_job_dir":"/tmp/fixture","executable":"/usr/bin/true","args":[],"cwd":null,"env_keys":[],"created_unix_ms":1,"idempotency_key":"test","request_fingerprint":fingerprint(&digest)})).unwrap();
	assert!(matches_request(&record, &digest).is_err());
	record.request_digest = Some(digest.clone());
	assert!(matches_request(&record, &digest).unwrap());
	let mut changed = params;
	changed.env.insert("X".into(), "changed".into());
	assert!(!matches_request(&record, &request_digest(&changed).unwrap()).unwrap());
}

#[test]
fn precomputed_request_match_checks_digest_beyond_legacy_prefix() {
	let params: ProcessStartParams =
		serde_json::from_value(json!({"host":"rog","executable":"/usr/bin/true"})).unwrap();
	let digest = request_digest(&params).unwrap();
	let mut record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	record.request_fingerprint = fingerprint(&digest);
	record.request_digest = Some(digest.clone());
	assert!(matches_request(&record, &digest).unwrap());
	let mut changed = digest.clone();
	changed.replace_range(63..64, if &digest[63..64] == "0" { "1" } else { "0" });
	assert_eq!(fingerprint(&digest), fingerprint(&changed));
	assert!(!matches_request(&record, &changed).unwrap());
}

#[test]
#[ignore = "manual isolated request-binding CPU microbenchmark; not process-start TPS"]
fn request_binding_microbenchmark_small_and_1mib_stdin() {
	use std::hint::black_box;
	use std::time::Instant;

	// Reproduce the previous Value clone and JSON Vec allocation twice. An
	// existing key likewise computed one prefix and one complete binding digest.
	let previous = |params: &ProcessStartParams| {
		let prefix =
			u64::from_str_radix(&legacy_request_digest(black_box(params))[..16], 16).unwrap_or(0);
		(prefix, legacy_request_digest(black_box(params)))
	};
	let reused = |params: &ProcessStartParams| {
		let digest = request_digest(black_box(params)).unwrap();
		(fingerprint(&digest), digest)
	};
	let measure = |params: &ProcessStartParams,
	               iterations: usize,
	               calculate: &dyn Fn(&ProcessStartParams) -> (u64, String)| {
		let started = Instant::now();
		for _ in 0..iterations {
			black_box(calculate(black_box(params)));
		}
		started.elapsed().as_secs_f64() * 1_000_000.0 / iterations as f64
	};
	for (stdin_bytes, iterations) in [(0, 512), (MAX_STDIN_BYTES, 16)] {
		let mut params: ProcessStartParams = serde_json::from_value(json!({
			"host":"rog","executable":"/usr/bin/cat","args":[],
			"idempotency_key":"binding-benchmark"
		}))
		.unwrap();
		if stdin_bytes > 0 {
			params.stdin = Some("x".repeat(stdin_bytes));
		}
		assert_eq!(previous(&params), reused(&params));
		let mut previous_us = Vec::new();
		let mut reused_us = Vec::new();
		for round in 0..6 {
			if round % 2 == 0 {
				previous_us.push(measure(&params, iterations, &previous));
				reused_us.push(measure(&params, iterations, &reused));
			} else {
				reused_us.push(measure(&params, iterations, &reused));
				previous_us.push(measure(&params, iterations, &previous));
			}
		}
		previous_us.sort_by(f64::total_cmp);
		reused_us.sort_by(f64::total_cmp);
		let previous_median_us = (previous_us[2] + previous_us[3]) / 2.0;
		let reused_median_us = (reused_us[2] + reused_us[3]) / 2.0;
		println!(
			"{}",
			json!({
				"schema":"hepta-request-binding-microbenchmark/v2",
				"stdin_bytes":stdin_bytes,"iterations_per_round":iterations,"rounds":6,
				"previous_algorithm":"legacy_Value_to_vec_SHA256_twice",
				"candidate_algorithm":"borrowed_to_writer_SHA256_once",
				"previous_two_digests_median_us":previous_median_us,
				"reused_one_digest_median_us":reused_median_us,
				"speedup":previous_median_us / reused_median_us,
				"process_start_tps":false
			})
		);
	}
}

fn outcome_fixture(mode: ExecutionMode, system_jobctl: bool, state: &str) -> JobRecord {
	serde_json::from_value(json!({
		"id":"same-job-id","host":"main","ssh_target":"configured-private-target",
		"unit":"hepta-runtime-job-same-job-id","remote_job_dir":"/private-job-root/same-job-id",
		"executable":"/usr/bin/true","args":[],"cwd":null,"env_keys":[],
		"created_unix_ms":1,"idempotency_key":"fixed-key","request_fingerprint":1,
		"request_digest":"a".repeat(64),"launch_state":state,"execution_mode":mode,
		"system_jobctl":system_jobctl
	}))
	.unwrap()
}

#[test]
fn intent_failure_is_redacted_and_prevents_operation_submission() {
	let submitted = std::cell::Cell::new(false);
	let submit = || -> Result<()> {
		require_operation_intent(Err(anyhow::anyhow!("/secret/audit/path: CREDENTIAL")))?;
		submitted.set(true);
		Ok(())
	};
	let error = submit().unwrap_err();
	assert!(!submitted.get());
	let rendered = format!("{error:#}");
	assert!(rendered.contains("no remote operation submitted"));
	assert!(!rendered.contains("/secret"));
	assert!(!rendered.contains("CREDENTIAL"));
	assert!(error.source().is_none());
}

#[test]
fn post_operation_audit_failure_preserves_the_real_result_and_identity() {
	let original =
		json!({"job":{"id":"same-job-id"},"launch":{"ok":true,"pid":1234},"reused":false});
	let result = retain_result_after_audit(
		original.clone(),
		Err(anyhow::anyhow!(
			"permission denied /secret/audit/path TOKEN"
		)),
	);
	assert_eq!(result["job"], original["job"]);
	assert_eq!(result["launch"], original["launch"]);
	assert_eq!(result["reused"], false);
	assert_eq!(result["audit_recorded"], false);
	assert!(result["audit_warning"]
		.as_str()
		.unwrap()
		.contains("existing job_id"));
	let text = result.to_string();
	assert!(!text.contains("/secret"));
	assert!(!text.contains("TOKEN"));
	let ok = retain_result_after_audit(original.clone(), Ok(()));
	assert_eq!(ok["audit_recorded"], true);
	assert_eq!(ok["launch"], original["launch"]);
	assert!(ok.get("audit_warning").is_none());
}

#[test]
fn confirmed_remote_launch_survives_failed_local_completion_save() {
	let mut record = outcome_fixture(ExecutionMode::Operator, false, "pending");
	let original = json!({"ok":true,"backend":"systemd","unit":record.unit,"launcher_pid":5678});
	let saves = std::cell::Cell::new(0);
	let result = preserve_launch_outcome(&mut record, Ok(original.clone()), |r| {
		saves.set(saves.get() + 1);
		assert_eq!(r.launch_state, "launched");
		Err(anyhow::anyhow!("/private-record-path save failed SECRET"))
	});
	assert_eq!(saves.get(), 1);
	assert_eq!(result.value, original);
	assert!(result.local_record_pending);
	assert_eq!(record.launch_state, "launched");
	assert!(record.launch_error.is_none());
	let mut response = json!({"job":record,"launch":result.value});
	attach_launch_record_warning(&mut response, &result);
	assert_eq!(response["job"]["id"], "same-job-id");
	assert_eq!(response["local_record_pending"], true);
	assert_eq!(response["launch"]["launcher_pid"], 5678);
	assert!(!response.to_string().contains("SECRET"));
	assert!(!response.to_string().contains("/private-record-path"));
}

#[test]
fn untrusted_launch_ack_cannot_promote_pending_to_launched() {
	for ack in [
		Value::Null,
		json!("ACK_SECRET"),
		json!([1]),
		json!({}),
		json!({"ok":false,"backend":"detached","launcher_pid":1234}),
		json!({"ok":true,"backend":"detached","launcher_pid":0}),
		json!({"ok":true,"backend":"systemd","unit":"other-unit"}),
	] {
		let mut record = outcome_fixture(ExecutionMode::Operator, false, "pending");
		let result = preserve_launch_outcome(&mut record, Ok(ack), |_| Ok(()));
		assert_eq!(record.launch_state, "launch_unknown");
		assert_eq!(result.value["job_id"], "same-job-id");
		assert_eq!(result.value["automatic_retry"], false);
		assert!(!result.value.to_string().contains("ACK_SECRET"));
	}
	let mut record = outcome_fixture(ExecutionMode::Operator, false, "pending");
	let result = preserve_launch_outcome(
		&mut record,
		Ok(json!({"ok":true,"reused_remote":true,"backend":"launch_failed"})),
		|_| Ok(()),
	);
	assert_eq!(record.launch_state, "launch_failed");
	assert_eq!(result.value["backend"], "launch_failed");
}

#[test]
fn unknown_remote_launch_retains_job_id_without_claiming_failure_or_success() {
	let mut record = outcome_fixture(ExecutionMode::Operator, false, "pending");
	let saves = std::cell::Cell::new(0);
	let result = preserve_launch_outcome(
		&mut record,
		Err(anyhow::anyhow!(
			"upstream stdout=PRIVATE_FRAGMENT stderr=SECRET /private-target"
		)),
		|r| {
			saves.set(saves.get() + 1);
			assert_eq!(r.launch_state, "launch_unknown");
			Ok(())
		},
	);
	assert_eq!(saves.get(), 1);
	assert_eq!(record.launch_state, "launch_unknown");
	assert_eq!(result.value["job_id"], "same-job-id");
	assert_eq!(result.value["state"], "launch_unknown");
	assert_eq!(result.value["outcome"], "unknown");
	assert_eq!(result.value["status_authoritative"], false);
	assert_eq!(result.value["automatic_retry"], false);
	assert!(result.value.get("ok").is_none());
	assert!(!result.local_record_pending);
	let text = json!({"job":record,"launch":result.value}).to_string();
	for private in ["PRIVATE_FRAGMENT", "SECRET", "/private-target"] {
		assert!(!text.contains(private));
	}
}

#[test]
fn unknown_launch_and_failed_local_save_preserve_reconciliation_identity() {
	let mut record = outcome_fixture(ExecutionMode::Isolated, true, "pending");
	let outcome = preserve_launch_outcome(
		&mut record,
		Err(anyhow::anyhow!("remote connection outcome uncertain")),
		|_| Err(anyhow::anyhow!("local disk unavailable")),
	);
	let mut result = json!({"job":record,"launch":outcome.value});
	attach_launch_record_warning(&mut result, &outcome);
	assert_eq!(result["job"]["id"], "same-job-id");
	assert_eq!(result["local_record_pending"], true);
	assert_eq!(result["launch"]["reconcile_via"], "process_status");
}

#[test]
fn reconcile_retries_are_only_fixed_id_isolated_jobctl_records() {
	for state in ["pending", "launch_failed", "launch_unknown", "launched"] {
		let ordinary = outcome_fixture(ExecutionMode::Operator, false, state);
		assert!(!reconcile_retry_allowed(&ordinary));
		// A corrupted operator-side flag must not open the isolated retry path.
		let operator = outcome_fixture(ExecutionMode::Operator, true, state);
		assert!(!reconcile_retry_allowed(&operator));
		let isolated = outcome_fixture(ExecutionMode::Isolated, true, state);
		assert_eq!(
			reconcile_retry_allowed(&isolated),
			matches!(state, "pending" | "launch_failed")
		);
		let fallback = outcome_fixture(ExecutionMode::Isolated, false, state);
		assert!(!reconcile_retry_allowed(&fallback));
	}
}

#[test]
fn cancel_success_and_unknown_completion_are_identity_bound_and_redacted() {
	let result = retain_cancel_outcome(
		"same-job-id",
		Ok(
			json!({"job_id":"same-job-id","result":"stop_requested","untrusted_extra":"ACK_SECRET"}),
		),
	);
	let retained = retain_result_after_audit(
		result,
		Err(anyhow::anyhow!("audit /secret/path failed TOKEN")),
	);
	assert_eq!(retained["job_id"], "same-job-id");
	assert_eq!(retained["result"], "stop_requested");
	assert_eq!(retained["termination_confirmed"], false);
	assert_eq!(retained["automatic_retry"], false);
	assert!(!retained.to_string().contains("ACK_SECRET"));
	assert_eq!(retained["audit_recorded"], false);
	let unknown = retain_cancel_outcome(
		"same-job-id",
		Err(anyhow::anyhow!("remote /private-target failed SECRET")),
	);
	assert_eq!(unknown["job_id"], "same-job-id");
	assert_eq!(unknown["result"], "cancel_unknown");
	assert_eq!(unknown["outcome"], "unknown");
	assert_eq!(unknown["automatic_retry"], false);
	assert!(unknown.get("signal_sent").is_none());
	assert!(!unknown.to_string().contains("/private-target"));
	assert!(!unknown.to_string().contains("SECRET"));
}

#[test]
fn malformed_or_mismatched_cancel_ack_cannot_claim_a_confirmed_request_or_panic() {
	for ack in [
		Value::Null,
		json!("ACK_SECRET"),
		json!([1]),
		json!({}),
		json!({"job_id":"wrong-helper-id","result":"stop_requested"}),
		json!({"job_id":"same-job-id","result":"terminated"}),
	] {
		let result = retain_cancel_outcome("same-job-id", Ok(ack));
		assert_eq!(result["job_id"], "same-job-id");
		assert_eq!(result["result"], "cancel_unknown");
		assert_eq!(result["status_authoritative"], false);
		assert_eq!(result["automatic_retry"], false);
		assert_eq!(result["termination_confirmed"], false);
		assert!(!result.to_string().contains("ACK_SECRET"));
	}
}

#[test]
fn unavailable_reuse_status_never_discloses_upstream_diagnostics() {
	let status = unavailable_status("same-job-id");
	assert_eq!(status["job_id"], "same-job-id");
	assert_eq!(status["state"], "status_unavailable");
	assert_eq!(status["status_authoritative"], false);
	assert_eq!(status["automatic_retry"], false);
	assert!(status.get("error").is_none());
}

#[test]
fn canonical_jobctl_reconciliation_preserves_authoritative_launch_state() {
	for remote_state in [
		"pending",
		"launch_failed",
		"launched",
		"cancelled",
		"unrecognized",
	] {
		let mut record = outcome_fixture(ExecutionMode::Isolated, true, "pending");
		let remote = json!({"ok":true,"reused_remote":true,"backend":"systemd_system",
            "status":{"launch_state":remote_state,"state":"unknown"}});
		let expected = if remote_state == "unrecognized" {
			"launch_unknown"
		} else {
			remote_state
		};
		let outcome = preserve_launch_outcome(&mut record, Ok(remote.clone()), |persisted| {
			assert_eq!(persisted.launch_state, expected);
			Ok(())
		});
		assert_eq!(record.launch_state, expected);
		assert_eq!(outcome.value, remote);
		assert!(!outcome.local_record_pending);
		assert_eq!(
			record.launch_error.is_some(),
			remote_state == "unrecognized"
		);
	}
}

#[test]
fn paged_job_inventory_covers_large_registry_and_rejects_changed_snapshot() {
	let rows: Vec<Value> = (0..12000)
		.map(|number| {
			json!({
				"id": format!("{:08x}-1-1", number), "host":"rog", "created_unix_ms":number,
				"execution_mode":"operator", "launch_state":"launched"
			})
		})
		.collect();
	let mut params = ProcessListPageParams {
		host: Some("rog".into()),
		cursor: None,
		limit: Some(128),
	};
	let mut seen = Vec::new();
	loop {
		let text = page_job_rows(&rows, &params, "fixed-state").unwrap();
		let value: Value = serde_json::from_str(&text).unwrap();
		let wire =
			rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(text)]);
		assert!(serde_json::to_vec(&wire).unwrap().len() <= 64 * 1024);
		seen.extend(
			value["jobs"]
				.as_array()
				.unwrap()
				.iter()
				.map(|row| row["id"].clone()),
		);
		params.cursor = value["next_cursor"].as_str().map(str::to_owned);
		if params.cursor.is_none() {
			assert_eq!(value["inventory_complete"], true);
			break;
		}
		assert_eq!(value["inventory_complete"], false);
	}
	assert_eq!(seen.len(), rows.len());
	assert_eq!(
		seen,
		rows.iter().map(|row| row["id"].clone()).collect::<Vec<_>>()
	);
	let first: Value = serde_json::from_str(
		&page_job_rows(&rows, &ProcessListPageParams::default(), "fixed-state").unwrap(),
	)
	.unwrap();
	params.cursor = Some(first["next_cursor"].as_str().unwrap().into());
	let mut changed = rows.clone();
	changed[0]["launch_state"] = json!("cancelled");
	assert!(page_job_rows(&changed, &params, "fixed-state").is_err());
	assert!(page_job_rows(&rows, &params, "different-state").is_err());
	params.host = Some("mac".into());
	assert!(page_job_rows(&rows, &params, "fixed-state").is_err());
}

#[test]
fn paged_job_inventory_validates_limits_empty_registry_and_cursor() {
	let params = ProcessListPageParams::default();
	let value: Value =
		serde_json::from_str(&page_job_rows(&[], &params, "state").unwrap()).unwrap();
	assert_eq!(value["jobs"], json!([]));
	assert_eq!(value["inventory_complete"], true);
	assert_eq!(value["next_cursor"], Value::Null);
	assert!(page_job_rows(
		&[],
		&ProcessListPageParams {
			limit: Some(0),
			..params.clone()
		},
		"state"
	)
	.is_err());
	assert!(page_job_rows(
		&[],
		&ProcessListPageParams {
			limit: Some(129),
			..params.clone()
		},
		"state"
	)
	.is_err());
	assert!(page_job_rows(
		&[],
		&ProcessListPageParams {
			cursor: Some("bad".into()),
			..params
		},
		"state"
	)
	.is_err());
}

#[tokio::test]
async fn host_bound_start_lock_does_not_block_independent_hosts() {
	let rog = start_lock("hepta-fixture-rog", Some("same-key")).unwrap();
	let mac = start_lock("hepta-fixture-mac", Some("same-key")).unwrap();
	assert!(!Arc::ptr_eq(&rog, &mac));
	let guard = rog.lock().await;
	assert!(rog.try_lock().is_err());
	assert!(
		mac.try_lock().is_ok(),
		"another host must not queue behind ROG"
	);
	drop(guard);
}

#[tokio::test]
async fn key_lane_preserves_same_host_idempotency_serialization() {
	let first = start_lock("hepta-fixture-pocket4", Some("same-key")).unwrap();
	let second = start_lock("hepta-fixture-pocket4", Some("same-key")).unwrap();
	assert!(Arc::ptr_eq(&first, &second));
	let guard = first.lock().await;
	assert!(
		second.try_lock().is_err(),
		"the same host/key must serialize starts"
	);
	drop(guard);
	assert!(second.try_lock().is_ok());
}

#[tokio::test]
async fn different_key_lanes_allow_same_host_progress_during_remote_wait() {
	let host = "hepta-fixture-distinct-key-lanes";
	let first_key = "slow-first-key";
	let other_key = (0..1024)
		.map(|index| format!("fast-other-key-{index}"))
		.find(|key| start_lane(Some(key)) != start_lane(Some(first_key)))
		.unwrap();
	let first = start_lock(host, Some(first_key)).unwrap();
	let other = start_lock(host, Some(&other_key)).unwrap();
	assert!(!Arc::ptr_eq(&first, &other));
	let guard = first.lock().await;
	let original_completed = std::sync::atomic::AtomicBool::new(false);
	let original = async {
		tokio::task::yield_now().await;
		assert!(
			original_completed.load(Ordering::SeqCst),
			"another lane must complete before the slow original ACK is released"
		);
		drop(guard);
	};
	let independent = async {
		let _other_guard = other
			.try_lock()
			.expect("a distinct key lane must progress while the original holds its guard");
		assert!(first.try_lock().is_err());
		original_completed.store(true, Ordering::SeqCst);
	};
	tokio::join!(original, independent);
}

#[tokio::test]
async fn missing_keys_remain_on_one_serialized_lane() {
	let first = start_lock("hepta-fixture-no-key", None).unwrap();
	let second = start_lock("hepta-fixture-no-key", None).unwrap();
	assert_eq!(start_lane(None), 0);
	assert!(Arc::ptr_eq(&first, &second));
	let guard = first.lock().await;
	assert!(second.try_lock().is_err());
	drop(guard);
	assert!(second.try_lock().is_ok());
}

#[tokio::test]
async fn colliding_keys_share_a_lock_without_merging_their_identity() {
	let first_key = "first-collision-key";
	let other_key = (0..4096)
		.map(|index| format!("other-collision-key-{index}"))
		.find(|key| start_lane(Some(key)) == start_lane(Some(first_key)))
		.unwrap();
	assert_ne!(first_key, other_key);
	let first = start_lock("hepta-fixture-collision", Some(first_key)).unwrap();
	let other = start_lock("hepta-fixture-collision", Some(&other_key)).unwrap();
	assert!(Arc::ptr_eq(&first, &other));
	let guard = first.lock().await;
	assert!(other.try_lock().is_err());
	drop(guard);
	assert!(other.try_lock().is_ok());
}

#[test]
fn retained_start_locks_are_bounded_by_hosts_not_key_cardinality() {
	let registry = Mutex::new(HashMap::new());
	for host in ["first-private-host", "second-private-host"] {
		let mut identities = std::collections::HashSet::new();
		for index in 0..16_384 {
			let key = format!("private-key-{index}");
			let first = start_lock_in(&registry, host, Some(&key)).unwrap();
			let second = start_lock_in(&registry, host, Some(&key)).unwrap();
			assert!(Arc::ptr_eq(&first, &second));
			identities.insert(Arc::as_ptr(&first) as usize);
		}
		assert_eq!(identities.len(), START_LANE_COUNT);
	}
	let registry = registry.lock().unwrap();
	assert_eq!(registry.len(), 2);
	for lanes in registry.values() {
		assert_eq!(lanes.len(), START_LANE_COUNT);
		assert!(lanes.iter().all(|lane| Arc::strong_count(lane) == 1));
	}
}

fn fixture_write(dir: &Path, record: &JobRecord) {
	let bytes = serde_json::to_vec(record).unwrap();
	let file = dir.join(format!("{}.json", record.id));
	std::fs::write(&file, bytes).unwrap();
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
	}
}

#[cfg(unix)]
#[test]
fn positive_reuse_cache_never_negative_caches_or_allocates_new_identity() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let mut existing = outcome_fixture(ExecutionMode::Operator, false, "launched");
	existing.id = "same-job-id".to_owned();
	fixture_write(root.path(), &existing);
	let first = find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		.unwrap()
		.unwrap();
	assert_eq!(first.id, existing.id);
	assert_eq!(
		cache.lock().unwrap().hits.len(),
		usize::from(registry_has_content_watch(
			&registry_epoch(root.path()).unwrap()
		))
	);
	let reused = find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		.unwrap()
		.unwrap();
	assert_eq!(reused.id, existing.id);
	assert!(find_idempotent_in(root.path(), "main", "new-key", &cache)
		.unwrap()
		.is_none());
	assert_eq!(
		cache.lock().unwrap().hits.len(),
		usize::from(registry_has_content_watch(
			&registry_epoch(root.path()).unwrap()
		))
	);
}

#[cfg(unix)]
#[test]
fn positive_reuse_corrupted_or_rebound_identity_fails_closed() {
	let root = tempfile::tempdir().unwrap();

	let cache = Mutex::new(ReuseHitCache::default());
	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &record);
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	let mut rebound = record.clone();
	rebound.idempotency_key = Some("other-key".to_owned());
	fixture_write(root.path(), &rebound);
	let error = find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		.unwrap_err()
		.to_string();
	assert!(
		error.contains("binding") && error.contains("changed"),
		"{error}"
	);
	std::fs::remove_file(root.path().join("same-job-id.json")).unwrap();
	assert!(find_idempotent_in(root.path(), "main", "fixed-key", &cache).is_err());
}

#[cfg(unix)]
#[test]
fn positive_reuse_directory_generation_change_renews_complete_scan() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &record);
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	let original = cache.lock().unwrap().epoch;
	let mut another = record.clone();
	another.id = "different-id".to_owned();
	another.idempotency_key = Some("different-key".to_owned());
	std::thread::sleep(Duration::from_millis(5));
	fixture_write(root.path(), &another);

	assert_ne!(original, Some(registry_epoch(root.path()).unwrap()));
	let found = find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		.unwrap()
		.unwrap();
	assert_eq!(found.id, record.id);
	assert_eq!(
		cache.lock().unwrap().epoch,
		Some(registry_epoch(root.path()).unwrap())
	);
}

#[cfg(unix)]
#[test]
fn positive_reuse_duplicate_original_bindings_refuse_after_new_file() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &record);
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	let mut duplicate = record.clone();
	duplicate.id = "conflicting-id".to_owned();
	duplicate.created_unix_ms = 0;
	std::thread::sleep(Duration::from_millis(5));
	fixture_write(root.path(), &duplicate);
	assert!(find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		.unwrap_err()
		.to_string()
		.contains("duplicate original"));
}

#[cfg(unix)]
#[test]
fn pending_or_uncertain_identity_does_not_enter_positive_cache() {
	for state in ["pending", "unknown", "failed"] {
		let root = tempfile::tempdir().unwrap();
		let cache = Mutex::new(ReuseHitCache::default());
		let record = outcome_fixture(ExecutionMode::Operator, false, state);
		fixture_write(root.path(), &record);
		assert_eq!(
			find_idempotent_in(root.path(), "main", "fixed-key", &cache)
				.unwrap()
				.unwrap()
				.id,
			record.id
		);
		assert!(cache.lock().unwrap().hits.is_empty());
	}
}

#[cfg(unix)]
#[test]
fn unknown_key_preserves_full_scan_corruption_refusal() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &record);
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	std::fs::write(root.path().join("damaged.json"), b"not-json").unwrap();
	assert!(find_idempotent_in(root.path(), "main", "not-registered", &cache).is_err());
}

#[cfg(unix)]
#[test]
fn cached_positive_cannot_escape_configured_state_root() {
	let one = tempfile::tempdir().unwrap();
	let two = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());

	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(one.path(), &record);
	assert!(find_idempotent_in(one.path(), "main", "fixed-key", &cache)
		.unwrap()
		.is_some());
	assert!(find_idempotent_in(two.path(), "main", "fixed-key", &cache)
		.unwrap_err()
		.to_string()
		.contains("registry root changed"));
	assert_eq!(cache.lock().unwrap().root.as_deref(), Some(one.path()));
}

#[cfg(unix)]
#[test]
fn previously_observed_other_keys_survive_unrelated_registry_churn() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let first = outcome_fixture(ExecutionMode::Operator, false, "launched");
	let mut second = first.clone();
	second.id = "other-record-id".to_owned();
	second.idempotency_key = Some("second-key".to_owned());
	fixture_write(root.path(), &first);
	fixture_write(root.path(), &second);
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	find_idempotent_in(root.path(), "main", "second-key", &cache).unwrap();
	assert_eq!(cache.lock().unwrap().known.len(), 2);
	// Change directory generation and query a different key first; old
	// identities must still be retained as refusal evidence.
	std::thread::sleep(Duration::from_millis(5));
	std::fs::write(root.path().join("non-record.txt"), b"fixture").unwrap();
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	assert_eq!(cache.lock().unwrap().known.len(), 2);
	std::fs::remove_file(root.path().join("other-record-id.json")).unwrap();
	assert!(
		find_idempotent_in(root.path(), "main", "second-key", &cache)
			.unwrap_err()
			.to_string()
			.contains("previous idempotency binding")
	);
}

#[cfg(unix)]
#[test]

fn previously_observed_old_key_cannot_be_rebound_to_new_job_id() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let original = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &original);
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	std::fs::remove_file(root.path().join("same-job-id.json")).unwrap();
	let mut replacement = original.clone();
	replacement.id = "replacement-job-id".to_owned();
	fixture_write(root.path(), &replacement);
	assert!(find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		.unwrap_err()
		.to_string()
		.contains("previous idempotency binding"));
}

#[cfg(unix)]
#[test]
#[ignore = "manual isolated filesystem microbenchmark; not production TPS"]
fn positive_reuse_microbenchmark_6000_synthetic_records() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let template = outcome_fixture(ExecutionMode::Operator, false, "launched");
	for i in 0..6000u32 {
		let mut record = template.clone();
		record.id = format!("fixture-job-{i:05}");
		record.created_unix_ms = i as u128;
		record.idempotency_key = Some(format!("unique-key-{i:05}"));
		fixture_write(root.path(), &record);
	}
	let key = "unique-key-05999";
	let cold_start = std::time::Instant::now();
	let cold = find_idempotent_in(root.path(), "main", key, &cache)
		.unwrap()
		.unwrap();
	let cold_ms = cold_start.elapsed().as_secs_f64() * 1000.0;
	let hot_start = std::time::Instant::now();
	let hot = find_idempotent_in(root.path(), "main", key, &cache)
		.unwrap()
		.unwrap();
	let hot_ms = hot_start.elapsed().as_secs_f64() * 1000.0;
	assert_eq!(cold.id, hot.id);
	assert_eq!(hot.id, "fixture-job-05999");
	assert_eq!(cache.lock().unwrap().known.len(), 1);
	let legacy_scan = || {
		let start = std::time::Instant::now();
		let found = all_records_in(root.path())
			.unwrap()
			.into_iter()
			.find(|r| r.host == "main" && r.idempotency_key.as_deref() == Some(key))
			.unwrap();
		assert_eq!(found.id, hot.id);
		start.elapsed().as_secs_f64() * 1000.0
	};
	let streaming_scan = || {
		let start = std::time::Instant::now();
		let found = scan_idempotent_binding_in(root.path(), "main", key)
			.unwrap()
			.unwrap();
		assert_eq!(found.id, hot.id);
		start.elapsed().as_secs_f64() * 1000.0
	};
	let mut legacy_ms = Vec::new();
	let mut streamed_ms = Vec::new();
	for round in 0..6 {
		if round % 2 == 0 {
			legacy_ms.push(legacy_scan());
			streamed_ms.push(streaming_scan());
		} else {
			streamed_ms.push(streaming_scan());
			legacy_ms.push(legacy_scan());
		}
	}
	legacy_ms.sort_by(f64::total_cmp);
	streamed_ms.sort_by(f64::total_cmp);
	println!("isolated_fixture_records=6000 cold_lookup_ms={cold_ms:.3} hot_reuse_ms={hot_ms:.3} legacy_sorted_median_ms={:.3} streamed_median_ms={:.3}",
		(legacy_ms[2] + legacy_ms[3]) / 2.0,
		(streamed_ms[2] + streamed_ms[3]) / 2.0);
}

#[cfg(unix)]
#[test]
fn cached_hit_rejects_permissions_widened_without_directory_mutation() {
	use std::os::unix::fs::PermissionsExt;
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let job = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &job);
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	assert_eq!(
		cache.lock().unwrap().hits.len(),
		usize::from(registry_has_content_watch(
			&registry_epoch(root.path()).unwrap()
		))
	);
	// Preserve previously verified strict history even when a watch is unavailable.
	read_verified_cached_record(root.path(), "same-job-id").unwrap();
	cache
		.lock()
		.unwrap()
		.known
		.get_mut(&("main".into(), "fixed-key".into()))
		.unwrap()
		.strict = true;
	let path = root.path().join("same-job-id.json");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	let error = find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		.unwrap_err()
		.to_string();
	assert!(error.contains("permissions unsafe"), "{error}");
}

#[test]
fn cached_read_refuses_symlink_hardlink_and_oversize_record() {
	use std::os::unix::fs::symlink;
	let external = tempfile::tempdir().unwrap();
	let root = tempfile::tempdir().unwrap();
	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(external.path(), &record);
	let link = root.path().join("same-job-id.json");

	symlink(external.path().join("same-job-id.json"), &link).unwrap();
	assert!(read_verified_cached_record(root.path(), "same-job-id")
		.unwrap_err()
		.to_string()
		.contains("unsafe"));
	std::fs::remove_file(&link).unwrap();
	fixture_write(root.path(), &record);
	assert_eq!(
		read_verified_cached_record(root.path(), "same-job-id")
			.unwrap()
			.id,
		record.id
	);
	std::fs::hard_link(&link, root.path().join("second-hardlink.bak")).unwrap();
	assert!(read_verified_cached_record(root.path(), "same-job-id")
		.unwrap_err()
		.to_string()
		.contains("unsafe"));
	std::fs::remove_file(root.path().join("second-hardlink.bak")).unwrap();
	std::fs::write(&link, vec![b'x'; (MAX_CACHED_RECORD_BYTES + 1) as usize]).unwrap();
	assert!(read_verified_cached_record(root.path(), "same-job-id")
		.unwrap_err()
		.to_string()
		.contains("unsafe"));
}

#[test]
fn cached_read_rejects_invalid_record_name() {
	let root = tempfile::tempdir().unwrap();
	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &record);
	assert!(read_verified_cached_record(root.path(), "bad/child").is_err());
	assert!(read_verified_cached_record(root.path(), "same-job-id").is_ok());
}

#[test]
fn streaming_lookup_matches_sorted_legacy_record_scan() {
	let root = tempfile::tempdir().unwrap();
	let template = outcome_fixture(ExecutionMode::Operator, false, "launched");
	for i in 0..128u32 {
		let mut record = template.clone();
		record.id = format!("fixture-stream-{i:04}");
		record.created_unix_ms = i as u128;
		record.idempotency_key = Some(format!("stream-key-{i:04}"));
		record.host = if i % 2 == 0 {
			"main".into()
		} else {
			"mac".into()
		};
		fixture_write(root.path(), &record);
	}
	for i in [0, 1, 16, 63, 126, 127] {
		let host = if i % 2 == 0 { "main" } else { "mac" };
		let key = format!("stream-key-{i:04}");
		let old = all_records_in(root.path())
			.unwrap()
			.into_iter()
			.find(|r| r.host == host && r.idempotency_key.as_deref() == Some(key.as_str()))
			.unwrap();
		let current = scan_idempotent_binding_in(root.path(), host, &key)
			.unwrap()
			.unwrap();
		assert_eq!(old.id, current.id);
	}
	assert!(
		scan_idempotent_binding_in(root.path(), "main", "never-created")
			.unwrap()
			.is_none()
	);
}

#[test]
fn streaming_scan_rejects_corruption_and_duplicate_bindings() {
	let root = tempfile::tempdir().unwrap();
	let mut record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &record);
	record.id = "second-id".into();
	fixture_write(root.path(), &record);
	assert!(scan_idempotent_binding_in(root.path(), "main", "fixed-key")
		.unwrap_err()
		.to_string()
		.contains("duplicate original"));
	std::fs::remove_file(root.path().join("second-id.json")).unwrap();
	std::fs::write(root.path().join("corrupt.json"), b"{not-json").unwrap();
	assert!(scan_idempotent_binding_in(root.path(), "main", "other")
		.unwrap_err()
		.to_string()
		.contains("corrupt job record"));
}

#[cfg(unix)]
#[test]
fn streaming_scan_rejects_post_enumeration_directory_mutation() {
	let root = tempfile::tempdir().unwrap();
	let old = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &old);
	assert!(
		scan_idempotent_binding_in(root.path(), "main", "never-accepted")
			.unwrap()
			.is_none()
	);

	let mut inserted = old.clone();
	inserted.id = "newly-written-job".into();
	inserted.idempotency_key = Some("never-accepted".into());
	let rejected =
		scan_idempotent_binding_in_with_observer(root.path(), "main", "never-accepted", || {
			// This runs AFTER complete enumeration, BEFORE the authoritative
			// directory epoch comparison. It is not an unreliable race test.
			std::thread::sleep(Duration::from_millis(5));
			fixture_write(root.path(), &inserted);
		})
		.unwrap_err()
		.to_string();
	assert!(
		rejected.contains("registry changed during scan"),
		"{rejected}"
	);
	let accepted = scan_idempotent_binding_in(root.path(), "main", "never-accepted")
		.unwrap()
		.unwrap();
	assert_eq!(accepted.id, inserted.id);

	let mut duplicate = inserted.clone();
	duplicate.id = "second-conflicting-id".into();
	let rejected_existing =
		scan_idempotent_binding_in_with_observer(root.path(), "main", "never-accepted", || {
			std::thread::sleep(Duration::from_millis(5));
			fixture_write(root.path(), &duplicate);
		})
		.unwrap_err()
		.to_string();
	assert!(
		rejected_existing.contains("registry changed during scan"),
		"{rejected_existing}"
	);
	assert!(
		scan_idempotent_binding_in(root.path(), "main", "never-accepted")
			.unwrap_err()
			.to_string()
			.contains("duplicate original")
	);
}

#[cfg(unix)]
#[test]
fn streaming_retry_returns_inserted_original_instead_of_stale_miss() {
	let root = tempfile::tempdir().unwrap();
	let original = outcome_fixture(ExecutionMode::Operator, false, "launched");
	let mut scans = 0;
	let found =
		scan_idempotent_binding_in_with_retries(root.path(), "main", "fixed-key", |attempt| {
			scans += 1;
			if attempt == 0 {
				std::thread::sleep(Duration::from_millis(5));
				fixture_write(root.path(), &original);
			}
		})
		.unwrap()
		.unwrap();
	assert_eq!(found.id, original.id);
	assert_eq!(scans, 2, "a changed first scan must be fully repeated");
}

#[cfg(unix)]
#[test]
fn streaming_retry_tolerates_independent_host_atomic_publication() {
	let root = tempfile::tempdir().unwrap();
	let original = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &original);
	let mut other = original.clone();
	other.id = "mac-concurrent-job".into();
	other.host = "mac".into();
	other.idempotency_key = Some("mac-new-key".into());
	let writer_dir = root.path().to_path_buf();
	let (scan_done_tx, scan_done_rx) = std::sync::mpsc::channel();
	let (published_tx, published_rx) = std::sync::mpsc::channel();
	let writer = std::thread::spawn(move || {
		scan_done_rx.recv().unwrap();
		std::thread::sleep(Duration::from_millis(5));
		let stage = writer_dir.join("mac-concurrent-job.stage");
		std::fs::write(&stage, serde_json::to_vec(&other).unwrap()).unwrap();
		std::fs::rename(stage, writer_dir.join("mac-concurrent-job.json")).unwrap();
		published_tx.send(()).unwrap();
	});
	let mut scans = 0;
	let found =
		scan_idempotent_binding_in_with_retries(root.path(), "main", "main-new-key", |attempt| {
			scans += 1;
			if attempt == 0 {
				scan_done_tx.send(()).unwrap();
				published_rx.recv().unwrap();
			}
		})
		.unwrap();
	writer.join().unwrap();
	assert!(found.is_none());
	assert_eq!(scans, 2);
	assert_eq!(
		scan_idempotent_binding_in(root.path(), "mac", "mac-new-key")
			.unwrap()
			.unwrap()
			.id,
		"mac-concurrent-job"
	);
}

#[cfg(unix)]
#[test]
fn streaming_retry_budget_refuses_sustained_membership_churn() {
	let root = tempfile::tempdir().unwrap();
	let mut scans = 0;
	let error =
		scan_idempotent_binding_in_with_retries(root.path(), "main", "unaccepted", |attempt| {
			scans += 1;
			let mut other = outcome_fixture(ExecutionMode::Operator, false, "launched");
			other.id = format!("mac-churn-{attempt}");
			other.host = "mac".into();
			other.idempotency_key = Some(format!("mac-key-{attempt}"));
			std::thread::sleep(Duration::from_millis(5));
			fixture_write(root.path(), &other);
		})
		.unwrap_err();
	assert_eq!(scans, MAX_IDEMPOTENCY_SCAN_ATTEMPTS);
	assert!(error.downcast_ref::<RegistryScanChanged>().is_some());
}

#[cfg(unix)]
#[test]
fn streaming_retry_does_not_mask_corruption_or_duplicate_bindings() {
	for corruption in [false, true] {
		let root = tempfile::tempdir().unwrap();
		let original = outcome_fixture(ExecutionMode::Operator, false, "launched");
		fixture_write(root.path(), &original);
		let mut scans = 0;
		let error =
			scan_idempotent_binding_in_with_retries(root.path(), "main", "fixed-key", |_| {
				scans += 1;
				std::thread::sleep(Duration::from_millis(5));
				if corruption {
					std::fs::write(root.path().join("broken.json"), b"not-json").unwrap();
				} else {
					let mut duplicate = original.clone();
					duplicate.id = "conflicting-original".into();
					fixture_write(root.path(), &duplicate);
				}
			})
			.unwrap_err();
		assert_eq!(
			scans, 1,
			"invalid history must stop before another observer"
		);
		assert!(error.to_string().contains(if corruption {
			"corrupt job record"
		} else {
			"duplicate original"
		}));
		assert!(error.downcast_ref::<RegistryScanChanged>().is_none());
	}
}

#[cfg(unix)]
#[test]
fn streaming_retry_refuses_root_replacement_and_permission_changes() {
	use std::os::unix::fs::PermissionsExt;
	for replacement in [false, true] {
		let root = tempfile::tempdir().unwrap();
		let jobs = root.path().join("jobs");
		std::fs::create_dir(&jobs).unwrap();
		std::fs::set_permissions(&jobs, std::fs::Permissions::from_mode(0o700)).unwrap();
		let mut scans = 0;
		let error = scan_idempotent_binding_in_with_retries(&jobs, "main", "unaccepted", |_| {
			scans += 1;
			if replacement {
				std::fs::rename(&jobs, root.path().join("original-jobs")).unwrap();
				std::fs::create_dir(&jobs).unwrap();
				std::fs::set_permissions(&jobs, std::fs::Permissions::from_mode(0o700)).unwrap();
			} else {
				std::fs::set_permissions(&jobs, std::fs::Permissions::from_mode(0o755)).unwrap();
			}
		})
		.unwrap_err();
		assert_eq!(scans, 1, "root changes are not ordinary membership churn");
		assert!(error.to_string().contains("root identity changed"));
		assert!(error.downcast_ref::<RegistryScanChanged>().is_none());
	}
}

#[cfg(unix)]
#[test]
fn saturated_reuse_cache_never_admits_untracked_hits_or_evicts_known_bindings() {
	let root = tempfile::tempdir().unwrap();
	let original = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &original);
	let mut full = ReuseHitCache::default();
	full.known.insert(
		("main".into(), "fixed-key".into()),
		KnownReuseBinding {
			id: original.id.clone(),
			strict: false,
		},
	);
	for i in 1..MAX_REUSE_HITS {
		full.known.insert(
			("main".into(), format!("old-key-{i}")),
			KnownReuseBinding {
				id: format!("old-id-{i}"),
				strict: false,
			},
		);
	}
	let cache = Mutex::new(full);
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	let mut newer = original.clone();
	newer.id = "uncached-original".into();
	newer.idempotency_key = Some("newer-key".into());
	std::thread::sleep(Duration::from_millis(5));
	fixture_write(root.path(), &newer);
	let found = find_idempotent_in(root.path(), "main", "newer-key", &cache)
		.unwrap()
		.unwrap();
	assert_eq!(
		found.id, newer.id,
		"full scans still return the actual original"
	);
	{
		let guard = cache.lock().unwrap();
		assert_eq!(guard.known.len(), MAX_REUSE_HITS);
		assert!(!guard
			.known
			.contains_key(&("main".into(), "newer-key".into())));
		assert!(!guard
			.hits
			.contains_key(&("main".into(), "newer-key".into())));
		assert!(guard.hits.iter().all(|(identity, id)| guard
			.known
			.get(identity)
			.map(|binding| &binding.id)
			== Some(id)));
	}
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	assert_eq!(
		cache
			.lock()
			.unwrap()
			.hits
			.contains_key(&("main".into(), "fixed-key".into())),
		registry_has_content_watch(&registry_epoch(root.path()).unwrap())
	);
	std::fs::remove_file(root.path().join("same-job-id.json")).unwrap();
	assert!(find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		.unwrap_err()
		.to_string()
		.contains("previous idempotency binding"));
}

#[cfg(unix)]
#[test]
fn cached_hit_without_known_ownership_refuses_reuse() {
	let root = tempfile::tempdir().unwrap();
	let original = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &original);
	let cache = Mutex::new(ReuseHitCache::default());
	find_idempotent_in(root.path(), "main", "fixed-key", &cache).unwrap();
	cache.lock().unwrap().known.clear();
	let watched = registry_has_content_watch(&registry_epoch(root.path()).unwrap());
	if !watched {
		// With no positive hit, full history still has to be verified.
		std::fs::write(root.path().join("damaged.json"), b"not-json").unwrap();
	}
	let error = find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		.unwrap_err()
		.to_string();
	let expected = if watched {
		"lost original ownership"
	} else {
		"corrupt job record"
	};
	assert!(error.contains(expected), "{error}");
}

#[cfg(unix)]
#[test]
fn known_cache_refuses_changed_root_before_unknown_key_lookup() {
	let root = tempfile::tempdir().unwrap();
	let jobs = root.path().join("jobs");
	std::fs::create_dir(&jobs).unwrap();
	let original = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(&jobs, &original);
	let cache = Mutex::new(ReuseHitCache::default());
	find_idempotent_in(&jobs, "main", "fixed-key", &cache).unwrap();
	std::fs::rename(&jobs, root.path().join("original-jobs")).unwrap();
	std::fs::create_dir(&jobs).unwrap();
	assert!(find_idempotent_in(&jobs, "main", "new-key", &cache)
		.unwrap_err()
		.to_string()
		.contains("root identity changed"));
}

#[tokio::test]
async fn confirmed_reuse_status_wait_releases_same_host_start_lock() {
	let lock = start_lock("hepta-fixture-confirmed-reuse", Some("same-key")).unwrap();
	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	for unavailable in [false, true] {
		let mut guard = Some(lock.lock().await);
		let status = read_reuse_status(&record, false, &mut guard, async {
			tokio::task::yield_now().await;
			let admitted = lock
				.try_lock()
				.expect("status observation must not block a same-host start");
			drop(admitted);
			if unavailable {
				bail!("private upstream diagnostic")
			}
			Ok(json!({"job_id":record.id,"state":"exited"}))
		})
		.await;
		assert!(guard.is_none());
		assert_eq!(status["job_id"], record.id);
		if unavailable {
			assert_eq!(status["state"], "status_unavailable");
			assert_eq!(status["automatic_retry"], false);
			assert!(!status.to_string().contains("private upstream diagnostic"));
		} else {
			assert_eq!(status["state"], "exited");
		}
	}
}

#[tokio::test]
async fn uncertain_or_retried_reuse_keeps_start_lock_during_status_wait() {
	let lock = start_lock("hepta-fixture-uncertain-reuse", Some("same-key")).unwrap();
	for (state, retry) in [
		("pending", false),
		("unknown", false),
		("launch_failed", true),
		("launched", true),
	] {
		let record = outcome_fixture(ExecutionMode::Operator, false, state);
		let mut guard = Some(lock.lock().await);
		read_reuse_status(&record, retry, &mut guard, async {
			tokio::task::yield_now().await;
			assert!(
				lock.try_lock().is_err(),
				"uncertain/retried identity must remain serialized"
			);
			Ok(json!({"job_id":record.id,"state":"observed"}))
		})
		.await;
		assert!(guard.is_some());
	}
}

#[cfg(unix)]
#[test]
fn registry_gate_parallel_scans_survive_local_pending_and_outcome_publication() {
	use std::sync::mpsc::{channel, RecvTimeoutError};
	let root = tempfile::tempdir().unwrap();
	let gate = Arc::new(RwLock::new(()));
	let mut prior = outcome_fixture(ExecutionMode::Operator, false, "pending");
	prior.id = "prior-pending-job".into();
	fixture_write(root.path(), &prior);
	let (enumerated_tx, enumerated_rx) = channel();
	let mut releases = Vec::new();
	let mut workers = Vec::new();
	for host in ["main", "rog", "ai395", "pocket4", "x230", "mac"] {
		let dir = root.path().to_path_buf();
		let worker_gate = gate.clone();
		let enumerated = enumerated_tx.clone();
		let (release_tx, release_rx) = channel();
		releases.push(release_tx);
		workers.push(std::thread::spawn(move || {
			let key = format!("new-{host}");
			let mut scans = 0;
			let found = with_registry_read(&worker_gate, || {
				scan_idempotent_binding_in_with_retries(&dir, host, &key, |_| {
					scans += 1;
					enumerated.send(host).unwrap();
					release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
				})
			})?;
			assert!(found.is_none());
			let mut record = outcome_fixture(ExecutionMode::Operator, false, "pending");
			record.id = format!("new-job-{host}");
			record.host = host.into();
			record.idempotency_key = Some(key);
			let path = dir.join(format!("{}.json", record.id));
			save_record_with_registry_gate(&record, &worker_gate, || Ok(path.clone()))?;
			let outcome = preserve_launch_outcome(
				&mut record,
				Ok(json!({"ok":true,"backend":"detached","launcher_pid":321})),
				|record| save_record_with_registry_gate(record, &worker_gate, || Ok(path)),
			);
			assert!(!outcome.local_record_pending);
			Ok::<_, anyhow::Error>((record.id, scans))
		}));
	}
	drop(enumerated_tx);
	// All six must finish real enumeration before any is released. An exclusive
	// scan mutex would fail this handshake instead of preserving parallel reads.
	let mut observed = Vec::new();
	for _ in 0..6 {
		observed.push(enumerated_rx.recv_timeout(Duration::from_secs(10)).unwrap());
	}
	let stable = registry_epoch(root.path()).unwrap();
	let (attempt_tx, attempt_rx) = channel();
	let (acquired_tx, acquired_rx) = channel();
	let writer_gate = gate.clone();
	let prior_path = root.path().join("prior-pending-job.json");
	let writer = std::thread::spawn(move || {
		attempt_tx.send(()).unwrap();
		preserve_launch_outcome(
			&mut prior,
			Ok(json!({"ok":true,"backend":"detached","launcher_pid":322})),
			|record| {
				save_record_with_registry_gate(record, &writer_gate, || {
					acquired_tx.send(()).unwrap();
					Ok(prior_path)
				})
			},
		)
	});
	attempt_rx.recv_timeout(Duration::from_secs(10)).unwrap();
	let blocked = acquired_rx.recv_timeout(Duration::from_millis(100));
	let unchanged = registry_epoch(root.path()).unwrap() == stable;
	// Release and join before asserting the negative observation, so failures
	// cannot leave a publisher blocked behind a test-owned read guard.
	for release in releases {
		release.send(()).unwrap();
	}
	let results: Vec<_> = workers
		.into_iter()
		.map(|worker| worker.join().unwrap())
		.collect();
	let prior_outcome = writer.join().unwrap();
	assert!(matches!(blocked, Err(RecvTimeoutError::Timeout)));
	assert!(
		unchanged,
		"a local publication must not mutate a live scan epoch"
	);
	assert!(!prior_outcome.local_record_pending);
	observed.sort_unstable();
	observed.dedup();
	assert_eq!(observed.len(), 6);
	for result in results {
		let (id, scans) = result.unwrap();
		assert_eq!(
			scans, 1,
			"local publishers must not consume epoch retry attempts"
		);
		let saved: JobRecord =
			serde_json::from_slice(&std::fs::read(root.path().join(format!("{id}.json"))).unwrap())
				.unwrap();
		assert_eq!(saved.id, id);
		assert_eq!(saved.launch_state, "launched");
	}
	let saved_prior: JobRecord =
		serde_json::from_slice(&std::fs::read(root.path().join("prior-pending-job.json")).unwrap())
			.unwrap();
	assert_eq!(saved_prior.launch_state, "launched");
}

#[cfg(unix)]
#[test]
fn registry_gate_cached_lookup_waits_for_actual_outcome_replacement() {
	use std::sync::mpsc::{channel, RecvTimeoutError};
	let root = tempfile::tempdir().unwrap();
	let gate = Arc::new(RwLock::new(()));
	let cache = Arc::new(Mutex::new(ReuseHitCache::default()));
	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	let path = root.path().join(format!("{}.json", record.id));
	save_record_with_registry_gate(&record, &gate, || Ok(path.clone())).unwrap();
	with_registry_read(&gate, || {
		find_idempotent_in(root.path(), "main", "fixed-key", &cache)
	})
	.unwrap()
	.unwrap();
	assert_eq!(
		cache.lock().unwrap().hits.len(),
		usize::from(registry_has_content_watch(
			&registry_epoch(root.path()).unwrap()
		))
	);
	let (writer_inside_tx, writer_inside_rx) = channel();
	let (release_tx, release_rx) = channel();
	let writer_gate = gate.clone();
	let mut changed = record.clone();
	let writer = std::thread::spawn(move || {
		preserve_launch_outcome(
			&mut changed,
			Err(anyhow::anyhow!("unknown launch reply")),
			|record| {
				save_record_with_registry_gate(record, &writer_gate, || {
					writer_inside_tx.send(()).unwrap();
					release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
					Ok(path)
				})
			},
		)
	});
	writer_inside_rx
		.recv_timeout(Duration::from_secs(10))
		.unwrap();
	let (attempt_tx, attempt_rx) = channel();
	let (result_tx, result_rx) = channel();
	let reader_gate = gate.clone();
	let reader_cache = cache.clone();
	let dir = root.path().to_path_buf();
	let reader = std::thread::spawn(move || {
		attempt_tx.send(()).unwrap();
		let found = with_registry_read(&reader_gate, || {
			find_idempotent_in(&dir, "main", "fixed-key", &reader_cache)
		});
		result_tx.send(found).unwrap();
	});
	attempt_rx.recv_timeout(Duration::from_secs(10)).unwrap();
	let before_publication = result_rx.recv_timeout(Duration::from_millis(100));
	release_tx.send(()).unwrap();
	let outcome = writer.join().unwrap();
	reader.join().unwrap();
	assert!(
		matches!(before_publication, Err(RecvTimeoutError::Timeout)),
		"even a populated positive cache must wait for a local writer"
	);
	assert!(!outcome.local_record_pending);
	let found = result_rx
		.recv_timeout(Duration::from_secs(10))
		.unwrap()
		.unwrap()
		.unwrap();
	assert_eq!(found.id, record.id);
	assert_eq!(found.launch_state, "launch_unknown");
	assert!(cache.lock().unwrap().hits.is_empty());
}

#[cfg(unix)]
#[test]
fn registry_gate_preserves_external_epoch_and_integrity_refusals() {
	let root = tempfile::tempdir().unwrap();
	let gate = RwLock::new(());
	let mut scans = 0;
	let error = with_registry_read(&gate, || {
		scan_idempotent_binding_in_with_retries(root.path(), "main", "unaccepted", |attempt| {
			scans += 1;
			let mut external = outcome_fixture(ExecutionMode::Operator, false, "launched");
			external.id = format!("external-writer-{attempt}");
			external.host = "mac".into();
			external.idempotency_key = Some(format!("external-key-{attempt}"));
			// Deliberately bypass the process-local gate, like another process.
			std::thread::sleep(Duration::from_millis(5));
			fixture_write(root.path(), &external);
		})
	})
	.unwrap_err();
	assert_eq!(scans, MAX_IDEMPOTENCY_SCAN_ATTEMPTS);
	assert!(error.downcast_ref::<RegistryScanChanged>().is_some());
	for corrupt in [false, true] {
		let root = tempfile::tempdir().unwrap();
		let cache = Mutex::new(ReuseHitCache::default());
		let original = outcome_fixture(ExecutionMode::Operator, false, "launched");
		fixture_write(root.path(), &original);
		if corrupt {
			std::fs::write(root.path().join("corrupt.json"), b"not-json").unwrap();
		} else {
			let mut duplicate = original.clone();
			duplicate.id = "conflicting-original".into();
			fixture_write(root.path(), &duplicate);
		}
		let error = with_registry_read(&gate, || {
			find_idempotent_in(root.path(), "main", "fixed-key", &cache)
		})
		.unwrap_err();
		assert!(error.to_string().contains(if corrupt {
			"corrupt job record"
		} else {
			"duplicate original"
		}));
		assert!(cache.lock().unwrap().hits.is_empty());
	}
}

#[cfg(unix)]
#[test]
fn registry_gate_poison_refuses_cached_lookup_and_record_publication() {
	let root = tempfile::tempdir().unwrap();
	let gate = Arc::new(RwLock::new(()));
	let cache = Mutex::new(ReuseHitCache::default());
	let record = outcome_fixture(ExecutionMode::Operator, false, "launched");
	fixture_write(root.path(), &record);
	with_registry_read(&gate, || {
		find_idempotent_in(root.path(), "main", "fixed-key", &cache)
	})
	.unwrap()
	.unwrap();
	assert_eq!(
		cache.lock().unwrap().hits.len(),
		usize::from(registry_has_content_watch(
			&registry_epoch(root.path()).unwrap()
		))
	);
	let poisoned = gate.clone();
	assert!(std::thread::spawn(move || {
		let _write = poisoned.write().unwrap();
		panic!("fixture poisons an incomplete registry publication");
	})
	.join()
	.is_err());
	let error = with_registry_read(&gate, || {
		find_idempotent_in(root.path(), "main", "fixed-key", &cache)
	})
	.unwrap_err();
	assert!(error.to_string().contains("registry read lock unavailable"));
	let mut path_evaluated = false;
	let error = save_record_with_registry_gate(&record, &gate, || {
		path_evaluated = true;
		Ok(root.path().join("must-not-be-published.json"))
	})
	.unwrap_err();
	assert!(error
		.to_string()
		.contains("registry write lock unavailable"));
	assert!(!path_evaluated, "writer refusal must precede path creation");
	assert!(!root.path().join("must-not-be-published.json").exists());
}

fn observation_audit_fixture(root: &Path, subject: &str) -> PreparedAudit {
	prepare_audit_at(
		root.join("audit/events.jsonl"),
		"process_status",
		"original-host",
		subject,
		&json!({"phase":"observation","ok":true}),
	)
	.unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn observation_audit_releases_the_executor_but_waits_for_the_real_sync_barrier() {
	let root = tempfile::tempdir().unwrap();
	let slots = Arc::new(Semaphore::new(MAX_OBSERVATION_AUDITS));
	let caller_thread = std::thread::current().id();
	let mut host = "original-host".to_owned();
	let mut phase = json!({"phase":"observation","ok":true});
	let prepared = prepare_audit_at(
		root.path().join("audit/events.jsonl"),
		"process_read",
		&host,
		"original-job",
		&phase,
	)
	.unwrap();
	let frozen = prepared.line.clone();
	let frozen_path = prepared.path.clone();
	host.push_str("-changed-after-preparation");
	phase["phase"] = json!("changed-after-preparation");
	let original = json!({"job_id":"original-job","caller_request":"original-caller",
		"stdout":{"text":"retained-output","offset":5,"next_offset":20,"eof":true}});
	let expected = original.clone();
	let (entered, started) = tokio::sync::oneshot::channel();
	let (release, barrier) = std::sync::mpsc::channel();
	let audit_slots = slots.clone();
	let task = tokio::spawn(async move {
		let completion = run_observation_audit(prepared, audit_slots, move |event| {
			append_audit_with(event, |file| {
				entered
					.send(std::thread::current().id())
					.map_err(|_| anyhow::anyhow!("sync test observer disappeared"))?;
				// A broken implementation must fail this test instead of hanging
				// the single runtime thread or holding the global audit lock forever.
				barrier.recv_timeout(Duration::from_secs(10))?;
				file.sync_data()?;
				Ok(())
			})
		})
		.await;
		retain_observation_after_audit(original, completion, "original-host", "original-job")
	});
	let worker_thread = tokio::time::timeout(Duration::from_secs(3), started)
		.await
		.unwrap()
		.unwrap();
	assert_ne!(worker_thread, caller_thread);
	assert!(
		!task.is_finished(),
		"a written line is not a durable acknowledgement"
	);
	assert_eq!(slots.available_permits(), MAX_OBSERVATION_AUDITS - 1);
	tokio::time::timeout(Duration::from_secs(3), async {
		tokio::task::yield_now().await;
		tokio::time::sleep(Duration::from_millis(1)).await;
	})
	.await
	.expect("the observation audit must not block the single executor thread");
	assert!(!task.is_finished());
	assert_eq!(std::fs::read(&frozen_path).unwrap(), frozen);
	let stored: Value = serde_json::from_slice(&frozen).unwrap();
	assert_eq!(stored["host"], "original-host");
	assert_eq!(stored["subject"], "original-job");
	assert_eq!(stored["action"], "process_read");
	assert_eq!(stored["outcome"]["phase"], "observation");
	assert!(stored["at_unix_ms"].as_u64().is_some());
	assert_ne!(stored["host"], host);
	assert_ne!(stored["outcome"], phase);
	release.send(()).unwrap();
	let retained = tokio::time::timeout(Duration::from_secs(3), task)
		.await
		.unwrap()
		.unwrap();
	assert_eq!(retained["audit_recorded"], true);
	for (key, value) in expected.as_object().unwrap() {
		assert_eq!(&retained[key], value);
	}
	assert_eq!(slots.available_permits(), MAX_OBSERVATION_AUDITS);
}

struct ActiveObservationAudit(Arc<std::sync::atomic::AtomicUsize>);
impl Drop for ActiveObservationAudit {
	fn drop(&mut self) {
		self.0.fetch_sub(1, Ordering::SeqCst);
	}
}

#[tokio::test(flavor = "current_thread")]
async fn observation_audit_cancellation_keeps_the_worker_permit_and_the_eight_task_bound() {
	use std::sync::atomic::{AtomicBool, AtomicUsize};
	let root = tempfile::tempdir().unwrap();
	let slots = Arc::new(Semaphore::new(MAX_OBSERVATION_AUDITS));
	let active = Arc::new(AtomicUsize::new(0));
	let maximum = Arc::new(AtomicUsize::new(0));
	let mut tasks = Vec::new();
	let mut releases = Vec::new();
	let mut starts = Vec::new();
	for number in 0..MAX_OBSERVATION_AUDITS {
		let prepared = observation_audit_fixture(root.path(), &format!("job-{number}"));
		let (entered, started) = tokio::sync::oneshot::channel();
		let (release, barrier) = std::sync::mpsc::channel();
		let counter = active.clone();
		let peak = maximum.clone();
		tasks.push(tokio::spawn(run_observation_audit(
			prepared,
			slots.clone(),
			move |event| {
				let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
				let _active = ActiveObservationAudit(counter);
				peak.fetch_max(count, Ordering::SeqCst);
				entered
					.send(())
					.map_err(|_| anyhow::anyhow!("capacity test observer disappeared"))?;
				barrier.recv_timeout(Duration::from_secs(10))?;
				append_audit(event)
			},
		)));
		releases.push(release);
		starts.push(started);
	}
	for started in starts {
		tokio::time::timeout(Duration::from_secs(3), started)
			.await
			.unwrap()
			.unwrap();
	}
	assert_eq!(active.load(Ordering::SeqCst), MAX_OBSERVATION_AUDITS);
	assert_eq!(slots.available_permits(), 0);
	let (entered, mut ninth_started) = tokio::sync::oneshot::channel();
	let counter = active.clone();
	let peak = maximum.clone();
	let ninth = tokio::spawn(run_observation_audit(
		observation_audit_fixture(root.path(), "ninth-job"),
		slots.clone(),
		move |event| {
			let count = counter.fetch_add(1, Ordering::SeqCst) + 1;
			let _active = ActiveObservationAudit(counter);
			peak.fetch_max(count, Ordering::SeqCst);
			entered
				.send(())
				.map_err(|_| anyhow::anyhow!("ninth test observer disappeared"))?;
			append_audit(event)
		},
	));
	let waiting_started = Arc::new(AtomicBool::new(false));
	let unexpected = waiting_started.clone();
	let waiting = tokio::spawn(run_observation_audit(
		observation_audit_fixture(root.path(), "cancelled-before-submission"),
		slots.clone(),
		move |event| {
			unexpected.store(true, Ordering::SeqCst);
			append_audit(event)
		},
	));
	tokio::task::yield_now().await;
	assert!(matches!(
		ninth_started.try_recv(),
		Err(tokio::sync::oneshot::error::TryRecvError::Empty)
	));
	waiting.abort();
	assert!(waiting.await.unwrap_err().is_cancelled());
	let cancelled_waiter = tasks.remove(0);
	cancelled_waiter.abort();
	assert!(cancelled_waiter.await.unwrap_err().is_cancelled());
	tokio::task::yield_now().await;
	assert_eq!(slots.available_permits(), 0);
	assert_eq!(active.load(Ordering::SeqCst), MAX_OBSERVATION_AUDITS);
	assert!(!waiting_started.load(Ordering::SeqCst));
	assert!(matches!(
		ninth_started.try_recv(),
		Err(tokio::sync::oneshot::error::TryRecvError::Empty)
	));
	releases.remove(0).send(()).unwrap();
	tokio::time::timeout(Duration::from_secs(3), &mut ninth_started)
		.await
		.unwrap()
		.unwrap();
	tokio::time::timeout(Duration::from_secs(3), ninth)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
	for release in releases {
		release.send(()).unwrap();
	}
	for task in tasks {
		tokio::time::timeout(Duration::from_secs(3), task)
			.await
			.unwrap()
			.unwrap()
			.unwrap();
	}
	// The cancelled outer future detached its blocking task. Drain every permit
	// before dropping the filesystem fixture, including that detached worker.
	let drained = tokio::time::timeout(
		Duration::from_secs(3),
		slots
			.clone()
			.acquire_many_owned(MAX_OBSERVATION_AUDITS as u32),
	)
	.await
	.unwrap()
	.unwrap();
	drop(drained);
	assert_eq!(slots.available_permits(), MAX_OBSERVATION_AUDITS);
	assert_eq!(active.load(Ordering::SeqCst), 0);
	assert_eq!(maximum.load(Ordering::SeqCst), MAX_OBSERVATION_AUDITS);
	let rows = std::fs::read_to_string(root.path().join("audit/events.jsonl")).unwrap();
	let rows: Vec<Value> = rows
		.lines()
		.map(|line| serde_json::from_str(line).unwrap())
		.collect();
	assert_eq!(rows.len(), MAX_OBSERVATION_AUDITS + 1);
	assert!(rows.iter().any(|row| row["subject"] == "job-0"));
	assert!(rows.iter().any(|row| row["subject"] == "ninth-job"));
	assert!(!rows
		.iter()
		.any(|row| row["subject"] == "cancelled-before-submission"));
}

#[tokio::test(flavor = "current_thread")]
async fn observation_audit_append_sync_panic_and_closed_capacity_preserve_results_and_redact_errors(
) {
	for original in [
		json!({"job_id":"original-job","caller_request":"caller-a","state":"succeeded","exit_code":0}),
		json!({"job_id":"original-job","caller_request":"caller-b","state":"running","pid":1234}),
		json!({"job_id":"original-job","caller_request":"caller-c","stdout":{"text":"original-output","offset":7,"next_offset":22,"eof":true}}),
	] {
		for failure in 0..4 {
			let root = tempfile::tempdir().unwrap();
			let slots = Arc::new(Semaphore::new(MAX_OBSERVATION_AUDITS));
			let prepared = if failure == 0 {
				let blocked = root.path().join("PRIVATE_AUDIT_SECRET");
				std::fs::write(&blocked, b"not a directory").unwrap();
				prepare_audit_at(
					blocked.join("events.jsonl"),
					"process_status",
					"original-host",
					"original-job",
					&json!({"phase":"observation","ok":true}),
				)
				.unwrap()
			} else {
				observation_audit_fixture(root.path(), "original-job")
			};
			if failure == 3 {
				slots.close();
			}
			let completion =
				run_observation_audit(prepared, slots.clone(), move |event| match failure {
					0 => append_audit(event).context("PRIVATE_AUDIT_SECRET"),
					1 => append_audit_with(event, |_file| {
						Err(anyhow::anyhow!(
							"PRIVATE_AUDIT_SECRET: injected sync failure"
						))
					}),
					2 => std::panic::panic_any(("PRIVATE_AUDIT_SECRET", 17_u32)),
					_ => panic!("closed observation capacity must not submit a blocking task"),
				})
				.await;
			let error = completion.as_ref().unwrap_err();
			assert_eq!(
				error.to_string(),
				"Existing job observation completion audit unavailable"
			);
			assert!(!format!("{error:#}").contains("PRIVATE_AUDIT_SECRET"));
			assert!(error.source().is_none());
			let retained = retain_observation_after_audit(
				original.clone(),
				completion,
				"original-host",
				"original-job",
			);
			for (key, value) in original.as_object().unwrap() {
				assert_eq!(&retained[key], value);
			}
			assert_eq!(retained["audit_recorded"], false);
			assert_eq!(
				retained["audit_warning"],
				"Existing job observation retained; audit unavailable. No new job was launched."
			);
			assert!(!retained.to_string().contains("PRIVATE_AUDIT_SECRET"));
			assert_eq!(slots.available_permits(), MAX_OBSERVATION_AUDITS);
		}
	}
}

#[cfg(unix)]
fn publication_fixture(path: &Path, sequence: usize) -> PreparedAudit {
	prepare_audit_at(
		path.to_path_buf(),
		"process_status",
		"fixed-host",
		"fixed-job",
		&json!({"sequence":sequence}),
	)
	.unwrap()
}

#[cfg(unix)]
fn publication_append(
	path: &Path,
	sequence: usize,
	ready: &mut Option<AuditReadiness>,
) -> Vec<(bool, (u64, u64))> {
	let operations = std::cell::RefCell::new(Vec::new());
	append_audit_at_with(
		publication_fixture(path, sequence),
		ready,
		|file| {
			file.sync_data()?;
			operations
				.borrow_mut()
				.push((false, audit_inode(&file.metadata()?)));
			Ok(())
		},
		|directory| {
			directory.sync_all()?;
			operations
				.borrow_mut()
				.push((true, audit_inode(&directory.metadata()?)));
			Ok(())
		},
	)
	.unwrap();
	operations.into_inner()
}

#[cfg(unix)]
fn publication_expected_warm_operations(ready: &Option<AuditReadiness>) -> usize {
	let binding = &ready.as_ref().unwrap().binding;
	if audit_reliable_generation(&binding.stamps) {
		return 1;
	}
	let mut count = 1;
	binding
		.synchronize_directories(&mut |_| {
			count += 1;
			Ok(())
		})
		.unwrap();
	count
}

#[cfg(unix)]
#[test]
fn audit_publication_syncs_real_file_then_parents_and_keeps_warm_file_barrier() {
	let root = tempfile::tempdir().unwrap();
	let audit = root.path().join("audit");
	std::fs::create_dir(&audit).unwrap();
	let path = audit.join("events.jsonl");
	let mut ready = None;
	let expected = publication_fixture(&path, 1);
	let frozen = expected.line.clone();
	let operations = std::cell::RefCell::new(Vec::new());
	append_audit_at_with(
		expected,
		&mut ready,
		|file| {
			file.sync_data()?;
			operations.borrow_mut().push("file");
			Ok(())
		},
		|directory| {
			directory.sync_all()?;
			operations.borrow_mut().push(
				if audit_inode(&directory.metadata()?) == audit_inode(&std::fs::metadata(&audit)?) {
					"audit"
				} else {
					"state"
				},
			);
			Ok(())
		},
	)
	.unwrap();
	assert_eq!(operations.into_inner(), ["file", "audit", "state"]);
	assert_eq!(std::fs::read(&path).unwrap(), frozen);
	assert!(ready.is_some());
	for sequence in 2..5 {
		let expected = publication_expected_warm_operations(&ready);
		let operations = publication_append(&path, sequence, &mut ready);
		assert_eq!(operations.len(), expected);
		assert_eq!(
			operations[0],
			(false, audit_inode(&std::fs::metadata(&path).unwrap()))
		);
		assert!(operations[1..].iter().all(|(directory, _)| *directory));
	}
	let rows: Vec<Value> = std::fs::read_to_string(&path)
		.unwrap()
		.lines()
		.map(|line| serde_json::from_str(line).unwrap())
		.collect();
	assert_eq!(rows.len(), 4);
	for (index, row) in rows.iter().enumerate() {
		assert_eq!(row["outcome"]["sequence"], index + 1);
	}
}

#[cfg(unix)]
#[test]
fn audit_publication_barrier_failures_clear_readiness_and_retry_the_full_order() {
	for failed_barrier in 0..3 {
		let root = tempfile::tempdir().unwrap();
		std::fs::create_dir(root.path().join("audit")).unwrap();
		let path = root.path().join("audit/events.jsonl");
		let mut ready = None;
		publication_append(&path, 0, &mut ready);
		// A namespace edit invalidates warm readiness without changing the file.
		std::fs::write(root.path().join("audit/external-entry"), b"external").unwrap();
		let step = std::cell::Cell::new(0usize);
		let error = append_audit_at_with(
			publication_fixture(&path, 1),
			&mut ready,
			|file| {
				file.sync_data()?;
				step.set(step.get() + 1);
				if failed_barrier == 0 {
					bail!("injected file barrier failure");
				}
				Ok(())
			},
			|directory| {
				directory.sync_all()?;
				let current = step.get();
				step.set(current + 1);
				if current == failed_barrier {
					bail!("injected directory barrier failure");
				}
				Ok(())
			},
		)
		.unwrap_err();
		assert!(error.to_string().contains("injected"));
		assert_eq!(step.get(), failed_barrier + 1);
		assert!(
			ready.is_none(),
			"a partial success must not remain a publication proof"
		);
		let retried = publication_append(&path, 2, &mut ready);
		assert_eq!(
			retried
				.iter()
				.map(|(directory, _)| *directory)
				.collect::<Vec<_>>(),
			[false, true, true]
		);
		let expected = publication_expected_warm_operations(&ready);
		assert_eq!(publication_append(&path, 3, &mut ready).len(), expected);
	}
}

#[cfg(unix)]
#[test]
fn audit_publication_warm_file_failure_also_discards_successful_directory_readiness() {
	let root = tempfile::tempdir().unwrap();
	std::fs::create_dir(root.path().join("audit")).unwrap();
	let path = root.path().join("audit/events.jsonl");
	let mut ready = None;
	publication_append(&path, 0, &mut ready);
	let error = append_audit_at_with(
		publication_fixture(&path, 1),
		&mut ready,
		|file| {
			file.sync_data()?;
			bail!("injected warm file failure")
		},
		|_| panic!("the warm append does not call directory sync before its file barrier"),
	)
	.unwrap_err();
	assert!(error.to_string().contains("injected"));
	assert!(ready.is_none());
	assert_eq!(publication_append(&path, 2, &mut ready).len(), 3);
}

#[cfg(unix)]
#[test]
fn audit_publication_file_parent_replacement_and_same_inode_relink_republish() {
	for replacement in 0..4 {
		let root = tempfile::tempdir().unwrap();
		let audit = root.path().join("audit");
		std::fs::create_dir(&audit).unwrap();
		let path = audit.join("events.jsonl");
		let mut ready = None;
		publication_append(&path, 0, &mut ready);
		let original_inode = audit_inode(&std::fs::metadata(&path).unwrap());
		match replacement {
			0 => {
				std::fs::rename(&path, audit.join("old-events")).unwrap();
			}
			1 => {
				std::fs::rename(&audit, root.path().join("old-audit")).unwrap();
				std::fs::create_dir(&audit).unwrap();
			}
			2 => {
				let retained = root.path().join("retained-hardlink");
				std::fs::hard_link(&path, &retained).unwrap();
				// Preserve the original proof across a same-inode unlink/relink
				// ABA, but never append while an outside hard link exists. The
				// adopted strict sink policy requires one link before publication.
				std::fs::remove_file(&path).unwrap();
				std::fs::hard_link(&retained, &path).unwrap();
				std::fs::remove_file(&retained).unwrap();
				assert_eq!(
					audit_inode(&std::fs::metadata(&path).unwrap()),
					original_inode
				);
			}
			3 => {
				std::fs::write(root.path().join("external-state-entry"), b"external").unwrap();
			}
			_ => unreachable!(),
		}
		let operations = publication_append(&path, 1, &mut ready);
		assert_eq!(
			operations.len(),
			3,
			"replacement or parent namespace change needs both parent barriers"
		);
		let expected = publication_expected_warm_operations(&ready);
		assert_eq!(publication_append(&path, 2, &mut ready).len(), expected);
	}
}

#[cfg(unix)]
#[test]
fn audit_publication_rejects_binding_changes_during_file_or_directory_barriers() {
	for during_file in [true, false] {
		let root = tempfile::tempdir().unwrap();
		let audit = root.path().join("audit");
		std::fs::create_dir(&audit).unwrap();
		let path = audit.join("events.jsonl");
		let mut ready = None;
		let change = || -> Result<()> {
			std::fs::rename(&path, audit.join("replaced"))?;
			std::fs::write(&path, b"replacement\n")?;
			Ok(())
		};
		let changed = std::cell::Cell::new(false);
		let error = append_audit_at_with(
			publication_fixture(&path, 0),
			&mut ready,
			|file| {
				file.sync_data()?;
				if during_file {
					change()?;
					changed.set(true);
				}
				Ok(())
			},
			|directory| {
				directory.sync_all()?;
				if !during_file && !changed.replace(true) {
					change()?;
				}
				Ok(())
			},
		)
		.unwrap_err();
		assert!(error.to_string().contains("binding changed"));
		assert!(ready.is_none());
		assert_eq!(std::fs::read(&path).unwrap(), b"replacement\n");
		assert_eq!(publication_append(&path, 1, &mut ready).len(), 3);
	}
}

#[cfg(unix)]
#[test]
fn audit_publication_denies_dangling_file_symlink_without_publishing_target() {
	use std::os::unix::fs::symlink;
	let root = tempfile::tempdir().unwrap();
	let state = root.path().join("state");
	let audit = state.join("audit");
	std::fs::create_dir_all(&audit).unwrap();
	let target = root.path().join("untouched-target");
	let path = audit.join("events.jsonl");
	symlink(&target, &path).unwrap();
	let mut ready = None;
	let result = append_audit_at_with(
		publication_fixture(&path, 0),
		&mut ready,
		|file| {
			file.sync_data()?;
			Ok(())
		},
		|directory| {
			directory.sync_all()?;
			Ok(())
		},
	);
	assert!(result.is_err());
	assert!(ready.is_none());
	assert!(!target.exists());
}

#[cfg(unix)]
#[test]
fn audit_publication_failure_prevents_intent_effect_and_retains_observation_output() {
	let root = tempfile::tempdir().unwrap();
	std::fs::create_dir(root.path().join("audit")).unwrap();
	let path = root.path().join("audit/events.jsonl");
	let mut ready = None;
	let effect = std::cell::Cell::new(false);
	let mut intent = || -> Result<()> {
		let outcome = append_audit_at_with(
			publication_fixture(&path, 0),
			&mut ready,
			|file| Ok(file.sync_data()?),
			|directory| {
				directory.sync_all()?;
				bail!("injected parent barrier /private-path")
			},
		);
		require_operation_intent(outcome)?;
		effect.set(true);
		Ok(())
	};
	let error = intent().unwrap_err();
	assert!(!effect.get());
	assert!(error.to_string().contains("no remote operation submitted"));
	assert!(!error.to_string().contains("private-path"));
	assert!(ready.is_none());
	let result = json!({"job_id":"original-job","state":"exited","stdout":{"text":"marker","offset":7,"next_offset":13,"eof":true}});
	let audit = append_audit_at_with(
		publication_fixture(&path, 1),
		&mut ready,
		|file| Ok(file.sync_data()?),
		|directory| {
			directory.sync_all()?;
			bail!("injected parent barrier")
		},
	);
	let retained =
		retain_observation_after_audit(result.clone(), audit, "fixed-host", "original-job");
	for (key, value) in result.as_object().unwrap() {
		assert_eq!(&retained[key], value);
	}
	assert_eq!(retained["audit_recorded"], false);
	assert!(retained["audit_warning"]
		.as_str()
		.unwrap()
		.contains("retained"));
	assert!(ready.is_none());
}

#[cfg(unix)]
#[test]
fn audit_publication_parent_preparation_failure_discards_a_warm_positive_cache() {
	let root = tempfile::tempdir().unwrap();
	let audit = root.path().join("audit");
	std::fs::create_dir(&audit).unwrap();
	let path = audit.join("events.jsonl");
	let mut ready = None;
	publication_append(&path, 0, &mut ready);
	std::fs::rename(&audit, root.path().join("retained-audit")).unwrap();
	std::fs::write(&audit, b"not a directory").unwrap();
	let preparation = std::fs::create_dir_all(&audit).map_err(anyhow::Error::from);
	assert!(preparation.is_err());
	let error = append_audit_prepared_with(
		publication_fixture(&path, 1),
		&mut ready,
		preparation,
		|_| panic!("parent preparation failure must precede file sync"),
		|_| panic!("parent preparation failure must precede directory sync"),
	)
	.unwrap_err();
	assert!(!error.to_string().is_empty());
	assert!(ready.is_none());
	std::fs::remove_file(&audit).unwrap();
	std::fs::rename(root.path().join("retained-audit"), &audit).unwrap();
	assert_eq!(publication_append(&path, 2, &mut ready).len(), 3);
}

#[cfg(unix)]
#[test]
fn audit_publication_matching_fingerprints_never_authorize_warm_barrier_omission() {
	let fingerprint = AuditDirectoryStamp {
		device: 1,
		inode: 2,
		modified: (3, 4),
		changed: (5, 6),
		namespace: super::super::namespace_version::Version::Fingerprint([7; 32]),
	};
	assert!(!audit_reliable_generation(&[fingerprint; 3]));
	#[cfg(target_os = "linux")]
	{
		let watched = AuditDirectoryStamp {
			namespace: super::super::namespace_version::Version::Watch(8, 9),
			..fingerprint
		};
		assert!(audit_reliable_generation(&[watched; 3]));
		assert!(!audit_reliable_generation(&[watched, fingerprint, watched]));
	}
}

#[cfg(unix)]
#[test]
fn audit_publication_directory_open_refuses_regular_and_fifo_substitution_without_blocking() {
	use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
	let root = tempfile::tempdir().unwrap();
	let regular = root.path().join("substituted-regular");
	std::fs::write(&regular, b"regular").unwrap();
	assert!(open_audit_directory(&regular).is_err());
	let fifo = root.path().join("substituted-fifo");
	let raw = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
	assert_eq!(unsafe { libc::mkfifo(raw.as_ptr(), 0o600) }, 0);
	let (sender, receiver) = std::sync::mpsc::channel();
	let worker_path = fifo.clone();
	let worker = std::thread::spawn(move || {
		let _ = sender.send(open_audit_directory(&worker_path).is_err());
	});
	let first = receiver.recv_timeout(Duration::from_secs(2));
	if first.is_err() {
		// Rescue a regressed blocking read-open so the fixture cannot strand a
		// worker. This writer never blocks and never writes a byte.
		let rescue = OpenOptions::new()
			.write(true)
			.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
			.open(&fifo);
		drop(rescue);
		if receiver.recv_timeout(Duration::from_secs(2)).is_ok() {
			worker.join().unwrap();
		}
		panic!("directory open blocked on a substituted FIFO");
	}
	assert!(first.unwrap());
	worker.join().unwrap();
}

#[cfg(unix)]
#[test]
fn audit_publication_qualified_absolute_append_reuses_parents_but_reopens_file() {
	use std::os::fd::AsRawFd;
	let root = tempfile::tempdir().unwrap();
	std::fs::create_dir(root.path().join("audit")).unwrap();
	let path = root.path().join("audit/events.jsonl");
	let mut ready = None;
	publication_append(&path, 0, &mut ready);
	let held = &ready.as_ref().unwrap().binding;
	let previous_stamps = held.stamps;
	let previous_file = held.file.as_raw_fd();
	let previous_parents = [
		&held.audit_directory,
		&held.state_directory,
		&held.target_directory,
	]
	.map(AsRawFd::as_raw_fd);
	let operations = publication_append(&path, 1, &mut ready);
	let held = &ready.as_ref().unwrap().binding;
	assert_ne!(
		previous_file,
		held.file.as_raw_fd(),
		"every event opens its file again"
	);
	let parents = [
		&held.audit_directory,
		&held.state_directory,
		&held.target_directory,
	]
	.map(AsRawFd::as_raw_fd);
	if audit_reliable_generation(&previous_stamps) && held.stamps == previous_stamps {
		assert_eq!(operations.len(), 1);
		assert_eq!(
			parents, previous_parents,
			"a fully qualified proof reuses the original held parent descriptors"
		);
	} else {
		assert_eq!(
			operations.len(),
			3,
			"unavailable/changed watches must remain cold"
		);
		assert_ne!(parents, previous_parents);
	}
	held.validate().unwrap();
	// Resolve an equivalent relative spelling without changing process cwd.
	// Relative paths deliberately retain a fresh complete binding every event.
	let cwd = std::env::current_dir().unwrap();
	let mut relative = PathBuf::new();
	for part in cwd.components() {
		if matches!(part, std::path::Component::Normal(_)) {
			relative.push("..");
		}
	}
	relative.push(path.strip_prefix("/").unwrap());
	assert!(!relative.is_absolute());
	assert_eq!(publication_append(&relative, 2, &mut ready).len(), 3);
	let rebound = &ready.as_ref().unwrap().binding;
	let rebound_parents = [
		&rebound.audit_directory,
		&rebound.state_directory,
		&rebound.target_directory,
	]
	.map(AsRawFd::as_raw_fd);
	assert_ne!(parents, rebound_parents);
	rebound.validate().unwrap();
	assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 3);
}

#[cfg(unix)]
#[test]
fn audit_publication_invalid_previous_descriptor_or_fingerprint_is_irrevocably_cold() {
	for invalid in 0..3 {
		let root = tempfile::tempdir().unwrap();
		std::fs::create_dir(root.path().join("audit")).unwrap();
		let unrelated = root.path().join("unrelated");
		std::fs::create_dir(&unrelated).unwrap();
		let path = root.path().join("audit/events.jsonl");
		let mut ready = None;
		publication_append(&path, 0, &mut ready);
		let held = &mut ready.as_mut().unwrap().binding;
		match invalid {
			0 => held.audit_directory = std::fs::File::open(&path).unwrap(),
			1 => held.state_directory = open_audit_directory(&unrelated).unwrap(),
			2 => {
				held.stamps[0].namespace =
					super::super::namespace_version::Version::Fingerprint([19; 32])
			}
			_ => unreachable!(),
		}
		assert!(held.validate().is_err());
		// Names, the original file and stored real generations did not change
		// in the descriptor cases. Reopening a matching binding must not undo
		// the failed previous proof and silently omit either parent barrier.
		assert_eq!(publication_append(&path, 1, &mut ready).len(), 3);
		ready.as_ref().unwrap().binding.validate().unwrap();
		assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
	}
}

#[cfg(unix)]
#[test]
fn audit_publication_invalid_previous_proof_cannot_hide_cold_parent_failure() {
	let root = tempfile::tempdir().unwrap();
	std::fs::create_dir(root.path().join("audit")).unwrap();
	let path = root.path().join("audit/events.jsonl");
	let mut ready = None;
	publication_append(&path, 0, &mut ready);
	ready.as_mut().unwrap().binding.audit_directory = std::fs::File::open(&path).unwrap();
	let order = std::cell::RefCell::new(Vec::new());
	let error = append_audit_at_with(
		publication_fixture(&path, 1),
		&mut ready,
		|file| {
			file.sync_data()?;
			order.borrow_mut().push("file");
			Ok(())
		},
		|directory| {
			directory.sync_all()?;
			order.borrow_mut().push("parent");
			bail!("injected cold parent failure after invalid prior proof")
		},
	)
	.unwrap_err();
	assert!(
		error.to_string().contains("injected cold parent failure"),
		"{error:#}"
	);
	assert_eq!(order.into_inner(), ["file", "parent"]);
	assert!(ready.is_none());
	assert_eq!(publication_append(&path, 2, &mut ready).len(), 3);
	ready.as_ref().unwrap().binding.validate().unwrap();
}

#[cfg(unix)]
#[test]
fn audit_publication_hardlink_denial_clears_warm_readiness() {
	let root = tempfile::tempdir().unwrap();
	let audit = root.path().join("audit");
	std::fs::create_dir(&audit).unwrap();
	let path = audit.join("events.jsonl");
	let mut ready = None;
	publication_append(&path, 0, &mut ready);
	let original = std::fs::read(&path).unwrap();
	let alias = root.path().join("outside-alias");
	std::fs::hard_link(&path, &alias).unwrap();
	let error = append_audit_at_with(
		publication_fixture(&path, 1),
		&mut ready,
		|_| panic!("hard-linked sink must be refused before its file barrier"),
		|_| panic!("hard-linked sink must be refused before parent barriers"),
	)
	.unwrap_err();
	assert!(error.to_string().contains("hard-linked"));
	assert!(ready.is_none());
	assert_eq!(std::fs::read(&path).unwrap(), original);
	assert_eq!(std::fs::read(&alias).unwrap(), original);
	std::fs::remove_file(&alias).unwrap();
	assert_eq!(publication_append(&path, 2, &mut ready).len(), 3);
}
