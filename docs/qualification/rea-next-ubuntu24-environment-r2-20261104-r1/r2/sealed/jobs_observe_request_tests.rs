// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Lost acknowledgements resolve only original bindings; observation never launches.
use super::*;
use std::os::unix::fs::PermissionsExt;

fn request() -> ProcessStartParams {
	serde_json::from_value(json!({
		"host": "fixture",
		"executable": "/usr/bin/true",
		"idempotency_key": "original-request",
	}))
	.unwrap()
}

fn trace_rows(path: &Path) -> Vec<Value> {
	if !path.exists() {
		return Vec::new();
	}
	std::fs::read_to_string(path)
		.unwrap()
		.lines()
		.map(|line| serde_json::from_str(line).unwrap())
		.collect()
}

#[test]
fn lost_ack_observation_never_launches_and_preserves_original_binding() {
	const CHILD: &str = "HEPTA_OBSERVE_REQUEST_TEST_CHILD";
	if std::env::var_os(CHILD).is_none() {
		let output = std::process::Command::new(std::env::current_exe().unwrap())
			.args([
				"mcp::runtime::jobs::observe_request_tests::lost_ack_observation_never_launches_and_preserves_original_binding",
				"--exact",
				"--test-threads=1",
			])
			.env(CHILD, "1")
			.output()
			.unwrap();
		assert!(
			output.status.success(),
			"{}\n{}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr)
		);
		return;
	}

	// Change process-global configuration/PATH only in this single-test child.
	// The SSH executable is a local recorder, never a network connection.
	let root = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	let state = root.path().join("state");
	std::fs::create_dir(&state).unwrap();
	std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
	let executable = root.path().join("ssh");
	let trace = root.path().join("ssh.jsonl");
	std::fs::write(
		&executable,
		r#"#!/usr/bin/python3
import json, os, sys
request = json.load(sys.stdin)
with open(os.environ["HEPTA_OBSERVE_REQUEST_TEST_TRACE"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps({"argv": sys.argv[1:], "request": request}) + "\n")
print(json.dumps({"job_id": request["job_id"], "state": "running"}))
"#,
	)
	.unwrap();
	std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
	std::env::set_var("PATH", root.path());
	std::env::set_var("HEPTA_OBSERVE_REQUEST_TEST_TRACE", &trace);
	let config = serde_json::from_value(json!({
		"state_dir": state,
		"hosts": {
			"fixture": {
				"ssh_target": "never-connect.invalid",
				"platform": "linux",
				"execution_mode": "isolated",
				"remote_state_dir": "/frozen-job-root",
				"allow_execute": false
			}
		}
	}))
	.unwrap();
	super::super::init_runtime(config).unwrap();
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	runtime.block_on(async {
		let sequence = JOB_SEQUENCE.load(Ordering::Relaxed);
		// Policy revokes new launches, not observation of original bindings.
		let disabled = crate::native::execute_or_observe(request())
			.await
			.unwrap_err();
		assert!(disabled
			.to_string()
			.contains("process execution is disabled"));
		assert!(crate::native::observe_request(request())
			.await
			.unwrap()
			.is_none());
		assert!(trace_rows(&trace).is_empty());
		assert_eq!(std::fs::read_dir(state.join("jobs")).unwrap().count(), 0);
		assert_eq!(JOB_SEQUENCE.load(Ordering::Relaxed), sequence);

		let params = request();
		let digest = request_digest(&params).unwrap();
		let mut record: JobRecord = serde_json::from_value(json!({
			"id": "original-job",
			"host": params.host,
			"ssh_target": "never-connect.invalid",
			"unit": "hepta-runtime-job-original-job",
			"remote_job_dir": "/frozen-job-root/jobs/original-job",
			"executable": params.executable,
			"args": params.args,
			"cwd": null,
			"env_keys": [],
			"created_unix_ms": 1,
			"idempotency_key": params.idempotency_key,
			"request_fingerprint": fingerprint(&digest),
			"request_digest": digest,
			"launch_state": "pending",
			"execution_mode": "isolated",
			"system_jobctl": true
		}))
		.unwrap();
		save_record(&record).unwrap();
		let path = record_path(&record.id).unwrap();
		let original = std::fs::read(&path).unwrap();
		let observed: Value = serde_json::from_str(
			&crate::native::observe_request(request())
				.await
				.unwrap()
				.unwrap(),
		)
		.unwrap();
		assert_eq!(observed["observation_only"], true);
		assert_eq!(observed["retried_launch"], false);
		assert_eq!(observed["launch"], Value::Null);
		assert_eq!(observed["job"]["id"], "original-job");
		assert_eq!(observed["job"]["launch_state"], "pending");
		assert_eq!(observed["status"]["state"], "running");
		let rows = trace_rows(&trace);
		assert_eq!(rows.len(), 1);
		assert_eq!(
			rows[0]["request"],
			json!({"op": "status", "job_id": "original-job"})
		);
		assert_eq!(std::fs::read(&path).unwrap(), original);
		assert_eq!(JOB_SEQUENCE.load(Ordering::Relaxed), sequence);

		let mut changed = request();
		changed.args.push("different".into());
		assert!(crate::native::observe_request(changed)
			.await
			.unwrap_err()
			.to_string()
			.contains("different request"));
		assert_eq!(trace_rows(&trace).len(), 1);
		assert_eq!(std::fs::read(&path).unwrap(), original);

		record.ssh_target = "rebound.invalid".into();
		save_record(&record).unwrap();
		assert!(crate::native::observe_request(request())
			.await
			.unwrap_err()
			.to_string()
			.contains("host binding changed"));
		assert_eq!(trace_rows(&trace).len(), 1);

		record.ssh_target = "never-connect.invalid".into();
		save_record(&record).unwrap();
		let mut duplicate = record.clone();
		duplicate.id = "duplicate-job".into();
		duplicate.unit = "hepta-runtime-job-duplicate-job".into();
		duplicate.remote_job_dir = "/frozen-job-root/jobs/duplicate-job".into();
		save_record(&duplicate).unwrap();
		assert!(crate::native::observe_request(request())
			.await
			.unwrap_err()
			.to_string()
			.contains("duplicate original idempotency binding"));
		assert_eq!(trace_rows(&trace).len(), 1);
		assert_eq!(std::fs::read_dir(state.join("jobs")).unwrap().count(), 2);
		assert_eq!(JOB_SEQUENCE.load(Ordering::Relaxed), sequence);
	});
}
