// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Root-helper pure validation tests; no privileged side effects.
use super::*;
#[test]
fn strict_owned_ids() {
	assert!(safe_id("pty-ab12-77"));
	for s in ["", "..", "a/b", "a.service", "a;id"] {
		assert!(!safe_id(s));
	}
}
#[test]
fn unknown_root_actions_and_pid_fields_cannot_deserialize() {
	assert!(
		serde_json::from_value::<Request>(json!({"op":"cancel","job_id":"abc","pid":1})).is_err()
	);
}
#[test]
fn argv_and_stdin_bind_full_digest() {
	let mut q: Request =
		serde_json::from_value(json!({"op":"start","job_id":"abc","executable":"/bin/true"}))
			.unwrap();
	let d = digest(&q).unwrap();
	assert_eq!(d.len(), 64);
	q.stdin = Some("different".into());
	assert_ne!(d, digest(&q).unwrap());
}
#[test]
fn cwd_symlink_escape_is_rejected() {
	let root = tempfile::tempdir().unwrap();
	let other = tempfile::tempdir().unwrap();
	std::os::unix::fs::symlink(other.path(), root.path().join("escape")).unwrap();
	let p = Policy {
		workspace: root.path().to_owned(),
		allow_network: false,
		max_timeout_seconds: 60,
		max_cpu_percent: 25,
		max_memory_bytes: 134217728,
	};
	let mut q:Request=serde_json::from_value(json!({"op":"start","job_id":"abc","executable":"/usr/bin/true","cwd":root.path().join("escape")})).unwrap();
	assert!(validate(&mut q, &p).is_err());
}
#[test]
fn resources_are_capped_by_admin() {
	let root = tempfile::tempdir().unwrap();
	let p = Policy {
		workspace: root.path().to_owned(),
		allow_network: false,
		max_timeout_seconds: 60,
		max_cpu_percent: 25,
		max_memory_bytes: 134217728,
	};
	let mut q: Request = serde_json::from_value(
		json!({"op":"start","job_id":"abc","executable":"/usr/bin/true","cpu_quota_percent":26}),
	)
	.unwrap();
	assert!(validate(&mut q, &p).is_err());
	q.cpu_quota_percent = Some(20);
	assert!(validate(&mut q, &p).is_ok());
}

fn completed_fixture() -> (Record, Exit) {
	(
		Record {
			job_id: "fixture".into(),
			unit: "hepta-job-fixture.service".into(),
			request_digest: "digest".into(),
			boot_id: "previous-boot".into(),
			nonce: "owned-nonce".into(),
			invocation_id: Some("original-invocation".into()),
			launch_state: "launched".into(),
			created_unix_ms: 1,
		},
		Exit {
			job_id: "fixture".into(),
			nonce: "owned-nonce".into(),
			exit_code: 7,
			timed_out: false,
			cancelled: false,
			at_unix_ms: 2,
		},
	)
}
#[test]
fn completed_result_preserves_exit_from_previous_boot() {
	let (r, e) = completed_fixture();
	let result = completed_result(&r, &e).unwrap();
	assert_eq!(result["state"], "failed");
	assert_eq!(result["exit_code"], 7);
}
#[test]
fn completion_must_match_owned_nonce_and_job() {
	let (r, mut e) = completed_fixture();
	e.nonce = "foreign".into();
	assert!(completed_result(&r, &e).is_err());
	e.nonce = r.nonce.clone();
	e.job_id = "foreign".into();
	assert!(completed_result(&r, &e).is_err());
}
#[test]
fn json_fifo_rejected_without_waiting_for_a_writer() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("fifo");
	let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
	assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
	assert!(json_file::<Value>(&path).is_err());
}
