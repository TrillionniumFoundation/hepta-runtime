// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Regression tests for jobs.
use super::*;

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
	let original = fingerprint(&base);
	base.stdin = Some("different".into());
	assert_ne!(original, fingerprint(&base));
	base.stdin = None;
	base.cpu_quota_percent = Some(21);
	assert_ne!(original, fingerprint(&base));
}

#[test]
fn legacy_binding_does_not_silently_relaunch() {
	let params: ProcessStartParams =
		serde_json::from_value(json!({"host":"rog","executable":"/usr/bin/true"})).unwrap();
	let mut record:JobRecord=serde_json::from_value(json!({"id":"fixture","host":"rog","ssh_target":"hepta-rog","unit":"fixture","remote_job_dir":"/tmp/fixture","executable":"/usr/bin/true","args":[],"cwd":null,"env_keys":[],"created_unix_ms":1,"idempotency_key":"test","request_fingerprint":fingerprint(&params)})).unwrap();
	assert!(matches_request(&record, &params).is_err());
	record.request_digest = Some(request_digest(&params).unwrap());
	assert!(matches_request(&record, &params).unwrap());
	let mut changed = params;
	changed.env.insert("X".into(), "changed".into());
	assert!(!matches_request(&record, &changed).unwrap());
}
