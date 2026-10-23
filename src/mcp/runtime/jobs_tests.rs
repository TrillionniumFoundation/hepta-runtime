// Copyright 2026 Muvon Un Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;
use tempfile::tempdir;

fn record(id: &str) -> JobRecord {
	JobRecord {
		id: id.into(),
		host: "rog".into(),
		ssh_target: "rog".into(),
		unit: "hepta-test".into(),
		remote_job_dir: "/tmp/hepta-test".into(),
		executable: "/usr/bin/printf".into(),
		args: vec!["ok".into()],
		cwd: None,
		env_keys: vec![],
		created_unix_ms: 10,
		idempotency_key: Some("repeat-key".into()),
		request_fingerprint: 42,
		request_digest: Some("test-digest".into()),
		launch_state: "pending".into(),
		launch_error: None,
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
	let original = fingerprint(&base);
	let (legacy, full) = request_digest(&base);
	assert_eq!(legacy, original);
	assert_eq!(full.len(), 64);
	assert!(full.bytes().all(|byte| byte.is_ascii_hexdigit()));
	base.stdin = Some("different".into());
	assert_ne!(original, fingerprint(&base));
	base.stdin = None;
	base.cpu_quota_percent = Some(21);
	assert_ne!(original, fingerprint(&base));
}

#[test]
fn same_idempotency_key_uses_same_start_lock() {
	assert!(std::ptr::eq(
		start_lock("rog", Some("same")),
		start_lock("rog", Some("same"))
	));
}

#[test]
fn stored_job_host_binding_rejects_alias_remapping() {
	let mut previous = record("job-1");
	previous.remote_job_dir = "/var/lib/hepta/jobs/job-1".into();

	// A restart with unchanged host identity and remote state root may inspect.
	assert!(verify_host_binding(&previous, "rog", "/var/lib/hepta").is_ok());
	assert!(verify_host_binding(&previous, "rog", "/var/lib/hepta/").is_ok());

	// Reusing the alias for another physical SSH target must never cancel or
	// query the new host using the old durable operation's credentials.
	let error = verify_host_binding(&previous, "different-target", "/var/lib/hepta").unwrap_err();
	assert!(error.to_string().contains("host binding changed"));

	// The remote root is part of the operation identity even with the same SSH
	// address: otherwise the same job ID can resolve to unrelated stored state.
	let error = verify_host_binding(&previous, "rog", "/var/lib/another").unwrap_err();
	assert!(error.to_string().contains("host binding changed"));

	previous.ssh_target = "different-target".into();
	assert!(verify_host_binding(&previous, "rog", "/var/lib/hepta").is_err());
}

#[test]
fn corrupt_record_blocks_idempotency_scan() {
	let dir = tempdir().unwrap();
	let valid = record("job-1");
	std::fs::write(dir.path().join("job-1.json"), serde_json::to_vec(&valid).unwrap()).unwrap();
	std::fs::write(dir.path().join("job-2.json"), b"{truncated").unwrap();
	let error = scan_records_dir(dir.path()).unwrap_err();
	assert!(error.to_string().contains("corrupt durable job record"));
}

#[test]
fn multiple_durable_owners_of_one_idempotency_key_fail_closed() {
	let dir = tempdir().unwrap();
	let mut first = record("job-1");
	first.launch_state = "launched".into();
	let mut second = record("job-2");
	second.request_digest = Some("conflicting-payload".into());
	for entry in [first, second] {
		std::fs::write(
			dir.path().join(format!("{}.json", entry.id)),
			serde_json::to_vec(&entry).unwrap(),
		)
		.unwrap();
	}
	let scanned = scan_records_dir(dir.path()).unwrap();
	let error = select_idempotent_owner(scanned, "rog", "repeat-key").unwrap_err();
	assert!(error.to_string().contains("multiple durable job owners"));
}

#[test]
fn distinct_idempotency_owners_keep_host_and_key_isolation() {
	let own = record("job-1");
	let mut other_host = record("job-2");
	other_host.host = "pocket4".into();
	let mut other_key = record("job-3");
	other_key.idempotency_key = Some("different-key".into());
	let scanned = vec![own, other_host, other_key];
	let owner = select_idempotent_owner(scanned, "rog", "repeat-key")
		.unwrap()
		.unwrap();
	assert_eq!(owner.id, "job-1");
	assert!(select_idempotent_owner(Vec::new(), "rog", "repeat-key")
		.unwrap()
		.is_none());
}

#[test]
fn mismatched_filename_blocks_idempotency_scan() {
	let dir = tempdir().unwrap();
	let valid = record("job-1");
	std::fs::write(dir.path().join("wrong.json"), serde_json::to_vec(&valid).unwrap()).unwrap();
	let error = scan_records_dir(dir.path()).unwrap_err();
	assert!(error.to_string().contains("filename/identity mismatch"));
}

#[test]
fn direct_lookup_rejects_different_durable_job_identity() {
	let dir = tempdir().unwrap();
	let path = dir.path().join("job-1.json");
	std::fs::write(&path, serde_json::to_vec(&record("job-2")).unwrap()).unwrap();
	let error = read_record_at(&path, "job-1").unwrap_err();
	assert!(error.to_string().contains("filename/identity mismatch"));
}

#[cfg(unix)]
#[test]
fn direct_and_scan_lookup_reject_symlinked_job_receipts() {
	let records = tempdir().unwrap();
	let external = tempdir().unwrap();
	let target = external.path().join("job-1.json");
	let link = records.path().join("job-1.json");
	std::fs::write(&target, serde_json::to_vec(&record("job-1")).unwrap()).unwrap();
	std::os::unix::fs::symlink(target, &link).unwrap();
	let error = read_record_at(&link, "job-1").unwrap_err();
	assert!(error.to_string().contains("unsafe durable job record type"));
	let error = scan_records_dir(records.path()).unwrap_err();
	assert!(error.to_string().contains("unsafe durable job record type"));
}

#[test]
fn atomic_record_replacement_preserves_valid_identity() {
	let dir = tempdir().unwrap();
	let path = dir.path().join("job-1.json");
	let mut entry = record("job-1");
	save_record_at(&path, &entry).unwrap();
	entry.launch_state = "launched".into();
	save_record_at(&path, &entry).unwrap();
	let records = scan_records_dir(dir.path()).unwrap();
	assert_eq!(records.len(), 1);
	assert_eq!(records[0].launch_state, "launched");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
	}
}

#[cfg(unix)]
fn try_remote_resume(
	request_state: Option<&str>,
	extra: Option<(&str, &str)>,
) -> std::process::Output {
	use std::io::Write;
	use std::process::{Command, Stdio};
	let dir = tempdir().unwrap();
	let job_dir = dir.path().join("job");
	std::fs::create_dir_all(&job_dir).unwrap();
	if let Some(request_state) = request_state {
		std::fs::write(job_dir.join("request.json"), request_state).unwrap();
	}
	if let Some((filename, content)) = extra {
		std::fs::write(job_dir.join(filename), content).unwrap();
	}
	let input = json!({
		"job_id": "job-1",
		"job_dir": job_dir,
		"request_fingerprint": "aabb",
		"request_digest": "fullhash"
	})
	.to_string();
	let mut child = Command::new("python3")
		.arg("-c")
		.arg(START_CODE)
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
	child.wait_with_output().unwrap()
}

#[cfg(unix)]
#[test]
fn corrupt_remote_request_refuses_replay() {
	let output = try_remote_resume(Some("{partial"), None);
	assert!(!output.status.success());
	assert!(String::from_utf8_lossy(&output.stderr).contains("corrupt remote job state request.json"));
}

#[cfg(unix)]
#[test]
fn acknowledged_request_without_launch_evidence_refuses_replay() {
	let request = r#"{"job_id":"job-1","request_fingerprint":"aabb","request_digest":"fullhash"}"#;
	let output = try_remote_resume(Some(request), None);
	assert!(!output.status.success());
	assert!(String::from_utf8_lossy(&output.stderr).contains("ambiguous prior launch"));
}

#[cfg(unix)]
#[test]
fn failed_remote_launch_is_not_reported_as_successful_reuse() {
	let request = r#"{"job_id":"job-1","request_fingerprint":"aabb","request_digest":"fullhash"}"#;
	let output = try_remote_resume(
		Some(request),
		Some(("launch.json", r#"{"backend":"launch_failed"}"#)),
	);
	assert!(!output.status.success());
	assert!(String::from_utf8_lossy(&output.stderr).contains("prior remote launch failed"));
}

#[cfg(unix)]
#[test]
fn confirmed_remote_launch_can_be_reconciled_without_restarting() {
	let request = r#"{"job_id":"job-1","request_fingerprint":"aabb","request_digest":"fullhash"}"#;
	let output = try_remote_resume(
		Some(request),
		Some(("launch.json", r#"{"backend":"systemd","unit":"u"}"#)),
	);
	assert!(output.status.success());
	assert!(String::from_utf8_lossy(&output.stdout).contains("reused_remote"));
}

#[cfg(unix)]
#[test]
fn orphaned_remote_effect_state_refuses_new_launch() {
	let output = try_remote_resume(None, Some(("started.json", r#"{"supervisor_pid":123}"#)));
	assert!(!output.status.success());
	assert!(String::from_utf8_lossy(&output.stderr).contains("orphaned remote job state"));
}

#[test]
fn tool_schema_advertises_required_idempotency_key() {
	let schema = serde_json::to_value(rmcp::schemars::schema_for!(ProcessStartParams)).unwrap();
	let required = schema["required"].as_array().unwrap();
	assert!(required.contains(&json!("idempotency_key")));
}

#[test]
fn starts_without_stable_idempotency_are_denied_before_external_effects() {
	let mut params = ProcessStartParams {
		host: "rog".into(),
		executable: "/usr/bin/printf".into(),
		args: vec!["ok".into()],
		cwd: None,
		env: BTreeMap::new(),
		stdin: None,
		timeout_seconds: None,
		idempotency_key: None,
		nice: None,
		cpu_quota_percent: None,
		memory_max_bytes: None,
	};
	for key in [None, Some(String::new()), Some("   ".into()), Some("x".repeat(257))] {
		params.idempotency_key = key;
		let error = validate_start(&params).unwrap_err();
		assert!(error.to_string().contains("idempotency_key"), "{error}");
	}
}

#[test]
fn full_request_binding_changes_with_resource_limits() {
	let mut base = ProcessStartParams {
		host: "rog".into(),
		executable: "/usr/bin/printf".into(),
		args: vec!["ok".into()],
		cwd: None,
		env: BTreeMap::new(),
		stdin: Some("first".into()),
		timeout_seconds: None,
		idempotency_key: Some("key".into()),
		nice: None,
		cpu_quota_percent: None,
		memory_max_bytes: None,
	};
	let before = request_digest(&base).1;
	base.stdin = Some("second".into());
	assert_ne!(before, request_digest(&base).1);
}

#[test]
fn ambiguous_controller_launch_state_can_never_dispatch_a_reused_effect() {
	let mut entry = record("job-1");
	for state in ["pending", "launch_failed"] {
		entry.launch_state = state.into();
		let error = admit_observation_only_reuse(&entry).unwrap_err();
		assert!(error.to_string().contains("indeterminate"));
	}
	entry.launch_state = "unexpected".into();
	assert!(admit_observation_only_reuse(&entry).is_err());
	entry.launch_state = "launched".into();
	admit_observation_only_reuse(&entry).unwrap();
}

#[test]
fn legacy_request_binding_is_readable_but_not_replay_authority() {
	let mut entry = record("job-1");
	entry.request_digest = None;
	let err = verify_reuse_binding(&entry, "repeat-key", 42, "test-digest").unwrap_err();
	assert!(err.to_string().contains("legacy idempotency record"));
}

#[test]
fn full_request_binding_rejects_changed_payload() {
	let entry = record("job-1");
	verify_reuse_binding(&entry, "repeat-key", 42, "test-digest").unwrap();
	assert!(verify_reuse_binding(&entry, "repeat-key", 42, "tampered").is_err());
	assert!(verify_reuse_binding(&entry, "repeat-key", 43, "test-digest").is_err());
}

#[test]
fn stale_temp_record_is_never_overwritten() {
	let dir = tempdir().unwrap();
	let path = dir.path().join("job-1.json");
	let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
	std::fs::write(&tmp, b"uncommitted").unwrap();
	let error = save_record_at(&path, &record("job-1")).unwrap_err();
	assert!(error.downcast_ref::<std::io::Error>().is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists));
	assert_eq!(std::fs::read(&tmp).unwrap(), b"uncommitted");
	assert!(!path.exists());
}

#[test]
fn oversized_job_record_is_not_persisted_or_dispatched() {
	let dir = tempdir().unwrap();
	let path = dir.path().join("job-1.json");
	let mut entry = record("job-1");
	entry.args = vec!["x".repeat(MAX_JOB_RECORD_BYTES as usize + 1)];
	let error = save_record_at(&path, &entry).unwrap_err();
	assert!(error.to_string().contains("durable job record exceeds"));
	assert!(!path.exists(), "oversized receipt must not become durable");
	assert!(
		!path.with_extension(format!("json.tmp.{}", std::process::id())).exists(),
		"oversized receipt must not leave an ambiguous temporary owner"
	);
}

#[test]
fn oversized_job_record_is_rejected_without_deserialization() {
	let dir = tempdir().unwrap();
	let path = dir.path().join("job-1.json");
	std::fs::write(&path, vec![b'a'; (MAX_JOB_RECORD_BYTES + 1) as usize]).unwrap();
	let error = read_record_at(&path, "job-1").unwrap_err();
	assert!(error.to_string().contains("oversized durable job record"));
}

#[cfg(unix)]
#[test]
fn audit_append_denies_symlink_without_touching_target() {
	let dir = tempdir().unwrap();
	let target = dir.path().join("outside");
	let link = dir.path().join("events.jsonl");
	std::fs::write(&target, b"untouched").unwrap();
	std::os::unix::fs::symlink(&target, &link).unwrap();
	assert!(open_audit_append(&link).is_err());
	assert_eq!(std::fs::read(target).unwrap(), b"untouched");
}

#[cfg(unix)]
#[test]
fn audit_append_creates_private_regular_file() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempdir().unwrap();
	let path = dir.path().join("events.jsonl");
	let mut file = open_audit_append(&path).unwrap();
	file.write_all(b"first\n").unwrap();
	file.sync_data().unwrap();
	assert_eq!(
		std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
		0o600
	);
	assert_eq!(std::fs::read(&path).unwrap(), b"first\n");
}

#[cfg(unix)]
#[test]
fn audit_append_migrates_legacy_public_mode_without_changing_content() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempdir().unwrap();
	let path = dir.path().join("events.jsonl");
	std::fs::write(&path, b"original").unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	let mut file = open_audit_append(&path).unwrap();
	file.write_all(b"\n").unwrap();
	file.sync_data().unwrap();
	assert_eq!(
		std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
		0o600
	);
	assert_eq!(std::fs::read(path).unwrap(), b"original\n");
}

#[cfg(unix)]
#[test]
fn audit_append_denies_hardlinks_to_unrelated_files() {
	let dir = tempdir().unwrap();
	let target = dir.path().join("sensitive");
	let link = dir.path().join("events.jsonl");
	std::fs::write(&target, b"unchanged").unwrap();
	std::fs::hard_link(&target, &link).unwrap();
	let error = open_audit_append(&link).err().unwrap();
	assert!(error.to_string().contains("hard-linked"));
	assert_eq!(std::fs::read(target).unwrap(), b"unchanged");
}

#[cfg(unix)]
fn remote_observer_binding_probe(
	code: &str,
	stored_digest: &str,
	claimed_digest: Option<&str>,
	stored_unit: &str,
) -> (std::process::Output, bool) {
	use std::io::Write;
	use std::process::{Command, Stdio};

	let dir = tempdir().unwrap();
	let job_dir = dir.path().join("job");
	std::fs::create_dir(&job_dir).unwrap();
	std::fs::write(
		job_dir.join("request.json"),
		json!({
			"job_id": "job-1",
			"job_dir": job_dir,
			"unit": stored_unit,
			"request_digest": stored_digest,
		})
		.to_string(),
	)
	.unwrap();
	std::fs::write(job_dir.join("exit.json"), r#"{"exit_code":0}"#).unwrap();
	std::fs::write(job_dir.join("stdout.log"), "verified").unwrap();
	let query = json!({
		"job_id": "job-1",
		"job_dir": job_dir,
		"unit": "hepta-runtime-job-1",
		"request_digest": claimed_digest,
	});
	let mut child = Command::new("python3")
		.arg("-c")
		.arg(code)
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.spawn()
		.unwrap();
	child
		.stdin
		.take()
		.unwrap()
		.write_all(query.to_string().as_bytes())
		.unwrap();
	let output = child.wait_with_output().unwrap();
	(output, job_dir.join("cancel-request.json").exists())
}

#[cfg(unix)]
#[test]
fn remote_status_read_and_cancel_reject_wrong_or_missing_effect_binding() {
	let accepted = "a".repeat(64);
	let wrong = "b".repeat(64);
	for code in [STATUS_CODE, READ_CODE, CANCEL_CODE] {
		for claimed in [None, Some(wrong.as_str())] {
			let (output, cancelled) = remote_observer_binding_probe(
				code,
				&accepted,
				claimed,
				"hepta-runtime-job-1",
			);
			assert!(!output.status.success());
			assert!(!cancelled);
			assert!(
				String::from_utf8_lossy(&output.stderr)
					.contains("remote job request binding missing or mismatched")
			);
		}
		let (output, cancelled) = remote_observer_binding_probe(
			code,
			&accepted,
			Some(accepted.as_str()),
			"wrong-unit",
		);
		assert!(!output.status.success());
		assert!(!cancelled);
	}
}

#[cfg(unix)]
#[test]
fn remote_status_and_read_accept_only_exact_bound_observations() {
	let digest = "a".repeat(64);
	let (status, _) = remote_observer_binding_probe(
		STATUS_CODE,
		&digest,
		Some(digest.as_str()),
		"hepta-runtime-job-1",
	);
	assert!(
		status.status.success(),
		"{}",
		String::from_utf8_lossy(&status.stderr)
	);
	let value: Value = serde_json::from_slice(&status.stdout).unwrap();
	assert_eq!(value["state"], "succeeded");
	let (read, _) = remote_observer_binding_probe(
		READ_CODE,
		&digest,
		Some(digest.as_str()),
		"hepta-runtime-job-1",
	);
	assert!(
		read.status.success(),
		"{}",
		String::from_utf8_lossy(&read.stderr)
	);
	let value: Value = serde_json::from_slice(&read.stdout).unwrap();
	assert_eq!(value["stdout"]["text"], "verified");
}
