// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Projected operations preserve full receipt validation, bindings and remote requests.
use super::*;
use operation_record::read_operation_record_at;
use std::os::unix::fs::PermissionsExt;

fn record(system_jobctl: bool) -> JobRecord {
	serde_json::from_value(json!({
		"id":"projected-original", "host":"fixture", "ssh_target":"never-connect.invalid",
		"unit":"original-unit", "remote_job_dir":"/frozen-root/jobs/projected-original",
		"executable":"/usr/bin/true", "args":["x".repeat(128 * 1024), "escaped\n中文\\\"".repeat(8192)],
		"cwd":"/private\ncwd", "env_keys":["PLAIN", "ESCAPED\tKEY"], "created_unix_ms":7,
		"idempotency_key":"original-key", "request_fingerprint":7,
		"request_digest":"a".repeat(64), "launch_state":"launched",
		"launch_error":"private\nerror", "system_jobctl":system_jobctl,
		"execution_mode":"isolated"
	}))
	.unwrap()
}

fn string_bytes(record: &OperationRecord) -> usize {
	record.id.len()
		+ record.host.len()
		+ record.ssh_target.len()
		+ record.unit.len()
		+ record.remote_job_dir.len()
		+ record.request_digest.as_ref().map_or(0, String::len)
}

#[test]
fn projection_drops_large_private_strings_but_keeps_every_routing_field() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("projected-original.json");
	for system in [false, true] {
		let original = record(system);
		save_record_at(&path, &original).unwrap();
		let bytes = std::fs::read(&path).unwrap();
		let projected = read_operation_record_at(&path, &original.id).unwrap();
		assert_eq!(
			OperationRecordRef::from(&projected),
			OperationRecordRef::from(&original)
		);
		assert!(string_bytes(&projected) < 256);
		assert_eq!(std::mem::size_of::<ValidatedJobString>(), 0);
		let decoded: OperationRecordData<BorrowedJobString<'_>> =
			serde_json::from_slice(&bytes).unwrap();
		assert!(decoded.ssh_target.is_borrowed());
		assert_eq!(decoded.args.len(), 2);
		assert_eq!(decoded.env_keys.len(), 2);
		assert!(serde_json::to_string(&ValidatedJobString).is_err());
		assert_eq!(std::fs::read(&path).unwrap(), bytes);
	}
}

fn assert_same_read_error(path: &Path, bytes: &[u8]) {
	std::fs::write(path, bytes).unwrap();
	let original = format!(
		"{:#}",
		read_record_at(path, "projected-original").unwrap_err()
	);
	let projected = format!(
		"{:#}",
		read_operation_record_at(path, "projected-original").unwrap_err()
	);
	assert_eq!(projected, original);
}

#[test]
fn projection_preserves_required_optional_duplicate_and_private_type_validation() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("projected-original.json");
	let mut base = serde_json::to_value(record(false)).unwrap();
	base["args"] = json!([]);
	for field in [
		"executable",
		"args",
		"cwd",
		"env_keys",
		"launch_error",
		"ssh_target",
		"unit",
		"remote_job_dir",
		"request_digest",
		"idempotency_key",
		"launch_state",
	] {
		for bad in [json!(3), json!(true), json!({}), json!([3])] {
			let mut value = base.clone();
			value[field] = bad;
			assert_same_read_error(&path, &serde_json::to_vec(&value).unwrap());
		}
	}
	for field in [
		"id",
		"host",
		"ssh_target",
		"unit",
		"remote_job_dir",
		"executable",
		"args",
		"env_keys",
		"created_unix_ms",
		"request_fingerprint",
	] {
		let mut value = base.clone();
		value.as_object_mut().unwrap().remove(field);
		assert_same_read_error(&path, &serde_json::to_vec(&value).unwrap());
	}
	let valid = serde_json::to_string(&base).unwrap();
	for (field, value) in base.as_object().unwrap() {
		let duplicate = format!("{{\"{field}\":{value},{}", &valid[1..]);
		assert_same_read_error(&path, duplicate.as_bytes());
	}
	for replacement in [r#""\uD800""#, r#""\uDC00""#, r#""\x20""#] {
		let malformed = valid.replace("\"args\":[]", &format!("\"args\":[{replacement}]"));
		assert_ne!(malformed, valid);
		assert_same_read_error(&path, malformed.as_bytes());
	}
	let mut compatible = base;
	for field in [
		"execution_mode",
		"system_jobctl",
		"request_digest",
		"launch_state",
		"launch_error",
	] {
		compatible.as_object_mut().unwrap().remove(field);
	}
	compatible["future_unknown"] = json!({"nested":[true, 4, null]});
	std::fs::write(&path, serde_json::to_vec(&compatible).unwrap()).unwrap();
	let owned = read_record_at(&path, "projected-original").unwrap();
	let projected = read_operation_record_at(&path, "projected-original").unwrap();
	assert_eq!(
		OperationRecordRef::from(&projected),
		OperationRecordRef::from(&owned)
	);
}

#[test]
fn projection_keeps_original_filename_descriptor_and_host_binding_refusals() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("projected-original.json");
	let original = record(false);
	save_record_at(&path, &original).unwrap();
	let bytes = std::fs::read(&path).unwrap();
	let mut wrong = serde_json::to_value(&original).unwrap();
	wrong["id"] = json!("different-original");
	assert_same_read_error(&path, &serde_json::to_vec(&wrong).unwrap());
	std::fs::write(&path, &bytes).unwrap();
	let alias = root.path().join("alias.json");
	std::fs::hard_link(&path, &alias).unwrap();
	for reader in [
		read_record_at(&path, &original.id).map(|_| ()),
		read_operation_record_at(&path, &original.id).map(|_| ()),
	] {
		assert!(reader
			.unwrap_err()
			.to_string()
			.contains("ownership or inode"));
	}
	std::fs::remove_file(&alias).unwrap();
	std::os::unix::fs::symlink(&path, &alias).unwrap();
	for reader in [
		read_record_at(&alias, &original.id).map(|_| ()),
		read_operation_record_at(&alias, &original.id).map(|_| ()),
	] {
		assert!(reader
			.unwrap_err()
			.to_string()
			.contains("unsafe durable job record type"));
	}
	let projected = read_operation_record_at(&path, &original.id).unwrap();
	for (target, state) in [
		("never-connect.invalid", "/frozen-root"),
		("never-connect.invalid", "/frozen-root/"),
		("different.invalid", "/frozen-root"),
		("never-connect.invalid", "/other-root"),
	] {
		let full = verify_host_binding(&original, target, state).map_err(|e| e.to_string());
		let thin = verify_host_binding(&projected, target, state).map_err(|e| e.to_string());
		assert_eq!(thin, full);
	}
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
fn projected_status_wait_read_cancel_preserve_routes_and_refuse_before_effects() {
	const CHILD: &str = "HEPTA_PROJECTED_OPERATION_TEST_CHILD";
	if std::env::var_os(CHILD).is_none() {
		let output = std::process::Command::new(std::env::current_exe().unwrap())
			.args([
				"mcp::runtime::jobs::operation_record_tests::projected_status_wait_read_cancel_preserve_routes_and_refuse_before_effects",
				"--exact", "--test-threads=1",
			])
			.env(CHILD, "1").output().unwrap();
		assert!(
			output.status.success(),
			"{}\n{}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr)
		);
		return;
	}
	let root = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	let state = root.path().join("state");
	std::fs::create_dir(&state).unwrap();
	std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
	let trace = root.path().join("ssh.jsonl");
	let ssh = root.path().join("ssh");
	std::fs::write(
		&ssh,
		r#"#!/usr/bin/python3
import json, os, sys
request = json.load(sys.stdin)
with open(os.environ["HEPTA_PROJECTED_OPERATION_TRACE"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps({"argv":sys.argv[1:], "request":request}) + "\n")
print(json.dumps({"job_id":request["job_id"], "state":"succeeded", "fixture":True}))
"#,
	)
	.unwrap();
	std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700)).unwrap();
	std::env::set_var("PATH", root.path());
	std::env::set_var("HEPTA_PROJECTED_OPERATION_TRACE", &trace);
	std::env::remove_var("HEPTA_RUNTIME_OBSERVATION_POOL");
	let config = serde_json::from_value(json!({
		"state_dir":state, "hosts":{"fixture":{
			"ssh_target":"never-connect.invalid", "platform":"linux", "execution_mode":"isolated",
			"remote_state_dir":"/frozen-root", "allow_execute":false
		}}
	}))
	.unwrap();
	super::super::init_runtime(config).unwrap();
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	runtime.block_on(async {
		for system in [false, true] {
			let original = record(system);
			save_record(&original).unwrap();
			let path = record_path(&original.id).unwrap();
			let bytes = std::fs::read(&path).unwrap();
			let reference = ProcessRefParams {
				host: original.host.clone(),
				job_id: original.id.clone(),
			};
			let before = trace_rows(&trace).len();
			let status: Value =
				serde_json::from_str(&status_job(reference.clone()).await.unwrap()).unwrap();
			assert_eq!(status["state"], "succeeded");
			let wait: Value = serde_json::from_str(
				&wait_job(ProcessWaitParams {
					host: reference.host.clone(),
					job_id: reference.job_id.clone(),
					timeout_seconds: Some(40),
				})
				.await
				.unwrap(),
			)
			.unwrap();
			assert_eq!(wait["state"], "succeeded");
			read_job(ProcessReadParams {
				host: reference.host.clone(),
				job_id: reference.job_id.clone(),
				stdout_offset: Some(3),
				stderr_offset: Some(5),
				limit: Some(200_000),
			})
			.await
			.unwrap();
			let cancelled: Value = serde_json::from_str(
				&cancel_job(ProcessCancelParams {
					host: reference.host.clone(),
					job_id: reference.job_id.clone(),
					grace_seconds: Some(40),
				})
				.await
				.unwrap(),
			)
			.unwrap();
			assert_eq!(cancelled["audit_recorded"], true);
			assert_eq!(std::fs::read(&path).unwrap(), bytes);
			let rows = trace_rows(&trace);
			assert_eq!(rows.len(), before + 4);
			let actual: Vec<_> = rows[before..]
				.iter()
				.map(|r| r["request"].clone())
				.collect();
			let expected = if system {
				vec![
					json!({"op":"status","job_id":original.id}),
					json!({"op":"status","job_id":original.id}),
					json!({"op":"read","job_id":original.id,"stdout_offset":3,"stderr_offset":5,"limit":200_000}),
					json!({"op":"cancel","job_id":original.id}),
				]
			} else {
				vec![
					json!({"job_id":original.id,"job_dir":original.remote_job_dir,
						"request_digest":original.request_digest,"unit":original.unit,"wait_seconds":0}),
					json!({"job_id":original.id,"job_dir":original.remote_job_dir,
						"request_digest":original.request_digest,"unit":original.unit,"wait_seconds":30}),
					json!({"job_id":original.id,"job_dir":original.remote_job_dir,
						"request_digest":original.request_digest,"unit":original.unit,
						"stdout_offset":3,"stderr_offset":5,"limit":MAX_LOG_READ_BYTES}),
					json!({"job_id":original.id,"job_dir":original.remote_job_dir,
						"request_digest":original.request_digest,"unit":original.unit,"grace_seconds":30}),
				]
			};
			assert_eq!(actual, expected);
			let audit_path = state.join("audit/events.jsonl");
			let audit = std::fs::read(&audit_path).unwrap();
			let mut bad_private = serde_json::to_value(&original).unwrap();
			bad_private["args"] = json!([3]);
			let mut bad_target = original.clone();
			bad_target.ssh_target = "rebound.invalid".into();
			let mut bad_root = original.clone();
			bad_root.remote_job_dir = "/different-root/jobs/projected-original".into();
			let mut bad_mode = original.clone();
			bad_mode.execution_mode = ExecutionMode::Operator;
			for (bytes, host) in [
				(serde_json::to_vec(&bad_private).unwrap(), "fixture"),
				(serde_json::to_vec(&bad_target).unwrap(), "fixture"),
				(serde_json::to_vec(&bad_root).unwrap(), "fixture"),
				(serde_json::to_vec(&bad_mode).unwrap(), "fixture"),
				(bytes.clone(), "different-host"),
			] {
				std::fs::write(&path, bytes).unwrap();
				let bad_ref = ProcessRefParams {
					host: host.into(),
					job_id: reference.job_id.clone(),
				};
				let expected = format!("{:#}", check_ref(&bad_ref).unwrap_err());
				let got = check_ref_async(&bad_ref).await.unwrap_err();
				assert_eq!(format!("{got:#}"), expected);
				let got = cancel_job(ProcessCancelParams {
					host: bad_ref.host,
					job_id: bad_ref.job_id,
					grace_seconds: None,
				})
				.await
				.unwrap_err();
				assert_eq!(format!("{got:#}"), expected);
				assert_eq!(trace_rows(&trace).len(), before + 4);
				assert_eq!(std::fs::read(&audit_path).unwrap(), audit);
			}
		}
	});
}

#[test]
fn projection_preserves_top_level_and_sequence_struct_decoding() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("projected-original.json");
	for invalid in [b"null".as_slice(), b"3", b"true", br#""not-a-record""#] {
		assert_same_read_error(&path, invalid);
	}
	let mut original = record(false);
	original.args.clear();
	let value = serde_json::to_value(&original).unwrap();
	let fields = [
		"execution_mode",
		"system_jobctl",
		"id",
		"host",
		"ssh_target",
		"unit",
		"remote_job_dir",
		"executable",
		"args",
		"cwd",
		"env_keys",
		"created_unix_ms",
		"idempotency_key",
		"request_fingerprint",
		"request_digest",
		"launch_state",
		"launch_error",
	];
	let sequence: Vec<Value> = fields.iter().map(|field| value[*field].clone()).collect();
	for length in 0..=sequence.len() {
		std::fs::write(&path, serde_json::to_vec(&sequence[..length]).unwrap()).unwrap();
		match (
			read_record_at(&path, &original.id),
			read_operation_record_at(&path, &original.id),
		) {
			(Ok(full), Ok(projected)) => assert_eq!(
				OperationRecordRef::from(&projected),
				OperationRecordRef::from(&full)
			),
			(Err(full), Err(projected)) => {
				assert_eq!(format!("{projected:#}"), format!("{full:#}"))
			}
			_ => panic!("owned and projected sequence acceptance differed at length {length}"),
		}
	}
	let mut excess = sequence.clone();
	excess.push(json!("unexpected"));
	assert_same_read_error(&path, &serde_json::to_vec(&excess).unwrap());
	std::fs::write(&path, serde_json::to_vec(&sequence).unwrap()).unwrap();
	assert_eq!(read_record_at(&path, &original.id).unwrap(), original);
	let projected = read_operation_record_at(&path, &original.id).unwrap();
	assert_eq!(
		OperationRecordRef::from(&projected),
		OperationRecordRef::from(&original)
	);
}
