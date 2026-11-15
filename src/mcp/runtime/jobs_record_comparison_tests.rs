// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Complete decoded bindings must agree across independent guarded receipt reads.
use super::*;

fn original() -> JobRecord {
	serde_json::from_value(json!({
		"execution_mode":"operator", "system_jobctl":false,
		"id":"comparison-original", "host":"main", "ssh_target":"never-connect.invalid",
		"unit":"comparison-unit", "remote_job_dir":"/never-launch/comparison-original",
		"executable":"/usr/bin/true", "args":["argument", "escaped\n内容"],
		"cwd":"/never-launch", "env_keys":["FIRST", "SECOND"],
		"created_unix_ms":17, "idempotency_key":"comparison-key", "request_fingerprint":19,
		"request_digest":"a".repeat(64), "launch_state":"launched", "launch_error":null
	}))
	.unwrap()
}

fn fixed_epoch(root: &Path) -> RegistryEpoch {
	let mut epoch = registry_epoch(root).unwrap();
	// Deliberately hold the watch token constant: these tests isolate the
	// independent full-record recheck, rather than passing through invalidation.
	epoch.content = Some(super::super::namespace_version::Version::Watch(17, 23));
	epoch
}

#[test]
fn strict_rescan_rejects_a_change_to_every_persisted_binding_field() {
	let original = original();
	let value = serde_json::to_value(&original).unwrap();
	let mutations = [
		("execution_mode", json!("isolated")),
		("system_jobctl", json!(true)),
		("id", json!("other-original")),
		("host", json!("other-host")),
		("ssh_target", json!("other-target.invalid")),
		("unit", json!("other-unit")),
		("remote_job_dir", json!("/never-launch/other-original")),
		("executable", json!("/usr/bin/false")),
		("args", json!(["argument", "escaped\n别的内容"])),
		("cwd", Value::Null),
		("env_keys", json!(["SECOND", "FIRST"])),
		("created_unix_ms", json!(18)),
		("idempotency_key", Value::Null),
		("request_fingerprint", json!(20)),
		("request_digest", json!("b".repeat(64))),
		("launch_state", json!("pending")),
		("launch_error", json!("unacknowledged launch")),
	];
	// Adding a persisted field requires adding its mixed-generation case too.
	assert_eq!(value.as_object().unwrap().len(), mutations.len());
	for (field, replacement) in mutations {
		assert_ne!(value[field], replacement, "fixture must change {field}");
		let root = tempfile::tempdir().unwrap();
		let path = root.path().join(format!("{}.json", original.id));
		save_record_at(&path, &original).unwrap();
		let epoch = fixed_epoch(root.path());
		let mut changed = value.clone();
		changed[field] = replacement;
		let changed = serde_json::to_vec(&changed).unwrap();
		let error = scan_idempotent_binding_once(
			root.path(),
			&original.host,
			original.idempotency_key.as_deref().unwrap(),
			&epoch,
			Some(&original.id),
			&|_| Ok(epoch),
			RegistryScanObserver {
				cohort: &mut [],
				after_scan: || std::fs::write(&path, &changed).unwrap(),
			},
		)
		.unwrap_err();
		assert!(
			error.downcast_ref::<RegistryScanChanged>().is_some()
				|| error
					.to_string()
					.contains("previous idempotency binding missing or changed"),
			"{field}: {error:#}"
		);
		assert_eq!(std::fs::read(&path).unwrap(), changed);
	}
}

#[test]
fn strict_rescan_accepts_equivalent_json_representation() {
	let root = tempfile::tempdir().unwrap();
	let original = original();
	let path = root.path().join(format!("{}.json", original.id));
	// The serializer for Value sorts field names; the struct serializer emits
	// declaration order. Whitespace, key order and Unicode escapes are all inert.
	let compact = serde_json::to_string(&serde_json::to_value(&original).unwrap())
		.unwrap()
		.replace('内', "\\u5185")
		.replace('容', "\\u5bb9");
	save_record_at(&path, &original).unwrap();
	assert_ne!(std::fs::read(&path).unwrap(), compact.as_bytes());
	let epoch = fixed_epoch(root.path());
	let (found, _) = scan_idempotent_binding_once(
		root.path(),
		&original.host,
		original.idempotency_key.as_deref().unwrap(),
		&epoch,
		Some(&original.id),
		&|_| Ok(epoch),
		RegistryScanObserver {
			cohort: &mut [],
			after_scan: || std::fs::write(&path, compact.as_bytes()).unwrap(),
		},
	)
	.unwrap();
	assert_eq!(
		serde_json::to_value(found.unwrap()).unwrap(),
		serde_json::to_value(original).unwrap()
	);
}

#[test]
fn strict_reader_preserves_the_exact_one_mib_boundary() {
	let root = tempfile::tempdir().unwrap();
	let mut original = original();
	original.args = vec![String::new()];
	let overhead = serde_json::to_vec(&original).unwrap().len();
	original.args[0] = "x".repeat(MAX_CACHED_RECORD_BYTES as usize - overhead);
	let bytes = serde_json::to_vec(&original).unwrap();
	assert_eq!(bytes.len() as u64, MAX_CACHED_RECORD_BYTES);
	let path = root.path().join(format!("{}.json", original.id));
	// First create the exact private inode through the existing durable writer;
	// then use compact bytes so the fixture reaches the strict byte boundary.
	save_record_at(&path, &original).unwrap();
	std::fs::write(&path, &bytes).unwrap();
	let found = read_verified_cached_record(root.path(), &original.id).unwrap();
	assert_eq!(found.args, original.args);
	let mut file = OpenOptions::new().append(true).open(&path).unwrap();
	file.write_all(b" ").unwrap();
	drop(file);
	assert_eq!(
		std::fs::metadata(&path).unwrap().len(),
		MAX_CACHED_RECORD_BYTES + 1
	);
	assert!(read_verified_cached_record(root.path(), &original.id).is_err());
}
