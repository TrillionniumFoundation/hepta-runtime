// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Inventory projections retain complete validation and the former owned wire binding.
use super::*;
use std::os::unix::fs::PermissionsExt;

fn fixture() -> tempfile::TempDir {
	let root = tempfile::tempdir().unwrap();
	std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	let jobs = root.path().join("jobs");
	std::fs::create_dir(&jobs).unwrap();
	std::fs::set_permissions(jobs, std::fs::Permissions::from_mode(0o700)).unwrap();
	root
}

fn record(id: &str, host: &str) -> JobRecord {
	serde_json::from_value(json!({
		"id":id, "host":host, "ssh_target":"never-connect.invalid",
		"unit":"original-unit", "remote_job_dir":"/never-launch/original",
		"executable":"/usr/bin/true", "args":["x".repeat(64 * 1024), "escaped\n中文\\\""],
		"cwd":"/private", "env_keys":["PLAIN", "ESCAPED\tKEY"],
		"created_unix_ms":7, "idempotency_key":"original-key", "request_fingerprint":7,
		"request_digest":"a".repeat(64), "launch_state":"launched", "launch_error":null
	}))
	.unwrap()
}

fn write(root: &Path, record: &JobRecord) -> PathBuf {
	let path = root.join("jobs").join(format!("{}.json", record.id));
	save_record_at(&path, record).unwrap();
	path
}

fn owned_rows(root: &Path, host: Option<&str>) -> Vec<Value> {
	// Independently retain the old complete decoder before filtering or projection.
	let mut rows: Vec<_> = all_records_in(&root.join("jobs"))
		.unwrap()
		.into_iter()
		.filter(|record| host.is_none_or(|host| record.host == host))
		.map(|record| {
			json!({"id":record.id,"host":record.host,"created_unix_ms":record.created_unix_ms,
			"execution_mode":record.execution_mode,"launch_state":record.launch_state})
		})
		.collect();
	rows.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
	rows
}

#[test]
fn paged_inventory_borrows_plain_payloads_and_preserves_complete_original_records() {
	let root = fixture();
	let original = record("original", "main");
	let path = write(root.path(), &original);
	let bytes = std::fs::read(&path).unwrap();
	let projected = inventory_projected_at(root.path(), InventoryLimits::default(), |record| {
		assert!(record.args[0].is_borrowed());
		assert!(!record.args[1].is_borrowed());
		assert!(record.env_keys[0].is_borrowed());
		assert!(!record.env_keys[1].is_borrowed());
		record.into_owned()
	})
	.unwrap();
	assert_eq!(projected, [original]);
	assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
fn borrowed_inventory_source_keeps_owned_responses_and_restart_cursor_bytes() {
	let root = fixture();
	for (id, host) in [("third", "main"), ("first", "main"), ("second", "mac")] {
		let mut value = record(id, host);
		value.launch_state = format!("observed\n\"{id}\"\\中文");
		write(root.path(), &value);
	}
	let jobs = root.path().join("jobs");
	for host in [None, Some("main"), Some("missing")] {
		let owned: Vec<_> = all_records_in(&jobs)
			.unwrap()
			.into_iter()
			.filter(|record| host.is_none_or(|host| record.host == host))
			.collect();
		assert_eq!(
			job_inventory_rows_response(&list_job_rows_in(&jobs, host).unwrap()).unwrap(),
			job_inventory_response(&owned).unwrap()
		);
		let expected = owned_rows(root.path(), host);
		let actual = inventory_page_rows_at(root.path(), host, InventoryLimits::default()).unwrap();
		assert_eq!(actual, expected);
		let namespace = root.path().to_str().unwrap();
		let digest = Sha256::digest(
			serde_json::to_vec(&json!({"namespace":namespace,"host":host,"rows":expected}))
				.unwrap(),
		)
		.iter()
		.map(|byte| format!("{byte:02x}"))
		.collect::<String>();
		assert_eq!(
			inventory_snapshot_digest(&actual, host, namespace).unwrap(),
			digest
		);
		if expected.len() > 1 {
			let params = ProcessListPageParams {
				host: host.map(str::to_owned),
				cursor: Some(format!("{digest}:{}", expected[0]["id"].as_str().unwrap())),
				limit: Some(128),
			};
			let expected_wire = serde_json::to_string(&json!({
				"jobs":&expected[1..],"total":expected.len(),"next_cursor":null,
				"has_more":false,"inventory_complete":true,"snapshot_sha256":digest,
				"status_authoritative":false,"snapshot_semantics":"registry_metadata_at_observation"
			}))
			.unwrap();
			assert_eq!(
				page_job_rows(&actual, &params, namespace).unwrap(),
				expected_wire
			);
		}
	}
}

#[test]
fn both_inventory_paths_validate_unselected_private_fields_before_filtering() {
	let root = fixture();
	write(root.path(), &record("selected", "main"));
	let unselected = record("unselected", "mac");
	let path = write(root.path(), &unselected);
	let mut invalid_type = serde_json::to_value(&unselected).unwrap();
	invalid_type["args"] = json!(["valid first value", 17]);
	let mut missing_field = serde_json::to_value(&unselected).unwrap();
	missing_field.as_object_mut().unwrap().remove("env_keys");
	let original = serde_json::to_string(&unselected).unwrap();
	let duplicate_field = format!("{{\"cwd\":\"duplicate\",{}", &original[1..]);
	for bytes in [
		serde_json::to_vec(&invalid_type).unwrap(),
		serde_json::to_vec(&missing_field).unwrap(),
		duplicate_field.into_bytes(),
	] {
		std::fs::write(&path, &bytes).unwrap();
		let owned_error = serde_json::from_slice::<JobRecord>(&bytes)
			.unwrap_err()
			.to_string();
		let compatibility = list_job_rows_in(&root.path().join("jobs"), Some("main"))
			.err()
			.unwrap();
		assert!(format!("{compatibility:#}").ends_with(&owned_error));
		let paged = inventory_page_rows_at(root.path(), Some("main"), InventoryLimits::default())
			.unwrap_err();
		assert!(format!("{paged:#}").ends_with(&owned_error));
	}
}
