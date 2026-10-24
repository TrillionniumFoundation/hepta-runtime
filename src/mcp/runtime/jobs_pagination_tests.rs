// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Private descriptor-bound inventory source limits and hostile inode regressions.
#![cfg(unix)]

use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

fn fixture() -> tempfile::TempDir {
	let root = tempfile::tempdir().unwrap();
	std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	std::fs::create_dir(root.path().join("jobs")).unwrap();
	std::fs::set_permissions(
		root.path().join("jobs"),
		std::fs::Permissions::from_mode(0o700),
	)
	.unwrap();
	root
}

fn write_record(root: &Path, number: usize) -> PathBuf {
	let id = format!("1a14-{number:x}-1");
	let path = root.join("jobs").join(format!("{id}.json"));
	let value = json!({
		"id":id,"host":"main","created_unix_ms":number,"execution_mode":"operator",
		"ssh_target":"PRIVATE_SSH","unit":"PRIVATE_UNIT","remote_job_dir":"/PRIVATE_REMOTE",
		"executable":"/PRIVATE_EXECUTABLE","args":["PRIVATE_ARG"],"cwd":null,"env_keys":[],
		"idempotency_key":null,"request_fingerprint":0,"launch_state":"launched"
	});
	std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	path
}

#[test]
fn private_inventory_reads_complete_serde_records_without_rewriting_source() {
	let root = fixture();
	let first = write_record(root.path(), 1);
	write_record(root.path(), 2);
	let original = std::fs::read(&first).unwrap();
	let records = inventory_records_at(root.path(), InventoryLimits::default()).unwrap();
	assert_eq!(records.len(), 2);
	assert_eq!(records[0].id, "1a14-1-1");
	assert_eq!(records[0].args, ["PRIVATE_ARG"]);
	assert_eq!(std::fs::read(first).unwrap(), original);
}

#[test]
fn private_inventory_rejects_symlink_hardlink_and_public_metadata() {
	let root = fixture();
	let path = write_record(root.path(), 1);
	let outside = root.path().join("outside");
	std::fs::rename(&path, &outside).unwrap();
	symlink(&outside, &path).unwrap();
	assert!(inventory_records_at(root.path(), InventoryLimits::default()).is_err());
	std::fs::remove_file(&path).unwrap();
	std::fs::hard_link(&outside, &path).unwrap();
	assert!(inventory_records_at(root.path(), InventoryLimits::default()).is_err());
	std::fs::remove_file(&path).unwrap();
	std::fs::rename(&outside, &path).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	assert!(inventory_records_at(root.path(), InventoryLimits::default()).is_err());
}

#[test]
fn private_inventory_fifo_without_writer_refuses_promptly() {
	let root = fixture();
	let path =
		std::ffi::CString::new(root.path().join("jobs/1a14-1-1.json").to_str().unwrap()).unwrap();
	assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
	let started = std::time::Instant::now();
	assert!(inventory_records_at(root.path(), InventoryLimits::default()).is_err());
	assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn private_inventory_rejects_symlinked_root_ancestor_and_jobs_directory() {
	let root = fixture();
	let container = tempfile::tempdir().unwrap();
	let alias = container.path().join("alias");
	symlink(root.path(), &alias).unwrap();
	assert!(inventory_records_at(&alias, InventoryLimits::default()).is_err());
	assert!(inventory_records_at(&alias.join("jobs/.."), InventoryLimits::default()).is_err());
	let jobs = root.path().join("jobs");
	std::fs::rename(&jobs, root.path().join("held-jobs")).unwrap();
	symlink(root.path().join("held-jobs"), jobs).unwrap();
	assert!(inventory_records_at(root.path(), InventoryLimits::default()).is_err());
}

#[test]
fn private_inventory_validates_every_source_before_host_projection() {
	let root = fixture();
	write_record(root.path(), 1);
	let invalid = write_record(root.path(), 2);
	std::fs::write(
		&invalid,
		b"not JSON, even when another host would be filtered",
	)
	.unwrap();
	assert!(inventory_records_at(root.path(), InventoryLimits::default()).is_err());
	std::fs::remove_file(&invalid).unwrap();
	let path = write_record(root.path(), 2);
	let mut wrong: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
	wrong["id"] = json!("different-identity");
	std::fs::write(&path, serde_json::to_vec(&wrong).unwrap()).unwrap();
	assert!(inventory_records_at(root.path(), InventoryLimits::default()).is_err());
}

#[test]
fn private_inventory_enforces_source_count_total_bytes_record_bytes_and_time() {
	let root = fixture();
	let path = write_record(root.path(), 1);
	write_record(root.path(), 2);
	let defaults = InventoryLimits::default();
	for limits in [
		InventoryLimits {
			records: 1,
			..defaults
		},
		InventoryLimits {
			bytes: 1,
			..defaults
		},
		InventoryLimits {
			record_bytes: std::fs::metadata(path).unwrap().len() - 1,
			..defaults
		},
		InventoryLimits {
			time: Duration::ZERO,
			..defaults
		},
	] {
		assert!(inventory_records_at(root.path(), limits).is_err());
	}
}

#[test]
fn private_inventory_ignores_uncommitted_writer_files_without_removing_them() {
	let root = fixture();
	write_record(root.path(), 1);
	let staging = root.path().join("jobs/1a14-2-1.json.tmp.123");
	std::fs::write(&staging, b"uncommitted writer content").unwrap();
	assert_eq!(
		inventory_records_at(root.path(), InventoryLimits::default())
			.unwrap()
			.len(),
		1
	);
	assert_eq!(
		std::fs::read(staging).unwrap(),
		b"uncommitted writer content"
	);
}

#[test]
fn private_inventory_empty_private_source_is_complete() {
	let root = fixture();
	assert!(
		inventory_records_at(root.path(), InventoryLimits::default())
			.unwrap()
			.is_empty()
	);
}

#[test]
fn private_inventory_real_registry_scale_fits_source_limits() {
	let root = fixture();
	for number in 0..11_624 {
		write_record(root.path(), number);
	}
	let records = inventory_records_at(root.path(), InventoryLimits::default()).unwrap();
	assert_eq!(records.len(), 11_624);
	let rows: Vec<Value> = records
		.iter()
		.map(|record| {
			json!({
				"id":record.id,"host":record.host,"created_unix_ms":record.created_unix_ms,
				"execution_mode":record.execution_mode,"launch_state":record.launch_state
			})
		})
		.collect();
	let page = page_job_rows(&rows, &ProcessListPageParams::default(), "scale-fixture").unwrap();
	let value: Value = serde_json::from_str(&page).unwrap();
	assert_eq!(value["total"], 11_624);
	assert_eq!(value["jobs"].as_array().unwrap().len(), 128);
	assert!(!page.contains("PRIVATE_"));
}

fn legacy_page_rows(root: &Path, host: Option<&str>) -> Vec<Value> {
	let records = inventory_records_at(root, InventoryLimits::default()).unwrap();
	let mut rows: Vec<_> = records
		.into_iter()
		.filter(|record| host.is_none_or(|host| record.host == host))
		.map(|record| {
			json!({
				"id":record.id,"host":record.host,"created_unix_ms":record.created_unix_ms,
				"execution_mode":record.execution_mode,"launch_state":record.launch_state
			})
		})
		.collect();
	rows.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
	rows
}

#[test]
fn projected_inventory_preserves_exact_legacy_pages_cursors_and_wire_with_large_private_fields() {
	let root = fixture();
	for number in 0..137 {
		let path = write_record(root.path(), number);
		let mut record: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
		record["host"] = json!(if number % 2 == 0 { "main" } else { "mac" });
		record["execution_mode"] = json!(if number % 3 == 0 {
			"isolated"
		} else {
			"operator"
		});
		record["launch_state"] = json!(if number % 5 == 0 {
			"pending"
		} else {
			"launched"
		});
		record["args"] = json!([format!(
			"PRIVATE_ARGUMENT_{number}_{}",
			"x".repeat(24 * 1024)
		)]);
		record["cwd"] = json!(format!("/PRIVATE_CWD_{}", "c".repeat(1024)));
		record["env_keys"] = json!([format!("PRIVATE_ENV_{}", "e".repeat(1024))]);
		record["launch_error"] = json!(format!("PRIVATE_ERROR_{}", "l".repeat(1024)));
		std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
	}
	let first = root.path().join("jobs/1a14-0-1.json");
	let original = std::fs::read(&first).unwrap();
	for host in [None, Some("main"), Some("mac"), Some("unselected")] {
		let legacy = legacy_page_rows(root.path(), host);
		let projected =
			inventory_page_rows_at(root.path(), host, InventoryLimits::default()).unwrap();
		assert_eq!(projected, legacy);
		for limit in [7, 128] {
			let mut params = ProcessListPageParams {
				host: host.map(str::to_owned),
				cursor: None,
				limit: Some(limit),
			};
			loop {
				let old = page_job_rows(&legacy, &params, "exact-private-fixture").unwrap();
				let new = page_job_rows(&projected, &params, "exact-private-fixture").unwrap();
				assert_eq!(new, old, "page and cursor bytes changed");
				let wire = |text| {
					serde_json::to_vec(&rmcp::model::CallToolResult::success(vec![
						rmcp::model::ContentBlock::text(text),
					]))
					.unwrap()
				};
				assert_eq!(wire(new.clone()), wire(old));
				assert!(!new.contains("PRIVATE_"));
				let value: Value = serde_json::from_str(&new).unwrap();
				params.cursor = value["next_cursor"].as_str().map(str::to_owned);
				if params.cursor.is_none() {
					break;
				}
			}
		}
	}
	assert_eq!(std::fs::read(first).unwrap(), original);
}

#[test]
fn projected_inventory_fully_deserializes_discarded_fields_even_for_an_unselected_host() {
	let root = fixture();
	write_record(root.path(), 1);
	let path = write_record(root.path(), 2);
	let mut original: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
	original["host"] = json!("mac");
	for (field, malformed) in [
		("args", json!([{"private":"invalid argument type"}])),
		("cwd", json!(7)),
		("env_keys", json!([false])),
		("ssh_target", json!(null)),
		("request_digest", json!({"private":"invalid digest type"})),
		("launch_error", json!(["invalid error type"])),
	] {
		let mut corrupt = original.clone();
		corrupt[field] = malformed;
		std::fs::write(&path, serde_json::to_vec(&corrupt).unwrap()).unwrap();
		assert!(inventory_records_at(root.path(), InventoryLimits::default()).is_err());
		let error = inventory_page_rows_at(root.path(), Some("main"), InventoryLimits::default())
			.expect_err("host projection must not skip schema validation");
		assert!(
			error
				.to_string()
				.contains("corrupt durable inventory metadata"),
			"{field}: {error}"
		);
	}
	std::fs::write(&path, serde_json::to_vec(&original).unwrap()).unwrap();
	let rows =
		inventory_page_rows_at(root.path(), Some("main"), InventoryLimits::default()).unwrap();
	assert_eq!(rows.len(), 1);
	assert_eq!(rows[0]["id"], "1a14-1-1");
	// Even a filter returning no rows must fully validate every original file.
	std::fs::write(&path, b"{incomplete private record").unwrap();
	assert!(
		inventory_page_rows_at(root.path(), Some("unselected"), InventoryLimits::default())
			.is_err()
	);
}

#[test]
fn generic_inventory_projection_keeps_final_metadata_and_membership_fences() {
	for change_membership in [false, true] {
		let root = fixture();
		let path = write_record(root.path(), 1);
		let mut mutated = false;
		let error = inventory_projected_at(root.path(), InventoryLimits::default(), |record| {
			if !mutated {
				mutated = true;
				if change_membership {
					write_record(root.path(), 2);
				} else {
					let mut changed: Value =
						serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
					changed["args"] =
						json!(["different private data after the initial verified read"]);
					std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
				}
			}
			record.id
		})
		.expect_err("no projected result may escape the final source checks");
		assert!(error.to_string().contains(if change_membership {
			"membership changed"
		} else {
			"metadata changed"
		}));
	}
}

#[test]
fn projected_inventory_preserves_ignored_fields_and_unselected_wide_timestamps() {
	let root = fixture();
	let selected = write_record(root.path(), 1);
	let mut known: Value = serde_json::from_slice(&std::fs::read(&selected).unwrap()).unwrap();
	known["unrecognized_private_field"] = json!({"ignored":"PRIVATE_UNKNOWN_ACCEPTED"});
	std::fs::write(&selected, serde_json::to_vec(&known).unwrap()).unwrap();
	let unselected = write_record(root.path(), 2);
	let mut record: JobRecord =
		serde_json::from_slice(&std::fs::read(&unselected).unwrap()).unwrap();
	record.host = "mac".into();
	record.created_unix_ms = u128::MAX;
	record.args = vec!["PRIVATE_UNSELECTED_WIDE_TIMESTAMP".into()];
	std::fs::write(&unselected, serde_json::to_vec(&record).unwrap()).unwrap();
	// The baseline fully decodes this record but filters it before json! would
	// try to represent its u128 as a serde_json::Value integer. Keep that order.
	assert_eq!(
		inventory_records_at(root.path(), InventoryLimits::default())
			.unwrap()
			.len(),
		2
	);
	let expected = legacy_page_rows(root.path(), Some("main"));
	let projected =
		inventory_page_rows_at(root.path(), Some("main"), InventoryLimits::default()).unwrap();
	assert_eq!(projected, expected);
	let params = ProcessListPageParams {
		host: Some("main".into()),
		..Default::default()
	};
	let old = page_job_rows(&expected, &params, "same-private-source").unwrap();
	let new = page_job_rows(&projected, &params, "same-private-source").unwrap();
	assert_eq!(new, old);
	assert!(!new.contains("PRIVATE_"));
	assert_eq!(projected.len(), 1);
	// Validation errors in later files must still precede JSON projection,
	// including when an earlier selected timestamp exceeds Value's range.
	let mut selected_record: JobRecord =
		serde_json::from_slice(&std::fs::read(&selected).unwrap()).unwrap();
	selected_record.created_unix_ms = u128::MAX;
	std::fs::write(&selected, serde_json::to_vec(&selected_record).unwrap()).unwrap();
	std::fs::write(&unselected, b"{corrupt later original").unwrap();
	let error = inventory_page_rows_at(root.path(), Some("main"), InventoryLimits::default())
		.err()
		.unwrap();
	assert!(error
		.to_string()
		.contains("corrupt durable inventory metadata"));
}
