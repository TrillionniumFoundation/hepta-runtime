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
