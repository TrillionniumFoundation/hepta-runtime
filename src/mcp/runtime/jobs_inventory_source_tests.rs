// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Whole-original content checks and descriptor-relative final fences.
use super::*;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
	let owner = tempfile::tempdir().unwrap();
	let root = owner.path().canonicalize().unwrap().join("state");
	std::fs::create_dir(&root).unwrap();
	std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
	std::fs::create_dir(root.join("jobs")).unwrap();
	std::fs::set_permissions(root.join("jobs"), std::fs::Permissions::from_mode(0o700)).unwrap();
	let path = root.join("jobs/original.json");
	let value = json!({"id":"original","host":"main","created_unix_ms":1,
		"ssh_target":"PRIVATE_SSH","unit":"PRIVATE_UNIT","remote_job_dir":"/PRIVATE",
		"executable":"/bin/true","args":["A".repeat(128 * 1024)],"cwd":null,"env_keys":[],
		"idempotency_key":null,"request_fingerprint":0,"launch_state":"launched"});
	std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	(owner, root, path)
}

#[test]
fn complete_schema_validates_private_text_without_retaining_it() {
	let (_owner, root, path) = fixture();
	let original = std::fs::read(&path).unwrap();
	let (rows, source) = observe(&root, InventoryLimits::default(), |record| {
		assert_eq!(record.args.len(), 1);
		record.id
	})
	.unwrap();
	assert_eq!(rows, ["original"]);
	assert_eq!(
		validate(&root, InventoryLimits::default(), &source).unwrap(),
		ValidationPath::OriginalBytes
	);
	assert_eq!(std::fs::read(&path).unwrap(), original);
	let mut corrupt: Value = serde_json::from_slice(&original).unwrap();
	corrupt["args"] = json!([false]);
	std::fs::write(&path, serde_json::to_vec(&corrupt).unwrap()).unwrap();
	let error = observe(&root, InventoryLimits::default(), |record| record.id)
		.err()
		.unwrap();
	assert!(error
		.to_string()
		.contains("corrupt durable inventory metadata"));
}

#[test]
fn discarded_string_schema_matches_owned_decoding_for_private_type_counterexamples() {
	let (_owner, _root, path) = fixture();
	let original: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
	for field in [
		"ssh_target",
		"unit",
		"remote_job_dir",
		"executable",
		"args",
		"cwd",
		"env_keys",
		"request_digest",
		"launch_error",
	] {
		for value in [
			Value::Null,
			json!(false),
			json!(17),
			json!({"not":"a string"}),
			json!([false]),
			json!([]),
			json!("escaped\n\t\"\\控制"),
			json!(["escaped\n\t\"\\控制"]),
		] {
			let mut record = original.clone();
			record[field] = value;
			let bytes = serde_json::to_vec(&record).unwrap();
			let owned = serde_json::from_slice::<JobRecord>(&bytes).is_ok();
			let discarded =
				serde_json::from_slice::<JobRecordData<ValidatedJobString>>(&bytes).is_ok();
			assert_eq!(owned, discarded, "{field}: {}", record[field]);
		}
	}
}

#[test]
fn continuation_hashes_private_bytes_even_if_every_stamp_matches() {
	let (_owner, root, path) = fixture();
	let (_, mut source) = observe(&root, InventoryLimits::default(), |record| record.id).unwrap();
	let mut bytes = std::fs::read(&path).unwrap();
	let at = bytes.iter().position(|byte| *byte == b'A').unwrap();
	bytes[at] = b'B';
	std::fs::write(&path, bytes).unwrap();
	// Model a filesystem with no useful timestamp distinction. The production
	// proof is never caller-controlled; this deliberately makes the old stamp
	// equal to the new file so only a full original-content check can refuse it.
	source.records[0].stamp = stamp(&std::fs::metadata(&path).unwrap());
	let error = validate(&root, InventoryLimits::default(), &source).unwrap_err();
	assert!(error.to_string().contains("original content changed"));
}

#[test]
fn descriptor_stat_matches_the_original_opened_metadata_stamp() {
	let (_owner, root, path) = fixture();
	let directories = Directories::open(&root).unwrap();
	assert_eq!(
		named_stamp(&directories.jobs, "original.json").unwrap(),
		stamp(&std::fs::metadata(&path).unwrap())
	);
}

#[test]
fn final_named_fence_refuses_substituted_symlink_hardlink_directory_or_fifo() {
	for replacement in ["symlink", "hardlink", "directory", "fifo"] {
		let (_owner, root, path) = fixture();
		let began = Instant::now();
		let result = observe(&root, InventoryLimits::default(), |record| {
			let held = root.join("held-original");
			std::fs::rename(&path, &held).unwrap();
			match replacement {
				"symlink" => symlink(&held, &path).unwrap(),
				"hardlink" => std::fs::hard_link(&held, &path).unwrap(),
				"directory" => std::fs::create_dir(&path).unwrap(),
				"fifo" => {
					let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
					assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
				}
				_ => unreachable!(),
			}
			record.id
		});
		assert!(result.is_err(), "{replacement}");
		assert!(began.elapsed() < Duration::from_secs(1), "{replacement}");
	}
}

#[test]
fn final_root_binding_rejects_directory_replacement_after_read() {
	for replace_root in [false, true] {
		let (_owner, root, _path) = fixture();
		let result = observe(&root, InventoryLimits::default(), |record| {
			if replace_root {
				std::fs::rename(&root, root.with_file_name("held-state")).unwrap();
				std::fs::create_dir(&root).unwrap();
				std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
				std::fs::create_dir(root.join("jobs")).unwrap();
			} else {
				std::fs::rename(root.join("jobs"), root.join("held-jobs")).unwrap();
				std::fs::create_dir(root.join("jobs")).unwrap();
			}
			record.id
		});
		assert!(result.is_err());
	}
}

#[test]
fn cold_and_continuation_paths_keep_identical_source_limits() {
	let (_owner, root, path) = fixture();
	let (_, source) = observe(&root, InventoryLimits::default(), |record| record.id).unwrap();
	for limits in [
		InventoryLimits {
			records: 0,
			..InventoryLimits::default()
		},
		InventoryLimits {
			bytes: 1,
			..InventoryLimits::default()
		},
		InventoryLimits {
			record_bytes: std::fs::metadata(&path).unwrap().len() - 1,
			..InventoryLimits::default()
		},
		InventoryLimits {
			time: Duration::ZERO,
			..InventoryLimits::default()
		},
	] {
		assert!(observe(&root, limits, |record| record.id).is_err());
		assert!(validate(&root, limits, &source).is_err());
	}
}

#[cfg(target_os = "linux")]
#[test]
fn continuation_refuses_mapped_private_change_with_unchanged_content_watch() {
	let (_owner, root, path) = fixture();
	let bytes = std::fs::read(&path).unwrap();
	let at = bytes
		.windows(8)
		.position(|part| part == b"AAAAAAAA")
		.unwrap();
	let file = OpenOptions::new()
		.read(true)
		.write(true)
		.open(&path)
		.unwrap();
	let mapping = unsafe {
		libc::mmap(
			std::ptr::null_mut(),
			bytes.len(),
			libc::PROT_READ | libc::PROT_WRITE,
			libc::MAP_SHARED,
			file.as_raw_fd(),
			0,
		)
	};
	assert_ne!(mapping, libc::MAP_FAILED);
	// Dirty this page before observing it. Keep both the mapping and its file
	// descriptor alive so a later close-write event cannot mask the defect.
	unsafe { std::ptr::write_volatile(mapping.cast::<u8>().add(at), b'B') };
	let (_, source) = observe(&root, InventoryLimits::default(), |record| record.id).unwrap();
	let before = content_watch(&source.directories.jobs);
	assert!(matches!(
		before,
		Some(namespace_version::Version::Watch(_, _))
	));
	unsafe { std::ptr::write_volatile(mapping.cast::<u8>().add(at), b'C') };
	let original_changed = std::fs::read(&path).unwrap()[at] == b'C';
	let after = content_watch(&source.directories.jobs);
	let result = validate(&root, InventoryLimits::default(), &source);
	let unmap = unsafe { libc::munmap(mapping, bytes.len()) };
	drop(file);
	assert_eq!(unmap, 0);
	assert!(original_changed);
	assert_eq!(before, after, "fixture must exercise the silent mmap path");
	assert!(result
		.unwrap_err()
		.to_string()
		.contains("original content changed"));
}
