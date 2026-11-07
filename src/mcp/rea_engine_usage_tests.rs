// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Deterministic live-sample races on private fixtures; no engine qualification.

use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

#[test]
fn device_identity_comparison_never_truncates_or_accepts_negative_ids() {
	assert!(same_device(7_i32, 7));
	assert!(same_device(u64::MAX, u64::MAX));
	assert!(!same_device(-1_i32, u64::MAX));
	assert!(!same_device(7_u64, 8));
	assert!(!same_device(u128::from(u64::MAX) + 1, 0));
}

#[test]
fn vanished_enumerated_file_is_a_sample_absence_with_owned_root_unchanged() {
	let temp = tempfile::tempdir().unwrap();
	let directory = Directory::create(temp.path(), "scratch").unwrap();
	let file = directory.path.join("temporary");
	std::fs::write(&file, b"temporary bytes").unwrap();
	let sampled = sample_with(&directory, 1024, 32, |_, name| {
		assert_eq!(name, "temporary");
		std::fs::remove_file(&file)?;
		Ok(())
	})
	.unwrap();
	assert_eq!(sampled, 0);
	directory.verify().unwrap();
}

#[test]
fn sampling_refuses_replaced_entries_and_root_rebinding() {
	let temp = tempfile::tempdir().unwrap();
	let directory = Directory::create(temp.path(), "scratch").unwrap();
	let file = directory.path.join("temporary");
	std::fs::write(&file, b"original").unwrap();
	let retained = temp.path().join("retained-file");
	assert!(sample_with(&directory, 1024, 32, |_, _| {
		std::fs::rename(&file, &retained)?;
		std::fs::write(&file, b"replacement")?;
		Ok(())
	})
	.unwrap_err()
	.to_string()
	.contains("replaced"));
	assert_eq!(std::fs::read(&retained).unwrap(), b"original");
	let original = temp.path().join("original-root");
	assert!(sample_with(&directory, 1024, 32, |_, _| {
		std::fs::rename(&directory.path, &original)?;
		std::fs::create_dir(&directory.path)?;
		Ok(())
	})
	.is_err());
	assert_eq!(
		std::fs::read(original.join("temporary")).unwrap(),
		b"replacement"
	);
	assert!(directory.path.is_dir());
}

#[test]
fn sampling_preserves_permission_symlink_and_resource_errors() {
	let temp = tempfile::tempdir().unwrap();
	let directory = Directory::create(temp.path(), "scratch").unwrap();
	let child = directory.path.join("child");
	std::fs::create_dir(&child).unwrap();
	std::fs::write(child.join("data"), b"owned").unwrap();
	assert_eq!(sample(&directory, 1024, 32).unwrap(), 5);
	assert!(sample(&directory, 4, 32).is_err());
	assert!(sample(&directory, 1024, 1).is_err());
	if unsafe { libc::geteuid() } != 0 {
		std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o0)).unwrap();
		let error = sample(&directory, 1024, 32).unwrap_err();
		assert_eq!(
			error.downcast_ref::<std::io::Error>().unwrap().kind(),
			std::io::ErrorKind::PermissionDenied
		);
		std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
	}
	let outside = temp.path().join("outside");
	std::fs::write(&outside, b"preserved").unwrap();
	symlink(&outside, directory.path.join("link")).unwrap();
	assert!(sample(&directory, 1024, 32).is_err());
	assert_eq!(std::fs::read(outside).unwrap(), b"preserved");
}

#[test]
fn sampling_never_treats_a_disappeared_root_as_an_empty_sample() {
	let temp = tempfile::tempdir().unwrap();
	let directory = Directory::create(temp.path(), "scratch").unwrap();
	std::fs::remove_dir(&directory.path).unwrap();
	assert!(sample(&directory, 1024, 32).is_err());
}

#[test]
fn sampling_distinguishes_an_unlinked_open_directory_from_a_live_renamed_directory() {
	for removed in [true, false] {
		let temp = tempfile::tempdir().unwrap();
		let directory = Directory::create(temp.path(), "scratch").unwrap();
		let child = directory.path.join("child");
		let retained = temp.path().join("retained-child");
		std::fs::create_dir(&child).unwrap();
		std::fs::write(child.join("leaf"), b"preserved").unwrap();
		let result = sample_with(&directory, 1024, 32, |_, name| {
			if name == "leaf" {
				if removed {
					std::fs::remove_file(child.join("leaf"))?;
					std::fs::remove_dir(&child)?;
				} else {
					std::fs::rename(&child, &retained)?;
				}
			}
			Ok(())
		});
		if removed {
			assert_eq!(result.unwrap(), 0);
		} else {
			assert!(result.is_err());
			assert_eq!(std::fs::read(retained.join("leaf")).unwrap(), b"preserved");
		}
		directory.verify().unwrap();
	}
}
