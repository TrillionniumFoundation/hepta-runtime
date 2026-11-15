// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Scratch adoption and replacement safety at real filesystem boundaries.

use super::*;
#[cfg(target_os = "linux")]
use std::os::unix::fs::symlink;

#[cfg(target_os = "linux")]
fn binding(root: &Directory) -> String {
	let (device, inode) = root.identity();
	serde_json::to_string(&OwnerBinding {
		schema: "hepta.rea.engine-scratch-owner.v1".into(),
		job_id: "owned-job".into(),
		launch_nonce: "a".repeat(32),
		path: root.path.clone(),
		device,
		inode,
	})
	.unwrap()
}

#[cfg(target_os = "linux")]
#[test]
fn worker_adopts_exact_owner_and_defers_removal_to_original_owner() {
	let temp = tempfile::tempdir().unwrap();
	let root = Directory::create(temp.path(), "engine-scratch").unwrap();
	let work = create(
		temp.path(),
		"ghidra",
		Some(binding(&root)),
		Some("owned-job".into()),
	)
	.unwrap();
	assert_eq!(work.cleanup_owner(), "durable_job");
	assert_eq!(work.parent(), Some(root.path.as_path()));
	let claim: serde_json::Value =
		serde_json::from_slice(&std::fs::read(root.path.join("claim.json")).unwrap()).unwrap();
	assert_eq!(
		claim["owner"],
		serde_json::from_str::<serde_json::Value>(&binding(&root)).unwrap()
	);
	assert_eq!(claim["worker_pid"], std::process::id());
	let work_path = work.to_path_buf();
	let removed = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap()
		.block_on(work.finish())
		.unwrap();
	assert!(!removed);
	assert!(work_path.is_dir());
	assert!(root.path.join("claim.json").is_file());
	let path = root.path.clone();
	root.remove().unwrap();
	assert!(!path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn cleanup_refuses_rebound_parent_even_when_absolute_leaf_inode_is_unchanged() {
	let temp = tempfile::tempdir().unwrap();
	let parent = temp.path().join("parent");
	std::fs::create_dir(&parent).unwrap();
	let work = create(&parent, "jadx", None, None).unwrap();
	let leaf = work.file_name().unwrap().to_owned();
	std::fs::write(work.join("preserve"), b"original private data").unwrap();
	let old_parent = temp.path().join("old-parent");
	std::fs::rename(&parent, &old_parent).unwrap();
	std::fs::create_dir(&parent).unwrap();
	std::fs::rename(old_parent.join(&leaf), parent.join(&leaf)).unwrap();
	std::fs::create_dir(old_parent.join(&leaf)).unwrap();
	assert!(work.directory.remove().is_err());
	assert_eq!(
		std::fs::read(parent.join(&leaf).join("preserve")).unwrap(),
		b"original private data"
	);
	assert!(old_parent.join(&leaf).is_dir());
}

#[cfg(target_os = "linux")]
#[test]
fn wrong_owner_or_substituted_inode_cannot_be_adopted() {
	let temp = tempfile::tempdir().unwrap();
	let root = Directory::create(temp.path(), "engine-scratch").unwrap();
	let original = binding(&root);
	assert!(create(
		temp.path(),
		"jadx",
		Some(original.clone()),
		Some("other-job".into())
	)
	.is_err());
	std::fs::rename(&root.path, temp.path().join("retained-original")).unwrap();
	let replacement = Directory::create(temp.path(), "engine-scratch").unwrap();
	std::fs::write(
		replacement.path.join("preserve"),
		b"not-owned-by-this-request",
	)
	.unwrap();
	assert!(create(
		temp.path(),
		"jadx",
		Some(original),
		Some("owned-job".into())
	)
	.is_err());
	assert!(replacement.path.join("preserve").is_file());
	assert!(!replacement.path.join("claim.json").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn cleanup_refuses_a_replaced_root_and_unlinks_symlinks_without_following_them() {
	let temp = tempfile::tempdir().unwrap();
	let external = temp.path().join("external");
	std::fs::create_dir(&external).unwrap();
	std::fs::write(external.join("preserve"), b"external-data").unwrap();
	let work = create(temp.path(), "jadx", None, None).unwrap();
	symlink(&external, work.join("link")).unwrap();
	work.directory.remove().unwrap();
	assert_eq!(
		std::fs::read(external.join("preserve")).unwrap(),
		b"external-data"
	);
	let work = create(temp.path(), "jadx", None, None).unwrap();
	let path = work.to_path_buf();
	std::fs::rename(&path, temp.path().join("retained-owned")).unwrap();
	std::fs::create_dir(&path).unwrap();
	std::fs::write(path.join("preserve"), b"replacement").unwrap();
	assert!(work.directory.remove().is_err());
	assert!(path.join("preserve").is_file());
	assert!(temp.path().join("retained-owned").is_dir());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platform_refuses_creation_and_adoption_without_scratch_changes() {
	use std::os::unix::fs::{MetadataExt, PermissionsExt};
	let temp = tempfile::tempdir().unwrap();
	let parent = std::fs::canonicalize(temp.path()).unwrap();
	let existing = parent.join("engine-scratch");
	std::fs::create_dir(&existing).unwrap();
	std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o700)).unwrap();
	let sentinel = existing.join("sentinel");
	std::fs::write(&sentinel, b"existing private data").unwrap();
	let held = std::fs::metadata(&existing).unwrap();
	let error = "Static engine scratch lifecycle requires Linux";
	assert_eq!(
		Directory::create(&parent, "new-owned")
			.err()
			.unwrap()
			.to_string(),
		error
	);
	assert_eq!(
		Directory::open(&existing, held.dev(), held.ino())
			.err()
			.unwrap()
			.to_string(),
		error
	);
	let owner = serde_json::to_string(&OwnerBinding {
		schema: "hepta.rea.engine-scratch-owner.v1".into(),
		job_id: "owned-job".into(),
		launch_nonce: "a".repeat(32),
		path: existing.clone(),
		device: held.dev(),
		inode: held.ino(),
	})
	.unwrap();
	for engine in ["ghidra", "jadx"] {
		assert_eq!(
			create(&parent, engine, None, None)
				.err()
				.unwrap()
				.to_string(),
			error
		);
		assert_eq!(
			create(
				&parent,
				engine,
				Some(owner.clone()),
				Some("owned-job".into())
			)
			.err()
			.unwrap()
			.to_string(),
			error
		);
	}
	assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 1);
	assert_eq!(std::fs::read_dir(&existing).unwrap().count(), 1);
	assert!(!existing.join("claim.json").exists());
	assert_eq!(std::fs::read(sentinel).unwrap(), b"existing private data");
	let after = std::fs::metadata(existing).unwrap();
	assert_eq!(
		(held.dev(), held.ino(), held.mode()),
		(after.dev(), after.ino(), after.mode())
	);
}
