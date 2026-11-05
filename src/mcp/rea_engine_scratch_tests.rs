// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Scratch adoption and replacement safety at real filesystem boundaries.

use super::*;
use std::os::unix::fs::symlink;

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
