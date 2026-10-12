// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
//! Isolated native directory/create and no-replace file move regressions.

#[cfg(target_os = "linux")]
mod linux {
	use super::super::local_linux;
	use std::os::unix::fs::{symlink, MetadataExt};
	use std::path::Path;

	#[test]
	fn creates_nested_private_directories_and_idempotently_reuses_them() {
		let temp = tempfile::tempdir().unwrap();
		let p = temp.path().join("one/two/three");
		assert!(local_linux::make_directories(&p).unwrap());
		assert!(!local_linux::make_directories(&p).unwrap());
		assert!(p.is_dir());
		assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o700);
	}

	#[test]
	fn refuses_symlinked_parents_and_leaf_files() {
		let temp = tempfile::tempdir().unwrap();
		let p = temp.path();
		std::fs::create_dir(p.join("real")).unwrap();
		symlink(p.join("real"), p.join("alias")).unwrap();
		let parent_link = p.join("alias/forbidden");
		assert!(local_linux::make_directories(&parent_link).is_err());
		assert!(!p.join("real/forbidden").exists());
		symlink(p.join("real"), p.join("leaflink")).unwrap();
		assert!(local_linux::make_directories(&p.join("leaflink")).is_err());
		std::fs::write(p.join("file"), b"x").unwrap();
		assert!(local_linux::make_directories(&p.join("file")).is_err());
	}

	#[test]
	fn rejects_root_parent_and_dot_traversal() {
		assert!(local_linux::make_directories(Path::new("/")).is_err());
		assert!(local_linux::make_directories(Path::new("../x")).is_err());
		assert!(local_linux::make_directories(Path::new("/tmp/../forbidden")).is_err());
	}

	#[test]
	fn move_is_atomic_no_overwrite_and_retains_inode_metadata() {
		let temp = tempfile::tempdir().unwrap();
		let a = temp.path().join("old");
		let b = temp.path().join("new");
		let alias = temp.path().join("hardlink");
		std::fs::write(&a, b"hello").unwrap();
		std::fs::hard_link(&a, &alias).unwrap();
		let before = std::fs::metadata(&a).unwrap();
		local_linux::move_noreplace(&a, &b).unwrap();
		let after = std::fs::metadata(&b).unwrap();
		assert_eq!(before.ino(), after.ino());
		assert_eq!(before.dev(), after.dev());
		assert_eq!(after.nlink(), 2);
		assert_eq!(std::fs::read(&alias).unwrap(), b"hello");
		assert!(!a.exists());
		assert_eq!(std::fs::read(&b).unwrap(), b"hello");
		assert!(local_linux::move_noreplace(&a, &b).is_err());
	}

	#[test]
	fn existing_target_is_never_overwritten() {
		let temp = tempfile::tempdir().unwrap();
		let a = temp.path().join("source");
		let b = temp.path().join("target");
		std::fs::write(&a, b"original").unwrap();
		std::fs::write(&b, b"keep").unwrap();
		assert!(local_linux::move_noreplace(&a, &b).is_err());
		assert_eq!(std::fs::read(&a).unwrap(), b"original");
		assert_eq!(std::fs::read(&b).unwrap(), b"keep");
	}

	#[test]
	fn destination_symlink_is_never_replaced() {
		let temp = tempfile::tempdir().unwrap();
		let a = temp.path().join("source");
		let target = temp.path().join("actual");
		let b = temp.path().join("alias");
		std::fs::write(&a, b"original").unwrap();
		std::fs::write(&target, b"leave").unwrap();
		symlink(&target, &b).unwrap();
		assert!(local_linux::move_noreplace(&a, &b).is_err());
		assert_eq!(std::fs::read(&a).unwrap(), b"original");
		assert_eq!(std::fs::read(&target).unwrap(), b"leave");
	}

	#[test]
	fn destination_hardlink_to_source_is_not_a_move() {
		let temp = tempfile::tempdir().unwrap();
		let a = temp.path().join("source");
		let b = temp.path().join("existing-hardlink");
		std::fs::write(&a, b"keep both").unwrap();
		std::fs::hard_link(&a, &b).unwrap();
		assert!(local_linux::move_noreplace(&a, &b).is_err());
		assert_eq!(std::fs::read(&a).unwrap(), b"keep both");
		assert_eq!(std::fs::read(&b).unwrap(), b"keep both");
	}

	#[test]
	fn source_symlink_or_directory_is_rejected() {
		let temp = tempfile::tempdir().unwrap();
		let p = temp.path();
		std::fs::create_dir(p.join("dir")).unwrap();
		std::fs::write(p.join("regular"), b"x").unwrap();
		symlink(p.join("regular"), p.join("link")).unwrap();
		assert!(local_linux::move_noreplace(&p.join("dir"), &p.join("dirout")).is_err());
		assert!(local_linux::move_noreplace(&p.join("link"), &p.join("linkout")).is_err());
		assert!(p.join("link").is_symlink());
		assert!(p.join("dir").is_dir());
		assert!(local_linux::move_noreplace(&p.join("regular"), &p.join("regular")).is_err());
	}

	#[test]
	fn destination_parent_must_exist_and_cannot_be_symlink() {
		let temp = tempfile::tempdir().unwrap();
		let p = temp.path();
		std::fs::write(p.join("source"), b"x").unwrap();
		std::fs::create_dir(p.join("destination")).unwrap();
		symlink(p.join("destination"), p.join("alias")).unwrap();
		assert!(local_linux::move_noreplace(&p.join("source"), &p.join("missing/result")).is_err());
		assert!(local_linux::move_noreplace(&p.join("source"), &p.join("alias/result")).is_err());
		assert!(p.join("source").exists());
	}
	#[test]
	fn directory_move_preserves_nonempty_subtree_inodes_and_contents() {
		let temp = tempfile::tempdir().unwrap();
		let p = temp.path();
		std::fs::create_dir_all(p.join("from/child/grandchild")).unwrap();
		std::fs::write(p.join("from/child/grandchild/content"), b"real content").unwrap();
		let source_inode = std::fs::metadata(p.join("from")).unwrap().ino();
		let child_inode = std::fs::metadata(p.join("from/child")).unwrap().ino();
		local_linux::move_directory_noreplace(&p.join("from"), &p.join("after")).unwrap();
		assert!(!p.join("from").exists());
		assert_eq!(
			std::fs::metadata(p.join("after")).unwrap().ino(),
			source_inode
		);
		assert_eq!(
			std::fs::metadata(p.join("after/child")).unwrap().ino(),
			child_inode
		);
		assert_eq!(
			std::fs::read(p.join("after/child/grandchild/content")).unwrap(),
			b"real content"
		);
	}

	#[test]
	fn directory_move_denies_any_existing_destination_even_when_empty() {
		let temp = tempfile::tempdir().unwrap();
		let p = temp.path();
		std::fs::create_dir(p.join("from")).unwrap();
		std::fs::create_dir(p.join("to")).unwrap();
		assert!(local_linux::move_directory_noreplace(&p.join("from"), &p.join("to")).is_err());
		assert!(p.join("from").is_dir() && p.join("to").is_dir());
	}

	#[test]
	fn directory_move_rejects_source_symlink_or_plain_file() {
		let temp = tempfile::tempdir().unwrap();
		let p = temp.path();
		std::fs::create_dir(p.join("real")).unwrap();
		std::fs::write(p.join("file"), b"not a directory").unwrap();
		symlink(p.join("real"), p.join("link")).unwrap();
		assert!(local_linux::move_directory_noreplace(&p.join("link"), &p.join("bad")).is_err());
		assert!(local_linux::move_directory_noreplace(&p.join("file"), &p.join("bad")).is_err());
		assert!(p.join("link").is_symlink());
		assert!(p.join("file").is_file());
	}

	#[test]
	fn directory_move_rejects_symlink_parent_and_existing_leaf_symlink() {
		let temp = tempfile::tempdir().unwrap();
		let p = temp.path();
		std::fs::create_dir(p.join("source")).unwrap();
		std::fs::create_dir(p.join("parent")).unwrap();
		symlink(p.join("parent"), p.join("parent-link")).unwrap();
		assert!(local_linux::move_directory_noreplace(
			&p.join("source"),
			&p.join("parent-link/new")
		)
		.is_err());
		symlink(p.join("parent"), p.join("destination-link")).unwrap();
		assert!(local_linux::move_directory_noreplace(
			&p.join("source"),
			&p.join("destination-link")
		)
		.is_err());
		assert!(p.join("source").is_dir());
		assert!(p.join("destination-link").is_symlink());
	}

	#[test]
	fn directory_move_rejects_descendant_moves_and_absent_destination_parent() {
		let temp = tempfile::tempdir().unwrap();
		let p = temp.path();
		std::fs::create_dir_all(p.join("source/child")).unwrap();
		assert!(local_linux::move_directory_noreplace(
			&p.join("source"),
			&p.join("source/child/inner")
		)
		.is_err());
		assert!(
			local_linux::move_directory_noreplace(&p.join("source"), &p.join("missing/new"))
				.is_err()
		);
		assert!(p.join("source/child").is_dir());
	}

	#[test]
	fn directory_move_keeps_internal_symlinks_as_links_without_following() {
		let temp = tempfile::tempdir().unwrap();
		let p = temp.path();
		std::fs::create_dir(p.join("source")).unwrap();
		std::fs::write(p.join("external"), b"unchanged").unwrap();
		symlink(p.join("external"), p.join("source/child-link")).unwrap();
		local_linux::move_directory_noreplace(&p.join("source"), &p.join("new")).unwrap();
		assert!(p.join("new/child-link").is_symlink());
		assert_eq!(std::fs::read(p.join("external")).unwrap(), b"unchanged");
	}
}
