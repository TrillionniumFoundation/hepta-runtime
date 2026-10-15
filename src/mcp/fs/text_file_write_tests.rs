// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
//! Real local filesystem tests for bounded, fingerprinted UTF-8 publication.

#[cfg(target_os = "linux")]
mod linux {
	use super::super::{linux as publisher, valid_expectation};
	use sha2::{Digest, Sha256};
	use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

	fn digest(raw: &[u8]) -> String {
		Sha256::digest(raw)
			.iter()
			.map(|b| format!("{b:02x}"))
			.collect::<String>()
	}

	#[test]
	fn create_replace_append_preserve_utf8_and_mode() {
		let root = tempfile::tempdir().unwrap();
		let target = root.path().join("plain.txt");
		assert!(valid_expectation("create", "absent"));
		assert!(!valid_expectation("replace", "absent"));
		assert!(!valid_expectation("append", &"X".repeat(64)));
		let first = publisher::publish(&target, "create", "absent", "A中文\n").unwrap();
		assert!(first.was_new_file);
		assert_eq!(std::fs::read_to_string(&target).unwrap(), "A中文\n");
		assert_eq!(first.sha256, digest("A中文\n".as_bytes()));
		std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
		let second = publisher::publish(&target, "replace", &first.sha256, "B α\n").unwrap();
		assert!(!second.was_new_file);
		assert_eq!(std::fs::read_to_string(&target).unwrap(), "B α\n");
		assert_eq!(std::fs::metadata(&target).unwrap().mode() & 0o777, 0o644);
		let third = publisher::publish(&target, "append", &second.sha256, "中文🦀\n").unwrap();
		assert_eq!(std::fs::read_to_string(&target).unwrap(), "B α\n中文🦀\n");
		assert_eq!(third.sha256, digest("B α\n中文🦀\n".as_bytes()));
		assert_ne!(second.version, third.version);
	}

	#[test]
	fn stale_digest_and_duplicate_create_preserve_content() {
		let root = tempfile::tempdir().unwrap();
		let p = root.path().join("file");
		publisher::publish(&p, "create", "absent", "original").unwrap();
		assert!(publisher::publish(&p, "create", "absent", "overwrite").is_err());
		assert!(publisher::publish(&p, "replace", &digest(b"other"), "overwrite").is_err());
		assert!(publisher::publish(&p, "append", &digest(b"other"), "X").is_err());
		assert_eq!(std::fs::read_to_string(&p).unwrap(), "original");
		assert!(root.path().read_dir().unwrap().all(|e| {
			!e.unwrap()
				.file_name()
				.to_string_lossy()
				.starts_with(".hepta-text-")
		}));
	}

	#[test]
	fn source_symlink_and_parent_symlink_refused() {
		let root = tempfile::tempdir().unwrap();
		let real = root.path().join("real");
		std::fs::create_dir(&real).unwrap();
		let file = real.join("source");
		std::fs::write(&file, b"unchanged").unwrap();
		let expected = digest(b"unchanged");
		symlink(&file, root.path().join("alias")).unwrap();
		assert!(publisher::publish(&root.path().join("alias"), "append", &expected, "x").is_err());
		symlink(&real, root.path().join("diralias")).unwrap();
		assert!(publisher::publish(
			&root.path().join("diralias/source"),
			"replace",
			&expected,
			"x"
		)
		.is_err());
		assert!(
			publisher::publish(&root.path().join("diralias/new"), "create", "absent", "x").is_err()
		);
		assert_eq!(std::fs::read(&file).unwrap(), b"unchanged");
	}

	#[test]
	fn existing_hardlink_or_executable_refused() {
		let root = tempfile::tempdir().unwrap();
		let file = root.path().join("file");
		std::fs::write(&file, b"safe").unwrap();
		let linked = root.path().join("linked");
		std::fs::hard_link(&file, &linked).unwrap();
		assert!(publisher::publish(&file, "append", &digest(b"safe"), "x").is_err());
		assert_eq!(std::fs::read(&linked).unwrap(), b"safe");
		std::fs::remove_file(&linked).unwrap();
		std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap();
		assert!(publisher::publish(&file, "replace", &digest(b"safe"), "x").is_err());
		assert_eq!(std::fs::read(&file).unwrap(), b"safe");
	}

	#[test]
	fn existing_readonly_owner_file_is_not_replaced() {
		let root = tempfile::tempdir().unwrap();
		let path = root.path().join("readonly");
		std::fs::write(&path, b"protected").unwrap();
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
		assert!(publisher::publish(&path, "replace", &digest(b"protected"), "rewrite").is_err());
		assert_eq!(std::fs::read(&path).unwrap(), b"protected");
	}

	#[test]
	fn refuse_large_files_and_invalid_existing_utf8() {
		let root = tempfile::tempdir().unwrap();
		let file = root.path().join("large");
		std::fs::write(&file, vec![b'x'; (4 * 1024 * 1024) + 1]).unwrap();
		assert!(publisher::publish(&file, "append", &digest(b"irrelevant"), "x").is_err());
		let bad = root.path().join("bad-utf8");
		std::fs::write(&bad, [0xff, 0xfe]).unwrap();
		assert!(publisher::publish(&bad, "replace", &digest(&[0xff, 0xfe]), "new").is_err());
		assert_eq!(std::fs::read(&bad).unwrap(), [0xff, 0xfe]);
	}

	#[test]
	fn no_traversal_or_directory_target() {
		let root = tempfile::tempdir().unwrap();
		assert!(publisher::publish(root.path(), "create", "absent", "x").is_err());
		assert!(
			publisher::publish(&root.path().join("missing/target"), "create", "absent", "x")
				.is_err()
		);
		assert!(publisher::publish(
			std::path::Path::new("/tmp/../tmp/nothing"),
			"create",
			"absent",
			"x"
		)
		.is_err());
	}

	#[test]
	fn owner_and_permission_report_are_not_assumed() {
		let root = tempfile::tempdir().unwrap();
		let path = root.path().join("new");
		let output = publisher::publish(&path, "create", "absent", "").unwrap();
		assert_eq!(output.bytes, 0);
		assert_eq!(output.sha256, digest(b""));
		assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
		assert_eq!(output.version.split(':').count(), 7);
	}
}
