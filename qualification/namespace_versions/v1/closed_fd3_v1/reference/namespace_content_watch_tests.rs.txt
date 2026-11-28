// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Composite snapshots cover every physical archive directory in one drain.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

#[test]
fn complete_archive_scope_stays_stable_and_observes_both_ends() {
	let root = tempfile::tempdir().unwrap();
	let paths: Vec<_> = (0..258)
		.map(|number| {
			let path = root.path().join(format!("directory-{number}"));
			std::fs::create_dir(&path).unwrap();
			path
		})
		.collect();
	let directories: Vec<_> = paths
		.iter()
		.map(|path| Arc::new(File::open(path).unwrap()))
		.collect();
	let watches = ContentWatchSet::new(&directories).unwrap().unwrap();
	{
		let state = watches.state.lock().unwrap();
		assert_eq!(state.watcher.watches.len(), directories.len());
		for (watch, directory) in state.watcher.watches.iter().zip(&directories) {
			assert_eq!(watch._pin.as_raw_fd(), directory.as_raw_fd());
		}
	}
	let initial = watches.version().unwrap().unwrap();
	for _ in 0..260 {
		assert_eq!(Some(initial), watches.version().unwrap());
	}
	// Unwatched siblings do not invalidate this exact physical scope.
	std::fs::write(root.path().join("unrelated"), b"outside").unwrap();
	assert_eq!(Some(initial), watches.version().unwrap());
	std::fs::write(paths[257].join("last.json"), b"last bucket").unwrap();
	let last = watches.version().unwrap().unwrap();
	assert_ne!(initial, last);
	assert_eq!(Some(last), watches.version().unwrap());
	std::fs::write(paths[0].join("first.json"), b"legacy").unwrap();
	let first = watches.version().unwrap().unwrap();
	assert_ne!(last, first);
	assert_eq!(Some(first), watches.version().unwrap());
	// The fixed scope pins its own descriptors, rather than borrowing the
	// caller's handles or reinstalling watches on each snapshot.
	drop(directories);
	std::fs::write(paths[128].join("middle.json"), b"middle bucket").unwrap();
	let middle = watches.version().unwrap().unwrap();
	assert_ne!(first, middle);
	assert_eq!(Some(middle), watches.version().unwrap());
}

#[test]
fn composite_versions_track_in_place_bytes_permissions_and_names() {
	let root = tempfile::tempdir().unwrap();
	let directory = Arc::new(File::open(root.path()).unwrap());
	let watches = ContentWatchSet::new(std::slice::from_ref(&directory))
		.unwrap()
		.unwrap();
	let path = root.path().join("record.json");
	std::fs::write(&path, b"initial").unwrap();
	let created = watches.version().unwrap().unwrap();
	std::fs::write(&path, b"changed bytes").unwrap();
	let modified = watches.version().unwrap().unwrap();
	assert_ne!(created, modified);
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	let permissions = watches.version().unwrap().unwrap();
	assert_ne!(modified, permissions);
	let renamed = root.path().join("renamed.json");
	std::fs::rename(&path, &renamed).unwrap();
	let moved = watches.version().unwrap().unwrap();
	assert_ne!(permissions, moved);
	std::fs::remove_file(renamed).unwrap();
	let removed = watches.version().unwrap().unwrap();
	assert_ne!(moved, removed);
	assert_eq!(Some(removed), watches.version().unwrap());
}

#[test]
fn composite_identity_cannot_reuse_flat_or_other_scope_tokens() {
	let root = tempfile::tempdir().unwrap();
	let directory = Arc::new(File::open(root.path()).unwrap());
	let flat = content_version(&directory).unwrap().unwrap();
	let first = ContentWatchSet::new(std::slice::from_ref(&directory))
		.unwrap()
		.unwrap();
	let second = ContentWatchSet::new(std::slice::from_ref(&directory))
		.unwrap()
		.unwrap();
	let first = first.version().unwrap().unwrap();
	let second = second.version().unwrap().unwrap();
	match (flat, first, second) {
		(Version::Watch(flat, _), Version::Watch(first, _), Version::Watch(second, _)) => {
			assert_eq!(flat & CONTENT_SET_ID, 0);
			assert_ne!(first & CONTENT_SET_ID, 0);
			assert_ne!(second & CONTENT_SET_ID, 0);
			assert_ne!(first, second);
		}
		_ => panic!("fixture must use content watches"),
	}
}

#[test]
fn lost_composite_events_disable_reuse_permanently() {
	for mask in [libc::IN_Q_OVERFLOW, libc::IN_IGNORED, libc::IN_UNMOUNT] {
		let root = tempfile::tempdir().unwrap();
		let directory = Arc::new(File::open(root.path()).unwrap());
		let watches = ContentWatchSet::new(std::slice::from_ref(&directory))
			.unwrap()
			.unwrap();
		assert!(watches.version().unwrap().is_some());
		{
			let mut state = watches.state.lock().unwrap();
			let wd = state.watcher.watches[0].wd;
			state.watcher.changed(wd, mask).unwrap();
		}
		assert_eq!(None, watches.version().unwrap());
		std::fs::write(root.path().join("later.json"), b"new original").unwrap();
		assert_eq!(None, watches.version().unwrap());
		assert_eq!(None, watches.version().unwrap());
	}
}

#[test]
fn incomplete_or_ambiguous_composite_scope_never_gets_a_token() {
	let root = tempfile::tempdir().unwrap();
	let directory = Arc::new(File::open(root.path()).unwrap());
	assert!(ContentWatchSet::new(&[]).unwrap().is_none());
	assert!(
		ContentWatchSet::new(&[directory.clone(), directory.clone()])
			.unwrap()
			.is_none()
	);
	let too_many = vec![directory.clone(); MAX_CONTENT_DIRECTORIES + 1];
	assert!(ContentWatchSet::new(&too_many).unwrap().is_none());
	let path = root.path().join("file");
	std::fs::write(&path, b"not a directory").unwrap();
	let file = Arc::new(File::open(path).unwrap());
	assert!(ContentWatchSet::new(&[directory, file]).unwrap().is_none());
}
