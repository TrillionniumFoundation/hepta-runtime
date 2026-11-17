// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Cache generations must observe rapid namespace changes without timed sleeps.
use super::*;

#[test]
fn fingerprint_tracks_names_and_replaced_inodes_without_reading_payloads() {
	let root = tempfile::tempdir().unwrap();
	let directory = File::open(root.path()).unwrap();
	let empty = fingerprint(&directory).unwrap();
	let path = root.path().join("record.json");
	std::fs::write(&path, b"first").unwrap();
	let first = fingerprint(&directory).unwrap();
	assert_ne!(empty, first);
	std::fs::write(&path, b"in-place payload").unwrap();
	assert_eq!(first, fingerprint(&directory).unwrap());
	std::fs::write(root.path().join("replacement.tmp"), b"second").unwrap();
	std::fs::rename(root.path().join("replacement.tmp"), &path).unwrap();
	assert_ne!(first, fingerprint(&directory).unwrap());
	std::fs::remove_file(path).unwrap();
	assert_eq!(empty, fingerprint(&directory).unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn watched_generations_change_for_rapid_add_rename_and_remove() {
	let root = tempfile::tempdir().unwrap();
	let directory = File::open(root.path()).unwrap();
	let mut watcher = Watcher::new(4).unwrap();
	let mut previous = watcher.version(&directory).unwrap();
	for index in 0..32 {
		let path = root.path().join(format!("record-{index}"));
		std::fs::write(&path, b"metadata").unwrap();
		let added = watcher.version(&directory).unwrap();
		assert_ne!(previous, added);
		assert_eq!(added, watcher.version(&directory).unwrap());
		let moved = root.path().join(format!("moved-{index}"));
		std::fs::rename(&path, &moved).unwrap();
		let renamed = watcher.version(&directory).unwrap();
		assert_ne!(added, renamed);
		std::fs::remove_file(moved).unwrap();
		previous = watcher.version(&directory).unwrap();
		assert_ne!(renamed, previous);
	}
}

#[cfg(target_os = "linux")]
#[test]
fn evicted_watch_never_reuses_an_old_cache_token() {
	let roots: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
	let directories: Vec<_> = roots
		.iter()
		.map(|root| File::open(root.path()).unwrap())
		.collect();
	let mut watcher = Watcher::new(2).unwrap();
	let original = watcher.version(&directories[0]).unwrap();
	for directory in &directories[1..] {
		watcher.version(directory).unwrap();
	}
	assert_eq!(watcher.watches.len(), 2);
	assert_ne!(original, watcher.version(&directories[0]).unwrap());
	assert_eq!(watcher.watches.len(), 2);
}

#[cfg(target_os = "linux")]
#[test]
fn dropped_kernel_events_invalidate_every_cached_namespace() {
	let roots: Vec<_> = (0..2).map(|_| tempfile::tempdir().unwrap()).collect();
	let directories: Vec<_> = roots
		.iter()
		.map(|root| File::open(root.path()).unwrap())
		.collect();
	let mut watcher = Watcher::new(4).unwrap();
	let versions: Vec<_> = directories
		.iter()
		.map(|dir| watcher.version(dir).unwrap())
		.collect();
	watcher.changed(-1, libc::IN_Q_OVERFLOW).unwrap();
	for (directory, previous) in directories.iter().zip(versions) {
		let current = watcher.version(directory).unwrap();
		assert_ne!(previous, current);
		match (previous, current) {
			(Version::Watch(before, _), Version::Watch(after, _)) => assert_ne!(before, after),
			_ => panic!("fixture must exercise kernel watch replacement"),
		}
	}
}

#[cfg(target_os = "linux")]
#[test]
fn event_versions_preserve_the_unrelated_in_place_payload_contract() {
	let root = tempfile::tempdir().unwrap();
	let directory = File::open(root.path()).unwrap();
	let path = root.path().join("record.json");
	std::fs::write(&path, b"first").unwrap();
	let mut watcher = Watcher::new(4).unwrap();
	let before = watcher.version(&directory).unwrap();
	std::fs::write(path, b"changed payload").unwrap();
	assert_eq!(before, watcher.version(&directory).unwrap());
}
