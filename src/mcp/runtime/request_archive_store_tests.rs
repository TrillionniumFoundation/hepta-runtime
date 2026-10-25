// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::os::unix::fs::PermissionsExt;

fn fixture() -> (tempfile::TempDir, Archive) {
	let root = tempfile::tempdir().unwrap();
	std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	let archive = open_archive(root.path()).unwrap();
	(root, archive)
}

fn record(prefix: u8, suffix: u64) -> Record {
	Record {
		request_id: format!("{prefix:02x}{suffix:062x}"),
		owner: "b".repeat(64),
		tool_name: "run_command".into(),
		state: DurableState::Unknown,
		accepted_unix_ms: suffix as u128 + 100,
		elapsed_ms: None,
	}
}

fn filename(record: &Record) -> String {
	format!("{}.json", record.request_id)
}

fn overwrite_legacy_anchor(root: &File, bytes: &[u8]) -> File {
	let mut file = open_at(
		root,
		ARCHIVE_ANCHOR,
		libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
		0o600,
	)
	.unwrap();
	file.write_all(bytes).unwrap();
	file.sync_all().unwrap();
	file
}

fn changed_legacy_bytes(original: &[u8]) -> Vec<u8> {
	let mut changed = original.to_vec();
	let position = changed.iter().rposition(u8::is_ascii_digit).unwrap();
	changed[position] = if changed[position] == b'1' {
		b'2'
	} else {
		b'1'
	};
	changed
}

#[test]
fn pinned_legacy_anchor_reuses_positional_reads_without_changing_creation_or_reopen() {
	use std::io::Seek;
	let _guard = store_lock().unwrap();
	let (root, archive) = fixture();
	let path = root.path().join(ARCHIVE_ANCHOR);
	let original = std::fs::read(&path).unwrap();
	let stamp = AnchorStamp::held(&archive.0.legacy_anchor.file).unwrap();
	let mut descriptor = &archive.0.legacy_anchor.file;
	let position = descriptor.stream_position().unwrap();
	assert_eq!(position, original.len() as u64);
	let value = record(0x12, 71);
	save_archive_with_sync(&archive, &value, false, true).unwrap();
	for _ in 0..8 {
		archive.fence_at(archive.root()).unwrap();
		assert!(archive.read_record(&filename(&value)).unwrap() == value);
		let reopened = open_archive(root.path()).unwrap();
		assert!(Arc::ptr_eq(&archive.0, &reopened.0));
	}
	std::thread::scope(|scope| {
		for _ in 0..4 {
			scope.spawn(|| {
				for _ in 0..16 {
					archive.0.legacy_anchor.fence(archive.root()).unwrap();
				}
			});
		}
	});
	assert_eq!(descriptor.stream_position().unwrap(), position);
	assert_eq!(
		AnchorStamp::held(&archive.0.legacy_anchor.file).unwrap(),
		stamp
	);
	assert_eq!(
		AnchorStamp::named(archive.root(), &archive.0.legacy_anchor.component).unwrap(),
		stamp
	);
	assert_eq!(std::fs::read(&path).unwrap(), original);
}

#[test]
fn pinned_legacy_anchor_preserves_the_entire_existing_size_bound() {
	let _guard = store_lock().unwrap();
	let (root, archive) = fixture();
	let mut bytes = std::fs::read(root.path().join(ARCHIVE_ANCHOR)).unwrap();
	let base = archive.root().try_clone().unwrap();
	drop(archive);
	bytes.resize(MAX_RECORD_BYTES, b' ');
	drop(overwrite_legacy_anchor(&base, &bytes));
	let archive = open_archive(root.path()).unwrap();
	assert_eq!(archive.0.legacy_anchor.bytes.len(), MAX_RECORD_BYTES);
	archive.fence_at(&base).unwrap();
	assert_eq!(
		std::fs::read(root.path().join(ARCHIVE_ANCHOR)).unwrap(),
		bytes
	);
	bytes.push(b' ');
	drop(overwrite_legacy_anchor(&base, &bytes));
	assert!(PinnedAnchor::open(&base).is_err());
	assert!(archive.fence_at(&base).is_err());
}

#[test]
fn pinned_legacy_anchor_rejects_same_content_named_replacement_and_does_not_rebind() {
	let _guard = store_lock().unwrap();
	let (root, archive) = fixture();
	let path = root.path().join(ARCHIVE_ANCHOR);
	let original = std::fs::read(&path).unwrap();
	let held = root.path().join("held-legacy-anchor");
	std::fs::rename(&path, &held).unwrap();
	drop(overwrite_legacy_anchor(archive.root(), &original));
	assert_ne!(
		std::fs::metadata(&path).unwrap().ino(),
		archive.0.legacy_anchor.stamp.inode
	);
	assert_eq!(std::fs::read(&path).unwrap(), original);
	assert_eq!(std::fs::read(&held).unwrap(), original);
	assert!(archive.fence_at(archive.root()).is_err());
	assert!(open_archive(root.path()).is_err());
	assert!(held.is_file());
}

#[cfg(target_os = "linux")]
#[test]
fn pinned_legacy_anchor_rejects_replacement_even_after_the_original_inode_returns() {
	let _guard = store_lock().unwrap();
	let (root, archive) = fixture();
	let path = root.path().join(ARCHIVE_ANCHOR);
	let original = std::fs::read(&path).unwrap();
	let stamp = archive.0.legacy_anchor.stamp;
	let held = root.path().join("held-legacy-anchor");
	// Let the Linux timestamp clock advance before the rename sequence. No
	// production path waits or depends on sleeps to establish a fence.
	std::thread::sleep(std::time::Duration::from_millis(20));
	std::fs::rename(&path, &held).unwrap();
	drop(overwrite_legacy_anchor(archive.root(), &original));
	std::fs::remove_file(&path).unwrap();
	std::fs::rename(&held, &path).unwrap();
	let after = std::fs::metadata(&path).unwrap();
	assert_eq!(after.ino(), stamp.inode);
	assert_eq!((after.mtime(), after.mtime_nsec()), stamp.modified);
	assert_ne!((after.ctime(), after.ctime_nsec()), stamp.changed);
	assert_eq!(std::fs::read(&path).unwrap(), original);
	assert!(archive.fence_at(archive.root()).is_err());
	assert!(open_archive(root.path()).is_err());
}

#[test]
fn pinned_legacy_anchor_rejects_same_length_edit_even_after_mtime_is_restored() {
	let _guard = store_lock().unwrap();
	let (root, archive) = fixture();
	let path = root.path().join(ARCHIVE_ANCHOR);
	let original = std::fs::read(&path).unwrap();
	let metadata = std::fs::metadata(&path).unwrap();
	let changed = changed_legacy_bytes(&original);
	let file = overwrite_legacy_anchor(archive.root(), &changed);
	file.set_times(std::fs::FileTimes::new().set_modified(metadata.modified().unwrap()))
		.unwrap();
	let after = std::fs::metadata(&path).unwrap();
	assert_eq!(after.len(), metadata.len());
	assert_eq!(
		(after.mtime(), after.mtime_nsec()),
		(metadata.mtime(), metadata.mtime_nsec())
	);
	assert!(archive.fence_at(archive.root()).is_err());
	assert_eq!(std::fs::read(path).unwrap(), changed);
}

#[test]
fn pinned_legacy_anchor_raw_bytes_refuse_a_same_metadata_projection() {
	let _guard = store_lock().unwrap();
	let (root, archive) = fixture();
	let mut pinned = PinnedAnchor::open(archive.root()).unwrap();
	let original = pinned.bytes.to_vec();
	let changed = changed_legacy_bytes(&original);
	drop(overwrite_legacy_anchor(archive.root(), &changed));
	// Simulate equal/coarsely projected timestamps without weakening production
	// stamp checks. Only the stamp is refreshed; the original byte pin remains.
	pinned.stamp = AnchorStamp::held(&pinned.file).unwrap();
	assert_eq!(
		AnchorStamp::named(archive.root(), &pinned.component).unwrap(),
		pinned.stamp
	);
	let error = pinned.fence(archive.root()).unwrap_err();
	assert_eq!(
		error.to_string(),
		"request archive legacy anchor bytes changed"
	);
	assert_eq!(pinned.bytes.as_ref(), original.as_slice());
	assert_eq!(
		std::fs::read(root.path().join(ARCHIVE_ANCHOR)).unwrap(),
		changed
	);
}

#[test]
fn pinned_legacy_anchor_refuses_missing_names_links_symlinks_and_unsafe_mode() {
	let _guard = store_lock().unwrap();
	for fault in ["missing", "link", "symlink", "mode"] {
		let (root, archive) = fixture();
		let path = root.path().join(ARCHIVE_ANCHOR);
		let original = std::fs::read(&path).unwrap();
		let alias = root.path().join("held-legacy-anchor");
		match fault {
			"missing" => std::fs::remove_file(&path).unwrap(),
			"link" => std::fs::hard_link(&path, &alias).unwrap(),
			"symlink" => {
				std::fs::rename(&path, &alias).unwrap();
				std::os::unix::fs::symlink(&alias, &path).unwrap();
			}
			"mode" => {
				std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
			}
			_ => unreachable!(),
		}
		assert!(archive.fence_at(archive.root()).is_err(), "{fault}");
		assert!(open_archive(root.path()).is_err(), "{fault}");
		if fault == "missing" {
			assert!(!path.exists());
		} else {
			assert_eq!(std::fs::read(&path).unwrap(), original);
		}
	}
}

#[test]
fn pinned_legacy_anchor_rechecks_metadata_after_the_positional_read() {
	use std::os::unix::fs::FileExt;
	let _guard = store_lock().unwrap();
	let (root, archive) = fixture();
	let path = root.path().join(ARCHIVE_ANCHOR);
	let original = std::fs::read(&path).unwrap();
	let held = root.path().join("held-during-read");
	let error = archive
		.0
		.legacy_anchor
		.fence_with(archive.root(), |file, bytes| {
			file.read_exact_at(bytes, 0)?;
			std::fs::rename(&path, &held)?;
			drop(overwrite_legacy_anchor(archive.root(), &original));
			Ok(())
		})
		.unwrap_err();
	assert_eq!(
		error.to_string(),
		"request archive legacy anchor changed while reading"
	);
	assert_eq!(std::fs::read(&held).unwrap(), original);
	assert_eq!(std::fs::read(&path).unwrap(), original);
}

#[test]
fn pinned_legacy_anchor_short_read_is_an_error_without_repair_or_replay() {
	use std::os::unix::fs::FileExt;
	let _guard = store_lock().unwrap();
	let (root, archive) = fixture();
	let value = record(0x34, 72);
	save_archive_with_sync(&archive, &value, false, true).unwrap();
	let receipt = root.path().join(ARCHIVE_NAME).join(filename(&value));
	let original = std::fs::read(&receipt).unwrap();
	let original_stamp = file_stamp(&std::fs::metadata(&receipt).unwrap());
	let error = archive
		.0
		.legacy_anchor
		.fence_with(archive.root(), |file, bytes| {
			drop(overwrite_legacy_anchor(archive.root(), b"{"));
			file.read_exact_at(bytes, 0)
		})
		.unwrap_err();
	assert_eq!(
		error.downcast_ref::<std::io::Error>().unwrap().kind(),
		std::io::ErrorKind::UnexpectedEof
	);
	let mut terminal = value;
	terminal.state = DurableState::Completed;
	terminal.elapsed_ms = Some(3);
	assert!(archive_record(&archive, &terminal).is_err());
	assert_eq!(std::fs::read(&receipt).unwrap(), original);
	assert_eq!(
		file_stamp(&std::fs::metadata(&receipt).unwrap()),
		original_stamp
	);
	assert_eq!(
		std::fs::read(root.path().join(ARCHIVE_ANCHOR))
			.unwrap()
			.as_slice(),
		b"{"
	);
}

#[test]
fn mixed_layout_keeps_legacy_originals_and_updates_nonterminal_in_place() {
	let _guard = store_lock().unwrap();
	let (root, archive) = fixture();
	let mut terminal = record(0x12, 1);
	terminal.state = DurableState::Completed;
	terminal.elapsed_ms = Some(7);
	let mut pending = record(0xab, 2);
	save_archive_with_sync(&archive, &terminal, false, true).unwrap();
	save_archive_with_sync(&archive, &pending, false, true).unwrap();
	let preserved = root.path().join(ARCHIVE_NAME).join(filename(&terminal));
	let before = std::fs::read(&preserved).unwrap();
	let stamp = file_stamp(&std::fs::metadata(&preserved).unwrap());
	let legacy_identity = identity(&archive.metadata().unwrap());
	let old_epoch = archive.content_version().unwrap();
	let cloned = archive.try_clone().unwrap();
	archive.initialize_shards().unwrap();
	assert!(Arc::ptr_eq(&archive.0, &cloned.0));
	assert!(cloned.0.layout.get().is_some());
	if let (Some(before), Some(after)) = (old_epoch, cloned.content_version().unwrap()) {
		assert!(before != after);
	}
	let recent = record(0xfe, 3);
	save_archive_with_sync(&archive, &recent, false, true).unwrap();
	pending.state = DurableState::Completed;
	pending.elapsed_ms = Some(9);
	archive_record(&archive, &pending).unwrap();
	assert!(root
		.path()
		.join(SHARD_ROOT)
		.join("fe")
		.join(filename(&recent))
		.is_file());
	assert!(!root
		.path()
		.join(ARCHIVE_NAME)
		.join(filename(&recent))
		.exists());
	assert!(!root
		.path()
		.join(SHARD_ROOT)
		.join("ab")
		.join(filename(&pending))
		.exists());
	assert!(archive.read_record(&filename(&pending)).unwrap() == pending);
	assert!(archive.read_record(&filename(&recent)).unwrap() == recent);
	assert_eq!(std::fs::read(&preserved).unwrap(), before);
	assert_eq!(file_stamp(&std::fs::metadata(&preserved).unwrap()), stamp);
	assert_eq!(identity(&archive.metadata().unwrap()), legacy_identity);
	let mut names = HashSet::new();
	archive
		.walk(|_, name, _| {
			assert!(names.insert(name.to_owned()));
			Ok(())
		})
		.unwrap();
	assert_eq!(
		names,
		[filename(&terminal), filename(&pending), filename(&recent)]
			.into_iter()
			.collect()
	);
	let reopened = open_archive(root.path()).unwrap();
	assert!(Arc::ptr_eq(&archive.0, &reopened.0));
	assert!(reopened.metadata().unwrap().len() < FLAT_DIRECTORY_LIMIT);
	assert!(reopened.0.layout.get().is_some());
	assert!(!root.path().join(SHARD_INTENT).exists());
}

#[test]
fn record_fence_preserves_legacy_before_and_after_layout_activation() {
	let _guard = store_lock().unwrap();
	let (_root, archive) = fixture();
	let value = record(0xa5, 1);
	let name = filename(&value);
	save_archive_with_sync(&archive, &value, false, true).unwrap();
	let held = archive.legacy();
	let alias = held.try_clone().unwrap();
	assert_eq!(
		identity(&held.metadata().unwrap()),
		identity(&alias.metadata().unwrap())
	);
	assert_ne!(held.as_raw_fd(), alias.as_raw_fd());
	archive.fence_record(&name, held).unwrap();
	assert!(archive.fence_record(&name, &alias).is_err());
	archive.initialize_shards().unwrap();
	assert_eq!(
		archive.directory_for_existing(&name).unwrap().as_raw_fd(),
		held.as_raw_fd()
	);
	archive.fence_record(&name, held).unwrap();
	assert!(archive.fence_record(&name, &alias).is_err());
	assert!(archive
		.fence_record(&name, &archive.0.layout.get().unwrap().shards[0xa5])
		.is_err());
}

#[test]
fn record_fence_checks_exact_held_fd_across_shard_prefix_boundaries() {
	let _guard = store_lock().unwrap();
	let (_root, archive) = fixture();
	archive.initialize_shards().unwrap();
	let layout = archive.0.layout.get().unwrap();
	for prefix in [0x00, 0x09, 0x0a, 0x0f, 0x10, 0x7f, 0x80, 0xf0, 0xff] {
		let value = record(prefix, u64::from(prefix) + 1);
		let name = filename(&value);
		save_archive_with_sync(&archive, &value, false, true).unwrap();
		let held = archive.directory_for_existing(&name).unwrap();
		archive.fence_record(&name, held).unwrap();
		let alias = held.try_clone().unwrap();
		assert_eq!(
			identity(&held.metadata().unwrap()),
			identity(&alias.metadata().unwrap())
		);
		assert_ne!(held.as_raw_fd(), alias.as_raw_fd());
		assert!(archive
			.fence_record(&name, &alias)
			.unwrap_err()
			.to_string()
			.contains("record changed physical namespace"));
		let wrong = &layout.shards[(usize::from(prefix) + 1) % SHARDS];
		assert!(archive
			.fence_record(&name, wrong)
			.unwrap_err()
			.to_string()
			.contains("record changed physical namespace"));
	}
}

#[test]
fn record_fence_rejects_duplicate_namespaces_for_both_held_targets() {
	let _guard = store_lock().unwrap();
	let (root, archive) = fixture();
	let value = record(0x23, 1);
	let name = filename(&value);
	save_archive_with_sync(&archive, &value, false, true).unwrap();
	archive.initialize_shards().unwrap();
	let original = root.path().join(ARCHIVE_NAME).join(&name);
	let duplicate = root.path().join(SHARD_ROOT).join("23").join(&name);
	let bytes = std::fs::read(&original).unwrap();
	std::fs::copy(&original, &duplicate).unwrap();
	let shard = archive.0.layout.get().unwrap().shards[0x23].as_ref();
	for held in [archive.legacy(), shard] {
		assert!(archive
			.fence_record(&name, held)
			.unwrap_err()
			.to_string()
			.contains("duplicate request archive identity across namespaces"));
	}
	assert_eq!(std::fs::read(&original).unwrap(), bytes);
	assert_eq!(std::fs::read(&duplicate).unwrap(), bytes);
}

#[test]
fn record_fence_refuses_invalid_names_before_prefix_indexing() {
	let _guard = store_lock().unwrap();
	let (_root, archive) = fixture();
	archive.initialize_shards().unwrap();
	for name in [
		String::new(),
		"f".to_owned(),
		".json".to_owned(),
		"界.json".to_owned(),
		format!("{}.json", "A".repeat(64)),
		format!(".{}-{}.tmp", "a".repeat(64), "b".repeat(64)),
	] {
		assert!(archive
			.fence_record(&name, archive.legacy())
			.unwrap_err()
			.to_string()
			.contains("invalid request archive filename"));
	}
	let missing = format!("{}.json", "e".repeat(64));
	let error = archive
		.fence_record(&missing, archive.legacy())
		.unwrap_err();
	assert_eq!(
		error.downcast_ref::<std::io::Error>().unwrap().kind(),
		std::io::ErrorKind::NotFound
	);
}

#[test]
fn record_fence_keeps_the_final_legacy_named_directory_check() {
	let _guard = store_lock().unwrap();
	for with_layout in [false, true] {
		let (root, archive) = fixture();
		let value = record(0x91, 1);
		let name = filename(&value);
		save_archive_with_sync(&archive, &value, false, true).unwrap();
		if with_layout {
			archive.initialize_shards().unwrap();
		}
		let held = archive.legacy();
		archive.fence_record(&name, held).unwrap();
		let named = root.path().join(ARCHIVE_NAME);
		let retained = root.path().join("retained-legacy");
		let bytes = std::fs::read(named.join(&name)).unwrap();
		std::fs::rename(&named, &retained).unwrap();
		std::fs::create_dir(&named).unwrap();
		std::fs::set_permissions(&named, std::fs::Permissions::from_mode(0o700)).unwrap();
		// Lookup through the pinned legacy FD still finds the original. The
		// final named-directory fence must reject its replaced path binding.
		assert_eq!(
			archive.directory_for_existing(&name).unwrap().as_raw_fd(),
			held.as_raw_fd()
		);
		assert!(archive
			.fence_record(&name, held)
			.unwrap_err()
			.to_string()
			.contains("request archive directory binding changed"));
		assert_eq!(std::fs::read(retained.join(&name)).unwrap(), bytes);
		assert!(!named.join(&name).exists());
	}
}

#[test]
fn duplicate_original_is_refused_even_with_identical_bytes() {
	let _guard = store_lock().unwrap();
	let (root, archive) = fixture();
	let value = record(0x23, 1);
	save_archive_with_sync(&archive, &value, false, true).unwrap();
	archive.initialize_shards().unwrap();
	std::fs::copy(
		root.path().join(ARCHIVE_NAME).join(filename(&value)),
		root.path()
			.join(SHARD_ROOT)
			.join("23")
			.join(filename(&value)),
	)
	.unwrap();
	assert!(archive.read_record(&filename(&value)).is_err());
	assert!(archive.walk(|_, _, _| Ok(())).is_err());
	let mut physical = Vec::new();
	archive
		.walk_for_complete_identity_join(|directory, name, _| {
			assert_eq!(name, filename(&value));
			physical.push(identity(&directory.metadata()?));
			Ok(())
		})
		.unwrap();
	assert_eq!(physical.len(), 2);
	assert_ne!(physical[0], physical[1]);
	assert!(archive_record(&archive, &value).is_err());
	assert!(root
		.path()
		.join(ARCHIVE_NAME)
		.join(filename(&value))
		.is_file());
	assert!(root
		.path()
		.join(SHARD_ROOT)
		.join("23")
		.join(filename(&value))
		.is_file());
}

#[test]
fn wrong_shard_and_replaced_target_never_enter_the_logical_namespace() {
	let _guard = store_lock().unwrap();
	let (root, archive) = fixture();
	archive.initialize_shards().unwrap();
	let value = record(0x34, 1);
	save_archive_with_sync(&archive, &value, false, true).unwrap();
	let invalid = root.path().join(SHARD_ROOT).join("34").join("invalid.json");
	std::fs::write(&invalid, b"invalid").unwrap();
	assert!(archive
		.walk_for_complete_identity_join(|_, _, _| Ok(()))
		.unwrap_err()
		.to_string()
		.contains("invalid request archive filename"));
	std::fs::remove_file(invalid).unwrap();
	let source = root
		.path()
		.join(SHARD_ROOT)
		.join("34")
		.join(filename(&value));
	let wrong = root
		.path()
		.join(SHARD_ROOT)
		.join("35")
		.join(filename(&value));
	std::fs::rename(&source, &wrong).unwrap();
	assert!(archive.walk(|_, _, _| Ok(())).is_err());
	assert!(archive
		.walk_for_complete_identity_join(|_, _, _| Ok(()))
		.is_err());
	std::fs::rename(&wrong, &source).unwrap();
	let path = root.path().join(SHARD_ROOT).join("34");
	std::fs::rename(&path, root.path().join("held-shard")).unwrap();
	std::fs::create_dir(&path).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
	assert!(archive.read_record(&filename(&value)).is_err());
	assert!(archive.walk(|_, _, _| Ok(())).is_err());
	assert!(archive
		.walk_for_complete_identity_join(|_, _, _| Ok(()))
		.is_err());
	assert!(open_archive(root.path()).is_ok()); // Reuse stays cheap; exact targets and scans enforce the complete topology.
	assert!(root
		.path()
		.join("held-shard")
		.join(filename(&value))
		.is_file());
}

#[test]
fn cold_physical_walk_checks_layout_before_and_after_visiting_members() {
	for during_scan in [false, true] {
		let _guard = store_lock().unwrap();
		let (root, archive) = fixture();
		archive.initialize_shards().unwrap();
		let value = record(0x34, 1);
		save_archive_with_sync(&archive, &value, false, true).unwrap();
		let shard = root.path().join(SHARD_ROOT).join("34");
		let original = std::fs::read(shard.join(filename(&value))).unwrap();
		let held = root.path().join("held-shard");
		let replace = || {
			std::fs::rename(&shard, &held).unwrap();
			std::fs::create_dir(&shard).unwrap();
			std::fs::set_permissions(&shard, std::fs::Permissions::from_mode(0o700)).unwrap();
		};
		if !during_scan {
			replace();
		}
		let mut visited = 0usize;
		let result = archive.walk_for_complete_identity_join(|_, name, _| {
			assert_eq!(name, filename(&value));
			visited += 1;
			if during_scan {
				replace();
			}
			Ok(())
		});
		assert!(result.is_err());
		assert_eq!(visited, usize::from(during_scan));
		assert_eq!(
			std::fs::read(held.join(filename(&value))).unwrap(),
			original
		);
	}
}

#[test]
fn initialization_resumes_every_durable_boundary_without_rebinding_legacy() {
	let _guard = store_lock().unwrap();
	for cut in [
		InitStep::Intent,
		InitStep::RootCreated,
		InitStep::RootBound,
		InitStep::ShardCreated(0),
		InitStep::ShardBound(31),
		InitStep::ShardCreated(255),
		InitStep::ShardBound(255),
		InitStep::Anchor,
		InitStep::IntentRemoved,
	] {
		let (root, archive) = fixture();
		let value = record(0x45, 1);
		save_archive_with_sync(&archive, &value, false, true).unwrap();
		let path = root.path().join(ARCHIVE_NAME).join(filename(&value));
		let original = std::fs::read(&path).unwrap();
		let original_stamp = file_stamp(&std::fs::metadata(&path).unwrap());
		let legacy = identity(&archive.metadata().unwrap());
		let mut reached = false;
		assert!(archive
			.initialize_with(&mut |step| {
				if step == cut {
					reached = true;
					bail!("injected initialization interruption");
				}
				Ok(())
			})
			.is_err());
		assert!(reached);
		drop(archive);
		let reopened = open_archive(root.path()).unwrap();
		assert!(reopened.0.layout.get().is_some());
		assert_eq!(identity(&reopened.metadata().unwrap()), legacy);
		assert_eq!(std::fs::read(&path).unwrap(), original);
		assert_eq!(
			file_stamp(&std::fs::metadata(&path).unwrap()),
			original_stamp
		);
		assert!(!root.path().join(SHARD_INTENT).exists());
		let fresh = record(0x67, 2);
		save_archive_with_sync(&reopened, &fresh, false, true).unwrap();
		assert!(root
			.path()
			.join(SHARD_ROOT)
			.join("67")
			.join(filename(&fresh))
			.is_file());
	}
}

#[test]
fn initialization_never_adopts_unrecorded_history_or_replaced_directories() {
	let _guard = store_lock().unwrap();
	for replaced in [false, true] {
		let (root, archive) = fixture();
		assert!(archive
			.initialize_with(&mut |step| {
				if step == InitStep::ShardBound(0) {
					bail!("injected initialization interruption");
				}
				Ok(())
			})
			.is_err());
		let shard = root.path().join(SHARD_ROOT).join("00");
		let evidence = if replaced {
			let held = root.path().join("held-init-shard");
			std::fs::rename(&shard, &held).unwrap();
			std::fs::create_dir(&shard).unwrap();
			std::fs::set_permissions(&shard, std::fs::Permissions::from_mode(0o700)).unwrap();
			held
		} else {
			let path = shard.join("unexpected-original.json");
			std::fs::write(&path, b"original data must be preserved").unwrap();
			path
		};
		drop(archive);
		assert!(open_archive(root.path()).is_err());
		assert!(evidence.exists());
		assert!(root.path().join(SHARD_INTENT).is_file());
		assert!(!root.path().join(SHARD_ANCHOR).exists());
	}
	let (root, archive) = fixture();
	std::fs::create_dir(root.path().join(SHARD_ROOT)).unwrap();
	std::fs::set_permissions(
		root.path().join(SHARD_ROOT),
		std::fs::Permissions::from_mode(0o700),
	)
	.unwrap();
	drop(archive);
	assert!(open_archive(root.path()).is_err());
	assert!(root.path().join(SHARD_ROOT).is_dir());
}

#[test]
fn known_complete_metadata_aliases_recover_but_unknown_or_partial_aliases_remain() {
	let _guard = store_lock().unwrap();
	let (root, archive) = fixture();
	assert!(archive
		.initialize_with(&mut |step| {
			if step == InitStep::Intent {
				bail!("injected intent publication interruption");
			}
			Ok(())
		})
		.is_err());
	let alias = root
		.path()
		.join(format!(".archive-v12-init-{}.tmp", "a".repeat(64)));
	std::fs::hard_link(root.path().join(SHARD_INTENT), &alias).unwrap();
	drop(archive);
	let archive = open_archive(root.path()).unwrap();
	assert!(!alias.exists());
	let alias = root
		.path()
		.join(format!(".archive-v12-anchor-{}.tmp", "c".repeat(64)));
	std::fs::hard_link(root.path().join(SHARD_ANCHOR), &alias).unwrap();
	drop(archive);
	let archive = open_archive(root.path()).unwrap();
	assert!(!alias.exists());
	let unknown = root.path().join("unknown-anchor-alias");
	std::fs::hard_link(root.path().join(SHARD_ANCHOR), &unknown).unwrap();
	drop(archive);
	assert!(open_archive(root.path()).is_err());
	assert!(unknown.exists());
	std::fs::remove_file(&unknown).unwrap();
	let partial = root
		.path()
		.join(format!(".archive-v12-anchor-{}.tmp", "d".repeat(64)));
	std::fs::write(root.path().join(SHARD_ANCHOR), b"{partial").unwrap();
	std::fs::hard_link(root.path().join(SHARD_ANCHOR), &partial).unwrap();
	assert!(open_archive(root.path()).is_err());
	assert!(partial.exists());
}

#[test]
fn invalid_anchor_or_private_shard_mode_cannot_be_rebound() {
	let _guard = store_lock().unwrap();
	let (root, archive) = fixture();
	archive.initialize_shards().unwrap();
	let path = root.path().join(SHARD_ROOT).join("78");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
	assert!(archive
		.directory_for_write(&filename(&record(0x78, 1)), false)
		.is_err());
	assert!(archive.walk(|_, _, _| Ok(())).is_err());
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
	let anchor = root.path().join(SHARD_ANCHOR);
	let bytes = std::fs::read(&anchor).unwrap();
	std::fs::rename(&anchor, root.path().join("held-layout-anchor")).unwrap();
	std::fs::write(&anchor, &bytes).unwrap();
	std::fs::set_permissions(&anchor, std::fs::Permissions::from_mode(0o600)).unwrap();
	assert!(archive.fence_at(archive.root()).is_err());
	assert!(root.path().join("held-layout-anchor").is_file());
}

#[cfg(target_os = "linux")]
#[test]
fn audit_root_traverses_search_only_ancestors_and_refuses_nonsearchable_or_unsafe_leaf() {
	let _guard = store_lock().unwrap();
	let temporary = tempfile::tempdir().unwrap();
	let ancestor = temporary.path().join("search-only");
	let root = ancestor.join("private-state");
	std::fs::create_dir(&ancestor).unwrap();
	std::fs::create_dir(&root).unwrap();
	std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
	std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o111)).unwrap();
	let opened = audit_root(&root).unwrap();
	assert_eq!(
		identity(&opened.metadata().unwrap()),
		identity(&std::fs::metadata(&root).unwrap())
	);
	let archive = open_archive(&root).unwrap();
	assert!(archive.0.layout.get().is_none());
	std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o000)).unwrap();
	assert!(audit_root(&root).is_err());
	std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o700)).unwrap();
	std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
	assert!(audit_root(&root).is_err());
	std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
	let alias = temporary.path().join("state-alias");
	std::os::unix::fs::symlink(&root, &alias).unwrap();
	assert!(audit_root(&alias).is_err());
}
