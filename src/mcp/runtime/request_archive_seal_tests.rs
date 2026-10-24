// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Sealed cache corruption, cancellation and private-file boundary regressions.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::mpsc::{self, Receiver, SyncSender};

fn fixture() -> (tempfile::TempDir, Arc<Slot>, Database) {
	let (root, owner) = super::super::tests::fixture();
	let slot = super::super::tests::freeze_index(root.path(), &owner);
	let db = cached(&slot, Instant::now() + Duration::from_secs(5))
		.unwrap()
		.unwrap()
		.database;
	apply(&db, std::iter::empty(), None, true).unwrap();
	slot.state.lock().unwrap().last_publication = Instant::now() - IDLE_SYNC_QUIET;
	// The fixture models an idle interval without sleeping in the test process.
	slot.metadata_activity
		.last_finished_ns
		.store(0, Ordering::SeqCst);
	(root, slot, db)
}

#[test]
fn seal_binds_cache_inode_and_all_bits_except_the_recovery_marker() {
	let (_root, slot, _db) = fixture();
	let deadline = Instant::now() + Duration::from_secs(5);
	assert!(persist(&slot, deadline).unwrap());
	let cache = open_at(&slot.root, CACHE_NAME, libc::O_RDWR, 0).unwrap();
	assert!(verified(&slot, &cache, deadline).unwrap());
	let mut god = [0u8; 1];
	cache.read_exact_at(&mut god, 9).unwrap();
	cache.write_all_at(&[god[0] ^ 2], 9).unwrap();
	assert!(verified(&slot, &cache, deadline).unwrap());
	cache.write_all_at(&[god[0] ^ 1], 9).unwrap();
	assert!(!verified(&slot, &cache, deadline).unwrap());
	cache.write_all_at(&god, 9).unwrap();
	let end = cache.metadata().unwrap().len() - 1;
	let mut byte = [0u8; 1];
	cache.read_exact_at(&mut byte, end).unwrap();
	cache.write_all_at(&[byte[0] ^ 1], end).unwrap();
	assert!(!verified(&slot, &cache, deadline).unwrap());
	cache.write_all_at(&byte, end).unwrap();
	std::fs::set_permissions(
		_root.path().join(SEAL_NAME),
		std::fs::Permissions::from_mode(0o644),
	)
	.unwrap();
	assert!(verified(&slot, &cache, deadline).is_err());
}

#[test]
fn cache_sealing_yields_to_new_work_and_never_publishes_a_partial_digest() {
	let (root, slot, _db) = fixture();
	slot.state.lock().unwrap().requested = true;
	assert!(!persist(&slot, Instant::now() + Duration::from_secs(5)).unwrap());
	assert!(!root.path().join(SEAL_NAME).exists());
	slot.state.lock().unwrap().requested = false;
	assert!(persist(&slot, Instant::now()).is_err());
	assert!(!root.path().join(SEAL_NAME).exists());
	assert!(!std::fs::read_dir(root.path()).unwrap().any(|p| p
		.unwrap()
		.file_name()
		.to_string_lossy()
		.starts_with(".disk-index-")));
}

#[test]
fn a_valid_seal_cannot_hide_an_inconsistent_elapsed_field() {
	let (root, slot, db) = fixture();
	let original = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
		.unwrap()
		.next()
		.unwrap()
		.unwrap()
		.path();
	let before = std::fs::read(&original).unwrap();
	let mut write = db.begin_write().unwrap();
	write.set_quick_repair(true);
	{
		let mut rows = write.open_table(ROWS).unwrap();
		let (key, value) = rows.first().unwrap().unwrap();
		let raw_key = key.value().to_vec();
		drop(key);
		let mut entry: Entry = codec::decode(value.value()).unwrap();
		drop(value);
		entry.record.elapsed_ms = Some(entry.record.elapsed_ms.unwrap_or(0) + 1);
		rows.insert(
			raw_key.as_slice(),
			serde_json::to_vec(&entry).unwrap().as_slice(),
		)
		.unwrap();
	}
	write.commit().unwrap();
	assert!(persist(&slot, Instant::now() + Duration::from_secs(5)).unwrap());
	drop(db);
	assert!(cached(&slot, Instant::now() + Duration::from_secs(5))
		.unwrap()
		.is_none());
	assert_eq!(std::fs::read(original).unwrap(), before);
}

#[test]
fn parallel_seal_covers_odd_split_edges_and_every_tail_byte() {
	let file = tempfile::NamedTempFile::new().unwrap();
	let mut bytes = vec![0u8; HASH_CHUNK * 2 + 321];
	for (number, byte) in bytes.iter_mut().enumerate() {
		*byte = (number % 251) as u8;
	}
	bytes[..9].copy_from_slice(&MAGIC);
	file.as_file().write_all_at(&bytes, 0).unwrap();
	bytes[9] &= !2;
	let split = bytes.len() / 2;
	let mut oracle = Sha256::new();
	oracle.update(b"hepta-redb4.4.0-two-part-seal-v2\0");
	oracle.update((bytes.len() as u64).to_be_bytes());
	oracle.update((split as u64).to_be_bytes());
	oracle.update(Sha256::digest(&bytes[..split]));
	oracle.update(Sha256::digest(&bytes[split..]));
	let expected: String = oracle
		.finalize()
		.into_iter()
		.map(|byte| format!("{byte:02x}"))
		.collect();
	let deadline = Instant::now() + Duration::from_secs(10);
	assert_eq!(
		digest(file.as_file(), deadline, || Ok(false)).unwrap(),
		Some(expected.clone())
	);
	for offset in [11, split - 1, split, split + 1, bytes.len() - 1] {
		let original = bytes[offset];
		file.as_file()
			.write_all_at(&[original ^ 1], offset as u64)
			.unwrap();
		assert_ne!(
			digest(file.as_file(), deadline, || Ok(false)).unwrap(),
			Some(expected.clone())
		);
		file.as_file()
			.write_all_at(&[original], offset as u64)
			.unwrap();
	}
}

#[test]
fn legacy_seal_is_verified_then_replaced_with_the_complete_two_part_format() {
	let (root, slot, _db) = fixture();
	let deadline = Instant::now() + Duration::from_secs(5);
	assert!(persist(&slot, deadline).unwrap());
	let cache = open_at(&slot.root, CACHE_NAME, libc::O_RDWR, 0).unwrap();
	let path = root.path().join(SEAL_NAME);
	let mut old: Seal = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
	old.format = LEGACY_FORMAT.into();
	old.sha256 = legacy_digest(&cache, deadline, || Ok(false))
		.unwrap()
		.unwrap();
	std::fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
	assert!(verified(&slot, &cache, deadline).unwrap());
	assert!(persist(&slot, deadline).unwrap());
	let upgraded: Seal = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
	assert_eq!(upgraded.format, FORMAT);
	assert!(verified(&slot, &cache, deadline).unwrap());
}

#[test]
fn parallel_seal_cancellation_drops_the_queue_and_joins_both_workers() {
	let (_root, slot, _db) = fixture();
	let file = open_at(&slot.root, CACHE_NAME, libc::O_RDWR, 0).unwrap();
	let polls = std::sync::atomic::AtomicUsize::new(0);
	let value = digest(&file, Instant::now() + Duration::from_secs(5), || {
		Ok(polls.fetch_add(1, Ordering::Relaxed) >= 1)
	})
	.unwrap();
	assert!(value.is_none());
	assert!(polls.load(Ordering::Relaxed) >= 2);
}

#[test]
fn parallel_seal_rejects_a_truncated_partition_even_after_another_worker_finished() {
	let file = tempfile::NamedTempFile::new().unwrap();
	let mut bytes = [0u8; 320];
	bytes[..9].copy_from_slice(&MAGIC);
	file.as_file().write_all_at(&bytes, 0).unwrap();
	let changed = AtomicBool::new(false);
	let value = digest(
		file.as_file(),
		Instant::now() + Duration::from_secs(5),
		|| {
			if !changed.swap(true, Ordering::Relaxed) {
				file.as_file().set_len(319)?;
			}
			Ok(false)
		},
	);
	assert!(value.is_err());
}

fn pause_seal(slot: &Slot, at: SealEvent) -> (Receiver<()>, SyncSender<()>) {
	let (reached, observed) = mpsc::sync_channel(1);
	let (resume, resumed) = mpsc::sync_channel(1);
	let resumed = Mutex::new(resumed);
	let paused = AtomicBool::new(false);
	*slot.seal_hook.lock().unwrap() = Some(Arc::new(move |event| {
		if event == at && !paused.swap(true, Ordering::SeqCst) {
			reached.send(()).unwrap();
			resumed.lock().unwrap().recv().unwrap();
		}
	}));
	(observed, resume)
}

fn start_seal(slot: Arc<Slot>) -> (std::thread::JoinHandle<()>, Receiver<Result<bool>>) {
	let (send, receive) = mpsc::sync_channel(1);
	let worker = std::thread::spawn(move || {
		let result = persist(&slot, Instant::now() + Duration::from_secs(10));
		let _ = send.send(result);
	});
	(worker, receive)
}

fn no_temporary_seal(root: &Path) -> bool {
	!std::fs::read_dir(root).unwrap().any(|entry| {
		entry
			.unwrap()
			.file_name()
			.to_string_lossy()
			.starts_with(".disk-index-")
	})
}

#[test]
fn cold_publication_resets_metadata_quiet_without_changing_publication_time() {
	let (root, _owner) = super::super::tests::fixture();
	let archive = open_archive(root.path()).unwrap();
	let slot = slot_at(root.path(), &archive).unwrap();
	let publication = slot.state.lock().unwrap().last_publication;
	let ready_slot = ready(root.path(), &archive, Instant::now() + QUERY_BUDGET).unwrap();
	let same_slot = Arc::ptr_eq(&slot, &ready_slot);
	// ready() does not enter read_snapshot, so this touch belongs to publication.
	let published = slot
		.metadata_activity
		.last_finished_ns
		.load(Ordering::SeqCst);
	{
		let mut state = slot.state.lock().unwrap();
		state.retired = true;
	}
	slot.wake.notify_one();
	let deadline = Instant::now() + Duration::from_secs(5);
	while slot.state.lock().unwrap().worker {
		assert!(Instant::now() < deadline);
		std::thread::sleep(Duration::from_millis(2));
	}
	assert!(same_slot);
	assert!(published > 0);
	assert_eq!(slot.state.lock().unwrap().last_publication, publication);
	assert_eq!(slot.metadata_activity.active.load(Ordering::SeqCst), 0);
}

#[test]
fn metadata_activity_waits_for_every_reader_and_records_completion() {
	let activity = MetadataActivity::default();
	let initial = activity.quiet_epoch().unwrap();
	let first = activity.enter();
	let second = activity.enter();
	assert_eq!(activity.active.load(Ordering::SeqCst), 2);
	assert!(activity.quiet_epoch().is_none());
	drop(first);
	let first_finished = activity.last_finished_ns.load(Ordering::SeqCst);
	assert!(first_finished > 0);
	assert_eq!(activity.active.load(Ordering::SeqCst), 1);
	assert!(activity.quiet_epoch().is_none());
	drop(second);
	assert_eq!(activity.active.load(Ordering::SeqCst), 0);
	assert!(activity.last_finished_ns.load(Ordering::SeqCst) >= first_finished);
	assert!(activity.epoch.load(Ordering::SeqCst) > initial);
	assert!(activity.quiet_epoch().is_none());
}

#[test]
fn foreground_snapshot_cancels_an_inflight_seal_and_errors_release_activity() {
	let (root, slot, db) = fixture();
	slot.state.lock().unwrap().database = Some(Arc::new(db));
	let before = {
		let state = slot.state.lock().unwrap();
		(
			state.generation,
			state.applied,
			state.version,
			state.last_publication,
		)
	};
	let (reached, resume) = pause_seal(&slot, SealEvent::Hashing);
	let (worker, finished) = start_seal(slot.clone());
	reached.recv_timeout(Duration::from_secs(5)).unwrap();
	let result = read_snapshot(
		root.path(),
		&slot.archive,
		Instant::now() + QUERY_BUDGET,
		|database, _| {
			let transaction = database.begin_read()?;
			let rows = transaction.open_table(ROWS)?.len()?;
			let active = slot.metadata_activity.active.load(Ordering::SeqCst);
			resume
				.send(())
				.map_err(|_| anyhow!("seal resume unavailable"))?;
			let sealed = finished
				.recv_timeout(Duration::from_secs(2))
				.map_err(|_| anyhow!("seal did not yield while the query held state"))??;
			Ok((rows, active, sealed))
		},
	);
	// Also release the hook if a query failed before reaching its read closure.
	let _ = resume.try_send(());
	worker.join().unwrap();
	assert_eq!(result.unwrap(), (1, 1, false));
	assert!(!root.path().join(SEAL_NAME).exists());
	assert!(no_temporary_seal(root.path()));
	let error = read_snapshot(
		root.path(),
		&slot.archive,
		Instant::now() + QUERY_BUDGET,
		|_, _| -> Result<()> { bail!("injected metadata read failure") },
	);
	assert!(error.is_err());
	assert_eq!(slot.metadata_activity.active.load(Ordering::SeqCst), 0);
	assert!(slot.metadata_activity.quiet_epoch().is_none());
	let owner = "a".repeat(64);
	let (page, total) = page(
		root.path(),
		&slot.archive,
		&owner,
		None,
		32,
		Instant::now() + QUERY_BUDGET,
	)
	.unwrap();
	assert_eq!((page.len(), total), (1, 1));
	assert_eq!(page[0].owner, owner);
	let state = slot.state.lock().unwrap();
	assert_eq!(
		(
			state.generation,
			state.applied,
			state.version,
			state.last_publication
		),
		before
	);
	assert!(!state.failed && state.pending.is_empty());
	drop(state);
	assert!(!persist(&slot, Instant::now() + Duration::from_secs(5)).unwrap());
	// Advance only the fixture's scheduling hint, then require a complete seal.
	slot.metadata_activity
		.last_finished_ns
		.store(0, Ordering::SeqCst);
	assert!(persist(&slot, Instant::now() + Duration::from_secs(5)).unwrap());
	let cache = open_at(&slot.root, CACHE_NAME, libc::O_RDONLY, 0).unwrap();
	assert!(verified(&slot, &cache, Instant::now() + Duration::from_secs(5)).unwrap());
}

#[test]
fn inflight_seal_cancels_without_waiting_for_the_state_mutex() {
	let (root, slot, _db) = fixture();
	let (reached, resume) = pause_seal(&slot, SealEvent::Hashing);
	let (worker, finished) = start_seal(slot.clone());
	reached.recv_timeout(Duration::from_secs(5)).unwrap();
	let held = slot.state.lock().unwrap();
	resume.send(()).unwrap();
	let result = finished.recv_timeout(Duration::from_secs(2));
	// Always release before asserting, so the old blocking implementation fails
	// this test without leaving a stuck worker or poisoning any shared lock.
	drop(held);
	worker.join().unwrap();
	assert!(!result.unwrap().unwrap());
	assert!(!root.path().join(SEAL_NAME).exists());
	assert!(no_temporary_seal(root.path()));
	assert!(!slot.state.lock().unwrap().failed);
}

#[test]
fn a_short_query_after_hash_completion_preserves_the_previous_complete_seal() {
	let (root, slot, _db) = fixture();
	assert!(persist(&slot, Instant::now() + Duration::from_secs(5)).unwrap());
	let path = root.path().join(SEAL_NAME);
	let previous = std::fs::read(&path).unwrap();
	let initial_epoch = slot.metadata_activity.quiet_epoch().unwrap();
	let (reached, resume) = pause_seal(&slot, SealEvent::Hashed);
	let (worker, finished) = start_seal(slot.clone());
	reached.recv_timeout(Duration::from_secs(5)).unwrap();
	{
		let _short_query = slot.metadata_activity.enter();
	}
	assert_eq!(slot.metadata_activity.active.load(Ordering::SeqCst), 0);
	// Model a whole quiet interval without a sleep: the epoch must still reject
	// this old hash attempt even though no active or recent reader remains.
	slot.metadata_activity
		.last_finished_ns
		.store(0, Ordering::SeqCst);
	assert_ne!(slot.metadata_activity.quiet_epoch(), Some(initial_epoch));
	resume.send(()).unwrap();
	let result = finished.recv_timeout(Duration::from_secs(5));
	worker.join().unwrap();
	assert!(!result.unwrap().unwrap());
	assert_eq!(std::fs::read(path).unwrap(), previous);
	assert!(no_temporary_seal(root.path()));
	let cache = open_at(&slot.root, CACHE_NAME, libc::O_RDONLY, 0).unwrap();
	assert!(verified(&slot, &cache, Instant::now() + Duration::from_secs(5)).unwrap());
}
