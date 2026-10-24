// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Index correctness across publication, corruption, cold validation and deadlines.
use super::*;

#[test]
fn parallel_original_publication_keeps_the_exact_watch_and_generation_fence() {
	let (root, owner) = fixture();
	let slot = freeze_index(root.path(), &owner);
	let _pin = slot.clone();
	let db = Arc::new(
		cached(&slot, Instant::now() + Duration::from_secs(20))
			.unwrap()
			.unwrap()
			.database,
	);
	{
		let mut state = slot.state.lock().unwrap();
		state.database = Some(db);
		state.worker = true;
		state.busy = false;
	}
	let records: Vec<_> = (0..16)
		.map(|n| Record {
			request_id: format!("{:064x}", n + 1),
			owner: owner.clone(),
			tool_name: "host_list".into(),
			state: DurableState::Unknown,
			accepted_unix_ms: n,
			elapsed_ms: None,
		})
		.collect();
	let writes: Vec<_> = records.iter().map(|record| (record, false)).collect();
	let references: Vec<_> = records.iter().collect();
	let guard = store_lock().unwrap();
	let before = slot.state.lock().unwrap().generation;
	let results = publication_batch(&slot.archive, &references, || {
		stage::save(slot.archive.legacy(), &writes)
	});
	let mut state = slot.state.lock().unwrap();
	assert!(results.iter().all(Result::is_ok));
	assert!(!state.failed);
	assert_eq!(state.generation, before + 16);
	assert_eq!(state.version, content_version(&slot.archive).unwrap());
	for record in records {
		let entry = state.pending.get(&id(&record.request_id).unwrap()).unwrap();
		assert!(entry.record == record);
		assert!(
			entry.stamp == stamp(&slot.archive, &format!("{}.json", record.request_id)).unwrap()
		);
	}
	state.worker = false;
	state.retired = true;
	drop(state);
	drop(guard);
}
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub(super) fn fixture() -> (tempfile::TempDir, String) {
	let root = tempfile::Builder::new()
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	let owner = "a".repeat(64);
	let ticket = begin_at(root.path(), &owner, "host_list").unwrap();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	(root, owner)
}

#[test]
fn indexed_counts_and_pages_follow_new_admissions_and_completions() {
	let (root, owner) = fixture();
	let first: Value = serde_json::from_str(&usage_stats_at(root.path(), &owner).unwrap()).unwrap();
	assert_eq!(first["completed"], 1);
	let ticket = begin_at(root.path(), &owner, "file_info").unwrap();
	let active: Value =
		serde_json::from_str(&usage_stats_at(root.path(), &owner).unwrap()).unwrap();
	assert_eq!(active["active"], 1);
	assert_eq!(active["total_requests"], 2);
	finish_sync(ticket, AuditCompletion::Failed).unwrap();
	let terminal: Value =
		serde_json::from_str(&usage_stats_at(root.path(), &owner).unwrap()).unwrap();
	assert_eq!(terminal["failed"], 1);
	assert_eq!(terminal["active"], 0);
	let page: Value = serde_json::from_str(
		&archive_history_at(
			root.path(),
			&owner,
			RequestHistoryParams {
				after_id: None,
				limit: Some(32),
			},
		)
		.unwrap(),
	)
	.unwrap();
	assert_eq!(page["total"], 2);
	assert_eq!(page["requests"].as_array().unwrap().len(), 2);
}

#[test]
fn in_place_corruption_is_not_hidden_by_a_later_local_publication() {
	let (root, owner) = fixture();
	usage_stats_at(root.path(), &owner).unwrap();
	let archive = root.path().join(ARCHIVE_NAME);
	let receipt = std::fs::read_dir(&archive)
		.unwrap()
		.next()
		.unwrap()
		.unwrap()
		.path();
	let original = std::fs::read(&receipt).unwrap();
	std::fs::write(&receipt, b"private corrupt bytes").unwrap();
	let ticket = begin_at(root.path(), &owner, "host_list").unwrap();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	assert!(usage_stats_at(root.path(), &owner).is_err());
	assert_eq!(std::fs::read(&receipt).unwrap(), b"private corrupt bytes");
	std::fs::write(&receipt, original).unwrap();
}

#[test]
fn checkpoint_verifies_every_inode_and_ctime_on_cold_load() {
	let (root, owner) = fixture();
	let archive = open_archive(root.path()).unwrap();
	let slot = ready(root.path(), &archive, Instant::now() + QUERY_BUDGET).unwrap();
	usage_stats_at(root.path(), &owner).unwrap();
	// Wait for the asynchronous writer, then exercise the same cold loader used
	// after a process restart without destroying the live registry of other tests.
	let deadline = Instant::now() + Duration::from_secs(10);
	slot.state.lock().unwrap().retired = true;
	slot.wake.notify_one();
	while slot.state.lock().unwrap().worker {
		assert!(Instant::now() < deadline);
		std::thread::sleep(Duration::from_millis(5));
	}
	slot.state.lock().unwrap().database = None;
	slot.state.lock().unwrap().retired = false;
	let _pin = slot.clone();
	assert_eq!(
		cached(&slot, deadline)
			.unwrap()
			.unwrap()
			.database
			.begin_read()
			.unwrap()
			.open_table(ROWS)
			.unwrap()
			.len()
			.unwrap(),
		1
	);
	let receipt = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
		.unwrap()
		.next()
		.unwrap()
		.unwrap()
		.path();
	let bytes = std::fs::read(&receipt).unwrap();
	std::fs::write(&receipt, &bytes).unwrap();
	// A live watch rejects an outside edit; a fresh process starts a new epoch.
	assert!(cached(&slot, deadline).unwrap().is_none());
	slot.state.lock().unwrap().version = content_version(&archive).unwrap();
	let db = cached(&slot, deadline).unwrap().unwrap().database;
	let transaction = db.begin_read().unwrap();
	let rows = transaction.open_table(ROWS).unwrap();
	let key = id(receipt.file_stem().unwrap().to_str().unwrap()).unwrap();
	let entry: Entry = codec::decode(rows.get(key.as_slice()).unwrap().unwrap().value()).unwrap();
	assert!(
		entry.stamp == stamp(&archive, receipt.file_name().unwrap().to_str().unwrap()).unwrap()
	);
	drop(rows);
	drop(transaction);
	drop(db);
	std::fs::set_permissions(
		root.path().join(CACHE_NAME),
		std::fs::Permissions::from_mode(0o644),
	)
	.unwrap();
	assert!(cached(&slot, deadline).is_err());
}

#[test]
fn metadata_deadline_does_not_leave_a_blocking_query_behind_the_store_lock() {
	let guard = store_lock().unwrap();
	let worker =
		std::thread::spawn(|| query_lock(Instant::now() + Duration::from_millis(25)).is_err());
	assert!(worker.join().unwrap());
	drop(guard);
}

fn wait_for_audit_store_waiters(lock: &AuditStoreLock, expected: usize) {
	let deadline = Instant::now() + Duration::from_secs(5);
	loop {
		if lock.queue.lock().unwrap().waiting.len() == expected {
			return;
		}
		assert!(Instant::now() < deadline, "store waiter did not register");
		std::thread::sleep(Duration::from_millis(1));
	}
}

fn assert_audit_store_idle(lock: &AuditStoreLock) {
	let queue = lock.queue.lock().unwrap();
	assert!(!queue.active);
	assert!(queue.waiting.is_empty());
}

#[test]
fn audit_store_fifo_orders_writers_and_timed_queries_together() {
	let lock = Arc::new(AuditStoreLock::default());
	let held = lock.acquire(None).unwrap();
	let (send, receive) = std::sync::mpsc::channel();
	let mut workers = Vec::new();
	for (position, timed) in [false, true, false, true].into_iter().enumerate() {
		let worker_lock = lock.clone();
		let send = send.clone();
		workers.push(std::thread::spawn(move || {
			let deadline = timed.then(|| Instant::now() + Duration::from_secs(10));
			let _guard = worker_lock.acquire(deadline).unwrap();
			send.send(position).unwrap();
		}));
		// Observe registration, rather than assume a sleep established order.
		wait_for_audit_store_waiters(&lock, position + 1);
	}
	drop(held);
	let observed: Vec<_> = (0..4)
		.map(|_| receive.recv_timeout(Duration::from_secs(5)).unwrap())
		.collect();
	for worker in workers {
		worker.join().unwrap();
	}
	assert_eq!(observed, [0, 1, 2, 3]);
	assert_audit_store_idle(&lock);
}

#[test]
fn audit_store_expired_query_never_takes_an_available_turn() {
	let lock = AuditStoreLock::default();
	assert_eq!(
		lock.acquire(Some(Instant::now())).err(),
		Some(StoreLockFailure::Deadline)
	);
	assert_audit_store_idle(&lock);
	drop(lock.acquire(None).unwrap());
	assert_audit_store_idle(&lock);
}

#[test]
fn audit_store_timed_cancellation_removes_head_and_middle_waiters() {
	for preceding_writer in [false, true] {
		let lock = Arc::new(AuditStoreLock::default());
		let held = lock.acquire(None).unwrap();
		let (send, receive) = std::sync::mpsc::channel();
		let mut workers = Vec::new();
		if preceding_writer {
			let worker_lock = lock.clone();
			let send = send.clone();
			workers.push(std::thread::spawn(move || {
				let _guard = worker_lock.acquire(None).unwrap();
				send.send(0).unwrap();
			}));
			wait_for_audit_store_waiters(&lock, 1);
		}
		let (expired_send, expired_receive) = std::sync::mpsc::channel();
		let query_lock = lock.clone();
		let query = std::thread::spawn(move || {
			let result = query_lock
				.acquire(Some(Instant::now() + Duration::from_secs(2)))
				.err();
			expired_send.send(result).unwrap();
		});
		wait_for_audit_store_waiters(&lock, usize::from(preceding_writer) + 1);
		let worker_lock = lock.clone();
		workers.push(std::thread::spawn(move || {
			let _guard = worker_lock.acquire(None).unwrap();
			send.send(1).unwrap();
		}));
		wait_for_audit_store_waiters(&lock, usize::from(preceding_writer) + 2);
		assert_eq!(
			expired_receive
				.recv_timeout(Duration::from_secs(5))
				.unwrap(),
			Some(StoreLockFailure::Deadline)
		);
		query.join().unwrap();
		assert_eq!(
			lock.queue.lock().unwrap().waiting.len(),
			usize::from(preceding_writer) + 1
		);
		assert!(receive.try_recv().is_err());
		drop(held);
		let expected = if preceding_writer {
			vec![0, 1]
		} else {
			vec![1]
		};
		let observed: Vec<_> = (0..expected.len())
			.map(|_| receive.recv_timeout(Duration::from_secs(5)).unwrap())
			.collect();
		for worker in workers {
			worker.join().unwrap();
		}
		assert_eq!(observed, expected);
		assert_audit_store_idle(&lock);
		// An expired query has no background waiter that can later take a turn.
		drop(lock.acquire(None).unwrap());
		assert_audit_store_idle(&lock);
	}
}

#[test]
fn audit_store_owner_panic_preserves_poison_and_releases_all_waiters() {
	let lock = Arc::new(AuditStoreLock::default());
	let (held_send, held_receive) = std::sync::mpsc::channel();
	let (panic_send, panic_receive) = std::sync::mpsc::channel();
	let owner_lock = lock.clone();
	let owner = std::thread::spawn(move || {
		let _guard = owner_lock.acquire(None).unwrap();
		held_send.send(()).unwrap();
		panic_receive.recv_timeout(Duration::from_secs(5)).unwrap();
		panic!("intentional audit store owner panic");
	});
	held_receive.recv_timeout(Duration::from_secs(5)).unwrap();
	let mut waiters = Vec::new();
	for (position, timed) in [false, true].into_iter().enumerate() {
		let waiter_lock = lock.clone();
		waiters.push(std::thread::spawn(move || {
			let deadline = timed.then(|| Instant::now() + Duration::from_secs(10));
			waiter_lock.acquire(deadline).err()
		}));
		wait_for_audit_store_waiters(&lock, position + 1);
	}
	panic_send.send(()).unwrap();
	assert!(owner.join().is_err());
	for waiter in waiters {
		assert_eq!(waiter.join().unwrap(), Some(StoreLockFailure::Unavailable));
	}
	assert!(lock.inner.is_poisoned());
	assert_audit_store_idle(&lock);
	for deadline in [None, Some(Instant::now() + Duration::from_secs(5))] {
		assert_eq!(
			lock.acquire(deadline).err(),
			Some(StoreLockFailure::Unavailable)
		);
		assert_audit_store_idle(&lock);
	}
}

#[test]
fn interrupted_checkpoint_is_disposable_but_a_symlink_is_never_cleaned() {
	let (root, owner) = fixture();
	let temporary = root
		.path()
		.join(format!(".disk-index-{}.tmp", new_id().unwrap()));
	std::fs::write(&temporary, b"interrupted checkpoint").unwrap();
	std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();
	usage_stats_at(root.path(), &owner).unwrap();
	assert!(!temporary.exists());
	let archive = open_archive(root.path()).unwrap();
	let slot = slot_at(root.path(), &archive).unwrap();
	let outside = root.path().join("unrelated-original");
	std::fs::write(&outside, b"original bytes").unwrap();
	std::os::unix::fs::symlink(&outside, &temporary).unwrap();
	assert!(clean_staging(&slot).is_err());
	assert!(temporary.is_symlink());
	assert_eq!(std::fs::read(outside).unwrap(), b"original bytes");
}

#[test]
fn abandoned_intents_and_other_owners_do_not_inflate_active_counts() {
	let (root, owner) = fixture();
	for _ in 0..48 {
		let ticket = begin_at(root.path(), &owner, "host_list").unwrap();
		drop(ticket);
	}
	let mine = begin_at(root.path(), &owner, "host_list").unwrap();
	let other_owner = "b".repeat(64);
	let other = begin_at(root.path(), &other_owner, "host_list").unwrap();
	let stats: Value = serde_json::from_str(&usage_stats_at(root.path(), &owner).unwrap()).unwrap();
	assert_eq!(stats["active"], 1);
	assert_eq!(stats["unknown"], 48);
	assert_eq!(stats["total_requests"], 50);
	assert_eq!(stats["completed"], 1);
	drop(mine);
	let stats: Value = serde_json::from_str(&usage_stats_at(root.path(), &owner).unwrap()).unwrap();
	assert_eq!(stats["active"], 0);
	assert_eq!(stats["unknown"], 49);
	let foreign: Value =
		serde_json::from_str(&usage_stats_at(root.path(), &other_owner).unwrap()).unwrap();
	assert_eq!(foreign["total_requests"], 1);
	assert_eq!(foreign["active"], 1);
	drop(other);
}

#[test]
fn disk_tables_exceed_the_pending_cohort_without_lifetime_memory_rows() {
	let root = tempfile::tempdir().unwrap();
	let file = std::fs::OpenOptions::new()
		.read(true)
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(root.path().join("private.redb"))
		.unwrap();
	let db = database(file, Instant::now() + Duration::from_secs(30)).unwrap();
	let owner = "a".repeat(64);
	let count = MAX_PENDING + 127;
	for start in (0..count).step_by(BUILD_CHUNK) {
		let entries = (start..count.min(start + BUILD_CHUNK)).map(|n| Entry {
			record: Record {
				request_id: format!("{n:064x}"),
				owner: owner.clone(),
				tool_name: "host_list".into(),
				state: DurableState::Completed,
				accepted_unix_ms: n as u128,
				elapsed_ms: Some(1),
			},
			stamp: FileStamp {
				device: 1,
				inode: n as u64,
				mode: 0o100600,
				uid: 0,
				links: 1,
				length: 1,
				modified: (0, 0),
				changed: (0, 0),
			},
		});
		apply(&db, entries, None, false).unwrap();
	}
	let read = db.begin_read().unwrap();
	assert_eq!(read.open_table(ROWS).unwrap().len().unwrap(), count as u64);
	assert_eq!(read.open_table(ORDER).unwrap().len().unwrap(), count as u64);
	let counts = read.open_table(COUNTS).unwrap();
	assert_eq!(
		total(&counts, &id(&owner).unwrap()).unwrap(),
		[0, count as u64, 0]
	);
	// Exactly one state and one tool counter; counts do not retain a row in RAM.
	assert_eq!(counts.len().unwrap(), 2);
}

#[test]
fn an_unsafe_cache_never_changes_original_admission_or_completion() {
	let (root, owner) = fixture();
	let unrelated = root.path().join("unrelated");
	std::fs::write(&unrelated, b"keep original").unwrap();
	std::os::unix::fs::symlink(&unrelated, root.path().join(CACHE_NAME)).unwrap();
	assert!(usage_stats_at(root.path(), &owner).is_err());
	let ticket = begin_at(root.path(), &owner, "file_info").unwrap();
	let request = ticket.request_id().to_owned();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	let archive = open_archive(root.path()).unwrap();
	assert!(
		archive
			.read_record(&format!("{request}.json"))
			.unwrap()
			.state == DurableState::Completed
	);
	assert_eq!(std::fs::read(unrelated).unwrap(), b"keep original");
}

#[test]
fn streaming_fallback_checks_original_stamps_and_its_deadline() {
	let (root, owner) = fixture();
	let archive = open_archive(root.path()).unwrap();
	let slot = ready(root.path(), &archive, Instant::now() + QUERY_BUDGET).unwrap();
	usage_stats_at(root.path(), &owner).unwrap();
	let database = slot.state.lock().unwrap().database.clone().unwrap();
	verify_members(&database, &archive, Instant::now() + Duration::from_secs(3)).unwrap();
	assert!(verify_members(
		&database,
		&archive,
		Instant::now() - Duration::from_millis(1)
	)
	.is_err());
	let path = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
		.unwrap()
		.next()
		.unwrap()
		.unwrap()
		.path();
	let bytes = std::fs::read(&path).unwrap();
	std::fs::write(path, &bytes).unwrap();
	assert!(verify_members(&database, &archive, Instant::now() + Duration::from_secs(3)).is_err());
}

pub(super) fn freeze_index(root: &Path, owner: &str) -> Arc<Slot> {
	let archive = open_archive(root).unwrap();
	// Keep a real caller reference through the metadata check. Its return value
	// alone does not pin the index against another root's legitimate retirement.
	let slot = ready(root, &archive, Instant::now() + QUERY_BUDGET).unwrap();
	usage_stats_at(root, owner).unwrap();
	slot.state.lock().unwrap().retired = true;
	slot.wake.notify_one();
	let deadline = Instant::now() + Duration::from_secs(5);
	while slot.state.lock().unwrap().worker {
		assert!(Instant::now() < deadline);
		std::thread::sleep(Duration::from_millis(2));
	}
	{
		let mut state = slot.state.lock().unwrap();
		state.database = None;
		state.retired = false;
	}
	slot
}

#[test]
fn cold_cache_repairs_a_lost_tail_without_replaying_or_changing_originals() {
	let (root, owner) = fixture();
	let slot = freeze_index(root.path(), &owner);
	let _pin = slot.clone();
	let ticket = begin_at(root.path(), &owner, "host_list").unwrap();
	let identity = ticket.request_id().to_owned();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	let path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{identity}.json"));
	let original = std::fs::read(&path).unwrap();
	// Model a process loss of the volatile cohort while original receipts remain.
	slot.state.lock().unwrap().pending.clear();
	let db = cached(&slot, Instant::now() + Duration::from_secs(5))
		.unwrap()
		.unwrap()
		.database;
	let read = db.begin_read().unwrap();
	assert_eq!(read.open_table(ROWS).unwrap().len().unwrap(), 2);
	assert_eq!(read.open_table(IDS).unwrap().len().unwrap(), 2);
	assert_eq!(
		total(&read.open_table(COUNTS).unwrap(), &id(&owner).unwrap()).unwrap(),
		[0, 2, 0]
	);
	assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn cold_cache_rejects_inconsistent_tables_even_with_valid_database_checksums() {
	for kind in 0..3 {
		let (root, owner) = fixture();
		let slot = freeze_index(root.path(), &owner);
		let _pin = slot.clone();
		let file = open_at(&slot.root, CACHE_NAME, libc::O_RDWR, 0).unwrap();
		let db = database(file, Instant::now() + Duration::from_secs(5)).unwrap();
		let write = db.begin_write().unwrap();
		if kind == 0 {
			let mut counts = write.open_table(COUNTS).unwrap();
			let mut key = id(&owner).unwrap().to_vec();
			key.extend_from_slice(&[b's', 1]);
			counts.insert(key.as_slice(), 999).unwrap();
		} else if kind == 1 {
			let mut order = write.open_table(ORDER).unwrap();
			let old = order.first().unwrap().unwrap().0.value().to_vec();
			let mut new = old.clone();
			new[47] ^= 1;
			order.remove(old.as_slice()).unwrap();
			order.insert(new.as_slice(), &old[48..]).unwrap();
		} else {
			let mut ids = write.open_table(IDS).unwrap();
			let old = ids.first().unwrap().unwrap().0.value().to_vec();
			ids.remove(old.as_slice()).unwrap();
			ids.insert([255u8; 32].as_slice(), 1).unwrap();
		}
		write.commit().unwrap();
		drop(db);
		assert!(cached(&slot, Instant::now() + Duration::from_secs(5))
			.unwrap()
			.is_none());
	}
}

#[test]
fn unobserved_publications_coalesce_until_a_query_and_then_include_every_receipt() {
	let (root, owner) = fixture();
	let archive = open_archive(root.path()).unwrap();
	let slot = ready(root.path(), &archive, Instant::now() + QUERY_BUDGET).unwrap();
	usage_stats_at(root.path(), &owner).unwrap();
	let database = slot.state.lock().unwrap().database.clone().unwrap();
	let mut originals = Vec::new();
	for _ in 0..32 {
		let ticket = begin_at(root.path(), &owner, "host_list").unwrap();
		let identity = ticket.request_id().to_owned();
		finish_sync(ticket, AuditCompletion::Completed).unwrap();
		let path = root
			.path()
			.join(ARCHIVE_NAME)
			.join(format!("{identity}.json"));
		originals.push((path.clone(), std::fs::read(path).unwrap()));
	}
	// Background timer wakes alone must not add disk work to a small write burst.
	std::thread::sleep(MAINTENANCE_INTERVAL * 2);
	assert_eq!(slot.state.lock().unwrap().pending.len(), 32);
	assert_eq!(
		database
			.begin_read()
			.unwrap()
			.open_table(ROWS)
			.unwrap()
			.len()
			.unwrap(),
		1
	);
	let stats: Value = serde_json::from_str(&usage_stats_at(root.path(), &owner).unwrap()).unwrap();
	assert_eq!(stats["total_requests"], 33);
	assert_eq!(stats["completed"], 33);
	assert_eq!(stats["active"], 0);
	assert!(slot.state.lock().unwrap().pending.is_empty());
	assert_eq!(
		database
			.begin_read()
			.unwrap()
			.open_table(ROWS)
			.unwrap()
			.len()
			.unwrap(),
		33
	);
	for (path, before) in originals {
		assert_eq!(std::fs::read(path).unwrap(), before);
	}
}

#[test]
fn archive_recovery_child() {
	let Some(root) = std::env::var_os("HEPTA_TEST_ARCHIVE_RECOVERY_ROOT") else {
		return;
	};
	let root = std::path::PathBuf::from(root);
	let owner = "a".repeat(64);
	let ticket = begin_at(&root, &owner, "host_list").unwrap();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	usage_stats_at(&root, &owner).unwrap();
	let archive = open_archive(&root).unwrap();
	let slot = slot_at(&root, &archive).unwrap();
	let db = slot.state.lock().unwrap().database.clone().unwrap();
	if std::env::var_os("HEPTA_TEST_ARCHIVE_BAD_COUNTS").is_some() {
		let write = db.begin_write().unwrap();
		{
			let mut counts = write.open_table(COUNTS).unwrap();
			let mut key = id(&owner).unwrap().to_vec();
			key.extend_from_slice(&[b's', 1]);
			counts.insert(key.as_slice(), 999).unwrap();
		}
		write.commit().unwrap();
	}
	if std::env::var_os("HEPTA_TEST_ARCHIVE_USE_SEAL").is_some() {
		slot.state.lock().unwrap().retired = true;
		slot.wake.notify_one();
		let deadline = Instant::now() + Duration::from_secs(5);
		while slot.state.lock().unwrap().worker {
			assert!(Instant::now() < deadline);
			std::thread::sleep(Duration::from_millis(2));
		}
		slot.state.lock().unwrap().retired = false;
		apply(&db, std::iter::empty(), None, true).unwrap();
		slot.state.lock().unwrap().last_publication = Instant::now() - IDLE_SYNC_QUIET;
		// This child explicitly models a quiet durable image before its crash.
		slot.metadata_activity
			.last_finished_ns
			.store(0, Ordering::SeqCst);
		assert!(seal::persist(&slot, Instant::now() + Duration::from_secs(5)).unwrap());
	} else {
		let mut write = db.begin_write().unwrap();
		write.set_quick_repair(false);
		write.commit().unwrap();
	}
	unsafe { libc::_exit(86) };
}

fn crashed_archive(root: &Path, bad_counts: bool) {
	crashed_archive_mode(root, bad_counts, false);
}

fn crashed_archive_mode(root: &Path, bad_counts: bool, sealed: bool) {
	let mut command = std::process::Command::new(std::env::current_exe().unwrap());
	command
		.args([
			"mcp::runtime::request_audit::index::tests::archive_recovery_child",
			"--exact",
			"--test-threads=1",
		])
		.env("HEPTA_TEST_ARCHIVE_RECOVERY_ROOT", root)
		.stdout(std::process::Stdio::null())
		.stderr(std::process::Stdio::null());
	if bad_counts {
		command.env("HEPTA_TEST_ARCHIVE_BAD_COUNTS", "1");
	}
	if sealed {
		command.env("HEPTA_TEST_ARCHIVE_USE_SEAL", "1");
	}
	let mut child = command.spawn().unwrap();
	let deadline = Instant::now() + Duration::from_secs(30);
	let status = loop {
		if let Some(status) = child.try_wait().unwrap() {
			break status;
		}
		if Instant::now() >= deadline {
			child.kill().unwrap();
			child.wait().unwrap();
			panic!("archive recovery fixture did not exit");
		}
		std::thread::sleep(Duration::from_millis(5));
	};
	assert_eq!(status.code(), Some(86));
}

#[test]
fn successful_open_reports_full_recovery_only_after_unclean_exit() {
	let root = tempfile::tempdir().unwrap();
	crashed_archive(root.path(), false);
	let directory = audit_root(root.path()).unwrap();
	let file = open_at(&directory, CACHE_NAME, libc::O_RDWR, 0).unwrap();
	let (db, recovered) = open_database(file, Instant::now() + Duration::from_secs(5)).unwrap();
	assert!(recovered);
	assert_eq!(
		db.begin_read()
			.unwrap()
			.open_table(ROWS)
			.unwrap()
			.len()
			.unwrap(),
		1
	);
	drop(db);
	let file = open_at(&directory, CACHE_NAME, libc::O_RDWR, 0).unwrap();
	let (_, recovered) = open_database(file, Instant::now() + Duration::from_secs(5)).unwrap();
	assert!(!recovered);
}

#[test]
fn recovered_database_still_checks_originals_and_valid_crc_counter_inconsistency() {
	for bad in [false, true] {
		let root = tempfile::tempdir().unwrap();
		crashed_archive(root.path(), bad);
		let archive = open_archive(root.path()).unwrap();
		let slot = slot_at(root.path(), &archive).unwrap();
		let files: Vec<_> = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
			.unwrap()
			.map(|entry| {
				let path = entry.unwrap().path();
				let bytes = std::fs::read(&path).unwrap();
				(path, bytes)
			})
			.collect();
		let result = cached(&slot, Instant::now() + Duration::from_secs(5)).unwrap();
		assert_eq!(result.is_none(), bad);
		for (path, bytes) in files {
			assert_eq!(std::fs::read(path).unwrap(), bytes);
		}
	}
}

#[test]
fn cold_parallel_ranges_check_all_originals_and_reject_an_unsafe_member() {
	let (root, owner) = fixture();
	for _ in 0..32 {
		let ticket = begin_at(root.path(), &owner, "host_list").unwrap();
		finish_sync(ticket, AuditCompletion::Completed).unwrap();
	}
	let slot = freeze_index(root.path(), &owner);
	let _pin = slot.clone();
	let database = cached(&slot, Instant::now() + Duration::from_secs(5))
		.unwrap()
		.unwrap()
		.database;
	let files: Vec<_> = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
		.unwrap()
		.map(|entry| {
			let path = entry.unwrap().path();
			let bytes = std::fs::read(&path).unwrap();
			(path, bytes)
		})
		.collect();
	for bad in [false, true] {
		if bad {
			std::fs::set_permissions(
				&files.last().unwrap().0,
				std::fs::Permissions::from_mode(0o644),
			)
			.unwrap();
		}
		let transaction = database.begin_read().unwrap();
		let rows = transaction.open_table(ROWS).unwrap();
		let result = cold_rows(
			&database,
			&slot,
			&rows,
			&transaction.open_table(ORDER).unwrap(),
			&transaction.open_table(IDS).unwrap(),
			ScanPlan::new(Instant::now() + Duration::from_secs(5), None, None),
			|_| Ok(true),
		);
		assert_eq!(result.is_err(), bad);
		if let Ok(total) = result {
			assert_eq!(total.rows, files.len() as u64);
		}
	}
	for (path, bytes) in files {
		assert_eq!(std::fs::read(path).unwrap(), bytes);
	}
}

#[test]
fn cold_parallel_validation_joins_workers_on_unsafe_original_and_expired_deadline() {
	for expired in [false, true] {
		let (root, owner) = fixture();
		let slot = freeze_index(root.path(), &owner);
		let _pin = slot.clone();
		let database = cached(&slot, Instant::now() + Duration::from_secs(5))
			.unwrap()
			.unwrap()
			.database;
		let path = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
			.unwrap()
			.next()
			.unwrap()
			.unwrap()
			.path();
		let before = std::fs::read(&path).unwrap();
		if !expired {
			std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
		}
		let deadline = if expired {
			Instant::now() - Duration::from_secs(1)
		} else {
			Instant::now() + Duration::from_secs(5)
		};
		let transaction = database.begin_read().unwrap();
		let rows = transaction.open_table(ROWS).unwrap();
		assert!(cold_rows(
			&database,
			&slot,
			&rows,
			&transaction.open_table(ORDER).unwrap(),
			&transaction.open_table(IDS).unwrap(),
			ScanPlan::new(deadline, None, None),
			|_| Ok(true),
		)
		.is_err());
		assert_eq!(std::fs::read(&path).unwrap(), before);
	}
}

#[test]
fn partitioned_fingerprint_sums_match_serial_counts_including_full_width_carry() {
	let mut serial = Fingerprint::default();
	let mut combined = Fingerprint::default();
	for partition in 0..16u64 {
		let mut part = Fingerprint::default();
		for offset in 0..17u64 {
			let key = (partition * 17 + offset).to_be_bytes();
			let copies = offset % 7 + 1;
			serial.add(b"count", &key, copies);
			part.add(b"count", &key, copies);
		}
		combined.merge(part);
	}
	assert!(serial == combined);
	let mut carried = Fingerprint([u64::MAX; 4]);
	carried.merge(Fingerprint([1, 0, 0, 0]));
	assert!(carried == Fingerprint::default());
}

#[test]
fn partition_coverage_refuses_an_empty_cache_key_without_changing_originals() {
	let (root, owner) = fixture();
	let slot = freeze_index(root.path(), &owner);
	let _pin = slot.clone();
	let database = cached(&slot, Instant::now() + Duration::from_secs(5))
		.unwrap()
		.unwrap()
		.database;
	let path = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
		.unwrap()
		.next()
		.unwrap()
		.unwrap()
		.path();
	let before = std::fs::read(&path).unwrap();
	let raw = {
		let transaction = database.begin_read().unwrap();
		let rows = transaction.open_table(ROWS).unwrap();
		let (_, value) = rows.first().unwrap().unwrap();
		value.value().to_vec()
	};
	let write = database.begin_write().unwrap();
	write
		.open_table(ROWS)
		.unwrap()
		.insert(b"".as_slice(), raw.as_slice())
		.unwrap();
	write.commit().unwrap();
	let transaction = database.begin_read().unwrap();
	let rows = transaction.open_table(ROWS).unwrap();
	assert!(cold_rows(
		&database,
		&slot,
		&rows,
		&transaction.open_table(ORDER).unwrap(),
		&transaction.open_table(IDS).unwrap(),
		ScanPlan::new(Instant::now() + Duration::from_secs(5), None, None),
		|_| Ok(true),
	)
	.is_err());
	assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn cold_coverage_repairs_mixed_owner_tail_and_preserves_original_bytes() {
	let (root, owner) = fixture();
	let slot = freeze_index(root.path(), &owner);
	let foreign = "b".repeat(64);
	for (who, tool, completion) in [
		(&owner, "host_health", AuditCompletion::Failed),
		(&foreign, "file_info", AuditCompletion::Completed),
		(&owner, "host_list", AuditCompletion::Completed),
	] {
		let ticket = begin_at(root.path(), who, tool).unwrap();
		finish_sync(ticket, completion).unwrap();
	}
	slot.state.lock().unwrap().pending.clear();
	let originals: Vec<_> = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
		.unwrap()
		.map(|entry| {
			let path = entry.unwrap().path();
			let bytes = std::fs::read(&path).unwrap();
			(path, bytes)
		})
		.collect();
	let db = cached(&slot, Instant::now() + Duration::from_secs(5))
		.unwrap()
		.unwrap()
		.database;
	{
		let read = db.begin_read().unwrap();
		assert_eq!(read.open_table(ROWS).unwrap().len().unwrap(), 4);
		assert_eq!(read.open_table(IDS).unwrap().len().unwrap(), 4);
		let counts = read.open_table(COUNTS).unwrap();
		assert_eq!(total(&counts, &id(&owner).unwrap()).unwrap(), [0, 2, 1]);
		assert_eq!(total(&counts, &id(&foreign).unwrap()).unwrap(), [0, 1, 0]);
	}
	drop(db);
	assert!(cached(&slot, Instant::now() + Duration::from_secs(5))
		.unwrap()
		.is_some());
	for (path, bytes) in originals {
		assert_eq!(std::fs::read(path).unwrap(), bytes);
	}
}

#[test]
fn sealed_crash_recovery_keeps_full_logical_and_original_validation() {
	for kind in 0..3 {
		let root = tempfile::tempdir().unwrap();
		crashed_archive_mode(root.path(), kind == 1, true);
		let archive = open_archive(root.path()).unwrap();
		let slot = slot_at(root.path(), &archive).unwrap();
		let file = open_at(&slot.root, CACHE_NAME, libc::O_RDWR, 0).unwrap();
		assert!(seal::verified(&slot, &file, Instant::now() + Duration::from_secs(5)).unwrap());
		drop(file);
		let path = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
			.unwrap()
			.next()
			.unwrap()
			.unwrap()
			.path();
		let before = std::fs::read(&path).unwrap();
		if kind == 2 {
			std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
		}
		let result = cached(&slot, Instant::now() + Duration::from_secs(5)).unwrap();
		assert_eq!(result.is_some(), kind == 0);
		assert_eq!(std::fs::read(path).unwrap(), before);
	}
}

#[test]
fn waiting_reader_drains_a_paused_worker_cohort_without_changing_originals() {
	let (root, owner) = fixture();
	let slot = freeze_index(root.path(), &owner);
	// Match the production worker's strong reference while this caller remains live.
	let _worker_pin = slot.clone();
	let db = Arc::new(
		cached(&slot, Instant::now() + Duration::from_secs(5))
			.unwrap()
			.unwrap()
			.database,
	);
	{
		let mut state = slot.state.lock().unwrap();
		state.database = Some(db.clone());
		state.worker = true;
		state.busy = false;
	}
	assert!(
		!can_retire(&slot),
		"the simulated worker must not replace the live caller reference"
	);
	for _ in 0..64 {
		let ticket = begin_at(root.path(), &owner, "host_list").unwrap();
		finish_sync(ticket, AuditCompletion::Completed).unwrap();
	}
	let originals: Vec<_> = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
		.unwrap()
		.map(|entry| {
			let path = entry.unwrap().path();
			let bytes = std::fs::read(&path).unwrap();
			(path, bytes)
		})
		.collect();
	let result = usage_stats_at(root.path(), &owner);
	{
		let mut state = slot.state.lock().unwrap();
		state.worker = false;
		state.retired = true;
		assert!(state.pending.is_empty());
		assert_eq!(state.applied, state.generation);
		assert!(state.query_flushed);
	}
	let stats: Value = serde_json::from_str(&result.unwrap()).unwrap();
	assert_eq!(stats["total_requests"], 65);
	assert_eq!(stats["completed"], 65);
	assert_eq!(stats["unknown"], 0);
	for (path, before) in originals {
		assert_eq!(std::fs::read(path).unwrap(), before);
	}
}

#[test]
fn taking_a_worker_cohort_marks_it_busy_before_a_reader_can_observe_an_empty_queue() {
	let (root, owner) = fixture();
	let slot = freeze_index(root.path(), &owner);
	// Match the production worker's strong reference while this caller remains live.
	let _worker_pin = slot.clone();
	let db = Arc::new(
		cached(&slot, Instant::now() + Duration::from_secs(5))
			.unwrap()
			.unwrap()
			.database,
	);
	{
		let mut state = slot.state.lock().unwrap();
		state.database = Some(db.clone());
		state.worker = true;
		state.busy = false;
	}
	assert!(
		!can_retire(&slot),
		"the simulated worker must not replace the live caller reference"
	);
	let ticket = begin_at(root.path(), &owner, "host_list").unwrap();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	let (pending, generation) = claim_pending(&slot).unwrap();
	assert!(slot.state.lock().unwrap().busy);
	let (send, receive) = std::sync::mpsc::channel();
	let path = root.path().to_owned();
	let reader = std::thread::spawn(move || send.send(usage_stats_at(&path, &owner)).unwrap());
	std::thread::sleep(Duration::from_millis(50));
	assert!(matches!(
		receive.try_recv(),
		Err(std::sync::mpsc::TryRecvError::Empty)
	));
	apply(&db, pending.into_values(), None, false).unwrap();
	{
		let mut state = slot.state.lock().unwrap();
		state.applied = generation;
		state.busy = false;
	}
	let stats: Value = serde_json::from_str(
		&receive
			.recv_timeout(Duration::from_secs(5))
			.unwrap()
			.unwrap(),
	)
	.unwrap();
	reader.join().unwrap();
	let mut state = slot.state.lock().unwrap();
	state.worker = false;
	state.retired = true;
	assert_eq!(stats["total_requests"], 2);
	assert_eq!(stats["completed"], 2);
}

#[test]
fn large_backlog_yields_the_writer_fence_until_a_bounded_exact_tail_remains() {
	let (root, owner) = fixture();
	let slot = freeze_index(root.path(), &owner);
	// A real worker owns this extra reference. Keep the simulated worker alive
	// when other test threads create enough archives to exercise registry LRU.
	let _worker_pin = slot.clone();
	let db = Arc::new(
		cached(&slot, Instant::now() + Duration::from_secs(5))
			.unwrap()
			.unwrap()
			.database,
	);
	{
		let mut state = slot.state.lock().unwrap();
		state.database = Some(db.clone());
		state.worker = true;
		state.busy = false;
		// Exercise the large working-set policy without populating a huge test DB.
		state.large_archive = true;
	}
	for _ in 0..LARGE_WRITE_CHUNK + QUERY_WRITE_CHUNK - 1 {
		let ticket = begin_at(root.path(), &owner, "host_list").unwrap();
		finish_sync(ticket, AuditCompletion::Completed).unwrap();
	}
	let deadline = Instant::now() + Duration::from_secs(5);
	let mut trace = SteadyTrace::new("metadata_drain", Some(false));
	let guard = store_lock().unwrap();
	let deferred = drain_for_query(&slot, deadline, &mut trace);
	drop(guard);
	trace.outcome = if deferred.is_ok() {
		"ok"
	} else {
		"error_or_unwind"
	};
	drop(trace);
	assert!(!deferred.unwrap());
	assert!(slot.state.lock().unwrap().requested);
	// A deferred reader leaves admissions free to progress and does not expose
	// a partial count, even when another original is published before handoff.
	let ticket = begin_at(root.path(), &owner, "file_info").unwrap();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	let originals: Vec<_> = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
		.unwrap()
		.map(|entry| {
			let path = entry.unwrap().path();
			let bytes = std::fs::read(&path).unwrap();
			(path, bytes)
		})
		.collect();
	let (pending, generation) = claim_pending(&slot).unwrap();
	assert_eq!(pending.len(), LARGE_WRITE_CHUNK);
	assert_eq!(slot.state.lock().unwrap().pending.len(), QUERY_WRITE_CHUNK);
	apply(&db, pending.into_values(), None, false).unwrap();
	{
		let mut state = slot.state.lock().unwrap();
		state.applied = generation;
		state.busy = false;
		assert!(query_database(&state, &slot.archive).is_err());
	}
	let result = usage_stats_at(root.path(), &owner);
	let watched_tail = slot.state.lock().unwrap().version.is_some();
	if watched_tail {
		// The exact watched tail is now read without a cache write. It remains
		// owned by the original worker until that worker applies every entry.
		assert_eq!(slot.state.lock().unwrap().pending.len(), QUERY_WRITE_CHUNK);
		assert!(!slot.state.lock().unwrap().query_flushed);
		assert_eq!(
			db.begin_read()
				.unwrap()
				.open_table(ROWS)
				.unwrap()
				.len()
				.unwrap(),
			(LARGE_WRITE_CHUNK + 1) as u64
		);
		let (tail, generation) = claim_pending(&slot).unwrap();
		assert_eq!(tail.len(), QUERY_WRITE_CHUNK);
		apply(&db, tail.into_values(), None, false).unwrap();
		let mut state = slot.state.lock().unwrap();
		state.applied = generation;
		state.busy = false;
	}
	{
		let mut state = slot.state.lock().unwrap();
		state.worker = false;
		state.retired = true;
		assert!(state.pending.is_empty());
		assert_eq!(state.applied, state.generation);
	}
	let stats: Value = serde_json::from_str(&result.unwrap()).unwrap();
	assert_eq!(
		stats["total_requests"],
		LARGE_WRITE_CHUNK + QUERY_WRITE_CHUNK + 1
	);
	assert_eq!(
		stats["completed"],
		LARGE_WRITE_CHUNK + QUERY_WRITE_CHUNK + 1
	);
	assert_eq!(stats["active"], 0);
	assert_eq!(stats["unknown"], 0);
	assert_eq!(stats["tool_counts"]["file_info"], 1);
	for (path, before) in originals {
		assert_eq!(std::fs::read(path).unwrap(), before);
	}
}

#[test]
fn index_id_decoder_retains_canonical_lowercase_hex_acceptance() {
	for position in 0..64 {
		for value in 0u8..=127 {
			let mut text = vec![b'a'; 64];
			text[position] = value;
			let text = String::from_utf8(text).unwrap();
			assert_eq!(id(&text).is_ok(), valid_id(&text));
		}
	}
	assert_eq!(id(&"f".repeat(64)).unwrap(), [255; 32]);
	assert!(id(&"a".repeat(63)).is_err());
	assert!(id(&"a".repeat(65)).is_err());
}

#[test]
fn streaming_row_image_hash_matches_legacy_bytes_and_subtraction() {
	let key = [17u8; 32];
	let value = vec![123u8; MAX_RECORD_BYTES * 2];
	let mut legacy = key.to_vec();
	legacy.extend_from_slice(&value);
	let mut expected = Fingerprint::default();
	expected.add(b"row-image", &legacy, 1);
	let mut actual = Fingerprint::default();
	actual.row(&key, &value, true).unwrap();
	assert!(actual == expected);
	actual.row(&key, &value, false).unwrap();
	assert!(actual == Fingerprint::default());
	assert!(actual
		.row(&key, &vec![0; MAX_RECORD_BYTES * 2 + 1], true)
		.is_err());
}

#[test]
fn cache_read_advice_preserves_all_bytes_and_inode_stamps() {
	let temp = tempfile::NamedTempFile::new().unwrap();
	use std::os::unix::fs::FileExt;
	temp.as_file()
		.write_all_at(b"cache read advice is not a mutation", 0)
		.unwrap();
	let before = temp.as_file().metadata().unwrap();
	{
		let _hint = CacheReadHint::new(temp.as_file(), false);
	}
	{
		let _hint = CacheReadHint::new(temp.as_file(), true);
	}
	let after = temp.as_file().metadata().unwrap();
	assert_eq!(
		(
			before.dev(),
			before.ino(),
			before.mode(),
			before.uid(),
			before.nlink(),
			before.len(),
			before.mtime(),
			before.mtime_nsec(),
			before.ctime(),
			before.ctime_nsec()
		),
		(
			after.dev(),
			after.ino(),
			after.mode(),
			after.uid(),
			after.nlink(),
			after.len(),
			after.mtime(),
			after.mtime_nsec(),
			after.ctime(),
			after.ctime_nsec()
		)
	);
	let mut bytes = vec![0; before.len() as usize];
	temp.as_file().read_exact_at(&mut bytes, 0).unwrap();
	assert_eq!(bytes, b"cache read advice is not a mutation");
}

#[test]
fn archive_sha256_backend_preserves_streamed_padding_boundaries_and_full_bytes() {
	for length in [0, 1, 55, 56, 63, 64, 65, 167, 231, 1024, 1_048_577] {
		let bytes: Vec<u8> = (0..length).map(|i| (i as u8).wrapping_mul(197)).collect();
		let expected: [u8; 32] = Sha256::digest(&bytes).into();
		let mut hash = ArchiveHash::new();
		for chunk in bytes.chunks(37) {
			hash.update(chunk);
		}
		assert_eq!(hash.finalize(), expected);
	}
}

#[cfg(target_os = "linux")]
#[test]
fn background_index_priority_changes_only_the_worker_thread() {
	let caller = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
	let worker = std::thread::spawn(|| {
		background_priority();
		unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) }
	})
	.join()
	.unwrap();
	assert_eq!(worker, 19);
	assert_eq!(unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) }, caller);
}

#[test]
fn large_cache_preparing_reply_does_not_wait_for_the_query_budget() {
	let (root, owner) = fixture();
	let slot = freeze_index(root.path(), &owner);
	let _pin = slot.clone();
	let archive = open_archive(root.path()).unwrap();
	let original_path = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
		.unwrap()
		.next()
		.unwrap()
		.unwrap()
		.path();
	let original = std::fs::read(&original_path).unwrap();
	let cache = std::fs::OpenOptions::new()
		.write(true)
		.open(root.path().join(CACHE_NAME))
		.unwrap();
	cache.set_len(CACHE_BYTES as u64 + 1).unwrap();
	// Model a large index whose worker is still validating its private cache.
	// No unvalidated database may be published by this scheduling-only path.
	slot.state.lock().unwrap().worker = true;
	let started = Instant::now();
	let result = ready(root.path(), &archive, started + QUERY_BUDGET);
	let elapsed = started.elapsed();
	slot.state.lock().unwrap().worker = false;
	assert!(result
		.err()
		.unwrap()
		.to_string()
		.contains("index preparing"));
	assert!(elapsed < Duration::from_secs(1));
	assert!(slot.state.lock().unwrap().database.is_none());
	assert_eq!(std::fs::read(original_path).unwrap(), original);
}

#[test]
fn retirement_distinguishes_an_idle_worker_from_a_live_caller() {
	let (root, owner) = fixture();
	let slot = freeze_index(root.path(), &owner);
	// Exactly this active caller and its registry entry remain after freeze.
	// Removing only our entry gives the local variable the registry role for
	// deterministic ownership cases without clearing any other test's roots.
	{
		let mut registry = INDEXES.get().unwrap().lock().unwrap();
		let position = registry
			.iter()
			.position(|entry| Arc::ptr_eq(entry, &slot))
			.unwrap();
		drop(registry.remove(position).unwrap());
	}
	let deadline = Instant::now() + Duration::from_secs(5);
	while Arc::strong_count(&slot) != 1 {
		assert!(Instant::now() < deadline);
		std::thread::sleep(Duration::from_millis(1));
	}
	assert!(!slot.state.lock().unwrap().worker);
	assert!(can_retire(&slot));
	let caller = slot.clone();
	assert!(
		!can_retire(&slot),
		"registry plus a live caller cannot be retired"
	);
	drop(caller);
	// Model the sole background-worker reference separately from a reader.
	let worker = slot.clone();
	slot.state.lock().unwrap().worker = true;
	assert!(can_retire(&slot));
	let caller = slot.clone();
	assert!(!can_retire(&slot));
	drop(caller);
	slot.state.lock().unwrap().busy = true;
	assert!(!can_retire(&slot));
	{
		let mut state = slot.state.lock().unwrap();
		state.busy = false;
		state.worker = false;
	}
	// A thread finishing its epilogue is still an external owner until drop.
	assert!(!can_retire(&slot));
	drop(worker);
	assert!(can_retire(&slot));
}

#[test]
fn bounded_index_capacity_waits_without_retiring_live_callers_or_blocking_writers() {
	// This case deliberately fills the process-global pool. Isolate just this
	// fixture so unrelated tests can keep running with the unchanged pool bound.
	let mut child = std::process::Command::new(std::env::current_exe().unwrap())
		.args([
			"mcp::runtime::request_audit::index::tests::archive_capacity_wait_child",
			"--exact",
		])
		.env("HEPTA_TEST_ARCHIVE_CAPACITY_WAIT", "1")
		.stdout(std::process::Stdio::null())
		.stderr(std::process::Stdio::inherit())
		.spawn()
		.unwrap();
	let deadline = Instant::now() + Duration::from_secs(30);
	let status = loop {
		if let Some(status) = child.try_wait().unwrap() {
			break status;
		}
		if Instant::now() >= deadline {
			child.kill().unwrap();
			child.wait().unwrap();
			panic!("archive capacity fixture did not exit");
		}
		std::thread::sleep(Duration::from_millis(5));
	};
	assert!(status.success());
}

#[test]
fn archive_capacity_wait_child() {
	if std::env::var_os("HEPTA_TEST_ARCHIVE_CAPACITY_WAIT").is_none() {
		return;
	}
	assert_eq!(MAX_INDEXES, 2);
	let mut fixtures = Vec::new();
	let mut slots = Vec::new();
	let mut originals = Vec::new();
	for _ in 0..MAX_INDEXES {
		let (root, owner) = fixture();
		let archive = open_archive(root.path()).unwrap();
		let slot = slot_at(root.path(), &archive).unwrap();
		for entry in std::fs::read_dir(root.path().join(ARCHIVE_NAME)).unwrap() {
			let path = entry.unwrap().path();
			originals.push((path.clone(), std::fs::read(path).unwrap()));
		}
		fixtures.push((root, owner, archive));
		slots.push(slot);
	}
	let (waiting_root, owner) = fixture();
	let waiting_archive = open_archive(waiting_root.path()).unwrap();
	let error = {
		let _guard = store_lock().unwrap();
		try_slot_at(waiting_root.path(), &waiting_archive)
			.err()
			.unwrap()
	};
	assert!(error.is::<IndexCapacityBusy>());
	assert!(slots.iter().all(|slot| !slot.state.lock().unwrap().retired));
	// The full pool must still admit a caller of an already registered root.
	let same = slot_at(fixtures[0].0.path(), &fixtures[0].2).unwrap();
	assert!(Arc::ptr_eq(&same, &slots[0]));
	drop(same);
	let started = Instant::now();
	let deadline = started + Duration::from_millis(30);
	let error = slot_at_until(waiting_root.path(), &waiting_archive, deadline)
		.err()
		.unwrap();
	assert!(error.to_string().contains("total deadline exceeded"));
	assert!(Instant::now() >= deadline);
	assert!(started.elapsed() < Duration::from_secs(1));
	assert!(slots.iter().all(|slot| !slot.state.lock().unwrap().retired));
	assert_eq!(INDEXES.get().unwrap().lock().unwrap().len(), MAX_INDEXES);

	let (started_tx, started_rx) = std::sync::mpsc::channel();
	let (done_tx, done_rx) = std::sync::mpsc::channel();
	let waiting_path = waiting_root.path().to_owned();
	let query_owner = owner.clone();
	let query = std::thread::spawn(move || {
		started_tx.send(()).unwrap();
		done_tx
			.send(usage_stats_at(&waiting_path, &query_owner))
			.unwrap();
	});
	started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
	assert!(matches!(
		done_rx.recv_timeout(Duration::from_millis(30)),
		Err(std::sync::mpsc::RecvTimeoutError::Timeout)
	));
	// A pending third-root query must release STORE_LOCK so an authoritative
	// admission and completion can both finish while the two callers stay live.
	let (write_tx, write_rx) = std::sync::mpsc::channel();
	let writer_root = fixtures[0].0.path().to_owned();
	let writer_owner = fixtures[0].1.clone();
	let writer = std::thread::spawn(move || {
		let result = begin_at(&writer_root, &writer_owner, "host_list")
			.and_then(|ticket| finish_sync(ticket, AuditCompletion::Completed));
		write_tx.send(result).unwrap();
	});
	write_rx
		.recv_timeout(Duration::from_secs(1))
		.expect("waiting for a slot must not hold STORE_LOCK")
		.unwrap();
	writer.join().unwrap();
	assert!(matches!(
		done_rx.try_recv(),
		Err(std::sync::mpsc::TryRecvError::Empty)
	));
	assert!(slots.iter().all(|slot| !slot.state.lock().unwrap().retired));
	let released = Arc::downgrade(slots.last().unwrap());
	drop(slots.pop().unwrap());
	let stats = done_rx.recv_timeout(QUERY_BUDGET).unwrap().unwrap();
	query.join().unwrap();
	let stats: Value = serde_json::from_str(&stats).unwrap();
	assert_eq!(stats["total_requests"], 1);
	assert_eq!(stats["completed"], 1);
	assert!(released.upgrade().is_none());
	assert!(!slots[0].state.lock().unwrap().retired);
	assert_eq!(INDEXES.get().unwrap().lock().unwrap().len(), MAX_INDEXES);
	let stats: Value =
		serde_json::from_str(&usage_stats_at(fixtures[0].0.path(), &owner).unwrap()).unwrap();
	assert_eq!(stats["total_requests"], 2);
	assert_eq!(stats["completed"], 2);
	for (path, before) in originals {
		assert_eq!(std::fs::read(path).unwrap(), before);
	}
}

#[cfg(target_os = "linux")]
#[test]
fn derived_cache_files_never_change_the_flat_or_complete_original_epoch() {
	for sharded in [false, true] {
		let (root, _owner) = fixture();
		let archive = open_archive(root.path()).unwrap();
		if sharded {
			let _guard = store_lock().unwrap();
			archive.initialize_shards().unwrap();
		}
		let before = archive.content_version().unwrap().unwrap();
		let cache = root.path().join(CACHE_NAME);
		let seal = root.path().join(".request-archive-index-seal-v1.json");
		std::fs::write(&cache, b"disposable cache generation one").unwrap();
		std::fs::write(&seal, b"disposable seal generation one").unwrap();
		std::fs::write(&cache, b"disposable cache generation two").unwrap();
		std::fs::remove_file(seal).unwrap();
		assert_eq!(archive.content_version().unwrap(), Some(before));
		archive.fence_at(archive.root()).unwrap();
		let original = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
			.unwrap()
			.next()
			.unwrap()
			.unwrap()
			.path();
		let bytes = std::fs::read(&original).unwrap();
		std::fs::write(original, bytes).unwrap();
		assert_ne!(archive.content_version().unwrap(), Some(before));
	}
}

#[cfg(target_os = "linux")]
struct PausedLargeView {
	root: tempfile::TempDir,
	owner: String,
	slot: Arc<Slot>,
	database: Arc<Database>,
	_worker_pin: Arc<Slot>,
}
#[cfg(target_os = "linux")]
impl PausedLargeView {
	fn new() -> Self {
		let (root, owner) = fixture();
		let slot = freeze_index(root.path(), &owner);
		let database = Arc::new(
			cached(&slot, Instant::now() + Duration::from_secs(5))
				.unwrap()
				.unwrap()
				.database,
		);
		let worker_pin = slot.clone();
		let watched = slot.state.lock().unwrap().version.is_some();
		assert!(watched);
		{
			let mut state = slot.state.lock().unwrap();
			state.database = Some(database.clone());
			state.worker = true;
			state.busy = false;
			// Use the real watched publication path with a small fixture DB.
			state.large_archive = true;
		}
		Self {
			root,
			owner,
			slot,
			database,
			_worker_pin: worker_pin,
		}
	}
	fn stats(&self, owner: &str) -> Value {
		serde_json::from_str(&usage_stats_at(self.root.path(), owner).unwrap()).unwrap()
	}
	fn flush_worker(&self) {
		let (pending, generation) = claim_pending(&self.slot).unwrap();
		apply(&self.database, pending.into_values(), None, false).unwrap();
		let mut state = self.slot.state.lock().unwrap();
		state.applied = generation;
		state.busy = false;
	}
	fn pending_image(&self) -> (u64, u64, Vec<(Id, Vec<u8>)>) {
		let state = self.slot.state.lock().unwrap();
		(
			state.generation,
			state.applied,
			state
				.pending
				.iter()
				.map(|(key, entry)| (*key, codec::encode(entry).unwrap()))
				.collect(),
		)
	}
	fn cache_bytes(&self) -> Vec<u8> {
		std::fs::read(self.root.path().join(CACHE_NAME)).unwrap()
	}
}
#[cfg(target_os = "linux")]
impl Drop for PausedLargeView {
	fn drop(&mut self) {
		if let Ok(mut state) = self.slot.state.lock() {
			state.worker = false;
			state.busy = false;
			state.retired = true;
		}
		self.slot.wake.notify_one();
	}
}

#[cfg(target_os = "linux")]
#[test]
fn large_pending_view_preserves_exact_states_tools_owners_and_cursor_pages_without_writes() {
	let fixture = PausedLargeView::new();
	let old_live = begin_at(fixture.root.path(), &fixture.owner, "file_info").unwrap();
	fixture.flush_worker();
	finish_sync(old_live, AuditCompletion::Failed).unwrap();
	let completed = begin_at(fixture.root.path(), &fixture.owner, "host_list").unwrap();
	finish_sync(completed, AuditCompletion::Completed).unwrap();
	let live = begin_at(fixture.root.path(), &fixture.owner, "file_info").unwrap();
	drop(begin_at(fixture.root.path(), &fixture.owner, "host_health").unwrap());
	let foreign_owner = "b".repeat(64);
	let foreign = begin_at(fixture.root.path(), &foreign_owner, "host_list").unwrap();
	let foreign_id = foreign.request_id().to_owned();
	finish_sync(foreign, AuditCompletion::Completed).unwrap();
	let before = fixture.pending_image();
	assert_eq!(before.2.len(), 5);
	let cache = fixture.cache_bytes();
	let stats = fixture.stats(&fixture.owner);
	assert_eq!(stats["total_requests"], 5);
	assert_eq!(stats["completed"], 2);
	assert_eq!(stats["failed"], 1);
	assert_eq!(stats["active"], 1);
	assert_eq!(stats["unknown"], 1);
	assert_eq!(
		stats["tool_counts"],
		json!({"host_list":2,"file_info":2,"host_health":1})
	);
	let foreign = fixture.stats(&foreign_owner);
	assert_eq!(foreign["total_requests"], 1);
	assert_eq!(foreign["completed"], 1);
	assert_eq!(foreign["active"], 0);
	let mut after_id = None;
	let mut observed = Vec::new();
	loop {
		let page: Value = serde_json::from_str(
			&archive_history_at(
				fixture.root.path(),
				&fixture.owner,
				RequestHistoryParams {
					after_id,
					limit: Some(2),
				},
			)
			.unwrap(),
		)
		.unwrap();
		assert_eq!(page["total"], 5);
		observed.extend(page["requests"].as_array().unwrap().iter().cloned());
		after_id = page["next_after_id"].as_str().map(str::to_owned);
		if after_id.is_none() {
			break;
		}
		assert!(observed.len() < 5);
	}
	let mut expected = Vec::new();
	for name in std::fs::read_dir(fixture.root.path().join(ARCHIVE_NAME)).unwrap() {
		let record: Record =
			serde_json::from_slice(&std::fs::read(name.unwrap().path()).unwrap()).unwrap();
		if record.owner == fixture.owner {
			expected.push(record);
		}
	}
	expected.sort_by_key(|record| order_key(record).unwrap());
	assert_eq!(observed.len(), expected.len());
	for (actual, expected) in observed.iter().zip(&expected) {
		assert_eq!(actual["request_id"], expected.request_id);
		assert_eq!(actual["accepted_unix_ms"], json!(expected.accepted_unix_ms));
	}
	assert_eq!(
		stats["first_accepted_unix_ms"],
		json!(expected.first().unwrap().accepted_unix_ms)
	);
	assert_eq!(
		stats["last_accepted_unix_ms"],
		json!(expected.last().unwrap().accepted_unix_ms)
	);
	assert!(archive_history_at(
		fixture.root.path(),
		&fixture.owner,
		RequestHistoryParams {
			after_id: Some(foreign_id),
			limit: Some(2)
		},
	)
	.is_err());
	assert_eq!(fixture.pending_image(), before);
	assert_eq!(fixture.cache_bytes(), cache);
	assert!(!fixture.slot.state.lock().unwrap().query_flushed);
	assert_eq!(
		fixture
			.database
			.begin_read()
			.unwrap()
			.open_table(ROWS)
			.unwrap()
			.len()
			.unwrap(),
		2
	);
	fixture.flush_worker();
	assert_eq!(fixture.stats(&fixture.owner), stats);
	assert_eq!(fixture.stats(&foreign_owner), foreign);
	assert!(fixture.slot.state.lock().unwrap().pending.is_empty());
	drop(live);
}

#[cfg(target_os = "linux")]
#[test]
fn large_pending_view_merges_equal_time_cursor_rows_with_terminal_replacements() {
	let fixture = PausedLargeView::new();
	let record = |n: u64, state| Record {
		request_id: format!("{n:064x}"),
		owner: fixture.owner.clone(),
		tool_name: "host_list".into(),
		state,
		accepted_unix_ms: 1,
		elapsed_ms: if state == DurableState::Unknown {
			None
		} else {
			Some(1)
		},
	};
	let publish = |records: &[Record]| {
		let writes: Vec<_> = records
			.iter()
			.map(|record| {
				let replacing = record.request_id == format!("{:064x}", 2)
					&& record.state == DurableState::Completed;
				(record, replacing)
			})
			.collect();
		let references: Vec<_> = records.iter().collect();
		let guard = store_lock().unwrap();
		let results = publication_batch(&fixture.slot.archive, &references, || {
			stage::save(fixture.slot.archive.legacy(), &writes)
		});
		drop(guard);
		assert!(results.iter().all(Result::is_ok));
	};
	// These disk rows have the same time and surround the new pending IDs.
	publish(&[
		record(2, DurableState::Unknown),
		record(4, DurableState::Completed),
	]);
	fixture.flush_worker();
	publish(&[
		record(3, DurableState::Completed),
		record(1, DurableState::Completed),
		record(2, DurableState::Completed),
	]);
	let before = fixture.pending_image();
	let cache = fixture.cache_bytes();
	let mut after_id = None;
	let mut identities = Vec::new();
	loop {
		let page: Value = serde_json::from_str(
			&archive_history_at(
				fixture.root.path(),
				&fixture.owner,
				RequestHistoryParams {
					after_id,
					limit: Some(1),
				},
			)
			.unwrap(),
		)
		.unwrap();
		assert_eq!(page["total"], 5);
		let requests = page["requests"].as_array().unwrap();
		assert_eq!(requests.len(), 1);
		assert_eq!(requests[0]["state"], "completed");
		identities.push(requests[0]["request_id"].as_str().unwrap().to_owned());
		after_id = page["next_after_id"].as_str().map(str::to_owned);
		if after_id.is_none() {
			break;
		}
		assert!(identities.len() < 5);
	}
	assert_eq!(identities.len(), 5);
	let expected_ids: Vec<_> = (1..=4).map(|n| format!("{n:064x}")).collect();
	assert_eq!(identities[..4], expected_ids);
	let stats = fixture.stats(&fixture.owner);
	assert_eq!(stats["completed"], 5);
	assert_eq!(stats["first_accepted_unix_ms"], 1);
	assert_eq!(fixture.pending_image(), before);
	assert_eq!(fixture.cache_bytes(), cache);
	fixture.flush_worker();
	assert_eq!(fixture.stats(&fixture.owner), stats);
}

fn projection_test_database(check: impl FnOnce(&Database)) {
	let root = tempfile::tempdir().unwrap();
	let file = std::fs::OpenOptions::new()
		.read(true)
		.write(true)
		.create_new(true)
		.mode(0o600)
		.open(root.path().join("projection.redb"))
		.unwrap();
	let database = database(file, Instant::now() + Duration::from_secs(30)).unwrap();
	check(&database);
}

fn projection_test_entry() -> Entry {
	Entry {
		record: Record {
			request_id: "1".repeat(64),
			owner: "a".repeat(64),
			tool_name: "host_list".into(),
			state: DurableState::Unknown,
			accepted_unix_ms: 1234,
			elapsed_ms: None,
		},
		stamp: FileStamp {
			device: 1,
			inode: 2,
			mode: 0o100600,
			uid: 1000,
			links: 1,
			length: 256,
			modified: (1, 2),
			changed: (3, 4),
		},
	}
}

fn projection_image(database: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
	let read = database.begin_read().unwrap();
	let order = read.open_table(ORDER).unwrap();
	let image = order
		.iter()
		.unwrap()
		.map(|pair| {
			let (key, value) = pair.unwrap();
			(key.value().to_vec(), value.value().to_vec())
		})
		.collect();
	image
}

fn assert_projection_row(database: &Database, expected: &Entry, totals: [u64; 3]) {
	let key = id(&expected.record.request_id).unwrap();
	let read = database.begin_read().unwrap();
	let rows = read.open_table(ROWS).unwrap();
	let raw = rows.get(key.as_slice()).unwrap().unwrap();
	let actual = codec::decode(raw.value()).unwrap();
	assert!(actual.record == expected.record);
	assert!(actual.stamp == expected.stamp);
	assert_eq!(rows.len().unwrap(), 1);
	assert_eq!(read.open_table(IDS).unwrap().len().unwrap(), 1);
	let mut expected_sum = Fingerprint::default();
	expected_sum.row(key.as_slice(), raw.value(), true).unwrap();
	let meta = read.open_table(META).unwrap();
	let sum = meta.get("row_image_sum").unwrap().unwrap();
	assert!(Fingerprint::decode(sum.value()).unwrap() == expected_sum);
	let counts = read.open_table(COUNTS).unwrap();
	assert_eq!(
		total(&counts, &id(&expected.record.owner).unwrap()).unwrap(),
		totals
	);
	assert_eq!(counts.len().unwrap(), 2);
}

#[test]
fn completion_and_stamp_updates_preserve_the_order_projection_and_exact_row_image() {
	projection_test_database(|database| {
		let mut entry = projection_test_entry();
		apply(database, [entry.clone()], None, false).unwrap();
		let original_order = projection_image(database);
		assert_eq!(original_order.len(), 1);
		assert_projection_row(database, &entry, [1, 0, 0]);

		entry.record.state = DurableState::Completed;
		entry.record.elapsed_ms = Some(9);
		entry.stamp.inode += 1;
		entry.stamp.modified = (5, 6);
		apply(database, [entry.clone()], None, false).unwrap();
		assert_eq!(projection_image(database), original_order);
		assert_projection_row(database, &entry, [0, 1, 0]);

		// Revalidated replacement bytes can have the same terminal record and a
		// different original inode/stamp. Its row-image sum must still advance.
		entry.stamp.inode += 1;
		entry.stamp.changed = (7, 8);
		apply(database, [entry.clone()], None, false).unwrap();
		assert_eq!(projection_image(database), original_order);
		assert_projection_row(database, &entry, [0, 1, 0]);
	});
}

#[test]
fn completion_still_repairs_missing_or_different_disposable_order_values() {
	for missing in [true, false] {
		projection_test_database(|database| {
			let mut entry = projection_test_entry();
			apply(database, [entry.clone()], None, false).unwrap();
			let original_order = projection_image(database);
			let key = order_key(&entry.record).unwrap();
			let mut transaction = database.begin_write().unwrap();
			transaction.set_durability(Durability::None).unwrap();
			{
				let mut order = transaction.open_table(ORDER).unwrap();
				if missing {
					order.remove(key.as_slice()).unwrap();
				} else {
					order.insert(key.as_slice(), [0u8; 32].as_slice()).unwrap();
				}
			}
			transaction.commit().unwrap();
			assert_ne!(projection_image(database), original_order);

			entry.record.state = DurableState::Failed;
			entry.record.elapsed_ms = Some(11);
			entry.stamp.inode += 1;
			apply(database, [entry.clone()], None, false).unwrap();
			assert_eq!(projection_image(database), original_order);
			assert_projection_row(database, &entry, [0, 0, 1]);
		});
	}
}
#[cfg(target_os = "linux")]
#[test]
fn large_pending_view_reads_while_the_redb_write_slot_is_held() {
	let fixture = PausedLargeView::new();
	let ticket = begin_at(fixture.root.path(), &fixture.owner, "host_list").unwrap();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	let before = fixture.pending_image();
	// A query attempting begin_write would block here. Always release this test
	// transaction and join before asserting, so a regression cannot leak a thread.
	let write = fixture.database.begin_write().unwrap();
	let cache = fixture.cache_bytes();
	let (send, receive) = std::sync::mpsc::channel();
	let root = fixture.root.path().to_owned();
	let owner = fixture.owner.clone();
	let reader = std::thread::spawn(move || {
		let result = usage_stats_at(&root, &owner);
		let _ = send.send(result);
	});
	let response = receive.recv_timeout(QUERY_BUDGET);
	let unchanged = fixture.cache_bytes() == cache;
	drop(write);
	reader.join().unwrap();
	let stats: Value = serde_json::from_str(&response.unwrap().unwrap()).unwrap();
	assert_eq!(stats["total_requests"], 2);
	assert_eq!(stats["completed"], 2);
	assert!(unchanged);
	assert_eq!(fixture.pending_image(), before);
}

#[cfg(target_os = "linux")]
#[test]
fn large_pending_view_keeps_terminal_identity_rules_and_original_bounds() {
	let fixture = PausedLargeView::new();
	let old = {
		let read = fixture.database.begin_read().unwrap();
		let rows = read.open_table(ROWS).unwrap();
		let (_, raw) = rows.first().unwrap().unwrap();
		codec::decode(raw.value()).unwrap()
	};
	let key = id(&old.record.request_id).unwrap();
	let deadline = Instant::now() + QUERY_BUDGET;
	let mut pending = BTreeMap::from([(key, old.clone())]);
	assert!(PendingView::new(&fixture.database, &pending, deadline)
		.unwrap()
		.entries
		.is_empty());
	pending.get_mut(&key).unwrap().record.state = DurableState::Unknown;
	pending.get_mut(&key).unwrap().record.elapsed_ms = None;
	// An older unknown observation never replaces an already terminal row.
	assert!(PendingView::new(&fixture.database, &pending, deadline)
		.unwrap()
		.entries
		.is_empty());
	for kind in 0..5 {
		let mut changed = old.clone();
		match kind {
			0 => changed.record.owner = "b".repeat(64),
			1 => changed.record.tool_name = "file_info".into(),
			2 => changed.record.accepted_unix_ms += 1,
			3 => changed.record.state = DurableState::Failed,
			_ => changed.record.elapsed_ms = Some(changed.record.elapsed_ms.unwrap() + 1),
		}
		pending.insert(key, changed);
		assert!(PendingView::new(&fixture.database, &pending, deadline).is_err());
	}
	pending = BTreeMap::from([(key, old.clone())]);
	assert!(PendingView::new(
		&fixture.database,
		&pending,
		Instant::now() - Duration::from_millis(1)
	)
	.is_err());
	pending.get_mut(&key).unwrap().record.request_id = "f".repeat(64);
	assert!(PendingView::new(&fixture.database, &pending, deadline).is_err());
	pending.clear();
	for n in 0..=QUERY_WRITE_CHUNK {
		let mut entry = old.clone();
		entry.record.request_id = format!("{n:064x}");
		pending.insert(id(&entry.record.request_id).unwrap(), entry);
	}
	assert!(PendingView::new(&fixture.database, &pending, deadline).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn large_pending_view_rechecks_the_final_watch_and_each_returned_original_stamp() {
	for final_watch in [false, true] {
		let fixture = PausedLargeView::new();
		let ticket = begin_at(fixture.root.path(), &fixture.owner, "host_list").unwrap();
		let identity = ticket.request_id().to_owned();
		finish_sync(ticket, AuditCompletion::Completed).unwrap();
		let path = fixture
			.root
			.path()
			.join(ARCHIVE_NAME)
			.join(format!("{identity}.json"));
		let bytes = std::fs::read(&path).unwrap();
		if final_watch {
			let result = read_snapshot(
				fixture.root.path(),
				&fixture.slot.archive,
				Instant::now() + QUERY_BUDGET,
				|_, view| {
					assert_eq!(view.entries.len(), 1);
					std::fs::write(&path, &bytes)?;
					Ok(())
				},
			);
			assert!(result.is_err());
		} else {
			std::fs::write(&path, &bytes).unwrap();
			// Isolate the page's independent stamp check from the watch check.
			fixture.slot.state.lock().unwrap().version =
				content_version(&fixture.slot.archive).unwrap();
			assert!(archive_history_at(
				fixture.root.path(),
				&fixture.owner,
				RequestHistoryParams {
					after_id: None,
					limit: Some(32)
				},
			)
			.is_err());
		}
		assert_eq!(std::fs::read(&path).unwrap(), bytes);
	}
}

#[cfg(target_os = "linux")]
#[test]
fn large_pending_view_cannot_publish_while_a_taken_worker_cohort_is_in_flight() {
	let fixture = PausedLargeView::new();
	let ticket = begin_at(fixture.root.path(), &fixture.owner, "host_list").unwrap();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	let (pending, generation) = claim_pending(&fixture.slot).unwrap();
	assert!(fixture.slot.state.lock().unwrap().busy);
	let (send, receive) = std::sync::mpsc::channel();
	let root = fixture.root.path().to_owned();
	let owner = fixture.owner.clone();
	let reader = std::thread::spawn(move || {
		let _ = send.send(usage_stats_at(&root, &owner));
	});
	let early = receive.recv_timeout(Duration::from_millis(50));
	apply(&fixture.database, pending.into_values(), None, false).unwrap();
	{
		let mut state = fixture.slot.state.lock().unwrap();
		state.applied = generation;
		state.busy = false;
	}
	let response = receive.recv_timeout(QUERY_BUDGET);
	reader.join().unwrap();
	assert!(matches!(
		early,
		Err(std::sync::mpsc::RecvTimeoutError::Timeout)
	));
	let stats: Value = serde_json::from_str(&response.unwrap().unwrap()).unwrap();
	assert_eq!(stats["total_requests"], 2);
	assert_eq!(stats["completed"], 2);
}

#[cfg(target_os = "linux")]
#[test]
fn large_pending_view_remains_exact_while_continuous_publications_progress() {
	let fixture = PausedLargeView::new();
	let cache = fixture.cache_bytes();
	let finished = Arc::new(AtomicBool::new(false));
	let done = finished.clone();
	let (started_send, started_receive) = std::sync::mpsc::channel();
	let (continue_send, continue_receive) = std::sync::mpsc::channel();
	let root = fixture.root.path().to_owned();
	let owner = fixture.owner.clone();
	let writer = std::thread::spawn(move || {
		let result = (|| -> Result<()> {
			let first = begin_at(&root, &owner, "host_list")?;
			started_send.send(())?;
			continue_receive.recv()?;
			finish_sync(first, AuditCompletion::Completed)?;
			for _ in 1..64 {
				let ticket = begin_at(&root, &owner, "host_list")?;
				finish_sync(ticket, AuditCompletion::Completed)?;
			}
			Ok(())
		})();
		done.store(true, Ordering::Release);
		result
	});
	let started = started_receive.recv_timeout(QUERY_BUDGET);
	let first = if started.is_ok() {
		Some(usage_stats_at(fixture.root.path(), &fixture.owner))
	} else {
		None
	};
	// Release the writer even if the first query failed; assert only after join.
	let continued = continue_send.send(());
	let deadline = Instant::now() + Duration::from_secs(10);
	let mut last = 2;
	let mut observations = Vec::new();
	loop {
		let result = usage_stats_at(fixture.root.path(), &fixture.owner);
		observations.push(result);
		if finished.load(Ordering::Acquire) || Instant::now() >= deadline {
			break;
		}
		std::thread::sleep(Duration::from_millis(1));
	}
	writer.join().unwrap().unwrap();
	started.unwrap();
	continued.unwrap();
	let first: Value = serde_json::from_str(&first.unwrap().unwrap()).unwrap();
	assert_eq!(first["active"], 1);
	assert!(Instant::now() < deadline);
	assert!(!observations.is_empty());
	for result in observations {
		let stats: Value = serde_json::from_str(&result.unwrap()).unwrap();
		let total = stats["total_requests"].as_u64().unwrap();
		assert!((last..=65).contains(&total));
		assert_eq!(
			stats["completed"].as_u64().unwrap() + stats["active"].as_u64().unwrap(),
			total
		);
		assert_eq!(stats["unknown"], 0);
		assert_eq!(stats["failed"], 0);
		assert_eq!(stats["tool_counts"]["host_list"], total);
		last = total;
	}
	let stats = fixture.stats(&fixture.owner);
	assert_eq!(stats["total_requests"], 65);
	assert_eq!(stats["completed"], 65);
	assert_eq!(stats["active"], 0);
	assert_eq!(fixture.slot.state.lock().unwrap().pending.len(), 64);
	assert_eq!(fixture.cache_bytes(), cache);
	fixture.flush_worker();
	assert_eq!(fixture.stats(&fixture.owner), stats);
}
