// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Real production scheduling barriers, serial fallback and epoch publication failures.
use super::*;
use std::sync::atomic::AtomicUsize;

#[cfg(target_os = "linux")]
struct DirectWorkerFixture(Arc<Slot>);
#[cfg(target_os = "linux")]
impl DirectWorkerFixture {
	fn new(slot: &Arc<Slot>) -> Self {
		// freeze_index joined the background worker; only this synchronous call
		// can own a claimed cohort. The normal ready() wrapper is not running.
		assert!(!slot.state.lock().unwrap().worker);
		Self(slot.clone())
	}
}
#[cfg(target_os = "linux")]
impl Drop for DirectWorkerFixture {
	fn drop(&mut self) {
		if let Ok(mut hook) = self.0.parallel_hook.lock() {
			*hook = None;
		}
		if let Ok(mut state) = self.0.state.lock() {
			// Direct worker() errors bypass ready()'s normal thread epilogue.
			// Retire this test fixture after its assertions, including on unwind.
			state.retired = true;
			state.busy = false;
			state.worker = false;
			self.0.wake.notify_all();
		}
	}
}

#[cfg(target_os = "linux")]
type Latch = (Mutex<bool>, Condvar);
#[cfg(target_os = "linux")]
fn signal(latch: &Latch) {
	*latch.0.lock().unwrap() = true;
	latch.1.notify_all();
}
#[cfg(target_os = "linux")]
fn wait(latch: &Latch) {
	let (seen, _) = latch
		.1
		.wait_timeout_while(latch.0.lock().unwrap(), Duration::from_secs(5), |seen| {
			!*seen
		})
		.unwrap();
	assert!(*seen, "production scheduling barrier expired");
}
fn fixture() -> (tempfile::TempDir, Arc<Slot>, Database) {
	let (root, owner) = tests::fixture();
	let slot = tests::freeze_index(root.path(), &owner);
	let _pin = slot.clone();
	let database = cached(&slot, Instant::now() + Duration::from_secs(10))
		.unwrap()
		.unwrap()
		.database;
	(root, slot, database)
}
fn scan(
	slot: &Slot,
	db: &Database,
	epoch: Option<&ParallelEpoch>,
	valid: bool,
) -> Result<cold::ColdTotals> {
	let read = db.begin_read()?;
	let rows = read.open_table(ROWS)?;
	let order = read.open_table(ORDER)?;
	let ids = read.open_table(IDS)?;
	cold_rows(
		db,
		slot,
		&rows,
		&order,
		&ids,
		ScanPlan::new(Instant::now() + Duration::from_secs(10), None, epoch),
		|total| {
			assert_eq!(total.rows, rows.len()?);
			assert!(total.actual_ids.as_ref() == Some(&total.ids));
			assert!(total.actual_order.as_ref() == Some(&total.order));
			Ok(valid)
		},
	)
}
fn install(slot: &Slot, hook: impl Fn(ParallelEvent) + Send + Sync + 'static) {
	*slot.parallel_hook.lock().unwrap() = Some(Arc::new(hook));
}

#[cfg(target_os = "linux")]
fn physical_original_stamp(path: &std::path::Path) -> FileStamp {
	let directory = File::open(path.parent().unwrap()).unwrap();
	stamp_at(&directory, path.file_name().unwrap().to_str().unwrap()).unwrap()
}

#[cfg(target_os = "linux")]
#[test]
fn cold_complete_identity_join_refuses_duplicate_legacy_and_sharded_originals() {
	for parallel in [false, true] {
		let (root, slot, db) = fixture();
		let _pin = slot.clone();
		{
			let _guard = store_lock().unwrap();
			slot.archive.initialize_shards().unwrap();
		}
		let original = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
			.unwrap()
			.next()
			.unwrap()
			.unwrap()
			.path();
		let filename = original.file_name().unwrap().to_str().unwrap();
		let duplicate = root
			.path()
			.join(archive_store::SHARD_ROOT)
			.join(&filename[..2])
			.join(filename);
		std::fs::copy(&original, &duplicate).unwrap();
		let originals = [&original, &duplicate]
			.map(|path| (std::fs::read(path).unwrap(), physical_original_stamp(path)));
		slot.state.lock().unwrap().version = content_version(&slot.archive).unwrap();
		let epoch = parallel.then(|| {
			ParallelEpoch::capture(&slot)
				.unwrap()
				.expect("Linux content watch required")
		});
		let error = scan(&slot, &db, epoch.as_ref(), true).err().unwrap();
		// Parallel producers may report cancellation before the duplicate's
		// error reaches the coordinator; both must refuse the complete scan.
		if !parallel {
			assert!(error.to_string().contains("duplicate"));
		}
		assert!(!error.is::<ColdEpochChanged>());
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
		let _direct = DirectWorkerFixture::new(&slot);
		assert!(worker(&slot).is_err());
		assert!(slot.state.lock().unwrap().database.is_none());
		for (path, before) in [&original, &duplicate].into_iter().zip(originals) {
			assert_eq!(std::fs::read(path).unwrap(), before.0);
			assert!(physical_original_stamp(path) == before.1);
		}
		assert!(!std::fs::read_dir(root.path()).unwrap().any(|entry| {
			entry
				.unwrap()
				.file_name()
				.to_string_lossy()
				.starts_with(".disk-index-")
		}));
	}
}

#[cfg(target_os = "linux")]
#[test]
fn cold_complete_identity_join_refuses_a_duplicate_added_after_observation() {
	let (root, slot, db) = fixture();
	let _pin = slot.clone();
	{
		let _guard = store_lock().unwrap();
		slot.archive.initialize_shards().unwrap();
	}
	slot.state.lock().unwrap().version = content_version(&slot.archive).unwrap();
	let original = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
		.unwrap()
		.next()
		.unwrap()
		.unwrap()
		.path();
	let filename = original.file_name().unwrap().to_str().unwrap();
	let duplicate = root
		.path()
		.join(archive_store::SHARD_ROOT)
		.join(&filename[..2])
		.join(filename);
	let bytes = std::fs::read(&original).unwrap();
	let before = physical_original_stamp(&original);
	let epoch = ParallelEpoch::capture(&slot)
		.unwrap()
		.expect("Linux content watch required");
	let copied = Arc::new(AtomicBool::new(false));
	let (source, target, changed) = (original.clone(), duplicate.clone(), copied.clone());
	install(&slot, move |event| {
		if event == ParallelEvent::BeforeJoin {
			assert!(!changed.swap(true, Ordering::Relaxed));
			std::fs::copy(&source, &target).unwrap();
		}
	});
	let error = scan(&slot, &db, Some(&epoch), true).err().unwrap();
	assert!(copied.load(Ordering::Relaxed));
	assert!(error.is::<ColdEpochChanged>());
	assert!(slot.state.lock().unwrap().database.is_none());
	assert_eq!(
		db.begin_read()
			.unwrap()
			.open_table(ROWS)
			.unwrap()
			.len()
			.unwrap(),
		1
	);
	assert_eq!(std::fs::read(&original).unwrap(), bytes);
	assert!(physical_original_stamp(&original) == before);
	assert_eq!(std::fs::read(&duplicate).unwrap(), bytes);
}

#[cfg(target_os = "linux")]
#[test]
fn production_table_and_full_metadata_observation_reach_each_other_before_either_can_finish() {
	let (_root, slot, db) = fixture();
	let _pin = slot.clone();
	let epoch = ParallelEpoch::capture(&slot)
		.unwrap()
		.expect("Linux content watch required");
	let table = Arc::new((Mutex::new(false), Condvar::new()));
	let original = Arc::new((Mutex::new(false), Condvar::new()));
	let observations = Arc::new(AtomicUsize::new(0));
	let joins = Arc::new(AtomicUsize::new(0));
	let (tables, originals, count, joined) = (
		table.clone(),
		original.clone(),
		observations.clone(),
		joins.clone(),
	);
	install(&slot, move |event| match event {
		ParallelEvent::TableStarted => {
			signal(&tables);
			wait(&originals);
		}
		ParallelEvent::ObservationStarted => {
			count.fetch_add(1, Ordering::Relaxed);
			signal(&originals);
			wait(&tables);
		}
		ParallelEvent::BeforeJoin => {
			assert!(*tables.0.lock().unwrap() && *originals.0.lock().unwrap());
			joined.fetch_add(1, Ordering::Relaxed);
		}
		_ => {}
	});
	scan(&slot, &db, Some(&epoch), true).unwrap();
	assert_eq!(observations.load(Ordering::Relaxed), 1);
	assert_eq!(joins.load(Ordering::Relaxed), 1);
	assert!(slot.state.try_lock().is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn production_coordinator_waits_for_both_scan_orders_without_repeating_observation() {
	for table_first in [false, true] {
		let (_root, slot, db) = fixture();
		let _pin = slot.clone();
		let epoch = ParallelEpoch::capture(&slot)
			.unwrap()
			.expect("Linux content watch required");
		let done = Arc::new((Mutex::new(false), Condvar::new()));
		let observed = Arc::new(AtomicUsize::new(0));
		let tables = Arc::new(AtomicUsize::new(0));
		let (finished, originals, table_count) = (done.clone(), observed.clone(), tables.clone());
		install(&slot, move |event| {
			if table_first && event == ParallelEvent::ObservationStarted {
				wait(&finished);
			}
			if !table_first && event == ParallelEvent::TableStarted {
				wait(&finished);
			}
			if event == ParallelEvent::TablesComplete {
				table_count.fetch_add(1, Ordering::Relaxed);
				if table_first {
					signal(&finished);
				}
			}
			if event == ParallelEvent::ObservationComplete {
				originals.fetch_add(1, Ordering::Relaxed);
				if !table_first {
					signal(&finished);
				}
			}
		});
		scan(&slot, &db, Some(&epoch), true).unwrap();
		assert_eq!(observed.load(Ordering::Relaxed), 1);
		assert_eq!(tables.load(Ordering::Relaxed), 1);
	}
}

#[test]
fn production_without_a_watch_uses_the_original_serial_observation_order() {
	let (_root, slot, db) = fixture();
	let _pin = slot.clone();
	let tables = Arc::new(AtomicBool::new(false));
	let observed = Arc::new(AtomicUsize::new(0));
	let (done, count) = (tables.clone(), observed.clone());
	install(&slot, move |event| match event {
		ParallelEvent::TablesComplete => done.store(true, Ordering::Relaxed),
		ParallelEvent::ObservationStarted => {
			assert!(done.load(Ordering::Relaxed));
			count.fetch_add(1, Ordering::Relaxed);
		}
		ParallelEvent::BeforeJoin | ParallelEvent::NamespaceStarted => {
			panic!("parallel gate was entered without a watch")
		}
		_ => {}
	});
	scan(&slot, &db, None, true).unwrap();
	assert_eq!(observed.load(Ordering::Relaxed), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn failed_table_fingerprints_never_enter_the_observed_identity_join() {
	let (_root, slot, db) = fixture();
	let _pin = slot.clone();
	let epoch = ParallelEpoch::capture(&slot)
		.unwrap()
		.expect("Linux content watch required");
	let joined = Arc::new(AtomicBool::new(false));
	let seen = joined.clone();
	install(&slot, move |event| {
		if event == ParallelEvent::BeforeJoin {
			seen.store(true, Ordering::Relaxed);
		}
	});
	let error = scan(&slot, &db, Some(&epoch), false).err().unwrap();
	assert!(error.to_string().contains("table fingerprints changed"));
	assert!(!joined.load(Ordering::Relaxed));
	assert!(slot.state.try_lock().is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn production_producer_panics_cancel_the_other_side_and_join_every_scope() {
	for event_to_fail in [
		ParallelEvent::TableStarted,
		ParallelEvent::ObservationStarted,
		ParallelEvent::NamespaceStarted,
		ParallelEvent::NamespaceComplete,
	] {
		let (_root, slot, db) = fixture();
		let _pin = slot.clone();
		let epoch = ParallelEpoch::capture(&slot)
			.unwrap()
			.expect("Linux content watch required");
		install(&slot, move |event| {
			assert_ne!(event, event_to_fail, "injected producer failure");
		});
		assert!(scan(&slot, &db, Some(&epoch), true).is_err());
		assert!(slot.state.try_lock().is_ok());
		*slot.parallel_hook.lock().unwrap() = None;
		// A fresh successful pass exercises the same writer and receiver after cleanup.
		scan(&slot, &db, Some(&epoch), true).unwrap();
	}
}

#[cfg(target_os = "linux")]
#[test]
fn unsafe_observed_metadata_cancels_the_parallel_table_scope_and_closes_its_streams() {
	use std::os::unix::fs::PermissionsExt;
	let (root, slot, db) = fixture();
	let _pin = slot.clone();
	let path = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
		.unwrap()
		.next()
		.unwrap()
		.unwrap()
		.path();
	let before = std::fs::read(&path).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	slot.state.lock().unwrap().version = content_version(&slot.archive).unwrap();
	let epoch = ParallelEpoch::capture(&slot)
		.unwrap()
		.expect("Linux content watch required");
	let joined = Arc::new(AtomicBool::new(false));
	let seen = joined.clone();
	install(&slot, move |event| {
		if event == ParallelEvent::BeforeJoin {
			seen.store(true, Ordering::Relaxed);
		}
	});
	assert!(scan(&slot, &db, Some(&epoch), true).is_err());
	assert!(!joined.load(Ordering::Relaxed));
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	slot.state.lock().unwrap().version = content_version(&slot.archive).unwrap();
	let epoch = ParallelEpoch::capture(&slot)
		.unwrap()
		.expect("Linux content watch required");
	scan(&slot, &db, Some(&epoch), true).unwrap();
	assert!(joined.load(Ordering::Relaxed));
	assert_eq!(std::fs::read(path).unwrap(), before);
}

#[cfg(target_os = "linux")]
#[test]
fn epoch_changes_after_observation_or_before_join_cannot_accept_an_early_stamp() {
	for change_at in [
		ParallelEvent::ObservationComplete,
		ParallelEvent::NamespaceComplete,
		ParallelEvent::BeforeJoin,
	] {
		let (root, slot, db) = fixture();
		let _pin = slot.clone();
		let epoch = ParallelEpoch::capture(&slot)
			.unwrap()
			.expect("Linux content watch required");
		let path = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
			.unwrap()
			.next()
			.unwrap()
			.unwrap()
			.path();
		let bytes = std::fs::read(&path).unwrap();
		let content = bytes.clone();
		let original = path.clone();
		install(&slot, move |event| {
			if event == change_at {
				std::fs::write(&original, &content).unwrap();
			}
		});
		let error = scan(&slot, &db, Some(&epoch), true).err().unwrap();
		assert!(error.is::<ColdEpochChanged>());
		assert_eq!(std::fs::read(path).unwrap(), bytes);
		assert!(slot.state.lock().unwrap().database.is_none());
	}
}

#[cfg(target_os = "linux")]
#[test]
fn cold_epoch_failure_is_not_swallowed_as_a_request_to_rebuild_the_cache() {
	for change_at in [
		ParallelEvent::BeforeFold,
		ParallelEvent::BeforeJoin,
		ParallelEvent::NamespaceComplete,
		ParallelEvent::VerifiedOriginalCoverage,
	] {
		let (root, slot, db) = fixture();
		let _pin = slot.clone();
		drop(db);
		let path = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
			.unwrap()
			.next()
			.unwrap()
			.unwrap()
			.path();
		let bytes = std::fs::read(&path).unwrap();
		let before = std::fs::metadata(root.path().join(CACHE_NAME)).unwrap();
		install(&slot, move |event| {
			if event == change_at {
				std::fs::write(&path, &bytes).unwrap();
			}
		});
		let error = match build(&slot) {
			Ok(_) => panic!("epoch-changed cache was accepted"),
			Err(error) => error,
		};
		assert!(error.is::<ColdEpochChanged>());
		let after = std::fs::metadata(root.path().join(CACHE_NAME)).unwrap();
		assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
		assert!(!std::fs::read_dir(root.path()).unwrap().any(|row| row
			.unwrap()
			.file_name()
			.to_string_lossy()
			.starts_with(".disk-index-")));
	}
}

#[cfg(target_os = "linux")]
#[test]
fn cached_unindexed_originals_use_complete_join_coverage_after_all_change_cohorts_commit() {
	check_unindexed_original_coverage(false);
}

#[cfg(target_os = "linux")]
#[test]
fn cached_mixed_originals_keep_the_cache_inode_and_cover_the_complete_new_epoch() {
	check_unindexed_original_coverage(true);
}

#[cfg(target_os = "linux")]
fn check_unindexed_original_coverage(mixed: bool) {
	use std::os::unix::fs::PermissionsExt;
	let (root, slot, db) = fixture();
	let _pin = slot.clone();
	if mixed {
		let flat = ParallelEpoch::capture(&slot).unwrap().unwrap();
		{
			let _guard = store_lock().unwrap();
			slot.archive.initialize_shards().unwrap();
		}
		assert!(flat.check(&slot).unwrap_err().is::<ColdEpochChanged>());
		assert!(ParallelEpoch::capture(&slot).unwrap().is_none());
		let current = content_version(&slot.archive).unwrap().unwrap();
		for _ in 0..260 {
			assert_eq!(Some(current), content_version(&slot.archive).unwrap());
		}
	}
	let template = {
		let read = db.begin_read().unwrap();
		let rows = read.open_table(ROWS).unwrap();
		let (_, raw) = rows.first().unwrap().unwrap();
		codec::decode(raw.value()).unwrap().record
	};
	let old_rows = db
		.begin_read()
		.unwrap()
		.open_table(ROWS)
		.unwrap()
		.len()
		.unwrap();
	drop(db);
	let before = std::fs::metadata(root.path().join(CACHE_NAME)).unwrap();
	// Cross the coordinator's 512-record bound and all four ID partitions.
	// These are real, valid originals that the saved cache has never indexed.
	let mut additions = Vec::new();
	for number in 0..BUILD_CHUNK + 5 {
		let mut record = template.clone();
		let partition = if number <= BUILD_CHUNK {
			0
		} else {
			(number - BUILD_CHUNK) % COLD_ROW_WORKERS
		};
		record.request_id = format!("{:02x}{number:062x}", partition * 64 + 16);
		assert_ne!(record.request_id, template.request_id);
		let directory = if mixed && number % 5 != 0 {
			root.path()
				.join(archive_store::SHARD_ROOT)
				.join(&record.request_id[..2])
		} else {
			root.path().join(ARCHIVE_NAME)
		};
		let path = directory.join(format!("{}.json", record.request_id));
		assert!(!path.exists());
		let raw = serde_json::to_vec(&record).unwrap();
		std::fs::write(&path, &raw).unwrap();
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
		additions.push((record, path, raw));
	}
	slot.state.lock().unwrap().version = content_version(&slot.archive).unwrap();
	let coverage_checks = Arc::new(AtomicUsize::new(0));
	let checked = coverage_checks.clone();
	install(&slot, move |event| match event {
		ParallelEvent::BeforeMissingTailRepair => {
			panic!("complete stable-epoch join must not probe every old snapshot ID again")
		}
		ParallelEvent::VerifiedOriginalCoverage => {
			checked.fetch_add(1, Ordering::Relaxed);
		}
		_ => {}
	});
	let validated = cached(&slot, Instant::now() + Duration::from_secs(20))
		.unwrap()
		.expect("all real unindexed originals were checked and folded");
	assert!(validated.parallel_epoch.is_some());
	assert_eq!(coverage_checks.load(Ordering::Relaxed), 1);
	let read = validated.database.begin_read().unwrap();
	let rows = read.open_table(ROWS).unwrap();
	assert_eq!(rows.len().unwrap(), old_rows + additions.len() as u64);
	assert_eq!(
		read.open_table(IDS).unwrap().len().unwrap(),
		rows.len().unwrap()
	);
	assert_eq!(
		read.open_table(ORDER).unwrap().len().unwrap(),
		rows.len().unwrap()
	);
	let counts = read.open_table(COUNTS).unwrap();
	assert_eq!(
		total(&counts, &id(&template.owner).unwrap())
			.unwrap()
			.iter()
			.sum::<u64>(),
		rows.len().unwrap()
	);
	for (record, path, original) in additions {
		let raw = rows
			.get(id(&record.request_id).unwrap().as_slice())
			.unwrap()
			.unwrap();
		let indexed = codec::decode(raw.value()).unwrap();
		assert!(indexed.record == record);
		assert!(
			indexed.stamp == stamp(&slot.archive, &format!("{}.json", record.request_id)).unwrap()
		);
		assert_eq!(std::fs::read(path).unwrap(), original);
	}
	let after = std::fs::metadata(root.path().join(CACHE_NAME)).unwrap();
	assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
	assert!(slot.state.try_lock().is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn a_last_shard_edit_after_complete_coverage_still_refuses_publication() {
	use std::os::unix::fs::PermissionsExt;
	let (root, slot, db) = fixture();
	let _pin = slot.clone();
	let mut record = {
		let read = db.begin_read().unwrap();
		let rows = read.open_table(ROWS).unwrap();
		let (_, raw) = rows.first().unwrap().unwrap();
		codec::decode(raw.value()).unwrap().record
	};
	drop(db);
	{
		let _guard = store_lock().unwrap();
		slot.archive.initialize_shards().unwrap();
	}
	record.request_id = format!("ff{:062x}", 1);
	let path = root
		.path()
		.join(archive_store::SHARD_ROOT)
		.join("ff")
		.join(format!("{}.json", record.request_id));
	let bytes = serde_json::to_vec(&record).unwrap();
	std::fs::write(&path, &bytes).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	slot.state.lock().unwrap().version = content_version(&slot.archive).unwrap();
	let before = std::fs::metadata(root.path().join(CACHE_NAME)).unwrap();
	let changes = Arc::new(AtomicUsize::new(0));
	let changed = changes.clone();
	let original = path.clone();
	let raw = bytes.clone();
	install(&slot, move |event| {
		if event == ParallelEvent::VerifiedOriginalCoverage {
			std::fs::write(&original, &raw).unwrap();
			changed.fetch_add(1, Ordering::Relaxed);
		}
	});
	let error = cached(&slot, Instant::now() + Duration::from_secs(20))
		.err()
		.unwrap();
	assert!(error.is::<ColdEpochChanged>());
	assert_eq!(changes.load(Ordering::Relaxed), 1);
	let after = std::fs::metadata(root.path().join(CACHE_NAME)).unwrap();
	assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
	assert_eq!(std::fs::read(path).unwrap(), bytes);
	assert!(slot.state.try_lock().is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn worker_checks_the_epoch_before_claim_and_inside_the_actual_publication_fence() {
	let _fixtures = exercise_worker_epoch_failures();
}

#[cfg(target_os = "linux")]
fn exercise_worker_epoch_failures() -> (Vec<tempfile::TempDir>, Vec<std::sync::Weak<Slot>>) {
	let mut roots = Vec::new();
	let mut slots = Vec::new();
	for change_at in [
		ParallelEvent::AfterCachedBeforeClaim,
		ParallelEvent::BeforePublish,
	] {
		for own_publication in [false, true] {
			let (root, slot, db) = fixture();
			let _pin = slot.clone();
			drop(db);
			let cleanup = DirectWorkerFixture::new(&slot);
			let before = std::fs::metadata(root.path().join(CACHE_NAME)).unwrap();
			let archive = root.path().join(ARCHIVE_NAME);
			let path = std::fs::read_dir(&archive)
				.unwrap()
				.next()
				.unwrap()
				.unwrap()
				.path();
			let bytes = std::fs::read(&path).unwrap();
			let operator_root = root.path().to_path_buf();
			install(&slot, move |event| {
				if event != change_at {
					return;
				}
				if own_publication {
					let ticket = begin_at(&operator_root, &"a".repeat(64), "host_list").unwrap();
					finish_sync(ticket, AuditCompletion::Completed).unwrap();
				} else {
					std::fs::write(&path, &bytes).unwrap();
				}
			});
			let error = worker(&slot).unwrap_err();
			assert!(error.is::<ColdEpochChanged>());
			assert!(slot.state.lock().unwrap().database.is_none());
			let after = std::fs::metadata(root.path().join(CACHE_NAME)).unwrap();
			assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
			// Cleanup must follow, never substitute for, the production error,
			// unpublished database and unchanged cache-inode assertions above.
			drop(cleanup);
			{
				let state = slot.state.lock().unwrap();
				assert!(!state.worker && !state.busy && state.retired);
			}
			assert!(slot.parallel_hook.lock().unwrap().is_none());
			roots.push(root);
			slots.push(Arc::downgrade(&slot));
		}
	}
	(roots, slots)
}

#[cfg(target_os = "linux")]
#[test]
fn direct_worker_failure_fixtures_release_the_real_bounded_registry_capacity() {
	let (mut roots, failed) = exercise_worker_epoch_failures();
	assert_eq!(failed.len(), 4);
	// These are real slot_at registrations, without extra strong pins or a
	// registry reset. More than the descriptor-aware bound must evict retired slots.
	let mut fresh = Vec::new();
	for _ in 0..=MAX_INDEXES {
		let (root, _) = tests::fixture();
		let archive = open_archive(root.path()).unwrap();
		let slot = slot_at(root.path(), &archive).unwrap();
		fresh.push(Arc::downgrade(&slot));
		roots.push(root);
	}
	assert!(failed.iter().all(|slot| slot.upgrade().is_none()));
	assert!(fresh.iter().any(|slot| slot.upgrade().is_none()));
}

#[cfg(target_os = "linux")]
#[test]
fn production_namespace_rescan_and_tables_complete_in_either_order_before_publication() {
	for table_first in [false, true] {
		let (_root, slot, db) = fixture();
		let _pin = slot.clone();
		let epoch = ParallelEpoch::capture(&slot)
			.unwrap()
			.expect("Linux content watch required");
		let done = Arc::new((Mutex::new(false), Condvar::new()));
		let starts = Arc::new(AtomicUsize::new(0));
		let completes = Arc::new(AtomicUsize::new(0));
		let (finished, seen, counted) = (done.clone(), starts.clone(), completes.clone());
		install(&slot, move |event| {
			if event == ParallelEvent::NamespaceStarted {
				seen.fetch_add(1, Ordering::Relaxed);
				if table_first {
					wait(&finished);
				}
			}
			if !table_first && event == ParallelEvent::TableStarted {
				wait(&finished);
			}
			if table_first && event == ParallelEvent::TablesComplete {
				signal(&finished);
			}
			if event == ParallelEvent::NamespaceComplete {
				counted.fetch_add(1, Ordering::Relaxed);
				if !table_first {
					signal(&finished);
				}
			}
		});
		let result = scan(&slot, &db, Some(&epoch), true).unwrap();
		let (sum, names) = result.namespace.expect("full namespace rescan required");
		assert!(sum == result.ids);
		assert_eq!(names, result.rows);
		assert_eq!(starts.load(Ordering::Relaxed), 1);
		assert_eq!(completes.load(Ordering::Relaxed), 1);
	}
}

#[cfg(target_os = "linux")]
#[test]
fn namespace_changes_after_both_complete_scans_reject_the_early_coverage() {
	for operation in 0..4 {
		let (root, slot, db) = fixture();
		let _pin = slot.clone();
		let epoch = ParallelEpoch::capture(&slot)
			.unwrap()
			.expect("Linux content watch required");
		let archive = root.path().join(ARCHIVE_NAME);
		let path = std::fs::read_dir(&archive)
			.unwrap()
			.next()
			.unwrap()
			.unwrap()
			.path();
		let other = archive.join(format!("{}.json", "f".repeat(64)));
		assert_ne!(path, other);
		assert!(!other.exists());
		let bytes = std::fs::read(&path).unwrap();
		let replacement = root.path().join("replacement-original");
		let before = std::fs::metadata(root.path().join(CACHE_NAME)).unwrap();
		install(&slot, move |event| {
			if event != ParallelEvent::BeforeJoin {
				return;
			}
			match operation {
				0 => {
					std::fs::write(&other, &bytes).unwrap();
				}
				1 => {
					std::fs::remove_file(&path).unwrap();
				}
				2 => {
					std::fs::rename(&path, &other).unwrap();
				}
				_ => {
					std::fs::write(&replacement, &bytes).unwrap();
					std::fs::rename(&replacement, &path).unwrap();
				}
			}
		});
		let error = scan(&slot, &db, Some(&epoch), true).err().unwrap();
		assert!(error.is::<ColdEpochChanged>());
		assert!(slot.state.lock().unwrap().database.is_none());
		let after = std::fs::metadata(root.path().join(CACHE_NAME)).unwrap();
		assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
	}
}
