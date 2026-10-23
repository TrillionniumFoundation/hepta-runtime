// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Directory-stream coverage, repair, safety, EOF integrity and bounded cancellation.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn fixture() -> (tempfile::TempDir, Arc<Slot>, Database, Entry) {
	super::super::super::tests::fixture()
}
fn expected(slot: &Slot, db: &Database) -> Vec<(usize, Spool)> {
	let mut writers = (0..COLD_ROW_WORKERS)
		.map(|_| RowExpected::new(&slot.root).unwrap())
		.collect::<Vec<_>>();
	let read = db.begin_read().unwrap();
	let rows = read.open_table(ROWS).unwrap();
	for pair in rows.iter().unwrap() {
		let (key, raw) = pair.unwrap();
		let view = codec::view(raw.value()).unwrap();
		assert_eq!(key.value(), view.identity);
		writers[partition_of(&view.identity)]
			.push(order_image(&view.identity, view.stamp))
			.unwrap();
	}
	writers
		.into_iter()
		.enumerate()
		.map(|(part, writer)| (part, writer.finish().unwrap()))
		.collect()
}
fn refresh(slot: &Slot) {
	slot.state.lock().unwrap().version = content_version(&slot.archive).unwrap();
}
fn path(root: &Path, entry: &Entry) -> PathBuf {
	root.join(ARCHIVE_NAME)
		.join(format!("{}.json", entry.record.request_id))
}
fn entry_stamp(db: &Database, identity: &Id) -> FileStamp {
	let read = db.begin_read().unwrap();
	let rows = read.open_table(ROWS).unwrap();
	let raw = rows.get(identity.as_slice()).unwrap().unwrap();
	codec::view(raw.value()).unwrap().stamp
}
fn deadline() -> Instant {
	Instant::now() + Duration::from_secs(20)
}
fn identity_spool(slot: &Slot, images: impl IntoIterator<Item = Image>) -> Spool {
	let mut writer = RowExpected::new(&slot.root).unwrap();
	for image in images {
		writer.push(image).unwrap();
	}
	writer.finish().unwrap()
}

#[test]
fn directory_production_verifier_consumes_every_expected_and_observed_stamp() {
	let (root, slot, db, entry) = fixture();
	let _pin = slot.clone();
	let before = std::fs::read(path(root.path(), &entry)).unwrap();
	let sources = expected(&slot, &db);
	assert!(sources
		.iter()
		.all(|(_, source)| source.runs == 1 && source.order == SortOrder::Identity));
	let coverage = super::super::verify(&db, &slot, sources, deadline())
		.unwrap()
		.unwrap();
	let mut identities = Fingerprint::default();
	identities.add(b"id", &id(&entry.record.request_id).unwrap(), 1);
	assert!(coverage.matches_namespace(&identities, 1));
	assert_eq!(
		(coverage.matched, coverage.changed, coverage.extra),
		(1, 0, 0)
	);
	assert_eq!(std::fs::read(path(root.path(), &entry)).unwrap(), before);
	assert!(slot.state.try_lock().is_ok());
}

#[test]
fn directory_production_verifier_rejects_a_missing_original() {
	let (root, slot, db, entry) = fixture();
	let _pin = slot.clone();
	let sources = expected(&slot, &db);
	std::fs::remove_file(path(root.path(), &entry)).unwrap();
	refresh(&slot);
	let error = super::super::verify(&db, &slot, sources, deadline()).unwrap_err();
	assert!(error.to_string().contains("identity coverage changed"));
	assert!(slot.state.try_lock().is_ok());
}

#[test]
fn directory_production_verifier_checks_an_unindexed_tail_before_folding() {
	let (root, slot, db, entry) = fixture();
	let _pin = slot.clone();
	let sources = expected(&slot, &db);
	let mut extra = entry.clone();
	extra.record.request_id = if entry.record.request_id == "f".repeat(64) {
		"e".repeat(64)
	} else {
		"f".repeat(64)
	};
	let mut record: serde_json::Value =
		serde_json::from_slice(&std::fs::read(path(root.path(), &entry)).unwrap()).unwrap();
	record["request_id"] = extra.record.request_id.clone().into();
	std::fs::write(
		path(root.path(), &extra),
		serde_json::to_vec(&record).unwrap(),
	)
	.unwrap();
	std::fs::set_permissions(
		path(root.path(), &extra),
		std::fs::Permissions::from_mode(0o600),
	)
	.unwrap();
	refresh(&slot);
	let coverage = super::super::verify(&db, &slot, sources, deadline())
		.unwrap()
		.unwrap();
	let mut identities = Fingerprint::default();
	identities.add(b"id", &id(&entry.record.request_id).unwrap(), 1);
	identities.add(b"id", &id(&extra.record.request_id).unwrap(), 1);
	assert!(coverage.matches_namespace(&identities, 2));
	assert_eq!(
		(coverage.matched, coverage.changed, coverage.extra),
		(1, 0, 1)
	);
	assert!(!coverage.matches_namespace(&identities, 1));
	let mut altered = id(&extra.record.request_id).unwrap();
	altered[31] ^= 1;
	let mut wrong = Fingerprint::default();
	wrong.add(b"id", &id(&entry.record.request_id).unwrap(), 1);
	wrong.add(b"id", &altered, 1);
	assert!(!coverage.matches_namespace(&wrong, 2));
	assert!(
		entry_stamp(&db, &id(&extra.record.request_id).unwrap())
			== stamp(&slot.archive, &format!("{}.json", extra.record.request_id)).unwrap()
	);
}

#[test]
fn directory_production_verifier_repairs_a_replaced_inode_from_the_original() {
	let (root, slot, db, entry) = fixture();
	let _pin = slot.clone();
	let sources = expected(&slot, &db);
	let original = path(root.path(), &entry);
	let bytes = std::fs::read(&original).unwrap();
	let replacement = root.path().join("replacement");
	std::fs::write(&replacement, &bytes).unwrap();
	std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
	std::fs::rename(&replacement, &original).unwrap();
	let actual = stamp(&slot.archive, &format!("{}.json", entry.record.request_id)).unwrap();
	assert_ne!(actual.inode, entry.stamp.inode);
	refresh(&slot);
	super::super::verify(&db, &slot, sources, deadline()).unwrap();
	assert!(entry_stamp(&db, &id(&entry.record.request_id).unwrap()) == actual);
	assert_eq!(std::fs::read(original).unwrap(), bytes);
}

#[test]
fn directory_production_repair_drains_multiple_bounded_change_cohorts() {
	let (root, slot, db, template) = fixture();
	let _pin = slot.clone();
	let template_bytes = std::fs::read(path(root.path(), &template)).unwrap();
	let mut records = Vec::new();
	for number in 0..BUILD_CHUNK * 2 + 1 {
		let mut entry = template.clone();
		entry.record.request_id = format!("80{number:062x}");
		assert_ne!(entry.record.request_id, template.record.request_id);
		let mut record: serde_json::Value = serde_json::from_slice(&template_bytes).unwrap();
		record["request_id"] = entry.record.request_id.clone().into();
		let bytes = serde_json::to_vec(&record).unwrap();
		let filename = format!("{}.json", entry.record.request_id);
		std::fs::write(path(root.path(), &entry), &bytes).unwrap();
		std::fs::set_permissions(
			path(root.path(), &entry),
			std::fs::Permissions::from_mode(0o600),
		)
		.unwrap();
		entry.stamp = stamp(&slot.archive, &filename).unwrap();
		records.push((entry, bytes));
	}
	apply(
		&db,
		records.iter().map(|(entry, _)| entry.clone()),
		None,
		false,
	)
	.unwrap();
	let sources = expected(&slot, &db);
	for (entry, bytes) in &records {
		let replacement = root.path().join("cohort-replacement");
		std::fs::write(&replacement, bytes).unwrap();
		std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
		std::fs::rename(&replacement, path(root.path(), entry)).unwrap();
	}
	refresh(&slot);
	super::super::verify(&db, &slot, sources, deadline()).unwrap();
	for (entry, bytes) in records {
		let actual = stamp(&slot.archive, &format!("{}.json", entry.record.request_id)).unwrap();
		assert_ne!(actual.inode, entry.stamp.inode);
		assert!(entry_stamp(&db, &id(&entry.record.request_id).unwrap()) == actual);
		assert_eq!(std::fs::read(path(root.path(), &entry)).unwrap(), bytes);
	}
	assert!(slot.state.try_lock().is_ok());
}

#[test]
fn directory_production_verifier_accepts_an_empty_directory_and_empty_row_ranges() {
	let (root, slot, db, entry) = fixture();
	let _pin = slot.clone();
	std::fs::remove_file(path(root.path(), &entry)).unwrap();
	let write = db.begin_write().unwrap();
	write
		.open_table(ROWS)
		.unwrap()
		.remove(id(&entry.record.request_id).unwrap().as_slice())
		.unwrap();
	write.commit().unwrap();
	refresh(&slot);
	let sources = expected(&slot, &db);
	assert!(sources
		.iter()
		.all(|(_, source)| source.rows == 0 && source.runs == 1));
	super::super::verify(&db, &slot, sources, deadline()).unwrap();
}

#[test]
fn directory_scan_never_trusts_a_dirent_inode_hint() {
	let (root, slot, _db, entry) = fixture();
	let _pin = slot.clone();
	let identity = id(&entry.record.request_id).unwrap();
	let original_name = filename(&identity).unwrap();
	assert_eq!(original_name, format!("{}.json", entry.record.request_id));
	let mut tail_identity = identity;
	tail_identity[31] ^= 1;
	let tail_name = filename(&tail_identity).unwrap();
	assert_eq!(&original_name[..62], &tail_name[..62]);
	assert_ne!(original_name, tail_name);
	assert_eq!(tail_name.len(), 69);
	assert_eq!(
		id(tail_name.strip_suffix(".json").unwrap()).unwrap(),
		tail_identity
	);
	let mut record: serde_json::Value =
		serde_json::from_slice(&std::fs::read(path(root.path(), &entry)).unwrap()).unwrap();
	record["request_id"] = tail_name[..64].to_owned().into();
	let tail_path = root.path().join(ARCHIVE_NAME).join(&tail_name);
	std::fs::write(&tail_path, serde_json::to_vec(&record).unwrap()).unwrap();
	std::fs::set_permissions(&tail_path, std::fs::Permissions::from_mode(0o600)).unwrap();
	let tail_stamp = stamp(&slot.archive, &tail_name).unwrap();
	assert_ne!(entry.stamp.inode, tail_stamp.inode);
	// Equal deliberately false hints must still resolve both complete identities.
	let mut names = vec![
		NameHint {
			identity: tail_identity,
			inode: u64::MAX,
		},
		NameHint {
			identity,
			inode: u64::MAX,
		},
	];
	let mut sorters = (0..COLD_ROW_WORKERS)
		.map(|_| Sorter::new(&slot.root).unwrap())
		.collect::<Vec<_>>();
	let pool = rayon::ThreadPoolBuilder::new()
		.num_threads(STAT_WORKERS)
		.build()
		.unwrap();
	let mut stats = Observation::default();
	flush_names(
		slot.archive.legacy(),
		&mut names,
		&mut sorters,
		&pool,
		deadline(),
		&AtomicBool::new(false),
		&mut stats,
	)
	.unwrap();
	assert_eq!((stats.rows, stats.cohorts, stats.maximum_batch), (2, 1, 2));
	let sources = sorters
		.into_iter()
		.map(|sorter| sorter.finish().unwrap())
		.collect::<Vec<_>>();
	let mut observed = sources[partition_of(&identity)].one().unwrap();
	let mut images = [
		order_image(&identity, entry.stamp),
		order_image(&tail_identity, tail_stamp),
	];
	images.sort_unstable_by(|left, right| left[..32].cmp(&right[..32]));
	for image in images {
		assert_eq!(observed.next().unwrap(), Some(image));
	}
	assert!(observed.next().unwrap().is_none());
}

#[test]
fn directory_window_refuses_growth_before_any_stat_work() {
	let (_root, slot, _db, entry) = fixture();
	let _pin = slot.clone();
	let identity = id(&entry.record.request_id).unwrap();
	assert_eq!(std::mem::size_of::<NameHint>(), 40);
	let mut names = (0..=NAME_BATCH)
		.map(|_| NameHint { identity, inode: 0 })
		.collect::<Vec<_>>();
	let mut sorters = (0..COLD_ROW_WORKERS)
		.map(|_| Sorter::new(&slot.root).unwrap())
		.collect::<Vec<_>>();
	let pool = rayon::ThreadPoolBuilder::new()
		.num_threads(STAT_WORKERS)
		.build()
		.unwrap();
	let mut stats = Observation::default();
	assert!(flush_names(
		slot.archive.legacy(),
		&mut names,
		&mut sorters,
		&pool,
		deadline(),
		&AtomicBool::new(false),
		&mut stats
	)
	.is_err());
	assert_eq!((stats.rows, stats.cohorts), (0, 0));
}

#[test]
fn directory_production_verifier_rejects_symlinks_and_unsafe_modes() {
	for symlink in [false, true] {
		let (root, slot, db, entry) = fixture();
		let _pin = slot.clone();
		let sources = expected(&slot, &db);
		let original = path(root.path(), &entry);
		if symlink {
			let target = root.path().join("kept-original");
			std::fs::rename(&original, &target).unwrap();
			std::os::unix::fs::symlink(target, &original).unwrap();
		} else {
			std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o644)).unwrap();
		}
		refresh(&slot);
		assert!(super::super::verify(&db, &slot, sources, deadline()).is_err());
		assert!(slot.state.try_lock().is_ok());
	}
}

#[test]
fn identity_join_rejects_last_payload_corruption_even_with_a_fresh_file_stamp() {
	let (_root, slot, _db, entry) = fixture();
	let _pin = slot.clone();
	let images = [[0u8; 32], [1u8; 32]].map(|identity| order_image(&identity, entry.stamp));
	let expected = identity_spool(&slot, images);
	let mut actual = identity_spool(&slot, images);
	actual
		.file
		.write_all_at(&[images[1][VALUE_BYTES - 1] ^ 1], actual.length - 1)
		.unwrap();
	actual.stamp = private(&actual.file, actual.length).unwrap();
	let (send, _receive) = std::sync::mpsc::sync_channel(1);
	let error = join_partition(
		&slot,
		&expected,
		&actual,
		0,
		deadline(),
		&AtomicBool::new(false),
		&send,
	)
	.err()
	.unwrap();
	assert!(error.to_string().contains("record digest changed"));
}

#[test]
fn identity_join_rejects_duplicates_between_individually_valid_runs() {
	let (_root, slot, _db, entry) = fixture();
	let _pin = slot.clone();
	let image = order_image(&[0u8; 32], entry.stamp);
	let expected = identity_spool(&slot, [image]);
	let mut writer = Writer::new(&slot.root).unwrap();
	for _ in 0..2 {
		writer.begin().unwrap();
		writer.push(image).unwrap();
		writer.end().unwrap();
	}
	let actual = writer.finish().unwrap();
	let (send, _receive) = std::sync::mpsc::sync_channel(1);
	assert!(join_partition(
		&slot,
		&expected,
		&actual,
		0,
		deadline(),
		&AtomicBool::new(false),
		&send
	)
	.is_err());
}

#[test]
fn identity_join_consumes_empty_run_headers_and_enforces_partition_membership() {
	let (_root, slot, _db, entry) = fixture();
	let _pin = slot.clone();
	let expected = identity_spool(&slot, []);
	let actual = identity_spool(&slot, []);
	let (send, _receive) = std::sync::mpsc::sync_channel(1);
	let result = join_partition(
		&slot,
		&expected,
		&actual,
		0,
		deadline(),
		&AtomicBool::new(false),
		&send,
	)
	.unwrap();
	assert_eq!((result.matched, result.changed, result.extra), (0, 0, 0));
	let wrong = order_image(&[255u8; 32], entry.stamp);
	assert!(join_partition(
		&slot,
		&identity_spool(&slot, [wrong]),
		&identity_spool(&slot, [wrong]),
		0,
		deadline(),
		&AtomicBool::new(false),
		&send
	)
	.is_err());
}

#[test]
fn cancelled_and_expired_directory_scans_leave_no_named_spools_or_locked_state() {
	for cancelled in [false, true] {
		let (root, slot, db, _entry) = fixture();
		let _pin = slot.clone();
		let sources = expected(&slot, &db);
		let names = || {
			let mut names = std::fs::read_dir(root.path())
				.unwrap()
				.map(|item| item.unwrap().file_name())
				.collect::<Vec<_>>();
			names.sort();
			names
		};
		let before = names();
		let pool = rayon::ThreadPoolBuilder::new()
			.num_threads(STAT_WORKERS)
			.build()
			.unwrap();
		let (send, _receive) = std::sync::mpsc::sync_channel(1);
		let until = if cancelled {
			deadline()
		} else {
			Instant::now() - Duration::from_secs(1)
		};
		assert!(verify_sources(
			&slot,
			sources,
			&pool,
			until,
			&AtomicBool::new(cancelled),
			&send
		)
		.is_err());
		assert_eq!(names(), before);
		assert!(slot.state.try_lock().is_ok());
	}
}

#[test]
fn directory_scan_rejects_invalid_names_before_canonical_reconstruction() {
	for invalid in [
		format!("{}.json", "A".repeat(64)),
		format!("{}.json", "a".repeat(63)),
		format!("{}.json", "a".repeat(65)),
		format!("{}.json", "g".repeat(64)),
		format!("{}.JSON", "a".repeat(64)),
		".invalid-staging.tmp".to_owned(),
	] {
		let (root, slot, _db, entry) = fixture();
		let _pin = slot.clone();
		let original = std::fs::read(path(root.path(), &entry)).unwrap();
		let unexpected = root.path().join(ARCHIVE_NAME).join(&invalid);
		std::fs::write(&unexpected, b"invalid member").unwrap();
		std::fs::set_permissions(&unexpected, std::fs::Permissions::from_mode(0o600)).unwrap();
		let pool = rayon::ThreadPoolBuilder::new()
			.num_threads(STAT_WORKERS)
			.build()
			.unwrap();
		let error = observe(&slot, &pool, deadline(), &AtomicBool::new(false))
			.err()
			.unwrap();
		assert!(error.to_string().contains(if invalid.starts_with('.') {
			"request archive staging"
		} else {
			"invalid request archive filename"
		}));
		assert_eq!(std::fs::read(path(root.path(), &entry)).unwrap(), original);
		assert!(slot.state.try_lock().is_ok());
	}
}

#[test]
fn nonempty_directory_window_rejects_cancellation_and_expiry_before_sort_or_stat() {
	for cancelled in [false, true] {
		let (root, slot, _db, entry) = fixture();
		let _pin = slot.clone();
		let mut names = vec![NameHint {
			identity: id(&entry.record.request_id).unwrap(),
			inode: u64::MAX,
		}];
		let mut sorters = (0..COLD_ROW_WORKERS)
			.map(|_| Sorter::new(&slot.root).unwrap())
			.collect::<Vec<_>>();
		let pool = rayon::ThreadPoolBuilder::new()
			.num_threads(STAT_WORKERS)
			.build()
			.unwrap();
		let mut stats = Observation::default();
		let until = if cancelled {
			deadline()
		} else {
			Instant::now() - Duration::from_secs(1)
		};
		let error = flush_names(
			slot.archive.legacy(),
			&mut names,
			&mut sorters,
			&pool,
			until,
			&AtomicBool::new(cancelled),
			&mut stats,
		)
		.unwrap_err();
		assert!(error
			.to_string()
			.contains(if cancelled { "cancelled" } else { "deadline" }));
		assert_eq!((stats.rows, stats.cohorts, stats.batches), (0, 0, 0));
		assert_eq!(names.len(), 1);
		drop(sorters);
		assert!(!std::fs::read_dir(root.path()).unwrap().any(|item| {
			item.unwrap()
				.file_name()
				.to_string_lossy()
				.starts_with(".archive-compare-")
		}));
		assert!(slot.state.try_lock().is_ok());
	}
}

fn partition_image(part: usize, number: u64, stamp: FileStamp) -> Image {
	let mut identity = [0; 32];
	identity[0] = (part * 256 / COLD_ROW_WORKERS) as u8;
	identity[24..].copy_from_slice(&number.to_be_bytes());
	order_image(&identity, stamp)
}

fn parallel_join_sources(slot: &Slot, stamp: FileStamp) -> (Vec<(usize, Spool)>, Vec<Spool>) {
	let mut expected = Vec::new();
	let mut observed = Vec::new();
	for part in 0..COLD_ROW_WORKERS {
		expected.push((
			part,
			identity_spool(
				slot,
				(0..FAN_IN).map(|n| partition_image(part, n as u64, stamp)),
			),
		));
		let mut writer = Writer::new(&slot.root).unwrap();
		for number in 0..FAN_IN {
			writer.begin().unwrap();
			writer
				.push(partition_image(part, number as u64, stamp))
				.unwrap();
			writer.end().unwrap();
		}
		observed.push(writer.finish().unwrap());
	}
	(expected, observed)
}

#[derive(Default)]
struct JoinActivity {
	active: std::sync::atomic::AtomicUsize,
	readers: std::sync::atomic::AtomicUsize,
	maximum_active: std::sync::atomic::AtomicUsize,
	maximum_readers: std::sync::atomic::AtomicUsize,
	seen: std::sync::atomic::AtomicUsize,
}
struct Joining<'a> {
	activity: &'a JoinActivity,
	readers: usize,
}
impl JoinActivity {
	fn enter(&self, part: usize, readers: usize) -> Joining<'_> {
		let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
		self.maximum_active.fetch_max(active, Ordering::SeqCst);
		let total = self.readers.fetch_add(readers, Ordering::SeqCst) + readers;
		self.maximum_readers.fetch_max(total, Ordering::SeqCst);
		assert_eq!(
			self.seen.fetch_or(1 << part, Ordering::SeqCst) & (1 << part),
			0
		);
		Joining {
			activity: self,
			readers,
		}
	}
}
impl Drop for Joining<'_> {
	fn drop(&mut self) {
		self.activity
			.readers
			.fetch_sub(self.readers, Ordering::SeqCst);
		self.activity.active.fetch_sub(1, Ordering::SeqCst);
	}
}

#[test]
fn identity_partitions_overlap_two_workers_within_the_existing_reader_budget() {
	let (_root, slot, _db, entry) = fixture();
	let (expected, observed) = parallel_join_sources(&slot, entry.stamp);
	let cancelled = AtomicBool::new(false);
	let until = deadline();
	let activity = JoinActivity::default();
	let (entered, entries) = std::sync::mpsc::channel();
	let gates: Vec<_> = (0..JOIN_WORKERS)
		.map(|_| std::sync::mpsc::sync_channel(1))
		.collect();
	let (release, waits): (Vec<_>, Vec<_>) = gates.into_iter().unzip();
	let waits: Vec<_> = waits.into_iter().map(Mutex::new).collect();
	let (send, _receive) = std::sync::mpsc::sync_channel(1);
	let result = std::thread::scope(|scope| {
		let handle = scope.spawn(|| {
			join_partitions(
				&expected,
				&observed,
				until,
				&cancelled,
				|part, left, right| {
					let _joining = activity.enter(part, right.runs as usize + 1);
					if part < JOIN_WORKERS {
						entered.send(part)?;
						waits[part]
							.lock()
							.unwrap()
							.recv_timeout(Duration::from_secs(5))?;
					}
					join_partition(&slot, left, right, part, until, &cancelled, &send)
				},
			)
		});
		let first: Vec<_> = (0..JOIN_WORKERS)
			.map(|_| entries.recv_timeout(Duration::from_secs(5)))
			.collect();
		// Always release both workers before asserting, including a scheduling failure.
		for release in release {
			let _ = release.send(());
		}
		let result = handle.join().unwrap();
		assert!(first.iter().all(Result::is_ok));
		let mut first: Vec<_> = first.into_iter().map(Result::unwrap).collect();
		first.sort_unstable();
		assert_eq!(first, [0, 1]);
		result.unwrap()
	});
	assert_eq!(activity.maximum_active.load(Ordering::SeqCst), JOIN_WORKERS);
	assert_eq!(
		activity.maximum_readers.load(Ordering::SeqCst),
		JOIN_READER_BOUND
	);
	assert!(activity.maximum_readers.load(Ordering::SeqCst) <= TERMINAL_READERS);
	assert_eq!(activity.active.load(Ordering::SeqCst), 0);
	assert_eq!(activity.readers.load(Ordering::SeqCst), 0);
	assert_eq!(
		activity.seen.load(Ordering::SeqCst),
		(1 << COLD_ROW_WORKERS) - 1
	);
	assert_eq!(
		(result.matched, result.changed, result.extra),
		((COLD_ROW_WORKERS * FAN_IN) as u64, 0, 0)
	);
	let mut ids = Fingerprint::default();
	for part in 0..COLD_ROW_WORKERS {
		for number in 0..FAN_IN {
			ids.add(
				b"id",
				&partition_image(part, number as u64, entry.stamp)[..32],
				1,
			);
		}
	}
	assert_eq!(result.ids, ids);
}

#[test]
fn identity_join_preserves_the_triggering_failure_and_joins_every_worker() {
	for panic in [false, true] {
		let (_root, slot, _db, entry) = fixture();
		let (expected, mut observed) = parallel_join_sources(&slot, entry.stamp);
		let mut tail = [0];
		observed[1]
			.file
			.read_exact_at(&mut tail, observed[1].length - 1)
			.unwrap();
		observed[1]
			.file
			.write_all_at(&[tail[0] ^ 1], observed[1].length - 1)
			.unwrap();
		observed[1].stamp = private(&observed[1].file, observed[1].length).unwrap();
		let cancelled = AtomicBool::new(false);
		let until = deadline();
		let activity = JoinActivity::default();
		let (entered, entries) = std::sync::mpsc::channel();
		let gates: Vec<_> = (0..JOIN_WORKERS)
			.map(|_| std::sync::mpsc::sync_channel(1))
			.collect();
		let (release, waits): (Vec<_>, Vec<_>) = gates.into_iter().unzip();
		let waits: Vec<_> = waits.into_iter().map(Mutex::new).collect();
		let (send, _receive) = std::sync::mpsc::sync_channel(1);
		let error = std::thread::scope(|scope| {
			let handle = scope.spawn(|| {
				join_partitions(
					&expected,
					&observed,
					until,
					&cancelled,
					|part, left, right| {
						let _joining = activity.enter(part, right.runs as usize + 1);
						entered.send(part)?;
						waits[part]
							.lock()
							.unwrap()
							.recv_timeout(Duration::from_secs(5))?;
						if part == 0 {
							let until = Instant::now() + Duration::from_secs(5);
							while !cancelled.load(Ordering::Relaxed) && Instant::now() < until {
								std::thread::yield_now();
							}
							live(&cancelled, until)?;
						} else if panic {
							panic!("injected identity join worker failure");
						}
						join_partition(&slot, left, right, part, until, &cancelled, &send)
					},
				)
			});
			let first: Vec<_> = (0..JOIN_WORKERS)
				.map(|_| entries.recv_timeout(Duration::from_secs(5)))
				.collect();
			for release in release {
				let _ = release.send(());
			}
			let result = handle.join().unwrap();
			assert!(first.iter().all(Result::is_ok));
			result.err().unwrap()
		});
		assert!(error.to_string().contains(if panic {
			"worker panicked"
		} else {
			"record digest changed"
		}));
		assert!(cancelled.load(Ordering::Relaxed));
		assert_eq!(activity.active.load(Ordering::SeqCst), 0);
		assert_eq!(activity.readers.load(Ordering::SeqCst), 0);
		assert_eq!(activity.seen.load(Ordering::SeqCst), 3);
		assert!(slot.state.try_lock().is_ok());
	}
}

struct JoinedOriginal {
	identity: Id,
	filename: String,
	path: PathBuf,
	bytes: Vec<u8>,
}
fn add_partition_originals(root: &Path, slot: &Slot, entry: &Entry) -> Vec<JoinedOriginal> {
	let template: serde_json::Value =
		serde_json::from_slice(&std::fs::read(path(root, entry)).unwrap()).unwrap();
	let mut originals = Vec::new();
	for part in 0..COLD_ROW_WORKERS {
		let identity: Id = partition_image(part, 1, entry.stamp)[..32]
			.try_into()
			.unwrap();
		let filename = filename(&identity).unwrap();
		assert_ne!(&filename[..64], entry.record.request_id);
		let mut record = template.clone();
		record["request_id"] = filename[..64].to_owned().into();
		let bytes = serde_json::to_vec(&record).unwrap();
		let original = root.join(ARCHIVE_NAME).join(&filename);
		std::fs::write(&original, &bytes).unwrap();
		std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o600)).unwrap();
		originals.push(JoinedOriginal {
			identity,
			filename,
			path: original,
			bytes,
		});
	}
	refresh(slot);
	originals
}

#[test]
fn parallel_identity_changes_are_all_folded_before_original_done() {
	let (root, slot, db, entry) = fixture();
	let sources = expected(&slot, &db);
	let originals = add_partition_originals(root.path(), &slot, &entry);
	let mut identities = Fingerprint::default();
	identities.add(b"id", &id(&entry.record.request_id).unwrap(), 1);
	for original in &originals {
		identities.add(b"id", &original.identity, 1);
	}
	let coverage = super::super::verify(&db, &slot, sources, deadline())
		.unwrap()
		.unwrap();
	assert!(coverage.matches_namespace(&identities, (COLD_ROW_WORKERS + 1) as u64));
	assert_eq!(
		(coverage.matched, coverage.changed, coverage.extra),
		(1, 0, COLD_ROW_WORKERS as u64)
	);
	for original in originals {
		assert!(
			entry_stamp(&db, &original.identity)
				== stamp(&slot.archive, &original.filename).unwrap()
		);
		assert_eq!(std::fs::read(original.path).unwrap(), original.bytes);
	}
	assert!(slot.state.try_lock().is_ok());
}

#[test]
fn closing_a_full_changes_queue_releases_and_joins_both_identity_workers() {
	let (root, slot, db, entry) = fixture();
	let expected = expected(&slot, &db);
	let originals = add_partition_originals(root.path(), &slot, &entry);
	let until = deadline();
	let cancelled = AtomicBool::new(false);
	let pool = rayon::ThreadPoolBuilder::new()
		.num_threads(STAT_WORKERS)
		.build()
		.unwrap();
	let observed = observe(&slot, &pool, until, &cancelled).unwrap();
	let observed = reduce_sources(&slot, observed.sources, until, &cancelled).unwrap();
	let activity = JoinActivity::default();
	let (send, receive) = std::sync::mpsc::sync_channel(1);
	let (entered, entries) = std::sync::mpsc::channel();
	std::thread::scope(|scope| {
		let handle = scope.spawn(|| {
			join_partitions(
				&expected,
				&observed,
				until,
				&cancelled,
				|part, left, right| {
					let _joining = activity.enter(part, right.runs as usize + 1);
					entered.send(part)?;
					join_partition(&slot, left, right, part, until, &cancelled, &send)
				},
			)
		});
		// Reaching a third partition means one Changes send completed. Without
		// a consumer, the capacity-one queue is now full and further sends wait.
		let started: Vec<_> = (0..JOIN_WORKERS + 1)
			.map(|_| entries.recv_timeout(Duration::from_secs(5)))
			.collect();
		let full = matches!(
			send.try_send(Message::Changes(Vec::new())),
			Err(std::sync::mpsc::TrySendError::Full(_))
		);
		drop(receive);
		let result = handle.join().unwrap();
		assert!(started.iter().all(Result::is_ok));
		assert!(full);
		assert!(result.is_err());
	});
	assert!(cancelled.load(Ordering::Relaxed));
	assert_eq!(activity.active.load(Ordering::SeqCst), 0);
	assert_eq!(activity.readers.load(Ordering::SeqCst), 0);
	assert!(slot.state.try_lock().is_ok());
	for original in originals {
		assert_eq!(std::fs::read(original.path).unwrap(), original.bytes);
	}
}
