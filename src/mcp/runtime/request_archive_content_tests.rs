// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Synthetic original/view agreement, pure refusal and bounded cold recovery.
use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn stack_original_observations_keep_all_filename_domain_refusals_before_io() {
	fn refused<const BORROWED: bool>(archive: &Archive, filename: &str) -> String {
		let mut trace = NamespaceMutation {
			phase: ContentPhase::NamespaceBefore,
			action: Some(|| panic!("invalid filename reached a namespace observation")),
		};
		let error = observe_original_with_trace::<BORROWED, _>(
			archive,
			archive.legacy(),
			OriginalInput::Unparsed(filename),
			budget(),
			&mut trace,
			|_, _| -> Result<()> { panic!("invalid filename reached callback") },
		)
		.expect_err("invalid filename accepted");
		assert!(trace.action.is_some());
		error.to_string()
	}
	let (_root, archive, _record, _path) = fused_namespace_fixture(false, false);
	let mut cases = vec![
		String::new(),
		".json".into(),
		"..".into(),
		format!("{}.json", "a".repeat(63)),
		format!("{}.json", "a".repeat(65)),
		format!("{}.json", "A".repeat(64)),
		format!("{}.json", "g".repeat(64)),
		format!("{}.json", "é".repeat(32)),
		format!("{}.jsonx", "a".repeat(64)),
		format!("{}.json\0", "a".repeat(64)),
		format!(".{}-{}.tmp", "a".repeat(64), "b".repeat(64)),
	];
	for position in [0, 31, 63, 64, 68] {
		let mut bytes = format!("{}.json", "a".repeat(64)).into_bytes();
		bytes[position] = 0;
		cases.push(String::from_utf8(bytes).unwrap());
	}
	for filename in cases {
		assert_eq!(
			refused::<false>(&archive, &filename),
			"invalid request metadata filename"
		);
		assert_eq!(
			refused::<true>(&archive, &filename),
			"invalid request metadata filename"
		);
	}
}

struct Fixture {
	database: Database,
	slot: Slot,
	original: Record,
	root: tempfile::TempDir,
}

fn record(number: u128, state: DurableState) -> Record {
	Record {
		request_id: format!("{number:064x}"),
		owner: "a".repeat(64),
		tool_name: "host_list".into(),
		state,
		accepted_unix_ms: 1_000_000 + number,
		elapsed_ms: (state != DurableState::Unknown).then_some(1),
	}
}

fn budget() -> Instant {
	Instant::now() + Duration::from_secs(10)
}

impl Fixture {
	fn new(original: Record, indexed: Record) -> Self {
		let root = tempfile::Builder::new()
			.permissions(std::fs::Permissions::from_mode(0o700))
			.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
			.unwrap();
		let archive = open_archive(root.path()).unwrap();
		{
			let _guard = store_lock().unwrap();
			save_raw_with_sync(archive.legacy(), &original, false, true).unwrap();
		}
		let version = content_version(&archive).unwrap();
		let slot = Slot {
			root: archive.root().try_clone().unwrap(),
			identity: identity(archive.legacy()).unwrap(),
			archive,
			metadata_activity: MetadataActivity::default(),
			state: Mutex::new(State {
				database: None,
				worker: false,
				busy: false,
				failed: false,
				retired: false,
				pending: BTreeMap::new(),
				requested: false,
				query_flushed: false,
				large_archive: false,
				last_publication: Instant::now(),
				version,
				generation: 0,
				applied: 0,
			}),
			wake: Condvar::new(),
			parallel_hook: Mutex::new(None),
			seal_hook: Mutex::new(None),
		};
		let file = open_at(
			&slot.root,
			CACHE_NAME,
			libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
			0o600,
		)
		.unwrap();
		let database = database(file, budget()).unwrap();
		let entry = Entry {
			record: indexed,
			stamp: stamp(&slot.archive, &format!("{}.json", original.request_id)).unwrap(),
		};
		apply(&database, [entry], Some(&slot), true).unwrap();
		Self {
			database,
			slot,
			original,
			root,
		}
	}
	fn path(&self) -> std::path::PathBuf {
		self.root
			.path()
			.join(ARCHIVE_NAME)
			.join(format!("{}.json", self.original.request_id))
	}
	fn original_entry(&self) -> Entry {
		let filename = format!("{}.json", self.original.request_id);
		Entry {
			record: self.original.clone(),
			stamp: stamp(&self.slot.archive, &filename).unwrap(),
		}
	}
	fn verify(&self, view: &PendingView) -> Result<()> {
		verify_members(&self.database, &self.slot.archive, view, budget())
	}
}

#[test]
fn content_phase_aggregates_preserve_submicrosecond_cost_and_saturate_output() {
	let start = Instant::now();
	let mut trace = ContentPhases::at(start);
	trace.phase = ContentPhase::Row;
	for count in 1..=3 {
		trace.advance(start + Duration::from_nanos(count * 400));
	}
	assert_eq!(trace.nanos[ContentPhase::Row as usize], 1_200);
	assert_eq!(trace.micros()[ContentPhase::Row as usize], 1);
	assert_eq!(trace.nanos[ContentPhase::Walk as usize], 0);
	trace.nanos[ContentPhase::Order as usize] = u128::MAX;
	assert_eq!(trace.micros()[ContentPhase::Order as usize], u64::MAX);
	assert!(!trace.complete);
}

#[test]
fn instrumented_serial_scan_preserves_refusal_and_reports_incomplete_work() {
	fn observe(fixture: &Fixture, deadline: Instant, trace: &mut ContentPhases) -> Result<()> {
		let transaction = fixture.database.begin_read()?;
		let rows = transaction.open_table(ROWS)?;
		let order = transaction.open_table(ORDER)?;
		verify_members_serial(
			&fixture.slot.archive,
			(&rows, &order),
			&PendingView::default(),
			rows.len()?,
			deadline,
			trace,
		)
	}

	let original = record(1, DurableState::Completed);
	let fixture = Fixture::new(original.clone(), original);
	let original_bytes = std::fs::read(fixture.path()).unwrap();
	fixture.verify(&PendingView::default()).unwrap();
	let mut complete = ContentPhases::new();
	observe(&fixture, budget(), &mut complete).unwrap();
	assert_eq!(
		(complete.attempted, complete.verified, complete.complete),
		(1, 1, true)
	);
	assert_eq!(std::fs::read(fixture.path()).unwrap(), original_bytes);

	std::fs::write(fixture.path(), b"{").unwrap();
	let ordinary_error = fixture
		.verify(&PendingView::default())
		.unwrap_err()
		.to_string();
	let mut refused = ContentPhases::new();
	let diagnostic_error = observe(&fixture, budget(), &mut refused)
		.unwrap_err()
		.to_string();
	assert_eq!(diagnostic_error, ordinary_error);
	assert_eq!(
		(refused.attempted, refused.verified, refused.complete),
		(1, 0, false)
	);
	assert_eq!(std::fs::read(fixture.path()).unwrap(), b"{");

	let mut expired = ContentPhases::new();
	let error = observe(&fixture, Instant::now(), &mut expired).unwrap_err();
	assert!(error.to_string().contains("deadline exceeded"));
	assert_eq!(
		(expired.attempted, expired.verified, expired.complete),
		(0, 0, false)
	);
	assert_eq!(std::fs::read(fixture.path()).unwrap(), b"{");
}

#[test]
fn reused_component_stamps_reobserve_replacement_and_private_inode_policy() {
	let original = record(1, DurableState::Completed);
	let fixture = Fixture::new(original.clone(), original);
	let filename = format!("{}.json", fixture.original.request_id);
	let component = name(&filename).unwrap();
	let directory = fixture.slot.archive.legacy();
	let before = stamp_at_component(directory, &component).unwrap();
	assert!(before == stamp_at(directory, &filename).unwrap());
	let held = open_at_component(directory, &component, libc::O_RDONLY, 0).unwrap();
	descriptor_matches(&held, before).unwrap();
	let path = fixture.path();
	let retained = path.with_extension("retained");
	let bytes = std::fs::read(&path).unwrap();
	std::fs::rename(&path, &retained).unwrap();
	std::fs::copy(&retained, &path).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	let after = stamp_at_component(directory, &component).unwrap();
	assert_ne!((before.device, before.inode), (after.device, after.inode));
	assert!(descriptor_matches(&held, after).is_err());
	let alias = path.with_extension("linked");
	std::fs::hard_link(&path, &alias).unwrap();
	assert!(stamp_at_component(directory, &component).is_err());
	std::fs::remove_file(&alias).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	assert!(stamp_at_component(directory, &component).is_err());
	std::fs::remove_file(&path).unwrap();
	std::os::unix::fs::symlink(&retained, &path).unwrap();
	assert!(stamp_at_component(directory, &component).is_err());
	assert!(open_at_component(directory, &component, libc::O_RDONLY, 0).is_err());
	assert_eq!(std::fs::read(&retained).unwrap(), bytes);
}

#[test]
fn reused_component_complete_reads_keep_all_physical_namespace_choices() {
	for (with_layout, sharded) in [(false, false), (true, false), (true, true)] {
		let root = tempfile::Builder::new()
			.permissions(std::fs::Permissions::from_mode(0o700))
			.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
			.unwrap();
		let archive = open_archive(root.path()).unwrap();
		let original = record(1, DurableState::Completed);
		{
			let _guard = store_lock().unwrap();
			if sharded {
				archive.initialize_shards().unwrap();
			}
			save_archive_with_sync(&archive, &original, false, true).unwrap();
			if with_layout && !sharded {
				archive.initialize_shards().unwrap();
			}
		}
		let filename = format!("{}.json", original.request_id);
		let directory = archive.directory_for_existing(&filename).unwrap();
		let observed = read_original(&archive, directory, &filename, budget()).unwrap();
		assert!(observed.record == original);
		assert!(observed.stamp == stamp_at(directory, &filename).unwrap());
		let relative = if sharded {
			std::path::PathBuf::from(super::super::super::archive_store::SHARD_ROOT)
				.join(&original.request_id[..2])
		} else {
			std::path::PathBuf::from(ARCHIVE_NAME)
		};
		let path = root.path().join(relative).join(&filename);
		let bytes = std::fs::read(&path).unwrap();
		let repeated = read_original(&archive, directory, &filename, budget()).unwrap();
		assert!(repeated.record == original && repeated.stamp == observed.stamp);
		assert_eq!(std::fs::read(&path).unwrap(), bytes);
	}
}

#[test]
fn complete_content_gate_reads_originals_and_refuses_a_different_time_in_the_derived_view() {
	let original = record(1, DurableState::Completed);
	let exact = Fixture::new(original.clone(), original.clone());
	let before = std::fs::read(exact.path()).unwrap();
	exact.verify(&PendingView::default()).unwrap();
	assert_eq!(std::fs::read(exact.path()).unwrap(), before);
	#[cfg(target_os = "linux")]
	assert!(content_version(&exact.slot.archive).unwrap().is_some());

	// Only the synthetic derived view differs. The original is created once;
	// no timestamp collision, data mutation, sleep or writer-channel assumption.
	let mut different = original.clone();
	different.accepted_unix_ms += 1;
	let stale = Fixture::new(original, different);
	let before = std::fs::read(stale.path()).unwrap();
	let error = stale.verify(&PendingView::default()).unwrap_err();
	assert!(error.to_string().contains("full record content changed"));
	assert_eq!(std::fs::read(stale.path()).unwrap(), before);
}

#[test]
fn complete_content_gate_joins_pending_additions_and_terminal_replacements_without_writes() {
	let original = record(1, DurableState::Completed);
	let mut indexed = original.clone();
	indexed.state = DurableState::Unknown;
	indexed.elapsed_ms = None;
	let fixture = Fixture::new(original, indexed);
	let extra = record(2, DurableState::Failed);
	{
		let _guard = store_lock().unwrap();
		save_raw_with_sync(fixture.slot.archive.legacy(), &extra, false, true).unwrap();
	}
	let extra_entry = Entry {
		stamp: stamp(&fixture.slot.archive, &format!("{}.json", extra.request_id)).unwrap(),
		record: extra,
	};
	let pending = BTreeMap::from([
		(
			id(&fixture.original.request_id).unwrap(),
			fixture.original_entry(),
		),
		(id(&extra_entry.record.request_id).unwrap(), extra_entry),
	]);
	let view = PendingView::new(&fixture.database, &pending, budget()).unwrap();
	assert_eq!(view.entries.len(), 2);
	let cache_before = std::fs::read(fixture.root.path().join(CACHE_NAME)).unwrap();
	let original_before = std::fs::read(fixture.path()).unwrap();
	fixture.verify(&view).unwrap();
	assert_eq!(
		std::fs::read(fixture.root.path().join(CACHE_NAME)).unwrap(),
		cache_before
	);
	assert_eq!(std::fs::read(fixture.path()).unwrap(), original_before);
	let read = fixture.database.begin_read().unwrap();
	assert_eq!(read.open_table(ROWS).unwrap().len().unwrap(), 1);
	assert_eq!(
		view.totals(
			&read.open_table(COUNTS).unwrap(),
			&id(&fixture.original.owner).unwrap()
		)
		.unwrap(),
		[0, 1, 1]
	);
}

#[test]
fn complete_content_gate_preserves_an_ignored_old_pending_state() {
	let original = record(1, DurableState::Completed);
	let fixture = Fixture::new(original.clone(), original);
	let mut old = fixture.original_entry();
	old.record.state = DurableState::Unknown;
	old.record.elapsed_ms = None;
	let pending = BTreeMap::from([(id(&old.record.request_id).unwrap(), old)]);
	let view = PendingView::new(&fixture.database, &pending, budget()).unwrap();
	assert!(view.entries.is_empty());
	fixture.verify(&view).unwrap();
}

#[test]
fn complete_content_gate_refuses_missing_base_and_pending_members() {
	for pending_only in [false, true] {
		let original = record(1, DurableState::Completed);
		let fixture = Fixture::new(original.clone(), original);
		let absent = Entry {
			record: record(2, DurableState::Completed),
			stamp: fixture.original_entry().stamp,
		};
		let view = if pending_only {
			let pending = BTreeMap::from([(id(&absent.record.request_id).unwrap(), absent)]);
			PendingView::new(&fixture.database, &pending, budget()).unwrap()
		} else {
			apply(&fixture.database, [absent], None, false).unwrap();
			PendingView::default()
		};
		assert!(fixture.verify(&view).is_err());
	}
}

#[test]
fn complete_content_gate_refuses_staging_without_removing_either_fixture_file() {
	let original = record(1, DurableState::Completed);
	let fixture = Fixture::new(original.clone(), original);
	let temporary = format!(
		".{}-{}.tmp",
		fixture.original.request_id, fixture.original.request_id
	);
	let mut file = open_at(
		fixture.slot.archive.legacy(),
		&temporary,
		libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
		0o600,
	)
	.unwrap();
	file.write_all(b"synthetic unfinished staging").unwrap();
	drop(file);
	let temporary_path = fixture.root.path().join(ARCHIVE_NAME).join(temporary);
	let before = std::fs::read(fixture.path()).unwrap();
	let staged = std::fs::read(&temporary_path).unwrap();
	let error = fixture.verify(&PendingView::default()).unwrap_err();
	assert!(error.to_string().contains("unresolved staging"));
	assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
	assert_eq!(std::fs::read(temporary_path).unwrap(), staged);
}

#[test]
fn complete_content_gate_and_cold_phase_refuse_an_already_expired_budget() {
	let original = record(1, DurableState::Completed);
	let fixture = Fixture::new(original.clone(), original);
	let expired = Instant::now() - Duration::from_millis(1);
	for result in [
		verify_members(
			&fixture.database,
			&fixture.slot.archive,
			&PendingView::default(),
			expired,
		),
		validate_cached(&fixture.slot, &fixture.database, expired),
	] {
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("total deadline exceeded"));
	}
}

#[test]
fn cold_content_fence_checks_generation_even_without_a_watch_version() {
	let original = record(1, DurableState::Completed);
	let fixture = Fixture::new(original.clone(), original);
	let fence = ColdFence {
		version: None,
		generation: 0,
	};
	let mut state = fixture.slot.state.lock().unwrap();
	state.version = None;
	state.generation = 1;
	let error = fence
		.check_locked(&fixture.slot, &state, budget())
		.unwrap_err();
	assert!(error.is::<ColdEpochChanged>());
}

#[test]
fn cached_content_acceptance_recovers_a_legal_terminal_record_with_the_same_stamp() {
	let original = record(1, DurableState::Completed);
	let mut indexed = original.clone();
	indexed.state = DurableState::Unknown;
	indexed.elapsed_ms = None;
	let fixture = Fixture::new(original, indexed);
	let before = std::fs::read(fixture.path()).unwrap();
	let Fixture {
		database,
		slot,
		original,
		root,
	} = fixture;
	drop(database);
	let accepted = cached(&slot, budget()).unwrap().unwrap();
	verify_members(
		&accepted.database,
		&slot.archive,
		&PendingView::default(),
		budget(),
	)
	.unwrap();
	let read = accepted.database.begin_read().unwrap();
	let rows = read.open_table(ROWS).unwrap();
	let raw = rows
		.get(id(&original.request_id).unwrap().as_slice())
		.unwrap()
		.unwrap();
	assert!(codec::decode(raw.value()).unwrap().record == original);
	let path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", original.request_id));
	assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn cached_content_disagreement_is_an_error_instead_of_an_empty_rebuild_request() {
	let original = record(1, DurableState::Completed);
	let mut indexed = original.clone();
	indexed.accepted_unix_ms += 1;
	let fixture = Fixture::new(original, indexed);
	let before = std::fs::read(fixture.path()).unwrap();
	let Fixture {
		database,
		slot,
		original,
		root,
	} = fixture;
	drop(database);
	let error = cached(&slot, budget())
		.err()
		.expect("content mismatch must propagate");
	assert!(error.to_string().contains("archive index identity changed"));
	let path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", original.request_id));
	assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn cold_original_time_conflict_with_a_stale_derived_stamp_is_not_a_rebuild_request() {
	let original = record(1, DurableState::Completed);
	let mut indexed = original.clone();
	indexed.accepted_unix_ms += 1;
	let fixture = Fixture::new(original, indexed.clone());
	let before = std::fs::read(fixture.path()).unwrap();
	// Only the synthetic derived row has a different ordinary time and stale
	// stamp. The original is created once and is never modified or remapped.
	// This sends cold validation through its preexisting changed-stamp branch,
	// before the new complete-content stage, where an error must stay an error.
	let mut stale = fixture.original_entry();
	stale.record = indexed;
	stale.stamp.modified.1 ^= 1;
	apply(&fixture.database, [stale], None, false).unwrap();
	let Fixture {
		database,
		slot,
		original,
		root,
	} = fixture;
	drop(database);
	let error = cached(&slot, budget())
		.err()
		.expect("preexisting cold observation must preserve a content conflict");
	assert!(error.is::<OriginalRecordConflict>());
	assert_eq!(error.to_string(), "archive index identity changed");
	let path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", original.request_id));
	assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn cold_legal_completion_with_a_stale_derived_stamp_still_recovers() {
	let original = record(1, DurableState::Completed);
	let mut indexed = original.clone();
	indexed.state = DurableState::Unknown;
	indexed.elapsed_ms = None;
	let fixture = Fixture::new(original, indexed.clone());
	let before = std::fs::read(fixture.path()).unwrap();
	let mut stale = fixture.original_entry();
	stale.record = indexed;
	stale.stamp.modified.1 ^= 1;
	apply(&fixture.database, [stale], None, false).unwrap();
	let Fixture {
		database,
		slot,
		original,
		root,
	} = fixture;
	drop(database);
	let accepted = cached(&slot, budget()).unwrap().unwrap();
	verify_members(
		&accepted.database,
		&slot.archive,
		&PendingView::default(),
		budget(),
	)
	.unwrap();
	let read = accepted.database.begin_read().unwrap();
	let rows = read.open_table(ROWS).unwrap();
	let raw = rows
		.get(id(&original.request_id).unwrap().as_slice())
		.unwrap()
		.unwrap();
	assert!(codec::decode(raw.value()).unwrap().record == original);
	let path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", original.request_id));
	assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn cold_original_unknown_does_not_silently_agree_with_a_terminal_derived_row() {
	let original = record(1, DurableState::Unknown);
	let mut indexed = original.clone();
	indexed.state = DurableState::Completed;
	indexed.elapsed_ms = Some(1);
	let fixture = Fixture::new(original, indexed);
	let before = std::fs::read(fixture.path()).unwrap();
	let Fixture {
		database,
		slot,
		original,
		root,
	} = fixture;
	drop(database);
	// The existing apply rule ignores an older Unknown observation. A complete
	// content check must still see that the current original differs from the
	// retained terminal row and refuse this snapshot instead of accepting it.
	let error = cached(&slot, budget())
		.err()
		.expect("original disagreement must remain visible");
	assert!(error.to_string().contains("full record content changed"));
	let path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", original.request_id));
	assert_eq!(std::fs::read(path).unwrap(), before);
}

fn row_bytes(fixture: &Fixture, key: &Id) -> Vec<u8> {
	let read = fixture.database.begin_read().unwrap();
	let rows = read.open_table(ROWS).unwrap();
	let raw = rows.get(key.as_slice()).unwrap().unwrap();
	raw.value().to_vec()
}

fn replace_row_bytes(fixture: &Fixture, key: &Id, raw: &[u8]) {
	let write = fixture.database.begin_write().unwrap();
	write
		.open_table(ROWS)
		.unwrap()
		.insert(key.as_slice(), raw)
		.unwrap();
	write.commit().unwrap();
}

// These fixtures have exactly one ROW. Change its disposable ORDER projection
// to agree with the deliberately different expected entry, so the complete
// original comparison itself must detect every non-identity disagreement.
fn replace_single_expected(fixture: &Fixture, entry: &Entry, legacy: bool) {
	let raw = if legacy {
		serde_json::to_vec(entry).unwrap()
	} else {
		codec::encode(entry).unwrap()
	};
	let write = fixture.database.begin_write().unwrap();
	{
		let mut rows = write.open_table(ROWS).unwrap();
		assert_eq!(rows.len().unwrap(), 1);
		rows.insert(
			id(&fixture.original.request_id).unwrap().as_slice(),
			raw.as_slice(),
		)
		.unwrap();
	}
	{
		let mut order = write.open_table(ORDER).unwrap();
		let keys: Vec<_> = order
			.iter()
			.unwrap()
			.map(|pair| pair.unwrap().0.value().to_vec())
			.collect();
		for key in keys {
			order.remove(key.as_slice()).unwrap();
		}
		order
			.insert(
				order_key(&entry.record).unwrap().as_slice(),
				cold::order_value(entry).unwrap().as_slice(),
			)
			.unwrap();
	}
	write.commit().unwrap();
}

#[test]
fn borrowed_compact_order_matches_owned_keys_across_binary_and_optional_boundaries() {
	let stamp = FileStamp {
		device: u64::MAX,
		inode: 1,
		mode: u32::MAX,
		uid: 0,
		links: 1,
		length: 2048,
		modified: (i64::MIN, i64::MAX),
		changed: (0, -1),
	};
	for (identity, owner) in [("00", "ff"), ("ff", "00"), ("a5", "5a")] {
		for accepted in [0, 1, u128::MAX] {
			for state in [
				DurableState::Unknown,
				DurableState::Completed,
				DurableState::Failed,
			] {
				for elapsed in [None, Some(0), Some(u64::MAX)] {
					for tool in ["_".to_owned(), "a".repeat(64)] {
						let entry = Entry {
							record: Record {
								request_id: identity.repeat(32),
								owner: owner.repeat(32),
								tool_name: tool,
								state,
								accepted_unix_ms: accepted,
								elapsed_ms: elapsed,
							},
							stamp,
						};
						let compact = codec::encode(&entry).unwrap();
						let expected = ExpectedRow::parse(&compact).unwrap();
						assert!(matches!(expected, ExpectedRow::Compact(_)));
						assert_eq!(
							expected.order_value().unwrap(),
							cold::order_value(&entry).unwrap()
						);
						assert_eq!(
							expected.order_key().unwrap(),
							order_key(&entry.record).unwrap()
						);
						assert!(expected.matches(&entry).unwrap());
						let legacy = serde_json::to_vec(&entry).unwrap();
						let expected = ExpectedRow::parse(&legacy).unwrap();
						assert!(matches!(expected, ExpectedRow::Legacy(_)));
						assert_eq!(
							expected.order_value().unwrap(),
							cold::order_value(&entry).unwrap()
						);
						assert_eq!(
							expected.order_key().unwrap(),
							order_key(&entry.record).unwrap()
						);
						assert!(expected.matches(&entry).unwrap());
					}
				}
			}
		}
	}
}

#[test]
fn serial_borrowed_and_legacy_rows_refuse_every_record_and_stamp_disagreement() {
	for legacy in [false, true] {
		let original = record(1, DurableState::Completed);
		let fixture = Fixture::new(original.clone(), original);
		let exact = fixture.original_entry();
		let key = id(&exact.record.request_id).unwrap();
		let before = std::fs::read(fixture.path()).unwrap();
		for field in 0..16 {
			let mut different = exact.clone();
			match field {
				0 => different.record.request_id = "b".repeat(64),
				1 => different.record.owner = "c".repeat(64),
				2 => different.record.tool_name = "file_info".into(),
				3 => different.record.state = DurableState::Failed,
				4 => different.record.accepted_unix_ms ^= 1,
				5 => different.record.elapsed_ms = Some(0),
				6 => different.stamp.device ^= 1,
				7 => different.stamp.inode ^= 1,
				8 => different.stamp.mode ^= 1,
				9 => different.stamp.uid ^= 1,
				10 => different.stamp.links ^= 1,
				11 => different.stamp.length ^= 1,
				12 => different.stamp.modified.0 ^= 1,
				13 => different.stamp.modified.1 ^= 1,
				14 => different.stamp.changed.0 ^= 1,
				15 => different.stamp.changed.1 ^= 1,
				_ => unreachable!(),
			}
			replace_single_expected(&fixture, &different, legacy);
			let row_before = row_bytes(&fixture, &key);
			let error = fixture.verify(&PendingView::default()).unwrap_err();
			let expected_error = if field == 0 {
				"archive order projection changed"
			} else {
				"archive full record content changed"
			};
			assert_eq!(
				error.to_string(),
				expected_error,
				"field={field}, legacy={legacy}"
			);
			assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
			assert_eq!(row_bytes(&fixture, &key), row_before);
		}
		replace_single_expected(&fixture, &exact, legacy);
		fixture.verify(&PendingView::default()).unwrap();
	}
}

#[test]
fn malformed_compact_base_never_falls_back_or_hides_behind_a_pending_completion() {
	let original = record(1, DurableState::Completed);
	let mut indexed = original.clone();
	indexed.state = DurableState::Unknown;
	indexed.elapsed_ms = None;
	let fixture = Fixture::new(original, indexed);
	let key = id(&fixture.original.request_id).unwrap();
	let pending = BTreeMap::from([(key, fixture.original_entry())]);
	let view = PendingView::new(&fixture.database, &pending, budget()).unwrap();
	assert_eq!(view.entries.len(), 1);
	let raw = row_bytes(&fixture, &key);
	assert!(codec::view_if_compact(&raw).unwrap().is_some());
	let mut cases = vec![
		raw[..4].to_vec(),
		raw[..166].to_vec(),
		raw[..raw.len() - 1].to_vec(),
	];
	let mut trailing = raw.clone();
	trailing.push(0);
	cases.push(trailing);
	for (offset, value) in [
		(166, 0),
		(166, 65),
		(166, 1),
		(84, 2),
		(85, 1),
		(93, 3),
		(167, 0xff),
		(167, b'A'),
		(167, b'/'),
	] {
		let mut bad = raw.clone();
		bad[offset] = value;
		cases.push(bad);
	}
	let original_before = std::fs::read(fixture.path()).unwrap();
	for bad in cases {
		assert!(codec::view_if_compact(&bad).is_err());
		assert!(ExpectedRow::parse(&bad).is_err());
		replace_row_bytes(&fixture, &key, &bad);
		assert!(fixture.verify(&view).is_err());
		assert_eq!(row_bytes(&fixture, &key), bad);
		assert_eq!(std::fs::read(fixture.path()).unwrap(), original_before);
	}
}

#[test]
fn corrupt_base_order_still_refuses_a_valid_pending_terminal_replacement() {
	for legacy in [false, true] {
		let original = record(1, DurableState::Completed);
		let mut indexed = original.clone();
		indexed.state = DurableState::Unknown;
		indexed.elapsed_ms = None;
		let fixture = Fixture::new(original, indexed);
		let key = id(&fixture.original.request_id).unwrap();
		let entry = codec::decode(&row_bytes(&fixture, &key)).unwrap();
		replace_single_expected(&fixture, &entry, legacy);
		let pending = BTreeMap::from([(key, fixture.original_entry())]);
		let view = PendingView::new(&fixture.database, &pending, budget()).unwrap();
		assert_eq!(view.entries.len(), 1);
		let write = fixture.database.begin_write().unwrap();
		write
			.open_table(ORDER)
			.unwrap()
			.insert(
				order_key(&entry.record).unwrap().as_slice(),
				[0xffu8; 32].as_slice(),
			)
			.unwrap();
		write.commit().unwrap();
		let original_before = std::fs::read(fixture.path()).unwrap();
		let row_before = row_bytes(&fixture, &key);
		assert_eq!(
			fixture.verify(&view).unwrap_err().to_string(),
			"archive order projection changed"
		);
		assert_eq!(row_bytes(&fixture, &key), row_before);
		assert_eq!(std::fs::read(fixture.path()).unwrap(), original_before);
	}
}

#[test]
fn legacy_row_json_whitespace_escapes_and_strict_errors_keep_the_original_domain() {
	let mut original = record(1, DurableState::Completed);
	original.request_id = "a".repeat(64);
	original.owner = "b".repeat(64);
	let fixture = Fixture::new(original.clone(), original);
	let entry = fixture.original_entry();
	let key = id(&entry.record.request_id).unwrap();
	let record_json = serde_json::to_string_pretty(&entry.record).unwrap();
	let escaped = record_json
		.replace(&entry.record.request_id, &"\\u0061".repeat(64))
		.replace(&entry.record.owner, &"\\u0062".repeat(64))
		.replace("host_list", "\\u0068ost_list");
	let stamp_json = serde_json::to_string(&entry.stamp).unwrap();
	let valid = format!(" \n{{\"stamp\":{stamp_json},\"record\":{escaped}}}\n\t").into_bytes();
	assert!(codec::view_if_compact(&valid).unwrap().is_none());
	replace_row_bytes(&fixture, &key, &valid);
	fixture.verify(&PendingView::default()).unwrap();
	assert_eq!(row_bytes(&fixture, &key), valid);
	let plain = serde_json::to_vec(&entry).unwrap();
	let mut trailing = plain.clone();
	trailing.extend_from_slice(b" {}");
	let duplicate_record =
		format!("{{\"record\":{record_json},\"record\":{record_json},\"stamp\":{stamp_json}}}")
			.into_bytes();
	let duplicate_id = format!(
		"{{\"request_id\":\"{}\",{}",
		entry.record.request_id,
		&record_json[1..]
	);
	let duplicate_id = format!("{{\"record\":{duplicate_id},\"stamp\":{stamp_json}}}").into_bytes();
	let mut cases = vec![
		trailing,
		duplicate_record,
		duplicate_id,
		b"HAR".to_vec(),
		b"HAR2".to_vec(),
	];
	for location in ["entry", "record", "stamp"] {
		let mut value = serde_json::to_value(&entry).unwrap();
		let target = if location == "entry" {
			&mut value
		} else {
			&mut value[location]
		};
		target
			.as_object_mut()
			.unwrap()
			.insert("unexpected".into(), serde_json::json!(0));
		cases.push(serde_json::to_vec(&value).unwrap());
	}
	for (field, bad) in [
		("state", serde_json::json!("running")),
		("accepted_unix_ms", serde_json::json!(false)),
		("elapsed_ms", serde_json::json!(-1)),
	] {
		let mut value = serde_json::to_value(&entry).unwrap();
		value["record"][field] = bad;
		cases.push(serde_json::to_vec(&value).unwrap());
	}
	let original_before = std::fs::read(fixture.path()).unwrap();
	for bad in cases {
		assert!(codec::view_if_compact(&bad).unwrap().is_none());
		assert!(ExpectedRow::parse(&bad).is_err());
		replace_row_bytes(&fixture, &key, &bad);
		assert!(fixture.verify(&PendingView::default()).is_err());
		assert_eq!(row_bytes(&fixture, &key), bad);
		assert_eq!(std::fs::read(fixture.path()).unwrap(), original_before);
	}
}

#[test]
fn borrowed_matching_keeps_lowercase_id_domain_and_accepts_decoded_json_escapes() {
	let mut original = record(1, DurableState::Completed);
	original.request_id = "a".repeat(64);
	original.owner = "b".repeat(64);
	let fixture = Fixture::new(original.clone(), original);
	let key = id(&fixture.original.request_id).unwrap();
	let escaped = serde_json::to_string_pretty(&fixture.original)
		.unwrap()
		.replace(&fixture.original.request_id, &"\\u0061".repeat(64))
		.replace(&fixture.original.owner, &"\\u0062".repeat(64));
	// Replace only the already-created private 0600 file. No umask-dependent
	// file creation or relaxed permission validation belongs to these tests.
	std::fs::write(fixture.path(), format!(" {escaped}\n\t")).unwrap();
	let exact = fixture.original_entry();
	for legacy in [false, true] {
		replace_single_expected(&fixture, &exact, legacy);
		fixture.verify(&PendingView::default()).unwrap();
	}
	let compact = codec::encode(&exact).unwrap();
	let expected = ExpectedRow::parse(&compact).unwrap();
	for field in ["request_id", "owner"] {
		for bad in [
			"A".repeat(64),
			"a".repeat(63),
			"a".repeat(65),
			"g".repeat(64),
			"é".repeat(32),
		] {
			assert!(!valid_id(&bad));
			let identity_error = id(&bad).unwrap_err().to_string();
			let mut changed = exact.clone();
			if field == "request_id" {
				changed.record.request_id = bad.clone();
			} else {
				changed.record.owner = bad.clone();
			}
			assert!(expected.matches(&changed).is_err());
			let legacy = serde_json::to_vec(&changed).unwrap();
			replace_row_bytes(&fixture, &key, &legacy);
			assert_eq!(
				fixture
					.verify(&PendingView::default())
					.unwrap_err()
					.to_string(),
				identity_error
			);
			let mut value = serde_json::to_value(&fixture.original).unwrap();
			value[field] = serde_json::json!(bad);
			let raw = serde_json::to_vec(&value).unwrap();
			std::fs::write(fixture.path(), &raw).unwrap();
			let current = fixture.original_entry();
			replace_single_expected(&fixture, &current, false);
			assert_eq!(
				fixture
					.verify(&PendingView::default())
					.unwrap_err()
					.to_string(),
				"request audit metadata identity refused"
			);
			assert_eq!(std::fs::read(fixture.path()).unwrap(), raw);
		}
	}
}

#[test]
fn serial_complete_join_checks_another_owners_original_with_both_row_encodings() {
	let original = record(1, DurableState::Completed);
	let fixture = Fixture::new(original.clone(), original);
	let mut extra = record(2, DurableState::Failed);
	extra.owner = "b".repeat(64);
	{
		let _guard = store_lock().unwrap();
		save_raw_with_sync(fixture.slot.archive.legacy(), &extra, false, true).unwrap();
	}
	let key = id(&extra.request_id).unwrap();
	let extra_path = fixture
		.root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", extra.request_id));
	let entry = Entry {
		stamp: stamp(&fixture.slot.archive, &format!("{}.json", extra.request_id)).unwrap(),
		record: extra,
	};
	apply(&fixture.database, [entry.clone()], None, false).unwrap();
	fixture.verify(&PendingView::default()).unwrap();
	let before = std::fs::read(extra_path).unwrap();
	for legacy in [false, true] {
		let mut different = entry.clone();
		different.record.tool_name = "file_info".into();
		let raw = if legacy {
			serde_json::to_vec(&different).unwrap()
		} else {
			codec::encode(&different).unwrap()
		};
		replace_row_bytes(&fixture, &key, &raw);
		assert_eq!(
			fixture
				.verify(&PendingView::default())
				.unwrap_err()
				.to_string(),
			"archive full record content changed"
		);
		assert_eq!(row_bytes(&fixture, &key), raw);
		assert_eq!(
			std::fs::read(
				fixture
					.root
					.path()
					.join(ARCHIVE_NAME)
					.join(format!("{}.json", entry.record.request_id))
			)
			.unwrap(),
			before
		);
	}
}

// Mutate actual files at existing observation boundaries, without sleeps or
// timestamp assumptions. The production observer remains statically dispatched.
struct NamespaceMutation<F> {
	phase: ContentPhase,
	action: Option<F>,
}

impl<F: FnOnce()> ContentTrace for NamespaceMutation<F> {
	fn enter(&mut self, phase: ContentPhase) {
		if std::mem::discriminant(&phase) != std::mem::discriminant(&self.phase) {
			return;
		}
		if let Some(action) = self.action.take() {
			action();
		}
	}
}

fn fused_namespace_fixture(
	with_layout: bool,
	sharded: bool,
) -> (tempfile::TempDir, Archive, Record, std::path::PathBuf) {
	let root = tempfile::Builder::new()
		.permissions(std::fs::Permissions::from_mode(0o700))
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap();
	let archive = open_archive(root.path()).unwrap();
	let mut original = record(0xa5, DurableState::Completed);
	original.request_id = "a5".repeat(32);
	{
		let _guard = store_lock().unwrap();
		if sharded {
			archive.initialize_shards().unwrap();
		}
		save_archive_with_sync(&archive, &original, false, true).unwrap();
		if with_layout && !sharded {
			archive.initialize_shards().unwrap();
		}
	}
	let relative = if sharded {
		std::path::PathBuf::from(super::super::super::archive_store::SHARD_ROOT)
			.join(&original.request_id[..2])
	} else {
		std::path::PathBuf::from(ARCHIVE_NAME)
	};
	let path = root
		.path()
		.join(relative)
		.join(format!("{}.json", original.request_id));
	(root, archive, original, path)
}

fn fused_refusal_at(
	archive: &Archive,
	filename: &str,
	phase: ContentPhase,
	action: impl FnOnce(),
) -> String {
	let directory = archive.directory_for_existing(filename).unwrap();
	let mut trace = NamespaceMutation {
		phase,
		action: Some(action),
	};
	let result = read_original_with_trace(archive, directory, filename, budget(), &mut trace);
	assert!(
		trace.action.is_none(),
		"controlled mutation was not reached"
	);
	result
		.err()
		.expect("a changed original must not produce a successful observation")
		.to_string()
}

#[test]
fn fused_namespace_stamps_match_current_metadata_and_reject_descriptor_aliases() {
	for (with_layout, sharded) in [(false, false), (true, false), (true, true)] {
		let (_root, archive, original, _path) = fused_namespace_fixture(with_layout, sharded);
		let filename = format!("{}.json", original.request_id);
		let component = name(&filename).unwrap();
		let directory = archive.directory_for_existing(&filename).unwrap();
		let fresh = archive
			.fence_record_stat_component(&component, directory)
			.unwrap();
		assert!(
			stamp_from_stat(fresh).unwrap() == stamp_at_component(directory, &component).unwrap()
		);
		let observed = read_original(&archive, directory, &filename, budget()).unwrap();
		assert!(observed.record == original);
		assert!(observed.stamp == stamp_from_stat(fresh).unwrap());
		// A dup of the same inode is still not the exact held archive target FD.
		let alias = directory.try_clone().unwrap();
		let error = archive
			.fence_record_stat_component(&component, &alias)
			.err()
			.unwrap();
		assert!(error
			.to_string()
			.contains("record changed physical namespace"));
	}
}

#[test]
fn fused_namespace_read_rejects_name_exchange_before_open_and_during_post_observation() {
	for (with_layout, sharded) in [(false, false), (true, false), (true, true)] {
		for (phase, expected) in [
			(ContentPhase::Open, "archive content descriptor changed"),
			(
				ContentPhase::NamespaceAfter,
				"archive content member changed",
			),
		] {
			let (root, archive, original, path) = fused_namespace_fixture(with_layout, sharded);
			let filename = format!("{}.json", original.request_id);
			let bytes = std::fs::read(&path).unwrap();
			let replacement = root.path().join("replacement-original");
			let retained = root.path().join("retained-original");
			std::fs::write(&replacement, &bytes).unwrap();
			std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
			assert_ne!(
				std::fs::metadata(&replacement).unwrap().ino(),
				std::fs::metadata(&path).unwrap().ino()
			);
			let error = fused_refusal_at(&archive, &filename, phase, || {
				std::fs::rename(&path, &retained).unwrap();
				std::fs::rename(&replacement, &path).unwrap();
			});
			assert_eq!(error, expected);
			// Identical JSON is insufficient: both real inode bodies survive, and
			// neither a cleanup path nor an observation rewrites the replacement.
			assert_eq!(std::fs::read(&path).unwrap(), bytes);
			assert_eq!(std::fs::read(&retained).unwrap(), bytes);
		}
	}
}

#[test]
fn fused_namespace_read_keeps_cross_namespace_duplicate_refusal() {
	for sharded in [false, true] {
		for phase in [ContentPhase::Open, ContentPhase::NamespaceAfter] {
			let (root, archive, original, path) = fused_namespace_fixture(true, sharded);
			let filename = format!("{}.json", original.request_id);
			let other = if sharded {
				root.path().join(ARCHIVE_NAME).join(&filename)
			} else {
				root.path()
					.join(super::super::super::archive_store::SHARD_ROOT)
					.join(&original.request_id[..2])
					.join(&filename)
			};
			let bytes = std::fs::read(&path).unwrap();
			let error = fused_refusal_at(&archive, &filename, phase, || {
				std::fs::write(&other, &bytes).unwrap();
				std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o600)).unwrap();
			});
			assert_eq!(
				error,
				"duplicate request archive identity across namespaces"
			);
			assert_eq!(std::fs::read(&path).unwrap(), bytes);
			assert_eq!(std::fs::read(&other).unwrap(), bytes);
		}
	}
}

#[test]
fn fused_namespace_read_refuses_the_same_inode_moved_to_the_other_namespace() {
	for sharded in [false, true] {
		let (root, archive, original, path) = fused_namespace_fixture(true, sharded);
		let filename = format!("{}.json", original.request_id);
		let other = if sharded {
			root.path().join(ARCHIVE_NAME).join(&filename)
		} else {
			root.path()
				.join(super::super::super::archive_store::SHARD_ROOT)
				.join(&original.request_id[..2])
				.join(&filename)
		};
		let bytes = std::fs::read(&path).unwrap();
		let inode = std::fs::metadata(&path).unwrap().ino();
		let error = fused_refusal_at(&archive, &filename, ContentPhase::NamespaceAfter, || {
			std::fs::rename(&path, &other).unwrap();
		});
		assert_eq!(error, "request archive record changed physical namespace");
		assert_eq!(std::fs::metadata(&other).unwrap().ino(), inode);
		assert_eq!(std::fs::read(&other).unwrap(), bytes);
		assert!(!path.exists());
	}
}

#[test]
fn fused_namespace_read_keeps_the_final_named_directory_binding() {
	for (with_layout, sharded) in [(false, false), (true, false), (true, true)] {
		for phase in [ContentPhase::Open, ContentPhase::NamespaceAfter] {
			let (root, archive, original, path) = fused_namespace_fixture(with_layout, sharded);
			let filename = format!("{}.json", original.request_id);
			let directory = path.parent().unwrap();
			let retained = root.path().join("retained-physical-directory");
			let bytes = std::fs::read(&path).unwrap();
			let error = fused_refusal_at(&archive, &filename, phase, || {
				std::fs::rename(directory, &retained).unwrap();
				std::fs::create_dir(directory).unwrap();
				std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
					.unwrap();
			});
			assert_eq!(error, "request archive directory binding changed");
			assert_eq!(std::fs::read(retained.join(&filename)).unwrap(), bytes);
			assert!(!path.exists());
		}
	}
}

#[test]
fn fused_namespace_read_rechecks_real_post_read_private_inode_mutations() {
	for (with_layout, sharded) in [(false, false), (true, false), (true, true)] {
		let (root, archive, original, path) = fused_namespace_fixture(with_layout, sharded);
		let filename = format!("{}.json", original.request_id);
		let bytes = std::fs::read(&path).unwrap();
		let error = fused_refusal_at(&archive, &filename, ContentPhase::NamespaceAfter, || {
			std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
		});
		assert_eq!(error, "unsafe archive index member");
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

		let linked = root.path().join("unexpected-original-link");
		let error = fused_refusal_at(&archive, &filename, ContentPhase::NamespaceAfter, || {
			std::fs::hard_link(&path, &linked).unwrap();
		});
		assert_eq!(error, "unsafe archive index member");
		std::fs::remove_file(linked).unwrap();

		let error = fused_refusal_at(&archive, &filename, ContentPhase::NamespaceAfter, || {
			std::fs::write(&path, vec![b' '; MAX_RECORD_BYTES + 1]).unwrap();
		});
		assert_eq!(error, "unsafe archive index member");
		std::fs::write(&path, &bytes).unwrap();

		let retained = root.path().join("retained-symlink-target");
		let error = fused_refusal_at(&archive, &filename, ContentPhase::NamespaceAfter, || {
			std::fs::rename(&path, &retained).unwrap();
			std::os::unix::fs::symlink(&retained, &path).unwrap();
		});
		assert_eq!(error, "unsafe archive index member");
		assert!(std::fs::symlink_metadata(&path)
			.unwrap()
			.file_type()
			.is_symlink());
		assert_eq!(std::fs::read(&retained).unwrap(), bytes);
	}
}

#[test]
fn fused_namespace_stamp_keeps_uid_size_policy_and_expired_read_refusal() {
	let (_root, archive, original, path) = fused_namespace_fixture(false, false);
	let filename = format!("{}.json", original.request_id);
	let component = name(&filename).unwrap();
	let directory = archive.directory_for_existing(&filename).unwrap();
	let raw = archive
		.fence_record_stat_component(&component, directory)
		.unwrap();
	let mut wrong_owner = raw;
	wrong_owner.st_uid ^= 1;
	assert!(stamp_from_stat(wrong_owner).is_err());
	let mut negative_size = raw;
	negative_size.st_size = -1;
	assert!(stamp_from_stat(negative_size).is_err());
	assert!(stamp_from_stat(raw).unwrap() == stamp_at_component(directory, &component).unwrap());
	let bytes = std::fs::read(&path).unwrap();
	let mut trace = NamespaceMutation {
		phase: ContentPhase::Open,
		action: Some(|| panic!("expired observation reached open")),
	};
	let error =
		read_original_with_trace(&archive, directory, &filename, Instant::now(), &mut trace)
			.err()
			.unwrap();
	assert!(trace.action.is_some());
	assert_eq!(
		error.to_string(),
		"archive metadata query total deadline exceeded"
	);
	assert_eq!(std::fs::read(path).unwrap(), bytes);
}

// Frozen from the actual A58 request_audit.rs (d9e65290c11e45ee...): this
// independent test oracle keeps the original String-based serde contract.
mod frozen_a58_record {
	use super::DurableState;
	use serde::{Deserialize, Serialize};

	#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
	#[serde(deny_unknown_fields)]
	pub(super) struct Record {
		pub(super) request_id: String,
		pub(super) owner: String,
		pub(super) tool_name: String,
		pub(super) state: DurableState,
		pub(super) accepted_unix_ms: u128,
		pub(super) elapsed_ms: Option<u64>,
	}
}
type FrozenA58Record = frozen_a58_record::Record;

impl FrozenA58Record {
	fn into_record(self) -> Record {
		Record {
			request_id: self.request_id,
			owner: self.owner,
			tool_name: self.tool_name,
			state: self.state,
			accepted_unix_ms: self.accepted_unix_ms,
			elapsed_ms: self.elapsed_ms,
		}
	}
}

fn raw_record_members() -> Vec<(&'static str, String)> {
	vec![
		("request_id", format!("\"{}\"", "a".repeat(64))),
		("owner", format!("\"{}\"", "a".repeat(64))),
		("tool_name", "\"host_list\"".into()),
		("state", "\"completed\"".into()),
		("accepted_unix_ms", "1000000".into()),
		("elapsed_ms", "1".into()),
	]
}

fn raw_record_json(members: &[(&str, String)]) -> Vec<u8> {
	format!(
		"{{{}}}",
		members
			.iter()
			.map(|(name, value)| format!("\"{name}\":{value}"))
			.collect::<Vec<_>>()
			.join(",")
	)
	.into_bytes()
}

fn assert_same_json_error(expected: &serde_json::Error, actual: &serde_json::Error, raw: &[u8]) {
	assert_eq!(actual.to_string(), expected.to_string(), "raw={raw:?}");
	assert_eq!(actual.classify(), expected.classify(), "raw={raw:?}");
	assert_eq!(actual.line(), expected.line(), "raw={raw:?}");
	assert_eq!(actual.column(), expected.column(), "raw={raw:?}");
}

fn assert_frozen_json_equivalence(raw: &[u8]) -> bool {
	let frozen = serde_json::from_slice::<FrozenA58Record>(raw);
	let owned = serde_json::from_slice::<Record>(raw);
	let borrowed = serde_json::from_slice::<RecordFields<BorrowedText<'_>>>(raw);
	match (frozen, owned, borrowed) {
		(Ok(frozen), Ok(owned), Ok(borrowed)) => {
			let serialized = serde_json::to_vec(&frozen).unwrap();
			let expected = frozen.into_record();
			assert!(owned == expected, "owned fields changed: {raw:?}");
			assert!(
				record_fields(&borrowed) == record_fields(&expected),
				"borrowed fields changed: {raw:?}"
			);
			assert_eq!(serde_json::to_vec(&owned).unwrap(), serialized);
			true
		}
		(Err(frozen), Err(owned), Err(borrowed)) => {
			assert_same_json_error(&frozen, &owned, raw);
			assert_same_json_error(&frozen, &borrowed, raw);
			false
		}
		(frozen, owned, borrowed) => panic!(
			"parser acceptance changed: frozen={}, owned={}, borrowed={}, raw={raw:?}",
			frozen.is_ok(),
			owned.is_ok(),
			borrowed.is_ok()
		),
	}
}

#[test]
fn shared_record_schema_matches_frozen_a58_json_and_error_contract() {
	let original_null = match serde_json::from_slice::<FrozenA58Record>(b"null") {
		Ok(_) => panic!("the original Record must refuse null"),
		Err(error) => error,
	};
	assert_eq!(
		original_null.to_string(),
		"invalid type: null, expected struct Record at line 1 column 4"
	);
	let base = raw_record_members();
	let raw = raw_record_json(&base);
	assert!(assert_frozen_json_equivalence(&raw));
	let mut reordered = base.clone();
	reordered.reverse();
	assert!(assert_frozen_json_equivalence(&raw_record_json(&reordered)));
	let mut no_elapsed = base.clone();
	no_elapsed.pop();
	assert!(assert_frozen_json_equivalence(&raw_record_json(
		&no_elapsed
	)));
	let mut cases = vec![
		b"null".to_vec(),
		b"false".to_vec(),
		b"0".to_vec(),
		b"\"record\"".to_vec(),
		b"{}".to_vec(),
		b"[]".to_vec(),
		b"".to_vec(),
		b"[".to_vec(),
		b"{\"request_id\":".to_vec(),
	];
	for field in 0..base.len() {
		let mut missing = base.clone();
		missing.remove(field);
		cases.push(raw_record_json(&missing));
		for duplicate in [base[field].1.as_str(), "null"] {
			let mut members = base.clone();
			members.push((base[field].0, duplicate.into()));
			cases.push(raw_record_json(&members));
		}
		let mut members = base.clone();
		let name = base[field].0;
		let escaped = format!("\\u{:04x}{}", name.as_bytes()[0], &name[1..]);
		let json = String::from_utf8(raw_record_json(&members)).unwrap();
		let escaped_json = json.replace(&format!("\"{name}\":"), &format!("\"{escaped}\":"));
		assert!(assert_frozen_json_equivalence(escaped_json.as_bytes()));
		members.push((base[field].0, base[field].1.clone()));
		let duplicated = String::from_utf8(raw_record_json(&members)).unwrap();
		cases.push(
			duplicated
				.replacen(&format!("\"{name}\":"), &format!("\"{escaped}\":"), 1)
				.into_bytes(),
		);
	}
	for position in [0, base.len()] {
		let mut unknown = base.clone();
		unknown.insert(position, ("unexpected", "{\"nested\":[1,null]}".into()));
		cases.push(raw_record_json(&unknown));
	}
	for field in 0..3 {
		for value in [
			"null",
			"false",
			"1",
			"1.0",
			"[]",
			"{}",
			"\"\"",
			"\"\\u0061\"",
			"\"\\uD834\\uDD1E\"",
			"\"\\uD800\"",
			"\"\\uDC00\"",
			"\"\\x61\"",
			"\"line\nfeed\"",
			"\"quote\\\"slash\\\\\"",
		] {
			let mut members = base.clone();
			members[field].1 = value.into();
			cases.push(raw_record_json(&members));
		}
	}
	// These are raw JSON numeric tokens: a Value round trip could normalize
	// exponents, negative zero, or an integer outside its own numeric range.
	for field in [4, 5] {
		for value in [
			"null",
			"false",
			"\"1\"",
			"[]",
			"{}",
			"0",
			"-0",
			"-1",
			"1.0",
			"1e0",
			"18446744073709551615",
			"18446744073709551616",
			"340282366920938463463374607431768211455",
			"340282366920938463463374607431768211456",
			"1e9999",
		] {
			let mut members = base.clone();
			members[field].1 = value.into();
			cases.push(raw_record_json(&members));
		}
	}
	for state in [
		"\"unknown\"",
		"\"failed\"",
		"\"COMPLETED\"",
		"\"other\"",
		"null",
		"1",
		"[]",
		"{}",
		"{\"completed\":null}",
		"{\"completed\":1}",
		"{\"completed\":null,\"failed\":null}",
		"{\"completed\":null,\"completed\":null}",
	] {
		let mut members = base.clone();
		members[3].1 = state.into();
		cases.push(raw_record_json(&members));
	}
	let values: Vec<_> = base.iter().map(|(_, value)| value.as_str()).collect();
	for length in 0..=6 {
		let sequence = format!("[{}]", values[..length].join(","));
		if length == 6 {
			assert!(assert_frozen_json_equivalence(sequence.as_bytes()));
		} else {
			cases.push(sequence.into_bytes());
		}
	}
	cases.push(format!("[{},null]", values.join(",")).into_bytes());
	let text = String::from_utf8(raw.clone()).unwrap();
	assert!(assert_frozen_json_equivalence(
		format!(" \n\t{text}\r\n ").as_bytes()
	));
	for suffix in ["{}", " null", "x", "\0", ","] {
		cases.push(format!("{text}{suffix}").into_bytes());
	}
	cases.push(raw[..raw.len() - 1].to_vec());
	let mut invalid_utf8 = raw.clone();
	let first_value = text.find(&"a".repeat(64)).unwrap();
	invalid_utf8[first_value] = 0xff;
	cases.push(invalid_utf8);
	for case in cases {
		assert_frozen_json_equivalence(&case);
	}
}

#[test]
fn borrowed_record_strings_borrow_plain_and_own_only_decoded_escapes() {
	let base = raw_record_members();
	for escaped_mask in 0..8 {
		let mut members = base.clone();
		for (field, (_, value)) in members.iter_mut().enumerate().take(3) {
			if escaped_mask & (1 << field) != 0 {
				let byte = value.as_bytes()[1];
				value.replace_range(1..2, &format!("\\u{byte:04x}"));
			}
		}
		let raw = raw_record_json(&members);
		assert!(assert_frozen_json_equivalence(&raw));
		let parsed: RecordFields<BorrowedText<'_>> = serde_json::from_slice(&raw).unwrap();
		for (field, value) in [&parsed.request_id, &parsed.owner, &parsed.tool_name]
			.into_iter()
			.enumerate()
		{
			if escaped_mask & (1 << field) == 0 {
				let Cow::Borrowed(text) = &value.0 else {
					panic!("plain field {field} was allocated for mask={escaped_mask}");
				};
				let start = text.as_ptr() as usize;
				assert!(start >= raw.as_ptr() as usize);
				assert!(start + text.len() <= raw.as_ptr() as usize + raw.len());
			} else {
				assert!(matches!(&value.0, Cow::Owned(_)));
			}
		}
		let filename = format!("{}.json", "a".repeat(64));
		let member = OriginalName::member(&filename).unwrap();
		let observed = parse_observation::<true>(&raw, &member).unwrap();
		assert_eq!(observed.identities().unwrap(), ([0xaa; 32], [0xaa; 32]));
		assert!(observed.fields() == record_fields(&parsed));
	}
}

#[test]
fn borrowed_record_domain_matches_frozen_a58_actual_json_checks() {
	let filename = format!("{}.json", "a".repeat(64));
	let member = OriginalName::member(&filename).unwrap();
	let base = raw_record_members();
	let mut cases = vec![raw_record_json(&base)];
	for field in 0..2 {
		for value in [
			"a".repeat(63),
			"a".repeat(65),
			"A".repeat(64),
			"b".repeat(64),
			"g".repeat(64),
			"é".repeat(32),
			format!("\\u0061{}", "a".repeat(63)),
		] {
			let mut members = base.clone();
			members[field].1 = format!("\"{value}\"");
			cases.push(raw_record_json(&members));
		}
	}
	for tool in ["", "HOST_LIST", "host/list", "host list", "a", "a_9", "é"] {
		let mut members = base.clone();
		members[2].1 = format!("\"{tool}\"");
		cases.push(raw_record_json(&members));
	}
	for size in [64, 65] {
		let mut members = base.clone();
		members[2].1 = format!("\"{}\"", "a".repeat(size));
		cases.push(raw_record_json(&members));
	}
	for raw in cases {
		let frozen: FrozenA58Record = serde_json::from_slice(&raw).unwrap();
		let accepted = valid_id(&frozen.request_id)
			&& valid_id(&frozen.owner)
			&& valid_tool(&frozen.tool_name)
			&& frozen.request_id == "a".repeat(64);
		let result = parse_observation::<true>(&raw, &member);
		assert_eq!(result.is_ok(), accepted, "raw={raw:?}");
		match result {
			Ok(actual) => {
				assert!(actual.fields() == record_fields(&frozen.into_record()));
			}
			Err(error) => {
				assert_eq!(error.to_string(), "request audit metadata identity refused");
			}
		}
	}
}

fn borrowed_refusal_at(
	archive: &Archive,
	filename: &str,
	phase: ContentPhase,
	action: impl FnOnce(),
) -> String {
	let directory = archive.directory_for_existing(filename).unwrap();
	let member = OriginalName::member(filename).unwrap();
	let called = std::cell::Cell::new(false);
	let mut trace = NamespaceMutation {
		phase,
		action: Some(action),
	};
	let result = observe_original_with_trace::<true, _>(
		archive,
		directory,
		OriginalInput::Verified(member),
		budget(),
		&mut trace,
		|_, _| {
			called.set(true);
			Ok(())
		},
	);
	assert!(
		trace.action.is_none(),
		"controlled mutation was not reached"
	);
	assert!(
		!called.get(),
		"failed original escaped into the comparison callback"
	);
	result.expect_err("changed original accepted").to_string()
}

#[test]
fn borrowed_original_materializes_owned_values_only_after_all_fences() {
	for (with_layout, sharded) in [(false, false), (true, false), (true, true)] {
		let (_root, archive, original, path) = fused_namespace_fixture(with_layout, sharded);
		let filename = format!("{}.json", original.request_id);
		let directory = archive.directory_for_existing(&filename).unwrap();
		let expected_stamp = stamp(&archive, &filename).unwrap();
		let owned = read_original(&archive, directory, &filename, budget()).unwrap();
		let borrowed_owned = observe_original_with_trace::<true, _>(
			&archive,
			directory,
			OriginalInput::Verified(OriginalName::member(&filename).unwrap()),
			budget(),
			&mut UntracedContent,
			|actual, observed_stamp| {
				let RecordObservation::Borrowed { record, .. } = &actual else {
					panic!("fresh serial observation materialized owned strings");
				};
				assert!(matches!(&record.request_id.0, Cow::Borrowed(_)));
				assert!(matches!(&record.owner.0, Cow::Borrowed(_)));
				assert!(matches!(&record.tool_name.0, Cow::Borrowed(_)));
				assert!(actual.fields() == record_fields(&original));
				assert!(observed_stamp == expected_stamp);
				Ok(actual.into_owned())
			},
		)
		.unwrap();
		// Both returned owned values remain valid after the read buffer, FD and
		// callback are gone. Removing the original cannot supply their data.
		std::fs::remove_file(path).unwrap();
		assert!(owned.record == original);
		assert!(owned.stamp == expected_stamp);
		assert!(borrowed_owned == original);
		assert_eq!(
			serde_json::to_vec(&owned.record).unwrap(),
			serde_json::to_vec(&original).unwrap()
		);
	}
}

#[test]
fn borrowed_original_refuses_inode_exchanges_before_open_and_after_read() {
	for (with_layout, sharded) in [(false, false), (true, false), (true, true)] {
		for (phase, expected) in [
			(ContentPhase::Open, "archive content descriptor changed"),
			(
				ContentPhase::NamespaceAfter,
				"archive content member changed",
			),
		] {
			let (root, archive, original, path) = fused_namespace_fixture(with_layout, sharded);
			let filename = format!("{}.json", original.request_id);
			let bytes = std::fs::read(&path).unwrap();
			let replacement = root.path().join("borrowed-replacement");
			let retained = root.path().join("borrowed-retained");
			std::fs::write(&replacement, &bytes).unwrap();
			std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
			let error = borrowed_refusal_at(&archive, &filename, phase, || {
				std::fs::rename(&path, &retained).unwrap();
				std::fs::rename(&replacement, &path).unwrap();
			});
			assert_eq!(error, expected);
			assert_eq!(std::fs::read(&path).unwrap(), bytes);
			assert_eq!(std::fs::read(retained).unwrap(), bytes);
		}
	}
}

#[test]
fn borrowed_original_post_checks_refuse_mode_links_and_content_changes() {
	for (with_layout, sharded) in [(false, false), (true, false), (true, true)] {
		for phase in [ContentPhase::DescriptorAfter, ContentPhase::NamespaceAfter] {
			for mutation in 0..3 {
				let (root, archive, original, path) = fused_namespace_fixture(with_layout, sharded);
				let filename = format!("{}.json", original.request_id);
				let error = borrowed_refusal_at(&archive, &filename, phase, || match mutation {
					0 => {
						std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
							.unwrap();
					}
					1 => {
						std::fs::hard_link(&path, root.path().join("borrowed-extra-link")).unwrap();
					}
					2 => std::fs::write(&path, b"{}").unwrap(),
					_ => unreachable!(),
				});
				let expected = match (phase, mutation) {
					(ContentPhase::DescriptorAfter, 2) => "archive content descriptor changed",
					(ContentPhase::DescriptorAfter, _) => "private request audit inode refused",
					(ContentPhase::NamespaceAfter, 2) => "archive content member changed",
					_ => "unsafe archive index member",
				};
				assert_eq!(error, expected);
			}
		}
	}
}

#[test]
fn borrowed_original_keeps_duplicate_physical_and_named_directory_fences() {
	for sharded in [false, true] {
		for mutation in 0..3 {
			let (root, archive, original, path) = fused_namespace_fixture(true, sharded);
			let filename = format!("{}.json", original.request_id);
			let other = if sharded {
				root.path().join(ARCHIVE_NAME).join(&filename)
			} else {
				root.path()
					.join(super::super::super::archive_store::SHARD_ROOT)
					.join(&original.request_id[..2])
					.join(&filename)
			};
			let bytes = std::fs::read(&path).unwrap();
			let error =
				borrowed_refusal_at(&archive, &filename, ContentPhase::NamespaceAfter, || {
					match mutation {
						0 => {
							std::fs::write(&other, &bytes).unwrap();
							std::fs::set_permissions(
								&other,
								std::fs::Permissions::from_mode(0o600),
							)
							.unwrap();
						}
						1 => std::fs::rename(&path, &other).unwrap(),
						2 => {
							let directory = path.parent().unwrap();
							std::fs::rename(directory, root.path().join("borrowed-held-directory"))
								.unwrap();
							std::fs::create_dir(directory).unwrap();
							std::fs::set_permissions(
								directory,
								std::fs::Permissions::from_mode(0o700),
							)
							.unwrap();
						}
						_ => unreachable!(),
					}
				});
			let expected = [
				"duplicate request archive identity across namespaces",
				"request archive record changed physical namespace",
				"request archive directory binding changed",
			][mutation];
			assert_eq!(error, expected);
		}
	}
}

#[test]
fn borrowed_original_preserves_complete_eof_size_and_expired_deadline_refusal() {
	let (_root, archive, original, path) = fused_namespace_fixture(false, false);
	let filename = format!("{}.json", original.request_id);
	let directory = archive.directory_for_existing(&filename).unwrap();
	let bytes = std::fs::read(&path).unwrap();
	for (suffix, maximum, accepted) in [
		(b' ', MAX_RECORD_BYTES, true),
		(b' ', MAX_RECORD_BYTES + 1, false),
		(b'x', MAX_RECORD_BYTES, false),
	] {
		let mut body = bytes.clone();
		body.resize(maximum, suffix);
		std::fs::write(&path, &body).unwrap();
		let called = std::cell::Cell::new(false);
		let result = observe_original_with_trace::<true, _>(
			&archive,
			directory,
			OriginalInput::Verified(OriginalName::member(&filename).unwrap()),
			budget(),
			&mut UntracedContent,
			|actual, _| {
				called.set(true);
				assert!(actual.fields() == record_fields(&original));
				Ok(())
			},
		);
		assert_eq!(result.is_ok(), accepted);
		assert_eq!(called.get(), accepted);
		assert_eq!(std::fs::read(&path).unwrap(), body);
	}
	std::fs::write(&path, &bytes).unwrap();
	let error = observe_original_with_trace::<true, _>(
		&archive,
		directory,
		OriginalInput::Verified(OriginalName::member(&filename).unwrap()),
		Instant::now(),
		&mut UntracedContent,
		|_, _| -> Result<()> { panic!("expired original reached callback") },
	)
	.unwrap_err();
	assert_eq!(
		error.to_string(),
		"archive metadata query total deadline exceeded"
	);
	assert_eq!(std::fs::read(path).unwrap(), bytes);
}
