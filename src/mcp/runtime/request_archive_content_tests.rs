// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Synthetic original/view agreement, pure refusal and bounded cold recovery.
use super::*;

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
