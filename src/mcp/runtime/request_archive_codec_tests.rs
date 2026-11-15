// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Full-width codec equivalence, strict frames and resumable hash-safe migration.
use super::*;

fn entry(state: DurableState, time: u128, elapsed: Option<u64>) -> Entry {
	Entry {
		record: Record {
			request_id: "f".repeat(64),
			owner: "a".repeat(64),
			tool_name: "_".repeat(64),
			state,
			accepted_unix_ms: time,
			elapsed_ms: elapsed,
		},
		stamp: FileStamp {
			device: u64::MAX,
			inode: u64::MAX - 1,
			mode: u32::MAX,
			uid: u32::MAX - 1,
			links: u64::MAX - 2,
			length: u64::MAX - 3,
			modified: (i64::MIN, -1),
			changed: (i64::MAX, 999999999),
		},
	}
}
#[test]
fn compact_rows_preserve_every_record_and_stamp_field_without_json_expansion() {
	for state in [
		DurableState::Unknown,
		DurableState::Completed,
		DurableState::Failed,
	] {
		for time in [0, u128::from(u64::MAX) + 1, u128::MAX] {
			for elapsed in [None, Some(0), Some(u64::MAX)] {
				let value = entry(state, time, elapsed);
				let raw = encode(&value).unwrap();
				assert_eq!(raw.len(), 231);
				let restored = decode(&raw).unwrap();
				assert!(restored.record == value.record && restored.stamp == value.stamp);
				let legacy = serde_json::to_vec(&value).unwrap();
				assert!(raw.len() < legacy.len());
				let old = decode(&legacy).unwrap();
				assert!(old.record == value.record && old.stamp == value.stamp);
			}
		}
	}
}
#[test]
fn compact_rows_refuse_unknown_frames_invalid_flags_and_unclaimed_bytes() {
	let raw = encode(&entry(DurableState::Completed, 1, None)).unwrap();
	for position in [0, 84, 93, 166] {
		let mut bad = raw.clone();
		bad[position] = 255;
		assert!(view(&bad).is_err());
	}
	let mut bad = raw.clone();
	bad[85] = 1;
	assert!(view(&bad).is_err());
	let mut bad = raw.clone();
	bad[FIXED] = b'0';
	assert!(view(&bad).is_err());
	assert!(view(&raw[..raw.len() - 1]).is_err());
	let mut bad = raw.clone();
	bad.push(0);
	assert!(view(&bad).is_err());
}
fn fixture() -> (tempfile::TempDir, Arc<Slot>, Database) {
	let (root, owner) = super::super::tests::fixture();
	let ticket = begin_at(root.path(), &owner, "file_info").unwrap();
	finish_sync(ticket, AuditCompletion::Completed).unwrap();
	let slot = super::super::tests::freeze_index(root.path(), &owner);
	let db = cached(&slot, Instant::now() + Duration::from_secs(5))
		.unwrap()
		.unwrap()
		.database;
	(root, slot, db)
}
fn make_legacy(db: &Database, keep_expected_sum: bool) {
	let mut write = db.begin_write().unwrap();
	write.set_quick_repair(true);
	{
		let mut rows = write.open_table(ROWS).unwrap();
		let mut meta = write.open_table(META).unwrap();
		let (key, raw) = {
			let (key, raw) = rows.first().unwrap().unwrap();
			(key.value().to_vec(), raw.value().to_vec())
		};
		let legacy = serde_json::to_vec(&decode(&raw).unwrap()).unwrap();
		if !keep_expected_sum {
			let mut sum =
				Fingerprint::decode(meta.get("row_image_sum").unwrap().unwrap().value()).unwrap();
			sum.row(&key, &raw, false).unwrap();
			sum.row(&key, &legacy, true).unwrap();
			meta.insert("row_image_sum", sum.encode().as_slice())
				.unwrap();
		}
		rows.insert(key.as_slice(), legacy.as_slice()).unwrap();
		meta.remove(FORMAT_KEY).unwrap();
	}
	write.commit().unwrap();
}
#[test]
fn compact_migration_resumes_mixed_rows_and_preserves_every_original() {
	let (root, slot, db) = fixture();
	let originals: Vec<_> = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
		.unwrap()
		.map(|v| {
			let p = v.unwrap().path();
			let b = std::fs::read(&p).unwrap();
			(p, b)
		})
		.collect();
	make_legacy(&db, false);
	assert!(upgrade(&db, &slot, Instant::now()).is_err());
	upgrade(&db, &slot, Instant::now() + Duration::from_secs(5)).unwrap();
	{
		let read = db.begin_read().unwrap();
		assert_eq!(read.open_table(ROWS).unwrap().len().unwrap(), 2);
		for pair in read.open_table(ROWS).unwrap().iter().unwrap() {
			let (key, value) = pair.unwrap();
			assert_eq!(
				view(value.value()).unwrap().identity.as_slice(),
				key.value()
			);
		}
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
fn compact_migration_never_replaces_a_preexisting_row_image_mismatch() {
	let (_root, slot, db) = fixture();
	make_legacy(&db, true);
	upgrade(&db, &slot, Instant::now() + Duration::from_secs(5)).unwrap();
	drop(db);
	assert!(cached(&slot, Instant::now() + Duration::from_secs(5))
		.unwrap()
		.is_none());
}
