// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Ordered stamp coverage, partial upgrades, corruption and cancellation.
use super::*;

pub(super) fn fixture() -> (tempfile::TempDir, Arc<Slot>, Database, Entry) {
	let (root, owner) = super::super::tests::fixture();
	let slot = super::super::tests::freeze_index(root.path(), &owner);
	let db = cached(&slot, Instant::now() + Duration::from_secs(5))
		.unwrap()
		.unwrap()
		.database;
	let entry = {
		let read = db.begin_read().unwrap();
		let rows = read.open_table(ROWS).unwrap();
		let (_, value) = rows.first().unwrap().unwrap();
		codec::decode(value.value()).unwrap()
	};
	(root, slot, db, entry)
}

#[test]
fn compact_order_migration_keeps_the_expected_row_sum_and_rejects_prior_row_mismatch() {
	let (root, slot, db, entry) = fixture();
	let _pin = slot.clone();
	let path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", entry.record.request_id));
	let original = std::fs::read(&path).unwrap();
	let prior = [9u8; 32];
	let write = db.begin_write().unwrap();
	{
		let mut meta = write.open_table(META).unwrap();
		meta.remove(FORMAT_KEY).unwrap();
		meta.insert("row_image_sum", prior.as_slice()).unwrap();
	}
	write
		.open_table(ORDER)
		.unwrap()
		.insert(
			order_key(&entry.record).unwrap().as_slice(),
			order_image(&id(&entry.record.request_id).unwrap(), entry.stamp).as_slice(),
		)
		.unwrap();
	write.commit().unwrap();
	upgrade(&db, &slot, Instant::now() + Duration::from_secs(5)).unwrap();
	{
		let read = db.begin_read().unwrap();
		let meta = read.open_table(META).unwrap();
		assert_eq!(meta.get("row_image_sum").unwrap().unwrap().value(), prior);
		let order = read.open_table(ORDER).unwrap();
		for pair in order.iter().unwrap() {
			let (key, value) = pair.unwrap();
			assert_eq!(value.value().len(), 32);
			assert_eq!(&key.value()[48..], value.value());
		}
	}
	drop(db);
	assert!(cached(&slot, Instant::now() + Duration::from_secs(5))
		.unwrap()
		.is_none());
	assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn complete_parallel_directory_scan_matches_every_identity_and_rejects_invalid_names() {
	let (root, slot, db, entry) = fixture();
	let _pin = slot.clone();
	let mut expected = Fingerprint::default();
	let mut count = 0;
	{
		let read = db.begin_read().unwrap();
		let rows = read.open_table(ROWS).unwrap();
		for pair in rows.iter().unwrap() {
			let (key, _) = pair.unwrap();
			expected.add(b"id", key.value(), 1);
			count += 1;
		}
	}
	let (actual, names) = directory_coverage(
		&db,
		&slot,
		&mut Vec::new(),
		Instant::now() + Duration::from_secs(5),
	)
	.unwrap();
	assert!(actual == expected);
	assert_eq!(names, count);
	let path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", entry.record.request_id));
	let original = std::fs::read(&path).unwrap();
	std::fs::write(
		root.path().join(ARCHIVE_NAME).join("invalid.json"),
		b"not-an-identity",
	)
	.unwrap();
	assert!(directory_coverage(
		&db,
		&slot,
		&mut Vec::new(),
		Instant::now() + Duration::from_secs(5)
	)
	.is_err());
	assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn temporary_stamp_roundtrip_preserves_full_width_times_and_identity() {
	let (_root, _slot, _db, mut entry) = fixture();
	entry.stamp.device = u64::MAX;
	entry.stamp.inode = u64::MAX - 1;
	entry.stamp.modified = (i64::MIN, -1);
	entry.stamp.changed = (i64::MAX, 999_999_999);
	let value = order_image(&id(&entry.record.request_id).unwrap(), entry.stamp);
	let (name, decoded) = decode(&order_key(&entry.record).unwrap(), &value).unwrap();
	assert_eq!(name, format!("{}.json", entry.record.request_id));
	assert!(decoded == entry.stamp);
}

#[test]
fn malformed_temporary_stamps_cannot_escape_identity_or_length_checks() {
	let (_root, _slot, _db, entry) = fixture();
	let mut key = order_key(&entry.record).unwrap();
	let value = order_image(&id(&entry.record.request_id).unwrap(), entry.stamp);
	for size in [0, 32, 103, 105] {
		assert!(decode(&key, &vec![0; size]).is_err());
	}
	key[48] ^= 1;
	assert!(decode(&key, &value).is_err());
	assert!(decode(&key[..79], &value).is_err());
}

#[test]
fn a_partial_legacy_projection_is_upgraded_without_changing_any_original() {
	let (root, slot, db, entry) = fixture();
	let path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", entry.record.request_id));
	let original = std::fs::read(&path).unwrap();
	let write = db.begin_write().unwrap();
	write.open_table(META).unwrap().remove(FORMAT_KEY).unwrap();
	write
		.open_table(ORDER)
		.unwrap()
		.insert(
			order_key(&entry.record).unwrap().as_slice(),
			order_image(&id(&entry.record.request_id).unwrap(), entry.stamp).as_slice(),
		)
		.unwrap();
	write.commit().unwrap();
	assert!(upgrade(&db, &slot, Instant::now() - Duration::from_secs(1)).is_err());
	assert!(db
		.begin_read()
		.unwrap()
		.open_table(META)
		.unwrap()
		.get(FORMAT_KEY)
		.unwrap()
		.is_none());
	drop(db);
	let db = cached(&slot, Instant::now() + Duration::from_secs(5))
		.unwrap()
		.unwrap()
		.database;
	let read = db.begin_read().unwrap();
	assert_eq!(
		read.open_table(META)
			.unwrap()
			.get(FORMAT_KEY)
			.unwrap()
			.unwrap()
			.value(),
		FORMAT
	);
	assert_eq!(
		read.open_table(ORDER)
			.unwrap()
			.first()
			.unwrap()
			.unwrap()
			.1
			.value(),
		order_value(&entry).unwrap()
	);
	assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn valid_checksum_order_identity_forgery_is_not_hidden_by_unchanged_rows() {
	let (root, slot, db, entry) = fixture();
	let path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", entry.record.request_id));
	let original = std::fs::read(&path).unwrap();
	let mut value = order_value(&entry).unwrap();
	value[31] ^= 1;
	let write = db.begin_write().unwrap();
	write
		.open_table(ORDER)
		.unwrap()
		.insert(
			order_key(&entry.record).unwrap().as_slice(),
			value.as_slice(),
		)
		.unwrap();
	write.commit().unwrap();
	drop(db);
	assert!(cached(&slot, Instant::now() + Duration::from_secs(5))
		.unwrap()
		.is_none());
	assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn ordered_original_ranges_cancel_and_join_with_more_than_one_changed_cohort() {
	let (_root, slot, db, entry) = fixture();
	let entries = (0..4096u64).map(|number| {
		let mut next = entry.clone();
		next.record.request_id = format!("{number:064x}");
		next
	});
	apply(&db, entries, None, false).unwrap();
	let read = db.begin_read().unwrap();
	let rows = read.open_table(ROWS).unwrap();
	let order = read.open_table(ORDER).unwrap();
	let ids = read.open_table(IDS).unwrap();

	assert!(table_rows(
		&db,
		&slot,
		&rows,
		&order,
		&ids,
		ScanPlan::new(Instant::now() + Duration::from_secs(5), None, None),
		|_| Ok(true),
	)
	.is_err());
	assert!(slot.state.try_lock().is_ok());
}

#[test]
fn complete_range_validation_checks_unsafe_originals_even_when_rows_are_unchanged() {
	use std::os::unix::fs::PermissionsExt;
	let (root, slot, db, entry) = fixture();
	let path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", entry.record.request_id));
	let before = std::fs::read(&path).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	// Model a new process after the change. Its watcher starts at the current
	// namespace version; the stale disk index still has to check every original.
	slot.state.lock().unwrap().version = content_version(&slot.archive).unwrap();
	let read = db.begin_read().unwrap();
	let rows = read.open_table(ROWS).unwrap();
	let ids = read.open_table(IDS).unwrap();

	let order = read.open_table(ORDER).unwrap();
	let cache = std::fs::File::open(root.path().join(CACHE_NAME)).unwrap();
	assert!(table_rows(
		&db,
		&slot,
		&rows,
		&order,
		&ids,
		ScanPlan::new(Instant::now() + Duration::from_secs(5), None, None),
		|_| Ok(true),
	)
	.is_err());
	assert!(cold_rows(
		&db,
		&slot,
		&rows,
		&order,
		&ids,
		ScanPlan::new(Instant::now() + Duration::from_secs(5), Some(&cache), None),
		|_| Ok(true),
	)
	.is_err());
	assert_eq!(std::fs::read(&path).unwrap(), before);
	drop((rows, ids, order, read, db));
	assert!(cached(&slot, Instant::now() + Duration::from_secs(5))
		.unwrap()
		.is_none());
}

#[test]
fn ordered_original_ranges_repair_replaced_inode_without_changing_original_bytes() {
	use std::os::unix::fs::PermissionsExt;
	let (root, slot, db, entry) = fixture();
	let filename = format!("{}.json", entry.record.request_id);
	let path = root.path().join(ARCHIVE_NAME).join(&filename);
	let before = std::fs::read(&path).unwrap();
	let replacement = root.path().join("replacement.json");
	std::fs::write(&replacement, &before).unwrap();
	std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
	std::fs::rename(replacement, &path).unwrap();
	// A cold reopen gets a fresh watcher baseline, rather than accepting an
	// out-of-band change in an already running controller.
	slot.state.lock().unwrap().version = content_version(&slot.archive).unwrap();
	let now = stamp(&slot.archive, &filename).unwrap();
	assert_ne!(entry.stamp.inode, now.inode);
	let read = db.begin_read().unwrap();
	let original_rows = read.open_table(ROWS).unwrap();
	let order = read.open_table(ORDER).unwrap();
	let ids = read.open_table(IDS).unwrap();

	table_rows(
		&db,
		&slot,
		&original_rows,
		&order,
		&ids,
		ScanPlan::new(Instant::now() + Duration::from_secs(5), None, None),
		|_| Ok(true),
	)
	.unwrap();
	drop((original_rows, order, ids, read, db));
	let db = cached(&slot, Instant::now() + Duration::from_secs(5))
		.unwrap()
		.unwrap()
		.database;
	let read = db.begin_read().unwrap();
	let rows = read.open_table(ROWS).unwrap();
	let raw = rows
		.get(id(&entry.record.request_id).unwrap().as_slice())
		.unwrap()
		.unwrap();
	let repaired = codec::decode(raw.value()).unwrap();
	assert!(repaired.stamp == now);
	assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn borrowed_cold_projection_matches_owned_rows_including_escaped_strings() {
	let stamp = FileStamp {
		device: 4,
		inode: 7,
		mode: 0o100600,
		uid: 1000,
		links: 1,
		length: 511,
		modified: (-1, 999999999),
		changed: (2, 17),
	};
	for state in [
		DurableState::Unknown,
		DurableState::Completed,
		DurableState::Failed,
	] {
		let entry = Entry {
			record: Record {
				request_id: "0".repeat(64),
				owner: "a".repeat(64),
				tool_name: "host_list".into(),
				state,
				accepted_unix_ms: u128::MAX - 1,
				elapsed_ms: Some(u64::MAX),
			},
			stamp,
		};
		let plain = serde_json::to_string(&entry).unwrap();
		let escaped = plain
			.replace("\"request_id\":\"0", "\"request_id\":\"\\u0030")
			.replace("\"owner\":\"a", "\"owner\":\"\\u0061")
			.replace("host_list", "host\\u005flist");
		for encoded in [&plain, &escaped] {
			let borrowed: ColdEntry<'_> = serde_json::from_str(encoded).unwrap();
			let mut actual = ColdTotals::default();
			let mut counts = BTreeMap::new();
			project(
				&borrowed,
				&id(&entry.record.request_id).unwrap(),
				&id(&entry.record.owner).unwrap(),
				&mut actual,
				&mut counts,
			)
			.unwrap();
			let mut expected = Fingerprint::default();
			order_fingerprint(
				&mut expected,
				&order_key(&entry.record).unwrap(),
				&order_value(&entry).unwrap(),
			)
			.unwrap();
			assert!(actual.order == expected);
			assert_eq!(
				counts,
				BTreeMap::from([
					(state_key(&entry.record).unwrap(), 1),
					(tool_key(&entry.record).unwrap(), 1)
				])
			);
			assert!(borrowed.stamp == entry.stamp);
		}
		let borrowed: ColdEntry<'_> = serde_json::from_str(&plain).unwrap();
		assert!(matches!(
			borrowed.record.request_id,
			std::borrow::Cow::Borrowed(_)
		));
		assert!(matches!(
			borrowed.record.owner,
			std::borrow::Cow::Borrowed(_)
		));
		assert!(matches!(
			borrowed.record.tool_name,
			std::borrow::Cow::Borrowed(_)
		));
	}
}

#[test]
fn borrowed_cold_rows_keep_strict_unknown_and_elapsed_field_validation() {
	let entry = Entry {
		record: Record {
			request_id: "0".repeat(64),
			owner: "a".repeat(64),
			tool_name: "host_list".into(),
			state: DurableState::Completed,
			accepted_unix_ms: 123,
			elapsed_ms: None,
		},
		stamp: FileStamp {
			device: 1,
			inode: 2,
			mode: 0o100600,
			uid: 1000,
			links: 1,
			length: 11,
			modified: (1, 2),
			changed: (3, 4),
		},
	};
	let raw = serde_json::to_string(&entry).unwrap();
	let bad = raw.replace("\"elapsed_ms\":null", "\"elapsed_ms\":\"bad\"");
	assert!(serde_json::from_str::<ColdEntry<'_>>(&bad).is_err());
	let bad = raw.replacen("{", "{\"unexpected\":1,", 1);
	assert!(serde_json::from_str::<ColdEntry<'_>>(&bad).is_err());
}

#[test]
fn directory_original_coverage_refuses_a_missing_indexed_id_even_with_an_extra_original() {
	let (root, slot, db, entry) = fixture();
	let old_path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", entry.record.request_id));
	let old_bytes = std::fs::read(&old_path).unwrap();
	let mut changed: serde_json::Value = serde_json::from_slice(&old_bytes).unwrap();
	let other = if entry.record.request_id != "f".repeat(64) {
		"f".repeat(64)
	} else {
		"e".repeat(64)
	};
	changed["request_id"] = serde_json::Value::String(other.clone());
	let path = root.path().join(ARCHIVE_NAME).join(format!("{other}.json"));
	let bytes = serde_json::to_vec(&changed).unwrap();
	std::fs::write(&path, &bytes).unwrap();
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	}
	std::fs::remove_file(old_path).unwrap();
	slot.state.lock().unwrap().version = content_version(&slot.archive).unwrap();
	assert_eq!(
		slot.archive
			.read_record(&format!("{other}.json"))
			.unwrap()
			.request_id,
		other
	);
	let read = db.begin_read().unwrap();
	let rows = read.open_table(ROWS).unwrap();
	let order = read.open_table(ORDER).unwrap();
	let ids = read.open_table(IDS).unwrap();

	let error = cold_rows(
		&db,
		&slot,
		&rows,
		&order,
		&ids,
		ScanPlan::new(Instant::now() + Duration::from_secs(5), None, None),
		|_| Ok(true),
	)
	.err()
	.unwrap();
	assert!(
		error
			.to_string()
			.contains("original identity coverage changed"),
		"{error:#}"
	);
	assert_eq!(std::fs::read(path).unwrap(), bytes);
}

#[test]
fn order_range_partitions_check_malformed_keys_outside_sampled_receipt_bounds() {
	for malformed in [Vec::new(), vec![255u8; 81]] {
		let (_root, slot, db, entry) = fixture();
		let write = db.begin_write().unwrap();
		{
			let mut rows = write.open_table(ROWS).unwrap();
			for number in 0..64u64 {
				let mut other = entry.clone();
				other.record.request_id = format!("{number:064x}");
				rows.insert(
					id(&other.record.request_id).unwrap().as_slice(),
					codec::encode(&other).unwrap().as_slice(),
				)
				.unwrap();
			}
			write
				.open_table(ORDER)
				.unwrap()
				.insert(
					malformed.as_slice(),
					order_value(&entry).unwrap().as_slice(),
				)
				.unwrap();
		}
		write.commit().unwrap();
		let read = db.begin_read().unwrap();
		let rows = read.open_table(ROWS).unwrap();
		let order = read.open_table(ORDER).unwrap();
		let ids = read.open_table(IDS).unwrap();

		assert!(
			order_boundaries(&rows, Instant::now() + Duration::from_secs(5))
				.unwrap()
				.len() > 1
		);
		assert!(table_rows(
			&db,
			&slot,
			&rows,
			&order,
			&ids,
			ScanPlan::new(Instant::now() + Duration::from_secs(5), None, None),
			|_| Ok(true),
		)
		.is_err());
	}
}

#[test]
fn all_order_ranges_and_multiple_inode_cohorts_check_original_permissions_after_success() {
	use std::os::unix::fs::PermissionsExt;
	let (root, slot, db, entry) = fixture();
	// The global test registry may evict an otherwise idle frozen slot while
	// another test opens unrelated archives. Keep this standalone cold fixture pinned.
	let _pin = slot.clone();
	let original_path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", entry.record.request_id));
	let bytes = std::fs::read(&original_path).unwrap();
	let template: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
	let mut entries = Vec::new();
	for number in 0..1024u64 {
		let mut other = entry.clone();
		other.record.request_id = format!("{number:064x}");
		let filename = format!("{}.json", other.record.request_id);
		let path = root.path().join(ARCHIVE_NAME).join(&filename);
		let mut value = template.clone();
		value["request_id"] = serde_json::Value::String(other.record.request_id.clone());
		std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
		other.stamp = stamp(&slot.archive, &filename).unwrap();
		entries.push(other);
	}
	apply(&db, entries, None, false).unwrap();
	slot.state.lock().unwrap().version = content_version(&slot.archive).unwrap();
	let read = db.begin_read().unwrap();
	let rows = read.open_table(ROWS).unwrap();
	let order = read.open_table(ORDER).unwrap();
	let ids = read.open_table(IDS).unwrap();

	let deadline = Instant::now() + Duration::from_secs(5);
	assert_eq!(
		order_boundaries(&rows, deadline).unwrap().len(),
		ORDER_WORKERS - 1
	);
	table_rows(
		&db,
		&slot,
		&rows,
		&order,
		&ids,
		ScanPlan::new(deadline, None, None),
		|_| Ok(true),
	)
	.unwrap();
	std::fs::set_permissions(&original_path, std::fs::Permissions::from_mode(0o644)).unwrap();
	slot.state.lock().unwrap().version = content_version(&slot.archive).unwrap();
	let error = table_rows(
		&db,
		&slot,
		&rows,
		&order,
		&ids,
		ScanPlan::new(Instant::now() + Duration::from_secs(5), None, None),
		|_| Ok(true),
	)
	.err()
	.unwrap();
	assert!(format!("{error:#}").contains("unsafe archive index member"));
	assert_eq!(std::fs::read(original_path).unwrap(), bytes);
}
