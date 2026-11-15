// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Stream hashes, bounded multilevel merging, exact joins and anonymous cleanup.
use super::*;

fn image(number: u64, stamp: FileStamp) -> Image {
	let mut identity = [0; 32];
	identity[24..].copy_from_slice(&number.to_be_bytes());
	order_image(&identity, stamp)
}
fn one(slot: &Slot, images: impl IntoIterator<Item = Image>) -> Spool {
	let mut writer = Writer::new(&slot.root).unwrap();
	writer.begin().unwrap();
	for image in images {
		writer.push(image).unwrap();
	}
	writer.finish().unwrap()
}

#[test]
fn anonymous_run_preserves_every_byte_and_leaves_no_namespace_inventory() {
	let (root, slot, _db, entry) = super::super::tests::fixture();
	let _pin = slot.clone();
	let names = || {
		let mut names = std::fs::read_dir(root.path())
			.unwrap()
			.map(|e| e.unwrap().file_name())
			.collect::<Vec<_>>();
		names.sort();
		names
	};
	let before = names();
	{
		let spool = one(&slot, [image(1, entry.stamp), image(2, entry.stamp)]);
		let mut run = spool.one().unwrap();
		assert_eq!(run.next().unwrap(), Some(image(1, entry.stamp)));
		assert_eq!(run.next().unwrap(), Some(image(2, entry.stamp)));
		assert!(run.next().unwrap().is_none());
		assert_eq!(spool.file.metadata().unwrap().nlink(), 0);
	}
	assert_eq!(names(), before);
}

#[test]
fn complete_stream_crosses_multiple_large_read_buffers_and_partial_tail() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	let count = READ_ROWS * 3 + 1;
	let spool = one(
		&slot,
		(0..count).map(|number| image(number as u64, entry.stamp)),
	);
	let mut run = spool.one().unwrap();
	for number in 0..count {
		assert_eq!(run.next().unwrap(), Some(image(number as u64, entry.stamp)));
	}
	assert!(run.next().unwrap().is_none());
}

#[test]
fn large_run_seals_its_header_after_multiple_payload_writebacks() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	let count = (WRITEBACK_BYTES as usize * 2 / VALUE_BYTES) + READ_ROWS + 1;
	let spool = one(
		&slot,
		(0..count).map(|number| image(number as u64, entry.stamp)),
	);
	assert_eq!(spool.rows, count as u64);
	let mut run = spool.one().unwrap();
	for number in 0..count {
		assert_eq!(run.next().unwrap(), Some(image(number as u64, entry.stamp)));
	}
	assert!(run.next().unwrap().is_none());
	assert!(private(&spool.file, spool.length).unwrap() == spool.stamp);
}

#[test]
fn multiple_changed_original_cohorts_drain_a_single_message_queue_and_join() {
	exercise_changed_cohorts(false);
}

#[test]
fn inode_stream_rechecks_every_changed_cohort_and_joins_its_workers() {
	exercise_changed_cohorts(true);
}

fn exercise_changed_cohorts(physical: bool) {
	use std::os::unix::fs::PermissionsExt;
	let (root, slot, db, entry) = super::super::tests::fixture();
	let _pin = slot.clone();
	let count = BUILD_CHUNK * 2 + 1;
	let mut old = Vec::new();
	let mut observed = Vec::new();
	let mut entries = Vec::new();
	let mut paths = Vec::new();
	let template_path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", entry.record.request_id));
	let template: serde_json::Value =
		serde_json::from_slice(&std::fs::read(template_path).unwrap()).unwrap();
	for number in 0..count {
		let request = if physical {
			format!("{:02x}{number:062x}", (number % COLD_ROW_WORKERS) * 64)
		} else {
			format!("{number:064x}")
		};
		let filename = format!("{request}.json");
		let path = root.path().join(ARCHIVE_NAME).join(&filename);
		let mut value = template.clone();
		value["request_id"] = serde_json::Value::String(request.clone());
		let bytes = serde_json::to_vec(&value).unwrap();
		std::fs::write(&path, &bytes).unwrap();
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
		let identity = id(&request).unwrap();
		let prior = stamp(&slot.archive, &filename).unwrap();
		old.push(order_image(&identity, prior));
		let mut cached = entry.clone();
		cached.record.request_id = request;
		cached.stamp = prior;
		entries.push(cached);
		let replacement = root.path().join("cohort-replacement");
		std::fs::write(&replacement, &bytes).unwrap();
		std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
		std::fs::rename(replacement, &path).unwrap();
		let actual = stamp(&slot.archive, &filename).unwrap();
		assert_ne!(actual.inode, prior.inode);
		observed.push(order_image(&identity, actual));
		paths.push((path, bytes));
	}
	apply(&db, entries, None, false).unwrap();
	slot.state.lock().unwrap().version = content_version(&slot.archive).unwrap();
	let expected = if physical {
		let mut writers: Vec<_> = (0..COLD_ROW_WORKERS)
			.map(|_| Expected::new(&slot.root).unwrap())
			.collect();
		for image in old {
			writers[image[0] as usize * COLD_ROW_WORKERS / 256]
				.push(image)
				.unwrap();
		}
		let sources = writers
			.into_iter()
			.enumerate()
			.map(|(part, writer)| (part, writer.finish().unwrap()))
			.collect();
		reduce_sources(
			&slot,
			sources,
			Instant::now() + Duration::from_secs(10),
			&AtomicBool::new(false),
		)
		.unwrap()
	} else {
		vec![one(&slot, old)]
	};
	let actual = if physical {
		one(&slot, [])
	} else {
		one(&slot, observed)
	};
	let pool = rayon::ThreadPoolBuilder::new()
		.num_threads(STAT_WORKERS)
		.build()
		.unwrap();
	let deadline = Instant::now() + Duration::from_secs(15);
	let cancellation = AtomicBool::new(false);
	let mut batches = Vec::new();
	let mut repaired = std::collections::BTreeSet::new();
	std::thread::scope(|scope| {
		let (send, receive) = std::sync::mpsc::sync_channel(1);
		let slot = &slot;
		let cancellation = &cancellation;
		scope.spawn(move || {
			let result = if physical {
				check_sources(slot, &expected, &pool, deadline, cancellation, &send)
			} else {
				join(slot, &expected[0], &actual, deadline, cancellation, &send)
			};
			send.send(match result {
				Ok(()) => Message::OriginalDone(None),
				Err(e) => Message::Failed(e),
			})
			.unwrap();
		});
		loop {
			match receive.recv_timeout(Duration::from_secs(15)).unwrap() {
				Message::Changes(entries) => {
					batches.push(entries.len());
					for entry in &entries {
						assert!(repaired.insert(entry.record.request_id.clone()));
						assert!(
							entry.stamp
								== stamp(
									&slot.archive,
									&format!("{}.json", entry.record.request_id)
								)
								.unwrap()
						);
					}
					apply(&db, entries, None, false).unwrap();
				}
				Message::OriginalDone(_) => break,
				Message::Failed(e) => panic!("{e:#}"),
				_ => panic!("unexpected comparison result"),
			}
		}
	});
	assert_eq!(batches, [BUILD_CHUNK, BUILD_CHUNK, 1]);
	assert_eq!(repaired.len(), count);
	assert!(slot.state.try_lock().is_ok());
	for (path, bytes) in paths {
		assert_eq!(std::fs::read(path).unwrap(), bytes);
	}
}

#[test]
fn fan_in_merges_more_than_two_levels_with_fixed_reader_cohorts() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	let _pin = slot.clone();
	let mut sorter = Sorter::new(&slot.root).unwrap();
	let count = (FAN_IN * FAN_IN + 1) * 3;
	for number in (0..count).rev() {
		sorter.push(image(number as u64, entry.stamp)).unwrap();
		if number % 3 == 0 {
			sorter.flush().unwrap();
		}
	}
	let spool = sorter.finish().unwrap();
	assert!(spool.runs > FAN_IN as u64 * FAN_IN as u64);
	let spool = spool
		.sorted(
			&slot.root,
			Instant::now() + Duration::from_secs(5),
			&AtomicBool::new(false),
		)
		.unwrap();
	assert_eq!(spool.runs, 1);
	assert_eq!(spool.rows, count as u64);
	let mut run = spool.one().unwrap();
	for number in 0..count {
		assert_eq!(run.next().unwrap(), Some(image(number as u64, entry.stamp)));
	}
	assert!(run.next().unwrap().is_none());
}

#[test]
fn stream_payload_corruption_is_rejected_even_with_a_fresh_inode_stamp() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	let mut spool = one(&slot, [image(1, entry.stamp)]);
	let mut corrupt = image(1, entry.stamp);
	corrupt[103] ^= 1;
	spool.file.write_all_at(&corrupt, HEADER as u64).unwrap();
	spool.stamp = private(&spool.file, spool.length).unwrap();
	let mut run = spool.one().unwrap();
	assert!(run.next().unwrap().is_some());
	assert!(run.next().is_err());
}

#[test]
fn forged_header_overflow_truncation_and_permissions_never_become_records() {
	use std::os::unix::fs::PermissionsExt;
	for mutation in 0..4 {
		let (_root, slot, _db, entry) = super::super::tests::fixture();
		let mut spool = one(&slot, [image(1, entry.stamp)]);
		match mutation {
			0 => {
				spool.file.write_all_at(&u64::MAX.to_be_bytes(), 0).unwrap();
				spool.stamp = private(&spool.file, spool.length).unwrap();
			}
			1 => {
				spool.file.write_all_at(&[255; 32], 8).unwrap();
				spool.stamp = private(&spool.file, spool.length).unwrap();
			}
			2 => spool.file.set_len(spool.length - 1).unwrap(),
			_ => spool
				.file
				.set_permissions(std::fs::Permissions::from_mode(0o644))
				.unwrap(),
		}
		assert!(spool.one().is_err());
	}
}

#[test]
fn duplicate_identities_across_individually_valid_runs_are_rejected() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	let mut sorter = Sorter::new(&slot.root).unwrap();
	for _ in 0..2 {
		sorter.push(image(1, entry.stamp)).unwrap();
		sorter.flush().unwrap();
	}
	assert!(sorter
		.finish()
		.unwrap()
		.sorted(
			&slot.root,
			Instant::now() + Duration::from_secs(5),
			&AtomicBool::new(false)
		)
		.is_err());
}

#[test]
fn exact_stamp_join_reads_replaced_original_without_rewriting_its_bytes() {
	use std::os::unix::fs::PermissionsExt;
	let (root, slot, _db, entry) = super::super::tests::fixture();
	let _pin = slot.clone();
	let identity = id(&entry.record.request_id).unwrap();
	let path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", entry.record.request_id));
	let original = std::fs::read(&path).unwrap();
	let replacement = root.path().join("run-replacement");
	std::fs::write(&replacement, &original).unwrap();
	std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
	std::fs::rename(replacement, &path).unwrap();
	slot.state.lock().unwrap().version = content_version(&slot.archive).unwrap();
	let actual = stamp(&slot.archive, &format!("{}.json", entry.record.request_id)).unwrap();
	assert_ne!(actual.inode, entry.stamp.inode);
	let expected = one(&slot, [order_image(&identity, entry.stamp)]);
	let observed = one(&slot, [order_image(&identity, actual)]);
	let (send, receive) = std::sync::mpsc::sync_channel(1);
	join(
		&slot,
		&expected,
		&observed,
		Instant::now() + Duration::from_secs(5),
		&AtomicBool::new(false),
		&send,
	)
	.unwrap();
	match receive.recv().unwrap() {
		Message::Changes(entries) => {
			assert_eq!(entries.len(), 1);
			assert!(entries[0].stamp == actual);
		}
		_ => panic!("missing original repair"),
	}
	assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn missing_original_identity_is_refused_and_an_unindexed_tail_is_checked() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	let _pin = slot.clone();
	let identity = id(&entry.record.request_id).unwrap();
	let present = one(&slot, [order_image(&identity, entry.stamp)]);
	let empty = one(&slot, []);
	let (send, receive) = std::sync::mpsc::sync_channel(1);
	let deadline = Instant::now() + Duration::from_secs(5);
	let cancelled = AtomicBool::new(false);
	assert!(join(&slot, &present, &empty, deadline, &cancelled, &send).is_err());
	assert!(receive.try_recv().is_err());
	join(&slot, &empty, &present, deadline, &cancelled, &send).unwrap();
	match receive.recv().unwrap() {
		Message::Changes(entries) => {
			assert_eq!(entries[0].record.request_id, entry.record.request_id)
		}
		_ => panic!("missing checked tail"),
	}
}

#[test]
fn empty_streams_expired_deadlines_and_cancellation_are_bounded() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	let empty = one(&slot, []);
	let (send, _receive) = std::sync::mpsc::sync_channel(1);
	join(
		&slot,
		&empty,
		&empty,
		Instant::now() + Duration::from_secs(5),
		&AtomicBool::new(false),
		&send,
	)
	.unwrap();
	for cancelled in [false, true] {
		let mut sorter = Sorter::new(&slot.root).unwrap();
		for number in [1, 0] {
			sorter.push(image(number, entry.stamp)).unwrap();
			sorter.flush().unwrap();
		}
		let deadline = if cancelled {
			Instant::now() + Duration::from_secs(5)
		} else {
			Instant::now() - Duration::from_secs(1)
		};
		assert!(sorter
			.finish()
			.unwrap()
			.sorted(&slot.root, deadline, &AtomicBool::new(cancelled))
			.is_err());
	}
}

#[test]
fn directory_observation_checks_all_original_permissions_with_bounded_names() {
	use std::os::unix::fs::PermissionsExt;
	let (root, slot, _db, entry) = super::super::tests::fixture();
	let _pin = slot.clone();
	let before = observe_legacy_test_sources(
		&slot,
		Instant::now() + Duration::from_secs(5),
		&AtomicBool::new(false),
	)
	.unwrap();
	assert_eq!(before.len(), COLD_ROW_WORKERS);
	let path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", entry.record.request_id));
	let original = std::fs::read(&path).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	assert!(observe_legacy_test_sources(
		&slot,
		Instant::now() + Duration::from_secs(5),
		&AtomicBool::new(false)
	)
	.is_err());
	assert_eq!(std::fs::read(path).unwrap(), original);
}

#[test]
fn physical_merge_preserves_all_ids_and_stamp_bytes_across_multiple_levels() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	let mut sorter = Sorter::with_order(&slot.root, SortOrder::Inode).unwrap();
	let count = (FAN_IN * FAN_IN + 1) * 5;
	let mut expected = Vec::new();
	for n in (0..count).rev() {
		let mut stamp = entry.stamp;
		stamp.device = u64::MAX - (n % 3) as u64;
		stamp.inode = u64::MAX - (n % 113) as u64;
		stamp.changed = (n as i64, n as i64 * 23);
		let value = image(n as u64, stamp);
		expected.push(value);
		sorter.push(value).unwrap();
		if n % 5 == 0 {
			sorter.flush().unwrap();
		}
	}
	let spool = sorter.finish().unwrap();
	assert!(spool.runs > (FAN_IN * FAN_IN) as u64);
	let spool = spool
		.sorted(
			&slot.root,
			Instant::now() + Duration::from_secs(10),
			&AtomicBool::new(false),
		)
		.unwrap();
	expected.sort_unstable_by_key(|raw| {
		let stamp = decode_stamp(&raw[32..]).unwrap();
		(
			stamp.device,
			stamp.inode,
			<Id>::try_from(&raw[..32]).unwrap(),
		)
	});
	let mut run = spool.one().unwrap();
	for value in expected {
		assert_eq!(run.next().unwrap(), Some(value));
	}
	assert!(run.next().unwrap().is_none());
}

#[test]
fn physical_checker_rejects_missing_original_and_identity_order_substitution() {
	for wrong_order in [false, true] {
		let (root, slot, _db, entry) = super::super::tests::fixture();
		let path = root
			.path()
			.join(ARCHIVE_NAME)
			.join(format!("{}.json", entry.record.request_id));
		let before = std::fs::read(&path).unwrap();
		let identity = if wrong_order {
			id(&entry.record.request_id).unwrap()
		} else {
			[255; 32]
		};
		let spool = if wrong_order {
			one(&slot, [order_image(&identity, entry.stamp)])
		} else {
			let mut writer = Expected::new(&slot.root).unwrap();
			writer.push(order_image(&identity, entry.stamp)).unwrap();
			writer.finish().unwrap()
		};
		let pool = rayon::ThreadPoolBuilder::new()
			.num_threads(STAT_WORKERS)
			.build()
			.unwrap();
		let (send, _receive) = std::sync::mpsc::sync_channel(1);
		assert!(check_expected(
			&slot,
			&spool,
			&pool,
			Instant::now() + Duration::from_secs(5),
			&AtomicBool::new(false),
			&send
		)
		.is_err());
		assert_eq!(std::fs::read(path).unwrap(), before);
	}
}

#[test]
fn physical_stream_payload_corruption_never_survives_the_complete_digest() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	let identity = id(&entry.record.request_id).unwrap();
	let mut writer = Expected::new(&slot.root).unwrap();
	writer.push(order_image(&identity, entry.stamp)).unwrap();
	let mut spool = writer.finish().unwrap();
	let mut corrupt = order_image(&identity, entry.stamp);
	corrupt[103] ^= 1;
	spool.file.write_all_at(&corrupt, HEADER as u64).unwrap();
	spool.stamp = private(&spool.file, spool.length).unwrap();
	let mut run = spool.one().unwrap();
	assert!(run.next().unwrap().is_some());
	assert!(run.next().is_err());
}

fn physical_spool(slot: &Slot, images: impl IntoIterator<Item = Image>, run_rows: usize) -> Spool {
	let mut sorter = Sorter::with_order(&slot.root, SortOrder::Inode).unwrap();
	for (number, image) in images.into_iter().enumerate() {
		sorter.push(image).unwrap();
		if (number + 1).is_multiple_of(run_rows) {
			sorter.flush().unwrap();
		}
	}
	sorter.finish().unwrap()
}

#[test]
fn terminal_merge_reduces_multiple_generations_then_visits_all_partitions_in_global_inode_order() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	let deadline = Instant::now() + Duration::from_secs(15);
	let cancelled = AtomicBool::new(false);
	let count = (FAN_IN * FAN_IN + 1) * 3;
	let mut expected = Vec::new();
	let sources = (0..COLD_ROW_WORKERS)
		.map(|part| {
			let images: Vec<_> = (0..count)
				.rev()
				.map(|number| {
					let mut stamp = entry.stamp;
					stamp.device = (number % 3) as u64 + 1;
					stamp.inode = ((number * 7 + part) % 113) as u64;
					stamp.changed = (number as i64, (part * count + number) as i64);
					image((number * COLD_ROW_WORKERS + part) as u64, stamp)
				})
				.collect();
			expected.extend_from_slice(&images);
			let source = physical_spool(&slot, images, 3);
			assert!(source.runs > (FAN_IN * FAN_IN) as u64);
			(part, source)
		})
		.collect();
	let reduced = reduce_sources(&slot, sources, deadline, &cancelled).unwrap();
	assert_eq!(reduced.len(), COLD_ROW_WORKERS);
	assert!(reduced
		.iter()
		.all(|source| source.runs > 1 && source.runs <= FAN_IN as u64));
	let snapshots: Vec<_> = reduced
		.iter()
		.map(|source| (source.stamp, source.length))
		.collect();
	expected.sort_unstable_by_key(|raw| {
		let stamp = decode_stamp(&raw[32..]).unwrap();
		(
			stamp.device,
			stamp.inode,
			<Id>::try_from(&raw[..32]).unwrap(),
		)
	});
	let mut merged = TerminalMerge::new(&reduced, deadline, &cancelled).unwrap();
	let mut actual = Vec::new();
	while let Some(image) = merged.next(deadline, &cancelled).unwrap() {
		actual.push(image);
	}
	assert!(merged.complete);
	assert_eq!(merged.emitted, expected.len() as u64);
	assert_eq!(actual, expected);
	for (source, (stamp, length)) in reduced.iter().zip(snapshots) {
		assert!(private(&source.file, length).unwrap() == stamp);
		assert_eq!(source.file.metadata().unwrap().nlink(), 0);
		assert!(source.runs > 1);
	}
}

#[test]
fn terminal_stream_uses_the_existing_64_reader_bound_without_writing_another_spool() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	let deadline = Instant::now() + Duration::from_secs(5);
	let cancelled = AtomicBool::new(false);
	let sources: Vec<_> = (0..COLD_ROW_WORKERS)
		.map(|part| {
			physical_spool(
				&slot,
				(0..FAN_IN)
					.map(|number| image((number * COLD_ROW_WORKERS + part) as u64, entry.stamp)),
				1,
			)
		})
		.collect();
	let mut merged = TerminalMerge::new(&sources, deadline, &cancelled).unwrap();
	assert_eq!(merged.readers.len(), TERMINAL_READERS);
	for number in 0..TERMINAL_READERS {
		assert_eq!(
			merged.next(deadline, &cancelled).unwrap(),
			Some(image(number as u64, entry.stamp))
		);
	}
	assert!(merged.next(deadline, &cancelled).unwrap().is_none());
	assert!(sources.iter().all(|source| source.runs == FAN_IN as u64
		&& private(&source.file, source.length).unwrap() == source.stamp));
}

#[test]
fn terminal_merge_rejects_duplicates_in_one_partition_and_between_partitions() {
	for partitions in [1, 2] {
		let (_root, slot, _db, entry) = super::super::tests::fixture();
		let deadline = Instant::now() + Duration::from_secs(5);
		let cancelled = AtomicBool::new(false);
		let sources = if partitions == 1 {
			vec![physical_spool(&slot, [image(1, entry.stamp); 2], 1)]
		} else {
			(0..partitions)
				.map(|_| physical_spool(&slot, [image(1, entry.stamp)], 1))
				.collect()
		};
		let mut merged = TerminalMerge::new(&sources, deadline, &cancelled).unwrap();
		assert!(merged.next(deadline, &cancelled).unwrap().is_some());
		assert!(merged.next(deadline, &cancelled).is_err());
	}
}

#[test]
fn terminal_stream_validates_the_last_payload_byte_before_accepting_complete_coverage() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	let deadline = Instant::now() + Duration::from_secs(5);
	let cancelled = AtomicBool::new(false);
	let count = READ_ROWS + 1;
	let mut source = physical_spool(
		&slot,
		(0..count).map(|n| image(n as u64, entry.stamp)),
		count,
	);
	let mut corrupt = image((count - 1) as u64, entry.stamp);
	corrupt[103] ^= 1;
	source
		.file
		.write_all_at(&corrupt, HEADER as u64 + ((count - 1) * VALUE_BYTES) as u64)
		.unwrap();
	source.stamp = private(&source.file, source.length).unwrap();
	let sources = [source];
	let mut merged = TerminalMerge::new(&sources, deadline, &cancelled).unwrap();
	for n in 0..count - 1 {
		assert_eq!(
			merged.next(deadline, &cancelled).unwrap(),
			Some(image(n as u64, entry.stamp))
		);
	}
	assert!(merged.next(deadline, &cancelled).is_err());
	assert!(!merged.complete);
}

#[test]
fn terminal_stream_refuses_forged_header_counts_run_inventory_and_truncation() {
	for mutation in 0..5 {
		let (_root, slot, _db, entry) = super::super::tests::fixture();
		let deadline = Instant::now() + Duration::from_secs(5);
		let cancelled = AtomicBool::new(false);
		let mut source = physical_spool(&slot, [image(1, entry.stamp), image(2, entry.stamp)], 1);
		match mutation {
			0 => source.rows += 1,
			1 => source.runs += 1,
			2 => source.headers[31] ^= 1,
			3 => source.file.set_len(source.length - 1).unwrap(),
			_ => {
				source
					.file
					.write_all_at(&u64::MAX.to_be_bytes(), 0)
					.unwrap();
				source.stamp = private(&source.file, source.length).unwrap();
			}
		}
		assert!(TerminalMerge::new(&[source], deadline, &cancelled).is_err());
	}
}

#[test]
fn terminal_stream_rejects_unreduced_or_excess_partitions_before_allocating_readers() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	let deadline = Instant::now() + Duration::from_secs(5);
	let cancelled = AtomicBool::new(false);
	assert!(TerminalMerge::new(&[], deadline, &cancelled).is_err());
	let sources: Vec<_> = (0..=COLD_ROW_WORKERS)
		.map(|_| physical_spool(&slot, [], 1))
		.collect();
	assert!(TerminalMerge::new(&sources, deadline, &cancelled).is_err());
	let unreduced = physical_spool(&slot, (0..=FAN_IN).map(|n| image(n as u64, entry.stamp)), 1);
	assert!(TerminalMerge::new(&[unreduced], deadline, &cancelled).is_err());
}

#[test]
fn terminal_eof_rechecks_an_input_that_finished_before_the_other_partitions() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	let deadline = Instant::now() + Duration::from_secs(5);
	let cancelled = AtomicBool::new(false);
	let sources = [
		physical_spool(&slot, [image(1, entry.stamp)], 1),
		physical_spool(&slot, [image(2, entry.stamp)], 1),
	];
	let mut merged = TerminalMerge::new(&sources, deadline, &cancelled).unwrap();
	assert_eq!(
		merged.next(deadline, &cancelled).unwrap(),
		Some(image(1, entry.stamp))
	);
	let mut corrupt = image(1, entry.stamp);
	corrupt[103] ^= 1;
	sources[0]
		.file
		.write_all_at(&corrupt, HEADER as u64)
		.unwrap();
	// The first input is already consumed and hashed. Make its metadata change
	// observable so the terminal stamp recheck does not depend on clock granularity.
	let modified = sources[0].file.metadata().unwrap().modified().unwrap();
	sources[0]
		.file
		.set_modified(modified + Duration::from_secs(1))
		.unwrap();
	assert!(private(&sources[0].file, sources[0].length).unwrap() != sources[0].stamp);
	assert_eq!(
		merged.next(deadline, &cancelled).unwrap(),
		Some(image(2, entry.stamp))
	);
	assert!(merged.next(deadline, &cancelled).is_err());
	assert!(!merged.complete);
}

#[test]
fn global_verification_requires_exactly_the_four_row_partitions_and_checks_every_original() {
	use std::os::unix::fs::PermissionsExt;
	let (root, slot, db, entry) = super::super::tests::fixture();
	let deadline = Instant::now() + Duration::from_secs(10);
	for labels in [vec![], vec![0, 1, 2], vec![0, 1, 1, 3], vec![0, 1, 2, 4]] {
		let sources = labels
			.into_iter()
			.map(|part| (part, physical_spool(&slot, [], 1)))
			.collect();
		assert!(verify(&db, &slot, sources, deadline).is_err());
	}
	let identity = id(&entry.record.request_id).unwrap();
	let partition = identity[0] as usize * COLD_ROW_WORKERS / 256;
	let sources = || {
		(0..COLD_ROW_WORKERS)
			.rev()
			.map(|part| {
				let images = if part == partition {
					vec![order_image(&identity, entry.stamp)]
				} else {
					vec![]
				};
				(part, physical_spool(&slot, images, 1))
			})
			.collect()
	};
	verify(&db, &slot, sources(), deadline).unwrap();
	let path = root
		.path()
		.join(ARCHIVE_NAME)
		.join(format!("{}.json", entry.record.request_id));
	let before = std::fs::read(&path).unwrap();
	let unsafe_sources = sources();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
	assert!(verify(&db, &slot, unsafe_sources, deadline).is_err());
	assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn terminal_cancellation_expiry_and_sort_failure_leave_no_unjoined_spool_workers() {
	let (root, slot, _db, entry) = super::super::tests::fixture();
	let deadline = Instant::now() + Duration::from_secs(10);
	let cancelled = AtomicBool::new(false);
	let sources = [physical_spool(
		&slot,
		[image(1, entry.stamp), image(2, entry.stamp)],
		1,
	)];
	let mut merged = TerminalMerge::new(&sources, deadline, &cancelled).unwrap();
	assert!(merged.next(deadline, &cancelled).unwrap().is_some());
	cancelled.store(true, Ordering::Relaxed);
	assert!(merged.next(deadline, &cancelled).is_err());
	assert!(TerminalMerge::new(&sources, deadline, &cancelled).is_err());
	cancelled.store(false, Ordering::Relaxed);
	assert!(merged
		.next(Instant::now() - Duration::from_secs(1), &cancelled)
		.is_err());
	let namespace = || {
		let mut names: Vec<_> = std::fs::read_dir(root.path())
			.unwrap()
			.map(|item| item.unwrap().file_name())
			.collect();
		names.sort();
		names
	};
	let before = namespace();
	let sorting: Vec<_> = (0..COLD_ROW_WORKERS)
		.map(|part| {
			(
				part,
				physical_spool(
					&slot,
					(0..FAN_IN * FAN_IN + 1)
						.map(|n| image((n * COLD_ROW_WORKERS + part) as u64, entry.stamp)),
					1,
				),
			)
		})
		.collect();
	sorting[2].1.file.set_len(1).unwrap();
	assert!(reduce_sources(&slot, sorting, deadline, &cancelled).is_err());
	assert!(cancelled.load(Ordering::Relaxed));
	assert_eq!(namespace(), before);
	assert!(slot.state.try_lock().is_ok());
}

#[test]
fn buffered_run_hash_keeps_the_wire_digest_and_requires_a_consumed_eof() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	for count in [
		0,
		1,
		READ_ROWS - 1,
		READ_ROWS,
		READ_ROWS + 1,
		READ_ROWS * 3 + 1,
	] {
		let spool = one(&slot, (0..count).map(|n| image(n as u64, entry.stamp)));
		let mut bytes = vec![0; spool.length as usize];
		spool.file.read_exact_at(&mut bytes, 0).unwrap();
		let mut oracle = ring::digest::Context::new(&ring::digest::SHA256);
		oracle.update(b"archive-comparison-records-v1");
		oracle.update(&bytes[HEADER..]);
		assert_eq!(&bytes[8..HEADER], oracle.finish().as_ref());
		let mut run = spool.one().unwrap();
		for number in 0..count {
			assert!(run.hash.is_some());
			assert_eq!(run.next().unwrap(), Some(image(number as u64, entry.stamp)));
		}
		assert_eq!(run.left, 0);
		assert!(run.hash.is_some());
		assert!(run.next().unwrap().is_none());
		assert!(run.hash.is_none());
		assert_eq!(run.position, run.end);
		assert!(run.next().unwrap().is_none());
	}
}

#[test]
fn prefetched_payload_with_a_valid_digest_still_requires_strict_identity_order() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	for duplicate in [false, true] {
		let count = READ_ROWS + 1;
		let mut spool = one(&slot, (0..count).map(|n| image(n as u64, entry.stamp)));
		let replacement = if duplicate { READ_ROWS - 1 } else { 0 };
		spool
			.file
			.write_all_at(
				&image(replacement as u64, entry.stamp),
				(HEADER + READ_ROWS * VALUE_BYTES) as u64,
			)
			.unwrap();
		let mut payload = vec![0; count * VALUE_BYTES];
		spool
			.file
			.read_exact_at(&mut payload, HEADER as u64)
			.unwrap();
		let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
		digest.update(b"archive-comparison-records-v1");
		digest.update(&payload);
		spool
			.file
			.write_all_at(digest.finish().as_ref(), 8)
			.unwrap();
		let mut header = [0; HEADER];
		spool.file.read_exact_at(&mut header, 0).unwrap();
		let mut headers = ring::digest::Context::new(&ring::digest::SHA256);
		headers.update(b"archive-comparison-headers-v1");
		headers.update(&header);
		spool.headers.copy_from_slice(headers.finish().as_ref());
		spool.stamp = private(&spool.file, spool.length).unwrap();
		let mut run = spool.one().unwrap();
		for number in 0..READ_ROWS {
			assert_eq!(run.next().unwrap(), Some(image(number as u64, entry.stamp)));
		}
		let error = run.next().unwrap_err();
		assert!(error
			.to_string()
			.contains("duplicate or unordered identity"));
		assert!(run.hash.is_some());
	}
}

#[test]
fn buffered_terminal_hash_rejects_corruption_on_both_sides_of_a_refill_boundary() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	for count in [READ_ROWS, READ_ROWS + 1] {
		let mut spool = one(&slot, (0..count).map(|n| image(n as u64, entry.stamp)));
		let mut tail = [0];
		spool
			.file
			.read_exact_at(&mut tail, spool.length - 1)
			.unwrap();
		spool
			.file
			.write_all_at(&[tail[0] ^ 1], spool.length - 1)
			.unwrap();
		spool.stamp = private(&spool.file, spool.length).unwrap();
		let sources = [spool];
		let until = Instant::now() + Duration::from_secs(5);
		let cancelled = AtomicBool::new(false);
		let mut merged =
			TerminalMerge::with_order(&sources, until, &cancelled, SortOrder::Identity).unwrap();
		let mut emitted = 0;
		let error = loop {
			match merged.next(until, &cancelled) {
				Ok(Some(_)) => emitted += 1,
				Ok(None) => panic!("corrupt buffered payload was accepted"),
				Err(error) => break error,
			}
		};
		assert!(error.to_string().contains("record digest changed"));
		assert!(emitted < count);
		assert!(!merged.complete);
	}
}

#[test]
fn a_truncated_unread_tail_cannot_be_accepted_from_the_prefetched_buffer() {
	let (_root, slot, _db, entry) = super::super::tests::fixture();
	let count = READ_ROWS + 1;
	let spool = one(&slot, (0..count).map(|n| image(n as u64, entry.stamp)));
	let mut run = spool.one().unwrap();
	for number in 0..READ_ROWS {
		assert_eq!(run.next().unwrap(), Some(image(number as u64, entry.stamp)));
	}
	assert_eq!(run.left, 1);
	spool.file.set_len(spool.length - 1).unwrap();
	assert!(run.next().is_err());
	assert_eq!(run.left, 1);
	assert!(run.hash.is_some());
}
