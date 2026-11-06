// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Contract tests for diagnostic custody only; no SSH/runtime fixture is started.

use super::*;
use std::collections::BTreeSet;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::Barrier;

#[test]
fn concurrent_slot_writers_preserve_every_original_once() {
	let slots = Slots::new(8 * 257);
	let start = Barrier::new(8);
	std::thread::scope(|scope| {
		for worker in 0..8usize {
			let slots = &slots;
			let start = &start;
			scope.spawn(move || {
				start.wait();
				for sample in 0..257usize {
					assert!(slots.push((worker, sample)).is_some());
				}
			});
		}
	});
	let actual = slots.rows.iter().map(|value| *value.get().expect("original row")).collect::<BTreeSet<_>>();
	let expected = (0..8usize).flat_map(|worker| (0..257usize).map(move |sample| (worker, sample))).collect::<BTreeSet<_>>();
	assert_eq!(actual, expected);
	assert_eq!(slots.next.load(Ordering::SeqCst), 2056);
	assert_eq!(slots.dropped.load(Ordering::SeqCst), 0);
}

#[test]
fn exhausted_slots_cannot_replace_retained_original_records() {
	let slots = Slots::new(7);
	for value in 0..3usize {
		assert_eq!(slots.push(value), Some(value));
	}
	let start = Barrier::new(8);
	std::thread::scope(|scope| {
		for worker in 0..8usize {
			let slots = &slots;
			let start = &start;
			scope.spawn(move || {
				start.wait();
				for sample in 0..8usize {
					let _ = slots.push(100 + worker * 8 + sample);
				}
			});
		}
	});
	for value in 0..3usize {
		assert_eq!(slots.rows[value].get(), Some(&value));
	}
	assert_eq!(slots.rows.iter().filter(|value| value.get().is_some()).count(), 7);
	assert_eq!(slots.next.load(Ordering::SeqCst), 67);
	assert_eq!(slots.dropped.load(Ordering::SeqCst), 60);
	assert!(slots.push(999).is_none());
	assert_eq!(slots.dropped.load(Ordering::SeqCst), 61);
}

#[test]
fn diagnostic_output_is_create_only_and_refuses_symlink_parent() {
	let directory = tempfile::tempdir().unwrap();
	std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	let existing = directory.path().join("existing.jsonl");
	std::fs::write(&existing, b"original evidence\n").unwrap();
	std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o600)).unwrap();
	assert!(Output::create(&existing).is_err());
	assert_eq!(std::fs::read(&existing).unwrap(), b"original evidence\n");
	let parent_alias = directory.path().join("alias");
	symlink(directory.path(), &parent_alias).unwrap();
	assert!(Output::create(&parent_alias.join("forbidden.jsonl")).is_err());
	assert!(!directory.path().join("forbidden.jsonl").exists());
	let path = directory.path().join("trace.jsonl");
	let mut output = Output::create(&path).unwrap();
	output.line(&json!({"sentinel": 42})).unwrap();
	output.sync().unwrap();
	drop(output);
	assert_eq!(std::fs::read(&path).unwrap(), b"{\"sentinel\":42}\n");
	assert!(Output::create(&path).is_err());
}

#[test]
fn output_byte_limit_preserves_partial_file_without_truncation_or_retry() {
	use std::io::{Seek, SeekFrom};
	let directory = tempfile::tempdir().unwrap();
	let path = directory.path().join("bounded");
	let mut file = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path).unwrap();
	file.set_len(OUTPUT_LIMIT - 2).unwrap();
	file.seek(SeekFrom::End(0)).unwrap();
	let mut writer = BoundedFile { file, written: OUTPUT_LIMIT - 2 };
	assert_eq!(writer.write(b"x").unwrap(), 1);
	assert!(writer.write(b"yz").is_err());
	assert_eq!(writer.written, OUTPUT_LIMIT - 1);
	drop(writer);
	let mut retained = std::fs::File::open(&path).unwrap();
	assert_eq!(retained.metadata().unwrap().len(), OUTPUT_LIMIT - 1);
	retained.seek(SeekFrom::End(-1)).unwrap();
	let mut last = [0u8; 1];
	retained.read_exact(&mut last).unwrap();
	assert_eq!(last, *b"x");
}

#[test]
fn dropping_an_unflushed_diagnostic_sink_does_not_submit_more_bytes() {
	let directory = tempfile::tempdir().unwrap();
	std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
	let path = directory.path().join("unflushed.jsonl");
	let mut output = Output::create(&path).unwrap();
	output.line(&json!({"buffered": true})).unwrap();
	assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
	drop(output);
	assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
	assert_eq!(std::fs::read(&path).unwrap(), b"");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn context_crosses_only_explicit_task_and_blocking_handoffs() {
	let request = TraceContext(Some(41));
	in_context(request, async {
		assert_eq!(current().0, Some(41));
		tokio::task::yield_now().await;
		assert_eq!(current().0, Some(41));
		let unrelated = tokio::spawn(async { current().0 }).await.unwrap();
		assert_eq!(unrelated, None);
		let handed = current();
		let worker = tokio::task::spawn_blocking(move || {
			assert_eq!(current().0, None);
			let observed = with_context(handed, || current().0);
			assert_eq!(current().0, None);
			observed
		}).await.unwrap();
		assert_eq!(worker, Some(41));
		in_context(TraceContext(Some(99)), async {
			assert_eq!(current().0, Some(99));
		}).await;
		assert_eq!(current().0, Some(41));
	}).await;
	assert_eq!(current().0, None);
}
