// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Sustained or interrupted event streams must retire tokens within fixed work.
use super::*;

fn event_bytes(wd: i32) -> Vec<u8> {
	let mut bytes = Vec::new();
	bytes.extend_from_slice(&wd.to_ne_bytes());
	bytes.extend_from_slice(&libc::IN_ATTRIB.to_ne_bytes());
	bytes.extend_from_slice(&0u32.to_ne_bytes());
	bytes.extend_from_slice(&0u32.to_ne_bytes());
	assert_eq!(bytes.len(), std::mem::size_of::<libc::inotify_event>());
	bytes
}

#[test]
fn interrupted_reads_exhaust_the_same_finite_attempt_budget() {
	let mut watcher = Watcher::new(1).unwrap();
	let mut reads = 0;
	let error = watcher
		.drain_with_reader(|_, _| {
			reads += 1;
			Err(std::io::ErrorKind::Interrupted.into())
		})
		.unwrap_err();
	assert_eq!(reads, MAX_DRAIN_READS);
	assert!(error.to_string().contains("drain budget exhausted"));
}

#[test]
fn continuous_nonempty_reads_cannot_exceed_the_read_budget() {
	let mut watcher = Watcher::new(1).unwrap();
	let event = event_bytes(1);
	let mut reads = 0;
	let error = watcher
		.drain_with_reader(|_, buffer| {
			reads += 1;
			buffer[..event.len()].copy_from_slice(&event);
			Ok(event.len())
		})
		.unwrap_err();
	assert_eq!(reads, MAX_DRAIN_READS);
	assert_eq!(watcher.next, MAX_DRAIN_READS as u64);
	assert!(error.to_string().contains("drain budget exhausted"));
}

#[test]
fn dense_reads_stop_at_the_event_budget_without_processing_the_tail() {
	let mut watcher = Watcher::new(1).unwrap();
	let event = event_bytes(1);
	let per_read = (16 * 1024) / event.len();
	let mut reads = 0;
	let error = watcher
		.drain_with_reader(|_, buffer| {
			reads += 1;
			for slot in buffer.chunks_exact_mut(event.len()) {
				slot.copy_from_slice(&event);
			}
			Ok(per_read * event.len())
		})
		.unwrap_err();
	assert!(reads < MAX_DRAIN_READS);
	assert_eq!(watcher.next, MAX_DRAIN_EVENTS as u64);
	assert!(error.to_string().contains("drain budget exhausted"));
}

#[test]
fn a_finite_stream_can_confirm_empty_on_the_last_read_attempt() {
	let mut watcher = Watcher::new(1).unwrap();
	let event = event_bytes(1);
	let mut reads = 0;
	watcher
		.drain_with_reader(|_, buffer| {
			reads += 1;
			if reads == MAX_DRAIN_READS {
				return Err(std::io::ErrorKind::WouldBlock.into());
			}
			buffer[..event.len()].copy_from_slice(&event);
			Ok(event.len())
		})
		.unwrap();
	assert_eq!(reads, MAX_DRAIN_READS);
	assert_eq!(watcher.next, (MAX_DRAIN_READS - 1) as u64);
}

#[test]
fn exhausted_version_read_retires_every_token_then_rearms_new_identities() {
	for interrupted in [false, true] {
		let roots: Vec<_> = (0..2).map(|_| tempfile::tempdir().unwrap()).collect();
		let directories: Vec<_> = roots
			.iter()
			.map(|root| File::open(root.path()).unwrap())
			.collect();
		let mut watcher = Watcher::new(2).unwrap();
		watcher.content = true;
		let original: Vec<_> = directories
			.iter()
			.map(|directory| watcher.version(directory).unwrap())
			.collect();
		let event = event_bytes(watcher.watches[0].wd);
		let error = watcher
			.version_with_reader(&directories[0], None, |_, buffer| {
				if interrupted {
					Err(std::io::ErrorKind::Interrupted.into())
				} else {
					buffer[..event.len()].copy_from_slice(&event);
					Ok(event.len())
				}
			})
			.unwrap_err();
		assert!(error.to_string().contains("drain budget exhausted"));
		assert!(watcher.watches.iter().all(|watch| watch.dead));
		for (directory, old) in directories.iter().zip(original) {
			let current = watcher.version(directory).unwrap();
			assert_ne!(current, old);
			assert_eq!(watcher.version(directory).unwrap(), current);
			match (old, current) {
				(Version::Watch(old, _), Version::Watch(current, _)) => assert_ne!(old, current),
				_ => panic!("fixture must retain watch tokens"),
			}
		}
		assert_eq!(watcher.watches.len(), 2);
		assert!(watcher.watches.iter().all(|watch| !watch.dead));
	}
}
