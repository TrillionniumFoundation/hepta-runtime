// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Real staged files remain unpublished until persistent jobs drain, also on unwind.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::AtomicUsize;
use std::sync::{mpsc, Condvar};
use std::time::Duration;

fn private_root() -> tempfile::TempDir {
	tempfile::Builder::new()
		.permissions(std::fs::Permissions::from_mode(0o700))
		.tempdir_in(std::env::temp_dir().canonicalize().unwrap())
		.unwrap()
}

fn records(count: usize) -> Vec<Record> {
	(0..count)
		.map(|n| Record {
			request_id: format!("{:064x}", n + 1),
			owner: "a".repeat(64),
			tool_name: "host_list".into(),
			state: DurableState::Unknown,
			accepted_unix_ms: 1000 + n as u128,
			elapsed_ms: None,
		})
		.collect()
}

fn members(path: &Path) -> usize {
	std::fs::read_dir(path).unwrap().count()
}

fn assert_only_temporaries(path: &Path, count: usize) {
	let entries: Vec<_> = std::fs::read_dir(path)
		.unwrap()
		.map(|value| value.unwrap())
		.collect();
	assert_eq!(entries.len(), count);
	assert!(entries
		.iter()
		.all(|entry| entry.file_name().to_str().unwrap().ends_with(".tmp")));
}

fn wait_for_release(gate: &(Mutex<bool>, Condvar)) {
	let mut allowed = gate.0.lock().unwrap();
	while !*allowed {
		allowed = gate.1.wait(allowed).unwrap();
	}
}

fn release(gate: &(Mutex<bool>, Condvar)) {
	*gate.0.lock().unwrap() = true;
	gate.1.notify_all();
}

#[test]
fn one_file_barrier_cohort_spans_directories_and_preserves_exact_failure_slot() {
	let first = private_root();
	let second = private_root();
	let left = File::open(first.path()).unwrap();
	let right = File::open(second.path()).unwrap();
	let records = records(4);
	let writes = [
		(&left, &records[0], false),
		(&right, &records[1], false),
		(&left, &records[2], false),
		(&right, &records[3], false),
	];
	let calls = AtomicUsize::new(0);
	let drained = AtomicUsize::new(0);
	let results = save_many_with_barrier(
		&writes,
		Arc::new(|file| {
			file.sync_all()?;
			Ok(())
		}),
		&|files, operation| {
			calls.fetch_add(1, Ordering::SeqCst);
			assert_eq!(files.len(), 4);
			assert_only_temporaries(first.path(), 2);
			assert_only_temporaries(second.path(), 2);
			files
				.iter()
				.enumerate()
				.map(|(index, file)| {
					drained.fetch_add(1, Ordering::SeqCst);
					if index == 1 {
						Err(std::io::Error::from_raw_os_error(libc::EIO).into())
					} else {
						operation(file)
					}
				})
				.collect()
		},
	);
	assert_eq!(calls.load(Ordering::SeqCst), 1);
	assert_eq!(drained.load(Ordering::SeqCst), 4);
	assert_eq!(results.len(), 4);
	for (index, result) in results.into_iter().enumerate() {
		assert_eq!(result.is_err(), index == 1);
		let (directory, record, _) = writes[index];
		assert_eq!(
			read_record(directory, &format!("{}.json", record.request_id)).is_ok(),
			index != 1
		);
	}
	assert_eq!(members(first.path()), 2);
	assert_eq!(members(second.path()), 1);
}

#[test]
fn overlapping_file_barriers_are_bounded_and_nothing_publishes_until_all_complete() {
	let root = private_root();
	let path = root.path().to_owned();
	let gate = Arc::new((Mutex::new(false), Condvar::new()));
	let allow = gate.clone();
	let (send, receive) = mpsc::channel();
	let completed = Arc::new(AtomicUsize::new(0));
	let done = completed.clone();
	let handle = std::thread::spawn(move || {
		let directory = File::open(&path).unwrap();
		let records = records(16);
		let writes: Vec<_> = records.iter().map(|record| (record, false)).collect();
		let pool = file_sync::Pool::new().unwrap();
		let results = save_with_barrier(
			&directory,
			&writes,
			Arc::new(move |file: &File| {
				send.send(()).unwrap();
				wait_for_release(&allow);
				file.sync_all()?;
				done.fetch_add(1, Ordering::SeqCst);
				Ok(())
			}),
			&|files, operation| pool.synchronize(files, operation),
		);
		assert!(results.iter().all(Result::is_ok));
	});
	for _ in 0..file_sync::WORKERS {
		receive.recv_timeout(Duration::from_secs(20)).unwrap();
	}
	assert!(receive.try_recv().is_err());
	assert_eq!(completed.load(Ordering::SeqCst), 0);
	assert_only_temporaries(root.path(), 16);
	release(&gate);
	handle.join().unwrap();
	assert_eq!(completed.load(Ordering::SeqCst), 16);
	assert_eq!(members(root.path()), 16);
	let directory = File::open(root.path()).unwrap();
	for record in records(16) {
		assert!(read_record(&directory, &format!("{}.json", record.request_id)).unwrap() == record);
	}
}

#[test]
fn one_file_barrier_stays_on_the_caller_thread() {
	let root = private_root();
	let directory = File::open(root.path()).unwrap();
	let records = records(1);
	let caller = std::thread::current().id();
	let results = save_with(
		&directory,
		&[(&records[0], false)],
		Arc::new(move |file: &File| {
			assert_eq!(std::thread::current().id(), caller);
			file.sync_all()?;
			Ok(())
		}),
	);
	assert!(results.iter().all(Result::is_ok));
	assert_eq!(members(root.path()), 1);
}

#[test]
fn failed_file_barrier_never_publishes_its_original_and_other_results_remain_exact() {
	let root = private_root();
	let directory = File::open(root.path()).unwrap();
	let records = records(12);
	let writes: Vec<_> = records.iter().map(|record| (record, false)).collect();
	let number = Arc::new(AtomicUsize::new(0));
	let observed = number.clone();
	let results = save_with(
		&directory,
		&writes,
		Arc::new(move |file: &File| {
			if observed.fetch_add(1, Ordering::SeqCst) == 3 {
				bail!("injected file barrier failure");
			}
			file.sync_all()?;
			Ok(())
		}),
	);
	assert_eq!(results.iter().filter(|value| value.is_err()).count(), 1);
	assert_eq!(number.load(Ordering::SeqCst), records.len());
	for (record, result) in records.iter().zip(results) {
		let path = root.path().join(format!("{}.json", record.request_id));
		assert_eq!(path.exists(), result.is_ok());
		if result.is_ok() {
			assert_eq!(
				std::fs::read(path).unwrap(),
				serde_json::to_vec(record).unwrap()
			);
		}
	}
	assert_eq!(members(root.path()), records.len() - 1);
}

#[test]
fn panicking_worker_drains_every_other_file_before_refusing_the_entire_cohort() {
	let root = private_root();
	let path = root.path().to_owned();
	let gate = Arc::new((Mutex::new(false), Condvar::new()));
	let allow = gate.clone();
	let calls = Arc::new(AtomicUsize::new(0));
	let observed = calls.clone();
	let (started, receive) = mpsc::channel();
	let (finished, result) = mpsc::channel();
	let handle = std::thread::spawn(move || {
		let directory = File::open(&path).unwrap();
		let records = records(8);
		let writes: Vec<_> = records.iter().map(|record| (record, false)).collect();
		let pool = file_sync::Pool::new().unwrap();
		let results = save_with_barrier(
			&directory,
			&writes,
			Arc::new(move |file: &File| {
				assert_ne!(
					observed.fetch_add(1, Ordering::SeqCst),
					0,
					"injected worker panic"
				);
				started.send(()).unwrap();
				wait_for_release(&allow);
				file.sync_all()?;
				Ok(())
			}),
			&|files, operation| pool.synchronize(files, operation),
		);
		assert!(results.iter().all(Result::is_err));
		finished.send(()).unwrap();
	});
	for _ in 0..file_sync::WORKERS {
		receive.recv_timeout(Duration::from_secs(20)).unwrap();
	}
	assert!(result.try_recv().is_err());
	assert_only_temporaries(root.path(), 8);
	release(&gate);
	handle.join().unwrap();
	assert_eq!(calls.load(Ordering::SeqCst), 8);
	assert_eq!(members(root.path()), 0);
}

#[test]
fn caller_unwind_after_submission_drains_jobs_before_prepared_can_unlink() {
	let root = private_root();
	let path = root.path().to_owned();
	let gate = Arc::new((Mutex::new(false), Condvar::new()));
	let allow = gate.clone();
	let completed = Arc::new(AtomicUsize::new(0));
	let done = completed.clone();
	let (started, receive) = mpsc::channel();
	let handle = std::thread::spawn(move || {
		let directory = File::open(&path).unwrap();
		let records = records(8);
		let writes: Vec<_> = records.iter().map(|record| (record, false)).collect();
		let pool = file_sync::Pool::new().unwrap();
		let _ = save_with_barrier(
			&directory,
			&writes,
			Arc::new(move |file: &File| {
				started.send(()).unwrap();
				wait_for_release(&allow);
				file.sync_all()?;
				done.fetch_add(1, Ordering::SeqCst);
				Ok(())
			}),
			&|files, operation| {
				pool.synchronize_with_hook(files, operation, |submitted| {
					assert_ne!(submitted, 4, "injected caller unwind after accepted jobs");
				})
			},
		);
	});
	for _ in 0..file_sync::WORKERS {
		receive.recv_timeout(Duration::from_secs(20)).unwrap();
	}
	assert!(!handle.is_finished());
	assert_eq!(completed.load(Ordering::SeqCst), 0);
	assert_only_temporaries(root.path(), 8);
	release(&gate);
	assert!(handle.join().is_err());
	assert_eq!(completed.load(Ordering::SeqCst), 4);
	assert_eq!(members(root.path()), 0);
}

#[test]
fn parallel_staging_refuses_changed_owner_and_keeps_the_existing_original() {
	let root = private_root();
	let directory = File::open(root.path()).unwrap();
	let mut records = records(2);
	let before = serde_json::to_vec(&records[0]).unwrap();
	let path = root.path().join(format!("{}.json", records[0].request_id));
	super::super::save_raw_with_sync(&directory, &records[0], false, true).unwrap();
	records[0].owner = "b".repeat(64);
	let results = save(&directory, &[(&records[0], true), (&records[1], false)]);
	assert!(results[0].is_err() && results[1].is_ok());
	assert_eq!(std::fs::read(path).unwrap(), before);
	assert_eq!(members(root.path()), 2);
}

#[test]
fn oversized_cohort_is_refused_before_any_temporary_is_created() {
	let root = private_root();
	let directory = File::open(root.path()).unwrap();
	let records = records(MAX_FILES + 1);
	let writes: Vec<_> = records.iter().map(|record| (record, false)).collect();
	let results = save(&directory, &writes);
	assert!(results.iter().all(Result::is_err));
	assert_eq!(results.len(), MAX_FILES + 1);
	assert_eq!(members(root.path()), 0);
}
