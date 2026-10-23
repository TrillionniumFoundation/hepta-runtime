// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Persistent worker identity, closed queues, inline paths and reference fences.
use super::*;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Barrier;

fn files(root: &std::path::Path, count: usize) -> Vec<Arc<File>> {
	(0..count)
		.map(|index| {
			let file = File::create(root.join(format!("file-{index}"))).unwrap();
			file.set_len((index + 1) as u64).unwrap();
			Arc::new(file)
		})
		.collect()
}

fn actual_sync() -> Operation {
	Arc::new(|file: &File| {
		file.sync_all()?;
		Ok(())
	})
}

#[test]
fn exactly_the_same_four_threads_serve_multiple_cohorts_and_release_all_file_arcs() {
	let root = tempfile::tempdir().unwrap();
	let files = files(root.path(), 8);
	let pool = Pool::new().unwrap();
	assert!(pool.is_ready());
	let mut previous = None;
	for _ in 0..4 {
		let gate = Arc::new(Barrier::new(WORKERS));
		let ids = Arc::new(Mutex::new(HashSet::new()));
		let observed = ids.clone();
		let results = pool.synchronize(
			&files,
			Arc::new(move |file: &File| {
				observed.lock().unwrap().insert(std::thread::current().id());
				gate.wait();
				file.sync_all()?;
				Ok(())
			}),
		);
		assert!(results.iter().all(Result::is_ok));
		let ids = ids.lock().unwrap().clone();
		assert_eq!(ids.len(), WORKERS);
		if let Some(previous) = &previous {
			assert_eq!(&ids, previous);
		}
		previous = Some(ids);
		assert!(files.iter().all(|file| Arc::strong_count(file) == 1));
	}
}

#[test]
fn one_file_is_inline_without_initializing_any_worker() {
	let root = tempfile::tempdir().unwrap();
	let files = files(root.path(), 1);
	let cell = PoolCell::new();
	assert!(cell_is_ready(&cell));
	let caller = std::thread::current().id();
	let results = with_cell(
		&files,
		Arc::new(move |file: &File| {
			assert_eq!(std::thread::current().id(), caller);
			file.sync_all()?;
			Ok(())
		}),
		&cell,
		|| panic!("C1 must not initialize the sync pool"),
	);
	assert!(results.iter().all(Result::is_ok));
	assert!(cell.get().is_none());
	assert!(cell_is_ready(&cell));
	assert_eq!(Arc::strong_count(&files[0]), 1);
}

#[test]
fn partial_initialization_joins_existing_workers_and_caches_the_error_without_retries() {
	let root = tempfile::tempdir().unwrap();
	let files = files(root.path(), 8);
	let cell = PoolCell::new();
	let initialized = AtomicUsize::new(0);
	let attempted = AtomicUsize::new(0);
	let alive = Arc::new(AtomicUsize::new(0));
	for _ in 0..2 {
		let results = with_cell(&files, actual_sync(), &cell, || {
			initialized.fetch_add(1, Ordering::SeqCst);
			Pool::start_with(|index, task| {
				attempted.fetch_add(1, Ordering::SeqCst);
				if index == 2 {
					return Err(std::io::Error::from_raw_os_error(libc::EAGAIN));
				}
				let alive = alive.clone();
				Builder::new().spawn(move || {
					alive.fetch_add(1, Ordering::SeqCst);
					task();
					alive.fetch_sub(1, Ordering::SeqCst);
				})
			})
		});
		assert!(results.iter().all(Result::is_err));
		for result in &results {
			assert_eq!(
				result
					.as_ref()
					.unwrap_err()
					.chain()
					.find_map(|error| error.downcast_ref::<std::io::Error>())
					.and_then(std::io::Error::raw_os_error),
				Some(libc::EAGAIN)
			);
		}
		assert!(!cell_is_ready(&cell));
		assert_eq!(alive.load(Ordering::SeqCst), 0);
		assert!(files.iter().all(|file| Arc::strong_count(file) == 1));
	}
	assert_eq!(initialized.load(Ordering::SeqCst), 1);
	assert_eq!(attempted.load(Ordering::SeqCst), 3);
}

#[test]
fn ordinary_io_failure_maps_to_its_input_position_and_panic_refuses_the_whole_cohort() {
	let root = tempfile::tempdir().unwrap();
	let files = files(root.path(), 16);
	let pool = Pool::new().unwrap();
	let results = pool.synchronize(
		&files,
		Arc::new(|file: &File| {
			if file.metadata()?.len() == 4 {
				return Err(
					anyhow::Error::new(std::io::Error::from_raw_os_error(libc::EIO))
						.context("injected sync boundary"),
				);
			}
			file.sync_all()?;
			Ok(())
		}),
	);
	assert_eq!(results.iter().filter(|value| value.is_err()).count(), 1);
	assert!(results[3].is_err());
	assert_eq!(
		results[3]
			.as_ref()
			.unwrap_err()
			.chain()
			.find_map(|error| error.downcast_ref::<std::io::Error>())
			.and_then(std::io::Error::raw_os_error),
		Some(libc::EIO)
	);
	assert!(results
		.iter()
		.enumerate()
		.all(|(index, result)| index == 3 || result.is_ok()));
	let calls = Arc::new(AtomicUsize::new(0));
	let observed = calls.clone();
	let results = pool.synchronize(
		&files,
		Arc::new(move |file: &File| {
			observed.fetch_add(1, Ordering::SeqCst);
			assert_ne!(file.metadata()?.len(), 4, "injected file sync panic");
			file.sync_all()?;
			Ok(())
		}),
	);
	assert!(results.iter().all(Result::is_err));
	assert_eq!(calls.load(Ordering::SeqCst), files.len());
	assert!(files.iter().all(|file| Arc::strong_count(file) == 1));
	assert!(pool
		.synchronize(&files, actual_sync())
		.iter()
		.all(Result::is_ok));
}

#[test]
fn a_closed_queue_releases_the_rejected_job_reference_and_refuses_every_result() {
	let root = tempfile::tempdir().unwrap();
	let files = files(root.path(), 8);
	let (sender, receive) = mpsc::sync_channel(MAX_FILES);
	drop(receive);
	let pool = Pool {
		sender: Some(sender),
		workers: Vec::new(),
	};
	assert!(!pool.is_ready());
	assert!(pool
		.synchronize(&files, actual_sync())
		.iter()
		.all(Result::is_err));
	assert!(files.iter().all(|file| Arc::strong_count(file) == 1));
}

#[test]
fn duplicate_completion_cannot_end_draining_while_an_accepted_sender_is_alive() {
	let (reply, receive) = mpsc::sync_channel(MAX_FILES);
	let faulty = reply.clone();
	let pending = reply.clone();
	let (done, observed) = mpsc::channel();
	let handle = std::thread::spawn(move || {
		let mut drain = CohortDrainGuard {
			reply: Some(reply),
			receive,
			remaining: 2,
			disconnected: false,
		};
		drain.close_reply();
		while drain.next().is_some() {}
		assert!(drain.disconnected);
		done.send(()).unwrap();
	});
	for _ in 0..2 {
		faulty
			.send(Completion {
				index: 0,
				outcome: Outcome::Synced,
			})
			.unwrap();
	}
	drop(faulty);
	assert!(observed.try_recv().is_err());
	pending
		.send(Completion {
			index: 1,
			outcome: Outcome::Synced,
		})
		.unwrap();
	drop(pending);
	observed
		.recv_timeout(std::time::Duration::from_secs(20))
		.unwrap();
	handle.join().unwrap();
}

#[test]
fn oversized_cohorts_are_refused_without_initializing_or_synchronizing_files() {
	let root = tempfile::tempdir().unwrap();
	let files = files(root.path(), MAX_FILES + 1);
	let cell = PoolCell::new();
	let results = with_cell(
		&files,
		Arc::new(|_| panic!("oversized cohort reached fsync")),
		&cell,
		|| panic!("oversized cohort initialized workers"),
	);
	assert_eq!(results.len(), MAX_FILES + 1);
	assert!(results.iter().all(Result::is_err));
	assert!(cell.get().is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn workers_share_the_original_file_descriptors_without_duplication_or_retention() {
	use std::os::unix::fs::MetadataExt;
	let root = tempfile::tempdir().unwrap();
	let files = files(root.path(), MAX_FILES);
	let pool = Pool::new().unwrap();
	let results = pool.synchronize(
		&files,
		Arc::new(|file: &File| {
			let expected = file.metadata()?;
			let open = std::fs::read_dir("/proc/self/fd")?
				.filter_map(|entry| entry.ok())
				.filter_map(|entry| std::fs::metadata(entry.path()).ok())
				.filter(|info| info.dev() == expected.dev() && info.ino() == expected.ino())
				.count();
			assert_eq!(open, 1);
			file.sync_all()?;
			Ok(())
		}),
	);
	assert!(results.iter().all(Result::is_ok));
	assert!(files.iter().all(|file| Arc::strong_count(file) == 1));
}
