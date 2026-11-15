// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Uncapped scoped file barriers preserve exact results and reference fences.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Condvar, Mutex};
use std::time::Duration;

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

#[derive(Default)]
struct Gate {
	open: Mutex<bool>,
	changed: Condvar,
}
impl Gate {
	fn wait(&self) {
		let mut open = self.open.lock().unwrap();
		while !*open {
			open = self.changed.wait(open).unwrap();
		}
	}
	fn release(&self) {
		*self.open.lock().unwrap() = true;
		self.changed.notify_all();
	}
}
struct ReleaseOnDrop(Arc<Gate>);
impl Drop for ReleaseOnDrop {
	fn drop(&mut self) {
		self.0.release();
	}
}

#[test]
fn independent_cohorts_exceed_four_workers_and_32_files_while_owning_every_file() {
	const COHORT_FILES: usize = 40;
	let roots = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
	let files: Vec<_> = roots
		.iter()
		.map(|root| files(root.path(), COHORT_FILES))
		.collect();
	let gate = Arc::new(Gate::default());
	let release = ReleaseOnDrop(gate.clone());
	let (started, receive) = mpsc::channel();
	let completed = Arc::new(AtomicUsize::new(0));
	let mut callers = Vec::new();
	for cohort in &files {
		let cohort = cohort.clone();
		let gate = gate.clone();
		let started = started.clone();
		let completed = completed.clone();
		callers.push(std::thread::spawn(move || {
			synchronize(
				&cohort,
				Arc::new(move |file| {
					started.send(()).unwrap();
					gate.wait();
					file.sync_all()?;
					completed.fetch_add(1, Ordering::SeqCst);
					Ok(())
				}),
			)
		}));
	}
	for _ in 0..COHORT_FILES * files.len() {
		receive.recv_timeout(Duration::from_secs(5)).unwrap();
	}
	assert!(callers.iter().all(|caller| !caller.is_finished()));
	assert_eq!(completed.load(Ordering::SeqCst), 0);
	drop(release);
	for caller in callers {
		let results = caller.join().unwrap();
		assert_eq!(results.len(), COHORT_FILES);
		assert!(results.iter().all(Result::is_ok));
	}
	assert_eq!(completed.load(Ordering::SeqCst), COHORT_FILES * files.len());
	assert!(files
		.iter()
		.flatten()
		.all(|file| Arc::strong_count(file) == 1));
}

#[test]
fn one_file_stays_inline_and_empty_cohorts_spawn_nothing() {
	let root = tempfile::tempdir().unwrap();
	let files = files(root.path(), 1);
	let caller = std::thread::current().id();
	let results = synchronize_with_hooks(
		&files,
		Arc::new(move |file: &File| {
			assert_eq!(std::thread::current().id(), caller);
			file.sync_all()?;
			Ok(())
		}),
		|_| panic!("a singleton must not spawn"),
		|_| panic!("a singleton has no submitted workers"),
	);
	assert!(results.iter().all(Result::is_ok));
	assert_eq!(Arc::strong_count(&files[0]), 1);
	assert!(synchronize_with_hooks(
		&[],
		actual_sync(),
		|_| panic!("empty cohort spawned"),
		|_| panic!("empty cohort submitted")
	)
	.is_empty());
}

#[test]
fn partial_spawn_failure_joins_accepted_workers_and_preserves_errno_without_replay() {
	let root = tempfile::tempdir().unwrap();
	let files = files(root.path(), 8);
	let gate = Arc::new(Gate::default());
	let release = ReleaseOnDrop(gate.clone());
	let (started, receive) = mpsc::channel();
	let attempts = Arc::new(AtomicUsize::new(0));
	let attempted = attempts.clone();
	let completed = Arc::new(AtomicUsize::new(0));
	let done = completed.clone();
	let owned = files.clone();
	let caller = std::thread::spawn(move || {
		synchronize_with_hooks(
			&owned,
			Arc::new(move |file| {
				started.send(()).unwrap();
				gate.wait();
				file.sync_all()?;
				done.fetch_add(1, Ordering::SeqCst);
				Ok(())
			}),
			move |index| {
				attempted.fetch_add(1, Ordering::SeqCst);
				if index == 2 {
					Err(std::io::Error::from_raw_os_error(libc::EAGAIN))
				} else {
					Ok(())
				}
			},
			|_| {},
		)
	});
	for _ in 0..2 {
		receive.recv_timeout(Duration::from_secs(5)).unwrap();
	}
	assert!(!caller.is_finished());
	assert_eq!(completed.load(Ordering::SeqCst), 0);
	drop(release);
	let results = caller.join().unwrap();
	assert_eq!(results.len(), files.len());
	for result in results {
		assert_eq!(
			result
				.unwrap_err()
				.chain()
				.find_map(|error| error.downcast_ref::<std::io::Error>())
				.and_then(std::io::Error::raw_os_error),
			Some(libc::EAGAIN)
		);
	}
	assert_eq!(attempts.load(Ordering::SeqCst), 3);
	assert_eq!(completed.load(Ordering::SeqCst), 2);
	assert!(files.iter().all(|file| Arc::strong_count(file) == 1));
	// A separate explicit call remains possible; the failed cohort was not replayed.
	assert!(synchronize(&files, actual_sync()).iter().all(Result::is_ok));
}

#[test]
fn first_spawn_failure_runs_no_io_and_releases_every_rejected_file_reference() {
	let root = tempfile::tempdir().unwrap();
	let files = files(root.path(), 8);
	let results = synchronize_with_hooks(
		&files,
		Arc::new(|_| panic!("failed spawn must not run I/O")),
		|_| Err(std::io::Error::from_raw_os_error(libc::EAGAIN)),
		|_| panic!("failed spawn must not report submission"),
	);
	assert_eq!(results.len(), files.len());
	assert!(results.iter().all(Result::is_err));
	assert!(files.iter().all(|file| Arc::strong_count(file) == 1));
}

#[test]
fn ordinary_io_failure_maps_to_its_input_position_and_panic_refuses_the_whole_cohort() {
	let root = tempfile::tempdir().unwrap();
	let files = files(root.path(), 16);
	let results = synchronize(
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
	let results = synchronize(
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
	assert!(synchronize(&files, actual_sync()).iter().all(Result::is_ok));
}

#[cfg(target_os = "linux")]
#[test]
fn workers_share_the_original_file_descriptors_without_duplication_or_retention() {
	use std::os::unix::fs::MetadataExt;
	let root = tempfile::tempdir().unwrap();
	let files = files(root.path(), 64);
	let results = synchronize(
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
