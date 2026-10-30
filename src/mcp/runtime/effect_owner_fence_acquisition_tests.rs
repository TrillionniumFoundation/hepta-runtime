// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Actual fence acquisition stays bounded after caller cancellation.
use super::*;
use std::future::{poll_fn, Future};
use std::os::unix::fs::PermissionsExt;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::task::Poll;
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(10);

struct Fixture {
	_temp: tempfile::TempDir,
	root: PathBuf,
	state: PathBuf,
}

impl Fixture {
	fn new() -> Arc<Self> {
		let temp = tempfile::tempdir().unwrap();
		let root = temp.path().join("authority");
		let state = temp.path().join("controller");
		for directory in [&root, &state] {
			fs::create_dir(directory).unwrap();
			fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
		}
		for (name, bytes) in [
			(".owner.lock", Vec::new()),
			(
				".owner.json",
				serde_json::to_vec(&serde_json::json!({
					"schema": SCHEMA, "owner": "v4", "phase": "admitting",
					"epoch": 7, "state_root": state, "predecessor_state_root": null
				}))
				.unwrap(),
			),
		] {
			let path = root.join(name);
			fs::write(&path, bytes).unwrap();
			fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
		}
		Arc::new(Self {
			_temp: temp,
			root,
			state,
		})
	}

	fn acquire(&self) -> Result<AdmissionPermit> {
		acquire_from_root(&self.root, "v4", &self.state)
	}

	fn lock_file(&self) -> File {
		fs::OpenOptions::new()
			.read(true)
			.write(true)
			.open(self.root.join(".owner.lock"))
			.unwrap()
	}

	fn hold_exclusive(&self) -> File {
		let file = self.lock_file();
		assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) }, 0);
		// This independently opened File releases LOCK_EX on drop, including
		// an assertion unwind inside runtime.block_on. Workers own Arc<Fixture>
		// so no temporary authority tree disappears before their real return.
		file
	}
}

#[derive(Default)]
struct Counts {
	entered: AtomicUsize,
	active: AtomicUsize,
	maximum: AtomicUsize,
}

struct Active(Arc<Counts>);

impl Counts {
	fn enter(self: &Arc<Self>) -> Active {
		self.entered.fetch_add(1, Ordering::SeqCst);
		let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
		self.maximum.fetch_max(active, Ordering::SeqCst);
		Active(self.clone())
	}
}

impl Drop for Active {
	fn drop(&mut self) {
		self.0.active.fetch_sub(1, Ordering::SeqCst);
	}
}

fn observed_acquire(
	fixture: Arc<Fixture>,
	counts: Arc<Counts>,
	entered: tokio::sync::mpsc::UnboundedSender<()>,
) -> impl FnOnce() -> Result<AdmissionPermit> + Send + 'static {
	move || {
		let _active = counts.enter();
		let _ = entered.send(());
		fixture.acquire()
	}
}

async fn pending<F: Future>(mut future: Pin<&mut F>) {
	poll_fn(|context| {
		assert!(future.as_mut().poll(context).is_pending());
		Poll::Ready(())
	})
	.await;
}

async fn started(receiver: &mut tokio::sync::mpsc::UnboundedReceiver<()>, count: usize) {
	for _ in 0..count {
		tokio::time::timeout(WAIT, receiver.recv())
			.await
			.unwrap()
			.unwrap();
	}
}

async fn drain(slots: &Arc<Semaphore>) {
	let all = tokio::time::timeout(
		WAIT,
		slots
			.clone()
			.acquire_many_owned(MAX_FENCE_ACQUISITION_WORKERS as u32),
	)
	.await
	.unwrap()
	.unwrap();
	drop(all);
}

#[test]
fn real_exclusive_fence_cancelled_waiters_keep_four_acquisition_workers() {
	// More blocking threads than fence slots: the pool itself cannot hide an
	// admission leak. LOCK_EX is released before this runtime can be dropped.
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(MAX_FENCE_ACQUISITION_WORKERS * 2)
		.build()
		.unwrap();
	runtime.block_on(async {
		let fixture = Fixture::new();
		let exclusive = fixture.hold_exclusive();
		let slots = Arc::new(Semaphore::new(MAX_FENCE_ACQUISITION_WORKERS));
		let counts = Arc::new(Counts::default());
		let (entered, mut notices) = tokio::sync::mpsc::unbounded_channel();
		let mut owners = Vec::new();
		for _ in 0..MAX_FENCE_ACQUISITION_WORKERS {
			owners.push(tokio::spawn(run_fence_acquisition(
				slots.clone(),
				observed_acquire(fixture.clone(), counts.clone(), entered.clone()),
			)));
		}
		started(&mut notices, MAX_FENCE_ACQUISITION_WORKERS).await;
		assert_eq!(
			counts.active.load(Ordering::SeqCst),
			MAX_FENCE_ACQUISITION_WORKERS
		);
		for owner in owners {
			owner.abort();
			assert!(owner.await.unwrap_err().is_cancelled());
		}
		assert_eq!(slots.available_permits(), 0);
		for _wave in 0..3 {
			for _ in 0..MAX_FENCE_ACQUISITION_WORKERS * 2 {
				let mut waiter = Box::pin(run_fence_acquisition(
					slots.clone(),
					observed_acquire(fixture.clone(), counts.clone(), entered.clone()),
				));
				pending(waiter.as_mut()).await;
				drop(waiter);
			}
			assert_eq!(slots.available_permits(), 0);
			assert_eq!(
				counts.entered.load(Ordering::SeqCst),
				MAX_FENCE_ACQUISITION_WORKERS
			);
			assert_eq!(
				counts.active.load(Ordering::SeqCst),
				MAX_FENCE_ACQUISITION_WORKERS
			);
			assert!(notices.try_recv().is_err());
		}
		assert_eq!(
			tokio::time::timeout(WAIT, tokio::spawn(async { 42 }))
				.await
				.unwrap()
				.unwrap(),
			42
		);
		drop(exclusive);
		drain(&slots).await;
		assert_eq!(counts.active.load(Ordering::SeqCst), 0);
		assert_eq!(
			counts.maximum.load(Ordering::SeqCst),
			MAX_FENCE_ACQUISITION_WORKERS
		);
		assert_eq!(slots.available_permits(), MAX_FENCE_ACQUISITION_WORKERS);
	});
}

#[derive(Default)]
struct ReleaseBlockingPool(Vec<mpsc::Sender<()>>);

impl Drop for ReleaseBlockingPool {
	fn drop(&mut self) {
		for sender in &self.0 {
			let _ = sender.send(());
		}
	}
}

#[test]
fn cancelled_unstarted_fence_workers_keep_capacity_in_blocking_queue() {
	let blocking_threads = MAX_FENCE_ACQUISITION_WORKERS + 1;
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(blocking_threads)
		.build()
		.unwrap();
	runtime.block_on(async {
		let fixture = Fixture::new();
		let exclusive = fixture.hold_exclusive();
		let mut release_pool = ReleaseBlockingPool::default();
		let mut blockers = Vec::new();
		let (blocked, mut blocking_notices) = tokio::sync::mpsc::unbounded_channel();
		for _ in 0..blocking_threads {
			let (release, wait) = mpsc::channel();
			release_pool.0.push(release);
			let blocked = blocked.clone();
			blockers.push(tokio::task::spawn_blocking(move || {
				let _ = blocked.send(());
				wait.recv_timeout(WAIT).unwrap();
			}));
		}
		started(&mut blocking_notices, blocking_threads).await;
		let slots = Arc::new(Semaphore::new(MAX_FENCE_ACQUISITION_WORKERS));
		let counts = Arc::new(Counts::default());
		let (entered, mut notices) = tokio::sync::mpsc::unbounded_channel();
		let mut submitted = Vec::new();
		for _ in 0..MAX_FENCE_ACQUISITION_WORKERS {
			let mut caller = Box::pin(run_fence_acquisition(
				slots.clone(),
				observed_acquire(fixture.clone(), counts.clone(), entered.clone()),
			));
			pending(caller.as_mut()).await;
			submitted.push(caller);
		}
		assert_eq!(slots.available_permits(), 0);
		assert_eq!(counts.entered.load(Ordering::SeqCst), 0);
		// Dropping JoinHandle waiters must not release permits from closures
		// already queued inside Tokio, even though no closure has started yet.
		drop(submitted);
		for _ in 0..MAX_FENCE_ACQUISITION_WORKERS * 2 {
			let mut extra = Box::pin(run_fence_acquisition(
				slots.clone(),
				observed_acquire(fixture.clone(), counts.clone(), entered.clone()),
			));
			pending(extra.as_mut()).await;
			drop(extra);
		}
		assert_eq!(slots.available_permits(), 0);
		assert_eq!(counts.entered.load(Ordering::SeqCst), 0);
		drop(release_pool);
		for blocker in blockers {
			tokio::time::timeout(WAIT, blocker).await.unwrap().unwrap();
		}
		started(&mut notices, MAX_FENCE_ACQUISITION_WORKERS).await;
		assert_eq!(
			counts.entered.load(Ordering::SeqCst),
			MAX_FENCE_ACQUISITION_WORKERS
		);
		assert_eq!(
			counts.active.load(Ordering::SeqCst),
			MAX_FENCE_ACQUISITION_WORKERS
		);
		assert_eq!(slots.available_permits(), 0);
		drop(exclusive);
		drain(&slots).await;
		assert_eq!(
			counts.entered.load(Ordering::SeqCst),
			MAX_FENCE_ACQUISITION_WORKERS
		);
		assert_eq!(
			counts.maximum.load(Ordering::SeqCst),
			MAX_FENCE_ACQUISITION_WORKERS
		);
		assert_eq!(counts.active.load(Ordering::SeqCst), 0);
	});
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_or_closed_fence_admission_never_submits_a_worker() {
	let slots = Arc::new(Semaphore::new(1));
	let held = slots.clone().acquire_owned().await.unwrap();
	let calls = Arc::new(AtomicUsize::new(0));
	let (polled, waiting) = tokio::sync::oneshot::channel();
	let waiting_slots = slots.clone();
	let observed = calls.clone();
	let waiter = tokio::spawn(async move {
		let mut acquire = Box::pin(run_fence_acquisition(waiting_slots, move || {
			observed.fetch_add(1, Ordering::SeqCst);
			bail!("fixture must not reach an acquisition worker")
		}));
		pending(acquire.as_mut()).await;
		let _ = polled.send(());
		acquire.await
	});
	tokio::time::timeout(WAIT, waiting).await.unwrap().unwrap();
	waiter.abort();
	assert!(waiter.await.unwrap_err().is_cancelled());
	assert_eq!(calls.load(Ordering::SeqCst), 0);
	assert_eq!(slots.available_permits(), 0);
	drop(held);
	slots.close();
	let observed = calls.clone();
	let error = run_fence_acquisition(slots, move || {
		observed.fetch_add(1, Ordering::SeqCst);
		bail!("closed admission must not reach an acquisition worker")
	})
	.await
	.unwrap_err();
	assert_eq!(
		error.to_string(),
		"effect owner admission capacity unavailable"
	);
	assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn fence_acquisition_success_error_and_panic_release_worker_capacity() {
	let fixture = Fixture::new();
	let slots = Arc::new(Semaphore::new(1));
	let original = fixture.clone();
	let admission = run_fence_acquisition(slots.clone(), move || original.acquire())
		.await
		.unwrap();
	assert_eq!(admission.epoch, Some(7));
	assert_eq!(slots.available_permits(), 1);
	drop(admission);
	let expected = acquire_from_root(&fixture.root, "v11", &fixture.state)
		.unwrap_err()
		.to_string();
	let original = fixture.clone();
	let error = run_fence_acquisition(slots.clone(), move || {
		acquire_from_root(&original.root, "v11", &original.state)
	})
	.await
	.unwrap_err();
	assert_eq!(error.to_string(), expected);
	assert_eq!(slots.available_permits(), 1);
	let error = run_fence_acquisition(slots.clone(), || {
		panic!("fixture acquisition panic must release capacity without admission")
	})
	.await
	.unwrap_err();
	assert_eq!(
		error.to_string(),
		"effect owner admission worker unavailable"
	);
	assert_eq!(slots.available_permits(), 1);
	let original = fixture.clone();
	assert!(run_fence_acquisition(slots, move || original.acquire())
		.await
		.is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn acquired_shared_fence_outlives_the_worker_capacity_permit() {
	let fixture = Fixture::new();
	let slots = Arc::new(Semaphore::new(1));
	let original = fixture.clone();
	let admission = run_fence_acquisition(slots.clone(), move || original.acquire())
		.await
		.unwrap();
	assert_eq!(slots.available_permits(), 1);
	let worker_capacity = slots.try_acquire().unwrap();
	let contender = fixture.lock_file();
	let result = unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
	let error = std::io::Error::last_os_error();
	assert_eq!(
		result, -1,
		"the original effect still owns its shared fence"
	);
	assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
	drop(admission);
	assert_eq!(
		unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
		0,
		"dropping AdmissionPermit releases the effect fence independently of worker capacity"
	);
	drop(contender);
	drop(worker_capacity);
	assert_eq!(slots.available_permits(), 1);
}
