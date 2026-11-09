// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Uncapped acquisition preserves the actual shared/exclusive authority fence.
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

async fn drain(counts: &Counts) {
	tokio::time::timeout(WAIT, async {
		while counts.active.load(Ordering::SeqCst) != 0 {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
}

#[test]
fn exclusive_fence_waiters_exceed_old_capacity_and_preserve_authority_after_cancellation() {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	runtime.block_on(async {
		let fixture = Fixture::new();
		let exclusive = fixture.hold_exclusive();
		let counts = Arc::new(Counts::default());
		let (entered, mut notices) = tokio::sync::mpsc::unbounded_channel();
		let mut owners = Vec::new();
		for _ in 0..12 {
			owners.push(tokio::spawn(run_fence_acquisition(observed_acquire(
				fixture.clone(),
				counts.clone(),
				entered.clone(),
			))));
		}
		started(&mut notices, 12).await;
		assert_eq!(counts.active.load(Ordering::SeqCst), 12);
		for owner in owners.drain(..4) {
			owner.abort();
			assert!(owner.await.unwrap_err().is_cancelled());
		}
		assert_eq!(counts.active.load(Ordering::SeqCst), 12);
		assert!(owners.iter().all(|owner| !owner.is_finished()));
		assert_eq!(
			tokio::time::timeout(WAIT, tokio::spawn(async { 42 }))
				.await
				.unwrap()
				.unwrap(),
			42
		);
		drop(exclusive);
		let mut admissions = Vec::new();
		for owner in owners {
			admissions.push(owner.await.unwrap().unwrap());
		}
		drain(&counts).await;
		assert_eq!(counts.maximum.load(Ordering::SeqCst), 12);
		let contender = fixture.lock_file();
		assert_eq!(
			unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
			-1
		);
		drop(admissions);
		tokio::time::timeout(WAIT, async {
			while unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
			{
				tokio::task::yield_now().await;
			}
		})
		.await
		.unwrap();
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
fn cancelled_queued_fence_workers_complete_validation_without_leaking_authority() {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(1)
		.build()
		.unwrap();
	runtime.block_on(async {
		let fixture = Fixture::new();
		let exclusive = fixture.hold_exclusive();
		let mut release_pool = ReleaseBlockingPool::default();
		let (release, wait) = mpsc::channel();
		release_pool.0.push(release);
		let (blocked, blocked_notice) = tokio::sync::oneshot::channel();
		let blocker = tokio::task::spawn_blocking(move || {
			let _ = blocked.send(());
			wait.recv_timeout(WAIT).unwrap();
		});
		tokio::time::timeout(WAIT, blocked_notice)
			.await
			.unwrap()
			.unwrap();
		let counts = Arc::new(Counts::default());
		let (entered, mut notices) = tokio::sync::mpsc::unbounded_channel();
		for _ in 0..12 {
			let mut caller = Box::pin(run_fence_acquisition(observed_acquire(
				fixture.clone(),
				counts.clone(),
				entered.clone(),
			)));
			pending(caller.as_mut()).await;
			drop(caller);
		}
		assert_eq!(counts.entered.load(Ordering::SeqCst), 0);
		drop(exclusive);
		drop(release_pool);
		blocker.await.unwrap();
		started(&mut notices, 12).await;
		drain(&counts).await;
		assert_eq!(counts.entered.load(Ordering::SeqCst), 12);
		let contender = fixture.lock_file();
		tokio::time::timeout(WAIT, async {
			while unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
			{
				tokio::task::yield_now().await;
			}
		})
		.await
		.unwrap();
	});
}

#[tokio::test(flavor = "current_thread")]
async fn unpolled_fence_acquisition_never_submits_a_worker() {
	let calls = Arc::new(AtomicUsize::new(0));
	let observed = calls.clone();
	drop(run_fence_acquisition(move || {
		observed.fetch_add(1, Ordering::SeqCst);
		bail!("unpolled acquisition must not run")
	}));
	tokio::task::yield_now().await;
	assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn fence_acquisition_success_error_and_panic_preserve_results() {
	let fixture = Fixture::new();

	let original = fixture.clone();
	let admission = run_fence_acquisition(move || original.acquire())
		.await
		.unwrap();
	assert_eq!(admission.epoch, Some(7));

	drop(admission);
	let expected = acquire_from_root(&fixture.root, "v11", &fixture.state)
		.unwrap_err()
		.to_string();
	let original = fixture.clone();
	let error =
		run_fence_acquisition(move || acquire_from_root(&original.root, "v11", &original.state))
			.await
			.unwrap_err();
	assert_eq!(error.to_string(), expected);

	let error =
		run_fence_acquisition(|| panic!("fixture acquisition panic must not grant admission"))
			.await
			.unwrap_err();
	assert_eq!(
		error.to_string(),
		"effect owner admission worker unavailable"
	);

	let original = fixture.clone();
	assert!(run_fence_acquisition(move || original.acquire())
		.await
		.is_ok());
}

#[tokio::test(flavor = "current_thread")]
async fn acquired_shared_fence_outlives_the_acquisition_worker() {
	let fixture = Fixture::new();

	let original = fixture.clone();
	let admission = run_fence_acquisition(move || original.acquire())
		.await
		.unwrap();

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
		"dropping AdmissionPermit releases the effect fence"
	);
	drop(contender);
}
