// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Retained-result reads keep their actual worker bound across caller cancellation.
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
	root: tempfile::TempDir,
	identity: RequestIdentity,
	binding: String,
}

impl Fixture {
	fn new() -> Arc<Self> {
		let root = tempfile::tempdir().unwrap();
		std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
		prepare_at(root.path()).unwrap();
		let identity = RequestIdentity {
			request_id: format!("d1{:062x}", 1),
			owner: "a".repeat(64),
			tool_name: "host_health".into(),
			accepted_unix_ms: 1234,
		};
		let binding = "b".repeat(64);
		let legacy = open_store(root.path()).unwrap();
		let archive = open_archive_store(root.path(), &legacy, false)
			.unwrap()
			.unwrap();
		let directory = shard(&archive, &identity.request_id).unwrap();
		let record = Record {
			request_id: identity.request_id.clone(),
			owner: identity.owner.clone(),
			tool_name: identity.tool_name.clone(),
			accepted_unix_ms: identity.accepted_unix_ms,
			policy_binding: binding.clone(),
			state: ResultState::Unknown,
			payload_base64: None,
			payload_bytes: None,
			payload_sha256: None,
		};
		save(&directory, &record, false).unwrap();
		Arc::new(Self {
			root,
			identity,
			binding,
		})
	}

	fn read(&self) -> Result<Option<Record>> {
		lookup_at(self.root.path(), &self.identity, &self.binding)
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

fn observed_read(
	fixture: Arc<Fixture>,
	counts: Arc<Counts>,
	entered: tokio::sync::mpsc::UnboundedSender<()>,
) -> impl FnOnce() -> Result<Option<Record>> + Send + 'static {
	move || {
		let _active = counts.enter();
		let _ = entered.send(());
		fixture.read()
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
			.acquire_many_owned(MAX_RESULT_READ_WORKERS as u32),
	)
	.await
	.unwrap()
	.unwrap();
	drop(all);
}

#[test]
// Intentionally hold the real sync lock on this current-thread fixture while
// observing blocked workers; unwind drops the lock before runtime teardown.
#[allow(clippy::await_holding_lock)]
fn cancelled_reads_waiting_on_real_record_lock_keep_four_worker_slots() {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(MAX_RESULT_READ_WORKERS * 2)
		.build()
		.unwrap();
	runtime.block_on(async {
		let fixture = Fixture::new();
		// Model a slow durable completion holding the real per-record lock.
		// Declared inside block_on so an assertion unwind releases it before
		// dropping the runtime, whose blocking workers are not abortable.
		let held_record = record_lock(&fixture.identity.request_id).unwrap();
		let slots = Arc::new(Semaphore::new(MAX_RESULT_READ_WORKERS));
		let counts = Arc::new(Counts::default());
		let (entered, mut notices) = tokio::sync::mpsc::unbounded_channel();
		let mut callers = Vec::new();
		for _ in 0..MAX_RESULT_READ_WORKERS {
			callers.push(tokio::spawn(run_result_read(
				slots.clone(),
				observed_read(fixture.clone(), counts.clone(), entered.clone()),
			)));
		}
		started(&mut notices, MAX_RESULT_READ_WORKERS).await;
		for caller in callers {
			caller.abort();
			match caller.await {
				Err(error) => assert!(error.is_cancelled()),
				Ok(_) => {
					panic!("read caller unexpectedly completed while its record lock was held")
				}
			}
		}
		assert_eq!(slots.available_permits(), 0);
		for _wave in 0..3 {
			for _ in 0..MAX_RESULT_READ_WORKERS * 2 {
				let mut waiter = Box::pin(run_result_read(
					slots.clone(),
					observed_read(fixture.clone(), counts.clone(), entered.clone()),
				));
				pending(waiter.as_mut()).await;
				drop(waiter);
			}
			assert_eq!(
				counts.entered.load(Ordering::SeqCst),
				MAX_RESULT_READ_WORKERS
			);
			assert_eq!(
				counts.active.load(Ordering::SeqCst),
				MAX_RESULT_READ_WORKERS
			);
			assert_eq!(slots.available_permits(), 0);
			assert!(notices.try_recv().is_err());
		}
		assert_eq!(
			tokio::time::timeout(WAIT, tokio::spawn(async { 42 }))
				.await
				.unwrap()
				.unwrap(),
			42
		);
		drop(held_record);
		drain(&slots).await;
		assert_eq!(
			counts.maximum.load(Ordering::SeqCst),
			MAX_RESULT_READ_WORKERS
		);
		assert_eq!(counts.active.load(Ordering::SeqCst), 0);
		assert_eq!(slots.available_permits(), MAX_RESULT_READ_WORKERS);
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
// This current-thread fixture owns the lock until queued workers have started.
// Keeping it across awaits is the fault injection, not a production lock path.
#[allow(clippy::await_holding_lock)]
fn cancelled_queued_result_reads_keep_slots_before_workers_start() {
	let blocking_threads = MAX_RESULT_READ_WORKERS + 1;
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(blocking_threads)
		.build()
		.unwrap();
	runtime.block_on(async {
		let fixture = Fixture::new();
		let held_record = record_lock(&fixture.identity.request_id).unwrap();
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
		let slots = Arc::new(Semaphore::new(MAX_RESULT_READ_WORKERS));
		let counts = Arc::new(Counts::default());
		let (entered, mut notices) = tokio::sync::mpsc::unbounded_channel();
		let mut submitted = Vec::new();
		for _ in 0..MAX_RESULT_READ_WORKERS {
			let mut caller = Box::pin(run_result_read(
				slots.clone(),
				observed_read(fixture.clone(), counts.clone(), entered.clone()),
			));
			pending(caller.as_mut()).await;
			submitted.push(caller);
		}
		assert_eq!(slots.available_permits(), 0);
		assert_eq!(counts.entered.load(Ordering::SeqCst), 0);
		drop(submitted);
		for _ in 0..MAX_RESULT_READ_WORKERS * 2 {
			let mut extra = Box::pin(run_result_read(
				slots.clone(),
				observed_read(fixture.clone(), counts.clone(), entered.clone()),
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
		started(&mut notices, MAX_RESULT_READ_WORKERS).await;
		assert_eq!(
			counts.active.load(Ordering::SeqCst),
			MAX_RESULT_READ_WORKERS
		);
		assert_eq!(slots.available_permits(), 0);
		drop(held_record);
		drain(&slots).await;
		assert_eq!(
			counts.entered.load(Ordering::SeqCst),
			MAX_RESULT_READ_WORKERS
		);
		assert_eq!(
			counts.maximum.load(Ordering::SeqCst),
			MAX_RESULT_READ_WORKERS
		);
		assert_eq!(counts.active.load(Ordering::SeqCst), 0);
	});
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_or_closed_result_read_admission_never_submits_io() {
	let slots = Arc::new(Semaphore::new(1));
	let held = slots.clone().acquire_owned().await.unwrap();
	let calls = Arc::new(AtomicUsize::new(0));
	let observed = calls.clone();
	let mut waiter = Box::pin(run_result_read(slots.clone(), move || {
		observed.fetch_add(1, Ordering::SeqCst);
		Ok(None)
	}));
	pending(waiter.as_mut()).await;
	drop(waiter);
	assert_eq!(calls.load(Ordering::SeqCst), 0);
	assert_eq!(slots.available_permits(), 0);
	drop(held);
	slots.close();
	let observed = calls.clone();
	let error = run_result_read(slots, move || {
		observed.fetch_add(1, Ordering::SeqCst);
		Ok(None)
	})
	.await
	.err()
	.unwrap();
	assert_eq!(
		error.to_string(),
		"request result unavailable to this scope or current policy"
	);
	assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn result_read_success_refusal_missing_record_and_panic_release_capacity() {
	let fixture = Fixture::new();
	let slots = Arc::new(Semaphore::new(1));
	let original = fixture.clone();
	let record = run_result_read(slots.clone(), move || original.read())
		.await
		.unwrap()
		.unwrap();
	assert_eq!(record.request_id, fixture.identity.request_id);
	assert_eq!(result_state(Some(&record), "host_health"), "unknown");
	assert_eq!(slots.available_permits(), 1);
	let mut foreign = fixture.identity.clone();
	foreign.owner = "c".repeat(64);
	let expected = lookup_at(fixture.root.path(), &foreign, &fixture.binding)
		.err()
		.unwrap()
		.to_string();
	let original = fixture.clone();
	let error = run_result_read(slots.clone(), move || {
		lookup_at(original.root.path(), &foreign, &original.binding)
	})
	.await
	.err()
	.unwrap();
	assert_eq!(error.to_string(), expected);
	assert_eq!(slots.available_permits(), 1);
	let original = fixture.clone();
	assert!(run_result_read(slots.clone(), move || {
		let mut missing = original.identity.clone();
		missing.request_id = format!("d1{:062x}", 2);
		lookup_at(original.root.path(), &missing, &original.binding)
	})
	.await
	.unwrap()
	.is_none());
	assert_eq!(slots.available_permits(), 1);
	let error = run_result_read(slots.clone(), || {
		panic!("fixture result-read panic must release its worker slot")
	})
	.await
	.err()
	.unwrap();
	assert_eq!(
		error.to_string(),
		"request result unavailable to this scope or current policy"
	);
	assert_eq!(slots.available_permits(), 1);
	assert!(run_result_read(slots, move || fixture.read()).await.is_ok());
}
