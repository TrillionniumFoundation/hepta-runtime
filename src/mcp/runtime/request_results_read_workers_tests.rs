// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Uncapped retained-result reads preserve exact record isolation and worker custody.
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
// Intentionally hold the real sync lock on this current-thread fixture while
// observing blocked workers; unwind drops the lock before runtime teardown.
#[allow(clippy::await_holding_lock)]
fn result_reads_exceed_old_four_worker_limit_and_keep_actual_record_lock() {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	runtime.block_on(async {
		let fixture = Fixture::new();
		let held_record = record_lock(&fixture.identity.request_id).unwrap();
		let counts = Arc::new(Counts::default());
		let (entered, mut notices) = tokio::sync::mpsc::unbounded_channel();
		let mut callers = Vec::new();
		for _ in 0..12 {
			callers.push(tokio::spawn(run_result_read(observed_read(
				fixture.clone(),
				counts.clone(),
				entered.clone(),
			))));
		}
		started(&mut notices, 12).await;
		assert_eq!(counts.active.load(Ordering::SeqCst), 12);
		for caller in callers.drain(..4) {
			caller.abort();
			assert!(matches!(caller.await, Err(error) if error.is_cancelled()));
		}
		assert!(callers.iter().all(|caller| !caller.is_finished()));
		assert_eq!(
			tokio::time::timeout(WAIT, tokio::spawn(async { 42 }))
				.await
				.unwrap()
				.unwrap(),
			42
		);
		drop(held_record);
		for caller in callers {
			let record = caller.await.unwrap().unwrap().unwrap();
			assert_eq!(record.request_id, fixture.identity.request_id);
		}
		drain(&counts).await;
		assert_eq!(counts.maximum.load(Ordering::SeqCst), 12);
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
fn cancelled_queued_result_reads_retain_original_work_until_completion() {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(1)
		.build()
		.unwrap();
	runtime.block_on(async {
		let fixture = Fixture::new();
		let held_record = record_lock(&fixture.identity.request_id).unwrap();
		let mut release_pool = ReleaseBlockingPool::default();
		let (release, wait) = mpsc::channel();
		release_pool.0.push(release);
		let (blocked, blocking_notice) = tokio::sync::oneshot::channel();
		let blocker = tokio::task::spawn_blocking(move || {
			let _ = blocked.send(());
			wait.recv_timeout(WAIT).unwrap();
		});
		tokio::time::timeout(WAIT, blocking_notice)
			.await
			.unwrap()
			.unwrap();
		let counts = Arc::new(Counts::default());
		let (entered, mut notices) = tokio::sync::mpsc::unbounded_channel();
		for _ in 0..12 {
			let mut caller = Box::pin(run_result_read(observed_read(
				fixture.clone(),
				counts.clone(),
				entered.clone(),
			)));
			pending(caller.as_mut()).await;
			drop(caller);
		}
		assert_eq!(counts.entered.load(Ordering::SeqCst), 0);
		drop(held_record);
		drop(release_pool);
		blocker.await.unwrap();
		started(&mut notices, 12).await;
		drain(&counts).await;
		assert_eq!(counts.entered.load(Ordering::SeqCst), 12);
	});
}

#[tokio::test(flavor = "current_thread")]
async fn unpolled_result_read_never_submits_io() {
	let calls = Arc::new(AtomicUsize::new(0));
	let observed = calls.clone();
	drop(run_result_read(move || {
		observed.fetch_add(1, Ordering::SeqCst);
		Ok(None)
	}));
	tokio::task::yield_now().await;
	assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn result_read_success_refusal_missing_record_and_panic_preserve_results() {
	let fixture = Fixture::new();

	let original = fixture.clone();
	let record = run_result_read(move || original.read())
		.await
		.unwrap()
		.unwrap();
	assert_eq!(record.request_id, fixture.identity.request_id);
	assert_eq!(result_state(Some(&record), "host_health"), "unknown");

	let mut foreign = fixture.identity.clone();
	foreign.owner = "c".repeat(64);
	let expected = lookup_at(fixture.root.path(), &foreign, &fixture.binding)
		.err()
		.unwrap()
		.to_string();
	let original = fixture.clone();
	let error =
		run_result_read(move || lookup_at(original.root.path(), &foreign, &original.binding))
			.await
			.err()
			.unwrap();
	assert_eq!(error.to_string(), expected);

	let original = fixture.clone();
	assert!(run_result_read(move || {
		let mut missing = original.identity.clone();
		missing.request_id = format!("d1{:062x}", 2);
		lookup_at(original.root.path(), &missing, &original.binding)
	})
	.await
	.unwrap()
	.is_none());

	let error = run_result_read(|| panic!("fixture result-read panic must not return a record"))
		.await
		.err()
		.unwrap();
	assert_eq!(
		error.to_string(),
		"request result unavailable to this scope or current policy"
	);

	assert!(run_result_read(move || fixture.read()).await.is_ok());
}

#[test]
fn same_prefix_result_ids_are_independent_but_exact_id_remains_serialized() {
	let first_id = format!("cf{:062x}", 0xb16b00b5_u64);
	let second_id = format!("cf{:062x}", 0xb16b00b6_u64);
	let held = record_lock(&first_id).unwrap();
	let (other_send, other_recv) = mpsc::channel();
	let other = std::thread::spawn(move || {
		let _guard = record_lock(&second_id).unwrap();
		other_send.send(()).unwrap();
	});
	let (same_send, same_recv) = mpsc::channel();
	let same = std::thread::spawn(move || {
		let _guard = record_lock(&first_id).unwrap();
		same_send.send(()).unwrap();
	});
	let independent = other_recv.recv_timeout(Duration::from_secs(2));
	let serialized = same_recv.recv_timeout(Duration::from_millis(30));
	drop(held);
	other.join().unwrap();
	same.join().unwrap();
	assert!(independent.is_ok());
	assert!(matches!(serialized, Err(mpsc::RecvTimeoutError::Timeout)));
	same_recv.recv_timeout(WAIT).unwrap();
}

#[test]
fn poisoned_result_identity_does_not_poison_another_id_with_the_same_prefix() {
	let first_id = format!("ce{:062x}", 0xb16b00b5_u64);
	let second_id = format!("ce{:062x}", 0xb16b00b6_u64);
	let original = first_id.clone();
	assert!(std::thread::spawn(move || {
		let _guard = record_lock(&original).unwrap();
		panic!("poison only the original record identity");
	})
	.join()
	.is_err());
	assert!(record_lock(&first_id).is_err());
	assert!(record_lock(&second_id).is_ok());
}
