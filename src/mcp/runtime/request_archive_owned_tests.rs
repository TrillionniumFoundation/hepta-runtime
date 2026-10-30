// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Async registration, queued ownership and terminal publication ordering.
use super::*;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::task::{Context, Poll, Wake, Waker};

fn owner(index: usize) -> Query {
	Query {
		owner: format!("{index:064x}"),
		params: RequestHistoryParams {
			after_id: None,
			limit: Some(32),
		},
	}
}

fn budget() -> Instant {
	Instant::now() + Duration::from_secs(10)
}

fn trace(deadline: Instant) -> metadata_trace::QueryTrace {
	metadata_trace::QueryTrace::new("owned_test", deadline, 32, false)
}

fn replies(requests: &[Query]) -> ObservedPages {
	ObservedPages {
		replies: requests
			.iter()
			.map(|query| Ok(format!("private-{}", query.owner)))
			.collect(),
		large: true,
	}
}

fn runtime() -> tokio::runtime::Runtime {
	tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(1)
		.build()
		.unwrap()
}

// As in the existing blocking suite, direct membership tests inject a future
// entry clock instead of relying on OS scheduling inside the production 2 ms.
// Work::run tests fill all eight slots before start, so collection ends at the
// unchanged admission bound. Public execute_owned tests use its real clock.
struct Fixture {
	coordinator: Arc<Coordinator>,
	slots: Arc<Semaphore>,
	root: PathBuf,
	completion: Option<Completion>,
	waiters: Vec<AsyncWaiter>,
}
impl Fixture {
	fn new(deadline: Instant) -> Self {
		Self::at(
			Arc::new(Coordinator::default()),
			Arc::new(Semaphore::new(MAX_METADATA_QUERIES)),
			Path::new("/synthetic/owned"),
			deadline,
			Instant::now() + Duration::from_secs(30),
		)
	}

	fn at(
		coordinator: Arc<Coordinator>,
		slots: Arc<Semaphore>,
		root: &Path,
		deadline: Instant,
		entered: Instant,
	) -> Self {
		let permit = slots.clone().try_acquire_owned().unwrap();
		let registration = coordinator
			.register_owned(root, &owner(0), deadline, entered, permit, trace(deadline))
			.unwrap();
		let OwnedRegistration::Leader { completion, waiter } = registration else {
			panic!("test requires a new collecting group");
		};
		Self {
			coordinator,
			slots,
			root: root.to_path_buf(),
			completion: Some(completion),
			waiters: vec![waiter],
		}
	}

	fn add(&mut self, index: usize, deadline: Instant) {
		let registration = self
			.coordinator
			.register_owned(
				&self.root,
				&owner(index),
				deadline,
				Instant::now(),
				self.slots.clone().try_acquire_owned().unwrap(),
				trace(deadline),
			)
			.unwrap();
		let OwnedRegistration::Follower(waiter) = registration else {
			panic!("test requires the original collecting group");
		};
		self.waiters.push(waiter);
	}

	fn fill(&mut self, deadline: Instant) {
		for index in self.waiters.len()..MAX_METADATA_QUERIES {
			self.add(index, deadline);
		}
	}

	fn group(&self) -> Arc<Group> {
		self.completion.as_ref().unwrap().group.clone()
	}

	fn work<Q>(&mut self, operation: Q) -> Work<Q>
	where
		Q: FnOnce(&Path, &[Query], Instant) -> Result<ObservedPages>,
	{
		Work {
			operation: Some(operation),
			root: self.root.clone(),
			completion: self.completion.take().unwrap(),
		}
	}

	fn finish(&mut self, result: Result<ObservedPages>) {
		self.completion.as_mut().unwrap().stage(result);
		drop(self.completion.take());
	}
}

struct ReleaseOnDrop(Option<mpsc::Sender<()>>);
impl ReleaseOnDrop {
	fn release(&mut self) {
		if let Some(send) = self.0.take() {
			let _ = send.send(());
		}
	}
}
impl Drop for ReleaseOnDrop {
	fn drop(&mut self) {
		self.release();
	}
}

struct Cleanup(Arc<AtomicBool>);
impl Drop for Cleanup {
	fn drop(&mut self) {
		self.0.store(true, Ordering::Release);
	}
}

// Record, rather than panic during unwind, if a queued operation capture is
// destroyed after a permit or terminal state has already been published.
struct CaptureCleanup {
	slots: Arc<Semaphore>,
	group: Arc<Group>,
	cleaned: Arc<AtomicBool>,
	wrong_order: Arc<AtomicBool>,
}
impl Drop for CaptureCleanup {
	fn drop(&mut self) {
		let complete = self.group.cleanup_state().complete;
		self.wrong_order.store(
			self.slots.available_permits() != 0 || complete,
			Ordering::Release,
		);
		self.cleaned.store(true, Ordering::Release);
	}
}

#[derive(Debug)]
struct OriginalFailure;
impl std::fmt::Display for OriginalFailure {
	fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		out.write_str("owned-cohort original failure")
	}
}
impl std::error::Error for OriginalFailure {}

async fn until(mut condition: impl FnMut() -> bool) {
	tokio::time::timeout(Duration::from_secs(5), async {
		while !condition() {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
}

#[derive(Clone, Copy)]
enum IoCase {
	CancelLeader,
	CancelFollower,
	TimeoutAll,
	SharedError,
	ReaderUnwind,
	CoverageMismatch,
}

fn io_case(case: IoCase) {
	let runtime = runtime();
	runtime.block_on(async {
		let deadline = Instant::now()
			+ if matches!(case, IoCase::TimeoutAll) {
				Duration::from_secs(1)
			} else {
				Duration::from_secs(10)
			};
		let mut fixture = Fixture::new(deadline);
		fixture.coordinator.remember(&fixture.root, true);
		let group = fixture.group();
		let leader_waiter = fixture.waiters.pop().unwrap();
		let mut callers = vec![Some(tokio::spawn(async move {
			tokio::time::timeout_at(
				tokio::time::Instant::from_std(deadline),
				leader_waiter.result(trace(deadline)),
			)
			.await
			.map_err(|_| anyhow::Error::from(MetadataQueryDeadline))?
		}))];
		let follower_operations = Arc::new(AtomicUsize::new(0));
		// Every follower goes through the actual async admission and routing
		// function. The real owner has not been sent to the blocking pool yet.
		for index in 1..MAX_METADATA_QUERIES {
			let calls = follower_operations.clone();
			callers.push(Some(tokio::spawn(
				fixture.coordinator.clone().execute_owned(
					fixture.root.clone(),
					owner(index),
					deadline,
					fixture.slots.clone(),
					trace(deadline),
					move |_, _, _| {
						calls.fetch_add(1, Ordering::SeqCst);
						bail!("follower must not submit an independent observation")
					},
				),
			)));
		}
		until(|| group.cleanup_state().members.len() == MAX_METADATA_QUERIES).await;
		assert_eq!(fixture.slots.available_permits(), 0);
		assert_eq!(group.cleanup_state().permits.len(), MAX_METADATA_QUERIES);
		// With one blocking worker, a follower occupying the pool to wait for
		// this still-unsubmitted leader would prevent this sentinel completing.
		assert_eq!(
			tokio::time::timeout(Duration::from_secs(5), tokio::task::spawn_blocking(|| 17),)
				.await
				.unwrap()
				.unwrap(),
			17
		);
		let (started, ready) = tokio::sync::oneshot::channel();
		let (release, gate) = mpsc::channel();
		let mut release = ReleaseOnDrop(Some(release));
		let cleaned = Arc::new(AtomicBool::new(false));
		let reader_cleaned = cleaned.clone();
		let reads = Arc::new(AtomicUsize::new(0));
		let reader_calls = reads.clone();
		let work = fixture.work(move |_, requests, _| {
			reader_calls.fetch_add(1, Ordering::SeqCst);
			assert_eq!(requests.len(), MAX_METADATA_QUERIES);
			// Model a real scoped original-reader thread. Work must not publish
			// completion or release a permit until this join and its Drop finish.
			std::thread::scope(|scope| {
				let worker = scope.spawn(move || {
					let _cleanup = Cleanup(reader_cleaned);
					let _ = started.send(());
					gate.recv().unwrap();
					if matches!(case, IoCase::ReaderUnwind) {
						panic!("original reader unwind");
					}
				});
				if let Err(error) = worker.join() {
					std::panic::resume_unwind(error);
				}
			});
			match case {
				IoCase::SharedError => {
					Err(anyhow::Error::new(OriginalFailure).context("original validation failed"))
				}
				IoCase::CoverageMismatch => Ok(ObservedPages {
					replies: vec![Ok("incomplete coverage".to_owned())],
					large: true,
				}),
				_ => Ok(replies(requests)),
			}
		});
		let worker = tokio::task::spawn_blocking(move || work.run(trace(deadline)));
		tokio::time::timeout(Duration::from_secs(5), ready)
			.await
			.unwrap()
			.unwrap();
		assert!(!cleaned.load(Ordering::Acquire));
		match case {
			IoCase::CancelLeader | IoCase::CancelFollower => {
				let index = usize::from(matches!(case, IoCase::CancelFollower));
				let caller = callers[index].take().unwrap();
				caller.abort();
				assert!(tokio::time::timeout(Duration::from_secs(5), caller)
					.await
					.unwrap()
					.unwrap_err()
					.is_cancelled());
			}
			IoCase::TimeoutAll => {
				for caller in &mut callers {
					assert!(caller
						.take()
						.unwrap()
						.await
						.unwrap()
						.unwrap_err()
						.is::<MetadataQueryDeadline>());
				}
			}
			IoCase::SharedError | IoCase::ReaderUnwind | IoCase::CoverageMismatch => {}
		}
		assert_eq!(fixture.slots.available_permits(), 0);
		assert!(!group.cleanup_state().complete);
		assert!(!cleaned.load(Ordering::Acquire));
		release.release();
		let worker_result = worker.await;
		if matches!(case, IoCase::ReaderUnwind) {
			assert!(worker_result.unwrap_err().is_panic());
		} else {
			worker_result.unwrap();
		}
		assert!(cleaned.load(Ordering::Acquire));
		for (index, caller) in callers.into_iter().enumerate() {
			if let Some(caller) = caller {
				let result = tokio::time::timeout(Duration::from_secs(5), caller)
					.await
					.unwrap()
					.unwrap();
				match case {
					IoCase::SharedError => {
						assert!(result.unwrap_err().root_cause().is::<OriginalFailure>());
					}
					IoCase::ReaderUnwind | IoCase::CoverageMismatch => assert!(result.is_err()),
					_ => assert_eq!(result.unwrap(), format!("private-{}", owner(index).owner)),
				}
			}
		}
		assert_eq!(reads.load(Ordering::SeqCst), 1);
		assert_eq!(follower_operations.load(Ordering::SeqCst), 0);
		assert_eq!(fixture.slots.available_permits(), MAX_METADATA_QUERIES);
		assert!(group.cleanup_state().complete);
		assert!(group.cleanup_state().permits.is_empty());
		assert!(fixture
			.coordinator
			.registry
			.lock()
			.unwrap()
			.collecting
			.is_empty());
	});
}

#[test]
fn owned_leader_waiter_cancellation_keeps_all_permits_through_reader_join() {
	io_case(IoCase::CancelLeader);
}

#[test]
fn async_follower_cancellation_is_nonblocking_and_keeps_its_group_permit() {
	io_case(IoCase::CancelFollower);
}

#[test]
fn async_follower_timeouts_leave_all_eight_permits_with_original_work() {
	io_case(IoCase::TimeoutAll);
}

#[test]
fn owned_common_error_retains_original_cause_after_original_reader_cleanup() {
	io_case(IoCase::SharedError);
}

#[test]
fn original_reader_unwind_joins_and_cleans_before_owned_completion() {
	io_case(IoCase::ReaderUnwind);
}

#[test]
fn owned_reply_coverage_failure_never_publishes_partial_success() {
	io_case(IoCase::CoverageMismatch);
}

#[derive(Clone, Copy)]
enum QueueCase {
	CancelCaller,
	LateStart,
}

fn queued_public_case(case: QueueCase) {
	let runtime = runtime();
	runtime.block_on(async {
		let (entered, ready) = tokio::sync::oneshot::channel();
		let (release, gate) = mpsc::channel();
		let mut release = ReleaseOnDrop(Some(release));
		let blocking_owner = tokio::task::spawn_blocking(move || {
			let _ = entered.send(());
			gate.recv().unwrap();
		});
		ready.await.unwrap();
		let coordinator = Arc::new(Coordinator::default());
		let root = PathBuf::from("/synthetic/owned-queued-public");
		coordinator.remember(&root, true);
		let slots = Arc::new(Semaphore::new(1));
		let calls = Arc::new(AtomicUsize::new(0));
		let call_count = calls.clone();
		let deadline = Instant::now()
			+ if matches!(case, QueueCase::LateStart) {
				Duration::from_secs(1)
			} else {
				Duration::from_secs(10)
			};
		let caller = tokio::spawn(coordinator.clone().execute_owned(
			root,
			owner(0),
			deadline,
			slots.clone(),
			trace(deadline),
			move |_, requests, _| {
				call_count.fetch_add(1, Ordering::SeqCst);
				Ok(replies(requests))
			},
		));
		until(|| coordinator.registrations.load(Ordering::Relaxed) == 1).await;
		let group = coordinator.registry.lock().unwrap().collecting[0].1.clone();
		assert_eq!(slots.available_permits(), 0);
		assert_eq!(calls.load(Ordering::SeqCst), 0);
		match case {
			QueueCase::CancelCaller => {
				caller.abort();
				assert!(caller.await.unwrap_err().is_cancelled());
			}
			QueueCase::LateStart => {
				assert!(caller
					.await
					.unwrap()
					.unwrap_err()
					.is::<MetadataQueryDeadline>());
			}
		}
		assert_eq!(slots.available_permits(), 0);
		assert!(!group.cleanup_state().complete);
		release.release();
		blocking_owner.await.unwrap();
		until(|| group.cleanup_state().complete).await;
		assert_eq!(slots.available_permits(), 1);
		assert!(coordinator.registry.lock().unwrap().collecting.is_empty());
		assert_eq!(
			calls.load(Ordering::SeqCst),
			usize::from(matches!(case, QueueCase::CancelCaller))
		);
		assert_eq!(
			group.cleanup_state().expired,
			matches!(case, QueueCase::LateStart)
		);
	});
}

#[test]
fn public_async_leader_abort_does_not_release_queued_original_work() {
	queued_public_case(QueueCase::CancelCaller);
}

#[test]
fn public_async_deadline_before_blocking_start_performs_zero_observation() {
	queued_public_case(QueueCase::LateStart);
}

#[test]
fn aborted_queued_closure_destroys_captures_then_finalizes_without_io() {
	let runtime = runtime();
	runtime.block_on(async {
		let deadline = budget();
		let mut fixture = Fixture::new(deadline);
		fixture.fill(deadline);
		let group = fixture.group();
		let cleaned = Arc::new(AtomicBool::new(false));
		let wrong_order = Arc::new(AtomicBool::new(false));
		let cleanup = CaptureCleanup {
			slots: fixture.slots.clone(),
			group: group.clone(),
			cleaned: cleaned.clone(),
			wrong_order: wrong_order.clone(),
		};
		let calls = Arc::new(AtomicUsize::new(0));
		let operation_calls = calls.clone();
		let work = fixture.work(move |_, requests, _| {
			let _cleanup = cleanup;
			operation_calls.fetch_add(1, Ordering::SeqCst);
			Ok(replies(requests))
		});
		let (entered, ready) = tokio::sync::oneshot::channel();
		let (release, gate) = mpsc::channel();
		let mut release = ReleaseOnDrop(Some(release));
		let blocker = tokio::task::spawn_blocking(move || {
			let _ = entered.send(());
			gate.recv().unwrap();
		});
		ready.await.unwrap();
		let queued = tokio::task::spawn_blocking(move || work.run(trace(deadline)));
		queued.abort();
		// Tokio may retain the cancelled closure until its worker dequeues it.
		// Either way, only actual destruction may end custody.
		if !cleaned.load(Ordering::Acquire) {
			assert_eq!(fixture.slots.available_permits(), 0);
		}
		release.release();
		blocker.await.unwrap();
		assert!(queued.await.unwrap_err().is_cancelled());
		assert!(cleaned.load(Ordering::Acquire));
		assert!(!wrong_order.load(Ordering::Acquire));
		assert_eq!(calls.load(Ordering::SeqCst), 0);
		assert_eq!(fixture.slots.available_permits(), MAX_METADATA_QUERIES);
		assert!(group.cleanup_state().complete);
		for waiter in fixture.waiters {
			assert!(waiter.result(trace(deadline)).await.is_err());
		}
	});
}

#[test]
fn unsubmitted_owner_unwind_drops_captures_before_permits_and_has_no_arc_cycle() {
	let deadline = budget();
	let mut fixture = Fixture::new(deadline);
	fixture.fill(deadline);
	let group = fixture.group();
	let coordinator = Arc::downgrade(&fixture.coordinator);
	let slots = fixture.slots.clone();
	let cleaned = Arc::new(AtomicBool::new(false));
	let wrong_order = Arc::new(AtomicBool::new(false));
	let cleanup = CaptureCleanup {
		slots: slots.clone(),
		group: group.clone(),
		cleaned: cleaned.clone(),
		wrong_order: wrong_order.clone(),
	};
	let work = fixture.work(move |_, _, _| {
		let _cleanup = cleanup;
		panic!("never-submitted observation must not run");
	});
	let waiters = std::mem::take(&mut fixture.waiters);
	drop(fixture);
	assert!(coordinator.upgrade().is_some());
	let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
		let _queued = move || work.run(trace(deadline));
		panic!("synthetic submission unwind");
	}));
	assert!(result.is_err());
	assert!(cleaned.load(Ordering::Acquire));
	assert!(!wrong_order.load(Ordering::Acquire));
	assert_eq!(slots.available_permits(), MAX_METADATA_QUERIES);
	assert!(group.cleanup_state().complete);
	assert!(coordinator.upgrade().is_none());
	runtime().block_on(async {
		for waiter in waiters {
			assert!(waiter.result(trace(deadline)).await.is_err());
		}
	});
}

struct CompletionWake {
	group: Arc<Group>,
	slots: Arc<Semaphore>,
	expected_permits: usize,
	wakes: AtomicUsize,
	wrong_order: AtomicBool,
}
impl Wake for CompletionWake {
	fn wake(self: Arc<Self>) {
		self.wake_by_ref();
	}

	fn wake_by_ref(self: &Arc<Self>) {
		let complete = self.group.cleanup_state().complete;
		self.wrong_order.fetch_or(
			!complete || self.slots.available_permits() != self.expected_permits,
			Ordering::Release,
		);
		self.wakes.fetch_add(1, Ordering::SeqCst);
	}
}

fn notify_case(complete_before_poll: bool) {
	let deadline = budget();
	let mut fixture = Fixture::new(deadline);
	fixture.add(1, deadline);
	let group = fixture.group();
	let frozen = fixture.completion.as_ref().unwrap().freeze().unwrap();
	let wake = Arc::new(CompletionWake {
		group: group.clone(),
		slots: fixture.slots.clone(),
		expected_permits: MAX_METADATA_QUERIES,
		wakes: AtomicUsize::new(0),
		wrong_order: AtomicBool::new(false),
	});
	let waker = Waker::from(wake.clone());
	let mut context = Context::from_waker(&waker);
	let waiter = fixture.waiters.remove(0);
	let mut future = Box::pin(waiter.result(trace(deadline)));
	if !complete_before_poll {
		assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
	}
	fixture.finish(Ok(replies(&frozen.requests)));
	assert!(group.cleanup_state().complete);
	assert_eq!(fixture.slots.available_permits(), MAX_METADATA_QUERIES);
	let Poll::Ready(result) = future.as_mut().poll(&mut context) else {
		panic!("a terminal group must not lose its notification");
	};
	assert_eq!(result.unwrap(), format!("private-{}", owner(0).owner));
	assert!(!wake.wrong_order.load(Ordering::Acquire));
	if !complete_before_poll {
		assert!(wake.wakes.load(Ordering::SeqCst) > 0);
	}
	// A second waiter first polled after publication must use persistent state.
	let second = fixture.waiters.pop().unwrap();
	let mut second = Box::pin(second.result(trace(deadline)));
	assert!(matches!(
		second.as_mut().poll(&mut context),
		Poll::Ready(Ok(_))
	));
}

#[test]
fn completion_before_first_poll_is_persistent_for_each_private_reply() {
	notify_case(true);
}

#[test]
fn enabled_notification_wakes_only_after_permit_release_and_complete() {
	notify_case(false);
}

#[test]
fn cancelled_earliest_member_keeps_minimum_deadline_and_blocks_late_io() {
	let runtime = runtime();
	runtime.block_on(async {
		let leader_deadline = budget();
		let earlier_deadline = Instant::now() + Duration::from_secs(1);
		let mut fixture = Fixture::new(leader_deadline);
		fixture.add(1, earlier_deadline);
		let group = fixture.group();
		drop(fixture.waiters.pop());
		assert_eq!(group.cleanup_state().deadline(), earlier_deadline);
		assert_eq!(group.cleanup_state().members.len(), 2);
		assert_eq!(fixture.slots.available_permits(), MAX_METADATA_QUERIES - 2);
		tokio::time::sleep_until(tokio::time::Instant::from_std(earlier_deadline)).await;
		let calls = Arc::new(AtomicUsize::new(0));
		let read_calls = calls.clone();
		let work = fixture.work(move |_, requests, _| {
			read_calls.fetch_add(1, Ordering::SeqCst);
			Ok(replies(requests))
		});
		tokio::task::spawn_blocking(move || work.run(trace(leader_deadline)))
			.await
			.unwrap();
		assert_eq!(calls.load(Ordering::SeqCst), 0);
		assert_eq!(fixture.slots.available_permits(), MAX_METADATA_QUERIES);
		assert!(group.cleanup_state().expired);
		assert!(fixture
			.waiters
			.pop()
			.unwrap()
			.result(trace(leader_deadline))
			.await
			.unwrap_err()
			.is::<MetadataQueryDeadline>());
	});
}

#[test]
fn old_owned_completion_removes_only_its_identity_and_preserves_successor_custody() {
	let deadline = budget();
	let coordinator = Arc::new(Coordinator::default());
	let slots = Arc::new(Semaphore::new(2));
	let root = Path::new("/synthetic/owned-successor");
	let mut old = Fixture::at(
		coordinator.clone(),
		slots.clone(),
		root,
		deadline,
		Instant::now() - Duration::from_secs(1),
	);
	let mut next = Fixture::at(
		coordinator.clone(),
		slots.clone(),
		root,
		deadline,
		Instant::now() + Duration::from_secs(30),
	);
	let next_group = next.group();
	assert_eq!(slots.available_permits(), 0);
	drop(old.completion.take());
	assert_eq!(slots.available_permits(), 1);
	assert!(!next_group.cleanup_state().complete);
	let registry = coordinator.registry.lock().unwrap();
	assert_eq!(registry.collecting.len(), 1);
	assert!(Arc::ptr_eq(&registry.collecting[0].1, &next_group));
	drop(registry);
	let frozen = next.completion.as_ref().unwrap().freeze().unwrap();
	next.finish(Ok(replies(&frozen.requests)));
	assert_eq!(slots.available_permits(), 2);
	runtime().block_on(async {
		assert!(old
			.waiters
			.pop()
			.unwrap()
			.result(trace(deadline))
			.await
			.is_err());
		assert!(next
			.waiters
			.pop()
			.unwrap()
			.result(trace(deadline))
			.await
			.is_ok());
	});
}

#[derive(Clone, Copy)]
enum Poison {
	Registry,
	Group,
	Reply,
}

#[test]
fn poisoned_owned_coordination_drains_every_permit_and_refuses_all_successes() {
	for poison in [Poison::Registry, Poison::Group, Poison::Reply] {
		let deadline = budget();
		let mut fixture = Fixture::new(deadline);
		fixture.fill(deadline);
		let group = fixture.group();
		let frozen = fixture.completion.as_ref().unwrap().freeze().unwrap();
		fixture
			.completion
			.as_mut()
			.unwrap()
			.stage(Ok(replies(&frozen.requests)));
		let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match poison {
			Poison::Registry => {
				let _guard = fixture.coordinator.registry.lock().unwrap();
				panic!("poison owned registry");
			}
			Poison::Group => {
				let _guard = group.state.lock().unwrap();
				panic!("poison owned group");
			}
			Poison::Reply => {
				let _guard = fixture.waiters[0].reply.value.lock().unwrap();
				panic!("poison private reply slot");
			}
		}));
		assert!(result.is_err());
		drop(fixture.completion.take());
		assert_eq!(fixture.slots.available_permits(), MAX_METADATA_QUERIES);
		assert!(group.cleanup_state().complete);
		assert!(group.cleanup_state().failed);
		assert!(group.cleanup_state().permits.is_empty());
		runtime().block_on(async {
			for waiter in fixture.waiters {
				assert!(waiter.result(trace(deadline)).await.is_err());
			}
		});
	}
}

#[test]
fn poisoned_hint_registry_preserves_public_unhinted_singleton_behavior() {
	let runtime = runtime();
	runtime.block_on(async {
		let coordinator = Arc::new(Coordinator::default());
		let poisoned = coordinator.clone();
		assert!(std::panic::catch_unwind(move || {
			let _guard = poisoned.registry.lock().unwrap();
			panic!("poison a scheduling hint only");
		})
		.is_err());
		let deadline = budget();
		let slots = Arc::new(Semaphore::new(1));
		let result = coordinator
			.clone()
			.execute_owned(
				PathBuf::from("/synthetic/owned-unhinted"),
				owner(0),
				deadline,
				slots.clone(),
				trace(deadline),
				|_, requests, _| Ok(replies(requests)),
			)
			.await;
		assert_eq!(result.unwrap(), format!("private-{}", owner(0).owner));
		assert_eq!(slots.available_permits(), 1);
		assert_eq!(coordinator.registrations.load(Ordering::Relaxed), 0);
	});
}

#[test]
fn invalid_or_admission_expired_public_call_cannot_register_or_observe() {
	let runtime = runtime();
	runtime.block_on(async {
		let coordinator = Arc::new(Coordinator::default());
		let root = PathBuf::from("/synthetic/owned-no-admission");
		coordinator.remember(&root, true);
		let slots = Arc::new(Semaphore::new(1));
		let held = slots.clone().try_acquire_owned().unwrap();
		let mut invalid = owner(0);
		invalid.params.limit = Some(0);
		let deadline = budget();
		let result = coordinator
			.clone()
			.execute_owned(
				root.clone(),
				invalid,
				deadline,
				slots.clone(),
				trace(deadline),
				|_, _, _| panic!("invalid caller must not observe"),
			)
			.await;
		assert!(result
			.unwrap_err()
			.to_string()
			.contains("invalid request archive page"));
		let deadline = Instant::now() + Duration::from_millis(25);
		let result = coordinator
			.clone()
			.execute_owned(
				root,
				owner(0),
				deadline,
				slots.clone(),
				trace(deadline),
				|_, _, _| panic!("non-admitted caller must not observe"),
			)
			.await;
		assert!(result.unwrap_err().is::<MetadataQueryDeadline>());
		assert_eq!(coordinator.registrations.load(Ordering::Relaxed), 0);
		assert!(coordinator.registry.lock().unwrap().collecting.is_empty());
		assert_eq!(slots.available_permits(), 0);
		drop(held);
		assert_eq!(slots.available_permits(), 1);
	});
}
