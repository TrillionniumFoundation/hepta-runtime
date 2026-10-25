// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Fixed membership, private replies and actual blocking-closure custody.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

fn owner(index: usize) -> String {
	format!("{index:064x}")
}
fn budget() -> Instant {
	Instant::now() + Duration::from_secs(10)
}
fn replies(owners: &[String]) -> ObservedUsage {
	ObservedUsage {
		replies: owners
			.iter()
			.map(|owner| Ok(format!("private-{owner}")))
			.collect(),
		large: true,
	}
}

// Membership tests use a future entry clock and call freeze directly. They do
// not depend on scheduling four OS threads within 1 ms. The real fixed cutoff
// and its elapsed collection path are checked separately below.
struct FixedGroup<'a> {
	coordinator: &'a Coordinator,
	root: PathBuf,
	completion: Option<Completion<'a>>,
	leader: Option<Waiter>,
	followers: Vec<Waiter>,
}
impl<'a> FixedGroup<'a> {
	fn at(coordinator: &'a Coordinator, root: &Path, first: &str, entered: Instant) -> Self {
		match coordinator
			.register(root, first, budget(), entered)
			.unwrap()
		{
			Registration::Leader { completion, waiter } => Self {
				coordinator,
				root: root.to_path_buf(),
				completion: Some(completion),
				leader: Some(waiter),
				followers: Vec::new(),
			},
			Registration::Follower(mut waiter) => {
				// A failed synthetic membership assertion must be able to unwind
				// to the old FixedGroup that this thread still owns. No real I/O
				// or semaphore permit exists on this test-only failure path.
				waiter.follower_custody = false;
				panic!("expected a new test group");
			}
		}
	}
	fn new(coordinator: &'a Coordinator, root: &Path, first: &str) -> Self {
		Self::at(
			coordinator,
			root,
			first,
			Instant::now() + Duration::from_secs(30),
		)
	}
	fn add(&mut self, owner: &str, deadline: Instant) {
		match self
			.coordinator
			.register(
				&self.root,
				owner,
				deadline,
				Instant::now() + Duration::from_secs(60),
			)
			.unwrap()
		{
			Registration::Follower(waiter) => self.followers.push(waiter),
			Registration::Leader { .. } => panic!("expected the still collecting test group"),
		}
	}
	fn freeze(&self) -> Frozen {
		self.completion.as_ref().unwrap().freeze().unwrap()
	}
	fn finish(&mut self, result: Result<ObservedUsage>) {
		self.completion.as_mut().unwrap().stage(result);
		drop(self.completion.take());
	}
	fn results(&mut self) -> Vec<Result<String>> {
		let mut results = vec![self.leader.take().unwrap().result()];
		results.extend(self.followers.drain(..).map(Waiter::result));
		results
	}
}
impl Drop for FixedGroup<'_> {
	fn drop(&mut self) {
		// Also releases waiters after a failed assertion in the test itself.
		drop(self.completion.take());
	}
}

#[derive(Debug)]
struct OriginalFailure;
impl std::fmt::Display for OriginalFailure {
	fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		out.write_str("original test failure")
	}
}
impl std::error::Error for OriginalFailure {}

#[test]
fn frozen_different_owners_share_one_new_observation_and_private_slots() {
	let coordinator = Coordinator::default();
	let root = Path::new("/synthetic/fixed-usage");
	let mut group = FixedGroup::new(&coordinator, root, &owner(0));
	for index in 1..4 {
		group.add(&owner(index), budget());
	}
	// Repeated owner strings still have distinct request/result channels.
	group.add(&owner(0), budget());
	let frozen = group.freeze();
	assert!(coordinator.registry.lock().unwrap().collecting.is_empty());
	let calls = AtomicUsize::new(0);
	let result = coordinator.observe(root, &frozen.owners, frozen.deadline, |_, owners, _| {
		calls.fetch_add(1, Ordering::SeqCst);
		assert_eq!(owners, &[owner(0), owner(1), owner(2), owner(3), owner(0)]);
		Ok(replies(owners))
	});
	group.finish(result);
	let actual: Vec<_> = group.results().into_iter().map(Result::unwrap).collect();
	let expected: Vec<_> = frozen
		.owners
		.iter()
		.map(|owner| format!("private-{owner}"))
		.collect();
	assert_eq!(actual, expected);
	assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn local_projection_failure_does_not_reject_another_owner() {
	let coordinator = Coordinator::default();
	let mut group = FixedGroup::new(&coordinator, Path::new("/synthetic/local"), &owner(0));
	group.add(&owner(1), budget());
	group.freeze();
	group.finish(Ok(ObservedUsage {
		replies: vec![
			Err(anyhow::Error::new(OriginalFailure).context("owner wire budget")),
			Ok("only-owner-one".to_owned()),
		],
		large: true,
	}));
	let mut results = group.results().into_iter();
	let error = results.next().unwrap().unwrap_err();
	assert!(error.root_cause().is::<OriginalFailure>());
	assert_eq!(results.next().unwrap().unwrap(), "only-owner-one");
	assert!(!metadata_query_public_error(error)
		.to_string()
		.contains("owner wire budget"));
}

#[test]
fn common_failure_retains_its_cause_chain_and_typed_deadline_category() {
	let coordinator = Coordinator::default();
	let mut group = FixedGroup::new(&coordinator, Path::new("/synthetic/common"), &owner(0));
	group.add(&owner(1), budget());
	group.freeze();
	group.finish(Err(anyhow::Error::new(OriginalFailure)
		.context("complete original validation")
		.context(MetadataQueryDeadline)));
	for result in group.results() {
		let error = result.unwrap_err();
		assert!(error.is::<MetadataQueryDeadline>());
		assert!(error.root_cause().is::<OriginalFailure>());
		assert!(error
			.chain()
			.any(|cause| cause.to_string() == "complete original validation"));
		assert!(metadata_query_public_error(error).is::<MetadataQueryDeadline>());
	}
}

#[test]
fn late_error_gets_typed_common_deadline_without_losing_the_original_cause() {
	let coordinator = Coordinator::default();
	let deadline = Instant::now() + Duration::from_secs(1);
	let result = coordinator.observe(
		Path::new("/synthetic/late-error"),
		&[owner(0)],
		deadline,
		|_, _, deadline| {
			std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
			Err(anyhow::Error::new(OriginalFailure).context("original read error"))
		},
	);
	let error = result.err().unwrap();
	assert!(error.is::<MetadataQueryDeadline>());
	assert!(error.root_cause().is::<OriginalFailure>());
	assert!(error
		.chain()
		.any(|cause| cause.to_string() == "original read error"));
}

#[test]
fn freeze_excludes_late_callers_and_completed_results_are_not_reused() {
	let coordinator = Coordinator::default();
	let root = Path::new("/synthetic/no-late-join");
	let mut first = FixedGroup::new(&coordinator, root, &owner(0));
	let a = first.freeze();
	let mut second = FixedGroup::new(&coordinator, root, &owner(1));
	assert!(!Arc::ptr_eq(
		&first.leader.as_ref().unwrap().group,
		&second.leader.as_ref().unwrap().group
	));
	first.finish(Ok(replies(&a.owners)));
	assert_eq!(first.results().len(), 1);
	let b = second.freeze();
	second.finish(Ok(replies(&b.owners)));
	assert_eq!(second.results().len(), 1);
	let mut third = FixedGroup::new(&coordinator, root, &owner(0));
	let c = third.freeze();
	third.finish(Ok(replies(&c.owners)));
	assert_eq!(third.results().len(), 1);
}

#[test]
fn expired_old_group_cannot_remove_or_freeze_its_new_same_root_successor() {
	let coordinator = Coordinator::default();
	let root = Path::new("/synthetic/cutoff-race");
	let mut old = FixedGroup::at(
		&coordinator,
		root,
		&owner(0),
		Instant::now() - Duration::from_secs(1),
	);
	let mut next = FixedGroup::new(&coordinator, root, &owner(1));
	let old_frozen = old.freeze();
	assert_eq!(coordinator.registry.lock().unwrap().collecting.len(), 1);
	old.finish(Ok(replies(&old_frozen.owners)));
	next.add(&owner(2), budget());
	let next_frozen = next.freeze();
	assert_eq!(next_frozen.owners, vec![owner(1), owner(2)]);
	next.finish(Ok(replies(&next_frozen.owners)));
	assert!(old.results().into_iter().all(|result| result.is_ok()));
	assert!(next.results().into_iter().all(|result| result.is_ok()));
}

#[test]
fn different_root_keys_never_share_a_group() {
	let coordinator = Coordinator::default();
	let mut first = FixedGroup::new(&coordinator, Path::new("/synthetic/root-a"), &owner(0));
	let mut second = FixedGroup::new(&coordinator, Path::new("/synthetic/root-b"), &owner(0));
	assert_eq!(coordinator.registry.lock().unwrap().collecting.len(), 2);
	let a = first.freeze();
	let b = second.freeze();
	first.finish(Ok(ObservedUsage {
		replies: vec![Ok("root-a".into())],
		large: true,
	}));
	second.finish(Ok(ObservedUsage {
		replies: vec![Ok("root-b".into())],
		large: true,
	}));
	assert_eq!(a.owners, b.owners);
	assert_eq!(first.results().pop().unwrap().unwrap(), "root-a");
	assert_eq!(second.results().pop().unwrap().unwrap(), "root-b");
}

#[test]
fn fixed_cutoff_is_one_millisecond_and_new_members_never_extend_it() {
	let coordinator = Coordinator::default();
	let entered = Instant::now() + Duration::from_secs(30);
	let mut group = FixedGroup::at(
		&coordinator,
		Path::new("/synthetic/fixed-window"),
		&owner(0),
		entered,
	);
	let earlier = Instant::now() + Duration::from_secs(5);
	group.add(&owner(1), earlier);
	assert_eq!(COLLECT_WINDOW, Duration::from_millis(1));
	assert_eq!(
		group.completion.as_ref().unwrap().group.collect_until,
		entered + Duration::from_millis(1)
	);
	let frozen = group.freeze();
	assert_eq!(frozen.deadline, earlier);
	group.finish(Ok(replies(&frozen.owners)));
	assert!(group.results().into_iter().all(|result| result.is_ok()));
}

#[test]
fn real_collect_waits_only_for_the_original_fixed_cutoff() {
	let coordinator = Coordinator::default();
	let entered = Instant::now();
	let mut group = FixedGroup::at(
		&coordinator,
		Path::new("/synthetic/real-window"),
		&owner(0),
		entered,
	);
	group.completion.as_ref().unwrap().collect().unwrap();
	assert!(Instant::now() >= entered + COLLECT_WINDOW);
	let frozen = group.freeze();
	group.finish(Ok(replies(&frozen.owners)));
	assert!(group.results().pop().unwrap().is_ok());
}

#[test]
fn unregistered_expired_member_cannot_poison_a_healthy_groups_deadline() {
	let coordinator = Coordinator::default();
	let root = Path::new("/synthetic/expired-arrival");
	let mut group = FixedGroup::new(&coordinator, root, &owner(0));
	let before = group
		.completion
		.as_ref()
		.unwrap()
		.group
		.state
		.lock()
		.unwrap()
		.deadline();
	let error = coordinator
		.register(root, &owner(1), Instant::now(), Instant::now())
		.err()
		.expect("an already expired member must not register");
	assert!(error.is::<MetadataQueryDeadline>());
	let frozen = group.freeze();
	assert_eq!(frozen.owners, vec![owner(0)]);
	assert_eq!(frozen.deadline, before);
	group.finish(Ok(replies(&frozen.owners)));
	assert!(group.results().pop().unwrap().is_ok());
}

#[test]
fn invalid_owner_and_expired_entry_do_not_observe_or_change_membership() {
	let coordinator = Coordinator::default();
	let root = Path::new("/synthetic/invalid-scope");
	coordinator.remember(root, true);
	let mut group = FixedGroup::new(&coordinator, root, &owner(0));
	let calls = AtomicUsize::new(0);
	for (scope, deadline) in [
		("not-an-owner".to_owned(), budget()),
		(owner(1), Instant::now()),
	] {
		assert!(coordinator
			.execute(
				root,
				std::array::from_ref(&scope),
				deadline,
				|_, owners, _| {
					calls.fetch_add(1, Ordering::SeqCst);
					Ok(replies(owners))
				}
			)
			.is_err());
	}
	assert_eq!(calls.load(Ordering::SeqCst), 0);
	let frozen = group.freeze();
	assert_eq!(frozen.owners, vec![owner(0)]);
	group.finish(Ok(replies(&frozen.owners)));
}

#[test]
fn hints_are_bounded_and_never_replace_a_complete_observation() {
	let coordinator = Coordinator::default();
	let root = Path::new("/synthetic/hint");
	let calls = AtomicUsize::new(0);
	assert!(!coordinator.large_hint(root));
	for large in [false, true, false] {
		coordinator
			.execute(
				root,
				std::array::from_ref(&owner(0)),
				budget(),
				|_, owners, _| {
					calls.fetch_add(1, Ordering::SeqCst);
					assert!(coordinator.registry.lock().unwrap().collecting.is_empty());
					let mut observed = replies(owners);
					observed.large = large;
					Ok(observed)
				},
			)
			.unwrap();
		assert_eq!(coordinator.large_hint(root), large);
	}
	assert_eq!(calls.load(Ordering::SeqCst), 3);
	for index in 0..MAX_HINTS + 2 {
		coordinator.remember(&PathBuf::from(format!("/synthetic/hint-{index}")), true);
	}
	assert_eq!(
		coordinator.registry.lock().unwrap().large_roots.len(),
		MAX_HINTS
	);
	assert!(!coordinator.large_hint(Path::new("/synthetic/hint-0")));
}

#[test]
fn one_group_cannot_accept_more_than_the_existing_eight_admitted_slots() {
	let coordinator = Coordinator::default();
	let root = Path::new("/synthetic/eight");
	let mut full = FixedGroup::new(&coordinator, root, &owner(0));
	for index in 1..MAX_METADATA_QUERIES {
		full.add(&owner(index), budget());
	}
	let mut next = FixedGroup::new(&coordinator, root, &owner(8));
	let frozen = full.freeze();
	assert_eq!(frozen.owners.len(), MAX_METADATA_QUERIES);
	assert_eq!(coordinator.registry.lock().unwrap().collecting.len(), 1);
	full.finish(Ok(replies(&frozen.owners)));
	let next_frozen = next.freeze();
	next.finish(Ok(replies(&next_frozen.owners)));
	assert_eq!(full.results().len(), MAX_METADATA_QUERIES);
	assert_eq!(next.results().len(), 1);
}

#[test]
fn final_common_failure_discards_all_staged_owner_successes() {
	let coordinator = Coordinator::default();
	let mut group = FixedGroup::new(&coordinator, Path::new("/synthetic/final-fence"), &owner(0));
	group.add(&owner(1), budget());
	let frozen = group.freeze();
	let original_error = coordinator.observe(
		&group.root,
		&frozen.owners,
		frozen.deadline,
		|_, owners, _| {
			let _unpublished = replies(owners);
			Err(anyhow::Error::new(OriginalFailure).context("final namespace fence"))
		},
	);
	group.finish(original_error);
	for result in group.results() {
		assert!(result.unwrap_err().root_cause().is::<OriginalFailure>());
	}
}

struct ReleaseOnDrop(Option<mpsc::Sender<()>>);
impl ReleaseOnDrop {
	fn release(&mut self) {
		if let Some(sender) = self.0.take() {
			let _ = sender.send(());
		}
	}
}
impl Drop for ReleaseOnDrop {
	fn drop(&mut self) {
		self.release();
	}
}
struct IoCleanup(Arc<AtomicBool>);
impl Drop for IoCleanup {
	fn drop(&mut self) {
		self.0.store(true, Ordering::Release);
	}
}

#[derive(Clone, Copy)]
enum ClosureCase {
	CancelLeader,
	CancelFollower,
	TimeoutBoth,
	SharedError,
	LeaderUnwind,
}

fn closure_case(case: ClosureCase) {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(4)
		.build()
		.unwrap();
	runtime.block_on(async {
		let coordinator = Arc::new(Coordinator::default());
		let slots = Arc::new(Semaphore::new(2));
		let cleaned = Arc::new(AtomicBool::new(false));
		let follower_saw_cleanup = Arc::new(AtomicBool::new(false));
		let (leader_admitted, leader_ready) = tokio::sync::oneshot::channel();
		let (follower_admitted, follower_ready) = tokio::sync::oneshot::channel();
		let (io_started, io_ready) = tokio::sync::oneshot::channel();
		let (freeze_sender, freeze_receiver) = mpsc::channel();
		let (io_sender, io_receiver) = mpsc::channel();
		// On any assertion failure these release the same original closures
		// before Runtime::drop waits for its blocking pool.
		let mut release_io = ReleaseOnDrop(Some(io_sender));
		let mut release_freeze = ReleaseOnDrop(Some(freeze_sender));
		let deadline = Instant::now()
			+ if matches!(case, ClosureCase::TimeoutBoth) {
				Duration::from_secs(1)
			} else {
				Duration::from_secs(10)
			};
		let leader_coordinator = coordinator.clone();
		let leader_cleaned = cleaned.clone();
		let leader = tokio::spawn(run_metadata_query(
			deadline,
			slots.clone(),
			move |deadline| {
				let registration = leader_coordinator.register(
					Path::new("/synthetic/closure"),
					&owner(0),
					deadline,
					Instant::now() + Duration::from_secs(30),
				)?;
				let Registration::Leader {
					mut completion,
					waiter,
				} = registration
				else {
					bail!("test leader unexpectedly joined another group");
				};
				let _ = leader_admitted.send(());
				freeze_receiver
					.recv()
					.map_err(|_| anyhow!("test freeze gate closed"))?;
				let frozen = completion.freeze()?;
				let result = (|| {
					let _io = IoCleanup(leader_cleaned);
					let _ = io_started.send(());
					io_receiver
						.recv()
						.map_err(|_| anyhow!("test I/O gate closed"))?;
					match case {
						ClosureCase::LeaderUnwind => panic!("test leader unwind after I/O"),
						ClosureCase::SharedError => Err(anyhow::Error::new(OriginalFailure)
							.context("test full validation failed")),
						_ => Ok(replies(&frozen.owners)),
					}
				})();
				completion.stage(result);
				drop(completion);
				waiter.result()
			},
		));
		tokio::time::timeout(Duration::from_secs(5), leader_ready)
			.await
			.unwrap()
			.unwrap();
		let follower_coordinator = coordinator.clone();
		let follower_cleaned = cleaned.clone();
		let follower_observed = follower_saw_cleanup.clone();
		let follower = tokio::spawn(run_metadata_query(
			deadline,
			slots.clone(),
			move |deadline| {
				let registration = follower_coordinator.register(
					Path::new("/synthetic/closure"),
					&owner(1),
					deadline,
					Instant::now(),
				)?;
				let Registration::Follower(waiter) = registration else {
					bail!("test follower failed to join the fixed group");
				};
				let _ = follower_admitted.send(());
				let result = waiter.result();
				follower_observed
					.store(follower_cleaned.load(Ordering::Acquire), Ordering::Release);
				result
			},
		));
		tokio::time::timeout(Duration::from_secs(5), follower_ready)
			.await
			.unwrap()
			.unwrap();
		release_freeze.release();
		tokio::time::timeout(Duration::from_secs(5), io_ready)
			.await
			.unwrap()
			.unwrap();
		assert_eq!(slots.available_permits(), 0);
		assert!(!cleaned.load(Ordering::Acquire));
		let mut leader = Some(leader);
		let mut follower = Some(follower);
		match case {
			ClosureCase::CancelLeader => {
				leader.as_ref().unwrap().abort();
				assert!(leader.take().unwrap().await.unwrap_err().is_cancelled());
			}
			ClosureCase::CancelFollower => {
				follower.as_ref().unwrap().abort();
				assert!(follower.take().unwrap().await.unwrap_err().is_cancelled());
			}
			ClosureCase::TimeoutBoth => {
				assert!(leader
					.take()
					.unwrap()
					.await
					.unwrap()
					.unwrap_err()
					.is::<MetadataQueryDeadline>());
				assert!(follower
					.take()
					.unwrap()
					.await
					.unwrap()
					.unwrap_err()
					.is::<MetadataQueryDeadline>());
			}
			ClosureCase::SharedError | ClosureCase::LeaderUnwind => {}
		}
		assert_eq!(slots.available_permits(), 0);
		assert!(slots.clone().try_acquire_owned().is_err());
		assert!(!follower_saw_cleanup.load(Ordering::Acquire));
		release_io.release();
		for task in [leader, follower].into_iter().flatten() {
			let result = tokio::time::timeout(Duration::from_secs(5), task)
				.await
				.unwrap()
				.unwrap();
			match case {
				ClosureCase::SharedError => {
					assert!(result.unwrap_err().root_cause().is::<OriginalFailure>());
				}
				ClosureCase::LeaderUnwind => assert!(result.is_err()),
				_ => assert!(result.is_ok()),
			}
		}
		let drained =
			tokio::time::timeout(Duration::from_secs(5), slots.clone().acquire_many_owned(2))
				.await
				.unwrap()
				.unwrap();
		assert!(cleaned.load(Ordering::Acquire));
		assert!(follower_saw_cleanup.load(Ordering::Acquire));
		drop(drained);
		assert_eq!(slots.available_permits(), 2);
	});
}

#[test]
fn cancelled_leader_async_handle_does_not_release_either_actual_closures_permit() {
	closure_case(ClosureCase::CancelLeader);
}
#[test]
fn cancelled_follower_async_handle_keeps_its_permit_until_actual_leader_cleanup() {
	closure_case(ClosureCase::CancelFollower);
}
#[test]
fn both_async_timeouts_keep_all_admitted_permits_until_actual_io_cleanup() {
	closure_case(ClosureCase::TimeoutBoth);
}
#[test]
fn shared_error_releases_every_waiter_after_io_cleanup_and_preserves_the_cause() {
	closure_case(ClosureCase::SharedError);
}
#[test]
fn unwinding_leader_releases_every_waiter_only_after_io_guard_cleanup() {
	closure_case(ClosureCase::LeaderUnwind);
}

#[test]
fn follower_unwind_custody_and_spurious_wakeup_do_not_escape_unfinished_work() {
	let coordinator = Coordinator::default();
	std::thread::scope(|scope| {
		let mut group = FixedGroup::new(
			&coordinator,
			Path::new("/synthetic/follower-unwind"),
			&owner(0),
		);
		group.add(&owner(1), budget());
		let frozen = group.freeze();
		let original_waiter = &group.followers[0];
		let shared = original_waiter.group.clone();
		let thread_group = shared.clone();
		let thread_reply = original_waiter.reply.clone();
		let thread_deadline = original_waiter.deadline;
		let cleanup = Arc::new(AtomicBool::new(false));
		let observed_cleanup = cleanup.clone();
		let (started, ready) = mpsc::channel();
		let (finished, done) = mpsc::channel();
		let follower = scope.spawn(move || {
			// Activate custody only after successful thread creation. A failed
			// spawn drops plain Arc snapshots in the parent, never a waiting
			// guard before that parent's FixedGroup can publish completion.
			let waiter = Waiter {
				group: thread_group,
				reply: thread_reply,
				deadline: thread_deadline,
				follower_custody: true,
			};
			let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
				let _custody = waiter;
				started.send(()).unwrap();
				panic!("test follower unwind");
			}));
			finished
				.send(observed_cleanup.load(Ordering::Acquire))
				.unwrap();
			assert!(result.is_err());
		});
		ready.recv_timeout(Duration::from_secs(5)).unwrap();
		shared.changed.notify_all();
		assert!(matches!(
			done.recv_timeout(Duration::from_millis(20)),
			Err(mpsc::RecvTimeoutError::Timeout)
		));
		cleanup.store(true, Ordering::Release);
		group.finish(Ok(replies(&frozen.owners)));
		assert!(done.recv_timeout(Duration::from_secs(5)).unwrap());
		follower.join().unwrap();
		assert!(group.leader.take().unwrap().result().is_ok());
	});
}

#[test]
fn poisoned_group_waits_for_real_completion_then_refuses_success() {
	let coordinator = Coordinator::default();
	std::thread::scope(|scope| {
		let mut group = FixedGroup::new(&coordinator, Path::new("/synthetic/poison"), &owner(0));
		group.add(&owner(1), budget());
		let frozen = group.freeze();
		let original_waiter = &group.followers[0];
		let shared = original_waiter.group.clone();
		let thread_group = shared.clone();
		let thread_reply = original_waiter.reply.clone();
		let thread_deadline = original_waiter.deadline;
		let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			let _guard = shared.state.lock().unwrap();
			panic!("test coordinator poison");
		}));
		assert!(poisoned.is_err());
		let (started, ready) = mpsc::channel();
		let (finished, done) = mpsc::channel();
		let follower = scope.spawn(move || {
			let waiter = Waiter {
				group: thread_group,
				reply: thread_reply,
				deadline: thread_deadline,
				follower_custody: true,
			};
			started.send(()).unwrap();
			finished.send(waiter.result().is_err()).unwrap();
		});
		ready.recv_timeout(Duration::from_secs(5)).unwrap();
		shared.changed.notify_all();
		assert!(matches!(
			done.recv_timeout(Duration::from_millis(20)),
			Err(mpsc::RecvTimeoutError::Timeout)
		));
		group.finish(Ok(replies(&frozen.owners)));
		assert!(done.recv_timeout(Duration::from_secs(5)).unwrap());
		follower.join().unwrap();
		assert!(group.leader.take().unwrap().result().is_err());
	});
}

#[test]
fn completion_after_fixed_minimum_deadline_rejects_even_a_later_deadline_member() {
	let coordinator = Coordinator::default();
	let mut group = FixedGroup::new(
		&coordinator,
		Path::new("/synthetic/shared-expiry"),
		&owner(0),
	);
	let early = Instant::now() + Duration::from_secs(1);
	group.add(&owner(1), early);
	let frozen = group.freeze();
	assert_eq!(frozen.deadline, early);
	std::thread::sleep(early.saturating_duration_since(Instant::now()));
	group.finish(Err(
		anyhow::Error::new(OriginalFailure).context("read failed at common deadline")
	));
	for result in group.results() {
		let error = result.unwrap_err();
		assert!(error.is::<MetadataQueryDeadline>());
		assert!(error.root_cause().is::<OriginalFailure>());
	}
}
