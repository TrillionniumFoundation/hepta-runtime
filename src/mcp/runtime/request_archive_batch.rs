// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Fresh archive-page groups with fixed membership and original work custody.
//! The shared observation starts after freeze; no result or content lease is reused.
use super::*;
use std::path::PathBuf;
use std::sync::{Condvar, MutexGuard};
use std::time::Duration;
use tokio::sync::{Notify, OwnedSemaphorePermit};

// Large snapshots amortize one complete observation across already admitted calls.
// The fixed 2 ms is included in every member's original deadline, including C1.
// Small snapshots bypass collection; freeze still closes membership permanently.
const COLLECT_WINDOW: Duration = Duration::from_millis(2);
const MAX_HINTS: usize = MAX_METADATA_QUERIES;
static COORDINATOR: OnceLock<Arc<Coordinator>> = OnceLock::new();

#[derive(Clone)]
struct Query {
	owner: String,
	params: RequestHistoryParams,
}
impl Query {
	fn validate(&self) -> Result<()> {
		if !valid_id(&self.owner) {
			bail!("request archive unavailable to this scope");
		}
		let limit = self.params.limit.unwrap_or(32) as usize;
		if !(1..=32).contains(&limit)
			|| self
				.params
				.after_id
				.as_deref()
				.is_some_and(|id| !valid_id(id))
		{
			bail!("invalid request archive page");
		}
		Ok(())
	}
}

struct ObservedPages {
	replies: Vec<Result<String>>,
	large: bool,
}

// The original error remains the source, including all of its context/cause
// chain. A typed deadline context keeps the existing public category/downcast.
#[derive(Clone, Debug)]
struct SharedFailure {
	error: Arc<anyhow::Error>,
	deadline: bool,
}
impl SharedFailure {
	fn new(error: anyhow::Error) -> Self {
		let deadline = error.is::<MetadataQueryDeadline>()
			|| error
				.chain()
				.any(|cause| cause.is::<MetadataQueryDeadline>());
		Self {
			error: Arc::new(error),
			deadline,
		}
	}
	fn as_error(&self) -> anyhow::Error {
		let error = anyhow::Error::new(self.clone());
		if self.deadline {
			error.context(MetadataQueryDeadline)
		} else {
			error
		}
	}
}
impl std::fmt::Display for SharedFailure {
	fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		std::fmt::Display::fmt(self.error.as_ref(), out)
	}
}
impl std::error::Error for SharedFailure {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		Some(self.error.as_ref().as_ref())
	}
}

// Each member owns a distinct one-shot result slot. The fallback is allocated
// before registration, so the unwinding publisher needs no allocation or I/O.
struct Reply {
	value: Mutex<Option<Result<String>>>,
}
#[derive(Clone)]
struct Member {
	request: Query,
	reply: Arc<Reply>,
}
struct GroupState {
	members: Vec<Member>,
	permits: Vec<OwnedSemaphorePermit>,
	deadline: Instant,
	frozen: bool,
	finishing: bool,
	complete: bool,
	failed: bool,
	expired: bool,
}
impl GroupState {
	fn deadline(&self) -> Instant {
		self.deadline
	}
}

struct Group {
	trace_id: u64,
	collect_until: Instant,
	state: Mutex<GroupState>,
	changed: Condvar,
	completed: Notify,
}
impl Group {
	fn cleanup_state(&self) -> MutexGuard<'_, GroupState> {
		match self.state.lock() {
			Ok(state) => state,
			Err(error) => {
				let mut state = error.into_inner();
				state.failed = true;
				state
			}
		}
	}
	fn wait_complete(&self) -> (bool, bool) {
		let mut state = self.cleanup_state();
		while !state.complete {
			state = match self.changed.wait(state) {
				Ok(state) => state,
				Err(error) => {
					let mut state = error.into_inner();
					state.failed = true;
					state
				}
			};
		}
		(!state.failed, state.expired)
	}
}

struct Waiter {
	group: Arc<Group>,
	reply: Arc<Reply>,
	deadline: Instant,
	// A follower's own unwind must also retain the outer query permit until
	// the leader is really done. A leader has its separate completion guard.
	follower_custody: bool,
}
impl Waiter {
	#[cfg(test)]
	fn result(self) -> Result<String> {
		metadata_trace::mark("group_wait", self.group.trace_id, 0);
		let (healthy, expired) = self.group.wait_complete();
		metadata_trace::mark("group_ready", self.group.trace_id, u64::from(expired));
		self.reply.result(self.deadline, healthy, expired)
	}

	fn into_async(mut self) -> AsyncWaiter {
		// register_owned has already put the permit in the group. The async
		// waiter must never inherit a Condvar-blocking destructor.
		self.follower_custody = false;
		AsyncWaiter {
			group: self.group.clone(),
			reply: self.reply.clone(),
			deadline: self.deadline,
		}
	}
}
impl Drop for Waiter {
	fn drop(&mut self) {
		if self.follower_custody {
			// No deadline/poison/notification shortcut may return its permit
			// while shared I/O is still owned by the actual leader closure.
			self.group.wait_complete();
		}
	}
}

impl Reply {
	fn result(&self, deadline: Instant, healthy: bool, expired: bool) -> Result<String> {
		if !healthy {
			bail!("archive page query group coordination unavailable");
		}
		let result = self
			.value
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner)
			.take()
			.ok_or_else(|| anyhow!("archive page query result unavailable"))?;
		if expired || Instant::now() >= deadline {
			return Err(match result {
				Ok(_) => MetadataQueryDeadline.into(),
				Err(error) => error.context(MetadataQueryDeadline),
			});
		}
		result
	}
}

// Dropping an async caller releases only these Arc snapshots. Every admitted
// permit stays in the original group until its work owner finishes cleanup.
struct AsyncWaiter {
	group: Arc<Group>,
	reply: Arc<Reply>,
	deadline: Instant,
}
impl AsyncWaiter {
	async fn result(self, trace: metadata_trace::QueryTrace) -> Result<String> {
		trace.mark_cohort("group_wait", self.group.trace_id, 0);
		loop {
			let notified = self.group.completed.notified();
			tokio::pin!(notified);
			// Register before checking persistent terminal state. A completion
			// between that check and await must not lose notify_waiters.
			notified.as_mut().enable();
			let terminal = {
				let state = self.group.cleanup_state();
				state.complete.then_some((!state.failed, state.expired))
			};
			if let Some((healthy, expired)) = terminal {
				trace.mark_cohort("group_ready", self.group.trace_id, u64::from(expired));
				return self.reply.result(self.deadline, healthy, expired);
			}
			notified.await;
		}
	}
}

enum OwnedRegistration {
	Leader {
		completion: Completion,
		waiter: AsyncWaiter,
	},
	Follower(AsyncWaiter),
}

// No I/O handles exist here before run. Field order keeps arbitrary test
// operation captures and the path alive no longer than the unique finalizer.
struct Work<Q> {
	operation: Option<Q>,
	root: PathBuf,
	completion: Completion,
}
impl<Q> Work<Q>
where
	Q: FnOnce(&Path, &[Query], Instant) -> Result<ObservedPages>,
{
	fn run(self, trace: metadata_trace::QueryTrace) {
		let _context = trace.enter();
		let mut work = self;
		trace.mark("blocking_entered", 0);
		let result = (|| {
			work.completion.collect()?;
			let frozen = work.completion.freeze()?;
			let operation = work
				.operation
				.take()
				.ok_or_else(|| anyhow!("archive page query operation unavailable"))?;
			work.completion.coordinator.observe(
				&work.root,
				&frozen.requests,
				frozen.deadline,
				operation,
			)
		})();
		trace.mark("blocking_result", u64::from(result.is_err()));
		work.completion.stage(result);
		// The observed call and all its original-reader joins have returned.
		// On unwind Work's finalizer also runs before the trace context drops.
		drop(work);
	}
}

fn registration_mark(
	trace: Option<metadata_trace::QueryTrace>,
	phase: &'static str,
	cohort: u64,
	value: u64,
) {
	if let Some(trace) = trace {
		trace.mark_cohort(phase, cohort, value);
	} else {
		metadata_trace::mark(phase, cohort, value);
	}
}

#[derive(Default)]
struct Registry {
	large_roots: VecDeque<PathBuf>,
	collecting: Vec<(PathBuf, Arc<Group>)>,
}
#[derive(Default)]
struct Coordinator {
	registry: Mutex<Registry>,
	#[cfg(test)]
	registrations: std::sync::atomic::AtomicUsize,
}

enum Registration {
	Leader {
		completion: Completion,
		waiter: Waiter,
	},
	Follower(Waiter),
}
struct Frozen {
	requests: Vec<Query>,
	deadline: Instant,
}

// This guard exists before registry exposure. All coordinator lock guards are
// shorter inner scopes, and all archive I/O is a nested synchronous call. Its
// destructor therefore runs after those resources, including on Rust unwind.
// Release panic=abort still terminates the process; it does not run this Drop.
struct Completion {
	coordinator: Arc<Coordinator>,
	trace: Option<metadata_trace::QueryTrace>,
	group: Arc<Group>,
	replies: Option<Vec<Result<String>>>,
	armed: bool,
}
impl Completion {
	fn collect(&self) -> Result<()> {
		let _trace = metadata_trace::Stage::new("cohort_collect");
		let mut state = self
			.group
			.state
			.lock()
			.map_err(|_| anyhow!("archive page query group coordination unavailable"))?;
		loop {
			let until = self.group.collect_until.min(state.deadline());
			let now = Instant::now();
			if state.members.len() == MAX_METADATA_QUERIES || now >= until {
				return Ok(());
			}
			state = self
				.group
				.changed
				.wait_timeout(state, until.saturating_duration_since(now))
				.map_err(|_| anyhow!("archive page query group coordination unavailable"))?
				.0;
		}
	}
	fn freeze(&self) -> Result<Frozen> {
		// Join and freeze serialize in this order. Do not retain either lock
		// for any hot/root/namespace/original observation or request projection.
		let mut registry = self
			.coordinator
			.registry
			.lock()
			.map_err(|_| anyhow!("archive page query admission unavailable"))?;
		let mut state = self
			.group
			.state
			.lock()
			.map_err(|_| anyhow!("archive page query group coordination unavailable"))?;
		if state.frozen || state.finishing || state.complete || state.failed {
			bail!("archive page query group no longer collecting");
		}
		state.frozen = true;
		metadata_trace::mark(
			"cohort_frozen",
			self.group.trace_id,
			state.members.len() as u64,
		);
		registry
			.collecting
			.retain(|(_, group)| !Arc::ptr_eq(group, &self.group));
		let deadline = state.deadline();
		if Instant::now() >= deadline {
			return Err(MetadataQueryDeadline.into());
		}
		Ok(Frozen {
			requests: state
				.members
				.iter()
				.map(|member| member.request.clone())
				.collect(),
			deadline,
		})
	}
	fn stage(&mut self, result: Result<ObservedPages>) {
		let count = { self.group.cleanup_state().members.len() };
		let result = result.and_then(|observed| {
			if observed.replies.len() != count {
				bail!("archive page query result coverage changed");
			}
			Ok(observed)
		});
		self.replies = Some(match result {
			Ok(observed) => observed.replies,
			Err(error) => {
				let shared = SharedFailure::new(error);
				(0..count).map(|_| Err(shared.as_error())).collect()
			}
		});
	}
}
impl Drop for Completion {
	fn drop(&mut self) {
		if !self.armed {
			return;
		}
		let registry_poisoned = {
			let (mut registry, poisoned) = match self.coordinator.registry.lock() {
				Ok(registry) => (registry, false),
				Err(error) => (error.into_inner(), true),
			};
			// A newer same-root group may already exist after our cutoff.
			// Never remove it by pathname or freeze it in place of this group.
			registry
				.collecting
				.retain(|(_, group)| !Arc::ptr_eq(group, &self.group));
			poisoned
		};
		let permits = {
			let mut state = self.group.cleanup_state();
			state.frozen = true;
			state.finishing = true;
			state.failed |= registry_poisoned;
			if !state.failed {
				if let Some(replies) = self.replies.take() {
					let mut reply_poisoned = false;
					for (member, result) in state.members.iter().zip(replies) {
						let mut slot = match member.reply.value.lock() {
							Ok(slot) => slot,
							Err(error) => {
								reply_poisoned = true;
								error.into_inner()
							}
						};
						*slot = Some(result);
					}
					state.failed |= reply_poisoned;
				}
			}
			std::mem::take(&mut state.permits)
		};
		// No observation, original-reader join or coordination lock survives
		// here. Releasing permits can wake another admitted async caller.
		drop(permits);
		let expired = {
			let mut state = self.group.cleanup_state();
			state.expired = Instant::now() >= state.deadline();
			state.complete = true;
			state.expired
		};
		registration_mark(
			self.trace,
			"cohort_complete",
			self.group.trace_id,
			u64::from(expired),
		);
		self.group.changed.notify_all();
		self.group.completed.notify_waiters();
	}
}

impl Coordinator {
	fn large_hint(&self, root: &Path) -> bool {
		self.registry.lock().is_ok_and(|registry| {
			registry
				.large_roots
				.iter()
				.any(|saved| saved.as_os_str() == root.as_os_str())
		})
	}
	fn remember(&self, root: &Path, large: bool) {
		// Only a scheduling hint. A poisoned/unavailable hint never certifies
		// content and is not a reason to reject an otherwise valid singleton.
		if let Ok(mut registry) = self.registry.lock() {
			registry
				.large_roots
				.retain(|saved| saved.as_os_str() != root.as_os_str());
			if large {
				registry.large_roots.push_front(root.to_path_buf());
				registry.large_roots.truncate(MAX_HINTS);
			}
		}
	}
	#[cfg(test)]
	fn register(
		self: &Arc<Self>,
		root: &Path,
		request: &Query,
		deadline: Instant,
		entered: Instant,
	) -> Result<Registration> {
		self.register_inner(root, request, deadline, entered, None, None)
	}

	fn register_owned(
		self: &Arc<Self>,
		root: &Path,
		request: &Query,
		deadline: Instant,
		entered: Instant,
		permit: OwnedSemaphorePermit,
		trace: metadata_trace::QueryTrace,
	) -> Result<OwnedRegistration> {
		match self.register_inner(root, request, deadline, entered, Some(permit), Some(trace))? {
			Registration::Leader { completion, waiter } => Ok(OwnedRegistration::Leader {
				completion,
				waiter: waiter.into_async(),
			}),
			Registration::Follower(waiter) => Ok(OwnedRegistration::Follower(waiter.into_async())),
		}
	}

	fn register_inner(
		self: &Arc<Self>,
		root: &Path,
		request: &Query,
		deadline: Instant,
		entered: Instant,
		mut permit: Option<OwnedSemaphorePermit>,
		trace: Option<metadata_trace::QueryTrace>,
	) -> Result<Registration> {
		let owned = permit.is_some();
		#[cfg(test)]
		self.registrations.fetch_add(1, Ordering::Relaxed);
		let fallback = SharedFailure::new(anyhow!("archive page query leader unavailable"));
		let reply = Arc::new(Reply {
			value: Mutex::new(Some(Err(fallback.as_error()))),
		});
		let member = Member {
			request: request.to_owned(),
			reply: reply.clone(),
		};
		let mut members = Vec::with_capacity(MAX_METADATA_QUERIES);
		members.push(member.clone());
		let candidate = Arc::new(Group {
			trace_id: metadata_trace::next_cohort(),
			collect_until: entered + COLLECT_WINDOW,
			state: Mutex::new(GroupState {
				members,
				permits: Vec::with_capacity(MAX_METADATA_QUERIES),
				deadline,
				frozen: false,
				finishing: false,
				complete: false,
				failed: false,
				expired: false,
			}),
			changed: Condvar::new(),
			completed: Notify::new(),
		});
		let mut completion = Completion {
			coordinator: self.clone(),
			trace,
			group: candidate.clone(),
			replies: None,
			armed: true,
		};
		// Declared before any registry/group lock. If a joining worker unwinds,
		// those inner guards release before its follower custody waits.
		let mut follower: Option<Waiter> = None;
		let mut registry = self
			.registry
			.lock()
			.map_err(|_| anyhow!("archive page query admission unavailable"))?;
		if Instant::now() >= deadline {
			return Err(MetadataQueryDeadline.into());
		}
		if let Some((_, group)) = registry
			.collecting
			.iter()
			.find(|(saved, _)| saved.as_os_str() == root.as_os_str())
		{
			let mut state = group
				.state
				.lock()
				.map_err(|_| anyhow!("archive page query group coordination unavailable"))?;
			let now = Instant::now();
			if now >= deadline {
				return Err(MetadataQueryDeadline.into());
			}
			if !state.frozen
				&& !state.finishing
				&& !state.complete
				&& !state.failed
				&& state.members.len() < MAX_METADATA_QUERIES
				&& now < group.collect_until
				&& now < state.deadline()
			{
				follower = Some(Waiter {
					group: group.clone(),
					reply: reply.clone(),
					deadline,
					follower_custody: !owned,
				});
				// Transfer ownership before exposing this new member. Both
				// vectors were preallocated to the fixed admission bound.
				if let Some(permit) = permit.take() {
					state.permits.push(permit);
				}
				state.deadline = state.deadline.min(deadline);
				state.members.push(member);
				registration_mark(
					trace,
					"cohort_follower",
					group.trace_id,
					state.members.len() as u64,
				);
				group.changed.notify_all();
			}
		}
		if let Some(waiter) = follower {
			drop(registry);
			completion.armed = false;
			return Ok(Registration::Follower(waiter));
		}
		// Expired collection windows cannot receive late members even when
		// their leader has not been scheduled to freeze yet.
		let now = Instant::now();
		if now >= deadline {
			return Err(MetadataQueryDeadline.into());
		}
		registry.collecting.retain(|(saved, group)| {
			saved.as_os_str() != root.as_os_str() && now < group.collect_until
		});
		if registry.collecting.len() >= MAX_METADATA_QUERIES {
			bail!("archive page query group admission bound exceeded");
		}
		if let Some(permit) = permit.take() {
			candidate.cleanup_state().permits.push(permit);
		}
		registry
			.collecting
			.push((root.to_path_buf(), candidate.clone()));
		registration_mark(trace, "cohort_leader", candidate.trace_id, 1);
		drop(registry);
		Ok(Registration::Leader {
			completion,
			waiter: Waiter {
				group: candidate,
				reply,
				deadline,
				follower_custody: false,
			},
		})
	}
	fn observe(
		&self,
		root: &Path,
		requests: &[Query],
		deadline: Instant,
		query: impl FnOnce(&Path, &[Query], Instant) -> Result<ObservedPages>,
	) -> Result<ObservedPages> {
		if Instant::now() >= deadline {
			return Err(MetadataQueryDeadline.into());
		}
		// The complete synchronous call returns owned results only. All of its
		// archive/transaction/lock/trace guards have already dropped here.
		let result = query(root, requests, deadline);
		if Instant::now() >= deadline {
			return Err(match result {
				Ok(_) => MetadataQueryDeadline.into(),
				Err(error) => error.context(MetadataQueryDeadline),
			});
		}
		let observed = result?;
		if observed.replies.len() != requests.len() {
			bail!("archive page query result coverage changed");
		}
		if observed.replies.iter().any(Result::is_ok) {
			self.remember(root, observed.large);
		}
		if Instant::now() >= deadline {
			return Err(MetadataQueryDeadline.into());
		}
		Ok(observed)
	}
	#[cfg(test)]
	fn execute(
		self: &Arc<Self>,
		root: &Path,
		requests: &[Query; 1],
		deadline: Instant,
		query: impl FnOnce(&Path, &[Query], Instant) -> Result<ObservedPages>,
	) -> Result<String> {
		let [request] = requests;
		request.validate()?;
		if Instant::now() >= deadline {
			return Err(MetadataQueryDeadline.into());
		}
		if !self.large_hint(root) {
			metadata_trace::mark("cohort_singleton_no_hint", 0, 1);
			return self
				.observe(root, requests, deadline, query)?
				.replies
				.pop()
				.ok_or_else(|| anyhow!("archive page query result unavailable"))?;
		}
		match self.register(root, request, deadline, Instant::now())? {
			Registration::Follower(waiter) => waiter.result(),
			Registration::Leader {
				mut completion,
				waiter,
			} => {
				let result = (|| {
					completion.collect()?;
					let frozen = completion.freeze()?;
					self.observe(root, &frozen.requests, frozen.deadline, query)
				})();
				completion.stage(result);
				drop(completion);
				waiter.result()
			}
		}
	}
	async fn execute_owned<Q>(
		self: Arc<Self>,
		root: PathBuf,
		request: Query,
		deadline: Instant,
		slots: Arc<Semaphore>,
		trace: metadata_trace::QueryTrace,
		operation: Q,
	) -> Result<String>
	where
		Q: FnOnce(&Path, &[Query], Instant) -> Result<ObservedPages> + Send + 'static,
	{
		let _trace_boundary = trace.boundary("caller_scope_end");
		if Instant::now() >= deadline {
			trace.mark("expired_before_admission", 1);
			return Err(MetadataQueryDeadline.into());
		}
		let result =
			tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async move {
				request.validate()?;
				trace.mark("permit_wait", 0);
				let permit = slots
					.acquire_owned()
					.await
					.map_err(|_| anyhow!("archive metadata query admission unavailable"))?;
				trace.mark("permit_acquired", 0);
				if Instant::now() >= deadline {
					return Err(MetadataQueryDeadline.into());
				}
				if !self.large_hint(&root) {
					// A poisoned hint must not refuse an otherwise valid singleton.
					trace.mark_cohort("cohort_singleton_no_hint", 0, 1);
					trace.mark("blocking_submitted", 0);
					return tokio::task::spawn_blocking(move || {
						let _context = trace.enter();
						let _permit = permit;
						trace.mark("blocking_entered", 0);
						let result = self
							.observe(&root, std::slice::from_ref(&request), deadline, operation)
							.and_then(|mut observed| {
								observed.replies.pop().ok_or_else(|| {
									anyhow!("archive page query result unavailable")
								})?
							});
						trace.mark("blocking_result", u64::from(result.is_err()));
						result
					})
					.await
					.map_err(|_| anyhow!("archive metadata query worker unavailable"))?;
				}

				// Registration and transfer to the original queued Work contain no
				// await. Its Completion already exists before registry exposure.
				let registration =
					self.register_owned(&root, &request, deadline, Instant::now(), permit, trace)?;
				let waiter = match registration {
					OwnedRegistration::Leader { completion, waiter } => {
						let work = Work {
							operation: Some(operation),
							root,
							completion,
						};
						trace.mark("blocking_submitted", 0);
						drop(tokio::task::spawn_blocking(move || work.run(trace)));
						waiter
					}
					OwnedRegistration::Follower(waiter) => {
						// The follower contributes only a private projection request.
						// Its operation cannot issue an independent observation.
						drop(operation);
						waiter
					}
				};
				waiter.result(trace).await
			})
			.await
			.map_err(|_| anyhow::Error::from(MetadataQueryDeadline))
			.and_then(|result| result);
		trace.mark("caller_result_ready", u64::from(result.is_err()));
		let result = result?;
		if Instant::now() >= deadline {
			trace.mark("caller_late_result", 1);
			return Err(MetadataQueryDeadline.into());
		}
		Ok(result)
	}
}

fn read_pages(root: &Path, requests: &[Query], deadline: Instant) -> Result<ObservedPages> {
	let _trace = metadata_trace::Stage::new("read_pages");
	let shared_requests: Vec<_> = requests
		.iter()
		.map(|request| index::SharedPageRequest {
			owner: request.owner.clone(),
			after_id: request.params.after_id.clone(),
			limit: request.params.limit.unwrap_or(32) as usize,
		})
		.collect();
	if let Some(observed) = index::try_shared_pages(root, &shared_requests, deadline)? {
		return Ok(ObservedPages {
			replies: observed.values,
			large: observed.large,
		});
	}
	// Only an early, pure preflight miss reaches the original exclusive path.
	// This is the same cohort and absolute deadline, never a second dispatch.
	let (archive, queries) = {
		let _trace = metadata_trace::Stage::new("hot_snapshot_and_cursors");
		let _guard = index::query_lock(deadline)?;
		let hot = open_store(root)?;
		let archive = hot_snapshot(root, &hot)?.1;
		let queries = requests
			.iter()
			.map(|request| {
				if Instant::now() >= deadline {
					return Err(MetadataQueryDeadline.into());
				}
				let cursor = if let Some(id) = request.params.after_id.as_deref() {
					let record = archive.read_record(&format!("{id}.json"))?;
					if record.owner != request.owner {
						bail!("request archive cursor unavailable to this scope");
					}
					Some(record)
				} else {
					None
				};
				Ok(index::PageQuery {
					owner: request.owner.clone(),
					cursor,
					limit: request.params.limit.unwrap_or(32) as usize,
				})
			})
			.collect::<Vec<_>>();
		(archive, queries)
	};
	// An all-refused cohort has no successful data to certify and must not
	// spend a complete-archive pass merely to return those cursor errors.
	if queries.iter().all(Result::is_err) {
		return Ok(ObservedPages {
			replies: queries
				.into_iter()
				.map(|query| query.and_then(|_| bail!("archive page refusal coverage changed")))
				.collect(),
			large: false,
		});
	}
	let observed = index::pages(root, &archive, queries, deadline)?;
	Ok(ObservedPages {
		replies: observed.values,
		large: observed.large,
	})
}

#[cfg(test)]
pub(super) fn run(
	root: &Path,
	owner: &str,
	params: RequestHistoryParams,
	deadline: Instant,
) -> Result<String> {
	let requests = [Query {
		owner: owner.to_owned(),
		params,
	}];
	COORDINATOR
		.get_or_init(|| Arc::new(Coordinator::default()))
		.execute(root, &requests, deadline, read_pages)
}
pub(super) async fn run_owned(
	root: PathBuf,
	owner: String,
	params: RequestHistoryParams,
	deadline: Instant,
	slots: Arc<Semaphore>,
	trace: metadata_trace::QueryTrace,
) -> Result<String> {
	COORDINATOR
		.get_or_init(|| Arc::new(Coordinator::default()))
		.clone()
		.execute_owned(
			root,
			Query { owner, params },
			deadline,
			slots,
			trace,
			read_pages,
		)
		.await
}

#[cfg(test)]
#[path = "request_archive_owned_tests.rs"]
mod owned_tests;

#[cfg(test)]
#[path = "request_archive_batch_tests.rs"]
mod tests;
