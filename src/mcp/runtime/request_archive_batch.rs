// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Fresh archive-page groups with fixed membership and original blocking custody.
//! The shared observation starts after freeze; no result or content lease is reused.
use super::*;
use std::path::PathBuf;
use std::sync::{Condvar, MutexGuard};
use std::time::Duration;

// Large snapshots amortize one complete observation across already admitted calls.
// The fixed 1 ms is included in every member's original deadline, including C1.
const COLLECT_WINDOW: Duration = Duration::from_millis(1);
const MAX_HINTS: usize = MAX_METADATA_QUERIES;
static COORDINATOR: OnceLock<Coordinator> = OnceLock::new();

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
	deadline: Instant,
	frozen: bool,
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
	collect_until: Instant,
	state: Mutex<GroupState>,
	changed: Condvar,
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
	fn result(self) -> Result<String> {
		let (healthy, expired) = self.group.wait_complete();
		if !healthy {
			bail!("archive page query group coordination unavailable");
		}
		let result = self
			.reply
			.value
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner)
			.take()
			.ok_or_else(|| anyhow!("archive page query result unavailable"))?;
		if expired || Instant::now() >= self.deadline {
			return Err(match result {
				Ok(_) => MetadataQueryDeadline.into(),
				Err(error) => error.context(MetadataQueryDeadline),
			});
		}
		result
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

enum Registration<'a> {
	Leader {
		completion: Completion<'a>,
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
struct Completion<'a> {
	coordinator: &'a Coordinator,
	group: Arc<Group>,
	replies: Option<Vec<Result<String>>>,
	armed: bool,
}
impl Completion<'_> {
	fn collect(&self) -> Result<()> {
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
		if state.frozen || state.complete || state.failed {
			bail!("archive page query group no longer collecting");
		}
		state.frozen = true;
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
impl Drop for Completion<'_> {
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
		let mut state = self.group.cleanup_state();
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
		state.expired = Instant::now() >= state.deadline();
		state.complete = true;
		self.group.changed.notify_all();
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
	fn register(
		&self,
		root: &Path,
		request: &Query,
		deadline: Instant,
		entered: Instant,
	) -> Result<Registration<'_>> {
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
		let candidate = Arc::new(Group {
			collect_until: entered + COLLECT_WINDOW,
			state: Mutex::new(GroupState {
				members: vec![member.clone()],
				deadline,
				frozen: false,
				complete: false,
				failed: false,
				expired: false,
			}),
			changed: Condvar::new(),
		});
		let mut completion = Completion {
			coordinator: self,
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
					follower_custody: true,
				});
				state.deadline = state.deadline.min(deadline);
				state.members.push(member);
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
		registry
			.collecting
			.push((root.to_path_buf(), candidate.clone()));
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
	fn execute(
		&self,
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
}

fn read_pages(root: &Path, requests: &[Query], deadline: Instant) -> Result<ObservedPages> {
	let (archive, queries) = {
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
		.get_or_init(Coordinator::default)
		.execute(root, &requests, deadline, read_pages)
}

#[cfg(test)]
#[path = "request_archive_batch_tests.rs"]
mod tests;
