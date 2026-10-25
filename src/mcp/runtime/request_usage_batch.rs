// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Fresh, fixed usage groups; neither a content lease nor a response cache.
use super::*;
use std::path::PathBuf;
use std::sync::{Condvar, MutexGuard};
use std::time::Duration;

const COLLECT_WINDOW: Duration = Duration::from_millis(1);
const MAX_HINTS: usize = MAX_METADATA_QUERIES;
static COORDINATOR: OnceLock<Coordinator> = OnceLock::new();

struct ObservedUsage {
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
	owner: String,
	deadline: Instant,
	reply: Arc<Reply>,
}
struct GroupState {
	members: Vec<Member>,
	frozen: bool,
	complete: bool,
	failed: bool,
	expired: bool,
}
impl GroupState {
	fn deadline(&self) -> Instant {
		// The first member is installed before the group can be exposed.
		self.members
			.iter()
			.map(|member| member.deadline)
			.min()
			.expect("usage group has its original member")
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
			bail!("usage query group coordination unavailable");
		}
		let result = self
			.reply
			.value
			.lock()
			.unwrap_or_else(std::sync::PoisonError::into_inner)
			.take()
			.ok_or_else(|| anyhow!("usage query result unavailable"))?;
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
}

enum Registration<'a> {
	Leader {
		completion: Completion<'a>,
		waiter: Waiter,
	},
	Follower(Waiter),
}
struct Frozen {
	owners: Vec<String>,
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
			.map_err(|_| anyhow!("usage query group coordination unavailable"))?;
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
				.map_err(|_| anyhow!("usage query group coordination unavailable"))?
				.0;
		}
	}
	fn freeze(&self) -> Result<Frozen> {
		// Join and freeze serialize in this order. Do not retain either lock
		// for any hot/root/namespace/original observation or owner projection.
		let mut registry = self
			.coordinator
			.registry
			.lock()
			.map_err(|_| anyhow!("usage query admission unavailable"))?;
		let mut state = self
			.group
			.state
			.lock()
			.map_err(|_| anyhow!("usage query group coordination unavailable"))?;
		if state.frozen || state.complete || state.failed {
			bail!("usage query group no longer collecting");
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
			owners: state
				.members
				.iter()
				.map(|member| member.owner.clone())
				.collect(),
			deadline,
		})
	}
	fn stage(&mut self, result: Result<ObservedUsage>) {
		let count = { self.group.cleanup_state().members.len() };
		let result = result.and_then(|observed| {
			if observed.replies.len() != count {
				bail!("usage query result coverage changed");
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
		owner: &str,
		deadline: Instant,
		entered: Instant,
	) -> Result<Registration<'_>> {
		let fallback = SharedFailure::new(anyhow!("usage query leader unavailable"));
		let reply = Arc::new(Reply {
			value: Mutex::new(Some(Err(fallback.as_error()))),
		});
		let member = Member {
			owner: owner.to_owned(),
			deadline,
			reply: reply.clone(),
		};
		let candidate = Arc::new(Group {
			collect_until: entered + COLLECT_WINDOW,
			state: Mutex::new(GroupState {
				members: vec![member.clone()],
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
			.map_err(|_| anyhow!("usage query admission unavailable"))?;
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
				.map_err(|_| anyhow!("usage query group coordination unavailable"))?;
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
			bail!("usage query group admission bound exceeded");
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
		owners: &[String],
		deadline: Instant,
		query: impl FnOnce(&Path, &[String], Instant) -> Result<ObservedUsage>,
	) -> Result<ObservedUsage> {
		if Instant::now() >= deadline {
			return Err(MetadataQueryDeadline.into());
		}
		// The complete synchronous call returns owned results only. All of its
		// archive/transaction/lock/trace guards have already dropped here.
		let result = query(root, owners, deadline);
		if Instant::now() >= deadline {
			return Err(match result {
				Ok(_) => MetadataQueryDeadline.into(),
				Err(error) => error.context(MetadataQueryDeadline),
			});
		}
		let observed = result?;
		if observed.replies.len() != owners.len() {
			bail!("usage query result coverage changed");
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
		owners: &[String; 1],
		deadline: Instant,
		query: impl FnOnce(&Path, &[String], Instant) -> Result<ObservedUsage>,
	) -> Result<String> {
		let [owner] = owners;
		if !valid_id(owner) {
			bail!("request usage unavailable to this scope");
		}
		if Instant::now() >= deadline {
			return Err(MetadataQueryDeadline.into());
		}
		if !self.large_hint(root) {
			return self
				.observe(root, owners, deadline, query)?
				.replies
				.pop()
				.ok_or_else(|| anyhow!("usage query result unavailable"))?;
		}
		match self.register(root, owner, deadline, Instant::now())? {
			Registration::Follower(waiter) => waiter.result(),
			Registration::Leader {
				mut completion,
				waiter,
			} => {
				let result = (|| {
					completion.collect()?;
					let frozen = completion.freeze()?;
					self.observe(root, &frozen.owners, frozen.deadline, query)
				})();
				completion.stage(result);
				drop(completion);
				waiter.result()
			}
		}
	}
}

fn read_usage(root: &Path, owners: &[String], deadline: Instant) -> Result<ObservedUsage> {
	let archive = {
		let _guard = index::query_lock(deadline)?;
		let hot = open_store(root)?;
		hot_snapshot(root, &hot)?.1
	};
	let observed = index::usage(root, &archive, owners, deadline)?;
	let replies = observed
		.values
		.into_iter()
		.map(|result| result.and_then(|value| serde_json::to_string(&value).map_err(Into::into)))
		.collect();
	Ok(ObservedUsage {
		replies,
		large: observed.large,
	})
}

pub(super) fn run(root: &Path, owners: &[String; 1], deadline: Instant) -> Result<String> {
	COORDINATOR
		.get_or_init(Coordinator::default)
		.execute(root, owners, deadline, read_usage)
}

#[cfg(test)]
#[path = "request_usage_batch_tests.rs"]
mod tests;
