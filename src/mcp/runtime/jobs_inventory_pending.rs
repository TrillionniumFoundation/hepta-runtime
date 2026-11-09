// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Continuous, deadline-bound original validation with read-only pending polls.
use super::*;
use inventory_source::Progress;
use std::sync::atomic::AtomicUsize;
use std::thread::JoinHandle;

const MAX_OBSERVATION_TIME: Duration = Duration::from_secs(30);
const MAX_ERROR_BYTES: usize = 2048;

enum Work {
	Observe(Option<Progress<InventoryRow>>),
	Validate {
		scan: Option<Progress<()>>,
		snapshot: Arc<Snapshot>,
		after: String,
	},
}

enum Completed {
	Observe(Box<Snapshot>),
	Validate {
		snapshot: Arc<Snapshot>,
		after: String,
		interval: ObservationInterval,
	},
}

enum State {
	Working,
	Ready(Completed),
	Failed(String),
	Claimed,
}

pub(super) struct Pending {
	root: PathBuf,
	host: Option<String>,
	token: String,
	created: Instant,
	started: OnceLock<(Instant, u64)>,
	invalidated: AtomicBool,
	reserved: AtomicUsize,
	fixed_bytes: usize,
	original: Option<Arc<Snapshot>>,
	state: Mutex<State>,
	worker: Mutex<Option<JoinHandle<()>>>,
}

impl Pending {
	pub(super) fn finished(&self) -> bool {
		self.worker
			.try_lock()
			.ok()
			.is_some_and(|worker| worker.as_ref().is_some_and(JoinHandle::is_finished))
	}

	pub(super) fn expired(&self, now: Instant) -> bool {
		now.saturating_duration_since(self.created) >= SNAPSHOT_TTL
			|| self.invalidated.load(Ordering::Acquire)
	}

	pub(super) fn reserved_bytes(&self) -> usize {
		self.reserved.load(Ordering::Acquire)
	}

	fn new(root: &Path, host: Option<&str>, work: &Work) -> Result<Self> {
		let root = root.to_path_buf();
		let host = host.map(str::to_owned);
		let token = random_token()?;
		let (extra, original) = match work {
			Work::Validate {
				after, snapshot, ..
			} => (after.capacity(), Some(snapshot.clone())),
			_ => (0, None),
		};
		let fixed_bytes = std::mem::size_of::<Self>()
			+ std::mem::size_of::<Work>()
			+ root.capacity()
			+ host.as_ref().map_or(0, String::capacity)
			+ token.capacity()
			+ extra + MAX_ERROR_BYTES;
		Ok(Self {
			root,
			host,
			token,
			created: Instant::now(),
			started: OnceLock::new(),
			invalidated: AtomicBool::new(false),
			reserved: AtomicUsize::new(fixed_bytes),
			fixed_bytes,
			original,
			state: Mutex::new(State::Working),
			worker: Mutex::new(None),
		})
	}

	fn response(&self) -> Result<String> {
		Ok(serde_json::to_string(&json!({
			"jobs":[], "total":null, "next_cursor":format!("pending:{}:0", self.token),
			"has_more":true, "inventory_complete":false, "validation_pending":true,
			"status_authoritative":false, "snapshot_sha256":null,
			"observation_started_unix_ms":self.started.get().map(|(_, unix)| unix),
			"observation_deadline_seconds":MAX_OBSERVATION_TIME.as_secs(),
			"observer_mode":"continuous_background", "observation_atomic":false,
			"snapshot_semantics":"registry_metadata_at_observation"
		}))?)
	}
}

pub(super) fn remove_idle_entry(state: &mut SnapshotCache) -> bool {
	if let Some(at) = state
		.entries
		.iter()
		.position(|entry| Arc::strong_count(entry) == 1)
	{
		if let Some(old) = state.entries.remove(at) {
			let bytes = old.retained_bytes;
			drop(old);
			state.bytes -= bytes;
		}
		return true;
	}
	if let Some(at) = state
		.pending
		.iter()
		.position(|entry| Arc::strong_count(entry) == 1 && entry.finished())
	{
		if let Some(old) = state.pending.remove(at) {
			let bytes = old.reserved_bytes();
			drop(old);
			state.bytes -= bytes;
		}
		return true;
	}
	false
}

fn admit(cache: &Arc<Mutex<SnapshotCache>>, pending: Pending) -> Result<Arc<Pending>> {
	let pending = Arc::new(pending);
	let mut state = cache
		.lock()
		.map_err(|_| anyhow::anyhow!("inventory snapshot cache unavailable"))?;
	state.prune(Instant::now());
	if state
		.pending
		.iter()
		.any(|entry| entry.token == pending.token)
		|| state
			.entries
			.iter()
			.any(|entry| entry.token == pending.token)
	{
		bail!("durable inventory snapshot identity collision");
	}
	if pending.reserved_bytes() > MAX_SNAPSHOT_BYTES {
		bail!("durable inventory progress cache byte bound exceeded");
	}
	while state.entries.len() + state.pending.len() >= IDLE_SNAPSHOT_TARGET
		|| state.bytes + pending.reserved_bytes() > MAX_SNAPSHOT_BYTES
	{
		if !remove_idle_entry(&mut state) {
			if state.bytes + pending.reserved_bytes() > MAX_SNAPSHOT_BYTES {
				bail!("durable inventory snapshot byte budget in use; retry a fresh first page");
			}
			// The idle count target must not reject another active observation
			// whose actual retained payload fits the shared byte budget.
			break;
		}
	}
	state.bytes += pending.reserved_bytes();
	state.pending.push_back(pending.clone());
	Ok(pending)
}

fn reserve(cache: &Mutex<SnapshotCache>, pending: &Pending, payload: usize) -> Result<()> {
	let needed = payload
		.checked_add(pending.fixed_bytes)
		.context("durable inventory progress byte overflow")?;
	if needed > MAX_SNAPSHOT_BYTES {
		bail!("durable inventory progress cache byte bound exceeded");
	}
	if needed <= pending.reserved_bytes() {
		return Ok(());
	}
	let charged = needed
		.div_ceil(64 * 1024)
		.saturating_mul(64 * 1024)
		.min(MAX_SNAPSHOT_BYTES);
	let mut state = cache
		.lock()
		.map_err(|_| anyhow::anyhow!("inventory snapshot cache unavailable"))?;
	state.prune(Instant::now());
	let extra = charged.saturating_sub(pending.reserved_bytes());
	while state.bytes + extra > MAX_SNAPSHOT_BYTES {
		if !remove_idle_entry(&mut state) {
			bail!("durable inventory snapshot byte budget in use; retry a fresh first page");
		}
	}
	pending.reserved.store(charged, Ordering::Release);
	state.bytes += extra;
	Ok(())
}

fn shrink_after_drop(cache: &Mutex<SnapshotCache>, pending: &Pending, payload: usize) {
	let kept = pending.fixed_bytes.saturating_add(payload);
	if let Ok(mut state) = cache.lock() {
		let previous = pending.reserved_bytes();
		if kept < previous {
			pending.reserved.store(kept, Ordering::Release);
			state.bytes -= previous - kept;
		}
	}
}

fn retire(state: &mut SnapshotCache, pending: &Pending) {
	pending.invalidated.store(true, Ordering::Release);
	state.pending.retain(|entry| entry.token != pending.token);
	state.bytes = state
		.entries
		.iter()
		.map(|entry| entry.retained_bytes)
		.sum::<usize>()
		+ state
			.pending
			.iter()
			.map(|entry| entry.reserved_bytes())
			.sum::<usize>();
}

fn run_work(
	mut work: Work,
	pending: &Pending,
	cache: &Mutex<SnapshotCache>,
	limits: InventoryLimits,
) -> Result<Completed> {
	let started = Instant::now();
	let unix = now_ms()
		.try_into()
		.context("inventory clock exceeds JSON range")?;
	if pending.started.set((started, unix)).is_err() {
		bail!("inventory observation worker already started");
	}
	#[cfg(test)]
	tests::worker_started(&pending.root);
	#[cfg(test)]
	let total_budget = tests::observation_limit(&pending.root).unwrap_or(MAX_OBSERVATION_TIME);
	#[cfg(not(test))]
	let total_budget = MAX_OBSERVATION_TIME;
	loop {
		let total_remaining = total_budget.saturating_sub(started.elapsed());
		if total_remaining.is_zero() || pending.expired(Instant::now()) {
			bail!("durable inventory observation deadline exceeded; no partial inventory returned");
		}
		if limits.time.is_zero() {
			bail!("durable inventory source time budget exceeded; no partial inventory returned");
		}
		let step_started = Instant::now();
		let step_limits = InventoryLimits {
			time: limits.time.min(total_remaining),
			..limits
		};
		let complete = match &mut work {
			Work::Observe(scan) => {
				if scan.is_none() {
					*scan = Some(Progress::begin(
						&pending.root,
						step_limits,
						None,
						MAX_SNAPSHOT_BYTES,
						|bytes| reserve(cache, pending, bytes),
					)?);
				}
				let remaining = step_limits.time.saturating_sub(step_started.elapsed());
				if remaining.is_zero() {
					continue;
				}
				scan.as_mut()
					.context("inventory observation unavailable")?
					.observe_step(
						&pending.root,
						InventoryLimits {
							time: remaining,
							..step_limits
						},
						|record| InventoryRow {
							id: record.id,
							host: record.host,
							created_unix_ms: record.created_unix_ms,
							execution_mode: record.execution_mode,
							launch_state: record.launch_state,
						},
						|row| row.id.capacity() + row.host.capacity() + row.launch_state.capacity(),
						|bytes| reserve(cache, pending, bytes),
					)?
			}
			Work::Validate { scan, snapshot, .. } => {
				if snapshot.expired(Instant::now()) {
					bail!("inventory snapshot expired or invalidated; restart from the first page");
				}
				if scan.is_none() {
					*scan = Some(Progress::begin(
						&pending.root,
						step_limits,
						Some(&snapshot.source),
						MAX_SNAPSHOT_BYTES,
						|bytes| reserve(cache, pending, bytes),
					)?);
				}
				let remaining = step_limits.time.saturating_sub(step_started.elapsed());
				if remaining.is_zero() {
					continue;
				}
				scan.as_mut()
					.context("inventory validation unavailable")?
					.validate_step(
						&pending.root,
						InventoryLimits {
							time: remaining,
							..step_limits
						},
						&snapshot.source,
					)?
			}
		};
		if started.elapsed() >= total_budget {
			bail!("durable inventory observation deadline exceeded; no partial inventory returned");
		}
		if complete {
			let interval = ObservationInterval::finish(unix, started)?;
			return match work {
				Work::Observe(Some(scan)) => {
					let (rows, source) = scan.finish()?;
					Ok(Completed::Observe(Box::new(snapshot_from_rows(
						&pending.root,
						pending.host.as_deref(),
						rows,
						source,
						interval,
					)?)))
				}
				Work::Validate {
					scan,
					snapshot,
					after,
				} => {
					drop(scan);
					Ok(Completed::Validate {
						snapshot,
						after,
						interval,
					})
				}
				Work::Observe(None) => bail!("inventory observation unavailable"),
			};
		}
		#[cfg(test)]
		tests::after_step(&pending.root);
		std::thread::yield_now();
	}
}

fn worker_body(
	work: Work,
	pending: &Pending,
	cache: &Mutex<SnapshotCache>,
	limits: InventoryLimits,
) {
	let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
		run_work(work, pending, cache, limits)
	}))
	.unwrap_or_else(|_| Err(anyhow::anyhow!("durable inventory worker unavailable")));
	let result = result.and_then(|completed| {
		let bytes = match &completed {
			Completed::Observe(snapshot) => snapshot.retained_bytes,
			Completed::Validate { after, .. } => after.capacity(),
		};
		reserve(cache, pending, bytes)?;
		Ok((completed, bytes))
	});
	match result {
		Ok((completed, bytes)) => {
			if let Ok(mut state) = pending.state.lock() {
				*state = State::Ready(completed);
				drop(state);
				shrink_after_drop(cache, pending, bytes);
			}
		}
		Err(error) => {
			if let Some(snapshot) = &pending.original {
				snapshot.invalidated.store(true, Ordering::Release);
			}
			// run_work has dropped every partial proof and row before uncharging.
			let text = error.to_string();
			let mut end = text.len().min(MAX_ERROR_BYTES);
			while !text.is_char_boundary(end) {
				end -= 1;
			}
			if let Ok(mut state) = pending.state.lock() {
				*state = State::Failed(text[..end].to_owned());
			}
			shrink_after_drop(cache, pending, 0);
		}
	}
}

fn start(
	root: &Path,
	params: &ProcessListPageParams,
	limits: InventoryLimits,
	cache: &Arc<Mutex<SnapshotCache>>,
	work: Work,
) -> Result<String> {
	let pending = admit(cache, Pending::new(root, params.host.as_deref(), &work)?)?;
	let owner = pending.clone();
	let worker_cache = cache.clone();
	let worker = std::thread::Builder::new()
		.name("hepta-inventory".into())
		.spawn(move || {
			worker_body(work, &owner, &worker_cache, limits);
			// Keep the owner and cache alive through every actual payload use.
			drop(owner);
		});
	match worker {
		Ok(worker) => {
			*pending
				.worker
				.lock()
				.map_err(|_| anyhow::anyhow!("inventory worker handle unavailable"))? = Some(worker);
			pending.response()
		}
		Err(error) => {
			let mut state = cache
				.lock()
				.map_err(|_| anyhow::anyhow!("inventory snapshot cache unavailable"))?;
			retire(&mut state, &pending);
			Err(error.into())
		}
	}
}

pub(super) fn start_observation(
	root: &Path,
	params: &ProcessListPageParams,
	limits: InventoryLimits,
	cache: &Arc<Mutex<SnapshotCache>>,
) -> Result<String> {
	start(root, params, limits, cache, Work::Observe(None))
}

pub(super) fn start_validation(
	root: &Path,
	params: &ProcessListPageParams,
	limits: InventoryLimits,
	cache: &Arc<Mutex<SnapshotCache>>,
	snapshot: Arc<Snapshot>,
	after: &str,
) -> Result<String> {
	start(
		root,
		params,
		limits,
		cache,
		Work::Validate {
			scan: None,
			snapshot,
			after: after.to_owned(),
		},
	)
}

pub(super) fn resume(
	root: &Path,
	params: &ProcessListPageParams,
	cache: &Arc<Mutex<SnapshotCache>>,
	token: &str,
	step: u64,
) -> Result<String> {
	if step != 0 {
		bail!("invalid inventory pending cursor");
	}
	let pending = {
		let mut state = cache
			.lock()
			.map_err(|_| anyhow::anyhow!("inventory snapshot cache unavailable"))?;
		state.prune(Instant::now());
		state.pending.iter().find(|entry| entry.root == root && entry.host == params.host
			&& entry.token == token && !entry.expired(Instant::now())).cloned()
			.context("inventory progress cursor unavailable, expired or invalidated; restart from the first page")?
	};
	// Polls neither advance nor restart work. The thread-completion fence also
	// covers result publication and the retained payload reservation's lifetime.
	if !pending.finished() {
		return pending.response();
	}
	let completed = {
		let mut state = pending
			.state
			.lock()
			.map_err(|_| anyhow::anyhow!("inventory result unavailable"))?;
		std::mem::replace(&mut *state, State::Claimed)
	};
	let result = match completed {
		State::Ready(Completed::Observe(snapshot)) => {
			let output = if snapshot.expired(Instant::now()) {
				Err(anyhow::anyhow!(
					"inventory snapshot expired or invalidated; restart from the first page"
				))
			} else {
				render(&snapshot, params, None, None)
			};
			match output {
				Ok((text, more)) => {
					let mut state = cache
						.lock()
						.map_err(|_| anyhow::anyhow!("inventory snapshot cache unavailable"))?;
					if more {
						retire(&mut state, &pending);
						state.insert(*snapshot, Instant::now())?;
					} else {
						drop(snapshot);
						retire(&mut state, &pending);
					}
					return Ok(text);
				}
				Err(error) => {
					drop(snapshot);
					Err(error)
				}
			}
		}
		State::Ready(Completed::Validate {
			snapshot,
			after,
			interval,
		}) => {
			if snapshot.expired(Instant::now()) {
				Err(anyhow::anyhow!(
					"inventory snapshot expired or invalidated; restart from the first page"
				))
			} else {
				render(&snapshot, params, Some(&after), Some(interval)).map(|(text, _)| text)
			}
		}
		State::Failed(message) => Err(anyhow::anyhow!(message)),
		State::Working => {
			if let Some(snapshot) = &pending.original {
				snapshot.invalidated.store(true, Ordering::Release);
			}
			Err(anyhow::anyhow!(
				"durable inventory worker exited without a complete result"
			))
		}
		State::Claimed => {
			bail!("inventory progress cursor already claimed; restart from the first page")
		}
	};
	// Owned completion payloads have left the match before reservation removal.
	let mut state = cache
		.lock()
		.map_err(|_| anyhow::anyhow!("inventory snapshot cache unavailable"))?;
	retire(&mut state, &pending);
	result
}

#[cfg(test)]
#[path = "jobs_inventory_pending_tests.rs"]
pub(super) mod tests;
