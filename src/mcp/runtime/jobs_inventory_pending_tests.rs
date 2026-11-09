// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Deterministic worker lifetime and poll-independence checks over local fixtures.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::mpsc::{self, Receiver, Sender};

struct Hook {
	entered: Mutex<Option<Sender<()>>>,
	release: Mutex<Option<Receiver<()>>>,
	starts: AtomicUsize,
	limit: Option<Duration>,
}

static HOOKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Hook>>>> = OnceLock::new();

pub(in super::super) struct Gate {
	root: PathBuf,
	hook: Arc<Hook>,
	entered: Receiver<()>,
	release: Option<Sender<()>>,
}

impl Gate {
	pub(in super::super) fn wait(&self) {
		self.entered.recv_timeout(Duration::from_secs(5)).unwrap();
	}
	pub(in super::super) fn release(&mut self) {
		if let Some(sender) = self.release.take() {
			sender.send(()).unwrap();
		}
	}
	pub(in super::super) fn starts(&self) -> usize {
		self.hook.starts.load(Ordering::Acquire)
	}
}

impl Drop for Gate {
	fn drop(&mut self) {
		self.release.take();
		HOOKS
			.get_or_init(|| Mutex::new(HashMap::new()))
			.lock()
			.unwrap()
			.remove(&self.root);
	}
}

fn hook(root: &Path) -> Option<Arc<Hook>> {
	HOOKS
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.unwrap()
		.get(root)
		.cloned()
}

pub(super) fn worker_started(root: &Path) {
	if let Some(hook) = hook(root) {
		hook.starts.fetch_add(1, Ordering::AcqRel);
	}
}

pub(super) fn observation_limit(root: &Path) -> Option<Duration> {
	hook(root).and_then(|hook| hook.limit)
}

pub(super) fn after_step(root: &Path) {
	if let Some(hook) = hook(root) {
		let entered = hook.entered.lock().unwrap().take();
		if let Some(entered) = entered {
			entered.send(()).unwrap();
			let release = hook.release.lock().unwrap().take();
			if let Some(release) = release {
				let _ = release.recv();
			}
		}
	}
}

pub(in super::super) fn block_after_step(root: &Path) -> Gate {
	block_with_limit(root, None)
}

fn block_with_limit(root: &Path, limit: Option<Duration>) -> Gate {
	let (entered, observed) = mpsc::channel();
	let (release, held) = mpsc::channel();
	let hook = Arc::new(Hook {
		entered: Mutex::new(Some(entered)),
		release: Mutex::new(Some(held)),
		starts: AtomicUsize::new(0),
		limit,
	});
	assert!(HOOKS
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.unwrap()
		.insert(root.to_path_buf(), hook.clone())
		.is_none());
	Gate {
		root: root.to_path_buf(),
		hook,
		entered: observed,
		release: Some(release),
	}
}

fn fixture() -> (tempfile::TempDir, PathBuf) {
	let owner = tempfile::tempdir().unwrap();
	let root = owner.path().canonicalize().unwrap().join("state");
	std::fs::create_dir(&root).unwrap();
	std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
	std::fs::create_dir(root.join("jobs")).unwrap();
	for index in 0..5 {
		let record = json!({"id":format!("job-{index}"),"host":"main","ssh_target":"PRIVATE",
			"unit":"PRIVATE","remote_job_dir":"/PRIVATE","executable":"/bin/true","args":[],
			"cwd":null,"env_keys":[],"created_unix_ms":1,"idempotency_key":null,"request_fingerprint":0});
		let path = root.join(format!("jobs/job-{index}.json"));
		std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
		std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
	}
	(owner, root)
}

fn limits() -> InventoryLimits {
	InventoryLimits {
		bytes: 400,
		..InventoryLimits::default()
	}
}
fn request() -> ProcessListPageParams {
	ProcessListPageParams {
		limit: Some(1),
		..ProcessListPageParams::default()
	}
}

pub(in super::super) fn wait_finished(cache: &Arc<Mutex<SnapshotCache>>) {
	let began = Instant::now();
	loop {
		if cache
			.lock()
			.unwrap()
			.pending
			.iter()
			.all(|pending| pending.finished())
		{
			return;
		}
		assert!(began.elapsed() < Duration::from_secs(5));
		std::thread::sleep(Duration::from_millis(1));
	}
}

#[test]
fn background_validation_finishes_without_any_continuation_call() {
	let (_owner, root) = fixture();
	let cache = Arc::new(Mutex::new(SnapshotCache::default()));
	let mut gate = block_after_step(&root);
	let initial: Value =
		serde_json::from_str(&request_at(&root, &request(), limits(), &cache).unwrap()).unwrap();
	gate.wait();
	let mut poll = request();
	poll.cursor = initial["next_cursor"].as_str().map(str::to_owned);
	let started = cache
		.lock()
		.unwrap()
		.pending
		.front()
		.unwrap()
		.started
		.get()
		.unwrap()
		.0;
	for _ in 0..5 {
		let next: Value =
			serde_json::from_str(&request_at(&root, &poll, limits(), &cache).unwrap()).unwrap();
		assert_eq!(next["next_cursor"], initial["next_cursor"]);
		assert_eq!(gate.starts(), 1);
		assert_eq!(
			cache
				.lock()
				.unwrap()
				.pending
				.front()
				.unwrap()
				.started
				.get()
				.unwrap()
				.0,
			started
		);
	}
	gate.release();
	wait_finished(&cache);
	let final_page: Value =
		serde_json::from_str(&request_at(&root, &poll, limits(), &cache).unwrap()).unwrap();
	assert_eq!(final_page["total"], 5);
	assert_eq!(final_page["validation_pending"], false);
	assert_eq!(final_page["observation_atomic"], false);
	assert!(
		final_page["source_validation"]["elapsed_ms"]
			.as_u64()
			.unwrap() < 30_000
	);
}

#[test]
fn total_deadline_is_not_renewed_by_steps_or_polls_and_partial_payload_drops() {
	let (_owner, root) = fixture();
	let cache = Arc::new(Mutex::new(SnapshotCache::default()));
	let mut gate = block_with_limit(&root, Some(Duration::from_millis(200)));
	let initial: Value =
		serde_json::from_str(&request_at(&root, &request(), limits(), &cache).unwrap()).unwrap();
	gate.wait();
	let mut poll = request();
	poll.cursor = initial["next_cursor"].as_str().map(str::to_owned);
	for _ in 0..4 {
		assert!(request_at(&root, &poll, limits(), &cache).is_ok());
		std::thread::sleep(Duration::from_millis(60));
	}
	gate.release();
	wait_finished(&cache);
	let error = request_at(&root, &poll, limits(), &cache).unwrap_err();
	assert!(error.to_string().contains("observation deadline"));
	let state = cache.lock().unwrap();
	assert!(state.pending.is_empty());
	assert!(state.entries.is_empty());
	assert_eq!(state.bytes, 0);
}

#[test]
fn abandoned_caller_keeps_retained_bytes_but_leaves_no_cache_reference_cycle() {
	let (_owner, root) = fixture();
	let cache = Arc::new(Mutex::new(SnapshotCache::default()));
	let weak = Arc::downgrade(&cache);
	let mut gate = block_after_step(&root);
	let _ = request_at(&root, &request(), limits(), &cache).unwrap();
	gate.wait();
	assert!(cache.lock().unwrap().bytes > 0);
	assert!(!remove_idle_entry(&mut cache.lock().unwrap()));
	drop(cache);
	assert!(weak.upgrade().is_some());
	gate.release();
	let started = Instant::now();
	while weak.upgrade().is_some() {
		assert!(started.elapsed() < Duration::from_secs(5));
		std::thread::sleep(Duration::from_millis(1));
	}
}

#[test]
fn more_than_four_active_observations_complete_within_the_shared_byte_budget() {
	let cache = Arc::new(Mutex::new(SnapshotCache::default()));
	let mut active = Vec::new();
	for _ in 0..IDLE_SNAPSHOT_TARGET + 2 {
		let (owner, root) = fixture();
		let gate = block_after_step(&root);
		let params = ProcessListPageParams {
			limit: Some(128),
			..request()
		};
		let first: Value =
			serde_json::from_str(&request_at(&root, &params, limits(), &cache).unwrap()).unwrap();
		assert_eq!(first["validation_pending"], true);
		gate.wait();
		let mut poll = params;
		poll.cursor = first["next_cursor"].as_str().map(str::to_owned);
		active.push((owner, root, gate, poll));
	}
	{
		let mut state = cache.lock().unwrap();
		assert_eq!(state.pending.len(), IDLE_SNAPSHOT_TARGET + 2);
		assert!(state.entries.is_empty());
		assert!(state.pending.iter().all(|pending| !pending.finished()));
		let bytes = state.bytes;
		assert!(bytes > 0 && bytes < MAX_SNAPSHOT_BYTES);
		assert_eq!(
			bytes,
			state
				.pending
				.iter()
				.map(|p| p.reserved_bytes())
				.sum::<usize>()
		);
		state.prune(Instant::now() + SNAPSHOT_TTL + Duration::from_secs(1));
		assert_eq!(state.pending.len(), IDLE_SNAPSHOT_TARGET + 2);
		assert_eq!(
			state.bytes, bytes,
			"expired live workers must remain charged"
		);
	}
	for (_, _, gate, _) in &mut active {
		gate.release();
	}
	wait_finished(&cache);
	for (_, root, gate, poll) in &active {
		let page: Value =
			serde_json::from_str(&request_at(root, poll, limits(), &cache).unwrap()).unwrap();
		assert_eq!(gate.starts(), 1);
		assert_eq!(page["validation_pending"], false);
		assert_eq!(page["total"], 5);
		assert_eq!(page["jobs"].as_array().unwrap().len(), 5);
		assert_eq!(page["inventory_complete"], true);
		assert!(page["next_cursor"].is_null());
	}
	let state = cache.lock().unwrap();
	assert!(state.entries.is_empty() && state.pending.is_empty());
	assert_eq!(state.bytes, 0);
}

fn large_fixture() -> (tempfile::TempDir, PathBuf, InventoryLimits) {
	let (owner, root) = fixture();
	for index in 0..5 {
		let path = root.join(format!("jobs/job-{index}.json"));
		let mut record: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
		record["launch_state"] = json!("X".repeat(3 * 1024 * 1024));
		std::fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
	}
	let bytes = std::fs::metadata(root.join("jobs/job-0.json"))
		.unwrap()
		.len();
	(
		owner,
		root,
		InventoryLimits {
			bytes: bytes * 4,
			..InventoryLimits::default()
		},
	)
}

#[test]
fn shared_byte_pressure_refuses_growth_and_cancelled_workers_stay_charged_until_exit() {
	let cache = Arc::new(Mutex::new(SnapshotCache::default()));
	let mut held = Vec::new();
	for _ in 0..2 {
		let (owner, root, step_limits) = large_fixture();
		let gate = block_after_step(&root);
		let _ = request_at(&root, &request(), step_limits, &cache).unwrap();
		gate.wait();
		held.push((owner, gate));
	}
	let charged = cache.lock().unwrap().bytes;
	assert!(charged > 24 * 1024 * 1024 && charged < MAX_SNAPSHOT_BYTES);
	let (_owner, root, step_limits) = large_fixture();
	let first: Value =
		serde_json::from_str(&request_at(&root, &request(), step_limits, &cache).unwrap()).unwrap();
	let mut poll = request();
	poll.cursor = first["next_cursor"].as_str().map(str::to_owned);
	let third = cache.lock().unwrap().pending.back().unwrap().clone();
	let began = Instant::now();
	while !third.finished() {
		assert!(began.elapsed() < Duration::from_secs(5));
		assert!(cache.lock().unwrap().bytes <= MAX_SNAPSHOT_BYTES);
		std::thread::sleep(Duration::from_millis(1));
	}
	let error = request_at(&root, &poll, step_limits, &cache).unwrap_err();
	assert!(error.to_string().contains("byte budget in use"));
	drop(third);
	let expired = Instant::now() + SNAPSHOT_TTL + Duration::from_secs(1);
	{
		let mut state = cache.lock().unwrap();
		assert_eq!(state.pending.len(), 2);
		assert_eq!(
			state.bytes, charged,
			"failed work must drop its partial rows first"
		);
		for pending in &state.pending {
			pending.invalidated.store(true, Ordering::Release);
		}
		state.prune(expired);
		assert!(!remove_idle_entry(&mut state));
		assert_eq!(state.pending.len(), 2);
		assert_eq!(
			state.bytes, charged,
			"cancellation cannot uncharge live payloads"
		);
	}
	for (_, gate) in &mut held {
		gate.release();
	}
	wait_finished(&cache);
	let mut state = cache.lock().unwrap();
	state.prune(expired);
	assert!(state.pending.is_empty() && state.entries.is_empty());
	assert_eq!(state.bytes, 0);
}

#[test]
fn one_completed_pending_cursor_has_only_one_successful_concurrent_claim() {
	let (_owner, root) = fixture();
	let cache = Arc::new(Mutex::new(SnapshotCache::default()));
	let mut params = ProcessListPageParams {
		limit: Some(128),
		..request()
	};
	let first: Value =
		serde_json::from_str(&request_at(&root, &params, limits(), &cache).unwrap()).unwrap();
	params.cursor = first["next_cursor"].as_str().map(str::to_owned);
	wait_finished(&cache);
	let barrier = Arc::new(std::sync::Barrier::new(3));
	let mut callers = Vec::new();
	for _ in 0..2 {
		let root = root.clone();
		let cache = cache.clone();
		let params = params.clone();
		let barrier = barrier.clone();
		callers.push(std::thread::spawn(move || {
			barrier.wait();
			request_at(&root, &params, limits(), &cache)
		}));
	}
	barrier.wait();
	let results = callers
		.into_iter()
		.map(|thread| thread.join().unwrap())
		.collect::<Vec<_>>();
	assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
	let page: Value =
		serde_json::from_str(results.iter().find_map(|r| r.as_ref().ok()).unwrap()).unwrap();
	assert_eq!(page["jobs"].as_array().unwrap().len(), 5);
	assert_eq!(page["inventory_complete"], true);
	let state = cache.lock().unwrap();
	assert!(state.pending.is_empty() && state.entries.is_empty());
	assert_eq!(state.bytes, 0);
}
