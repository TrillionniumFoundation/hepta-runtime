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
	assert_eq!(
		cache.lock().unwrap().workers.available_permits(),
		MAX_INVENTORY_WORKERS
	);
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
	assert_eq!(state.workers.available_permits(), MAX_INVENTORY_WORKERS);
}

#[test]
fn abandoned_caller_keeps_worker_capacity_but_leaves_no_cache_reference_cycle() {
	let (_owner, root) = fixture();
	let cache = Arc::new(Mutex::new(SnapshotCache::default()));
	let weak = Arc::downgrade(&cache);
	let workers = cache.lock().unwrap().workers.clone();
	let mut gate = block_after_step(&root);
	let _ = request_at(&root, &request(), limits(), &cache).unwrap();
	gate.wait();
	assert_eq!(workers.available_permits(), 1);
	assert!(remove_idle_entry(&mut cache.lock().unwrap()).is_err());
	drop(cache);
	assert!(weak.upgrade().is_some());
	gate.release();
	let started = Instant::now();
	while weak.upgrade().is_some() {
		assert!(started.elapsed() < Duration::from_secs(5));
		std::thread::sleep(Duration::from_millis(1));
	}
	assert_eq!(workers.available_permits(), MAX_INVENTORY_WORKERS);
}
