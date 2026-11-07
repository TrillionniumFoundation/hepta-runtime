// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Snapshot bounds, host/root/cursor custody and original-source invalidation.
use super::*;
use std::os::unix::fs::PermissionsExt;

struct Fixture {
	_owner: tempfile::TempDir,
	root: PathBuf,
}

impl Fixture {
	fn new(count: usize) -> Self {
		let owner = tempfile::tempdir().unwrap();
		let root = owner.path().canonicalize().unwrap().join("state");
		std::fs::create_dir(&root).unwrap();
		std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
		std::fs::create_dir(root.join("jobs")).unwrap();
		std::fs::set_permissions(root.join("jobs"), std::fs::Permissions::from_mode(0o700))
			.unwrap();
		let fixture = Self {
			_owner: owner,
			root,
		};
		for index in 0..count {
			fixture.write(index, "main", "PRIVATE_ARGUMENT");
		}
		fixture
	}

	fn path(&self, index: usize) -> PathBuf {
		self.root.join("jobs").join(format!("job-{index:05}.json"))
	}

	fn write(&self, index: usize, host: &str, argument: &str) {
		let value = json!({"id":format!("job-{index:05}"),"host":host,"created_unix_ms":index,
			"execution_mode":"operator","ssh_target":"PRIVATE_TARGET","unit":"PRIVATE_UNIT",
			"remote_job_dir":"/PRIVATE_PATH","executable":"/PRIVATE_EXECUTABLE","args":[argument],
			"cwd":null,"env_keys":[],"idempotency_key":null,"request_fingerprint":0,"launch_state":"launched"});
		std::fs::write(self.path(index), serde_json::to_vec(&value).unwrap()).unwrap();
		std::fs::set_permissions(self.path(index), std::fs::Permissions::from_mode(0o600)).unwrap();
	}
}

fn params() -> ProcessListPageParams {
	ProcessListPageParams {
		host: Some("main".into()),
		cursor: None,
		limit: Some(1),
	}
}

fn call(fixture: &Fixture, params: &ProcessListPageParams, cache: &Mutex<SnapshotCache>) -> Value {
	serde_json::from_str(
		&page_at(&fixture.root, params, InventoryLimits::default(), cache).unwrap(),
	)
	.unwrap()
}

fn continue_from(value: &Value, params: &mut ProcessListPageParams) {
	params.cursor = value["next_cursor"].as_str().map(str::to_owned);
}

#[test]
fn complete_original_pages_reuse_one_snapshot_with_unchanged_public_binding() {
	let fixture = Fixture::new(275);
	let cache = Mutex::new(SnapshotCache::default());
	let mut params = ProcessListPageParams {
		limit: Some(128),
		..params()
	};
	let original = super::super::inventory_page_rows_at(
		&fixture.root,
		Some("main"),
		InventoryLimits::default(),
	)
	.unwrap();
	let digest =
		inventory_snapshot_digest(&original, Some("main"), &fixture.root.to_string_lossy())
			.unwrap();
	let mut observed = Vec::new();
	loop {
		let page = call(&fixture, &params, &cache);
		assert_eq!(page["snapshot_sha256"], digest);
		assert_eq!(page["total"], 275);
		assert_eq!(page["status_authoritative"], false);
		assert!(!page.to_string().contains("PRIVATE_"));
		observed.extend(page["jobs"].as_array().unwrap().iter().cloned());
		continue_from(&page, &mut params);
		if params.cursor.is_none() {
			assert_eq!(page["inventory_complete"], true);
			break;
		}
	}
	assert_eq!(observed, original);
	let cache = cache.lock().unwrap();
	assert_eq!(cache.entries.len(), 1);
	assert!(cache.bytes <= MAX_SNAPSHOT_BYTES);
}

#[test]
fn every_first_page_revalidates_all_originals_before_filtering() {
	let fixture = Fixture::new(3);
	fixture.write(2, "mac", "PRIVATE_OTHER_HOST");
	let cache = Mutex::new(SnapshotCache::default());
	call(&fixture, &params(), &cache);
	std::fs::write(fixture.path(2), br#"{"args":[false]}"#).unwrap();
	let error = page_at(&fixture.root, &params(), InventoryLimits::default(), &cache).unwrap_err();
	assert!(error
		.to_string()
		.contains("corrupt durable inventory metadata"));
	assert_eq!(cache.lock().unwrap().entries.len(), 1);
}

#[test]
fn continuation_refuses_private_other_host_change_and_does_not_resurrect_after_restore() {
	let fixture = Fixture::new(3);
	fixture.write(2, "mac", "PRIVATE_BEFORE");
	let original = std::fs::read(fixture.path(2)).unwrap();
	let cache = Mutex::new(SnapshotCache::default());
	let mut params = params();
	let first = call(&fixture, &params, &cache);
	continue_from(&first, &mut params);
	fixture.write(2, "mac", "PRIVATE_AFTER_");
	assert!(page_at(&fixture.root, &params, InventoryLimits::default(), &cache).is_err());
	std::fs::write(fixture.path(2), original).unwrap();
	let error = page_at(&fixture.root, &params, InventoryLimits::default(), &cache).unwrap_err();
	assert!(error.to_string().contains("snapshot unavailable"));
	params.cursor = None;
	let fresh = call(&fixture, &params, &cache);
	assert_eq!(first["snapshot_sha256"], fresh["snapshot_sha256"]);
	assert_ne!(first["next_cursor"], fresh["next_cursor"]);
}

#[test]
fn continuation_is_bound_to_root_host_and_original_process_cache() {
	let fixture = Fixture::new(2);
	let other = Fixture::new(2);
	let cache = Mutex::new(SnapshotCache::default());
	let mut params = params();
	let first = call(&fixture, &params, &cache);
	continue_from(&first, &mut params);
	assert!(page_at(&other.root, &params, InventoryLimits::default(), &cache).is_err());
	assert!(page_at(
		&fixture.root,
		&params,
		InventoryLimits::default(),
		&Mutex::new(SnapshotCache::default())
	)
	.is_err());
	params.host = None;
	assert!(page_at(&fixture.root, &params, InventoryLimits::default(), &cache).is_err());
	params.host = Some("main".into());
	assert_eq!(call(&fixture, &params, &cache)["inventory_complete"], true);
}

#[test]
fn additions_removals_and_directory_replacements_invalidate_the_original_cursor() {
	for change in ["add", "remove", "jobs", "root"] {
		let fixture = Fixture::new(2);
		let cache = Mutex::new(SnapshotCache::default());
		let mut params = params();
		continue_from(&call(&fixture, &params, &cache), &mut params);
		match change {
			"add" => fixture.write(2, "main", "ADDED"),
			"remove" => std::fs::remove_file(fixture.path(1)).unwrap(),
			"jobs" => {
				std::fs::rename(fixture.root.join("jobs"), fixture.root.join("held-jobs")).unwrap();
				std::fs::create_dir(fixture.root.join("jobs")).unwrap();
			}
			"root" => {
				std::fs::rename(&fixture.root, fixture.root.with_file_name("held-state")).unwrap();
				std::fs::create_dir(&fixture.root).unwrap();
				std::fs::set_permissions(&fixture.root, std::fs::Permissions::from_mode(0o700))
					.unwrap();
				std::fs::create_dir(fixture.root.join("jobs")).unwrap();
			}
			_ => unreachable!(),
		}
		assert!(
			page_at(&fixture.root, &params, InventoryLimits::default(), &cache).is_err(),
			"{change}"
		);
	}
}

#[test]
fn ignored_staging_files_do_not_become_committed_inventory_rows() {
	let fixture = Fixture::new(2);
	let cache = Mutex::new(SnapshotCache::default());
	let mut params = params();
	continue_from(&call(&fixture, &params, &cache), &mut params);
	std::fs::write(
		fixture.root.join("jobs/unfinished.json.tmp.7"),
		b"not committed JSON",
	)
	.unwrap();
	assert_eq!(call(&fixture, &params, &cache)["total"], 2);
}

#[test]
fn expiration_does_not_uncharge_an_inflight_snapshot() {
	let fixture = Fixture::new(2);
	let cache = Mutex::new(SnapshotCache::default());
	let first = call(&fixture, &params(), &cache);
	let cursor = first["next_cursor"].as_str().unwrap();
	let token = cursor.split_once(':').unwrap().0;
	let mut state = cache.lock().unwrap();
	let held = state
		.lookup(&fixture.root, Some("main"), token, Instant::now())
		.unwrap();
	let expired = held.created + SNAPSHOT_TTL;
	assert!(state
		.lookup(&fixture.root, Some("main"), token, expired)
		.is_err());
	assert_eq!(state.entries.len(), 1);
	assert!(state.bytes > 0);
	drop(held);
	state.prune(expired);
	assert!(state.entries.is_empty());
	assert_eq!(state.bytes, 0);
}

#[test]
fn count_and_byte_capacity_never_evict_inflight_payloads() {
	let fixture = Fixture::new(2);
	let mut cache = SnapshotCache::default();
	let mut held = Vec::new();
	for _ in 0..MAX_SNAPSHOTS {
		let snapshot = observe(&fixture.root, Some("main"), InventoryLimits::default()).unwrap();
		let token = snapshot.token.clone();
		cache.insert(snapshot, Instant::now()).unwrap();
		held.push(
			cache
				.lookup(&fixture.root, Some("main"), &token, Instant::now())
				.unwrap(),
		);
	}
	let next = observe(&fixture.root, Some("main"), InventoryLimits::default()).unwrap();
	assert!(cache
		.insert(next, Instant::now())
		.unwrap_err()
		.to_string()
		.contains("cache busy"));
	assert_eq!(cache.entries.len(), MAX_SNAPSHOTS);
	held.pop();
	let next = observe(&fixture.root, Some("main"), InventoryLimits::default()).unwrap();
	cache.insert(next, Instant::now()).unwrap();
	assert_eq!(cache.entries.len(), MAX_SNAPSHOTS);
	let mut oversized = observe(&fixture.root, Some("main"), InventoryLimits::default()).unwrap();
	oversized.retained_bytes = MAX_SNAPSHOT_BYTES + 1;
	assert!(cache
		.insert(oversized, Instant::now())
		.unwrap_err()
		.to_string()
		.contains("byte bound"));
}

#[test]
fn page_wire_limit_shrinks_the_slice_without_changing_the_snapshot() {
	let fixture = Fixture::new(3);
	for index in 0..3 {
		let mut record: Value =
			serde_json::from_slice(&std::fs::read(fixture.path(index)).unwrap()).unwrap();
		record["launch_state"] = json!("x".repeat(24 * 1024));
		std::fs::write(fixture.path(index), serde_json::to_vec(&record).unwrap()).unwrap();
	}
	let cache = Mutex::new(SnapshotCache::default());
	let mut params = ProcessListPageParams {
		limit: Some(3),
		..params()
	};
	let first = call(&fixture, &params, &cache);
	assert_eq!(first["jobs"].as_array().unwrap().len(), 2);
	continue_from(&first, &mut params);
	let final_page = call(&fixture, &params, &cache);
	assert_eq!(first["snapshot_sha256"], final_page["snapshot_sha256"]);
	assert_eq!(final_page["inventory_complete"], true);
	assert_eq!(final_page["jobs"].as_array().unwrap().len(), 1);
}

#[test]
fn malformed_cursor_and_limit_fail_before_any_source_read() {
	let cache = Mutex::new(SnapshotCache::default());
	for (limit, cursor) in [
		(0, None),
		(129, None),
		(1, Some("x".repeat(257))),
		(1, Some("bad:job-00000".into())),
	] {
		let params = ProcessListPageParams {
			host: None,
			limit: Some(limit),
			cursor,
		};
		let error = page_at(
			Path::new("/does-not-exist"),
			&params,
			InventoryLimits::default(),
			&cache,
		)
		.unwrap_err();
		assert!(error.to_string().starts_with("invalid"));
	}
}

#[test]
fn cached_pages_do_not_bypass_the_original_source_deadline() {
	let fixture = Fixture::new(2);
	let cache = Mutex::new(SnapshotCache::default());
	let mut params = params();
	continue_from(&call(&fixture, &params, &cache), &mut params);
	let limits = InventoryLimits {
		time: Duration::ZERO,
		..InventoryLimits::default()
	};
	assert!(page_at(&fixture.root, &params, limits, &cache)
		.unwrap_err()
		.to_string()
		.contains("source time budget"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_request_keeps_actual_blocking_worker_admission_until_exit() {
	let workers = Arc::new(Semaphore::new(1));
	let worker_slots = workers.clone();
	let (entered, ready) = tokio::sync::oneshot::channel();
	let (finished, complete) = tokio::sync::oneshot::channel();
	let (release, blocked) = std::sync::mpsc::channel();
	let request = tokio::spawn(async move {
		tokio::task::spawn_blocking(move || {
			let permit = acquire_worker(&worker_slots).unwrap();
			entered.send(()).unwrap();
			blocked.recv().unwrap();
			drop(permit);
			finished.send(()).unwrap();
		})
		.await
		.unwrap();
	});
	ready.await.unwrap();
	request.abort();
	assert!(request.await.unwrap_err().is_cancelled());
	assert!(acquire_worker(&workers).is_err());
	release.send(()).unwrap();
	complete.await.unwrap();
	assert!(acquire_worker(&workers).is_ok());
}
