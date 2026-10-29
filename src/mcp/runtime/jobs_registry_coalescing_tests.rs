// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Concurrent cold readers share only completely scanned positive bindings.
use super::*;
use std::cell::{Cell, RefCell};
use std::os::unix::fs::PermissionsExt;
use std::sync::Condvar;

thread_local! {
	static AFTER_REGISTRATION: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
	static ON_SCAN: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
	static AFTER_SCAN: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
	static ON_COHORT_WAIT: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
	static SCANS: Cell<usize> = const { Cell::new(0) };
}

pub(super) fn after_registration() {
	let hook = AFTER_REGISTRATION.with(|slot| slot.borrow_mut().take());
	if let Some(hook) = hook {
		hook();
	}
}

pub(super) fn scan_started() {
	SCANS.with(|count| count.set(count.get() + 1));
	let hook = ON_SCAN.with(|slot| slot.borrow_mut().take());
	if let Some(hook) = hook {
		hook();
	}
}

pub(super) fn cohort_wait_started() {
	let hook = ON_COHORT_WAIT.with(|slot| slot.borrow_mut().take());
	if let Some(hook) = hook {
		hook();
	}
}

pub(super) fn scan_finished() {
	let hook = AFTER_SCAN.with(|slot| slot.borrow_mut().take());
	if let Some(hook) = hook {
		hook();
	}
}

struct Hooks;

impl Hooks {
	fn new() -> Self {
		SCANS.with(|count| count.set(0));
		Self
	}
}

impl Drop for Hooks {
	fn drop(&mut self) {
		AFTER_REGISTRATION.with(|slot| slot.borrow_mut().take());
		ON_SCAN.with(|slot| slot.borrow_mut().take());
		AFTER_SCAN.with(|slot| slot.borrow_mut().take());
		ON_COHORT_WAIT.with(|slot| slot.borrow_mut().take());
	}
}

fn record(id: &str, host: &str, key: &str, state: &str) -> JobRecord {
	serde_json::from_value(json!({
		"id":id, "host":host, "ssh_target":"never-connect.invalid",
		"unit":format!("unit-{id}"), "remote_job_dir":format!("/never-launch/{id}"),
		"executable":"/usr/bin/true", "args":[], "cwd":null, "env_keys":[],
		"created_unix_ms":1, "idempotency_key":key, "request_fingerprint":1,
		"request_digest":"a".repeat(64), "launch_state":state
	}))
	.unwrap()
}

fn write(root: &Path, value: &JobRecord) {
	save_record_at(&root.join(format!("{}.json", value.id)), value).unwrap();
}

fn no_watch(root: &Path) -> Result<RegistryEpoch> {
	let mut epoch = registry_epoch(root)?;
	epoch.content = None;
	Ok(epoch)
}

fn demand(scans: &Arc<RegistryColdScans>, host: &str, key: &str) -> RegistryColdDemand {
	RegistryColdDemand::register(scans.clone(), host, key)
		.unwrap()
		.unwrap()
}

fn share_from(
	root: &Path,
	leader: &RegistryColdDemand,
	probe: impl Fn(&Path) -> Result<RegistryEpoch>,
) -> Option<JobRecord> {
	let mut cohort = leader.cohort().unwrap();
	let (found, epoch) = scan_idempotent_binding_cohort(
		root,
		&leader.identity.0,
		&leader.identity.1,
		None,
		&probe,
		RegistryScanObserver {
			cohort: &mut cohort,
			after_scan: |_| {},
		},
	)
	.unwrap();
	leader.publish(cohort, epoch).unwrap();
	found
}

#[cfg(target_os = "linux")]
#[test]
fn four_invalidated_known_hosts_share_one_complete_scan_and_retain_originals() {
	let root = tempfile::tempdir().unwrap();
	let cache = Arc::new(Mutex::new(ReuseHitCache::default()));
	for index in 0..4 {
		write(
			root.path(),
			&record(
				&format!("original-{index}"),
				&format!("host-{index}"),
				"same-key",
				"launched",
			),
		);
	}
	assert!(registry_has_content_watch(
		&registry_epoch(root.path()).unwrap()
	));
	for index in 0..4 {
		find_idempotent_in(root.path(), &format!("host-{index}"), "same-key", &cache).unwrap();
	}
	assert!(cache
		.lock()
		.unwrap()
		.known
		.values()
		.all(|binding| binding.strict));
	std::fs::write(root.path().join("invalidate.marker"), b"changed").unwrap();
	let registered = Arc::new((Mutex::new(0), Condvar::new()));
	let frozen = Arc::new((Mutex::new(false), Condvar::new()));
	let workers: Vec<_> = (0..4)
		.map(|index| {
			let root = root.path().to_owned();
			let cache = cache.clone();
			let registered = registered.clone();
			let frozen = frozen.clone();
			std::thread::spawn(move || {
				let _hooks = Hooks::new();
				if index == 0 {
					let frozen = frozen.clone();
					ON_SCAN.with(|slot| {
						*slot.borrow_mut() = Some(Box::new(move || {
							*frozen.0.lock().unwrap() = true;
							frozen.1.notify_all();
						}))
					});
				}
				AFTER_REGISTRATION.with(|slot| {
					*slot.borrow_mut() = Some(Box::new(move || {
						let (lock, changed) = &*registered;
						let mut count = lock.lock().unwrap();
						*count += 1;
						changed.notify_all();
						let (count, timeout) = changed
							.wait_timeout_while(count, Duration::from_secs(10), |count| *count < 4)
							.unwrap();
						assert!(!timeout.timed_out(), "only {count} workers registered");
						drop(count);
						if index != 0 {
							let (lock, changed) = &*frozen;
							let (_frozen, timeout) = changed
								.wait_timeout_while(
									lock.lock().unwrap(),
									Duration::from_secs(10),
									|ready| !*ready,
								)
								.unwrap();
							assert!(!timeout.timed_out(), "leader never froze the cohort");
						}
					}))
				});
				let found = find_idempotent_in(&root, &format!("host-{index}"), "same-key", &cache)
					.unwrap()
					.unwrap();
				assert_eq!(found.id, format!("original-{index}"));
				SCANS.with(Cell::get)
			})
		})
		.collect();
	let scans: usize = workers
		.into_iter()
		.map(|worker| worker.join().unwrap())
		.sum();
	assert_eq!(scans, 1);
	let cache = cache.lock().unwrap();
	assert_eq!(cache.known.len(), 4);
	assert_eq!(cache.hits.len(), 4);
	assert!(cache.known.values().all(|binding| binding.strict));
	let cold = cache.cold.state.lock().unwrap();
	assert!(cold.demands.is_empty());
	assert!(cold.hints.is_empty());
	assert!(cold.active.is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn duplicate_target_never_resurrects_a_hint_or_rejects_healthy_leader() {
	let root = tempfile::tempdir().unwrap();
	let scans = Arc::new(RegistryColdScans::default());
	let leader = demand(&scans, "main", "healthy");
	let duplicate = demand(&scans, "main", "duplicate");
	write(
		root.path(),
		&record("healthy-original", "main", "healthy", "launched"),
	);
	for index in 0..3 {
		write(
			root.path(),
			&record(
				&format!("duplicate-{index}"),
				"main",
				"duplicate",
				"launched",
			),
		);
	}
	assert_eq!(
		share_from(root.path(), &leader, registry_epoch).unwrap().id,
		"healthy-original"
	);
	assert!(duplicate
		.read_hint(root.path(), &registry_epoch)
		.unwrap()
		.is_none());
	assert!(scan_idempotent_binding_in(root.path(), "main", "duplicate")
		.unwrap_err()
		.to_string()
		.contains("duplicate original"));
}

#[cfg(target_os = "linux")]
#[test]
fn sharing_requires_the_same_generation_and_fresh_complete_receipt() {
	let root = tempfile::tempdir().unwrap();
	let scans = Arc::new(RegistryColdScans::default());
	let leader = demand(&scans, "main", "leader");
	let waiter = demand(&scans, "main", "waiter");
	write(
		root.path(),
		&record("leader-original", "main", "leader", "launched"),
	);
	let mut original = record("waiter-original", "main", "waiter", "launched");
	write(root.path(), &original);
	share_from(root.path(), &leader, registry_epoch);
	assert_eq!(
		waiter
			.read_hint(root.path(), &registry_epoch)
			.unwrap()
			.unwrap()
			.id,
		original.id
	);
	original.args.push("changed".into());
	write(root.path(), &original);
	assert!(waiter
		.read_hint(root.path(), &registry_epoch)
		.unwrap()
		.is_none());
	let mut cohort = leader.cohort().unwrap();
	let (_, epoch) = scan_idempotent_binding_cohort(
		root.path(),
		"main",
		"leader",
		None,
		&registry_epoch,
		RegistryScanObserver {
			cohort: &mut cohort,
			after_scan: |_| {},
		},
	)
	.unwrap();
	leader.publish(cohort, epoch).unwrap();
	// A stale content token alone cannot make a changed complete receipt pass.
	original.args.push("changed-again".into());
	write(root.path(), &original);
	assert!(waiter
		.read_hint(root.path(), &|_| Ok(epoch))
		.unwrap()
		.is_none());
}

#[test]
fn missing_pending_and_watchless_targets_never_publish_hints() {
	let root = tempfile::tempdir().unwrap();
	let scans = Arc::new(RegistryColdScans::default());
	let leader = demand(&scans, "main", "leader");
	let missing = demand(&scans, "main", "missing");
	let pending = demand(&scans, "main", "pending");
	let launched = demand(&scans, "main", "launched");
	for (key, state) in [
		("leader", "launched"),
		("pending", "pending"),
		("launched", "launched"),
	] {
		write(
			root.path(),
			&record(&format!("original-{key}"), "main", key, state),
		);
	}
	share_from(root.path(), &leader, registry_epoch);
	assert!(missing
		.read_hint(root.path(), &registry_epoch)
		.unwrap()
		.is_none());
	assert!(pending
		.read_hint(root.path(), &registry_epoch)
		.unwrap()
		.is_none());
	scans.state.lock().unwrap().hints.clear();
	let _hooks = Hooks::new();
	share_from(root.path(), &leader, no_watch);
	assert_eq!(SCANS.with(Cell::get), 2);
	assert!(launched
		.read_hint(root.path(), &no_watch)
		.unwrap()
		.is_none());
	assert!(scans.state.lock().unwrap().hints.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn legacy_hint_falls_back_to_full_compatibility_scan_without_strict_promotion() {
	for large in [false, true] {
		let root = tempfile::tempdir().unwrap();
		let cache = Mutex::new(ReuseHitCache::default());
		let scans = cache.lock().unwrap().cold.clone();
		let leader = demand(&scans, "main", "leader");
		let waiter = demand(&scans, "main", "legacy");
		write(
			root.path(),
			&record("leader-original", "main", "leader", "launched"),
		);
		let mut legacy = record("legacy-original", "main", "legacy", "launched");
		if large {
			legacy
				.args
				.push("x".repeat(MAX_CACHED_RECORD_BYTES as usize));
		}
		write(root.path(), &legacy);
		if !large {
			std::fs::set_permissions(
				root.path().join("legacy-original.json"),
				std::fs::Permissions::from_mode(0o644),
			)
			.unwrap();
		}
		share_from(root.path(), &leader, registry_epoch);
		assert!(waiter
			.read_hint(root.path(), &registry_epoch)
			.unwrap()
			.is_none());
		let _hooks = Hooks::new();
		assert_eq!(
			find_idempotent_in(root.path(), "main", "legacy", &cache)
				.unwrap()
				.unwrap()
				.id,
			legacy.id
		);
		assert_eq!(SCANS.with(Cell::get), 1);
		let cache = cache.lock().unwrap();
		assert!(!cache.known[&("main".into(), "legacy".into())].strict);
		assert!(cache.hits.is_empty());
	}
}

#[test]
fn cold_demand_has_worker_byte_and_lifetime_bounds() {
	let scans = Arc::new(RegistryColdScans::default());
	let mut guards = Vec::new();
	for index in 0..MAX_REGISTRY_LOOKUPS {
		guards.push(demand(&scans, "main", &format!("key-{index}")));
	}
	assert!(RegistryColdDemand::register(scans.clone(), "main", "extra")
		.unwrap()
		.is_none());
	guards.pop();
	assert!(RegistryColdDemand::register(
		scans.clone(),
		"main",
		&"x".repeat(MAX_COLD_DEMAND_BYTES)
	)
	.unwrap()
	.is_none());
	drop(guards);
	assert!(scans.state.lock().unwrap().demands.is_empty());
	assert!(scans.state.lock().unwrap().hints.is_empty());
	let first = demand(&scans, "main", "same");
	let second = demand(&scans, "main", "same");
	assert_eq!(
		scans.state.lock().unwrap().demands[&("main".into(), "same".into())],
		2
	);
	drop(first);
	assert_eq!(
		scans.state.lock().unwrap().demands[&("main".into(), "same".into())],
		1
	);
	drop(second);
	assert!(scans.state.lock().unwrap().demands.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn later_demand_is_excluded_and_retry_discards_earlier_hint() {
	let root = tempfile::tempdir().unwrap();
	let scans = Arc::new(RegistryColdScans::default());
	let leader = demand(&scans, "main", "leader");
	let waiter = demand(&scans, "main", "waiter");
	write(
		root.path(),
		&record("leader-original", "main", "leader", "launched"),
	);
	write(
		root.path(),
		&record("waiter-original", "main", "waiter", "launched"),
	);
	write(
		root.path(),
		&record("late-original", "main", "late", "launched"),
	);
	let mut cohort = leader.cohort().unwrap();
	let late = demand(&scans, "main", "late");
	let mut attempts = 0;
	let (found, epoch) = scan_idempotent_binding_cohort(
		root.path(),
		"main",
		"leader",
		None,
		&registry_epoch,
		RegistryScanObserver {
			cohort: &mut cohort,
			after_scan: |attempt| {
				attempts += 1;
				if attempt == 0 {
					std::fs::remove_file(root.path().join("waiter-original.json")).unwrap();
				}
			},
		},
	)
	.unwrap();
	assert_eq!(found.unwrap().id, "leader-original");
	assert_eq!(attempts, 2);
	leader.publish(cohort, epoch).unwrap();
	assert!(waiter
		.read_hint(root.path(), &registry_epoch)
		.unwrap()
		.is_none());
	assert!(late
		.read_hint(root.path(), &registry_epoch)
		.unwrap()
		.is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn corruption_never_publishes_partial_cohort_hints() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	let scans = cache.lock().unwrap().cold.clone();
	let _waiter = demand(&scans, "main", "waiter");
	write(
		root.path(),
		&record("leader-original", "main", "leader", "launched"),
	);
	write(
		root.path(),
		&record("waiter-original", "main", "waiter", "launched"),
	);
	find_idempotent_in(root.path(), "main", "leader", &cache).unwrap();
	assert!(cache.lock().unwrap().known[&("main".into(), "leader".into())].strict);
	std::fs::write(root.path().join("broken.json"), b"not-json").unwrap();
	assert!(find_idempotent_in(root.path(), "main", "leader", &cache)
		.unwrap_err()
		.to_string()
		.contains("corrupt job record"));
	let state = scans.state.lock().unwrap();
	assert_eq!(state.demands.len(), 1);
	assert!(state.hints.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn early_registered_waiter_keeps_its_original_strict_read_before_shared_hints() {
	let root = tempfile::tempdir().unwrap();
	let cache = Arc::new(Mutex::new(ReuseHitCache::default()));
	for key in ["leader", "waiter"] {
		write(
			root.path(),
			&record(&format!("original-{key}"), "main", key, "launched"),
		);
	}
	for key in ["leader", "waiter"] {
		find_idempotent_in(root.path(), "main", key, &cache).unwrap();
	}
	assert!(cache
		.lock()
		.unwrap()
		.known
		.values()
		.all(|binding| binding.strict));
	std::fs::write(root.path().join("invalidate.marker"), b"changed").unwrap();
	let scans = cache.lock().unwrap().cold.clone();
	let (registered, ready) = std::sync::mpsc::channel();
	let (release, released) = std::sync::mpsc::channel();
	let waiter_root = root.path().to_owned();
	let waiter_cache = cache.clone();
	let waiter = std::thread::spawn(move || {
		let _hooks = Hooks::new();
		AFTER_REGISTRATION.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || {
				registered.send(()).unwrap();
				released.recv_timeout(Duration::from_secs(20)).unwrap();
			}))
		});
		let result = find_idempotent_in(&waiter_root, "main", "waiter", &waiter_cache)
			.map(|found| found.map(|record| record.id))
			.map_err(|error| error.to_string());
		(result, SCANS.with(Cell::get))
	});
	let waiter_registered = ready.recv_timeout(Duration::from_secs(5));
	let (completed, completion) = std::sync::mpsc::channel();
	let leader_root = root.path().to_owned();
	let leader_cache = cache.clone();
	let leader = std::thread::spawn(move || {
		let _hooks = Hooks::new();
		let result = find_idempotent_in(&leader_root, "main", "leader", &leader_cache)
			.map(|found| found.map(|record| record.id))
			.map_err(|error| error.to_string());
		let _ = completed.send(());
		(result, SCANS.with(Cell::get))
	});
	let leader_completed = completion.recv_timeout(Duration::from_secs(5));
	let published_hint = scans
		.state
		.lock()
		.map(|state| {
			state
				.hints
				.get(&("main".into(), "waiter".into()))
				.map(|hint| hint.id.clone())
		})
		.map_err(|error| error.to_string());
	let permission_change = std::fs::set_permissions(
		root.path().join("original-waiter.json"),
		std::fs::Permissions::from_mode(0o644),
	);
	// Release and join both original workers before inspecting any failure.
	// A misplaced hook or gate therefore fails without stranding the waiter.
	let release_sent = release.send(());
	let waiter_result = waiter.join();
	let leader_result = leader.join();
	assert!(waiter_registered.is_ok(), "waiter never registered");
	assert!(
		leader_completed.is_ok(),
		"leader did not publish while waiter paused"
	);
	assert_eq!(published_hint.unwrap().as_deref(), Some("original-waiter"));
	permission_change.unwrap();
	release_sent.unwrap();
	let (leader_result, leader_scans) = leader_result.unwrap();
	assert_eq!(leader_result.unwrap().as_deref(), Some("original-leader"));
	assert_eq!(leader_scans, 1);
	let (waiter_result, waiter_scans) = waiter_result.unwrap();
	assert!(waiter_result
		.unwrap_err()
		.contains("previous idempotency binding could not be verified"));
	// If the hook still ran after the strict read, chmod would instead be
	// discovered by a later scan. The early strict refusal must precede it.
	assert_eq!(waiter_scans, 0);
	let state = scans.state.lock().unwrap();
	assert!(state.demands.is_empty());
	assert!(state.hints.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn warm_hit_does_not_wait_for_a_cold_scan_gate() {
	let root = tempfile::tempdir().unwrap();
	let cache = Arc::new(Mutex::new(ReuseHitCache::default()));
	for key in ["warm", "cold"] {
		write(
			root.path(),
			&record(&format!("original-{key}"), "main", key, "launched"),
		);
	}
	find_idempotent_in(root.path(), "main", "cold", &cache).unwrap();
	assert!(cache.lock().unwrap().known[&("main".into(), "cold".into())].strict);
	std::fs::write(root.path().join("invalidate.marker"), b"changed").unwrap();
	find_idempotent_in(root.path(), "main", "warm", &cache).unwrap();
	assert_eq!(cache.lock().unwrap().hits.len(), 1);
	let scans = cache.lock().unwrap().cold.clone();
	let held = scans.gate.lock().unwrap();
	let (registered, ready) = std::sync::mpsc::channel();
	let cold_root = root.path().to_owned();
	let cold_cache = cache.clone();
	let cold = std::thread::spawn(move || {
		let _hooks = Hooks::new();
		AFTER_REGISTRATION
			.with(|slot| *slot.borrow_mut() = Some(Box::new(move || registered.send(()).unwrap())));
		find_idempotent_in(&cold_root, "main", "cold", &cold_cache)
			.unwrap()
			.unwrap()
			.id
	});
	ready.recv_timeout(Duration::from_secs(5)).unwrap();
	let warm_root = root.path().to_owned();
	let warm_cache = cache.clone();
	let (completed, result) = std::sync::mpsc::channel();
	let warm = std::thread::spawn(move || {
		completed
			.send(
				find_idempotent_in(&warm_root, "main", "warm", &warm_cache)
					.map(|record| record.unwrap().id),
			)
			.unwrap();
	});
	let observed = result.recv_timeout(Duration::from_secs(5));
	drop(held);
	assert_eq!(observed.unwrap().unwrap(), "original-warm");
	warm.join().unwrap();
	assert_eq!(cold.join().unwrap(), "original-cold");
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "current_thread")]
async fn cancelled_cold_leader_and_waiter_retain_real_worker_capacity_and_cleanup() {
	let root = tempfile::tempdir().unwrap();
	let cache = Arc::new(Mutex::new(ReuseHitCache::default()));
	for key in ["leader", "waiter"] {
		write(
			root.path(),
			&record(&format!("original-{key}"), "main", key, "launched"),
		);
	}
	for key in ["leader", "waiter"] {
		find_idempotent_in(root.path(), "main", key, &cache).unwrap();
	}
	assert!(cache
		.lock()
		.unwrap()
		.known
		.values()
		.all(|binding| binding.strict));
	std::fs::write(root.path().join("invalidate.marker"), b"changed").unwrap();
	let slots = Arc::new(Semaphore::new(2));
	let release = Arc::new((Mutex::new(false), Condvar::new()));
	let waiter_release = Arc::new((Mutex::new(false), Condvar::new()));
	let (entered, running) = tokio::sync::oneshot::channel();
	let (finished, mut completions) = tokio::sync::mpsc::unbounded_channel();
	let (registered, ready) = tokio::sync::oneshot::channel();
	let (waiting, wait_started) = tokio::sync::oneshot::channel();
	let waiter_root = root.path().to_owned();
	let waiter_cache = cache.clone();
	let waiter_resume = waiter_release.clone();
	let waiter_finished = finished.clone();
	let waiter = tokio::spawn(run_registry_lookup(slots.clone(), move || {
		let _hooks = Hooks::new();
		AFTER_REGISTRATION.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || {
				let _ = registered.send(());
				let (lock, changed) = &*waiter_resume;
				let (_released, timeout) = changed
					.wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(10), |released| {
						!*released
					})
					.unwrap();
				assert!(!timeout.timed_out());
			}))
		});
		ON_COHORT_WAIT.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || {
				let _ = waiting.send(());
			}))
		});
		let result = find_idempotent_in(&waiter_root, "main", "waiter", &waiter_cache);
		waiter_finished
			.send(
				result
					.as_ref()
					.map(|found| found.as_ref().unwrap().id.clone())
					.map_err(ToString::to_string),
			)
			.unwrap();
		result
	}));
	tokio::time::timeout(Duration::from_secs(5), ready)
		.await
		.unwrap()
		.unwrap();
	let leader_root = root.path().to_owned();
	let leader_cache = cache.clone();
	let leader_release = release.clone();
	let leader_finished = finished.clone();
	let leader = tokio::spawn(run_registry_lookup(slots.clone(), move || {
		let _hooks = Hooks::new();
		ON_SCAN.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || {
				let _ = entered.send(());
				let (lock, changed) = &*leader_release;
				let (_released, timeout) = changed
					.wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(10), |released| {
						!*released
					})
					.unwrap();
				assert!(!timeout.timed_out());
			}))
		});
		let result = find_idempotent_in(&leader_root, "main", "leader", &leader_cache);
		leader_finished
			.send(
				result
					.as_ref()
					.map(|found| found.as_ref().unwrap().id.clone())
					.map_err(ToString::to_string),
			)
			.unwrap();
		result
	}));
	tokio::time::timeout(Duration::from_secs(5), running)
		.await
		.unwrap()
		.unwrap();
	let scans = cache.lock().unwrap().cold.clone();
	assert_eq!(
		scans.state.lock().unwrap().active.as_deref(),
		Some([("main".to_owned(), "waiter".to_owned())].as_slice())
	);
	*waiter_release.0.lock().unwrap() = true;
	waiter_release.1.notify_all();
	tokio::time::timeout(Duration::from_secs(5), wait_started)
		.await
		.unwrap()
		.unwrap();
	leader.abort();
	waiter.abort();
	assert!(leader.await.unwrap_err().is_cancelled());
	assert!(waiter.await.unwrap_err().is_cancelled());
	assert_eq!(slots.available_permits(), 0);
	assert_eq!(scans.state.lock().unwrap().demands.len(), 2);
	*release.0.lock().unwrap() = true;
	release.1.notify_all();
	let mut identities = Vec::new();
	for _ in 0..2 {
		identities.push(
			tokio::time::timeout(Duration::from_secs(5), completions.recv())
				.await
				.unwrap()
				.unwrap()
				.unwrap(),
		);
	}
	identities.sort();
	assert_eq!(identities, ["original-leader", "original-waiter"]);
	tokio::time::timeout(Duration::from_secs(5), async {
		while slots.available_permits() != 2 {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	let state = scans.state.lock().unwrap();
	assert!(state.demands.is_empty());
	assert!(state.hints.is_empty());
	assert!(state.active.is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn fresh_absent_and_unfrozen_known_lookups_do_not_wait_for_gate() {
	let root = tempfile::tempdir().unwrap();
	let cache = Arc::new(Mutex::new(ReuseHitCache::default()));
	write(
		root.path(),
		&record("original-fresh", "main", "fresh", "launched"),
	);
	write(
		root.path(),
		&record("original-known", "main", "known", "launched"),
	);
	find_idempotent_in(root.path(), "main", "known", &cache).unwrap();
	assert!(cache.lock().unwrap().known[&("main".into(), "known".into())].strict);
	std::fs::write(root.path().join("invalidate.marker"), b"changed").unwrap();
	let scans = cache.lock().unwrap().cold.clone();
	let held = scans.gate.lock().unwrap();
	assert!(scans.state.lock().unwrap().active.is_none());
	let (completed, received) = std::sync::mpsc::channel();
	let workers: Vec<_> = ["fresh", "absent", "known"]
		.into_iter()
		.map(|key| {
			let path = root.path().to_owned();
			let cache = cache.clone();
			let completed = completed.clone();
			std::thread::spawn(move || {
				let result = find_idempotent_in(&path, "main", key, &cache)
					.map(|found| found.map(|record| record.id))
					.map_err(|error| error.to_string());
				completed.send((key, result)).unwrap();
			})
		})
		.collect();
	let first = received.recv_timeout(Duration::from_secs(5));
	let second = received.recv_timeout(Duration::from_secs(5));
	let third = received.recv_timeout(Duration::from_secs(5));
	// Release before asserting so a deliberately broken gate policy remains
	// a bounded test failure rather than leaving blocked worker threads behind.
	drop(held);
	for worker in workers {
		worker.join().unwrap();
	}
	let mut results = [first.unwrap(), second.unwrap(), third.unwrap()];
	results.sort_by_key(|(key, _)| *key);
	assert!(results[0].1.as_ref().unwrap().is_none());
	assert_eq!(
		results[1].1.as_ref().unwrap().as_deref(),
		Some("original-fresh")
	);
	assert_eq!(
		results[2].1.as_ref().unwrap().as_deref(),
		Some("original-known")
	);
	let state = scans.state.lock().unwrap();
	assert!(state.demands.is_empty());
	assert!(state.hints.is_empty());
	assert!(state.active.is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn late_known_refresh_bypasses_an_active_frozen_cohort() {
	let root = tempfile::tempdir().unwrap();
	let cache = Arc::new(Mutex::new(ReuseHitCache::default()));
	for key in ["leader", "late"] {
		write(
			root.path(),
			&record(&format!("original-{key}"), "main", key, "launched"),
		);
	}
	for key in ["leader", "late"] {
		find_idempotent_in(root.path(), "main", key, &cache).unwrap();
	}
	assert!(cache
		.lock()
		.unwrap()
		.known
		.values()
		.all(|binding| binding.strict));
	// Keep original ownership but model an identity outside the bounded recent
	// prediction window. Covered late arrivals are tested separately below.
	cache.lock().unwrap().recent_cold.clear();
	std::fs::write(root.path().join("invalidate.marker"), b"changed").unwrap();
	let scans = cache.lock().unwrap().cold.clone();
	let (entered, frozen) = std::sync::mpsc::channel();
	let (release, released) = std::sync::mpsc::channel();
	let leader_root = root.path().to_owned();
	let leader_cache = cache.clone();
	let leader = std::thread::spawn(move || {
		let _hooks = Hooks::new();
		ON_SCAN.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || {
				entered.send(()).unwrap();
				released.recv_timeout(Duration::from_secs(20)).unwrap();
			}))
		});
		let result = find_idempotent_in(&leader_root, "main", "leader", &leader_cache)
			.map(|found| found.unwrap().id)
			.map_err(|error| error.to_string());
		(result, SCANS.with(Cell::get))
	});
	frozen.recv_timeout(Duration::from_secs(5)).unwrap();
	assert_eq!(
		scans.state.lock().unwrap().active.as_deref(),
		Some([].as_slice())
	);
	let (completed, completion) = std::sync::mpsc::channel();
	let late_root = root.path().to_owned();
	let late_cache = cache.clone();
	let late = std::thread::spawn(move || {
		let _hooks = Hooks::new();
		let result = find_idempotent_in(&late_root, "main", "late", &late_cache)
			.map(|found| found.unwrap().id)
			.map_err(|error| error.to_string());
		completed.send((result, SCANS.with(Cell::get))).unwrap();
	});
	let observed = completion.recv_timeout(Duration::from_secs(5));
	// Always release and join the original workers before reporting a routing
	// failure; a regression that waits for the gate remains a bounded failure.
	let released = release.send(());
	late.join().unwrap();
	let leader_result = leader.join().unwrap();
	released.unwrap();
	let (late_result, late_scans) = observed.unwrap();
	assert_eq!(late_result.unwrap(), "original-late");
	assert_eq!(late_scans, 1);
	assert_eq!(leader_result.0.unwrap(), "original-leader");
	assert_eq!(leader_result.1, 1);
	let state = scans.state.lock().unwrap();
	assert!(state.demands.is_empty());
	assert!(state.hints.is_empty());
	assert!(state.active.is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn cohort_member_without_a_hint_releases_gate_before_full_scan() {
	let root = tempfile::tempdir().unwrap();
	let cache = Arc::new(Mutex::new(ReuseHitCache::default()));
	write(
		root.path(),
		&record("original-waiter", "main", "waiter", "launched"),
	);
	find_idempotent_in(root.path(), "main", "waiter", &cache).unwrap();
	assert!(cache.lock().unwrap().known[&("main".into(), "waiter".into())].strict);
	std::fs::write(root.path().join("invalidate.marker"), b"changed").unwrap();
	let scans = cache.lock().unwrap().cold.clone();
	let member = demand(&scans, "main", "waiter");
	let leader = demand(&scans, "main", "leader");
	let (active, targets) = leader
		.start_cohort(scans.gate.lock().unwrap(), Vec::new())
		.unwrap();
	assert_eq!(targets.len(), 1);
	let (waiting, observed_wait) = std::sync::mpsc::channel();
	let worker_root = root.path().to_owned();
	let worker_cache = cache.clone();
	let worker_scans = scans.clone();
	let worker = std::thread::spawn(move || {
		let _hooks = Hooks::new();
		ON_COHORT_WAIT
			.with(|slot| *slot.borrow_mut() = Some(Box::new(move || waiting.send(()).unwrap())));
		ON_SCAN.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || {
				assert!(
					worker_scans.gate.try_lock().is_ok(),
					"fallback scan still holds the gate"
				);
			}))
		});
		let found = find_idempotent_in(&worker_root, "main", "waiter", &worker_cache)
			.unwrap()
			.unwrap();
		(found.id, SCANS.with(Cell::get))
	});
	let waited = observed_wait.recv_timeout(Duration::from_secs(5));
	// Simulate a finished leader with no shareable positive result. The member
	// must retain its original complete scan without extending this gate.
	drop(active);
	let (id, count) = worker.join().unwrap();
	waited.unwrap();
	assert_eq!(id, "original-waiter");
	assert_eq!(count, 1);
	drop(member);
	drop(leader);
	let state = scans.state.lock().unwrap();
	assert!(state.demands.is_empty());
	assert!(state.hints.is_empty());
	assert!(state.active.is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn poisoned_leader_clears_active_and_refuses_an_existing_valid_hint() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	for key in ["leader", "waiter"] {
		write(
			root.path(),
			&record(&format!("original-{key}"), "main", key, "launched"),
		);
	}
	find_idempotent_in(root.path(), "main", "waiter", &cache).unwrap();
	assert!(cache.lock().unwrap().known[&("main".into(), "waiter".into())].strict);
	std::fs::write(root.path().join("invalidate.marker"), b"changed").unwrap();
	let scans = cache.lock().unwrap().cold.clone();
	let leader = demand(&scans, "main", "leader");
	let waiter = demand(&scans, "main", "waiter");
	share_from(root.path(), &leader, registry_epoch);
	assert!(waiter
		.read_hint(root.path(), &registry_epoch)
		.unwrap()
		.is_some());
	let poison_scans = scans.clone();
	let panicked = std::thread::spawn(move || {
		let worker = demand(&poison_scans, "main", "poison");
		let (_active, _) = worker
			.start_cohort(poison_scans.gate.lock().unwrap(), Vec::new())
			.unwrap();
		assert!(poison_scans
			.state
			.lock()
			.unwrap()
			.active
			.as_ref()
			.is_some_and(|targets| targets.contains(&("main".into(), "waiter".into()))));
		panic!("simulate original scan worker panic");
	})
	.join();
	assert!(panicked.is_err());
	assert!(scans.gate.is_poisoned());
	assert!(scans.state.lock().unwrap().active.is_none());
	let _hooks = Hooks::new();
	let error = find_idempotent_in(root.path(), "main", "waiter", &cache).unwrap_err();
	assert!(error
		.to_string()
		.contains("job registry cold scan unavailable"));
	assert_eq!(SCANS.with(Cell::get), 0);
	drop(waiter);
	drop(leader);
	let state = scans.state.lock().unwrap();
	assert!(state.demands.is_empty());
	assert!(state.hints.is_empty());
	assert!(state.active.is_none());
}

#[cfg(target_os = "linux")]
fn prime_strict_keys(root: &Path, cache: &Mutex<ReuseHitCache>, keys: &[&str]) {
	for key in keys {
		write(
			root,
			&record(&format!("original-{key}"), "main", key, "launched"),
		);
	}
	for key in keys {
		find_idempotent_in(root, "main", key, cache).unwrap();
		assert!(cache.lock().unwrap().known[&("main".into(), (*key).into())].strict);
	}
}

#[cfg(target_os = "linux")]
#[test]
fn predicted_late_identity_joins_after_its_complete_scan() {
	let root = tempfile::tempdir().unwrap();
	let cache = Arc::new(Mutex::new(ReuseHitCache::default()));
	prime_strict_keys(root.path(), &cache, &["leader", "late"]);
	std::fs::write(root.path().join("invalidate.marker"), b"changed").unwrap();
	let scans = cache.lock().unwrap().cold.clone();
	let (scanned, scan_complete) = std::sync::mpsc::channel();
	let (release, released) = std::sync::mpsc::channel();
	let leader_root = root.path().to_owned();
	let leader_cache = cache.clone();
	let leader = std::thread::spawn(move || {
		let _hooks = Hooks::new();
		AFTER_SCAN.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || {
				scanned.send(()).unwrap();
				released.recv_timeout(Duration::from_secs(20)).unwrap();
			}))
		});
		let result = find_idempotent_in(&leader_root, "main", "leader", &leader_cache)
			.map(|found| found.unwrap().id)
			.map_err(|error| error.to_string());
		(result, SCANS.with(Cell::get))
	});
	scan_complete.recv_timeout(Duration::from_secs(5)).unwrap();
	{
		let state = scans.state.lock().unwrap();
		assert!(state
			.active
			.as_ref()
			.unwrap()
			.contains(&("main".into(), "late".into())));
		assert!(!state.demands.contains_key(&("main".into(), "late".into())));
		assert!(state.hints.is_empty());
	}
	let (waiting, wait_started) = std::sync::mpsc::channel();
	let late_root = root.path().to_owned();
	let late_cache = cache.clone();
	let late = std::thread::spawn(move || {
		let _hooks = Hooks::new();
		ON_COHORT_WAIT
			.with(|slot| *slot.borrow_mut() = Some(Box::new(move || waiting.send(()).unwrap())));
		let result = find_idempotent_in(&late_root, "main", "late", &late_cache)
			.map(|found| found.unwrap().id)
			.map_err(|error| error.to_string());
		(result, SCANS.with(Cell::get))
	});
	let waited = wait_started.recv_timeout(Duration::from_secs(5));
	let released = release.send(());
	let late_result = late.join().unwrap();
	let leader_result = leader.join().unwrap();
	released.unwrap();
	waited.unwrap();
	assert_eq!(leader_result.0.unwrap(), "original-leader");
	assert_eq!(leader_result.1, 1);
	assert_eq!(late_result.0.unwrap(), "original-late");
	assert_eq!(late_result.1, 0);
	let cache = cache.lock().unwrap();
	assert!(cache.recent_cold.contains(&("main".into(), "late".into())));
	let state = scans.state.lock().unwrap();
	assert!(state.demands.is_empty());
	assert!(state.hints.is_empty());
	assert!(state.active.is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn recent_predictions_follow_strict_cold_commits_not_warm_or_legacy_reads() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	prime_strict_keys(root.path(), &cache, &["first", "second"]);
	let before = cache.lock().unwrap().recent_cold.clone();
	assert_eq!(before.back().unwrap().1, "second");
	let _hooks = Hooks::new();
	find_idempotent_in(root.path(), "main", "first", &cache).unwrap();
	assert_eq!(SCANS.with(Cell::get), 0);
	assert_eq!(cache.lock().unwrap().recent_cold, before);
	std::fs::write(root.path().join("invalidate.marker"), b"changed").unwrap();
	find_idempotent_in(root.path(), "main", "first", &cache).unwrap();
	let refreshed = cache.lock().unwrap().recent_cold.clone();
	assert_eq!(refreshed.len(), 2);
	assert_eq!(refreshed.back().unwrap().1, "first");
	write(
		root.path(),
		&record("legacy-original", "main", "legacy", "launched"),
	);
	std::fs::set_permissions(
		root.path().join("legacy-original.json"),
		std::fs::Permissions::from_mode(0o644),
	)
	.unwrap();
	find_idempotent_in(root.path(), "main", "legacy", &cache).unwrap();
	assert!(!cache.lock().unwrap().known[&("main".into(), "legacy".into())].strict);
	write(
		root.path(),
		&record("pending-original", "main", "pending", "pending"),
	);
	find_idempotent_in(root.path(), "main", "pending", &cache).unwrap();
	assert!(find_idempotent_in(root.path(), "main", "absent", &cache)
		.unwrap()
		.is_none());
	assert_eq!(cache.lock().unwrap().recent_cold, refreshed);
}

#[cfg(target_os = "linux")]
#[test]
fn recent_prediction_budget_and_full_ownership_map_do_not_evict_known() {
	let root = tempfile::tempdir().unwrap();
	let mut cache = ReuseHitCache {
		root: Some(root.path().to_owned()),
		..ReuseHitCache::default()
	};
	let long = |index| {
		(
			"main".to_owned(),
			format!("{index}{}", "x".repeat(MAX_COLD_DEMAND_BYTES - 5)),
		)
	};
	for index in 0..MAX_REUSE_HITS {
		let identity = if index < 3 {
			long(index)
		} else {
			("main".into(), format!("retained-{index}"))
		};
		cache.known.insert(
			identity,
			KnownReuseBinding {
				id: format!("original-{index}"),
				strict: true,
			},
		);
	}
	let known_before: HashMap<_, _> = cache
		.known
		.iter()
		.map(|(identity, binding)| (identity.clone(), (binding.id.clone(), binding.strict)))
		.collect();
	for index in 3..13 {
		cache.remember_cold_identity(&("main".into(), format!("retained-{index}")));
	}
	assert_eq!(cache.recent_cold.len(), MAX_COLD_COHORT_IDENTITIES);
	assert_eq!(cache.recent_cold.front().unwrap().1, "retained-5");
	cache.remember_cold_identity(&("main".into(), "retained-6".into()));
	assert_eq!(cache.recent_cold.len(), MAX_COLD_COHORT_IDENTITIES);
	assert_eq!(cache.recent_cold.back().unwrap().1, "retained-6");
	assert_eq!(
		cache.recent_strict_candidates(root.path())[0].1,
		"retained-6"
	);
	assert!(cache
		.recent_strict_candidates(&root.path().join("other"))
		.is_empty());
	for index in 0..3 {
		cache.remember_cold_identity(&long(index));
		assert!(
			cache
				.recent_cold
				.iter()
				.map(|(host, key)| host.len() + key.len())
				.sum::<usize>()
				<= MAX_RECENT_COLD_KEY_BYTES
		);
	}
	assert_eq!(cache.recent_cold.len(), 2);
	assert_eq!(cache.recent_cold.front(), Some(&long(1)));
	let recent_before = cache.recent_cold.clone();
	cache.remember_cold_identity(&("main".into(), "x".repeat(MAX_COLD_DEMAND_BYTES)));
	assert_eq!(cache.recent_cold, recent_before);
	// A fully strict read cannot enter predictions if the original ownership
	// map is full and therefore cannot retain this new identity's refusal data.
	write(
		root.path(),
		&record("unretained-original", "main", "unretained", "launched"),
	);
	let cache = Mutex::new(cache);
	assert!(
		find_idempotent_in(root.path(), "main", "unretained", &cache)
			.unwrap()
			.is_some()
	);
	let cache = cache.lock().unwrap();
	assert_eq!(cache.recent_cold, recent_before);
	assert!(cache.hits.is_empty());
	let known_after: HashMap<_, _> = cache
		.known
		.iter()
		.map(|(identity, binding)| (identity.clone(), (binding.id.clone(), binding.strict)))
		.collect();
	assert_eq!(known_after, known_before);
}

#[cfg(target_os = "linux")]
#[test]
fn frozen_prediction_budget_prioritizes_distinct_live_demands() {
	let scans = Arc::new(RegistryColdScans::default());
	let leader = demand(&scans, "main", "leader");
	let actual: Vec<_> = (0..3)
		.map(|i| demand(&scans, "main", &format!("actual-{i}")))
		.collect();
	let mut recent = vec![
		("main".into(), "leader".into()),
		("main".into(), "actual-0".into()),
	];
	recent.extend((0..6).map(|i| ("main".into(), format!("predicted-{i}"))));
	let (active, targets) = leader
		.start_cohort(scans.gate.lock().unwrap(), recent)
		.unwrap();
	assert_eq!(targets.len(), MAX_COLD_COHORT_IDENTITIES - 1);
	for worker in &actual {
		assert_eq!(
			targets
				.iter()
				.filter(|target| target.identity == worker.identity)
				.count(),
			1
		);
		assert!(targets[..3]
			.iter()
			.any(|target| target.identity == worker.identity));
	}
	assert!(targets
		.iter()
		.all(|target| target.identity != leader.identity));
	assert_eq!(
		scans.state.lock().unwrap().active.as_ref().unwrap(),
		&targets
			.iter()
			.map(|target| target.identity.clone())
			.collect::<Vec<_>>()
	);
	drop(active);
	drop(actual);
	let large: Vec<_> = (0..3)
		.map(|i| {
			demand(
				&scans,
				"main",
				&format!("{i}{}", "x".repeat(MAX_COLD_DEMAND_BYTES - 5)),
			)
		})
		.collect();
	let recent = (0..8)
		.map(|i| ("main".into(), format!("predicted-{i}")))
		.collect();
	let (active, targets) = leader
		.start_cohort(scans.gate.lock().unwrap(), recent)
		.unwrap();
	assert_eq!(targets.len(), 3);
	assert_eq!(
		targets
			.iter()
			.map(|target| target.identity.0.len() + target.identity.1.len())
			.sum::<usize>(),
		MAX_COLD_TARGET_KEY_BYTES
	);
	drop(active);
	drop(large);
	let one = demand(&scans, "main", "same");
	let two = demand(&scans, "main", "same");
	let (active, targets) = leader
		.start_cohort(
			scans.gate.lock().unwrap(),
			vec![("main".into(), "same".into())],
		)
		.unwrap();
	assert_eq!(targets.len(), 1);
	let mut target = targets.into_iter().next().unwrap();
	target
		.observe(&record(&"x".repeat(129), "main", "same", "launched"))
		.unwrap();
	assert!(target.seen && target.candidate.is_none());
	target
		.observe(&record("valid-second-owner", "main", "same", "launched"))
		.unwrap();
	assert!(
		target.candidate.is_none(),
		"invalid unhintable first owner still counts as a duplicate"
	);
	drop(active);
	drop(one);
	drop(two);
	drop(leader);
	assert!(scans.state.lock().unwrap().demands.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn predicted_key_without_live_demand_is_not_published_and_closes_membership() {
	let root = tempfile::tempdir().unwrap();
	let cache = Mutex::new(ReuseHitCache::default());
	prime_strict_keys(root.path(), &cache, &["leader", "predicted"]);
	let scans = cache.lock().unwrap().cold.clone();
	let leader = demand(&scans, "main", "leader");
	let recent = cache.lock().unwrap().recent_strict_candidates(root.path());
	let (active, mut targets) = leader
		.start_cohort(scans.gate.lock().unwrap(), recent)
		.unwrap();
	assert_eq!(targets.len(), 1);
	assert!(scans.state.lock().unwrap().active.is_some());
	let (_, epoch) = scan_idempotent_binding_cohort(
		root.path(),
		"main",
		"leader",
		None,
		&registry_epoch,
		RegistryScanObserver {
			cohort: &mut targets,
			after_scan: |_| {},
		},
	)
	.unwrap();
	assert!(targets[0].candidate.is_some());
	leader.publish(targets, epoch).unwrap();
	{
		let state = scans.state.lock().unwrap();
		assert!(state.active.is_none());
		assert!(state.hints.is_empty());
	}
	let late = demand(&scans, "main", "predicted");
	assert!(late
		.read_hint(root.path(), &registry_epoch)
		.unwrap()
		.is_none());
	drop(active);
	drop(late);
	drop(leader);
	assert!(scans.state.lock().unwrap().demands.is_empty());
	assert!(cache
		.lock()
		.unwrap()
		.recent_cold
		.contains(&("main".into(), "predicted".into())));
}

#[cfg(target_os = "linux")]
#[test]
fn predicted_duplicates_and_corruption_retain_original_refusals() {
	for corrupt in [false, true] {
		let root = tempfile::tempdir().unwrap();
		let cache = Mutex::new(ReuseHitCache::default());
		prime_strict_keys(root.path(), &cache, &["leader", "predicted"]);
		let scans = cache.lock().unwrap().cold.clone();
		if corrupt {
			std::fs::write(root.path().join("original-predicted.json"), b"broken-json").unwrap();
		} else {
			for index in 0..2 {
				write(
					root.path(),
					&record(
						&format!("duplicate-{index}"),
						"main",
						"predicted",
						"launched",
					),
				);
			}
		}
		let _hooks = Hooks::new();
		let leader = find_idempotent_in(root.path(), "main", "leader", &cache);
		if corrupt {
			assert!(leader
				.unwrap_err()
				.to_string()
				.contains("corrupt job record"));
		} else {
			assert_eq!(leader.unwrap().unwrap().id, "original-leader");
		}
		assert_eq!(SCANS.with(Cell::get), 1);
		assert!(scans.state.lock().unwrap().hints.is_empty());
		let original = find_idempotent_in(root.path(), "main", "predicted", &cache).unwrap_err();
		if corrupt {
			assert!(original
				.to_string()
				.contains("previous idempotency binding could not be verified"));
		} else {
			assert!(original
				.to_string()
				.contains("duplicate original idempotency binding"));
		}
		let state = scans.state.lock().unwrap();
		assert!(state.demands.is_empty());
		assert!(state.hints.is_empty());
		assert!(state.active.is_none());
	}
}
