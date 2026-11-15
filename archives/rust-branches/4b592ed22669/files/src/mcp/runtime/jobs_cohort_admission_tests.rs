// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Deterministic production lookup interleavings around cold cohort ownership.
use super::*;

#[derive(Clone, Copy)]
enum Window {
	Admission,
	Publication,
}

fn assert_single_scan_across_window(window: Window) {
	let root = tempfile::tempdir().unwrap();
	let cache = Arc::new(Mutex::new(ReuseHitCache::default()));
	prime_strict_keys(root.path(), &cache, &["leader", "waiter"]);
	std::fs::write(root.path().join("invalidate.marker"), b"changed").unwrap();
	let scans = cache.lock().unwrap().cold.clone();
	let (hint_read, observed_hint) = std::sync::mpsc::channel();
	let (resume_waiter, waiter_resumed) = std::sync::mpsc::channel();
	let (approaching, observed_admission) = std::sync::mpsc::channel();
	let (covered, observed_covered) = std::sync::mpsc::channel();
	let waiter_root = root.path().to_owned();
	let waiter_cache = cache.clone();
	let waiter = std::thread::spawn(move || {
		let _hooks = Hooks::new();
		AFTER_COHORT_HINT_READ.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || {
				hint_read.send(()).unwrap();
				waiter_resumed
					.recv_timeout(Duration::from_secs(10))
					.unwrap();
			}));
		});
		BEFORE_COHORT_ADMISSION.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || approaching.send(()).unwrap()));
		});
		ON_COHORT_WAIT.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || covered.send(()).unwrap()));
		});
		let found = find_idempotent_in(&waiter_root, "main", "waiter", &waiter_cache)
			.map(|value| value.map(|record| record.id))
			.map_err(|error| error.to_string());
		(found, SCANS.with(Cell::get))
	});
	observed_hint.recv_timeout(Duration::from_secs(5)).unwrap();
	let (in_window, observed_window) = std::sync::mpsc::channel();
	let (resume_leader, leader_resumed) = std::sync::mpsc::channel();
	let leader_root = root.path().to_owned();
	let leader_cache = cache.clone();
	let leader = std::thread::spawn(move || {
		let _hooks = Hooks::new();
		let pause: Box<dyn FnOnce()> = Box::new(move || {
			// This hook can run from Drop after an earlier failure. Never panic
			// before the owner releases its gate and notifies its original waiters.
			let _ = in_window.send(());
			let _ = leader_resumed.recv_timeout(Duration::from_secs(10));
		});
		match window {
			Window::Admission => {
				AFTER_COHORT_GATE_ACQUIRED.with(|slot| *slot.borrow_mut() = Some(pause));
				ON_SCAN.with(|slot| {
					*slot.borrow_mut() = Some(Box::new(move || {
						observed_covered
							.recv_timeout(Duration::from_secs(10))
							.unwrap();
					}));
				});
			}
			Window::Publication => {
				BEFORE_COHORT_GATE_RELEASE.with(|slot| *slot.borrow_mut() = Some(pause));
			}
		}
		let found = find_idempotent_in(&leader_root, "main", "leader", &leader_cache)
			.map(|value| value.map(|record| record.id))
			.map_err(|error| error.to_string());
		(found, SCANS.with(Cell::get))
	});
	let entered = observed_window.recv_timeout(Duration::from_secs(5));
	let waiter_released = resume_waiter.send(());
	let approached = observed_admission.recv_timeout(Duration::from_secs(5));
	// The real competing lookup already read no hint. It must not observe a
	// gate without the corresponding frozen membership at either boundary.
	let state_is_atomic = matches!(scans.state.try_lock(), Err(TryLockError::WouldBlock));
	let original_gate_is_held = matches!(scans.gate.try_lock(), Err(TryLockError::WouldBlock));
	let leader_released = resume_leader.send(());
	let leader_result = leader.join();
	let waiter_result = waiter.join();
	entered.unwrap();
	waiter_released.unwrap();
	approached.unwrap();
	leader_released.unwrap();
	assert!(state_is_atomic, "partial cohort ownership was observable");
	assert!(original_gate_is_held);
	let (leader_result, leader_scans) = leader_result.unwrap();
	let (waiter_result, waiter_scans) = waiter_result.unwrap();
	assert_eq!(leader_result.unwrap().as_deref(), Some("original-leader"));
	assert_eq!(waiter_result.unwrap().as_deref(), Some("original-waiter"));
	assert_eq!(leader_scans, 1);
	assert_eq!(
		waiter_scans, 0,
		"covered refresh performed another full scan"
	);
	assert!(scans.gate.try_lock().is_ok());
	let state = scans.state.lock().unwrap();
	assert!(state.active.is_none());
	assert!(state.active_epoch.is_none());
	assert!(state.active_completion.is_none());
	assert!(state.demands.is_empty());
	assert!(state.hints.is_empty());
}

#[test]
fn cold_admission_freezes_membership_before_a_competing_refresh_observes_gate() {
	assert_single_scan_across_window(Window::Admission);
}

#[test]
fn cold_publication_releases_original_gate_before_empty_membership_is_observable() {
	assert_single_scan_across_window(Window::Publication);
}

#[test]
fn covered_refresh_cannot_lose_completion_or_wait_for_a_later_cohort() {
	let root = tempfile::tempdir().unwrap();
	let epoch = registry_epoch(root.path()).unwrap();
	let scans = Arc::new(RegistryColdScans::default());
	let leader = demand(&scans, "main", "leader");
	let waiter = demand(&scans, "main", "waiter");
	let RegistryColdAdmission::Leader(first, _) = leader.admit_cohort(Vec::new(), epoch).unwrap()
	else {
		panic!("first cohort was not admitted");
	};
	let RegistryColdAdmission::Covered(original_completion) =
		waiter.admit_cohort(Vec::new(), epoch).unwrap()
	else {
		panic!("original member was not covered");
	};
	// Complete before the waiter enters Condvar::wait, then freeze another
	// cohort containing the same identity. The pinned old Arc prevents ABA.
	drop(first);
	let RegistryColdAdmission::Leader(next, _) = leader.admit_cohort(Vec::new(), epoch).unwrap()
	else {
		panic!("next cohort was not admitted");
	};
	assert!(!Arc::ptr_eq(
		&original_completion,
		scans
			.state
			.lock()
			.unwrap()
			.active_completion
			.as_ref()
			.unwrap()
	));
	let (completed, observed) = std::sync::mpsc::channel();
	let worker = std::thread::spawn(move || {
		let result = waiter
			.wait_for_cohort(&original_completion)
			.map_err(|error| error.to_string());
		completed.send(result).unwrap();
	});
	let returned_before_next_completed = observed.recv_timeout(Duration::from_secs(5));
	drop(next);
	worker.join().unwrap();
	returned_before_next_completed.unwrap().unwrap();
	drop(leader);
	let state = scans.state.lock().unwrap();
	assert!(state.active_completion.is_none());
	assert!(state.demands.is_empty());
}

#[test]
fn changed_epoch_refresh_bypasses_a_frozen_cohort_covering_its_key() {
	let root = tempfile::tempdir().unwrap();
	let cache = Arc::new(Mutex::new(ReuseHitCache::default()));
	prime_strict_keys(root.path(), &cache, &["leader", "waiter"]);
	std::fs::write(root.path().join("first.marker"), b"first").unwrap();
	let before = registry_epoch(root.path()).unwrap();
	let scans = cache.lock().unwrap().cold.clone();
	let leader = demand(&scans, "main", "leader");
	let recent = cache.lock().unwrap().recent_strict_candidates(root.path());
	let RegistryColdAdmission::Leader(active, _) = leader.admit_cohort(recent, before).unwrap()
	else {
		panic!("initial cohort was not admitted");
	};
	assert!(scans
		.state
		.lock()
		.unwrap()
		.active
		.as_ref()
		.unwrap()
		.contains(&("main".into(), "waiter".into())));
	std::fs::write(root.path().join("second.marker"), b"second").unwrap();
	assert_ne!(registry_epoch(root.path()).unwrap(), before);
	let (completed, observed) = std::sync::mpsc::channel();
	let worker_root = root.path().to_owned();
	let worker_cache = cache.clone();
	let worker = std::thread::spawn(move || {
		let _hooks = Hooks::new();
		ON_COHORT_WAIT.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(|| panic!("new epoch waited for old cohort")));
		});
		let result = find_idempotent_in(&worker_root, "main", "waiter", &worker_cache)
			.map(|value| value.map(|record| record.id))
			.map_err(|error| error.to_string());
		completed.send((result, SCANS.with(Cell::get))).unwrap();
	});
	let independent = observed.recv_timeout(Duration::from_secs(5));
	drop(active);
	worker.join().unwrap();
	let (result, count) = independent.unwrap();
	assert_eq!(result.unwrap().as_deref(), Some("original-waiter"));
	assert_eq!(count, 1);
	drop(leader);
	let state = scans.state.lock().unwrap();
	assert!(state.active_completion.is_none());
	assert!(state.demands.is_empty());
}

#[test]
fn panicking_cold_leader_wakes_covered_refresh_and_preserves_poison_refusal() {
	let root = tempfile::tempdir().unwrap();
	let cache = Arc::new(Mutex::new(ReuseHitCache::default()));
	prime_strict_keys(root.path(), &cache, &["leader", "waiter"]);
	std::fs::write(root.path().join("invalidate.marker"), b"changed").unwrap();
	let scans = cache.lock().unwrap().cold.clone();
	let (hint_read, observed_hint) = std::sync::mpsc::channel();
	let (resume_waiter, waiter_resumed) = std::sync::mpsc::channel();
	let (covered, observed_covered) = std::sync::mpsc::channel();
	let waiter_root = root.path().to_owned();
	let waiter_cache = cache.clone();
	let waiter = std::thread::spawn(move || {
		let _hooks = Hooks::new();
		AFTER_COHORT_HINT_READ.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || {
				hint_read.send(()).unwrap();
				waiter_resumed
					.recv_timeout(Duration::from_secs(10))
					.unwrap();
			}));
		});
		ON_COHORT_WAIT.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || covered.send(()).unwrap()));
		});
		let result = find_idempotent_in(&waiter_root, "main", "waiter", &waiter_cache)
			.map(|value| value.map(|record| record.id))
			.map_err(|error| error.to_string());
		(result, SCANS.with(Cell::get))
	});
	observed_hint.recv_timeout(Duration::from_secs(5)).unwrap();
	let (frozen, observed_frozen) = std::sync::mpsc::channel();
	let (unwind, unwind_requested) = std::sync::mpsc::channel();
	let leader_root = root.path().to_owned();
	let leader_cache = cache.clone();
	let leader = std::thread::spawn(move || {
		let _hooks = Hooks::new();
		ON_SCAN.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || {
				frozen.send(()).unwrap();
				unwind_requested
					.recv_timeout(Duration::from_secs(10))
					.unwrap();
				panic!("injected original cold leader unwind");
			}));
		});
		find_idempotent_in(&leader_root, "main", "leader", &leader_cache).unwrap();
	});
	let froze = observed_frozen.recv_timeout(Duration::from_secs(5));
	let resumed = resume_waiter.send(());
	let waiting = observed_covered.recv_timeout(Duration::from_secs(5));
	let released = unwind.send(());
	let leader_result = leader.join();
	let waiter_result = waiter.join();
	froze.unwrap();
	resumed.unwrap();
	waiting.unwrap();
	released.unwrap();
	assert!(leader_result.is_err());
	let (result, count) = waiter_result.unwrap();
	assert!(result
		.unwrap_err()
		.contains("job registry cold scan unavailable"));
	assert_eq!(count, 0);
	assert!(scans.gate.is_poisoned());
	let state = scans.state.lock().unwrap();
	assert!(state.active.is_none());
	assert!(state.active_epoch.is_none());
	assert!(state.active_completion.is_none());
	assert!(state.demands.is_empty());
	assert!(state.hints.is_empty());
}

#[test]
fn poisoned_cohort_state_is_refused_and_leader_drop_still_cleans_completion() {
	let root = tempfile::tempdir().unwrap();
	let epoch = registry_epoch(root.path()).unwrap();
	let scans = Arc::new(RegistryColdScans::default());
	let leader = demand(&scans, "main", "leader");
	let waiter = demand(&scans, "main", "waiter");
	let RegistryColdAdmission::Leader(active, _) = leader.admit_cohort(Vec::new(), epoch).unwrap()
	else {
		panic!("original cohort was not admitted");
	};
	let RegistryColdAdmission::Covered(completion) =
		waiter.admit_cohort(Vec::new(), epoch).unwrap()
	else {
		panic!("original member was not covered");
	};
	let worker = std::thread::spawn(move || {
		waiter
			.wait_for_cohort(&completion)
			.map_err(|error| error.to_string())
	});
	let poisoned_scans = scans.clone();
	assert!(std::thread::spawn(move || {
		let _state = poisoned_scans.state.lock().unwrap();
		panic!("injected cold state poison");
	})
	.join()
	.is_err());
	drop(active);
	let error = worker.join().unwrap().unwrap_err();
	assert!(error.contains("job registry cold demand unavailable"));
	assert!(scans.gate.try_lock().is_ok());
	drop(leader);
	assert!(scans.state.is_poisoned());
	let state = scans
		.state
		.lock()
		.unwrap_or_else(|error| error.into_inner());
	assert!(state.active.is_none());
	assert!(state.active_epoch.is_none());
	assert!(state.active_completion.is_none());
	assert!(state.demands.is_empty());
}

#[test]
fn shared_hint_validation_holds_no_gate_and_rechecks_a_later_leader_poison() {
	let root = tempfile::tempdir().unwrap();
	let cache = Arc::new(Mutex::new(ReuseHitCache::default()));
	prime_strict_keys(root.path(), &cache, &["leader", "waiter"]);
	std::fs::write(root.path().join("invalidate.marker"), b"changed").unwrap();
	let epoch = registry_epoch(root.path()).unwrap();
	let scans = cache.lock().unwrap().cold.clone();
	let (hint_read, observed_hint) = std::sync::mpsc::channel();
	let (resume_waiter, waiter_resumed) = std::sync::mpsc::channel();
	let (covered, observed_covered) = std::sync::mpsc::channel();
	let (verified, observed_verified) = std::sync::mpsc::channel();
	let (resume_verified, verified_resumed) = std::sync::mpsc::channel();
	let waiter_root = root.path().to_owned();
	let waiter_cache = cache.clone();
	let waiter = std::thread::spawn(move || {
		let _hooks = Hooks::new();
		AFTER_COHORT_HINT_READ.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || {
				hint_read.send(()).unwrap();
				waiter_resumed
					.recv_timeout(Duration::from_secs(10))
					.unwrap();
			}));
		});
		ON_COHORT_WAIT.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || covered.send(()).unwrap()));
		});
		AFTER_COHORT_HINT_VERIFIED.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || {
				verified.send(()).unwrap();
				verified_resumed
					.recv_timeout(Duration::from_secs(10))
					.unwrap();
			}));
		});
		let result = find_idempotent_in(&waiter_root, "main", "waiter", &waiter_cache)
			.map(|value| value.map(|record| record.id))
			.map_err(|error| error.to_string());
		(result, SCANS.with(Cell::get))
	});
	observed_hint.recv_timeout(Duration::from_secs(5)).unwrap();
	let (frozen, observed_frozen) = std::sync::mpsc::channel();
	let leader_root = root.path().to_owned();
	let leader_cache = cache.clone();
	let leader = std::thread::spawn(move || {
		let _hooks = Hooks::new();
		ON_SCAN.with(|slot| {
			*slot.borrow_mut() = Some(Box::new(move || {
				frozen.send(()).unwrap();
				observed_covered
					.recv_timeout(Duration::from_secs(10))
					.unwrap();
			}));
		});
		find_idempotent_in(&leader_root, "main", "leader", &leader_cache)
			.unwrap()
			.unwrap()
			.id
	});
	let froze = observed_frozen.recv_timeout(Duration::from_secs(5));
	let resumed = resume_waiter.send(());
	let hint_verified = observed_verified.recv_timeout(Duration::from_secs(5));
	let no_gate_during_validation = scans.gate.try_lock().is_ok();
	let no_state_during_validation = scans.state.try_lock().is_ok();
	let poisoned =
		if hint_verified.is_ok() && no_gate_during_validation && no_state_during_validation {
			let poison_scans = scans.clone();
			Some(
				std::thread::spawn(move || {
					let next = demand(&poison_scans, "main", "next");
					let RegistryColdAdmission::Leader(_active, _) =
						next.admit_cohort(Vec::new(), epoch).unwrap()
					else {
						panic!("completed follower retained the leader gate");
					};
					panic!("injected later cohort leader unwind");
				})
				.join(),
			)
		} else {
			// Release the original worker before reporting a held-lock regression.
			None
		};
	let released = resume_verified.send(());
	let leader_result = leader.join();
	let waiter_result = waiter.join();
	froze.unwrap();
	resumed.unwrap();
	hint_verified.unwrap();
	released.unwrap();
	assert!(no_gate_during_validation);
	assert!(no_state_during_validation);
	assert!(poisoned.is_some_and(|result| result.is_err()));
	assert_eq!(leader_result.unwrap(), "original-leader");
	let (result, count) = waiter_result.unwrap();
	assert!(result
		.unwrap_err()
		.contains("job registry cold scan unavailable"));
	assert_eq!(count, 0);
	assert!(scans.gate.is_poisoned());
	let state = scans.state.lock().unwrap();
	assert!(state.active_completion.is_none());
	assert!(state.demands.is_empty());
	assert!(state.hints.is_empty());
}
