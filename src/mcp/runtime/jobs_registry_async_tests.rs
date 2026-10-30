// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Slow registry reads leave the executor live and retain bounded cancellation ownership.
use super::*;
use std::sync::atomic::AtomicUsize;
use std::sync::Condvar;

type Gate = Arc<(Mutex<bool>, Condvar)>;

struct ReleaseGate(Gate);
impl Drop for ReleaseGate {
	fn drop(&mut self) {
		let (lock, changed) = &*self.0;
		*lock.lock().unwrap() = true;
		changed.notify_all();
	}
}

fn wait_gate(gate: &Gate) -> Result<()> {
	let locked = gate.0.lock().unwrap();
	let (_released, timeout) = gate
		.1
		.wait_timeout_while(locked, Duration::from_secs(10), |released| !*released)
		.unwrap();
	if timeout.timed_out() {
		bail!("test registry worker was not released");
	}
	Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_registry_lookup_keeps_current_thread_executor_responsive() {
	let slots = Arc::new(Semaphore::new(1));
	let gate: Gate = Arc::new((Mutex::new(false), Condvar::new()));
	let release = ReleaseGate(gate.clone());
	let (entered, started) = tokio::sync::oneshot::channel();
	let lookup = tokio::spawn(run_registry_lookup(slots.clone(), move || {
		let _ = entered.send(());
		wait_gate(&gate)?;
		Ok(None)
	}));
	tokio::time::timeout(Duration::from_secs(5), started)
		.await
		.unwrap()
		.unwrap();
	assert!(!lookup.is_finished());
	let heartbeat = tokio::spawn(async {
		tokio::task::yield_now().await;
		42
	});
	assert_eq!(
		tokio::time::timeout(Duration::from_secs(5), heartbeat)
			.await
			.unwrap()
			.unwrap(),
		42
	);
	assert!(!lookup.is_finished());
	assert_eq!(slots.available_permits(), 0);
	drop(release);
	assert!(lookup.await.unwrap().unwrap().is_none());
	assert_eq!(slots.available_permits(), 1);
}

struct ActiveWorker(Arc<AtomicUsize>);
impl Drop for ActiveWorker {
	fn drop(&mut self) {
		self.0.fetch_sub(1, Ordering::SeqCst);
	}
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_lookup_waiters_keep_the_actual_four_worker_bound() {
	let slots = Arc::new(Semaphore::new(MAX_REGISTRY_LOOKUPS));
	let gate: Gate = Arc::new((Mutex::new(false), Condvar::new()));
	let release = ReleaseGate(gate.clone());
	let active = Arc::new(AtomicUsize::new(0));
	let maximum = Arc::new(AtomicUsize::new(0));
	let (entered, mut started) = tokio::sync::mpsc::unbounded_channel();
	let launch = || {
		let gate = gate.clone();
		let active = active.clone();
		let maximum = maximum.clone();
		let entered = entered.clone();
		tokio::spawn(run_registry_lookup(slots.clone(), move || {
			let now = active.fetch_add(1, Ordering::SeqCst) + 1;
			let _active = ActiveWorker(active);
			maximum.fetch_max(now, Ordering::SeqCst);
			let _ = entered.send(());
			wait_gate(&gate)?;
			Ok(None)
		}))
	};
	let owners: Vec<_> = (0..MAX_REGISTRY_LOOKUPS).map(|_| launch()).collect();
	for _ in 0..MAX_REGISTRY_LOOKUPS {
		tokio::time::timeout(Duration::from_secs(5), started.recv())
			.await
			.unwrap()
			.unwrap();
	}
	assert_eq!(active.load(Ordering::SeqCst), MAX_REGISTRY_LOOKUPS);
	for owner in owners {
		owner.abort();
		assert!(owner.await.unwrap_err().is_cancelled());
	}
	assert_eq!(slots.available_permits(), 0);
	let queued: Vec<_> = (0..2).map(|_| launch()).collect();
	assert!(
		tokio::time::timeout(Duration::from_millis(50), started.recv())
			.await
			.is_err()
	);
	assert_eq!(active.load(Ordering::SeqCst), MAX_REGISTRY_LOOKUPS);
	drop(release);
	for waiter in queued {
		assert!(waiter.await.unwrap().unwrap().is_none());
	}
	tokio::time::timeout(Duration::from_secs(5), async {
		while active.load(Ordering::SeqCst) != 0
			|| slots.available_permits() != MAX_REGISTRY_LOOKUPS
		{
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert_eq!(maximum.load(Ordering::SeqCst), MAX_REGISTRY_LOOKUPS);
	assert_eq!(slots.available_permits(), MAX_REGISTRY_LOOKUPS);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_or_closed_admission_never_submits_a_registry_worker() {
	let slots = Arc::new(Semaphore::new(1));
	let held = slots.clone().acquire_owned().await.unwrap();
	let calls = Arc::new(AtomicUsize::new(0));
	let observed = calls.clone();
	let waiter = tokio::spawn(run_registry_lookup(slots.clone(), move || {
		observed.fetch_add(1, Ordering::SeqCst);
		Ok(None)
	}));
	tokio::task::yield_now().await;
	waiter.abort();
	assert!(waiter.await.unwrap_err().is_cancelled());
	drop(held);
	slots.close();
	let observed = calls.clone();
	let error = run_registry_lookup(slots, move || {
		observed.fetch_add(1, Ordering::SeqCst);
		Ok(None)
	})
	.await
	.unwrap_err();
	assert_eq!(
		error.to_string(),
		"job registry lookup capacity unavailable"
	);
	assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn registry_worker_failures_preserve_validation_errors_and_release_capacity() {
	let slots = Arc::new(Semaphore::new(1));
	let error = run_registry_lookup(slots.clone(), || {
		Err(anyhow::anyhow!("original registry validation error"))
	})
	.await
	.unwrap_err();
	assert_eq!(error.to_string(), "original registry validation error");
	assert_eq!(slots.available_permits(), 1);
	let error = run_registry_lookup(slots.clone(), || {
		panic!("fixture worker panic must not become a successful lookup")
	})
	.await
	.unwrap_err();
	assert_eq!(error.to_string(), "job registry lookup worker unavailable");
	assert_eq!(slots.available_permits(), 1);
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn offloaded_real_lookup_preserves_original_identity_and_duplicate_refusal() {
	let root = tempfile::tempdir().unwrap();
	let original: JobRecord = serde_json::from_value(json!({
		"id":"original-job", "host":"main", "ssh_target":"never-connect.invalid",
		"unit":"original-unit", "remote_job_dir":"/never-launch/jobs/original-job",
		"executable":"/usr/bin/true", "args":[], "cwd":null, "env_keys":[],
		"created_unix_ms":1, "idempotency_key":"original-key", "request_fingerprint":1,
		"request_digest":"a".repeat(64), "launch_state":"launched"
	}))
	.unwrap();
	save_record_at(&root.path().join("original-job.json"), &original).unwrap();
	let cache = Arc::new(Mutex::new(ReuseHitCache::default()));
	let slots = Arc::new(Semaphore::new(1));
	let lookup = || {
		let root = root.path().to_owned();
		let cache = cache.clone();
		run_registry_lookup(slots.clone(), move || {
			find_idempotent_in(&root, "main", "original-key", &cache)
		})
	};
	for _ in 0..2 {
		let found = lookup().await.unwrap().unwrap();
		assert_eq!(found.id, original.id);
		assert_eq!(found.request_digest, original.request_digest);
	}
	let mut duplicate = original.clone();
	duplicate.id = "duplicate-original".to_owned();
	save_record_at(&root.path().join("duplicate-original.json"), &duplicate).unwrap();
	let error = lookup().await.unwrap_err();
	assert!(error.to_string().contains("duplicate original"));
	assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);
	assert_eq!(slots.available_permits(), 1);
}
