// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Slow registry reads leave the executor live and retain original cancellation ownership.
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
	let gate: Gate = Arc::new((Mutex::new(false), Condvar::new()));
	let release = ReleaseGate(gate.clone());
	let (entered, started) = tokio::sync::oneshot::channel();
	let lookup = tokio::spawn(run_registry_lookup(move || {
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

	drop(release);
	assert!(lookup.await.unwrap().unwrap().is_none());
}

struct ActiveWorker(Arc<AtomicUsize>);
impl Drop for ActiveWorker {
	fn drop(&mut self) {
		self.0.fetch_sub(1, Ordering::SeqCst);
	}
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_lookup_waiters_do_not_limit_independent_registry_reads() {
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
		tokio::spawn(run_registry_lookup(move || {
			let now = active.fetch_add(1, Ordering::SeqCst) + 1;
			let _active = ActiveWorker(active);
			maximum.fetch_max(now, Ordering::SeqCst);
			let _ = entered.send(());
			wait_gate(&gate)?;
			Ok(None)
		}))
	};
	let owners: Vec<_> = (0..4).map(|_| launch()).collect();
	for _ in 0..4 {
		tokio::time::timeout(Duration::from_secs(5), started.recv())
			.await
			.unwrap()
			.unwrap();
	}
	for owner in owners {
		owner.abort();
		assert!(owner.await.unwrap_err().is_cancelled());
	}
	let independent: Vec<_> = (0..8).map(|_| launch()).collect();
	for _ in 0..8 {
		tokio::time::timeout(Duration::from_secs(5), started.recv())
			.await
			.unwrap()
			.unwrap();
	}
	assert_eq!(active.load(Ordering::SeqCst), 12);
	drop(release);
	for lookup in independent {
		assert!(lookup.await.unwrap().unwrap().is_none());
	}
	tokio::time::timeout(Duration::from_secs(5), async {
		while active.load(Ordering::SeqCst) != 0 {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert_eq!(maximum.load(Ordering::SeqCst), 12);
}

#[tokio::test(flavor = "current_thread")]
async fn unpolled_registry_lookup_never_submits_a_worker() {
	let calls = Arc::new(AtomicUsize::new(0));
	let observed = calls.clone();
	drop(run_registry_lookup(move || {
		observed.fetch_add(1, Ordering::SeqCst);
		Ok(None)
	}));
	tokio::task::yield_now().await;
	assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn registry_worker_failures_preserve_validation_errors() {
	let error = run_registry_lookup(|| Err(anyhow::anyhow!("original registry validation error")))
		.await
		.unwrap_err();
	assert_eq!(error.to_string(), "original registry validation error");

	let error =
		run_registry_lookup(|| panic!("fixture worker panic must not become a successful lookup"))
			.await
			.unwrap_err();
	assert_eq!(error.to_string(), "job registry lookup worker unavailable");
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

	let lookup = || {
		let root = root.path().to_owned();
		let cache = cache.clone();
		run_registry_lookup(move || find_idempotent_in(&root, "main", "original-key", &cache))
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
}
