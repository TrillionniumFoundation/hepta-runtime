// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Two physical preparations retain the original eight cancellation publication reservations.
use super::*;
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::Condvar;
use std::task::Poll;

type Gate = Arc<(Mutex<bool>, Condvar)>;

struct ReleaseGate(Gate);

impl Drop for ReleaseGate {
	fn drop(&mut self) {
		let (lock, changed) = &*self.0;
		*lock.lock().unwrap() = true;
		changed.notify_all();
	}
}

fn gate() -> (Gate, ReleaseGate) {
	let gate = Arc::new((Mutex::new(false), Condvar::new()));
	(gate.clone(), ReleaseGate(gate))
}

fn wait_gate(gate: &Gate) -> Result<()> {
	let guard = gate.0.lock().unwrap();
	let (_released, timeout) = gate
		.1
		.wait_timeout_while(guard, Duration::from_secs(10), |released| !*released)
		.unwrap();
	if timeout.timed_out() {
		bail!("cancel receipt fixture gate not released");
	}
	Ok(())
}

fn record() -> JobRecord {
	serde_json::from_value(json!({
		"id":"cancel-read", "host":"main", "ssh_target":"never-connect.invalid",
		"unit":"original-unit", "remote_job_dir":"/never-launch/cancel-read",
		"executable":"/usr/bin/true", "args":["retained\n中文".repeat(8192)],
		"cwd":null, "env_keys":[], "created_unix_ms":1,
		"idempotency_key":"original-key", "request_fingerprint":7,
		"request_digest":"a".repeat(64), "launch_state":"launched"
	}))
	.unwrap()
}

fn intent(root: &Path) -> PreparedAudit {
	prepare_audit_at(
		root.join("audit/events.jsonl"),
		"process_cancel_intent",
		"main",
		"cancel-read",
		&json!({"phase":"intent", "remote_operation_submitted":false}),
	)
	.unwrap()
}

async fn assert_pending<F: Future>(mut future: Pin<&mut F>) {
	poll_fn(|context| {
		assert!(future.as_mut().poll(context).is_pending());
		Poll::Ready(())
	})
	.await;
}

async fn drain(slots: Arc<Semaphore>, count: usize) {
	let all = tokio::time::timeout(
		Duration::from_secs(5),
		slots.acquire_many_owned(count as u32),
	)
	.await
	.unwrap()
	.unwrap();
	drop(all);
}

#[tokio::test(flavor = "current_thread")]
async fn slow_cancel_receipt_preparation_keeps_executor_live_and_original_bytes() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("cancel-read.json");
	let original = record();
	save_record_at(&path, &original).unwrap();
	let bytes = std::fs::read(&path).unwrap();
	let slots = Arc::new(Semaphore::new(MAX_CANCEL_PUBLICATIONS));
	let preparations = Arc::new(Semaphore::new(MAX_CANCEL_PREPARATIONS));
	let (gate, release) = gate();
	let (entered, started) = tokio::sync::oneshot::channel();
	let prepared = intent(root.path());
	let source = path.clone();
	let caller_thread = std::thread::current().id();
	let reader = tokio::spawn(run_cancel_intent(
		slots.clone(),
		preparations.clone(),
		move || {
			let _ = entered.send(std::thread::current().id());
			wait_gate(&gate)?;
			Ok((prepared, read_record_at(&source, "cancel-read")?))
		},
		append_audit,
	));
	let worker_thread = tokio::time::timeout(Duration::from_secs(5), started)
		.await
		.unwrap()
		.unwrap();
	assert_ne!(worker_thread, caller_thread);
	assert!(!reader.is_finished());
	assert_eq!(slots.available_permits(), MAX_CANCEL_PUBLICATIONS - 1);
	assert_eq!(
		preparations.available_permits(),
		MAX_CANCEL_PREPARATIONS - 1
	);
	let heartbeat = tokio::spawn(async {
		tokio::task::yield_now().await;
		37
	});
	assert_eq!(
		tokio::time::timeout(Duration::from_secs(5), heartbeat)
			.await
			.unwrap()
			.unwrap(),
		37
	);
	drop(release);
	let (permit, restored) = reader.await.unwrap().unwrap();
	assert_eq!(preparations.available_permits(), MAX_CANCEL_PREPARATIONS);
	assert_eq!(restored, original);
	assert_eq!(std::fs::read(path).unwrap(), bytes);
	let audit = std::fs::read_to_string(root.path().join("audit/events.jsonl")).unwrap();
	assert_eq!(audit.lines().count(), 1);
	assert_eq!(
		serde_json::from_str::<Value>(audit.trim()).unwrap()["action"],
		"process_cancel_intent"
	);
	// Preparation has returned, but remote continuation still owns this slot.
	assert_eq!(slots.available_permits(), MAX_CANCEL_PUBLICATIONS - 1);
	drop(permit);
	drain(slots, MAX_CANCEL_PUBLICATIONS).await;
	drain(preparations, MAX_CANCEL_PREPARATIONS).await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_receipt_preparations_keep_two_physical_slots_and_release_unsubmitted_waiters() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("cancel-read.json");
	save_record_at(&path, &record()).unwrap();
	let slots = Arc::new(Semaphore::new(MAX_CANCEL_PUBLICATIONS));
	let preparations = Arc::new(Semaphore::new(MAX_CANCEL_PREPARATIONS));
	let (gate, release) = gate();
	let calls = Arc::new(AtomicUsize::new(0));
	let appended = Arc::new(AtomicUsize::new(0));
	let remote = Arc::new(AtomicUsize::new(0));
	let (entered, mut started) = tokio::sync::mpsc::unbounded_channel();
	let mut readers = Vec::new();
	for _ in 0..MAX_CANCEL_PUBLICATIONS {
		let entered = entered.clone();
		let gate = gate.clone();
		let calls = calls.clone();
		let appended = appended.clone();
		let remote = remote.clone();
		let path = path.clone();
		let prepared = intent(root.path());
		let worker_slots = slots.clone();
		let worker_preparations = preparations.clone();
		readers.push(tokio::spawn(async move {
			let retained = run_cancel_intent(
				worker_slots,
				worker_preparations,
				move || {
					calls.fetch_add(1, Ordering::SeqCst);
					entered.send(()).unwrap();
					wait_gate(&gate)?;
					Ok((prepared, read_record_at(&path, "cancel-read")?))
				},
				move |_| {
					appended.fetch_add(1, Ordering::SeqCst);
					Ok(())
				},
			)
			.await?;
			remote.fetch_add(1, Ordering::SeqCst);
			Ok::<_, anyhow::Error>(retained)
		}));
	}
	for _ in 0..MAX_CANCEL_PREPARATIONS {
		tokio::time::timeout(Duration::from_secs(5), started.recv())
			.await
			.unwrap()
			.unwrap();
	}
	tokio::time::timeout(Duration::from_secs(5), async {
		while slots.available_permits() != 0 {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert_eq!(preparations.available_permits(), 0);
	for reader in readers {
		reader.abort();
		assert!(reader.await.unwrap_err().is_cancelled());
	}
	assert_eq!(
		slots.available_permits(),
		MAX_CANCEL_PUBLICATIONS - MAX_CANCEL_PREPARATIONS
	);
	assert_eq!(preparations.available_permits(), 0);
	let observed = calls.clone();
	let mut extra = Box::pin(run_cancel_intent::<()>(
		slots.clone(),
		preparations.clone(),
		move || {
			observed.fetch_add(100, Ordering::SeqCst);
			bail!("cancellation before preparation admission must not read a receipt")
		},
		|_| Ok::<(), anyhow::Error>(()),
	));
	assert_pending(extra.as_mut()).await;
	assert_eq!(
		slots.available_permits(),
		MAX_CANCEL_PUBLICATIONS - MAX_CANCEL_PREPARATIONS - 1
	);
	drop(extra);
	assert_eq!(
		slots.available_permits(),
		MAX_CANCEL_PUBLICATIONS - MAX_CANCEL_PREPARATIONS
	);
	assert_eq!(calls.load(Ordering::SeqCst), MAX_CANCEL_PREPARATIONS);
	assert_eq!(appended.load(Ordering::SeqCst), 0);
	assert_eq!(remote.load(Ordering::SeqCst), 0);
	drop(release);
	drain(slots, MAX_CANCEL_PUBLICATIONS).await;
	drain(preparations, MAX_CANCEL_PREPARATIONS).await;
	assert_eq!(calls.load(Ordering::SeqCst), MAX_CANCEL_PREPARATIONS);
	assert_eq!(appended.load(Ordering::SeqCst), MAX_CANCEL_PREPARATIONS);
	assert_eq!(remote.load(Ordering::SeqCst), 0);
}

#[test]
fn cancelled_receipt_preparations_queued_in_blocking_pool_keep_reservations() {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(1)
		.build()
		.unwrap();
	runtime.block_on(async {
		let (gate, release) = gate();
		let (entered, started) = tokio::sync::oneshot::channel();
		let blocker = tokio::task::spawn_blocking(move || {
			let _ = entered.send(());
			wait_gate(&gate)
		});
		tokio::time::timeout(Duration::from_secs(5), started)
			.await
			.unwrap()
			.unwrap();
		let slots = Arc::new(Semaphore::new(MAX_CANCEL_PUBLICATIONS));
		let preparations = Arc::new(Semaphore::new(MAX_CANCEL_PREPARATIONS));
		let calls = Arc::new(AtomicUsize::new(0));
		let mut queued = Vec::new();
		for _ in 0..MAX_CANCEL_PUBLICATIONS {
			let calls = calls.clone();
			let mut reader = Box::pin(run_cancel_intent::<()>(
				slots.clone(),
				preparations.clone(),
				move || {
					calls.fetch_add(1, Ordering::SeqCst);
					bail!("original receipt unavailable")
				},
				|_| panic!("failed preparation must not append an intent"),
			));
			assert_pending(reader.as_mut()).await;
			queued.push(reader);
		}
		drop(queued);
		assert_eq!(
			slots.available_permits(),
			MAX_CANCEL_PUBLICATIONS - MAX_CANCEL_PREPARATIONS
		);
		assert_eq!(preparations.available_permits(), 0);
		assert_eq!(calls.load(Ordering::SeqCst), 0);
		drop(release);
		blocker.await.unwrap().unwrap();
		drain(slots, MAX_CANCEL_PUBLICATIONS).await;
		drain(preparations, MAX_CANCEL_PREPARATIONS).await;
		assert_eq!(calls.load(Ordering::SeqCst), MAX_CANCEL_PREPARATIONS);
	});
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_cancel_receipts_keep_original_errors_before_intent_or_remote_effect() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("cancel-read.json");
	for failure in ["malformed", "identity", "missing"] {
		save_record_at(&path, &record()).unwrap();
		let expected_id = if failure == "identity" {
			"other-identity"
		} else {
			"cancel-read"
		};
		if failure == "malformed" {
			std::fs::write(&path, b"{truncated").unwrap();
		} else if failure == "missing" {
			std::fs::remove_file(&path).unwrap();
		}
		let expected = format!("{:#}", read_record_at(&path, expected_id).unwrap_err());
		let source = path.clone();
		let prepared = intent(root.path());
		let slots = Arc::new(Semaphore::new(MAX_CANCEL_PUBLICATIONS));
		let preparations = Arc::new(Semaphore::new(MAX_CANCEL_PREPARATIONS));
		let appended = Arc::new(AtomicUsize::new(0));
		let append_calls = appended.clone();
		let remote = Arc::new(AtomicUsize::new(0));
		let remote_calls = remote.clone();
		let worker_slots = slots.clone();
		let worker_preparations = preparations.clone();
		let result = async move {
			let retained = run_cancel_intent(
				worker_slots,
				worker_preparations,
				move || Ok((prepared, read_record_at(&source, expected_id)?)),
				move |prepared| {
					append_calls.fetch_add(1, Ordering::SeqCst);
					append_audit(prepared)
				},
			)
			.await?;
			remote_calls.fetch_add(1, Ordering::SeqCst);
			Ok::<_, anyhow::Error>(retained)
		}
		.await;
		assert_eq!(format!("{:#}", result.unwrap_err()), expected);
		assert_eq!(appended.load(Ordering::SeqCst), 0);
		assert_eq!(remote.load(Ordering::SeqCst), 0);
		assert!(!root.path().join("audit/events.jsonl").exists());
		drain(slots, MAX_CANCEL_PUBLICATIONS).await;
		drain(preparations, MAX_CANCEL_PREPARATIONS).await;
	}
}

#[tokio::test(flavor = "current_thread")]
async fn public_cancel_reserves_original_capacity_before_reading_a_receipt() {
	let slots = cancel_publication_slots();
	let preparations = cancel_preparation_slots();
	assert!(!Arc::ptr_eq(&slots, &observation_record_read_slots()));
	assert!(!Arc::ptr_eq(
		&preparations,
		&observation_record_read_slots()
	));
	assert!(!Arc::ptr_eq(&slots, &preparations));
	let held = slots
		.clone()
		.acquire_many_owned(MAX_CANCEL_PUBLICATIONS as u32)
		.await
		.unwrap();
	let reference = ProcessRefParams {
		host: "never-connect".into(),
		job_id: "../invalid-id".into(),
	};
	let expected = format!("{:#}", check_ref(&reference).unwrap_err());
	let cancellation = || {
		cancel_job(ProcessCancelParams {
			host: reference.host.clone(),
			job_id: reference.job_id.clone(),
			grace_seconds: None,
		})
	};
	let mut cancel = Box::pin(cancellation());
	assert_pending(cancel.as_mut()).await;
	assert_eq!(preparations.available_permits(), MAX_CANCEL_PREPARATIONS);
	drop(held);
	let error = tokio::time::timeout(Duration::from_secs(5), cancel)
		.await
		.unwrap()
		.unwrap_err();
	assert_eq!(format!("{error:#}"), expected);
	let held_preparations = preparations
		.clone()
		.acquire_many_owned(MAX_CANCEL_PREPARATIONS as u32)
		.await
		.unwrap();
	let mut waiting = Box::pin(cancellation());
	assert_pending(waiting.as_mut()).await;
	assert_eq!(slots.available_permits(), MAX_CANCEL_PUBLICATIONS - 1);
	assert_eq!(preparations.available_permits(), 0);
	drop(waiting);
	assert_eq!(slots.available_permits(), MAX_CANCEL_PUBLICATIONS);
	drop(held_preparations);
	let error = tokio::time::timeout(Duration::from_secs(5), cancellation())
		.await
		.unwrap()
		.unwrap_err();
	assert_eq!(format!("{error:#}"), expected);
	drain(slots, MAX_CANCEL_PUBLICATIONS).await;
	drain(preparations, MAX_CANCEL_PREPARATIONS).await;
}

#[tokio::test(flavor = "current_thread")]
async fn two_preparation_slots_preserve_eight_publication_continuations() {
	let root = tempfile::tempdir().unwrap();
	let slots = Arc::new(Semaphore::new(MAX_CANCEL_PUBLICATIONS));
	let preparations = Arc::new(Semaphore::new(MAX_CANCEL_PREPARATIONS));
	assert_eq!(MAX_CANCEL_PUBLICATIONS, 8);
	assert_eq!(MAX_CANCEL_PREPARATIONS, 2);
	let calls = Arc::new(AtomicUsize::new(0));
	let mut continuations = Vec::new();
	for _ in 0..8 {
		let prepared = intent(root.path());
		let entered = calls.clone();
		let continuation = tokio::time::timeout(
			Duration::from_secs(5),
			run_cancel_intent(
				slots.clone(),
				preparations.clone(),
				move || {
					entered.fetch_add(1, Ordering::SeqCst);
					Ok((prepared, ()))
				},
				append_audit,
			),
		)
		.await
		.unwrap()
		.unwrap();
		continuations.push(continuation);
	}
	assert_eq!(slots.available_permits(), 0);
	assert_eq!(preparations.available_permits(), 2);
	assert_eq!(calls.load(Ordering::SeqCst), 8);
	let prepared = intent(root.path());
	let entered = calls.clone();
	let mut ninth = Box::pin(run_cancel_intent(
		slots.clone(),
		preparations.clone(),
		move || {
			entered.fetch_add(1, Ordering::SeqCst);
			Ok((prepared, ()))
		},
		append_audit,
	));
	assert_pending(ninth.as_mut()).await;
	assert_eq!(calls.load(Ordering::SeqCst), 8);
	assert_eq!(preparations.available_permits(), 2);
	drop(continuations.pop().unwrap());
	let ninth = tokio::time::timeout(Duration::from_secs(5), ninth)
		.await
		.unwrap()
		.unwrap();
	assert_eq!(calls.load(Ordering::SeqCst), 9);
	assert_eq!(slots.available_permits(), 0);
	assert_eq!(preparations.available_permits(), 2);
	drop(ninth);
	drop(continuations);
	drain(slots, MAX_CANCEL_PUBLICATIONS).await;
	drain(preparations, MAX_CANCEL_PREPARATIONS).await;
}
