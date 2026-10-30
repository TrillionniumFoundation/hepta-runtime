// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Cancellation audit contention stays off the executor and retains original continuation capacity.
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
		bail!("cancel audit fixture gate not released");
	}
	Ok(())
}

fn original() -> Arc<JobRecord> {
	Arc::new(
		serde_json::from_value(json!({
			"id":"original-cancel", "host":"main", "ssh_target":"never-connect.invalid",
			"unit":"hepta-runtime-job-original-cancel", "remote_job_dir":"/private/jobs/original-cancel",
			"execution_mode":"operator", "system_jobctl":false,
			"executable":"/usr/bin/true", "args":[], "cwd":null, "env_keys":[],
			"created_unix_ms":1, "idempotency_key":"original-key", "request_fingerprint":1,
			"request_digest":"a".repeat(64), "launch_state":"launched", "launch_error":null
		}))
		.unwrap(),
	)
}

fn event(root: &Path, action: &str, subject: &str) -> PreparedAudit {
	prepare_audit_at(
		root.join("audit/events.jsonl"),
		action,
		"main",
		subject,
		&if action.ends_with("intent") {
			json!({"phase":"intent", "remote_operation_submitted":false})
		} else {
			json!({"phase":"result", "outcome_unknown":false})
		},
	)
	.unwrap()
}

fn cancel_ack() -> Value {
	retain_cancel_outcome(
		"original-cancel",
		Ok(json!({"job_id":"original-cancel", "result":"stop_requested", "atomic_identity":true})),
	)
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
async fn cancel_intent_contending_for_real_audit_lock_keeps_executor_live_and_custody() {
	let root = tempfile::tempdir().unwrap();
	let (gate, release) = gate();
	let (locked, lock_held) = tokio::sync::oneshot::channel();
	let blocker_event = event(root.path(), "process_start_intent", "unrelated-start");
	let blocker = tokio::task::spawn_blocking(move || {
		append_audit_with(blocker_event, move |file| {
			let _ = locked.send(());
			wait_gate(&gate)?;
			Ok(file.sync_data()?)
		})
	});
	tokio::time::timeout(Duration::from_secs(5), lock_held)
		.await
		.unwrap()
		.unwrap();
	let slots = Arc::new(Semaphore::new(1));
	let record = original();
	let binding = Arc::downgrade(&record);
	let prepared = event(root.path(), "process_cancel_intent", &record.id);
	let frozen = prepared.line.clone();
	let (entered, started) = tokio::sync::oneshot::channel();
	let remote_calls = Arc::new(AtomicUsize::new(0));
	let calls = remote_calls.clone();
	let worker_slots = slots.clone();
	let caller_thread = std::thread::current().id();
	let cancelled = tokio::spawn(async move {
		let retained = run_cancel_intent(prepared, worker_slots, record, move |prepared| {
			let _ = entered.send(std::thread::current().id());
			append_audit(prepared)
		})
		.await?;
		calls.fetch_add(1, Ordering::SeqCst);
		Ok::<_, anyhow::Error>(retained)
	});
	let worker_thread = tokio::time::timeout(Duration::from_secs(5), started)
		.await
		.unwrap()
		.unwrap();
	assert_ne!(worker_thread, caller_thread);
	assert!(!cancelled.is_finished());
	assert_eq!(slots.available_permits(), 0);
	let heartbeat = tokio::spawn(async {
		tokio::task::yield_now().await;
		17
	});
	assert_eq!(
		tokio::time::timeout(Duration::from_secs(5), heartbeat)
			.await
			.unwrap()
			.unwrap(),
		17
	);
	cancelled.abort();
	assert!(cancelled.await.unwrap_err().is_cancelled());
	assert!(binding.upgrade().is_some());
	assert_eq!(slots.available_permits(), 0);
	assert_eq!(remote_calls.load(Ordering::SeqCst), 0);
	drop(release);
	blocker.await.unwrap().unwrap();
	drain(slots, 1).await;
	// The abandoned intent result drops its permit before its record field;
	// permit acquisition alone is not a cross-thread record-drop barrier.
	tokio::time::timeout(Duration::from_secs(5), async {
		while binding.upgrade().is_some() {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert_eq!(remote_calls.load(Ordering::SeqCst), 0);
	let rows = std::fs::read(root.path().join("audit/events.jsonl")).unwrap();
	assert!(rows.ends_with(&frozen));
	assert_eq!(
		rows.split(|byte| *byte == b'\n')
			.filter(|row| !row.is_empty())
			.count(),
		2
	);
}

#[tokio::test(flavor = "current_thread")]
async fn saturated_new_launch_capacity_does_not_block_original_cancellation() {
	let root = tempfile::tempdir().unwrap();
	let pending_slots = start_io_slots();
	let launch_slots = start_outcome_slots();
	let cancel_slots = cancel_publication_slots();
	assert!(!Arc::ptr_eq(&pending_slots, &cancel_slots));
	assert!(!Arc::ptr_eq(&launch_slots, &cancel_slots));
	let pending = tokio::time::timeout(
		Duration::from_secs(5),
		pending_slots
			.clone()
			.acquire_many_owned(MAX_START_IO_WORKERS as u32),
	)
	.await
	.unwrap()
	.unwrap();
	let launches = tokio::time::timeout(
		Duration::from_secs(5),
		launch_slots
			.clone()
			.acquire_many_owned(MAX_START_OUTCOME_PUBLICATIONS as u32),
	)
	.await
	.unwrap()
	.unwrap();
	let record = original();
	let (permit, record) = tokio::time::timeout(
		Duration::from_secs(5),
		run_cancel_intent(
			event(root.path(), "process_cancel_intent", &record.id),
			cancel_slots.clone(),
			record,
			append_audit,
		),
	)
	.await
	.unwrap()
	.unwrap();
	assert_eq!(pending_slots.available_permits(), 0);
	assert_eq!(launch_slots.available_permits(), 0);
	assert_eq!(
		cancel_slots.available_permits(),
		MAX_CANCEL_PUBLICATIONS - 1
	);
	let completed = complete_cancel_audit(
		cancel_ack(),
		Ok(event(root.path(), "process_cancel", &record.id)),
		permit,
		record,
		append_audit,
	)
	.await;
	assert_eq!(completed["result"], "stop_requested");
	assert_eq!(completed["termination_confirmed"], false);
	assert_eq!(completed["audit_recorded"], true);
	assert_eq!(cancel_slots.available_permits(), MAX_CANCEL_PUBLICATIONS);
	drop((pending, launches));
}

struct ActiveWriter(Arc<AtomicUsize>);

impl Drop for ActiveWriter {
	fn drop(&mut self) {
		self.0.fetch_sub(1, Ordering::SeqCst);
	}
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_intent_waiters_retain_the_eight_actual_writer_bound() {
	let root = tempfile::tempdir().unwrap();
	let slots = Arc::new(Semaphore::new(MAX_CANCEL_PUBLICATIONS));
	let active = Arc::new(AtomicUsize::new(0));
	let maximum = Arc::new(AtomicUsize::new(0));
	let (gate, release) = gate();
	let (entered, mut started) = tokio::sync::mpsc::unbounded_channel();
	let launch = |name: &str| {
		let active = active.clone();
		let maximum = maximum.clone();
		let entered = entered.clone();
		let gate = gate.clone();
		tokio::spawn(run_cancel_intent(
			event(root.path(), "process_cancel_intent", name),
			slots.clone(),
			original(),
			move |_| {
				let count = active.fetch_add(1, Ordering::SeqCst) + 1;
				let _active = ActiveWriter(active);
				maximum.fetch_max(count, Ordering::SeqCst);
				entered.send(()).unwrap();
				wait_gate(&gate)
			},
		))
	};
	let tasks: Vec<_> = (0..MAX_CANCEL_PUBLICATIONS)
		.map(|index| launch(&format!("cancel-{index}")))
		.collect();
	for _ in 0..MAX_CANCEL_PUBLICATIONS {
		tokio::time::timeout(Duration::from_secs(5), started.recv())
			.await
			.unwrap()
			.unwrap();
	}
	for task in tasks {
		task.abort();
		assert!(task.await.unwrap_err().is_cancelled());
	}
	let cancelled_before_admission = launch("must-not-start");
	tokio::task::yield_now().await;
	cancelled_before_admission.abort();
	assert!(cancelled_before_admission.await.unwrap_err().is_cancelled());
	let following = launch("next-cancel");
	assert!(
		tokio::time::timeout(Duration::from_millis(50), started.recv())
			.await
			.is_err()
	);
	assert_eq!(slots.available_permits(), 0);
	assert_eq!(active.load(Ordering::SeqCst), MAX_CANCEL_PUBLICATIONS);
	drop(release);
	let (permit, record) = tokio::time::timeout(Duration::from_secs(5), following)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
	let completed = complete_cancel_audit(
		cancel_ack(),
		Ok(event(root.path(), "process_cancel", &record.id)),
		permit,
		record,
		append_audit,
	)
	.await;
	assert_eq!(completed["audit_recorded"], true);
	drain(slots.clone(), MAX_CANCEL_PUBLICATIONS).await;
	assert_eq!(active.load(Ordering::SeqCst), 0);
	assert_eq!(maximum.load(Ordering::SeqCst), MAX_CANCEL_PUBLICATIONS);
	assert!(started.try_recv().is_ok());
	assert!(matches!(
		started.try_recv(),
		Err(tokio::sync::mpsc::error::TryRecvError::Empty)
	));
}

#[tokio::test(flavor = "current_thread")]
async fn failed_or_closed_cancel_intent_never_submits_remote_cancel() {
	let root = tempfile::tempdir().unwrap();
	for failure in ["write", "panic", "closed"] {
		let slots = Arc::new(Semaphore::new(1));
		if failure == "closed" {
			slots.close();
		}
		let remote_calls = Arc::new(AtomicUsize::new(0));
		let remote = remote_calls.clone();
		let prepared = event(root.path(), "process_cancel_intent", "original-cancel");
		let publication_slots = slots.clone();
		let submit = async move {
			let (permit, record) =
				run_cancel_intent(prepared, publication_slots, original(), move |_| {
					if failure == "write" {
						bail!("private-path credential in audit failure");
					}
					panic!("cancel intent panic fixture")
				})
				.await?;
			remote.fetch_add(1, Ordering::SeqCst);
			Ok::<_, anyhow::Error>((permit, record))
		};
		let error = submit.await.unwrap_err();
		assert_eq!(
			error.to_string(),
			"Operation intent audit unavailable; no remote operation submitted"
		);
		assert_eq!(remote_calls.load(Ordering::SeqCst), 0);
		assert_eq!(slots.available_permits(), 1);
	}
}

#[test]
fn cancel_ack_is_owned_before_waiter_cancellation_with_all_publication_slots_reserved() {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(1)
		.build()
		.unwrap();
	runtime.block_on(async {
		let root = tempfile::tempdir().unwrap();
		let slots = Arc::new(Semaphore::new(MAX_CANCEL_PUBLICATIONS));
		let mut reservations = Vec::new();
		for _ in 1..MAX_CANCEL_PUBLICATIONS {
			reservations.push(slots.clone().acquire_owned().await.unwrap());
		}
		let record = original();
		let binding = Arc::downgrade(&record);
		let (permit, record) = run_cancel_intent(
			event(root.path(), "process_cancel_intent", &record.id),
			slots.clone(),
			record,
			append_audit,
		)
		.await
		.unwrap();
		assert_eq!(slots.available_permits(), 0);
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
		let prepared = event(root.path(), "process_cancel", &record.id);
		let frozen = prepared.line.clone();
		let (handling, handled) = tokio::sync::oneshot::channel();
		let (published, mut publication) = tokio::sync::oneshot::channel();
		let caller = tokio::spawn(async move {
			let _ = handling.send(());
			complete_cancel_audit(
				cancel_ack(),
				Ok(prepared),
				permit,
				record,
				move |prepared| {
					append_audit(prepared)?;
					let _ = published.send(());
					Ok(())
				},
			)
			.await
		});
		tokio::time::timeout(Duration::from_secs(5), handled)
			.await
			.unwrap()
			.unwrap();
		assert!(matches!(
			publication.try_recv(),
			Err(tokio::sync::oneshot::error::TryRecvError::Empty)
		));
		caller.abort();
		assert!(caller.await.unwrap_err().is_cancelled());
		assert!(binding.upgrade().is_some());
		assert_eq!(slots.available_permits(), 0);
		slots.close();
		drop(release);
		blocker.await.unwrap().unwrap();
		tokio::time::timeout(Duration::from_secs(5), publication)
			.await
			.unwrap()
			.unwrap();
		tokio::time::timeout(Duration::from_secs(5), async {
			while slots.available_permits() != 1 {
				tokio::task::yield_now().await;
			}
		})
		.await
		.unwrap();
		assert!(binding.upgrade().is_none());
		let rows = std::fs::read(root.path().join("audit/events.jsonl")).unwrap();
		assert!(rows.ends_with(&frozen));
		assert_eq!(
			rows.split(|byte| *byte == b'\n')
				.filter(|row| !row.is_empty())
				.count(),
			2
		);
		drop(reservations);
		assert_eq!(slots.available_permits(), MAX_CANCEL_PUBLICATIONS);
	});
}

#[tokio::test(flavor = "current_thread")]
async fn cancel_ack_and_uncertainty_survive_completion_audit_failures() {
	let root = tempfile::tempdir().unwrap();
	for original_output in [
		cancel_ack(),
		retain_cancel_outcome(
			"original-cancel",
			Err(anyhow::anyhow!("remote transport failure")),
		),
	] {
		for failure in ["write", "panic", "prepare", "none"] {
			let slots = Arc::new(Semaphore::new(1));
			let permit = slots.clone().acquire_owned().await.unwrap();
			let prepared = if failure == "prepare" {
				Err(anyhow::anyhow!("private audit destination unavailable"))
			} else {
				Ok(event(root.path(), "process_cancel", "original-cancel"))
			};
			let retained = complete_cancel_audit(
				original_output.clone(),
				prepared,
				permit,
				original(),
				move |_| match failure {
					"write" => bail!("private append/sync error"),
					"panic" => panic!("cancel completion panic fixture"),
					"none" => Ok(()),
					_ => panic!("failed preparation must not append"),
				},
			)
			.await;
			for (key, value) in original_output.as_object().unwrap() {
				assert_eq!(&retained[key], value);
			}
			assert_eq!(retained["audit_recorded"], failure == "none");
			assert_eq!(retained["termination_confirmed"], false);
			assert_eq!(retained["automatic_retry"], false);
			assert!(!retained.to_string().contains("private"));
			assert_eq!(slots.available_permits(), 1);
		}
	}
}
