// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Cancellation audit contention stays off the executor and retains original continuation custody.
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

async fn wait_released(binding: &Weak<JobRecord>) {
	tokio::time::timeout(Duration::from_secs(5), async {
		while binding.upgrade().is_some() {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
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

	let record = original();
	let binding = Arc::downgrade(&record);
	let prepared = event(root.path(), "process_cancel_intent", &record.id);
	let frozen = prepared.line.clone();
	let (entered, started) = tokio::sync::oneshot::channel();
	let remote_calls = Arc::new(AtomicUsize::new(0));
	let calls = remote_calls.clone();

	let caller_thread = std::thread::current().id();
	let cancelled = tokio::spawn(async move {
		let retained = run_cancel_intent(prepared, record, move |prepared| {
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

	assert_eq!(remote_calls.load(Ordering::SeqCst), 0);
	drop(release);
	blocker.await.unwrap().unwrap();
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
async fn busy_new_launch_writers_do_not_block_original_cancellation() {
	let root = tempfile::tempdir().unwrap();
	let (gate, release) = gate();
	let (entered, mut started) = tokio::sync::mpsc::unbounded_channel();
	let mut writers = Vec::new();
	for _ in 0..12 {
		let gate = gate.clone();
		let entered = entered.clone();
		writers.push(tokio::spawn(run_start_io((), move || {
			entered.send(()).unwrap();
			wait_gate(&gate)
		})));
	}
	for _ in 0..12 {
		tokio::time::timeout(Duration::from_secs(5), started.recv())
			.await
			.unwrap()
			.unwrap();
	}
	let record = original();
	let record = tokio::time::timeout(
		Duration::from_secs(5),
		run_cancel_intent(
			event(root.path(), "process_cancel_intent", &record.id),
			record,
			append_audit,
		),
	)
	.await
	.unwrap()
	.unwrap();
	let completed = complete_cancel_audit(
		cancel_ack(),
		Ok(event(root.path(), "process_cancel", &record.id)),
		record,
		append_audit,
	)
	.await;
	assert_eq!(completed["result"], "stop_requested");
	assert_eq!(completed["termination_confirmed"], false);
	assert_eq!(completed["audit_recorded"], true);
	assert!(writers.iter().all(|writer| !writer.is_finished()));
	drop(release);
	for writer in writers {
		writer.await.unwrap().unwrap();
	}
}

struct ActiveWriter(Arc<AtomicUsize>);

impl Drop for ActiveWriter {
	fn drop(&mut self) {
		self.0.fetch_sub(1, Ordering::SeqCst);
	}
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_intent_waiters_do_not_limit_independent_cancellations() {
	let root = tempfile::tempdir().unwrap();
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
	let tasks: Vec<_> = (0..8)
		.map(|index| launch(&format!("cancel-{index}")))
		.collect();
	for _ in 0..8 {
		tokio::time::timeout(Duration::from_secs(5), started.recv())
			.await
			.unwrap()
			.unwrap();
	}
	for task in tasks {
		task.abort();
		assert!(task.await.unwrap_err().is_cancelled());
	}
	let following: Vec<_> = (0..8)
		.map(|index| launch(&format!("independent-{index}")))
		.collect();
	for _ in 0..8 {
		tokio::time::timeout(Duration::from_secs(5), started.recv())
			.await
			.unwrap()
			.unwrap();
	}
	assert_eq!(active.load(Ordering::SeqCst), 16);
	drop(release);
	for task in following {
		task.await.unwrap().unwrap();
	}
	tokio::time::timeout(Duration::from_secs(5), async {
		while active.load(Ordering::SeqCst) != 0 {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert_eq!(maximum.load(Ordering::SeqCst), 16);
}

#[tokio::test(flavor = "current_thread")]
async fn failed_cancel_intent_never_submits_remote_cancel() {
	let root = tempfile::tempdir().unwrap();
	for failure in ["write", "panic"] {
		let remote_calls = Arc::new(AtomicUsize::new(0));
		let remote = remote_calls.clone();
		let prepared = event(root.path(), "process_cancel_intent", "original-cancel");

		let submit = async move {
			let record = run_cancel_intent(prepared, original(), move |_| {
				if failure == "write" {
					bail!("private-path credential in audit failure");
				}
				panic!("cancel intent panic fixture")
			})
			.await?;
			remote.fetch_add(1, Ordering::SeqCst);
			Ok::<_, anyhow::Error>(record)
		};
		let error = submit.await.unwrap_err();
		assert_eq!(
			error.to_string(),
			"Operation intent audit unavailable; no remote operation submitted"
		);
		assert_eq!(remote_calls.load(Ordering::SeqCst), 0);
	}
}

#[test]
fn cancel_ack_is_owned_before_waiter_cancellation_with_busy_blocking_pool() {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(1)
		.build()
		.unwrap();
	runtime.block_on(async {
		let root = tempfile::tempdir().unwrap();
		let record = original();
		let binding = Arc::downgrade(&record);
		let record = run_cancel_intent(
			event(root.path(), "process_cancel_intent", &record.id),
			record,
			append_audit,
		)
		.await
		.unwrap();

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
			complete_cancel_audit(cancel_ack(), Ok(prepared), record, move |prepared| {
				append_audit(prepared)?;
				let _ = published.send(());
				Ok(())
			})
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

		drop(release);
		blocker.await.unwrap().unwrap();
		tokio::time::timeout(Duration::from_secs(5), publication)
			.await
			.unwrap()
			.unwrap();
		wait_released(&binding).await;
		assert!(binding.upgrade().is_none());
		let rows = std::fs::read(root.path().join("audit/events.jsonl")).unwrap();
		assert!(rows.ends_with(&frozen));
		assert_eq!(
			rows.split(|byte| *byte == b'\n')
				.filter(|row| !row.is_empty())
				.count(),
			2
		);
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
			let prepared = if failure == "prepare" {
				Err(anyhow::anyhow!("private audit destination unavailable"))
			} else {
				Ok(event(root.path(), "process_cancel", "original-cancel"))
			};
			let retained =
				complete_cancel_audit(original_output.clone(), prepared, original(), move |_| {
					match failure {
						"write" => bail!("private append/sync error"),
						"panic" => panic!("cancel completion panic fixture"),
						"none" => Ok(()),
						_ => panic!("failed preparation must not append"),
					}
				})
				.await;
			for (key, value) in original_output.as_object().unwrap() {
				assert_eq!(&retained[key], value);
			}
			assert_eq!(retained["audit_recorded"], failure == "none");
			assert_eq!(retained["termination_confirmed"], false);
			assert_eq!(retained["automatic_retry"], false);
			assert!(!retained.to_string().contains("private"));
		}
	}
}
