// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Start publication keeps the executor responsive without abandoning durable ownership.
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
	let value = Arc::new((Mutex::new(false), Condvar::new()));
	(value.clone(), ReleaseGate(value))
}

fn wait_gate(gate: &Gate) -> Result<()> {
	let value = gate.0.lock().unwrap();
	let (_released, timeout) = gate
		.1
		.wait_timeout_while(value, Duration::from_secs(10), |released| !*released)
		.unwrap();
	if timeout.timed_out() {
		bail!("publication fixture gate was not released");
	}
	Ok(())
}

fn record() -> JobRecord {
	serde_json::from_value(json!({
		"execution_mode":"operator", "system_jobctl":false,
		"id":"original-start", "host":"main", "ssh_target":"never-connect.invalid",
		"unit":"hepta-runtime-job-original-start", "remote_job_dir":"/private/jobs/original-start",
		"executable":"/usr/bin/true", "args":[], "cwd":null, "env_keys":[],
		"created_unix_ms":1, "idempotency_key":"original-key", "request_fingerprint":1,
		"request_digest":"a".repeat(64), "launch_state":"pending", "launch_error":null
	}))
	.unwrap()
}

fn acknowledgement() -> Value {
	json!({"ok":true, "backend":"systemd", "unit":"hepta-runtime-job-original-start"})
}

fn prepared(path: &Path) -> PreparedAudit {
	prepare_audit_at(
		path.to_owned(),
		"process_start_intent",
		"main",
		"original-start",
		&json!({"phase":"intent", "remote_operation_submitted":false}),
	)
	.unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_start_publication_keeps_single_thread_executor_responsive() {
	let slots = Arc::new(Semaphore::new(1));
	let (gate, release) = gate();
	let (entered, started) = tokio::sync::oneshot::channel();
	let writer = tokio::spawn(run_start_io(slots.clone(), (), move || {
		let _ = entered.send(());
		wait_gate(&gate)?;
		Ok(7)
	}));
	tokio::time::timeout(Duration::from_secs(5), started)
		.await
		.unwrap()
		.unwrap();
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
	assert!(!writer.is_finished());
	assert_eq!(slots.available_permits(), 0);
	drop(release);
	assert_eq!(writer.await.unwrap().unwrap(), 7);
	assert_eq!(slots.available_permits(), 1);
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn cancelled_pending_writer_retains_same_key_lane_and_actual_owner_flock() {
	use std::os::fd::AsRawFd;
	let root = tempfile::tempdir().unwrap();
	let lock_path = root.path().join("owner.lock");
	let owner = File::create(&lock_path).unwrap();
	assert_eq!(unsafe { libc::flock(owner.as_raw_fd(), libc::LOCK_SH) }, 0);
	let contender = File::open(&lock_path).unwrap();
	let registry = root.path().join("jobs");
	std::fs::create_dir(&registry).unwrap();
	let lane = Arc::new(AsyncMutex::new(()));
	let guard = Arc::new(lane.clone().lock_owned().await);
	let slots = Arc::new(Semaphore::new(1));
	let (gate, release) = gate();
	let (entered, started) = tokio::sync::oneshot::channel();
	let path = registry.join("original-start.json");
	let writer = tokio::spawn(run_start_io(
		slots.clone(),
		(Some(guard), Arc::new(owner)),
		move || {
			let _ = entered.send(());
			wait_gate(&gate)?;
			save_record_at(&path, &record())
		},
	));
	tokio::time::timeout(Duration::from_secs(5), started)
		.await
		.unwrap()
		.unwrap();
	writer.abort();
	assert!(writer.await.unwrap_err().is_cancelled());
	assert_eq!(slots.available_permits(), 0);
	assert!(lane.try_lock().is_err());
	assert_ne!(
		unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
		0,
		"the cancelled caller must not permit an owner transition during publication"
	);
	let (entered, mut following_started) = tokio::sync::mpsc::unbounded_channel();
	let following_registry = registry.clone();
	let following = tokio::spawn(async move {
		let _lane = lane.lock_owned().await;
		entered.send(()).unwrap();
		find_idempotent_in(
			&following_registry,
			"main",
			"original-key",
			&Mutex::new(ReuseHitCache::default()),
		)
	});
	assert!(
		tokio::time::timeout(Duration::from_millis(50), following_started.recv())
			.await
			.is_err()
	);
	drop(release);
	let original = tokio::time::timeout(Duration::from_secs(5), following)
		.await
		.unwrap()
		.unwrap()
		.unwrap()
		.unwrap();
	assert_eq!(original.id, "original-start");
	assert_eq!(original.launch_state, "pending");
	assert_eq!(std::fs::read_dir(registry).unwrap().count(), 1);
	tokio::time::timeout(Duration::from_secs(5), async {
		while slots.available_permits() != 1 {
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert_eq!(
		unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
		0
	);
	assert_eq!(
		unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_UN) },
		0
	);
}

struct ActiveWriter(Arc<AtomicUsize>);

impl Drop for ActiveWriter {
	fn drop(&mut self) {
		self.0.fetch_sub(1, Ordering::SeqCst);
	}
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_start_waiters_do_not_expand_actual_writer_capacity() {
	let slots = Arc::new(Semaphore::new(MAX_START_IO_WORKERS));
	let (gate, release) = gate();
	let active = Arc::new(AtomicUsize::new(0));
	let maximum = Arc::new(AtomicUsize::new(0));
	let (entered, mut started) = tokio::sync::mpsc::unbounded_channel();
	let launch = || {
		let gate = gate.clone();
		let active = active.clone();
		let maximum = maximum.clone();
		let entered = entered.clone();
		tokio::spawn(run_start_io(slots.clone(), (), move || {
			let count = active.fetch_add(1, Ordering::SeqCst) + 1;
			let _active = ActiveWriter(active);
			maximum.fetch_max(count, Ordering::SeqCst);
			entered.send(()).unwrap();
			wait_gate(&gate)
		}))
	};
	let owners: Vec<_> = (0..MAX_START_IO_WORKERS).map(|_| launch()).collect();
	for _ in 0..MAX_START_IO_WORKERS {
		tokio::time::timeout(Duration::from_secs(5), started.recv())
			.await
			.unwrap()
			.unwrap();
	}
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
	assert_eq!(active.load(Ordering::SeqCst), MAX_START_IO_WORKERS);
	drop(release);
	for waiter in queued {
		waiter.await.unwrap().unwrap();
	}
	tokio::time::timeout(Duration::from_secs(5), async {
		while active.load(Ordering::SeqCst) != 0
			|| slots.available_permits() != MAX_START_IO_WORKERS
		{
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert_eq!(maximum.load(Ordering::SeqCst), MAX_START_IO_WORKERS);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_or_closed_start_admission_never_submits_a_writer() {
	let slots = Arc::new(Semaphore::new(1));
	let held = slots.clone().acquire_owned().await.unwrap();
	let calls = Arc::new(AtomicUsize::new(0));
	let seen = calls.clone();
	let waiting = tokio::spawn(run_start_io(slots.clone(), (), move || {
		seen.fetch_add(1, Ordering::SeqCst);
		Ok(())
	}));
	tokio::task::yield_now().await;
	waiting.abort();
	assert!(waiting.await.unwrap_err().is_cancelled());
	drop(held);
	slots.close();
	let seen = calls.clone();
	let error = run_start_io(slots, (), move || {
		seen.fetch_add(1, Ordering::SeqCst);
		Ok(())
	})
	.await
	.unwrap_err();
	assert_eq!(error.to_string(), "job start I/O capacity unavailable");
	assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn start_worker_errors_and_panics_release_capacity_without_success() {
	let slots = Arc::new(Semaphore::new(1));
	let error = run_start_io(slots.clone(), (), || -> Result<()> {
		bail!("original publication failure")
	})
	.await
	.unwrap_err();
	assert_eq!(error.to_string(), "original publication failure");
	assert_eq!(slots.available_permits(), 1);
	let error = run_start_io(slots.clone(), (), || -> Result<()> {
		panic!("publication worker panic fixture")
	})
	.await
	.unwrap_err();
	assert_eq!(error.to_string(), "job start I/O worker unavailable");
	assert_eq!(slots.available_permits(), 1);
}

#[test]
fn failed_pending_intent_or_identity_never_reaches_effect_submission() {
	let root = tempfile::tempdir().unwrap();
	let saves = AtomicUsize::new(0);
	let launches = AtomicUsize::new(0);
	for failure in ["intent", "record"] {
		let outcome = (|| -> Result<()> {
			persist_pending_with(
				prepared(&root.path().join("audit.jsonl")),
				&record(),
				|_| {
					if failure == "intent" {
						bail!("secret audit path or credential");
					}
					Ok(())
				},
				|_| {
					saves.fetch_add(1, Ordering::SeqCst);
					bail!("secret receipt path or credential")
				},
			)?;
			launches.fetch_add(1, Ordering::SeqCst);
			Ok(())
		})();
		let error = outcome.unwrap_err().to_string();
		assert!(!error.contains("secret"));
		assert!(error.contains("no remote"));
	}
	assert_eq!(saves.load(Ordering::SeqCst), 1);
	assert_eq!(launches.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn pending_publication_saves_frozen_intent_before_recoverable_identity() {
	let root = tempfile::tempdir().unwrap();
	let audit_path = root.path().join("audit.jsonl");
	let record_path = root.path().join("original-start.json");
	let prepared = prepared(&audit_path);
	let original_line = prepared.line.clone();
	let observed_audit_path = audit_path.clone();
	let observed_record_path = record_path.clone();
	let slots = Arc::new(Semaphore::new(1));
	let held = slots.clone().acquire_owned().await.unwrap();
	let writer = tokio::spawn(run_start_io(slots, (), move || {
		persist_pending_with(
			prepared,
			&record(),
			|prepared| {
				append_audit_prepared_with(
					prepared,
					&mut None,
					Ok(()),
					|file| Ok(file.sync_data()?),
					|directory| Ok(directory.sync_all()?),
				)
			},
			|record| {
				assert_eq!(std::fs::read(observed_audit_path)?, original_line);
				save_record_at(&observed_record_path, record)
			},
		)
	}));
	tokio::task::yield_now().await;
	assert!(!audit_path.exists());
	assert!(!record_path.exists());
	drop(held);
	writer.await.unwrap().unwrap();
	let saved = read_record_at(&record_path, "original-start").unwrap();
	assert_eq!(saved.id, "original-start");
	assert_eq!(saved.launch_state, "pending");
}

#[cfg(unix)]
#[test]
fn acknowledged_launch_is_owned_before_cancellation_even_with_a_busy_blocking_pool() {
	use std::os::fd::AsRawFd;
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(1)
		.build()
		.unwrap();
	runtime.block_on(async {
		assert_eq!(MAX_START_OUTCOME_PUBLICATIONS, 8);
		assert!(!Arc::ptr_eq(&start_io_slots(), &start_outcome_slots()));
		let slots = Arc::new(Semaphore::new(MAX_START_OUTCOME_PUBLICATIONS));
		let mut reserved = Vec::new();
		for _ in 0..MAX_START_OUTCOME_PUBLICATIONS {
			reserved.push(slots.clone().acquire_owned().await.unwrap());
		}
		let permit = reserved.pop().unwrap();
		assert_eq!(slots.available_permits(), 0);
		let (blocker_gate, blocker_release) = gate();
		let (entered, started) = tokio::sync::oneshot::channel();
		let blocker = tokio::task::spawn_blocking(move || {
			let _ = entered.send(());
			wait_gate(&blocker_gate)
		});
		tokio::time::timeout(Duration::from_secs(5), started)
			.await
			.unwrap()
			.unwrap();

		let root = tempfile::tempdir().unwrap();
		let path = root.path().join("original-start.json");
		let pending = record();
		save_record_at(&path, &pending).unwrap();
		let lock_path = root.path().join("owner.lock");
		let owner = File::create(&lock_path).unwrap();
		assert_eq!(unsafe { libc::flock(owner.as_raw_fd(), libc::LOCK_SH) }, 0);
		let contender = File::open(&lock_path).unwrap();
		let lane = Arc::new(AsyncMutex::new(()));
		let guard = Arc::new(lane.clone().lock_owned().await);
		let publication_path = path.clone();
		let (handling, handled) = tokio::sync::oneshot::channel();
		let (published, mut publication) = tokio::sync::oneshot::channel();
		let waiter = tokio::spawn(async move {
			let mut record = pending;
			let _ = handling.send(());
			preserve_launch_outcome_async(
				&mut record,
				Ok(acknowledgement()),
				permit,
				(Some(guard), Arc::new(owner)),
				move |record| {
					save_record_at(&publication_path, record)?;
					let _ = published.send(());
					Ok(())
				},
			)
			.await
		});
		// On this single-thread executor the ACK task has run through its first
		// suspension before we can resume. Its writer is queued, not yet started.
		tokio::time::timeout(Duration::from_secs(5), handled)
			.await
			.unwrap()
			.unwrap();
		assert!(matches!(
			publication.try_recv(),
			Err(tokio::sync::oneshot::error::TryRecvError::Empty)
		));
		waiter.abort();
		assert!(waiter.await.unwrap_err().is_cancelled());
		assert!(lane.try_lock().is_err());
		assert_eq!(slots.available_permits(), 0);
		assert_ne!(
			unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
			0
		);
		assert_eq!(
			read_record_at(&path, "original-start")
				.unwrap()
				.launch_state,
			"pending"
		);
		// Closing admission after the ACK must not revoke its earlier reservation.
		slots.close();
		drop(blocker_release);
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
		let saved = read_record_at(&path, "original-start").unwrap();
		assert_eq!(saved.id, "original-start");
		assert_eq!(saved.launch_state, "launched");
		assert!(lane.try_lock().is_ok());
		assert_eq!(
			unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
			0
		);
		drop(reserved);
		assert_eq!(slots.available_permits(), MAX_START_OUTCOME_PUBLICATIONS);
	});
}

#[tokio::test(flavor = "current_thread")]
async fn successful_remote_ack_survives_local_publication_failure() {
	for failure in ["write", "panic"] {
		let slots = Arc::new(Semaphore::new(1));
		let permit = slots.clone().acquire_owned().await.unwrap();
		let mut record = record();
		let ack = acknowledgement();
		let retained =
			preserve_launch_outcome_async(&mut record, Ok(ack.clone()), permit, (), move |_| {
				if failure == "write" {
					bail!("private sync failure");
				}
				panic!("original outcome writer panic fixture")
			})
			.await;
		assert_eq!(retained.value, ack);
		assert!(retained.local_record_pending);
		assert_eq!(record.id, "original-start");
		assert_eq!(record.launch_state, "launched");
		let mut response = json!({"job":record, "launch":retained.value});
		attach_launch_record_warning(&mut response, &retained);
		assert_eq!(response["local_record_pending"], true);
		assert!(response["reconcile_warning"]
			.as_str()
			.unwrap()
			.contains("existing job_id"));
		assert_eq!(slots.available_permits(), 1);
	}
}

#[tokio::test(flavor = "current_thread")]
async fn uncertain_ack_publishes_only_the_original_unknown_identity() {
	for ack in [
		Ok(json!({"ok":true, "backend":"invalid"})),
		Err(anyhow::anyhow!("transport unavailable")),
	] {
		let slots = Arc::new(Semaphore::new(1));
		let permit = slots.acquire_owned().await.unwrap();
		let saved = Arc::new(Mutex::new(None));
		let observed = saved.clone();
		let mut record = record();
		let retained = preserve_launch_outcome_async(&mut record, ack, permit, (), move |record| {
			*observed.lock().unwrap() = Some(record.clone());
			Ok(())
		})
		.await;
		assert_eq!(retained.value["state"], "launch_unknown");
		assert_eq!(retained.value["automatic_retry"], false);
		assert!(!retained.local_record_pending);
		let saved = saved.lock().unwrap();
		let saved = saved.as_ref().unwrap();
		assert_eq!(saved.id, "original-start");
		assert_eq!(saved.request_digest, record.request_digest);
		assert_eq!(saved.launch_state, "launch_unknown");
		assert!(!reconcile_retry_allowed(saved));
	}
}
