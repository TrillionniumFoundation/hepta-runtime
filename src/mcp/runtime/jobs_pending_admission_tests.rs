// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Pending publication transfers the original payload and retains worker custody.
use super::*;
use std::sync::atomic::AtomicUsize;
#[cfg(unix)]
use std::sync::Condvar;

fn record() -> JobRecord {
	serde_json::from_value(json!({
		"execution_mode":"operator", "system_jobctl":false,
		"id":"original-pending", "host":"main", "ssh_target":"never-connect.invalid",
		"unit":"original-unit", "remote_job_dir":"/never-launch/original-pending",
		"executable":"/usr/bin/true", "args":["x".repeat(64 * 1024)],
		"cwd":null, "env_keys":[], "created_unix_ms":1,
		"idempotency_key":"original-key", "request_fingerprint":1,
		"request_digest":"a".repeat(64), "launch_state":"pending", "launch_error":null
	}))
	.unwrap()
}

fn intent() -> PreparedAudit {
	prepare_audit_at(
		PathBuf::from("/never-publish/pending-admission-audit.jsonl"),
		"process_start_intent",
		"main",
		"original-pending",
		&json!({"phase":"intent", "remote_operation_submitted":false}),
	)
	.unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn pending_publication_returns_original_allocations_and_preserves_frozen_intent_order() {
	let original = record();
	let args_ptr = original.args[0].as_ptr() as usize;
	let digest_ptr = original.request_digest.as_ref().unwrap().as_ptr() as usize;
	let prepared = intent();
	let frozen_line = prepared.line.clone();
	let events = Arc::new(Mutex::new(Vec::new()));
	let appended = events.clone();
	let persisted = events.clone();
	let returned = publish_pending_with(
		original,
		prepared,
		(),
		move |prepared| {
			assert_eq!(prepared.line, frozen_line);
			appended.lock().unwrap().push("intent");
			Ok(())
		},
		move |record| {
			assert_eq!(record.args[0].as_ptr() as usize, args_ptr);
			assert_eq!(
				record.request_digest.as_ref().unwrap().as_ptr() as usize,
				digest_ptr
			);
			let mut events = persisted.lock().unwrap();
			assert_eq!(events.as_slice(), ["intent"]);
			events.push("pending");
			Ok(())
		},
	)
	.await
	.unwrap();
	assert_eq!(returned.args[0].as_ptr() as usize, args_ptr);
	assert_eq!(
		returned.request_digest.as_ref().unwrap().as_ptr() as usize,
		digest_ptr
	);
	assert_eq!(returned.id, "original-pending");
	assert_eq!(returned.idempotency_key.as_deref(), Some("original-key"));
	assert_eq!(returned.args[0].len(), 64 * 1024);
	assert_eq!(returned.launch_state, "pending");
	assert_eq!(events.lock().unwrap().as_slice(), ["intent", "pending"]);
}

#[tokio::test(flavor = "current_thread")]
async fn unpolled_pending_publication_never_publishes() {
	let publications = Arc::new(AtomicUsize::new(0));
	let appended = publications.clone();
	let persisted = publications.clone();
	drop(publish_pending_with(
		record(),
		intent(),
		(),
		move |_| {
			appended.fetch_add(1, Ordering::SeqCst);
			Ok(())
		},
		move |_| {
			persisted.fetch_add(1, Ordering::SeqCst);
			Ok(())
		},
	));
	tokio::task::yield_now().await;
	assert_eq!(publications.load(Ordering::SeqCst), 0);
}

#[cfg(unix)]
type Gate = Arc<(Mutex<bool>, Condvar)>;

#[cfg(unix)]
struct ReleaseGate(Gate);

#[cfg(unix)]
impl Drop for ReleaseGate {
	fn drop(&mut self) {
		let (lock, changed) = &*self.0;
		*lock.lock().unwrap() = true;
		changed.notify_all();
	}
}

#[cfg(unix)]
fn wait_gate(gate: &Gate) -> Result<()> {
	let (_released, timeout) = gate
		.1
		.wait_timeout_while(
			gate.0.lock().unwrap(),
			Duration::from_secs(10),
			|released| !*released,
		)
		.unwrap();
	if timeout.timed_out() {
		bail!("pending publication fixture gate was not released");
	}
	Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn pending_cancellation_keeps_original_worker_key_and_flock() {
	use std::os::fd::AsRawFd;
	let root = tempfile::tempdir().unwrap();
	let owner_path = root.path().join("owner.lock");
	let owner = File::create(&owner_path).unwrap();
	assert_eq!(unsafe { libc::flock(owner.as_raw_fd(), libc::LOCK_SH) }, 0);
	let contender = File::open(&owner_path).unwrap();
	let record_path = root.path().join("original-pending.json");
	let saved_path = record_path.clone();

	let lane = Arc::new(AsyncMutex::new(()));
	let original_lane = Arc::new(lane.clone().lock_owned().await);
	let gate: Gate = Arc::new((Mutex::new(false), Condvar::new()));
	let release = ReleaseGate(gate.clone());
	let original = record();
	let args_ptr = original.args[0].as_ptr() as usize;
	let publications = Arc::new(AtomicUsize::new(0));
	let observed = publications.clone();

	let (entered, started) = tokio::sync::oneshot::channel();
	let writer = tokio::spawn(publish_pending_with(
		original,
		intent(),
		(original_lane, Arc::new(owner)),
		move |_| {
			let _ = entered.send(());
			wait_gate(&gate)
		},
		move |record| {
			assert_eq!(record.args[0].as_ptr() as usize, args_ptr);
			save_record_at(&saved_path, record)?;
			observed.fetch_add(1, Ordering::SeqCst);
			Ok(())
		},
	));
	tokio::time::timeout(Duration::from_secs(5), started)
		.await
		.unwrap()
		.unwrap();
	writer.abort();
	assert!(writer.await.unwrap_err().is_cancelled());

	assert!(lane.try_lock().is_err());
	assert_ne!(
		unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
		0
	);
	assert_eq!(publications.load(Ordering::SeqCst), 0);

	let next_calls = Arc::new(AtomicUsize::new(0));
	let next_append = next_calls.clone();
	let next_persist = next_calls.clone();
	let (entered, queued) = tokio::sync::oneshot::channel();
	let waiter = tokio::spawn(async move {
		let _ = entered.send(());
		publish_pending_with(
			record(),
			intent(),
			(),
			move |_| {
				next_append.fetch_add(1, Ordering::SeqCst);
				Ok(())
			},
			move |_| {
				next_persist.fetch_add(1, Ordering::SeqCst);
				Ok(())
			},
		)
		.await
	});
	queued.await.unwrap();
	tokio::time::timeout(Duration::from_secs(5), waiter)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
	assert_eq!(next_calls.load(Ordering::SeqCst), 2);
	assert!(lane.try_lock().is_err());
	drop(release);
	tokio::time::timeout(Duration::from_secs(5), async {
		while lane.try_lock().is_err()
			|| unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
		{
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert_eq!(publications.load(Ordering::SeqCst), 1);
	assert_eq!(next_calls.load(Ordering::SeqCst), 2);
	assert!(lane.try_lock().is_ok());
	assert_eq!(
		unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
		0
	);
	assert_eq!(
		unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_UN) },
		0
	);
	let saved = read_record_at(&record_path, "original-pending").unwrap();
	assert_eq!(saved.idempotency_key.as_deref(), Some("original-key"));
	assert_eq!(saved.args[0].len(), 64 * 1024);
	assert_eq!(saved.launch_state, "pending");
}
