// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Receipt reads leave the executor live and retain physical capacity after cancellation.
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

fn wait_gate(gate: &Gate) -> Result<()> {
	let locked = gate.0.lock().unwrap();
	let (_released, timeout) = gate
		.1
		.wait_timeout_while(locked, Duration::from_secs(10), |released| !*released)
		.unwrap();
	if timeout.timed_out() {
		bail!("test observation reader was not released");
	}
	Ok(())
}

fn record() -> JobRecord {
	serde_json::from_value(json!({
		"id":"original-observation", "host":"main", "ssh_target":"never-connect.invalid",
		"unit":"original-unit", "remote_job_dir":"/never-launch/original-observation",
		"executable":"/usr/bin/true", "args":["original\n中文"], "cwd":null, "env_keys":[],
		"created_unix_ms":1, "idempotency_key":"original-key", "request_fingerprint":7,
		"request_digest":"a".repeat(64), "launch_state":"launched"
	}))
	.unwrap()
}

async fn assert_pending<F: Future>(mut future: Pin<&mut F>) {
	poll_fn(|context| {
		assert!(future.as_mut().poll(context).is_pending());
		Poll::Ready(())
	})
	.await;
}

struct ActiveReader(Arc<AtomicUsize>);

impl Drop for ActiveReader {
	fn drop(&mut self) {
		self.0.fetch_sub(1, Ordering::SeqCst);
	}
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_observers_keep_four_physical_readers_and_executor_responsive() {
	let slots = Arc::new(Semaphore::new(MAX_OBSERVATION_RECORD_READS));
	let gate: Gate = Arc::new((Mutex::new(false), Condvar::new()));
	let release = ReleaseGate(gate.clone());
	let active = Arc::new(AtomicUsize::new(0));
	let maximum = Arc::new(AtomicUsize::new(0));
	let mut owners = Vec::new();
	for _ in 0..MAX_OBSERVATION_RECORD_READS {
		let (entered, started) = tokio::sync::oneshot::channel();
		let gate = gate.clone();
		let active = active.clone();
		let maximum = maximum.clone();
		owners.push(tokio::spawn(run_observation_record_read(
			slots.clone(),
			move || {
				let now = active.fetch_add(1, Ordering::SeqCst) + 1;
				let _active = ActiveReader(active);
				maximum.fetch_max(now, Ordering::SeqCst);
				let _ = entered.send(());
				wait_gate(&gate)?;
				Ok(record())
			},
		)));
		tokio::time::timeout(Duration::from_secs(5), started)
			.await
			.unwrap()
			.unwrap();
	}
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
	for owner in owners {
		owner.abort();
		assert!(owner.await.unwrap_err().is_cancelled());
	}
	assert_eq!(slots.available_permits(), 0);
	assert_eq!(active.load(Ordering::SeqCst), MAX_OBSERVATION_RECORD_READS);
	let calls = Arc::new(AtomicUsize::new(0));
	let observed = calls.clone();
	let mut waiter = Box::pin(run_observation_record_read(slots.clone(), move || {
		observed.fetch_add(1, Ordering::SeqCst);
		Ok(record())
	}));
	assert_pending(waiter.as_mut()).await;
	drop(waiter);
	assert_eq!(calls.load(Ordering::SeqCst), 0);
	drop(release);
	tokio::time::timeout(Duration::from_secs(5), async {
		while active.load(Ordering::SeqCst) != 0
			|| slots.available_permits() != MAX_OBSERVATION_RECORD_READS
		{
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert_eq!(maximum.load(Ordering::SeqCst), MAX_OBSERVATION_RECORD_READS);
	assert_eq!(calls.load(Ordering::SeqCst), 0);
	assert_eq!(
		run_observation_record_read(slots, || Ok(record()))
			.await
			.unwrap(),
		record()
	);
}

#[test]
fn cancelled_receipt_reads_in_blocking_queue_keep_slots_until_actual_exit() {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(1)
		.build()
		.unwrap();
	runtime.block_on(async {
		let gate: Gate = Arc::new((Mutex::new(false), Condvar::new()));
		let release = ReleaseGate(gate.clone());
		let (entered, started) = tokio::sync::oneshot::channel();
		let blocker = tokio::task::spawn_blocking(move || {
			let _ = entered.send(());
			wait_gate(&gate).unwrap();
		});
		tokio::time::timeout(Duration::from_secs(5), started)
			.await
			.unwrap()
			.unwrap();
		let slots = Arc::new(Semaphore::new(MAX_OBSERVATION_RECORD_READS));
		let calls = Arc::new(AtomicUsize::new(0));
		let mut submitted = Vec::new();
		for _ in 0..MAX_OBSERVATION_RECORD_READS {
			let calls = calls.clone();
			let mut caller = Box::pin(run_observation_record_read(slots.clone(), move || {
				calls.fetch_add(1, Ordering::SeqCst);
				Ok(record())
			}));
			assert_pending(caller.as_mut()).await;
			submitted.push(caller);
		}
		assert_eq!(calls.load(Ordering::SeqCst), 0);
		drop(submitted);
		assert_eq!(slots.available_permits(), 0);
		let observed = calls.clone();
		let mut extra = Box::pin(run_observation_record_read(slots.clone(), move || {
			observed.fetch_add(100, Ordering::SeqCst);
			Ok(record())
		}));
		assert_pending(extra.as_mut()).await;
		drop(extra);
		drop(release);
		blocker.await.unwrap();
		tokio::time::timeout(Duration::from_secs(5), async {
			while slots.available_permits() != MAX_OBSERVATION_RECORD_READS {
				tokio::task::yield_now().await;
			}
		})
		.await
		.unwrap();
		assert_eq!(calls.load(Ordering::SeqCst), MAX_OBSERVATION_RECORD_READS);
	});
}

#[tokio::test(flavor = "current_thread")]
async fn observation_reader_preserves_real_receipt_and_validation_errors() {
	let root = tempfile::tempdir().unwrap();
	let path = root.path().join("original-observation.json");
	let original = record();
	save_record_at(&path, &original).unwrap();
	let bytes = std::fs::read(&path).unwrap();
	let slots = Arc::new(Semaphore::new(1));
	let source = path.clone();
	assert_eq!(
		run_observation_record_read(slots.clone(), move || {
			read_record_at(&source, "original-observation")
		})
		.await
		.unwrap(),
		original
	);
	assert_eq!(std::fs::read(&path).unwrap(), bytes);
	std::fs::write(&path, b"{truncated receipt").unwrap();
	let expected = format!(
		"{:#}",
		read_record_at(&path, "original-observation").unwrap_err()
	);
	let error = run_observation_record_read(slots.clone(), move || {
		read_record_at(&path, "original-observation")
	})
	.await
	.unwrap_err();
	assert_eq!(format!("{error:#}"), expected);
	assert_eq!(slots.available_permits(), 1);
	let error = run_observation_record_read(slots.clone(), || {
		panic!("test observation worker must not become a successful read")
	})
	.await
	.unwrap_err();
	assert_eq!(
		error.to_string(),
		"job observation record worker unavailable"
	);
	assert_eq!(slots.available_permits(), 1);
	slots.close();
	let calls = Arc::new(AtomicUsize::new(0));
	let observed = calls.clone();
	let error = run_observation_record_read(slots, move || {
		observed.fetch_add(1, Ordering::SeqCst);
		Ok(record())
	})
	.await
	.unwrap_err();
	assert_eq!(
		error.to_string(),
		"job observation record capacity unavailable"
	);
	assert_eq!(calls.load(Ordering::SeqCst), 0);
}

async fn assert_uses_observation_pool(read: impl Future<Output = Result<String>>) {
	let slots = observation_record_read_slots();
	let held = slots
		.clone()
		.acquire_many_owned(MAX_OBSERVATION_RECORD_READS as u32)
		.await
		.unwrap();
	let mut read = Box::pin(read);
	assert_pending(read.as_mut()).await;
	let mut probe = Box::pin(
		slots
			.clone()
			.acquire_many_owned(MAX_OBSERVATION_RECORD_READS as u32),
	);
	assert_pending(probe.as_mut()).await;
	drop(held);
	// FIFO reserves a slot for the unpolled original read. Dropping that caller
	// before it can submit physical work must restore the complete pool.
	assert_pending(probe.as_mut()).await;
	drop(read);
	let restored = tokio::time::timeout(Duration::from_secs(5), probe)
		.await
		.unwrap()
		.unwrap();
	drop(restored);
}

#[tokio::test(flavor = "current_thread")]
async fn status_wait_and_read_share_only_the_observation_receipt_pool() {
	assert!(!Arc::ptr_eq(
		&observation_record_read_slots(),
		&start_io_slots()
	));
	assert!(!Arc::ptr_eq(
		&observation_record_read_slots(),
		&inventory_read_slots()
	));
	let reference = ProcessRefParams {
		host: "never-connect".into(),
		job_id: "../invalid-id".into(),
	};
	assert_uses_observation_pool(status_job(reference.clone())).await;
	assert_uses_observation_pool(wait_job(ProcessWaitParams {
		host: reference.host.clone(),
		job_id: reference.job_id.clone(),
		timeout_seconds: None,
	}))
	.await;
	assert_uses_observation_pool(read_job(ProcessReadParams {
		host: reference.host.clone(),
		job_id: reference.job_id.clone(),
		stdout_offset: None,
		stderr_offset: None,
		limit: None,
	}))
	.await;
	let expected = format!("{:#}", check_ref(&reference).unwrap_err());
	assert_eq!(
		format!("{:#}", check_ref_async(&reference).await.unwrap_err()),
		expected
	);
}
