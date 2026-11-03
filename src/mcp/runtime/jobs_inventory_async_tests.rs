// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Physical inventory capacity remains with original reads after caller cancellation.
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
		bail!("test inventory worker was not released");
	}
	Ok(())
}

async fn assert_pending<F: Future>(mut future: Pin<&mut F>) {
	poll_fn(|context| {
		assert!(future.as_mut().poll(context).is_pending());
		Poll::Ready(())
	})
	.await;
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_inventory_read_keeps_single_thread_executor_responsive() {
	let slots = Arc::new(Semaphore::new(1));
	let gate: Gate = Arc::new((Mutex::new(false), Condvar::new()));
	let release = ReleaseGate(gate.clone());
	let (entered, started) = tokio::sync::oneshot::channel();
	let owner = tokio::spawn(run_inventory_read(slots.clone(), move || {
		let _ = entered.send(());
		wait_gate(&gate)?;
		Ok("complete inventory".into())
	}));
	tokio::time::timeout(Duration::from_secs(5), started)
		.await
		.unwrap()
		.unwrap();
	assert_eq!(slots.available_permits(), 0);
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
	assert!(!owner.is_finished());
	drop(release);
	assert_eq!(owner.await.unwrap().unwrap(), "complete inventory");
	assert_eq!(slots.available_permits(), 1);
}

struct DropNotice(Option<tokio::sync::oneshot::Sender<()>>);

impl Drop for DropNotice {
	fn drop(&mut self) {
		if let Some(sender) = self.0.take() {
			let _ = sender.send(());
		}
	}
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_inventory_queue_wait_never_submits_a_read() {
	let slots = Arc::new(Semaphore::new(1));
	let held = slots.clone().acquire_owned().await.unwrap();
	let calls = Arc::new(AtomicUsize::new(0));
	let observed = calls.clone();
	let (dropped, mut notice) = tokio::sync::oneshot::channel();
	let ownership = DropNotice(Some(dropped));
	let mut waiting = Box::pin(run_inventory_read(slots.clone(), move || {
		let _ownership = ownership;
		observed.fetch_add(1, Ordering::SeqCst);
		Ok("unexpected inventory".into())
	}));
	assert_pending(waiting.as_mut()).await;
	drop(waiting);
	// A never-submitted closure is dropped synchronously with its waiting future.
	// This also detects a worker submitted early and blocked on capacity inside.
	notice.try_recv().unwrap();
	assert_eq!(calls.load(Ordering::SeqCst), 0);
	drop(held);
	let reacquired = tokio::time::timeout(Duration::from_secs(5), slots.clone().acquire_owned())
		.await
		.unwrap()
		.unwrap();
	assert_eq!(calls.load(Ordering::SeqCst), 0);
	drop(reacquired);
	assert_eq!(slots.available_permits(), 1);
}

struct ActiveWorker(Arc<AtomicUsize>);

impl Drop for ActiveWorker {
	fn drop(&mut self) {
		self.0.fetch_sub(1, Ordering::SeqCst);
	}
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_inventory_callers_keep_all_four_physical_slots() {
	let slots = Arc::new(Semaphore::new(MAX_INVENTORY_READ_WORKERS));
	let gate: Gate = Arc::new((Mutex::new(false), Condvar::new()));
	let release = ReleaseGate(gate.clone());
	let active = Arc::new(AtomicUsize::new(0));
	let maximum = Arc::new(AtomicUsize::new(0));
	let mut owners = Vec::new();
	for _ in 0..MAX_INVENTORY_READ_WORKERS {
		let (entered, started) = tokio::sync::oneshot::channel();
		let gate = gate.clone();
		let active = active.clone();
		let maximum = maximum.clone();
		owners.push(tokio::spawn(run_inventory_read(slots.clone(), move || {
			let now = active.fetch_add(1, Ordering::SeqCst) + 1;
			let _active = ActiveWorker(active);
			maximum.fetch_max(now, Ordering::SeqCst);
			let _ = entered.send(());
			wait_gate(&gate)?;
			Ok("original inventory".into())
		})));
		tokio::time::timeout(Duration::from_secs(5), started)
			.await
			.unwrap()
			.unwrap();
	}
	assert_eq!(active.load(Ordering::SeqCst), MAX_INVENTORY_READ_WORKERS);
	for owner in owners {
		owner.abort();
		assert!(owner.await.unwrap_err().is_cancelled());
	}
	assert_eq!(slots.available_permits(), 0);
	let later_calls = Arc::new(AtomicUsize::new(0));
	let mut waiters = Vec::new();
	for _ in 0..2 {
		let later_calls = later_calls.clone();
		let active = active.clone();
		let maximum = maximum.clone();
		let mut waiter = Box::pin(run_inventory_read(slots.clone(), move || {
			let now = active.fetch_add(1, Ordering::SeqCst) + 1;
			let _active = ActiveWorker(active);
			maximum.fetch_max(now, Ordering::SeqCst);
			later_calls.fetch_add(1, Ordering::SeqCst);
			Ok("later inventory".into())
		}));
		assert_pending(waiter.as_mut()).await;
		waiters.push(waiter);
	}
	assert_eq!(later_calls.load(Ordering::SeqCst), 0);
	assert_eq!(active.load(Ordering::SeqCst), MAX_INVENTORY_READ_WORKERS);
	drop(release);
	for waiter in waiters {
		assert_eq!(
			tokio::time::timeout(Duration::from_secs(5), waiter)
				.await
				.unwrap()
				.unwrap(),
			"later inventory"
		);
	}
	tokio::time::timeout(Duration::from_secs(5), async {
		while active.load(Ordering::SeqCst) != 0
			|| slots.available_permits() != MAX_INVENTORY_READ_WORKERS
		{
			tokio::task::yield_now().await;
		}
	})
	.await
	.unwrap();
	assert_eq!(later_calls.load(Ordering::SeqCst), 2);
	assert_eq!(maximum.load(Ordering::SeqCst), MAX_INVENTORY_READ_WORKERS);
}

#[test]
fn cancelled_inventory_closures_in_blocking_queue_keep_their_original_slots() {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(1)
		.build()
		.unwrap();
	runtime.block_on(async {
		let pool_gate: Gate = Arc::new((Mutex::new(false), Condvar::new()));
		// Release during an assertion unwind before dropping the runtime, which
		// must still drain its non-abortable submitted blocking closures.
		let release_pool = ReleaseGate(pool_gate.clone());
		let (entered, started) = tokio::sync::oneshot::channel();
		let blocker = tokio::task::spawn_blocking(move || {
			let _ = entered.send(());
			wait_gate(&pool_gate).unwrap();
		});
		tokio::time::timeout(Duration::from_secs(5), started)
			.await
			.unwrap()
			.unwrap();
		let slots = Arc::new(Semaphore::new(MAX_INVENTORY_READ_WORKERS));
		let calls = Arc::new(AtomicUsize::new(0));
		let mut submitted = Vec::new();
		for _ in 0..MAX_INVENTORY_READ_WORKERS {
			let calls = calls.clone();
			let mut caller = Box::pin(run_inventory_read(slots.clone(), move || {
				calls.fetch_add(1, Ordering::SeqCst);
				Ok("original queued inventory".into())
			}));
			assert_pending(caller.as_mut()).await;
			submitted.push(caller);
		}
		assert_eq!(slots.available_permits(), 0);
		assert_eq!(calls.load(Ordering::SeqCst), 0);
		drop(submitted);
		assert_eq!(slots.available_permits(), 0);
		let observed = calls.clone();
		let mut extra = Box::pin(run_inventory_read(slots.clone(), move || {
			observed.fetch_add(1, Ordering::SeqCst);
			Ok("unexpected extra inventory".into())
		}));
		assert_pending(extra.as_mut()).await;
		drop(extra);
		assert_eq!(slots.available_permits(), 0);
		assert_eq!(calls.load(Ordering::SeqCst), 0);
		drop(release_pool);
		tokio::time::timeout(Duration::from_secs(5), blocker)
			.await
			.unwrap()
			.unwrap();
		tokio::time::timeout(Duration::from_secs(5), async {
			while slots.available_permits() != MAX_INVENTORY_READ_WORKERS {
				tokio::task::yield_now().await;
			}
		})
		.await
		.unwrap();
		assert_eq!(calls.load(Ordering::SeqCst), MAX_INVENTORY_READ_WORKERS);
	});
}

#[tokio::test(flavor = "current_thread")]
async fn inventory_errors_panics_and_closed_capacity_preserve_refusal_and_release_slots() {
	let slots = Arc::new(Semaphore::new(1));
	let error = run_inventory_read(slots.clone(), || {
		Err(anyhow::anyhow!("original inventory validation error"))
	})
	.await
	.unwrap_err();
	assert_eq!(error.to_string(), "original inventory validation error");
	assert_eq!(slots.available_permits(), 1);
	let error = run_inventory_read(slots.clone(), || {
		panic!("fixture inventory worker panic must not become a successful list")
	})
	.await
	.unwrap_err();
	assert_eq!(
		error.to_string(),
		"Durable job inventory worker unavailable"
	);
	assert_eq!(slots.available_permits(), 1);
	slots.close();
	let calls = Arc::new(AtomicUsize::new(0));
	let observed = calls.clone();
	let error = run_inventory_read(slots, move || {
		observed.fetch_add(1, Ordering::SeqCst);
		Ok("unexpected inventory".into())
	})
	.await
	.unwrap_err();
	assert_eq!(
		error.to_string(),
		"Durable job inventory worker unavailable"
	);
	assert_eq!(calls.load(Ordering::SeqCst), 0);
}

async fn assert_uses_shared_inventory_pool(read: impl Future<Output = Result<String>>) {
	let slots = inventory_read_slots();
	let held = slots
		.clone()
		.acquire_many_owned(MAX_INVENTORY_READ_WORKERS as u32)
		.await
		.unwrap();
	let mut read = Box::pin(read);
	assert_pending(read.as_mut()).await;
	let mut probe = Box::pin(
		slots
			.clone()
			.acquire_many_owned(MAX_INVENTORY_READ_WORKERS as u32),
	);
	assert_pending(probe.as_mut()).await;
	drop(held);
	// Semaphore FIFO reserves a slot for the earlier unpolled read. The probe
	// cannot receive all four until that exact waiting call is dropped.
	// An entry point using another pool or bypassing admission fails here.
	assert_pending(probe.as_mut()).await;
	drop(read);
	let restored = tokio::time::timeout(Duration::from_secs(5), probe)
		.await
		.unwrap()
		.unwrap();
	assert_eq!(slots.available_permits(), 0);
	drop(restored);
}

#[tokio::test(flavor = "current_thread")]
async fn list_and_page_entry_points_use_one_physical_inventory_pool() {
	// Neither call is polled after its slot is available, so no global runtime
	// configuration, filesystem fixture or worker test hook is needed.
	assert_uses_shared_inventory_pool(list_jobs_async(ProcessListParams { host: None })).await;
	assert_uses_shared_inventory_pool(list_jobs_page_async(ProcessListPageParams::default())).await;
}
