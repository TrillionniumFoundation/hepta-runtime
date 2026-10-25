// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exercise real blocking closures, cancellation, late failure and drain ownership.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::timeout;

type HeldCheck = (
	Box<dyn FnOnce() -> Result<()> + Send + 'static>,
	oneshot::Receiver<()>,
	std::sync::mpsc::Sender<()>,
);

fn held_check(result: Result<()>) -> HeldCheck {
	let (entered, receive) = oneshot::channel();
	let (release, wait) = std::sync::mpsc::channel();
	let check = move || {
		let _ = entered.send(());
		wait.recv_timeout(Duration::from_secs(5))
			.context("test worker was not released")?;
		result
	};
	(Box::new(check), receive, release)
}

#[tokio::test(flavor = "current_thread")]
async fn workers_leave_owner_responsive_and_hash_each_call() {
	let workers = Arc::new(Workers::new());
	let stop = CancellationToken::new();
	let (check, entered, release) = held_check(Ok(()));
	let task_workers = workers.clone();
	let task_stop = stop.clone();
	let task = tokio::spawn(async move {
		task_workers
			.run(&task_stop, Instant::now() + Duration::from_secs(4), check)
			.await
	});
	timeout(Duration::from_secs(2), entered)
		.await
		.unwrap()
		.unwrap();
	// This single-thread executor must still advance its own timer while a
	// real blocking validation closure waits on a separate OS thread.
	timeout(
		Duration::from_millis(500),
		tokio::time::sleep(Duration::from_millis(10)),
	)
	.await
	.unwrap();
	assert!(!task.is_finished());
	release.send(()).unwrap();
	task.await.unwrap().unwrap();
	let count = Arc::new(AtomicUsize::new(0));
	for expected in 1..=8 {
		let checked = count.clone();
		workers
			.run(&stop, Instant::now() + Duration::from_secs(2), move || {
				checked.fetch_add(1, Ordering::SeqCst);
				Ok(())
			})
			.await
			.unwrap();
		assert_eq!(count.load(Ordering::SeqCst), expected);
	}
	assert!(!stop.is_cancelled());
	assert_eq!(workers.permits.available_permits(), WORKERS);
}

#[tokio::test(flavor = "current_thread")]
async fn dropped_callers_keep_worker_capacity_and_shutdown_waits() {
	let workers = Arc::new(Workers::new());
	let stop = CancellationToken::new();
	let mut releases = Vec::new();
	for _ in 0..WORKERS {
		let (check, entered, release) = held_check(Ok(()));
		let task_workers = workers.clone();
		let task_stop = stop.clone();
		let task = tokio::spawn(async move {
			task_workers
				.run(&task_stop, Instant::now() + Duration::from_secs(4), check)
				.await
		});
		timeout(Duration::from_secs(2), entered)
			.await
			.unwrap()
			.unwrap();
		task.abort();
		assert!(task.await.unwrap_err().is_cancelled());
		releases.push(release);
	}
	assert_eq!(workers.permits.available_permits(), 0);
	let called = Arc::new(AtomicUsize::new(0));
	let observed = called.clone();
	assert!(workers
		.run(
			&stop,
			Instant::now() + Duration::from_millis(25),
			move || {
				observed.fetch_add(1, Ordering::SeqCst);
				Ok(())
			}
		)
		.await
		.is_err());
	assert_eq!(called.load(Ordering::SeqCst), 0);
	assert_eq!(workers.permits.available_permits(), 0);
	stop.cancel();
	assert!(timeout(Duration::from_millis(25), workers.drain())
		.await
		.is_err());
	for release in releases {
		release.send(()).unwrap();
	}
	timeout(Duration::from_secs(2), workers.drain())
		.await
		.unwrap()
		.unwrap();
	assert_eq!(workers.permits.available_permits(), WORKERS);
}

#[tokio::test(flavor = "current_thread")]
async fn late_authority_failure_freezes_even_after_caller_cancellation() {
	let workers = Arc::new(Workers::new());
	let stop = CancellationToken::new();
	let (check, entered, release) = held_check(Err(anyhow!("late file identity mismatch")));
	let task_workers = workers.clone();
	let task_stop = stop.clone();
	let task = tokio::spawn(async move {
		task_workers
			.run(&task_stop, Instant::now() + Duration::from_secs(4), check)
			.await
	});
	timeout(Duration::from_secs(2), entered)
		.await
		.unwrap()
		.unwrap();
	task.abort();
	assert!(task.await.unwrap_err().is_cancelled());
	assert!(!stop.is_cancelled());
	assert_eq!(workers.permits.available_permits(), WORKERS - 1);
	release.send(()).unwrap();
	timeout(Duration::from_secs(2), stop.cancelled())
		.await
		.unwrap();
	timeout(Duration::from_secs(2), workers.drain())
		.await
		.unwrap()
		.unwrap();
	assert_eq!(workers.permits.available_permits(), WORKERS);
}

#[tokio::test(flavor = "current_thread")]
async fn deadline_discards_late_success_but_does_not_release_running_worker() {
	let workers = Arc::new(Workers::new());
	let stop = CancellationToken::new();
	let (check, entered, release) = held_check(Ok(()));
	let task_workers = workers.clone();
	let task_stop = stop.clone();
	let task = tokio::spawn(async move {
		task_workers
			.run(
				&task_stop,
				Instant::now() + Duration::from_millis(500),
				check,
			)
			.await
	});
	timeout(Duration::from_secs(2), entered)
		.await
		.unwrap()
		.unwrap();
	assert!(timeout(Duration::from_secs(2), task)
		.await
		.unwrap()
		.unwrap()
		.is_err());
	assert!(stop.is_cancelled());
	assert_eq!(workers.permits.available_permits(), WORKERS - 1);
	assert!(timeout(Duration::from_millis(25), workers.drain())
		.await
		.is_err());
	release.send(()).unwrap();
	timeout(Duration::from_secs(2), workers.drain())
		.await
		.unwrap()
		.unwrap();
	assert_eq!(workers.permits.available_permits(), WORKERS);
}

#[tokio::test(flavor = "current_thread")]
async fn worker_panic_freezes_before_capacity_is_reused() {
	let workers = Workers::new();
	let stop = CancellationToken::new();
	let error = workers
		.run(&stop, Instant::now() + Duration::from_secs(2), || {
			panic!("controlled validation worker panic");
		})
		.await;
	assert!(error.is_err());
	assert!(stop.is_cancelled());
	timeout(Duration::from_secs(2), workers.drain())
		.await
		.unwrap()
		.unwrap();
	let called = Arc::new(AtomicUsize::new(0));
	let observed = called.clone();
	assert!(workers
		.run(&stop, Instant::now() + Duration::from_secs(2), move || {
			observed.fetch_add(1, Ordering::SeqCst);
			Ok(())
		})
		.await
		.is_err());
	assert_eq!(called.load(Ordering::SeqCst), 0);
}

#[test]
fn queued_worker_rechecks_original_deadline_and_stop_before_full_read() {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(1)
		.build()
		.unwrap();
	runtime.block_on(async {
		for cause in ["deadline", "stop"] {
			// Occupy the only blocking thread first, so the validation closure
			// must remain queued even though it already owns its worker permit.
			let (entered, receive) = oneshot::channel();
			let (release, wait) = std::sync::mpsc::channel();
			let occupant = tokio::task::spawn_blocking(move || {
				entered.send(()).unwrap();
				wait.recv_timeout(Duration::from_secs(5)).unwrap();
			});
			timeout(Duration::from_secs(2), receive)
				.await
				.unwrap()
				.unwrap();
			let workers = Arc::new(Workers::new());
			let stop = CancellationToken::new();
			let called = Arc::new(AtomicUsize::new(0));
			let observed = called.clone();
			let task_workers = workers.clone();
			let task_stop = stop.clone();
			let deadline = Instant::now() + Duration::from_millis(500);
			let task = tokio::spawn(async move {
				task_workers
					.run(&task_stop, deadline, move || {
						observed.fetch_add(1, Ordering::SeqCst);
						Ok(())
					})
					.await
			});
			timeout(Duration::from_secs(2), async {
				while workers.permits.available_permits() == WORKERS {
					tokio::task::yield_now().await;
				}
			})
			.await
			.unwrap();
			// Discard the waiting future before expiry, preventing its timer
			// from setting stop. The closure itself must notice the old budget.
			task.abort();
			assert!(task.await.unwrap_err().is_cancelled());
			assert_eq!(workers.permits.available_permits(), WORKERS - 1);
			assert!(!stop.is_cancelled());
			if cause == "deadline" {
				tokio::time::sleep_until(deadline).await;
				assert!(!stop.is_cancelled());
			} else {
				stop.cancel();
			}
			release.send(()).unwrap();
			occupant.await.unwrap();
			timeout(Duration::from_secs(2), workers.drain())
				.await
				.unwrap()
				.unwrap();
			assert!(stop.is_cancelled());
			assert_eq!(called.load(Ordering::SeqCst), 0, "executed after {cause}");
			assert_eq!(workers.permits.available_permits(), WORKERS);
		}
	});
}

#[tokio::test(flavor = "current_thread")]
async fn returned_owner_tickets_keep_the_original_two_slot_budget() {
	let workers = Workers::new();
	let stop = CancellationToken::new();
	let deadline = Instant::now() + Duration::from_secs(4);
	let mut tickets = Vec::new();
	for _ in 0..WORKERS {
		let ticket = workers
			.run_retained(&stop, deadline, |_| Ok(()))
			.await
			.unwrap();
		assert_eq!(ticket.deadline, deadline);
		tickets.push(ticket);
	}
	assert_eq!(workers.permits.available_permits(), 0);
	let called = Arc::new(AtomicUsize::new(0));
	let observed = called.clone();
	assert!(workers
		.run_retained(
			&stop,
			Instant::now() + Duration::from_millis(25),
			move |_| {
				observed.fetch_add(1, Ordering::SeqCst);
				Ok(())
			}
		)
		.await
		.is_err());
	assert_eq!(called.load(Ordering::SeqCst), 0);
	assert!(!stop.is_cancelled());
	for (index, ticket) in tickets.into_iter().enumerate() {
		ticket
			.finish(|_| {
				assert_eq!(workers.permits.available_permits(), index);
				Ok(())
			})
			.unwrap();
		assert_eq!(workers.permits.available_permits(), index + 1);
	}
	assert!(!stop.is_cancelled());
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_waits_for_every_returned_owner_ticket() {
	use std::future::{poll_fn, Future};
	use std::task::Poll;
	let workers = Workers::new();
	let stop = CancellationToken::new();
	let mut tickets = Vec::new();
	for _ in 0..WORKERS {
		tickets.push(
			workers
				.run_retained(&stop, Instant::now() + Duration::from_secs(4), |_| Ok(()))
				.await
				.unwrap(),
		);
	}
	stop.cancel();
	let mut drain = Box::pin(workers.drain());
	assert!(poll_fn(|cx| Poll::Ready(drain.as_mut().poll(cx)))
		.await
		.is_pending());
	drop(tickets.pop().unwrap());
	assert!(poll_fn(|cx| Poll::Ready(drain.as_mut().poll(cx)))
		.await
		.is_pending());
	drop(tickets.pop().unwrap());
	drain.await.unwrap();
	assert_eq!(workers.permits.available_permits(), WORKERS);
}

#[tokio::test(flavor = "current_thread")]
async fn owner_error_and_panic_freeze_before_ticket_capacity_is_reused() {
	for panic in [false, true] {
		let workers = Workers::new();
		let stop = CancellationToken::new();
		let ticket = workers
			.run_retained(&stop, Instant::now() + Duration::from_secs(4), |_| Ok(()))
			.await
			.unwrap();
		let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			ticket.finish(|_| {
				assert_eq!(workers.permits.available_permits(), WORKERS - 1);
				if panic {
					panic!("controlled owner check panic");
				}
				Err(anyhow!("original owner content mismatch"))
			})
		}));
		if panic {
			assert!(result.is_err());
		} else {
			assert_eq!(
				result.unwrap().unwrap_err().to_string(),
				"original owner content mismatch"
			);
		}
		assert!(stop.is_cancelled());
		assert_eq!(workers.permits.available_permits(), WORKERS);
		workers.drain().await.unwrap();
	}
}

#[tokio::test(flavor = "current_thread")]
async fn owner_finish_checks_stop_before_and_after_its_fresh_read() {
	for cancel_before in [false, true] {
		let workers = Workers::new();
		let stop = CancellationToken::new();
		let ticket = workers
			.run_retained(&stop, Instant::now() + Duration::from_secs(4), |_| Ok(()))
			.await
			.unwrap();
		if cancel_before {
			stop.cancel();
		}
		let mut called = false;
		assert!(ticket
			.finish(|_| {
				called = true;
				stop.cancel();
				Ok(())
			})
			.is_err());
		assert_eq!(called, !cancel_before);
		assert!(stop.is_cancelled());
		assert_eq!(workers.permits.available_permits(), WORKERS);
	}
}

#[tokio::test(flavor = "current_thread")]
async fn expired_owner_ticket_cannot_begin_or_accept_a_late_success() {
	for expire_before in [false, true] {
		let workers = Workers::new();
		let stop = CancellationToken::new();
		// Construct the expiry boundary directly: no sleep is used to change
		// file stamps, and the production ticket never resets its deadline.
		let ticket = OwnerTicket {
			completion: Completion {
				_permit: workers.permits.clone().acquire_owned().await.unwrap(),
				stop: stop.clone(),
				completed: false,
			},
			deadline: if expire_before {
				Instant::now()
			} else {
				Instant::now() + Duration::from_secs(1)
			},
		};
		let mut called = false;
		assert!(ticket
			.finish(|ticket| {
				called = true;
				// A synchronous operation cannot be preempted by the Tokio
				// timer; the final original deadline must still refuse it.
				while Instant::now() < ticket.deadline {
					std::thread::yield_now();
				}
				Ok(())
			})
			.is_err());
		assert_eq!(called, !expire_before);
		assert!(stop.is_cancelled());
		assert_eq!(workers.permits.available_permits(), WORKERS);
	}
}

#[test]
fn dropping_an_unpolled_completed_worker_result_freezes_and_releases_its_ticket() {
	use std::future::{poll_fn, Future};
	use std::task::Poll;
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(1)
		.build()
		.unwrap();
	runtime.block_on(async {
		let workers = Workers::new();
		let stop = CancellationToken::new();
		let (check, entered, release) = held_check(Ok(()));
		let mut pending = Box::pin(workers.run_retained(
			&stop,
			Instant::now() + Duration::from_secs(8),
			move |_| check(),
		));
		assert!(poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
			.await
			.is_pending());
		timeout(Duration::from_secs(2), entered)
			.await
			.unwrap()
			.unwrap();
		release.send(()).unwrap();
		// The only blocking thread must return the first result before this
		// sentinel can run. The owner deliberately never repolls that result.
		let (sent, receive) = std::sync::mpsc::channel();
		let sentinel = tokio::task::spawn_blocking(move || sent.send(()).unwrap());
		receive.recv_timeout(Duration::from_secs(4)).unwrap();
		assert_eq!(workers.permits.available_permits(), WORKERS - 1);
		assert!(!stop.is_cancelled());
		drop(pending);
		assert!(stop.is_cancelled());
		sentinel.await.unwrap();
		workers.drain().await.unwrap();
		assert_eq!(workers.permits.available_permits(), WORKERS);
	});
}
