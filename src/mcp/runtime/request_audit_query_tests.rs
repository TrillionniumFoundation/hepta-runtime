// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Deterministic admission, cancellation and deadline checks for archive queries.
use super::{
	archive_history_at_until, metadata_query_public_error, run_metadata_query,
	usage_stats_at_until, MetadataQueryDeadline, RequestHistoryParams,
};
use std::future::{poll_fn, Future};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, Semaphore};

fn isolated_runtime() -> tokio::runtime::Runtime {
	tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(1)
		.build()
		.unwrap()
}

async fn blocking_queue_fence() {
	tokio::time::timeout(Duration::from_secs(5), tokio::task::spawn_blocking(|| ()))
		.await
		.unwrap()
		.unwrap();
}

#[test]
fn metadata_query_expired_before_admission_never_runs() {
	isolated_runtime().block_on(async {
		let slots = Arc::new(Semaphore::new(1));
		let calls = Arc::new(AtomicUsize::new(0));
		let observed = calls.clone();
		let error = run_metadata_query(Instant::now(), slots.clone(), move |_| {
			observed.fetch_add(1, Ordering::SeqCst);
			Ok(())
		})
		.await
		.unwrap_err();
		assert!(error.is::<MetadataQueryDeadline>());
		assert_eq!(calls.load(Ordering::SeqCst), 0);
		assert_eq!(slots.available_permits(), 1);
	});
}

#[test]
fn metadata_query_preserves_result_and_original_deadline() {
	isolated_runtime().block_on(async {
		let slots = Arc::new(Semaphore::new(1));
		let deadline = Instant::now() + Duration::from_secs(5);
		let result = run_metadata_query(deadline, slots.clone(), move |actual| {
			assert_eq!(actual, deadline);
			Ok("original query result")
		})
		.await
		.unwrap();
		assert_eq!(result, "original query result");
		assert_eq!(slots.available_permits(), 1);
	});
}

#[test]
fn metadata_query_expired_in_blocking_queue_never_runs() {
	isolated_runtime().block_on(async {
		let (started, ready) = oneshot::channel();
		let (release, blocked) = mpsc::channel();
		let blocker = tokio::task::spawn_blocking(move || {
			started.send(()).unwrap();
			blocked.recv().unwrap();
		});
		ready.await.unwrap();
		let slots = Arc::new(Semaphore::new(1));
		let calls = Arc::new(AtomicUsize::new(0));
		let observed = calls.clone();
		let mut query = Box::pin(run_metadata_query(
			Instant::now() + Duration::from_millis(250),
			slots.clone(),
			move |_| {
				observed.fetch_add(1, Ordering::SeqCst);
				Ok(())
			},
		));
		// The only blocking worker is held. Poll once to submit the query and
		// establish its slot ownership before waiting for its original deadline.
		poll_fn(|cx| {
			assert!(query.as_mut().poll(cx).is_pending());
			Poll::Ready(())
		})
		.await;
		assert_eq!(slots.available_permits(), 0);
		let error = query.await.unwrap_err();
		assert!(error.is::<MetadataQueryDeadline>());
		assert_eq!(slots.available_permits(), 0);
		release.send(()).unwrap();
		blocker.await.unwrap();
		blocking_queue_fence().await;
		assert_eq!(calls.load(Ordering::SeqCst), 0);
		assert_eq!(slots.available_permits(), 1);
	});
}

#[test]
fn metadata_query_cancelled_while_waiting_never_spawns() {
	isolated_runtime().block_on(async {
		let slots = Arc::new(Semaphore::new(1));
		let held = slots.clone().acquire_owned().await.unwrap();
		let calls = Arc::new(AtomicUsize::new(0));
		let observed = calls.clone();
		let mut query = Box::pin(run_metadata_query(
			Instant::now() + Duration::from_secs(5),
			slots.clone(),
			move |_| {
				observed.fetch_add(1, Ordering::SeqCst);
				Ok(())
			},
		));
		poll_fn(|cx| {
			assert!(query.as_mut().poll(cx).is_pending());
			Poll::Ready(())
		})
		.await;
		drop(query);
		drop(held);
		blocking_queue_fence().await;
		assert_eq!(calls.load(Ordering::SeqCst), 0);
		assert_eq!(slots.available_permits(), 1);
	});
}

#[test]
fn metadata_query_cancelled_worker_retains_capacity_until_exit() {
	isolated_runtime().block_on(async {
		let slots = Arc::new(Semaphore::new(1));
		let (started, ready) = oneshot::channel();
		let (release, blocked) = mpsc::channel();
		let query = tokio::spawn(run_metadata_query(
			Instant::now() + Duration::from_secs(5),
			slots.clone(),
			move |_| {
				started.send(()).unwrap();
				blocked.recv().unwrap();
				Ok(())
			},
		));
		ready.await.unwrap();
		query.abort();
		assert!(query.await.unwrap_err().is_cancelled());
		assert_eq!(slots.available_permits(), 0);
		assert!(slots.clone().try_acquire_owned().is_err());
		release.send(()).unwrap();
		blocking_queue_fence().await;
		assert_eq!(slots.available_permits(), 1);
	});
}

#[test]
fn metadata_query_timed_out_worker_retains_capacity_until_exit() {
	isolated_runtime().block_on(async {
		let slots = Arc::new(Semaphore::new(1));
		let (started, ready) = oneshot::channel();
		let (release, blocked) = mpsc::channel();
		let query = tokio::spawn(run_metadata_query(
			Instant::now() + Duration::from_millis(250),
			slots.clone(),
			move |_| {
				started.send(()).unwrap();
				blocked.recv().unwrap();
				Ok(())
			},
		));
		// Readiness proves that this case expires during the query itself,
		// distinct from the blocked-pool case above.
		ready.await.unwrap();
		assert!(query
			.await
			.unwrap()
			.unwrap_err()
			.is::<MetadataQueryDeadline>());
		assert_eq!(slots.available_permits(), 0);
		assert!(slots.clone().try_acquire_owned().is_err());
		release.send(()).unwrap();
		blocking_queue_fence().await;
		assert_eq!(slots.available_permits(), 1);
	});
}

#[test]
fn archive_query_expired_deadline_does_not_open_missing_store() {
	let directory = tempfile::tempdir().unwrap();
	let root = directory.path().join("missing");
	let owner = "a".repeat(64);
	let expired = Instant::now();
	let usage = usage_stats_at_until(&root, std::array::from_ref(&owner), expired).unwrap_err();
	assert!(usage.to_string().contains("total deadline exceeded"));
	let archive = archive_history_at_until(
		&root,
		&owner,
		RequestHistoryParams {
			after_id: None,
			limit: Some(1),
		},
		expired,
	)
	.unwrap_err();
	assert!(archive.to_string().contains("total deadline exceeded"));
	assert!(!root.exists());
}

#[test]
fn metadata_query_errors_preserve_timeout_and_redact_inner_details() {
	let timeout = metadata_query_public_error(MetadataQueryDeadline.into());
	assert!(timeout.is::<MetadataQueryDeadline>());
	let error = metadata_query_public_error(anyhow::anyhow!("private path detail"));
	assert_eq!(
		error.to_string(),
		"archive index preparing or validation unavailable; repeat only this metadata query"
	);
}

#[test]
fn metadata_query_ready_success_consumed_after_deadline_is_refused() {
	isolated_runtime().block_on(async {
		let slots = Arc::new(Semaphore::new(1));
		let calls = Arc::new(AtomicUsize::new(0));
		let observed = calls.clone();
		let (started, ready) = oneshot::channel();
		let (release, blocked) = mpsc::channel();
		let deadline = Instant::now() + Duration::from_secs(2);
		let mut query = Box::pin(run_metadata_query(deadline, slots.clone(), move |actual| {
			assert_eq!(actual, deadline);
			observed.fetch_add(1, Ordering::SeqCst);
			started.send(()).unwrap();
			blocked.recv_timeout(Duration::from_secs(5)).unwrap();
			Ok("completed original metadata result")
		}));
		// The barrier makes this first poll pending regardless of worker speed.
		poll_fn(|cx| {
			assert!(query.as_mut().poll(cx).is_pending());
			Poll::Ready(())
		})
		.await;
		tokio::time::timeout(Duration::from_secs(5), ready)
			.await
			.unwrap()
			.unwrap();
		release.send(()).unwrap();
		// The isolated runtime has one blocking thread. This subsequent fence
		// proves the query closure and its JoinHandle result are ready while
		// the caller future is deliberately left unpolled.
		blocking_queue_fence().await;
		assert_eq!(calls.load(Ordering::SeqCst), 1);
		assert_eq!(slots.available_permits(), 1);
		assert!(
			Instant::now() < deadline,
			"fixture missed its pre-deadline ready window"
		);
		// Pause this current-thread owner explicitly, not through system load.
		std::thread::sleep(
			deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
		);
		assert!(Instant::now() >= deadline);
		let error = query.await.unwrap_err();
		assert!(error.is::<MetadataQueryDeadline>());
		assert_eq!(
			calls.load(Ordering::SeqCst),
			1,
			"metadata query was replayed"
		);
		assert_eq!(slots.available_permits(), 1);
	});
}
