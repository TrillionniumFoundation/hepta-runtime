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
use tokio::sync::oneshot;

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
		let calls = Arc::new(AtomicUsize::new(0));
		let observed = calls.clone();
		let error = run_metadata_query(Instant::now(), move |_| {
			observed.fetch_add(1, Ordering::SeqCst);
			Ok(())
		})
		.await
		.unwrap_err();
		assert!(error.is::<MetadataQueryDeadline>());
		assert_eq!(calls.load(Ordering::SeqCst), 0);
	});
}

#[test]
fn metadata_query_preserves_result_and_original_deadline() {
	isolated_runtime().block_on(async {
		let deadline = Instant::now() + Duration::from_secs(5);
		let result = run_metadata_query(deadline, move |actual| {
			assert_eq!(actual, deadline);
			Ok("original query result")
		})
		.await
		.unwrap();
		assert_eq!(result, "original query result");
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

		let calls = Arc::new(AtomicUsize::new(0));
		let observed = calls.clone();
		let mut query = Box::pin(run_metadata_query(
			Instant::now() + Duration::from_millis(250),
			move |_| {
				observed.fetch_add(1, Ordering::SeqCst);
				Ok(())
			},
		));
		// The only blocking worker is held. Poll once to submit the query and
		// establish worker ownership before waiting for its original deadline.
		poll_fn(|cx| {
			assert!(query.as_mut().poll(cx).is_pending());
			Poll::Ready(())
		})
		.await;

		let error = query.await.unwrap_err();
		assert!(error.is::<MetadataQueryDeadline>());

		release.send(()).unwrap();
		blocker.await.unwrap();
		blocking_queue_fence().await;
		assert_eq!(calls.load(Ordering::SeqCst), 0);
	});
}

#[test]
fn metadata_query_dropped_before_poll_never_spawns() {
	isolated_runtime().block_on(async {
		let calls = Arc::new(AtomicUsize::new(0));
		let observed = calls.clone();
		drop(run_metadata_query(
			Instant::now() + Duration::from_secs(5),
			move |_| {
				observed.fetch_add(1, Ordering::SeqCst);
				Ok(())
			},
		));
		blocking_queue_fence().await;
		assert_eq!(calls.load(Ordering::SeqCst), 0);
	});
}

#[test]
fn metadata_query_cancelled_worker_retains_custody_until_exit() {
	isolated_runtime().block_on(async {
		let (started, ready) = oneshot::channel();
		let (release, blocked) = mpsc::channel();
		let custody = Arc::new(());
		let witness = Arc::downgrade(&custody);
		let query = tokio::spawn(run_metadata_query(
			Instant::now() + Duration::from_secs(5),
			move |_| {
				let _custody = custody;
				started.send(()).unwrap();
				blocked.recv().unwrap();
				Ok(())
			},
		));
		ready.await.unwrap();
		query.abort();
		assert!(query.await.unwrap_err().is_cancelled());

		assert!(witness.upgrade().is_some());
		release.send(()).unwrap();
		blocking_queue_fence().await;
		assert!(witness.upgrade().is_none());
	});
}

#[test]
fn metadata_query_timed_out_worker_retains_custody_until_exit() {
	isolated_runtime().block_on(async {
		let (started, ready) = oneshot::channel();
		let (release, blocked) = mpsc::channel();
		let custody = Arc::new(());
		let witness = Arc::downgrade(&custody);
		let query = tokio::spawn(run_metadata_query(
			Instant::now() + Duration::from_millis(250),
			move |_| {
				let _custody = custody;
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

		assert!(witness.upgrade().is_some());
		release.send(()).unwrap();
		blocking_queue_fence().await;
		assert!(witness.upgrade().is_none());
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
		let calls = Arc::new(AtomicUsize::new(0));
		let observed = calls.clone();
		let (started, ready) = oneshot::channel();
		let (release, blocked) = mpsc::channel();
		let deadline = Instant::now() + Duration::from_secs(2);
		let mut query = Box::pin(run_metadata_query(deadline, move |actual| {
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
	});
}

#[test]
fn metadata_queries_exceed_old_eight_worker_limit_and_preserve_custody() {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	runtime.block_on(async {
		let deadline = Instant::now() + Duration::from_secs(10);
		let (entered, mut started) = tokio::sync::mpsc::unbounded_channel();
		let mut tasks = Vec::new();
		let mut releases = Vec::new();
		let mut witnesses = Vec::new();
		for index in 0..16 {
			let (release, blocked) = mpsc::channel();
			let custody = Arc::new(());
			witnesses.push(Arc::downgrade(&custody));
			let entered = entered.clone();
			tasks.push(tokio::spawn(run_metadata_query(deadline, move |actual| {
				let _custody = custody;
				assert_eq!(actual, deadline);
				entered.send(index).unwrap();
				blocked.recv_timeout(Duration::from_secs(10)).unwrap();
				Ok(index)
			})));
			releases.push(release);
		}
		for _ in 0..16 {
			tokio::time::timeout(Duration::from_secs(5), started.recv())
				.await
				.unwrap()
				.unwrap();
		}
		for task in tasks.drain(..4) {
			task.abort();
			assert!(task.await.unwrap_err().is_cancelled());
		}
		assert!(witnesses.iter().all(|witness| witness.upgrade().is_some()));
		for release in releases {
			release.send(()).unwrap();
		}
		for task in tasks {
			task.await.unwrap().unwrap();
		}
		tokio::time::timeout(Duration::from_secs(5), async {
			while witnesses.iter().any(|witness| witness.upgrade().is_some()) {
				tokio::task::yield_now().await;
			}
		})
		.await
		.unwrap();
	});
}
