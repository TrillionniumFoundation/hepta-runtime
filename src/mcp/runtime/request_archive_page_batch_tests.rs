// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Shared page snapshots retain the actual complete terminal observation fence.
use super::*;

#[cfg(target_os = "linux")]
#[test]
#[serial_test::serial]
fn a_final_epoch_change_discards_every_already_projected_page() {
	let (root, owner) = tests::fixture();
	let archive = open_archive(root.path()).unwrap();
	let make_queries = || {
		(0..3)
			.map(|_| {
				Ok(PageQuery {
					owner: owner.clone(),
					cursor: None,
					limit: 32,
				})
			})
			.collect()
	};
	let warm = pages(
		root.path(),
		&archive,
		make_queries(),
		Instant::now() + QUERY_BUDGET,
	)
	.unwrap();
	assert_eq!(warm.values.len(), 3);
	assert!(warm.values.iter().all(Result::is_ok));
	let slot = slot_at(root.path(), &archive).unwrap();
	let original = std::fs::read_dir(root.path().join(ARCHIVE_NAME))
		.unwrap()
		.map(|entry| entry.unwrap().path())
		.find(|path| {
			path.extension()
				.is_some_and(|extension| extension == "json")
		})
		.unwrap();
	let bytes = std::fs::read(&original).unwrap();
	let changed = Arc::new(AtomicUsize::new(0));
	let count = changed.clone();
	*slot.parallel_hook.lock().unwrap() = Some(Arc::new(move |event| {
		if event == ParallelEvent::BeforeSnapshotFence {
			// The private read closure has already built all three wire pages.
			// Same bytes still create a distinct observed content epoch.
			std::fs::write(&original, &bytes).unwrap();
			count.fetch_add(1, Ordering::Relaxed);
		}
	}));
	let result = pages(
		root.path(),
		&archive,
		make_queries(),
		Instant::now() + QUERY_BUDGET,
	);
	*slot.parallel_hook.lock().unwrap() = None;
	assert_eq!(changed.load(Ordering::Relaxed), 1);
	assert!(
		result.is_err(),
		"no projected owner success may cross a failed final fence"
	);
	assert!(slot.state.try_lock().is_ok());
	assert!(store_lock().is_ok());
}

#[test]
#[serial_test::serial]
fn shared_page_projection_errors_stay_local_before_the_common_final_fence() {
	let (root, owner) = tests::fixture();
	let archive = open_archive(root.path()).unwrap();
	let result = pages(
		root.path(),
		&archive,
		vec![
			Err(anyhow!("one private cursor is unavailable")),
			Ok(PageQuery {
				owner,
				cursor: None,
				limit: 32,
			}),
		],
		Instant::now() + QUERY_BUDGET,
	)
	.unwrap();
	let mut replies = result.values.into_iter();
	assert!(replies.next().unwrap().is_err());
	let page: Value = serde_json::from_str(&replies.next().unwrap().unwrap()).unwrap();
	assert_eq!(page["total"], 1);
	assert_eq!(page["requests"].as_array().unwrap().len(), 1);
}
