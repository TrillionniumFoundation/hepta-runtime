// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Local create must not overwrite a name published after its preflight.

use super::*;

#[test]
fn concurrent_local_creates_after_identical_preflight_have_exactly_one_winner() {
	use std::future::{poll_fn, Future};
	use std::task::Poll;

	let temporary = tempfile::tempdir().unwrap();
	let path = temporary.path().join("created.txt");
	let source = PathSource::Local(path.clone());
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.max_blocking_threads(1)
		.build()
		.unwrap();
	let (first, second) = runtime.block_on(async {
		// Occupy the only filesystem worker until both real create requests
		// have passed exists() and queued their opens. No timing sleeps or
		// replacement I/O implementation can decide which call wins.
		let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
		let (release_tx, release_rx) = std::sync::mpsc::channel();
		let owner = tokio::task::spawn_blocking(move || {
			let _ = entered_tx.send(());
			release_rx.recv().unwrap();
		});
		entered_rx.await.unwrap();
		let first = create_file_spec(&source, "first caller bytes");
		let second = create_file_spec(&source, "second caller bytes");
		tokio::pin!(first, second);
		poll_fn(|context| {
			assert!(first.as_mut().poll(context).is_pending());
			assert!(second.as_mut().poll(context).is_pending());
			Poll::Ready(())
		})
		.await;
		release_tx.send(()).unwrap();
		let results = tokio::join!(first, second);
		owner.await.unwrap();
		results
	});
	assert_ne!(first.is_ok(), second.is_ok());
	let expected = if first.is_ok() {
		"first caller bytes"
	} else {
		"second caller bytes"
	};
	assert_eq!(std::fs::read_to_string(&path).unwrap(), expected);
}

#[cfg(unix)]
#[tokio::test]
async fn local_create_refuses_dangling_symlink_without_writing_its_target() {
	let temporary = tempfile::tempdir().unwrap();
	let target = temporary.path().join("must-remain-absent");
	let path = temporary.path().join("dangling");
	std::os::unix::fs::symlink(&target, &path).unwrap();
	assert!(!path.exists());
	assert!(
		create_file_spec(&PathSource::Local(path.clone()), "unwanted")
			.await
			.is_err()
	);
	assert!(!target.exists());
	assert!(std::fs::symlink_metadata(path)
		.unwrap()
		.file_type()
		.is_symlink());
}
