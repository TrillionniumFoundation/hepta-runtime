// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Physical spawn ordering and guard retention. Recording guards are test
//! observations, not the embedding host's production FinalUse authority.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

struct Guard(Arc<AtomicBool>);
impl Drop for Guard {
	fn drop(&mut self) {
		self.0.store(false, Ordering::SeqCst);
	}
}

#[tokio::test]
async fn denied_entry_never_spawns_and_valid_entry_keeps_exact_stdin() {
	let temp = tempfile::tempdir().unwrap();
	let effect = temp.path().join("effect");
	let mut denied = Command::new("python3");
	denied
		.arg("-c")
		.arg("import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('effect')")
		.arg(&effect);
	let result = capture_prepared(
		denied,
		"fixture",
		b"",
		Duration::from_secs(2),
		|| -> Result<()> { bail!("revoked at final spawn entry") },
	)
	.await;
	assert!(result.is_err());
	assert!(!tokio::fs::try_exists(&effect).await.unwrap());
	let live = Arc::new(AtomicBool::new(false));
	let held = Arc::clone(&live);
	let mut command = Command::new("python3");
	command
		.arg("-c")
		.arg("import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())");
	let output = capture_prepared(
		command,
		"fixture",
		b"original exact input\0bytes",
		Duration::from_secs(2),
		move || {
			held.store(true, Ordering::SeqCst);
			Ok(Guard(held))
		},
	)
	.await
	.unwrap();
	assert!(output.status.success());
	assert_eq!(output.stdout, b"original exact input\0bytes");
	assert!(!live.load(Ordering::SeqCst));
}

#[tokio::test]
async fn timeout_and_caller_cancellation_release_the_same_transport_guard() {
	for cancel in [false, true] {
		let live = Arc::new(AtomicBool::new(false));
		let held = Arc::clone(&live);
		let (entered, entry_seen) = tokio::sync::oneshot::channel();
		let mut command = Command::new("python3");
		command.arg("-c").arg("import time;time.sleep(30)");
		let timeout = if cancel {
			Duration::from_secs(2)
		} else {
			Duration::from_millis(30)
		};
		let task = tokio::spawn(async move {
			capture_prepared(command, "fixture", b"", timeout, move || {
				held.store(true, Ordering::SeqCst);
				let _ = entered.send(());
				Ok(Guard(held))
			})
			.await
		});
		entry_seen.await.unwrap();
		assert!(live.load(Ordering::SeqCst));
		if cancel {
			task.abort();
			assert!(task.await.unwrap_err().is_cancelled());
		} else {
			assert!(task.await.unwrap().is_err());
		}
		assert!(!live.load(Ordering::SeqCst));
	}
}
