// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Real subprocess regressions for stderr deadlines and private-owner drainage.

use super::*;
use serde_json::json;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::time::Duration;

const OPERATION: &str = "inspect_elf_notes";

fn child_with_retained_stderr(script: &str) -> (tokio::process::Child, UnixStream) {
	let (reader, writer) = UnixStream::pair().unwrap();
	let mut child = tokio::process::Command::new("/bin/sh")
		.arg("-c")
		.arg(script)
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::from(OwnedFd::from(writer.try_clone().unwrap())))
		.kill_on_drop(true)
		.spawn()
		.unwrap();
	// Keep a second write descriptor independently of the supervised child. No
	// unrelated process is launched or signalled to exercise an inherited pipe.
	child.stderr = Some(
		tokio::process::ChildStderr::from_std(std::process::ChildStderr::from(OwnedFd::from(
			reader,
		)))
		.unwrap(),
	);
	(child, writer)
}

fn spec(deadline_ms: u64) -> WorkerSpec {
	WorkerSpec {
		operation: OPERATION,
		reply_limit: 1024,
		deadline_ms,
	}
}

fn assert_reaped(pid: u32) {
	let mut status = 0;
	assert_eq!(
		unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) },
		-1,
		"the sole owner must reap its child before releasing capacity"
	);
	assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
}

#[cfg(target_os = "linux")]
async fn observe_reaped(pid: u32) {
	// Observation must not waitpid: the supervisor remains the only reaping owner.
	tokio::time::timeout(Duration::from_secs(2), async move {
		while tokio::fs::try_exists(format!("/proc/{pid}")).await.unwrap() {
			tokio::time::sleep(Duration::from_millis(5)).await;
		}
	})
	.await
	.unwrap();
}

#[tokio::test]
async fn worker_stderr_open_writer_cannot_escape_the_provider_deadline() {
	let (child, keeper) = child_with_retained_stderr(
		"/bin/cat >/dev/null; printf 'retained diagnostics' >&2; printf '{\"report\":{}}'",
	);
	let pid = child.id().unwrap();
	let result = tokio::time::timeout(
		Duration::from_secs(2),
		supervise_child(
			child,
			b"{}".to_vec(),
			Arc::new(vec![]),
			CancellationToken::new(),
			spec(50),
		),
	)
	.await;
	// Release the fixture even on the red baseline; never strand a test writer.
	drop(keeper);
	let failure = result.expect("stderr escaped the worker deadline").unwrap_err();
	assert_eq!(failure.0["code"], "provider_timeout");
	assert_eq!(failure.0["details"]["worker_stderr"], "retained diagnostics");
	assert!(failure.0["details"]["worker_stderr_error"]
		.as_str()
		.unwrap()
		.contains("cancelled"));
	assert_reaped(pid);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn worker_stderr_cancellation_still_applies_after_child_exit() {
	let (child, keeper) =
		child_with_retained_stderr("/bin/cat >/dev/null; printf '{\"report\":{}}'");
	let pid = child.id().unwrap();
	let cancellation = CancellationToken::new();
	let token = cancellation.clone();
	let owner = tokio::spawn(supervise_child(
		child,
		b"{}".to_vec(),
		Arc::new(vec![]),
		token,
		spec(30000),
	));
	observe_reaped(pid).await;
	cancellation.cancel();
	let result = tokio::time::timeout(Duration::from_secs(2), owner).await;
	drop(keeper);
	let failure = result
		.expect("stderr ignored cancellation after the child exited")
		.unwrap()
		.unwrap_err();
	assert_eq!(failure.0["code"], "cancelled");
	assert_reaped(pid);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn worker_stderr_request_abort_drains_owner_and_restores_capacity() {
	let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
	let lease = semaphore.clone().acquire_owned().await.unwrap();
	let (child, keeper) =
		child_with_retained_stderr("/bin/cat >/dev/null; printf '{\"report\":{}}'");
	let pid = child.id().unwrap();
	let request = tokio::spawn(async move {
		await_owned(
			lease,
			&CancellationToken::new(),
			OPERATION,
			move |token| supervise_child(child, b"{}".to_vec(), Arc::new(vec![]), token, spec(30000)),
		)
		.await
	});
	observe_reaped(pid).await;
	assert_eq!(semaphore.available_permits(), 0);
	request.abort();
	assert!(request.await.unwrap_err().is_cancelled());
	let capacity = tokio::time::timeout(Duration::from_secs(2), semaphore.clone().acquire_owned())
		.await;
	drop(keeper);
	let lease = capacity.expect("cancelled owner retained its worker slot").unwrap();
	assert_reaped(pid);
	let (child, keeper) =
		child_with_retained_stderr("/bin/cat >/dev/null; printf '{\"report\":{\"reused\":true}}'");
	drop(keeper);
	let result = await_owned(
		lease,
		&CancellationToken::new(),
		OPERATION,
		move |token| supervise_child(child, b"{}".to_vec(), Arc::new(vec![]), token, spec(5000)),
	)
	.await;
	assert_eq!(result.unwrap(), json!({"report":{"reused":true}}));
	assert_eq!(semaphore.available_permits(), 1);
}

#[tokio::test]
async fn worker_stderr_overflow_terminates_before_the_provider_deadline() {
	let (child, keeper) = child_with_retained_stderr(
		"i=0; while [ \"$i\" -lt 4096 ]; do printf '0123456789abcdef' >&2; i=$((i+1)); done; printf x >&2; exec /bin/sleep 30",
	);
	let pid = child.id().unwrap();
	drop(keeper);
	let result = tokio::time::timeout(
		Duration::from_secs(2),
		supervise_child(
			child,
			b"{}".to_vec(),
			Arc::new(vec![]),
			CancellationToken::new(),
			spec(20000),
		),
	)
	.await;
	let failure = result.expect("stderr overflow waited for the provider deadline").unwrap_err();
	assert_eq!(failure.0["code"], "unreadable_output");
	assert!(failure.0["details"]["reason"]
		.as_str()
		.unwrap()
		.contains("stderr exceeds its allowance"));
	assert!(failure.0["details"]["worker_stderr"]
		.as_str()
		.unwrap()
		.len() <= 64 * 1024);
	assert_reaped(pid);
}
