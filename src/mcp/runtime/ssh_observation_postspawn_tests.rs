// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::cell::Cell;
use std::future::Future;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::process::Command;
use tokio::sync::{Mutex, Semaphore};

async fn fixture() -> (Arc<OwnedChild>, ProcessIdentity, Arc<Semaphore>) {
	let capacity = Arc::new(Semaphore::new(1));
	let permit = Arc::new(capacity.clone().acquire_owned().await.unwrap());
	let child = Command::new("/usr/bin/cat")
		.stdin(Stdio::piped())
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.kill_on_drop(true)
		.spawn()
		.unwrap();
	let pid = child.id().unwrap();
	let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
	assert!(descriptor >= 0);
	let owned = Arc::new(OwnedChild {
		id: 701,
		pid,
		pidfd: Some(unsafe { OwnedFd::from_raw_fd(descriptor as i32) }),
		identity: OnceLock::new(),
		approved: AtomicBool::new(false),
		child: Mutex::new(child),
		_permits: vec![permit],
	});
	// Only fixture preparation may wait for a real long-lived test executable.
	// The production helper below has no errno retry or generic readiness rule.
	let deadline = Instant::now() + Duration::from_secs(5);
	let identity = loop {
		if let Ok(identity) = process_identity(pid) {
			if identity.argv == b"/usr/bin/cat\0" {
				break identity;
			}
		}
		assert!(Instant::now() < deadline, "fixture identity unavailable");
		tokio::time::sleep(Duration::from_millis(2)).await;
	};
	assert_eq!(identity.uid, unsafe { libc::geteuid() });
	assert_eq!(capacity.available_permits(), 0);
	(owned, identity, capacity)
}

async fn dispose(owned: Arc<OwnedChild>, capacity: Arc<Semaphore>) {
	owned.stop(Duration::ZERO).await.unwrap();
	assert!(owned.terminal().await.unwrap());
	assert_eq!(
		capacity.available_permits(),
		0,
		"reaping alone must not release ownership"
	);
	drop(owned);
	assert_eq!(capacity.available_permits(), 1);
}

fn empty(identity: &ProcessIdentity) -> ProcessIdentity {
	let mut result = identity.clone();
	result.argv.clear();
	result
}

fn await_exited_without_reaping(owned: &OwnedChild) {
	let fd = owned.pidfd.as_ref().unwrap().as_raw_fd();
	let deadline = std::time::Instant::now() + Duration::from_secs(5);
	let mut polling = libc::pollfd {
		fd,
		events: libc::POLLIN,
		revents: 0,
	};
	loop {
		let remaining = deadline.saturating_duration_since(std::time::Instant::now());
		assert!(!remaining.is_zero(), "fixture exit observation deadline");
		let milliseconds = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
		let result = unsafe { libc::poll(&mut polling, 1, milliseconds) };
		if result < 0 {
			assert_eq!(
				std::io::Error::last_os_error().raw_os_error(),
				Some(libc::EINTR)
			);
			continue;
		}
		assert_eq!(result, 1);
		assert_ne!(polling.revents & libc::POLLIN, 0);
		break;
	}
	loop {
		assert!(
			std::time::Instant::now() < deadline,
			"fixture exit observation deadline"
		);
		let mut status = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
		let result = unsafe {
			libc::waitid(
				libc::P_PIDFD,
				fd as libc::id_t,
				status.as_mut_ptr(),
				libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
			)
		};
		if result < 0 {
			assert_eq!(
				std::io::Error::last_os_error().raw_os_error(),
				Some(libc::EINTR)
			);
			continue;
		}
		assert_eq!(result, 0);
		let status = unsafe { status.assume_init() };
		let pid = unsafe { status.si_pid() };
		if pid != 0 {
			assert_eq!(pid as u32, owned.pid);
			assert_eq!(status.si_code, libc::CLD_KILLED);
			assert_eq!(unsafe { status.si_status() }, libc::SIGKILL);
			break;
		}
		std::thread::sleep(
			Duration::from_millis(1)
				.min(deadline.saturating_duration_since(std::time::Instant::now())),
		);
	}
}

fn waiting<'a>(
	owned: &'a OwnedChild,
	anchor: &'a ProcessIdentity,
	expected: &'a ProcessIdentity,
	deadline: Instant,
	cancel: &'a CancellationToken,
	stop: &'a CancellationToken,
) -> Waiting<'a> {
	Waiting {
		owned,
		anchor,
		expected: &expected.argv,
		ssh_inode: (expected.dev, expected.ino),
		deadline,
		cancel,
		stop,
	}
}

#[tokio::test(flavor = "current_thread")]
async fn empty_argv_readiness_requires_exact_match_before_identity_is_stored() {
	let (owned, exact, capacity) = fixture().await;
	let anchor = empty(&exact);
	let cancel = CancellationToken::new();
	let stop = CancellationToken::new();
	let samples = Cell::new(0);
	let ready = waiting(
		&owned,
		&anchor,
		&exact,
		Instant::now() + Duration::from_secs(5),
		&cancel,
		&stop,
	)
	.run_with(|pid| {
		assert_eq!(pid, owned.pid);
		assert!(
			owned.child.try_lock().is_err(),
			"proc sampling must hold the original Child lock"
		);
		assert!(
			owned.identity.get().is_none(),
			"empty snapshots must not fill OnceLock"
		);
		samples.set(samples.get() + 1);
		Ok(if samples.get() == 1 {
			anchor.clone()
		} else {
			exact.clone()
		})
	})
	.await
	.unwrap();
	assert_eq!(samples.get(), 2);
	assert!(!ready.terminal);
	assert_eq!(ready.identity.as_ref(), Some(&exact));
	assert!(!owned.approved.load(Ordering::Acquire));
	assert!(owned.identity.get().is_none());
	owned.identity.set(ready.identity.unwrap()).unwrap();
	assert_eq!(owned.identity.get(), Some(&exact));
	dispose(owned, capacity).await;
}

#[tokio::test(flavor = "current_thread")]
async fn empty_argv_readiness_serializes_reaping_and_never_reads_proc_after_terminal() {
	let (owned, exact, capacity) = fixture().await;
	let anchor = empty(&exact);
	let cancel = CancellationToken::new();
	let stop = CancellationToken::new();
	let probe = waiting(
		&owned,
		&anchor,
		&exact,
		Instant::now() + Duration::from_secs(5),
		&cancel,
		&stop,
	);
	let samples = Cell::new(0);
	let mut child = owned.child.lock().await;
	let mut future = Box::pin(probe.run_with(|_| {
		samples.set(samples.get() + 1);
		panic!("a reaped Child must not be followed through its numeric PID")
	}));
	std::future::poll_fn(|context| {
		assert!(future.as_mut().poll(context).is_pending());
		std::task::Poll::Ready(())
	})
	.await;
	tokio::time::sleep(Duration::from_millis(3)).await;
	std::future::poll_fn(|context| {
		assert!(future.as_mut().poll(context).is_pending());
		std::task::Poll::Ready(())
	})
	.await;
	assert_eq!(samples.get(), 0);
	drop(child.stdin.take());
	assert!(
		timeout_at(Instant::now() + Duration::from_secs(5), child.wait())
			.await
			.unwrap()
			.unwrap()
			.success()
	);
	drop(child);
	let ready = future.await.unwrap();
	assert!(ready.terminal);
	assert!(ready.identity.is_none());
	assert_eq!(samples.get(), 0);
	assert!(owned.identity.get().is_none());
	assert!(!owned.approved.load(Ordering::Acquire));
	dispose(owned, capacity).await;
}

#[tokio::test(flavor = "current_thread")]
async fn empty_argv_readiness_rejects_every_identity_contradiction_without_another_sample() {
	let (owned, exact, capacity) = fixture().await;
	let anchor = empty(&exact);
	let cancel = CancellationToken::new();
	let stop = CancellationToken::new();
	for field in ["birth", "uid", "dev", "ino", "argv"] {
		let samples = Cell::new(0);
		let mut wrong = exact.clone();
		match field {
			"birth" => wrong.birth ^= 1,
			"uid" => wrong.uid ^= 1,
			"dev" => wrong.dev ^= 1,
			"ino" => wrong.ino ^= 1,
			_ => wrong.argv = b"unexpected-nonempty-argv\0".to_vec(),
		}
		let result = waiting(
			&owned,
			&anchor,
			&exact,
			Instant::now() + Duration::from_secs(5),
			&cancel,
			&stop,
		)
		.run_with(|_| {
			samples.set(samples.get() + 1);
			Ok(if samples.get() == 1 {
				wrong.clone()
			} else {
				exact.clone()
			})
		})
		.await;
		assert!(result.is_err(), "{field}");
		assert_eq!(
			samples.get(),
			1,
			"{field} must not be washed away by a later match"
		);
		assert!(owned.identity.get().is_none());
	}
	dispose(owned, capacity).await;
}

#[tokio::test(flavor = "current_thread")]
async fn empty_argv_readiness_does_not_retry_any_proc_errno() {
	let (owned, exact, capacity) = fixture().await;
	let anchor = empty(&exact);
	let cancel = CancellationToken::new();
	let stop = CancellationToken::new();
	for errno in [
		libc::ENOENT,
		libc::ESRCH,
		libc::EACCES,
		libc::EPERM,
		libc::EINTR,
		libc::EIO,
	] {
		let samples = Cell::new(0);
		let result = waiting(
			&owned,
			&anchor,
			&exact,
			Instant::now() + Duration::from_secs(5),
			&cancel,
			&stop,
		)
		.run_with(|_| {
			samples.set(samples.get() + 1);
			Err(std::io::Error::from_raw_os_error(errno).into())
		})
		.await;
		assert_eq!(
			result
				.err()
				.unwrap()
				.downcast_ref::<std::io::Error>()
				.unwrap()
				.raw_os_error(),
			Some(errno)
		);
		assert_eq!(samples.get(), 1);
	}
	dispose(owned, capacity).await;
}

#[tokio::test(flavor = "current_thread")]
async fn empty_argv_readiness_checks_cancellation_after_an_otherwise_matching_observation() {
	let (owned, exact, capacity) = fixture().await;
	let anchor = empty(&exact);
	for pool_stop in [false, true] {
		let cancel = CancellationToken::new();
		let stop = CancellationToken::new();
		let samples = Cell::new(0);
		let result = waiting(
			&owned,
			&anchor,
			&exact,
			Instant::now() + Duration::from_secs(5),
			&cancel,
			&stop,
		)
		.run_with(|_| {
			samples.set(samples.get() + 1);
			if pool_stop {
				stop.cancel();
			} else {
				cancel.cancel();
			}
			Ok(exact.clone())
		})
		.await;
		assert!(result.is_err());
		assert_eq!(samples.get(), 1);
		assert!(owned.identity.get().is_none());
		assert!(!owned.approved.load(Ordering::Acquire));
	}
	dispose(owned, capacity).await;
}

#[tokio::test(flavor = "current_thread")]
async fn empty_argv_readiness_respects_original_deadline_and_retains_capacity_until_reap() {
	let (owned, exact, capacity) = fixture().await;
	let anchor = empty(&exact);
	let cancel = CancellationToken::new();
	let stop = CancellationToken::new();
	let expired = waiting(&owned, &anchor, &exact, Instant::now(), &cancel, &stop)
		.run_with(|_| panic!("expired readiness cannot read a process"))
		.await;
	assert!(expired.is_err());
	let deadline = Instant::now() + Duration::from_millis(30);
	let unresolved = waiting(&owned, &anchor, &exact, deadline, &cancel, &stop)
		.run_with(|_| Ok(anchor.clone()))
		.await;
	assert!(unresolved.is_err());
	assert!(Instant::now() >= deadline);
	assert!(!owned.terminal().await.unwrap());
	assert_eq!(capacity.available_permits(), 0);
	assert!(owned.identity.get().is_none());
	dispose(owned, capacity).await;
}

#[tokio::test(flavor = "current_thread")]
async fn empty_argv_readiness_requires_original_pidfd_and_exact_entry_identity() {
	let (mut owned, exact, capacity) = fixture().await;
	let cancel = CancellationToken::new();
	let stop = CancellationToken::new();
	for field in ["uid", "ino", "argv"] {
		let mut anchor = empty(&exact);
		match field {
			"uid" => anchor.uid ^= 1,
			"ino" => anchor.ino ^= 1,
			_ => anchor.argv = b"not-empty\0".to_vec(),
		}
		let result = waiting(
			&owned,
			&anchor,
			&exact,
			Instant::now() + Duration::from_secs(5),
			&cancel,
			&stop,
		)
		.run_with(|_| panic!("incorrect entry must not start polling"))
		.await;
		assert!(result.is_err());
	}
	let pidfd = Arc::get_mut(&mut owned).unwrap().pidfd.take();
	let anchor = empty(&exact);
	let result = waiting(
		&owned,
		&anchor,
		&exact,
		Instant::now() + Duration::from_secs(5),
		&cancel,
		&stop,
	)
	.run_with(|_| panic!("missing original pidfd must not start polling"))
	.await;
	assert!(result.is_err());
	Arc::get_mut(&mut owned).unwrap().pidfd = pidfd;
	dispose(owned, capacity).await;
}

#[tokio::test(flavor = "current_thread")]
async fn empty_argv_readiness_does_not_accept_a_late_matching_observation() {
	let (owned, exact, capacity) = fixture().await;
	let anchor = empty(&exact);
	let cancel = CancellationToken::new();
	let stop = CancellationToken::new();
	let deadline = Instant::now() + Duration::from_millis(300);
	let observed = Cell::new(false);
	let result = waiting(&owned, &anchor, &exact, deadline, &cancel, &stop)
		.run_with(|_| {
			observed.set(true);
			// Model the owner returning from a synchronous proc read after its
			// original deadline. The post-observation fence must still refuse.
			std::thread::sleep(
				deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(2),
			);
			Ok(exact.clone())
		})
		.await;
	assert!(observed.get());
	assert!(result.is_err());
	assert!(owned.identity.get().is_none());
	assert!(!owned.approved.load(Ordering::Acquire));
	dispose(owned, capacity).await;
}

#[tokio::test(flavor = "current_thread")]
async fn empty_argv_readiness_rejects_a_mismatch_even_when_the_same_child_exits() {
	let (owned, exact, capacity) = fixture().await;
	let anchor = empty(&exact);
	let cancel = CancellationToken::new();
	let stop = CancellationToken::new();
	let mut wrong = exact.clone();
	wrong.argv = b"wrong-nonempty-argv\0".to_vec();
	let result = waiting(
		&owned,
		&anchor,
		&exact,
		Instant::now() + Duration::from_secs(10),
		&cancel,
		&stop,
	)
	.run_with(|_| {
		let fd = owned.pidfd.as_ref().unwrap().as_raw_fd();
		assert_eq!(
			unsafe {
				libc::syscall(
					libc::SYS_pidfd_send_signal,
					fd,
					libc::SIGKILL,
					std::ptr::null::<libc::siginfo_t>(),
					0,
				)
			},
			0
		);
		// Same pidfd, same lock, WNOWAIT: confirm exit without another reaper.
		await_exited_without_reaping(&owned);
		Ok(wrong.clone())
	})
	.await;
	assert!(
		result.is_err(),
		"terminal must not erase an observed identity mismatch"
	);
	assert!(owned.terminal().await.unwrap());
	assert!(owned.identity.get().is_none());
	assert!(!owned.approved.load(Ordering::Acquire));
	dispose(owned, capacity).await;
}
