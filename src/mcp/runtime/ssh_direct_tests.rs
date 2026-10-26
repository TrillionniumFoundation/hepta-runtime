// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Original-child admission, cancellation and shutdown regressions; no SSH server.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Condvar;
use tokio::task::JoinHandle;

#[derive(Default)]
pub(super) struct Hooks {
	pub spawned: AtomicU64,
	pub after_commit: Mutex<Option<Arc<Gate>>>,
	pub panic_after_registration: AtomicBool,
	pub child: Mutex<Option<ChildHooks>>,
}

#[derive(Default)]
pub(super) struct ChildHooks {
	pub before_reap: Mutex<Option<Arc<Gate>>>,
	pub unconfirmed_wait: bool,
}

#[derive(Default)]
pub(super) struct Gate {
	reached: AtomicBool,
	released: Mutex<bool>,
	changed: Condvar,
}
impl Gate {
	pub fn block(&self) {
		self.reached.store(true, Ordering::Release);
		let mut released = self.released.lock().unwrap();
		while !*released {
			released = self.changed.wait(released).unwrap();
		}
	}
	fn release(&self) {
		*self.released.lock().unwrap() = true;
		self.changed.notify_all();
	}
}
struct ReleaseGate(Arc<Gate>);
impl Drop for ReleaseGate {
	fn drop(&mut self) {
		self.0.release();
	}
}

struct Owner(Arc<Proxy>);
impl Owner {
	fn new() -> Self {
		Self(Proxy::start().unwrap())
	}
	async fn finish(&self) {
		tokio::time::timeout(Duration::from_secs(5), self.0.shutdown())
			.await
			.unwrap()
			.unwrap();
		assert!(self.0.core.children.lock().unwrap().is_empty());
		assert_eq!(self.0.global.available_permits(), GLOBAL_CONNECTIONS);
		assert_eq!(self.0.admission.available_permits(), MAX_ADMITTED);
	}
}
impl Drop for Owner {
	fn drop(&mut self) {
		self.0.core.freeze();
		// Panic cleanup also owns and joins this test's original owner thread.
		let thread = { self.0.join.state.lock().unwrap().thread.take() };
		if let Some(thread) = thread {
			let result = thread
				.join()
				.map_err(|_| "test owner thread panicked".to_owned())
				.and_then(|value| value.map_err(|error| format!("{error:#}")));
			let mut state = self.0.join.state.lock().unwrap();
			state.started = true;
			state.finished = Some(result);
			self.0.join.done.notify_waiters();
		}
	}
}

struct Fixture(tempfile::TempDir);
impl Fixture {
	fn new() -> Self {
		let directory = tempfile::tempdir().unwrap();
		std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
		Self(directory)
	}
	fn ready(&self, slot: usize) -> PathBuf {
		self.0.path().join(format!("ready-{slot}"))
	}
	fn release(&self, slot: usize) {
		std::fs::write(self.0.path().join(format!("release-{slot}")), b"release\n").unwrap();
	}
	fn command(&self, slot: usize) -> Command {
		let mut command = Command::new("python3");
		command
			.args([
				"-I",
				"-S",
				"-c",
				r#"
import fcntl, os, pathlib, sys, time
root = pathlib.Path(sys.argv[1]); slot = sys.argv[2]
def event(kind):
    fd = os.open(root / 'events', os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, ('%s %s %d\n' % (kind, slot, os.getpid())).encode())
    finally:
        os.close(fd)
event('start')
fd = os.open(root / ('ready-' + slot), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(fd, str(os.getpid()).encode()); os.close(fd)
until = time.monotonic() + 8
while not (root / ('release-' + slot)).exists():
    if time.monotonic() >= until:
        raise RuntimeError('test release not received')
    time.sleep(.002)
value = sys.stdin.buffer.read()
sys.stdout.buffer.write(value); sys.stdout.buffer.flush()
sys.stderr.write('stderr-' + slot + '\n'); sys.stderr.flush()
event('end')
"#,
			])
			.arg(self.0.path())
			.arg(slot.to_string());
		pipes(&mut command);
		command
	}
	fn event_peak(&self) -> usize {
		let raw = std::fs::read_to_string(self.0.path().join("events")).unwrap();
		let mut active = 0usize;
		let mut peak = 0;
		for line in raw.lines() {
			match line.split_whitespace().next().unwrap() {
				"start" => {
					active += 1;
					peak = peak.max(active);
				}
				"end" => {
					active = active.checked_sub(1).unwrap();
				}
				other => panic!("unexpected event {other}"),
			}
		}
		assert_eq!(active, 0);
		peak
	}
}

fn pipes(command: &mut Command) {
	command
		.stdin(Stdio::piped())
		.stdout(Stdio::piped())
		.stderr(Stdio::piped())
		.kill_on_drop(true);
}

async fn until(mut ready: impl FnMut() -> bool) {
	tokio::time::timeout(Duration::from_secs(5), async {
		while !ready() {
			tokio::time::sleep(Duration::from_millis(1)).await;
		}
	})
	.await
	.unwrap();
}

fn submit(
	owner: &Owner,
	fixture: &Fixture,
	target: &str,
	slot: usize,
) -> JoinHandle<Result<Output>> {
	let owner = owner.0.clone();
	let command = fixture.command(slot);
	let target = target.to_owned();
	tokio::spawn(async move {
		owner
			.capture(
				&target,
				command,
				format!("input-{slot}").as_bytes(),
				Instant::now() + Duration::from_secs(10),
			)
			.await
	})
}

async fn finish_call(task: JoinHandle<Result<Output>>, slot: usize) {
	let output = tokio::time::timeout(Duration::from_secs(5), task)
		.await
		.unwrap()
		.unwrap()
		.unwrap();
	assert!(output.status.success());
	assert_eq!(output.stdout, format!("input-{slot}").as_bytes());
	assert_eq!(output.stderr, format!("stderr-{slot}\n").as_bytes());
}

async fn reply(receive: oneshot::Receiver<Result<Output>>) -> Result<Output> {
	tokio::time::timeout(Duration::from_secs(5), receive)
		.await
		.unwrap()
		.unwrap()
}

async fn idle(owner: &Owner) {
	until(|| {
		owner.0.admission.available_permits() == MAX_ADMITTED
			&& owner.0.global.available_permits() == GLOBAL_CONNECTIONS
	})
	.await;
	assert!(owner.0.core.children.lock().unwrap().is_empty());
}

#[tokio::test]
async fn sixteen_pending_calls_share_two_original_children_and_next_batch_has_all_capacity() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let tasks: Vec<_> = (0..16)
		.map(|slot| submit(&owner, &fixture, "same-target", slot))
		.collect();
	until(|| {
		(0..16).filter(|slot| fixture.ready(*slot).exists()).count() == 2
			&& owner.0.admission.available_permits() == 0
	})
	.await;
	assert_eq!(owner.0.global.available_permits(), 6);
	assert_eq!(owner.0.core.children.lock().unwrap().len(), 2);
	for slot in 0..16 {
		fixture.release(slot);
	}
	for (slot, task) in tasks.into_iter().enumerate() {
		finish_call(task, slot).await;
	}
	// Every reply is visible only after admitted, host and global capacity returns.
	assert_eq!(owner.0.admission.available_permits(), 16);
	assert_eq!(owner.0.global.available_permits(), 8);
	for slot in 16..32 {
		fixture.release(slot);
	}
	let next: Vec<_> = (16..32)
		.map(|slot| submit(&owner, &fixture, "same-target", slot))
		.collect();
	for (offset, task) in next.into_iter().enumerate() {
		finish_call(task, offset + 16).await;
	}
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 32);
	assert!(fixture.event_peak() <= HOST_CONNECTIONS);
	owner.finish().await;
}

#[tokio::test]
async fn seventeenth_request_is_rejected_before_new_target_or_payload_retention() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let tasks: Vec<_> = (0..16)
		.map(|slot| submit(&owner, &fixture, "full", slot))
		.collect();
	until(|| owner.0.admission.available_permits() == 0).await;
	let error = owner
		.0
		.capture(
			"never-registered",
			fixture.command(99),
			b"not-submitted",
			Instant::now() + Duration::from_secs(5),
		)
		.await
		.unwrap_err();
	assert!(error.to_string().contains("admitted capacity exhausted"));
	assert!(!fixture.ready(99).exists());
	assert!(!owner
		.0
		.hosts
		.lock()
		.unwrap()
		.contains_key("never-registered"));
	for slot in 0..16 {
		fixture.release(slot);
	}
	for (slot, task) in tasks.into_iter().enumerate() {
		finish_call(task, slot).await;
	}
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 16);
	owner.finish().await;
}

#[tokio::test]
async fn same_target_queue_does_not_take_global_capacity_from_another_target() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let held: Vec<_> = (0..10)
		.map(|slot| submit(&owner, &fixture, "held", slot))
		.collect();
	until(|| (0..10).filter(|slot| fixture.ready(*slot).exists()).count() == 2).await;
	fixture.release(20);
	finish_call(submit(&owner, &fixture, "other", 20), 20).await;
	assert_eq!(
		(0..10).filter(|slot| fixture.ready(*slot).exists()).count(),
		2
	);
	for slot in 0..10 {
		fixture.release(slot);
	}
	for (slot, task) in held.into_iter().enumerate() {
		finish_call(task, slot).await;
	}
	owner.finish().await;
}

#[tokio::test]
async fn global_eight_limit_and_cancelled_global_waiter_keep_original_capacity() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let held: Vec<_> = (0..8)
		.map(|slot| submit(&owner, &fixture, &format!("target-{}", slot / 2), slot))
		.collect();
	until(|| (0..8).all(|slot| fixture.ready(slot).exists())).await;
	assert_eq!(owner.0.global.available_permits(), 0);
	let waiting = submit(&owner, &fixture, "ninth-target", 9);
	until(|| owner.0.admission.available_permits() == 7).await;
	assert!(!fixture.ready(9).exists());
	waiting.abort();
	assert!(waiting.await.unwrap_err().is_cancelled());
	assert_eq!(owner.0.admission.available_permits(), 8);
	assert_eq!(
		owner.0.target("ninth-target").unwrap().available_permits(),
		2
	);
	assert_eq!(owner.0.core.children.lock().unwrap().len(), 8);
	for slot in 0..8 {
		fixture.release(slot);
	}
	for (slot, task) in held.into_iter().enumerate() {
		finish_call(task, slot).await;
	}
	assert!(!fixture.ready(9).exists());
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 8);
	owner.finish().await;
}

#[tokio::test]
async fn cancelled_host_waiter_never_submits_after_original_slots_return() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let first = submit(&owner, &fixture, "host", 0);
	let second = submit(&owner, &fixture, "host", 1);
	until(|| fixture.ready(0).exists() && fixture.ready(1).exists()).await;
	let waiting = submit(&owner, &fixture, "host", 2);
	until(|| owner.0.admission.available_permits() == 13).await;
	waiting.abort();
	assert!(waiting.await.unwrap_err().is_cancelled());
	fixture.release(0);
	fixture.release(1);
	finish_call(first, 0).await;
	finish_call(second, 1).await;
	assert!(!fixture.ready(2).exists());
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 2);
	owner.finish().await;
}

#[tokio::test]
async fn host_wait_counts_against_the_original_deadline_and_cannot_start_late() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let first = submit(&owner, &fixture, "host", 0);
	let second = submit(&owner, &fixture, "host", 1);
	until(|| fixture.ready(0).exists() && fixture.ready(1).exists()).await;
	let error = owner
		.0
		.capture(
			"host",
			fixture.command(2),
			b"expired",
			Instant::now() + Duration::from_millis(30),
		)
		.await
		.unwrap_err();
	assert!(error.to_string().contains("host admission deadline"));
	fixture.release(0);
	fixture.release(1);
	finish_call(first, 0).await;
	finish_call(second, 1).await;
	assert!(!fixture.ready(2).exists());
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 2);
	owner.finish().await;
}

async fn queued_request(
	owner: &Owner,
	fixture: &Fixture,
	slot: usize,
	deadline: Instant,
) -> (
	Request,
	Arc<Cancellation>,
	oneshot::Receiver<Result<Output>>,
) {
	let cancel = Cancellation::new();
	let leases = owner
		.0
		.acquire("host", Instant::now() + Duration::from_secs(5))
		.await
		.unwrap();
	let (reply, receive) = oneshot::channel();
	(
		Request {
			target: "host".into(),
			command: fixture.command(slot),
			input: vec![],
			deadline,
			cancel: cancel.clone(),
			reply,
			leases: Some(leases),
		},
		cancel,
		receive,
	)
}

#[tokio::test]
async fn queued_cancel_and_expired_deadline_are_refused_at_the_submission_boundary() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let (request, cancel, receive) =
		queued_request(&owner, &fixture, 0, Instant::now() + Duration::from_secs(5)).await;
	cancel.cancel();
	assert!(owner.0.sender.try_send(request).is_ok());
	assert!(reply(receive).await.is_err());
	let (request, _, receive) = queued_request(
		&owner,
		&fixture,
		1,
		Instant::now() - Duration::from_millis(1),
	)
	.await;
	assert!(owner.0.sender.try_send(request).is_ok());
	assert!(reply(receive).await.is_err());
	assert!(!fixture.ready(0).exists() && !fixture.ready(1).exists());
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 0);
	idle(&owner).await;
	owner.finish().await;
}

#[tokio::test]
async fn cancellation_that_wins_before_commit_prevents_the_original_spawn() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let (request, cancel, receive) =
		queued_request(&owner, &fixture, 0, Instant::now() + Duration::from_secs(5)).await;
	{
		let _gate = owner.0.core.accepting.lock().unwrap();
		assert!(owner.0.sender.try_send(request).is_ok());
		cancel.cancel();
		assert_eq!(cancel.phase.load(Ordering::Acquire), CANCELLED);
	}
	assert!(reply(receive).await.is_err());
	assert!(!fixture.ready(0).exists());
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 0);
	owner.finish().await;
}

#[tokio::test]
async fn committed_then_cancelled_attempt_keeps_all_permits_through_actual_reap() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let gate = Arc::new(Gate::default());
	let _release = ReleaseGate(gate.clone());
	*owner.0.core.hooks.after_commit.lock().unwrap() = Some(gate.clone());
	let (request, cancel, receive) =
		queued_request(&owner, &fixture, 0, Instant::now() + Duration::from_secs(5)).await;
	assert!(owner.0.sender.try_send(request).is_ok());
	until(|| gate.reached.load(Ordering::Acquire)).await;
	assert_eq!(cancel.phase.load(Ordering::Acquire), COMMITTED);
	cancel.cancel();
	assert_eq!(cancel.phase.load(Ordering::Acquire), COMMITTED);
	assert_eq!(owner.0.admission.available_permits(), 15);
	assert_eq!(owner.0.global.available_permits(), 7);
	assert_eq!(owner.0.target("host").unwrap().available_permits(), 1);
	gate.release();
	assert!(reply(receive).await.is_err());
	idle(&owner).await;
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 1);
	owner.finish().await;
}

#[tokio::test]
async fn running_caller_cancellation_cannot_return_permits_before_original_reap() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let gate = Arc::new(Gate::default());
	let _release = ReleaseGate(gate.clone());
	*owner.0.core.hooks.child.lock().unwrap() = Some(ChildHooks {
		before_reap: Mutex::new(Some(gate.clone())),
		unconfirmed_wait: false,
	});
	let call = submit(&owner, &fixture, "host", 0);
	until(|| fixture.ready(0).exists()).await;
	call.abort();
	assert!(call.await.unwrap_err().is_cancelled());
	until(|| gate.reached.load(Ordering::Acquire)).await;
	assert_eq!(owner.0.global.available_permits(), 7);
	assert_eq!(owner.0.admission.available_permits(), 15);
	assert_eq!(owner.0.target("host").unwrap().available_permits(), 1);
	gate.release();
	idle(&owner).await;
	owner.finish().await;
}

#[tokio::test]
async fn running_deadline_keeps_original_child_cleanup_outside_the_expired_caller() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let command = fixture.command(0);
	let capture = owner.0.capture(
		"host",
		command,
		b"input",
		Instant::now() + Duration::from_millis(250),
	);
	let error = capture.await.unwrap_err();
	assert!(format!("{error:#}").contains("deadline"));
	idle(&owner).await;
	owner.finish().await;
}

#[tokio::test]
async fn spawn_and_pipe_preparation_errors_never_leave_an_unowned_original_child() {
	let owner = Owner::new();
	let mut command = Command::new("/hepta-test-missing-ssh-executable");
	pipes(&mut command);
	assert!(owner
		.0
		.capture(
			"host",
			command,
			b"",
			Instant::now() + Duration::from_secs(5)
		)
		.await
		.is_err());
	let fixture = Fixture::new();
	let mut command = fixture.command(0);
	command.stdout(Stdio::null());
	assert!(owner
		.0
		.capture(
			"host",
			command,
			b"",
			Instant::now() + Duration::from_secs(5)
		)
		.await
		.unwrap_err()
		.to_string()
		.contains("missing SSH stdout"));
	idle(&owner).await;
	owner.finish().await;
}

#[tokio::test]
async fn response_capture_limit_error_reaps_the_original_child_before_capacity_returns() {
	let owner = Owner::new();
	let mut command = Command::new("python3");
	command.args(["-I", "-S", "-c", "import sys,time;sys.stdout.buffer.write(b'x'*(8*1024*1024+1));sys.stdout.flush();time.sleep(5)"]);
	pipes(&mut command);
	let error = owner
		.0
		.capture(
			"host",
			command,
			b"",
			Instant::now() + Duration::from_secs(5),
		)
		.await
		.unwrap_err();
	assert!(format!("{error:#}").contains("8 MiB"));
	assert_eq!(owner.0.global.available_permits(), 8);
	assert_eq!(owner.0.admission.available_permits(), 16);
	owner.finish().await;
}

#[tokio::test]
async fn original_nonzero_exit_and_both_streams_are_preserved_without_retry() {
	let owner = Owner::new();
	let mut command = Command::new("python3");
	command.args([
		"-I",
		"-S",
		"-c",
		"import sys;sys.stdout.write('out');sys.stderr.write('err');sys.exit(7)",
	]);
	pipes(&mut command);
	let output = owner
		.0
		.capture(
			"host",
			command,
			b"",
			Instant::now() + Duration::from_secs(5),
		)
		.await
		.unwrap();
	assert_eq!(output.status.code(), Some(7));
	assert_eq!(output.stdout, b"out");
	assert_eq!(output.stderr, b"err");
	assert_eq!(owner.0.core.sequence.load(Ordering::Relaxed), 2);
	owner.finish().await;
}

#[tokio::test]
async fn owner_unwind_reaps_registered_child_and_failed_shutdown_is_persistent() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	owner
		.0
		.core
		.hooks
		.panic_after_registration
		.store(true, Ordering::Release);
	assert!(owner
		.0
		.capture(
			"host",
			fixture.command(0),
			b"",
			Instant::now() + Duration::from_secs(5)
		)
		.await
		.is_err());
	assert!(owner.0.shutdown().await.is_err());
	assert!(owner.0.shutdown().await.is_err());
	assert!(owner.0.core.children.lock().unwrap().is_empty());
	assert_eq!(owner.0.global.available_permits(), 8);
	assert_eq!(owner.0.admission.available_permits(), 16);
}

#[tokio::test]
async fn cancelled_shutdown_waiter_cannot_replace_pending_join_with_success() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let gate = Arc::new(Gate::default());
	let _release = ReleaseGate(gate.clone());
	*owner.0.core.hooks.child.lock().unwrap() = Some(ChildHooks {
		before_reap: Mutex::new(Some(gate.clone())),
		unconfirmed_wait: false,
	});
	let call = submit(&owner, &fixture, "host", 0);
	until(|| fixture.ready(0).exists()).await;
	let proxy = owner.0.clone();
	let first = tokio::spawn(async move { proxy.shutdown().await });
	until(|| gate.reached.load(Ordering::Acquire) && owner.0.join.state.lock().unwrap().started)
		.await;
	first.abort();
	assert!(first.await.unwrap_err().is_cancelled());
	let second = owner.0.shutdown();
	tokio::pin!(second);
	std::future::poll_fn(|context| {
		assert!(std::future::Future::poll(second.as_mut(), context).is_pending());
		std::task::Poll::Ready(())
	})
	.await;
	assert!(owner.0.join.state.lock().unwrap().finished.is_none());
	gate.release();
	second.await.unwrap();
	assert!(call.await.unwrap().is_err());
	assert!(matches!(
		owner.0.join.state.lock().unwrap().finished.as_ref(),
		Some(Ok(()))
	));
	owner.finish().await;
}

#[tokio::test]
async fn unconfirmed_wait_quarantines_original_capacity_and_never_reports_shutdown_success() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	fixture.release(0);
	*owner.0.core.hooks.child.lock().unwrap() = Some(ChildHooks {
		before_reap: Mutex::new(None),
		unconfirmed_wait: true,
	});
	assert!(owner
		.0
		.capture(
			"host",
			fixture.command(0),
			b"",
			Instant::now() + Duration::from_secs(5)
		)
		.await
		.is_err());
	assert!(owner.0.shutdown().await.is_err());
	assert!(owner.0.shutdown().await.is_err());
	assert_eq!(owner.0.core.children.lock().unwrap().len(), 1);
	assert_eq!(owner.0.global.available_permits(), 7);
	assert_eq!(owner.0.admission.available_permits(), 15);
	assert_eq!(owner.0.target("host").unwrap().available_permits(), 1);
	assert!(owner
		.0
		.capture(
			"host",
			fixture.command(1),
			b"",
			Instant::now() + Duration::from_secs(1)
		)
		.await
		.is_err());
	assert!(!fixture.ready(1).exists());
	// The injected fault hid a real successful wait from the owner state. Use
	// that original Child's cached status only to leave the test itself clean;
	// admission remains frozen and the persisted shutdown outcome stays failed.
	let original = owner
		.0
		.core
		.children
		.lock()
		.unwrap()
		.values()
		.next()
		.unwrap()
		.clone();
	original.state.lock().await.wait_failed = false;
	original.stop_and_reap().await.unwrap();
	owner.0.core.release(&original).await.unwrap();
	drop(original);
	assert!(owner.0.shutdown().await.is_err());
	assert_eq!(owner.0.global.available_permits(), 8);
}

#[test]
fn caller_runtime_shutdown_does_not_retire_the_original_child_owner() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	let call = {
		let _entered = runtime.enter();
		submit(&owner, &fixture, "host", 0)
	};
	runtime.block_on(until(|| fixture.ready(0).exists()));
	drop(runtime);
	drop(call);
	let joining = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	joining.block_on(async {
		idle(&owner).await;
		owner.finish().await;
	});
}

#[tokio::test]
async fn weak_target_entries_are_reclaimed_but_live_permits_keep_the_exact_target() {
	let owner = Owner::new();
	let original = owner.0.target("held").unwrap();
	let weak = Arc::downgrade(&original);
	let permit = original.acquire_owned().await.unwrap();
	let same = owner.0.target("held").unwrap();
	assert!(Arc::ptr_eq(&same, &weak.upgrade().unwrap()));
	assert_eq!(same.available_permits(), 1);
	drop(same);
	for index in 0..1000 {
		drop(owner.0.target(&format!("temporary-{index}")).unwrap());
	}
	assert_eq!(owner.0.hosts.lock().unwrap().len(), 2);
	assert!(weak.upgrade().is_some());
	drop(permit);
	drop(owner.0.target("last").unwrap());
	assert_eq!(owner.0.hosts.lock().unwrap().len(), 1);
	assert!(weak.upgrade().is_none());
	owner.finish().await;
}

#[tokio::test]
async fn freeze_refuses_uncommitted_work_and_joins_all_original_children() {
	let owner = Owner::new();
	let fixture = Fixture::new();
	let first = submit(&owner, &fixture, "host", 0);
	let second = submit(&owner, &fixture, "host", 1);
	until(|| fixture.ready(0).exists() && fixture.ready(1).exists()).await;
	let queued = submit(&owner, &fixture, "host", 2);
	until(|| owner.0.admission.available_permits() == 13).await;
	owner.0.core.freeze();
	assert!(first.await.unwrap().is_err());
	assert!(second.await.unwrap().is_err());
	assert!(queued.await.unwrap().is_err());
	owner.finish().await;
	assert!(!fixture.ready(2).exists());
	assert_eq!(owner.0.core.hooks.spawned.load(Ordering::Acquire), 2);
}
