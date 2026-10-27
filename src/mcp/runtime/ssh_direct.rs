// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Direct SSH admission and original-child custody, independent of callers.
use anyhow::{anyhow, bail, Context, Result};
use std::collections::BTreeMap;
use std::process::{ExitStatus, Output};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{timeout_at, Instant};
use tokio_util::sync::CancellationToken;

const HOST_CONNECTIONS: usize = 2;
const GLOBAL_CONNECTIONS: usize = 8;
const MAX_ADMITTED: usize = 16;
const REAP: Duration = Duration::from_secs(3);
static DIRECT: OnceLock<std::result::Result<Arc<Proxy>, String>> = OnceLock::new();
static FROZEN: AtomicBool = AtomicBool::new(false);

const QUEUED: u8 = 0;
const CANCELLED: u8 = 1;
const COMMITTED: u8 = 2;

struct Cancellation {
	token: CancellationToken,
	phase: AtomicU8,
}
impl Cancellation {
	fn new() -> Arc<Self> {
		Arc::new(Self {
			token: CancellationToken::new(),
			phase: AtomicU8::new(QUEUED),
		})
	}
	fn cancel(&self) {
		let _ = self
			.phase
			.compare_exchange(QUEUED, CANCELLED, Ordering::AcqRel, Ordering::Acquire);
		self.token.cancel();
	}
	fn commit(&self) -> Result<()> {
		self.phase
			.compare_exchange(QUEUED, COMMITTED, Ordering::AcqRel, Ordering::Acquire)
			.map_err(|_| anyhow!("direct SSH cancelled before submission; no child submitted"))?;
		Ok(())
	}
}

struct CancelOnDrop(Arc<Cancellation>);
impl Drop for CancelOnDrop {
	fn drop(&mut self) {
		self.0.cancel();
	}
}

struct StopOnDrop(Arc<Core>);
impl Drop for StopOnDrop {
	fn drop(&mut self) {
		self.0.freeze();
	}
}

struct Leases {
	_admission: OwnedSemaphorePermit,
	_host: OwnedSemaphorePermit,
	_global: OwnedSemaphorePermit,
}

struct Request {
	target: String,
	command: Command,
	input: Vec<u8>,
	deadline: Instant,
	cancel: Arc<Cancellation>,
	reply: oneshot::Sender<Result<Output>>,
	leases: Option<Leases>,
}

struct ChildState {
	child: Child,
	reaped: bool,
	wait_failed: bool,
	cleanup_deadline: Option<Instant>,
}

struct OwnedChild {
	id: u64,
	state: AsyncMutex<ChildState>,
	#[cfg(all(test, unix))]
	hooks: tests::ChildHooks,
	// Registry ownership retains both limits across caller/task cancellation.
	_leases: Leases,
}

impl OwnedChild {
	async fn wait(&self) -> Result<ExitStatus> {
		let mut state = self.state.lock().await;
		if state.wait_failed {
			bail!("direct SSH original wait is uncertain; reconciliation required");
		}
		match state.child.wait().await {
			Ok(status) => {
				#[cfg(all(test, unix))]
				if self.hooks.unconfirmed_wait {
					state.wait_failed = true;
					bail!("injected unconfirmed original wait");
				}
				state.reaped = true;
				Ok(status)
			}
			Err(error) => {
				state.wait_failed = true;
				Err(error.into())
			}
		}
	}

	async fn stop_and_reap(&self) -> Result<()> {
		let mut state = self.state.lock().await;
		if state.reaped {
			return Ok(());
		}
		if state.wait_failed {
			bail!("direct SSH original wait failed; refusing an uncertain signal");
		}
		match state.child.try_wait() {
			Ok(Some(_)) => {
				state.reaped = true;
				return Ok(());
			}
			Ok(None) => {}
			Err(error) => {
				state.wait_failed = true;
				return Err(error.into());
			}
		}
		let deadline = *state
			.cleanup_deadline
			.get_or_insert_with(|| Instant::now() + REAP);
		if Instant::now() >= deadline {
			bail!("direct SSH original reap deadline exhausted; reconciliation required");
		}
		// This is the original unreaped Child, never a caller-selected PID.
		let signal_error = state.child.start_kill().err();
		#[cfg(all(test, unix))]
		if let Some(gate) = self.hooks.before_reap.lock().unwrap().take() {
			gate.block();
		}
		match timeout_at(deadline, state.child.wait()).await {
			Ok(Ok(_)) => {
				state.reaped = true;
				Ok(())
			}
			Ok(Err(error)) => {
				state.wait_failed = true;
				Err(error).context("direct SSH original reap failed; reconciliation required")
			}
			Err(error) => Err(error).with_context(|| {
				format!("direct SSH original reap incomplete; signal_error={signal_error:?}; reconciliation required")
			}),
		}
	}
}

struct Core {
	stop: CancellationToken,
	accepting: Mutex<bool>,
	children: Mutex<BTreeMap<u64, Arc<OwnedChild>>>,
	sequence: AtomicU64,
	#[cfg(all(test, unix))]
	hooks: tests::Hooks,
}

impl Core {
	fn freeze(&self) {
		// Only a short submission-commit transition is serialized here. No
		// caller Drop waits for an OS spawn, pipe I/O or original-child cleanup.
		*self
			.accepting
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
		self.stop.cancel();
	}

	fn active(&self, deadline: Instant, cancel: &CancellationToken) -> Result<()> {
		if self.stop.is_cancelled() || cancel.is_cancelled() || Instant::now() >= deadline {
			bail!("direct SSH cancelled or original deadline expired; no automatic retry");
		}
		Ok(())
	}

	fn spawn(&self, request: &mut Request, leases: Leases) -> Result<Arc<OwnedChild>> {
		// Acquire the only ownership registry before any child can exist. The
		// critical section has no await or fallible pipe/identity preparation.
		let mut children = self.children.lock().map_err(|_| {
			self.stop.cancel();
			anyhow!("direct SSH child registry poisoned; no new child submitted")
		})?;
		let id = self.sequence.fetch_add(1, Ordering::Relaxed);
		if id == u64::MAX {
			self.stop.cancel();
			bail!("direct SSH child sequence exhausted");
		}
		#[cfg(all(test, unix))]
		let child_hooks = self.hooks.child.lock().unwrap().take().unwrap_or_default();
		{
			let accepting = self
				.accepting
				.lock()
				.map_err(|_| anyhow!("direct SSH submission gate poisoned"))?;
			if !*accepting {
				bail!("direct SSH admission frozen; no child submitted");
			}
			self.active(request.deadline, &request.cancel.token)?;
			// This CAS is the submission linearization point. Cancellation that
			// wins while queued prevents spawn; cancellation after commit belongs
			// to this original attempt and must await its owner cleanup.
			request.cancel.commit()?;
		}
		#[cfg(all(test, unix))]
		if let Some(gate) = self.hooks.after_commit.lock().unwrap().take() {
			gate.block();
		}
		let child = request
			.command
			.spawn()
			.with_context(|| format!("failed to start ssh for {}", request.target))?;
		#[cfg(all(test, unix))]
		self.hooks.spawned.fetch_add(1, Ordering::AcqRel);
		let owned = Arc::new(OwnedChild {
			id,
			state: AsyncMutex::new(ChildState {
				child,
				reaped: false,
				wait_failed: false,
				cleanup_deadline: None,
			}),
			#[cfg(all(test, unix))]
			hooks: child_hooks,
			_leases: leases,
		});
		children.insert(id, owned.clone());
		drop(children);
		#[cfg(all(test, unix))]
		assert!(
			!self
				.hooks
				.panic_after_registration
				.swap(false, Ordering::AcqRel),
			"injected owner unwind after registration"
		);
		Ok(owned)
	}

	async fn release(&self, owned: &Arc<OwnedChild>) -> Result<()> {
		if !owned.state.lock().await.reaped {
			self.stop.cancel();
			bail!("direct SSH child was not reaped; capacity retained");
		}
		let mut children = self.children.lock().unwrap_or_else(|poisoned| {
			self.stop.cancel();
			poisoned.into_inner()
		});
		if children
			.get(&owned.id)
			.is_none_or(|value| !Arc::ptr_eq(value, owned))
		{
			self.stop.cancel();
			bail!("direct SSH original registry identity differs");
		}
		children.remove(&owned.id);
		Ok(())
	}

	async fn execute(&self, mut request: Request) {
		// Taking the leases before spawn does not expose a child. If admission
		// fails, these unsubmitted leases can be returned immediately.
		let result = match request.leases.take() {
			Some(leases) => self.capture(&mut request, leases).await,
			None => Err(anyhow!(
				"direct SSH request lacks original admission; no child submitted"
			)),
		};
		let _ = request.reply.send(result);
	}

	async fn capture(&self, request: &mut Request, leases: Leases) -> Result<Output> {
		let owned = self.spawn(request, leases)?;
		let outcome = async {
			let (stdin, stdout, stderr) = {
				let mut state = owned.state.lock().await;
				(state.child.stdin.take(), state.child.stdout.take(), state.child.stderr.take())
			};
			let mut stdin = stdin.context("missing SSH stdin")?;
			let stdout = stdout.context("missing SSH stdout")?;
			let stderr = stderr.context("missing SSH stderr")?;
			let io = async {
				let input = async {
					stdin.write_all(&request.input).await?;
					stdin.shutdown().await?;
					drop(stdin);
					Ok::<(), anyhow::Error>(())
				};
				let (_, stdout, stderr, status) = tokio::try_join!(
					input, super::read_bounded(stdout), super::read_bounded(stderr), owned.wait()
				)?;
				Ok::<_, anyhow::Error>(Output { status, stdout, stderr })
			};
			let output = tokio::select! {
				biased;
				_ = request.cancel.token.cancelled() => Err(anyhow!("direct SSH caller cancelled; no automatic retry")),
				_ = self.stop.cancelled() => Err(anyhow!("direct SSH stopped; no automatic retry")),
				value = timeout_at(request.deadline, io) => value.context("direct SSH original deadline expired; no automatic retry")?,
			}?;
			self.active(request.deadline, &request.cancel.token)?;
			Ok::<_, anyhow::Error>(output)
		}.await;
		// Every pipe future/borrow is gone before cleanup, including early errors.
		if outcome.is_err() {
			if let Err(error) = owned.stop_and_reap().await {
				self.stop.cancel();
				return Err(error);
			}
		}
		self.release(&owned).await?;
		drop(owned);
		// Drop the last owner and both permits before the reply is published.
		outcome
	}

	async fn run(
		self: &Arc<Self>,
		mut receiver: mpsc::Receiver<Request>,
		tasks: &mut JoinSet<()>,
	) -> Result<()> {
		loop {
			tokio::select! {
				biased;
				_ = self.stop.cancelled() => return Ok(()),
				result = tasks.join_next(), if !tasks.is_empty() => {
					if let Some(Err(error)) = result {
						self.stop.cancel();
						return Err(error).context("direct SSH owner work panicked");
					}
				}
				request = receiver.recv() => match request {
					Some(request) => {
						let core = self.clone();
						tasks.spawn(async move { core.execute(request).await; });
					}
					None => return Ok(()),
				},
			}
		}
	}

	async fn drain(&self) -> Result<()> {
		self.stop.cancel();
		let children: Vec<_> = self
			.children
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.values()
			.cloned()
			.collect();
		let mut errors = Vec::new();
		for owned in children {
			if let Err(error) = owned.stop_and_reap().await {
				errors.push(format!("{error:#}"));
				continue;
			}
			if let Err(error) = self.release(&owned).await {
				errors.push(format!("{error:#}"));
			}
		}
		if !errors.is_empty()
			|| !self
				.children
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner())
				.is_empty()
		{
			bail!("direct SSH cleanup incomplete; original custody retained: {errors:?}");
		}
		Ok(())
	}
}

struct Proxy {
	sender: mpsc::Sender<Request>,
	hosts: Mutex<BTreeMap<String, Weak<Semaphore>>>,
	admission: Arc<Semaphore>,
	global: Arc<Semaphore>,
	// The process-wide proxy retains quarantined original children and permits
	// even if its owner thread exits with an error. No replacement owner is made.
	core: Arc<Core>,
	join: Arc<JoinReceipt>,
}

struct JoinState {
	thread: Option<std::thread::JoinHandle<Result<()>>>,
	started: bool,
	finished: Option<std::result::Result<(), String>>,
}

struct JoinReceipt {
	state: Mutex<JoinState>,
	done: Notify,
}

impl Proxy {
	fn start() -> Result<Arc<Self>> {
		let (sender, receiver) = mpsc::channel(GLOBAL_CONNECTIONS);
		let core = Arc::new(Core {
			stop: CancellationToken::new(),
			accepting: Mutex::new(true),
			children: Mutex::new(BTreeMap::new()),
			sequence: AtomicU64::new(1),
			#[cfg(all(test, unix))]
			hooks: tests::Hooks::default(),
		});
		let proxy = Arc::new(Self {
			sender,
			hosts: Mutex::new(BTreeMap::new()),
			admission: Arc::new(Semaphore::new(MAX_ADMITTED)),
			global: Arc::new(Semaphore::new(GLOBAL_CONNECTIONS)),
			core: core.clone(),
			join: Arc::new(JoinReceipt {
				state: Mutex::new(JoinState {
					thread: None,
					started: false,
					finished: None,
				}),
				done: Notify::new(),
			}),
		});
		let thread = std::thread::Builder::new()
			.name("hepta-direct-ssh".into())
			.spawn(move || {
				let _stop_on_exit = StopOnDrop(core.clone());
				let runtime = tokio::runtime::Builder::new_current_thread()
					.enable_all()
					.build()?;
				// Both the child registry and task set live outside the fallible actor
				// future. A failed request cannot retire this runtime before cleanup.
				let mut tasks = JoinSet::new();
				let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
					runtime.block_on(core.run(receiver, &mut tasks))
				}));
				core.freeze();
				let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
					runtime.block_on(async {
						let mut failed = false;
						while let Some(result) = tasks.join_next().await {
							failed |= result.is_err();
						}
						core.drain().await?;
						if failed {
							bail!("direct SSH request panicked during shutdown");
						}
						Ok(())
					})
				}));
				cleanup.map_err(|_| {
					anyhow!("direct SSH cleanup panicked; original custody retained")
				})??;
				outcome.map_err(|_| anyhow!("direct SSH actor panicked"))?
			})?;
		proxy
			.join
			.state
			.lock()
			.map_err(|_| anyhow!("direct SSH thread registration failed"))?
			.thread = Some(thread);
		Ok(proxy)
	}

	fn target(&self, target: &str) -> Result<Arc<Semaphore>> {
		let mut hosts = self
			.hosts
			.lock()
			.map_err(|_| anyhow!("direct SSH admission registry poisoned"))?;
		// Owned permits hold this exact Semaphore Arc; a live child or waiter
		// cannot be bypassed by replacing a weakly registered target wrapper.
		hosts.retain(|_, value| value.strong_count() != 0);
		if let Some(value) = hosts.get(target).and_then(Weak::upgrade) {
			return Ok(value);
		}
		let value = Arc::new(Semaphore::new(HOST_CONNECTIONS));
		hosts.insert(target.to_owned(), Arc::downgrade(&value));
		Ok(value)
	}

	async fn acquire(&self, target: &str, deadline: Instant) -> Result<Leases> {
		let admission =
			self.admission.clone().try_acquire_owned().map_err(|_| {
				anyhow!("direct SSH admitted capacity exhausted; no child submitted; no automatic retry")
			})?;
		let host = self.target(target)?;
		let host = tokio::select! {
			biased;
			_ = self.core.stop.cancelled() => bail!("direct SSH admission stopped"),
			value = timeout_at(deadline, host.acquire_owned()) => value.context("direct SSH host admission deadline; no child submitted")??,
		};
		// Same-host waiters cannot consume all global slots while queued.
		let global = tokio::select! {
			biased;
			_ = self.core.stop.cancelled() => bail!("direct SSH admission stopped"),
			value = timeout_at(deadline, self.global.clone().acquire_owned()) => value.context("direct SSH global admission deadline; no child submitted")??,
		};
		Ok(Leases {
			_admission: admission,
			_host: host,
			_global: global,
		})
	}

	async fn capture(
		&self,
		target: &str,
		command: Command,
		input: &[u8],
		deadline: Instant,
	) -> Result<Output> {
		let leases = self.acquire(target, deadline).await?;
		let cancel = Cancellation::new();
		let _cancel_on_drop = CancelOnDrop(cancel.clone());
		self.core.active(deadline, &cancel.token)?;
		let (reply, receive) = oneshot::channel();
		let request = Request {
			target: target.to_owned(),
			command,
			input: input.to_vec(),
			deadline,
			cancel: cancel.clone(),
			reply,
			leases: Some(leases),
		};
		self.core.active(deadline, &cancel.token)?;
		self.sender
			.try_send(request)
			.map_err(|_| anyhow!("direct SSH owner unavailable; no child submitted"))?;
		let output = timeout_at(deadline, receive)
			.await
			.context("direct SSH original deadline expired; no automatic retry")?
			.context("direct SSH owner failed; outcome unconfirmed; no automatic retry")??;
		self.core.active(deadline, &cancel.token)?;
		Ok(output)
	}

	async fn shutdown(&self) -> Result<()> {
		self.core.freeze();
		let runtime = tokio::runtime::Handle::try_current()
			.context("direct SSH shutdown requires its joining runtime")?;
		let thread = {
			let mut state = self
				.join
				.state
				.lock()
				.map_err(|_| anyhow!("direct SSH shutdown ownership unavailable"))?;
			let thread = state.thread.take();
			if thread.is_some() {
				state.started = true;
			}
			thread
		};
		if let Some(thread) = thread {
			// This worker only joins the dedicated owner. Admission and original
			// child I/O/reaping never consume a blocking-pool waiter.
			let receipt = self.join.clone();
			runtime.spawn_blocking(move || {
				let result = thread
					.join()
					.map_err(|_| "direct SSH owner thread panicked".to_owned())
					.and_then(|value| value.map_err(|error| format!("{error:#}")));
				// Persist inside the original join worker, even when its caller's
				// shutdown future was cancelled or another guard is also joining.
				receipt
					.state
					.lock()
					.unwrap_or_else(|poisoned| poisoned.into_inner())
					.finished = Some(result);
				receipt.done.notify_waiters();
			});
		}
		loop {
			let notified = self.join.done.notified();
			tokio::pin!(notified);
			notified.as_mut().enable();
			let finished = {
				let state = self
					.join
					.state
					.lock()
					.map_err(|_| anyhow!("direct SSH join receipt unavailable"))?;
				if !state.started {
					bail!("direct SSH original join ownership missing");
				}
				state.finished.clone()
			};
			if let Some(result) = finished {
				return result
					.map_err(|error| anyhow!("direct SSH original shutdown failed: {error}"));
			}
			notified.await;
		}
	}
}

fn shared() -> Result<Arc<Proxy>> {
	if FROZEN.load(Ordering::Acquire) {
		bail!("direct SSH admission frozen");
	}
	let proxy = DIRECT
		.get_or_init(|| Proxy::start().map_err(|error| format!("{error:#}")))
		.as_ref()
		.map_err(|error| anyhow!("direct SSH owner startup failed: {error}"))?
		.clone();
	if FROZEN.load(Ordering::Acquire) || proxy.core.stop.is_cancelled() {
		proxy.core.freeze();
		bail!("direct SSH owner stopped; no automatic replacement");
	}
	Ok(proxy)
}

pub struct Guard(Arc<Proxy>);
impl Drop for Guard {
	fn drop(&mut self) {
		freeze();
		self.0.core.freeze();
	}
}
impl Guard {
	pub async fn shutdown(self) -> Result<()> {
		freeze();
		self.0.shutdown().await
	}
}

pub(super) fn start() -> Result<Guard> {
	Ok(Guard(shared()?))
}

pub(super) fn freeze() {
	FROZEN.store(true, Ordering::Release);
	if let Some(Ok(proxy)) = DIRECT.get() {
		proxy.core.freeze();
	}
}

pub(super) async fn capture(
	target: &str,
	command: Command,
	input: &[u8],
	deadline: Instant,
) -> Result<Output> {
	shared()?.capture(target, command, input, deadline).await
}

#[cfg(all(test, unix))]
#[path = "ssh_direct_tests.rs"]
mod tests;
