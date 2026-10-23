// Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
//! A separate, explicitly opted-in transport; it never falls back or replays.
#[path = "ssh_observation_profile.rs"]
mod profile;

use anyhow::{anyhow, bail, Context, Result};
use profile::{AgentIdentity, Profile, Stamp};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::BTreeMap;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, ChildStderr, Command};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{timeout, timeout_at, Instant};
use tokio_util::sync::CancellationToken;

const MAX_MASTERS: usize = 8;
const MAX_SESSIONS: usize = 8;
const HOST_SESSIONS: usize = 2;
const QUEUE: usize = 8;
const IDLE: Duration = Duration::from_secs(30);
const AGE: Duration = Duration::from_secs(120);
const START: Duration = Duration::from_secs(12);
const REAP: Duration = Duration::from_secs(3);
const STDERR_CAP: usize = 64 * 1024;
// OpenSSH publishes a ControlPath by first binding path + '.' + 16 random
// characters. Linux sun_path must also contain the terminating NUL byte.
const CONTROL_SOCKET_PATH_BYTES: usize = 108 - 17 - 1;
static POOL: OnceLock<Arc<Proxy>> = OnceLock::new();

fn check_control_socket_path(path: &Path) -> Result<()> {
	if path.as_os_str().as_encoded_bytes().len() > CONTROL_SOCKET_PATH_BYTES {
		bail!("observation socket path is too long for OpenSSH temporary publication");
	}
	Ok(())
}

struct Request {
	host: String,
	command: String,
	input: Vec<u8>,
	deadline: Instant,
	cancel: CancellationToken,
	reply: oneshot::Sender<Result<Captured>>,
}

/// Capacity also covers completed output until its original caller parses it.
pub(super) struct Captured {
	output: Output,
	_budget: Arc<OwnedSemaphorePermit>,
}
impl std::ops::Deref for Captured {
	type Target = Output;
	fn deref(&self) -> &Output {
		&self.output
	}
}

struct Proxy {
	sender: mpsc::Sender<Request>,
	stop: CancellationToken,
	healthy: AtomicBool,
	thread: Mutex<Option<std::thread::JoinHandle<Result<()>>>>,
}

/// Drop freezes admission even if startup or the surrounding transport fails.
pub struct PoolGuard(Arc<Proxy>);
impl Drop for PoolGuard {
	fn drop(&mut self) {
		self.0.healthy.store(false, Ordering::Release);
		self.0.stop.cancel();
	}
}
impl PoolGuard {
	pub async fn shutdown(self) -> Result<()> {
		self.0.healthy.store(false, Ordering::Release);
		self.0.stop.cancel();
		let thread = self
			.0
			.thread
			.lock()
			.map_err(|_| anyhow!("observation pool thread unavailable"))?
			.take();
		if let Some(thread) = thread {
			// Only joining happens here; no SSH child is spawned by this worker.
			tokio::task::spawn_blocking(move || thread.join())
				.await
				.context("observation pool join unavailable")?
				.map_err(|_| anyhow!("observation pool owner thread failed"))??;
		}
		Ok(())
	}
}

pub(super) fn requested() -> bool {
	POOL.get().is_some()
}
pub(super) fn freeze() {
	if let Some(pool) = POOL.get() {
		pool.healthy.store(false, Ordering::Release);
		pool.stop.cancel();
	}
}

pub(super) async fn start(path: &Path) -> Result<PoolGuard> {
	if POOL.get().is_some() {
		bail!("observation pool already requested");
	}
	let profile = Arc::new(Profile::load(path)?);
	let root = PrivateRoot::create(&profile)?;
	let (sender, receiver) = mpsc::channel(QUEUE);
	let (ready_tx, ready_rx) = oneshot::channel();
	let proxy = Arc::new(Proxy {
		sender,
		stop: CancellationToken::new(),
		healthy: AtomicBool::new(false),
		thread: Mutex::new(None),
	});
	let owner = proxy.clone();
	let thread = std::thread::Builder::new()
		.name("hepta-observation-ssh".into())
		.spawn(move || {
			let runtime = tokio::runtime::Builder::new_current_thread()
				.enable_all()
				.build()?;
			let core = Arc::new(Core {
				profile,
				root,
				stop: owner.stop.clone(),
				agent: OnceLock::new(),
				children: AsyncMutex::new(BTreeMap::new()),
				masters: AsyncMutex::new(BTreeMap::new()),
				background: Mutex::new(JoinSet::new()),
				sequence: AtomicU64::new(1),
				owner_tid: unsafe { libc::syscall(libc::SYS_gettid) },
			});
			// Child ownership lives outside the fallible actor future. All spawning,
			// pipe I/O and waiting occurs on this nonretiring current-thread runtime.
			let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
				runtime.block_on(async {
					let initialized = core.initialize().await;
					if initialized.is_ok() {
						owner.healthy.store(true, Ordering::Release);
					}
					let accepted = ready_tx
						.send(initialized.map_err(|error| format!("{error:#}")))
						.is_ok();
					if !accepted || !owner.healthy.load(Ordering::Acquire) {
						return Ok(());
					}
					core.clone().run(receiver).await
				})
			}));
			owner.healthy.store(false, Ordering::Release);
			core.stop.cancel();
			let cleanup = runtime.block_on(core.shutdown());
			match outcome {
				Ok(result) => {
					result?;
					cleanup
				}
				Err(_) => {
					cleanup?;
					bail!("observation pool owner failed; no request replayed")
				}
			}
		})?;
	*proxy
		.thread
		.lock()
		.map_err(|_| anyhow!("observation pool thread unavailable"))? = Some(thread);
	let guard = PoolGuard(proxy.clone());
	if POOL.set(proxy).is_err() {
		guard.shutdown().await?;
		bail!("observation pool already requested");
	}
	match ready_rx.await {
		Ok(Ok(())) => Ok(guard),
		Ok(Err(error)) => {
			guard.shutdown().await?;
			bail!("observation pool startup refused: {error}")
		}
		Err(_) => {
			guard.shutdown().await?;
			bail!("observation pool startup owner unavailable")
		}
	}
}

struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
	fn drop(&mut self) {
		self.0.cancel();
	}
}

pub(super) async fn capture(
	host: &str,
	command: String,
	input: Vec<u8>,
	duration: Duration,
) -> Result<Captured> {
	super::validate_observation_bytes(&command, &input)?;
	let pool = POOL.get().context("observation pool was not requested")?;
	if !pool.healthy.load(Ordering::Acquire) || pool.stop.is_cancelled() {
		bail!("observation pool unavailable; no fallback or automatic retry");
	}
	let deadline = Instant::now() + duration;
	let cancel = CancellationToken::new();
	let _guard = CancelOnDrop(cancel.clone());
	let (reply, receive) = oneshot::channel();
	pool.sender
		.try_send(Request {
			host: host.to_owned(),
			command,
			input,
			deadline,
			cancel,
			reply,
		})
		.map_err(|_| {
			anyhow!("observation pool capacity unavailable; no fallback or automatic retry")
		})?;
	timeout_at(deadline, receive)
		.await
		.context("observation transport deadline; no automatic retry")?
		.context("observation transport unavailable; no automatic retry")?
}

struct PrivateRoot {
	path: PathBuf,
	directory: File,
	identity: Stamp,
	parent: Stamp,
}
impl Drop for PrivateRoot {
	fn drop(&mut self) {
		if profile::private_directory(&self.path)
			.ok()
			.is_some_and(|stamp| stamp.same_directory(&self.identity))
			&& self
				.directory
				.metadata()
				.ok()
				.is_some_and(|info| self.identity.same_directory(&Stamp::of(&info)))
			&& self
				.path
				.parent()
				.and_then(|parent| profile::private_directory(parent).ok())
				.is_some_and(|stamp| stamp.same_directory(&self.parent))
		{
			// Only an empty pinned root may be removed on an early error.
			let _ = std::fs::remove_dir(&self.path);
		}
	}
}
impl PrivateRoot {
	fn create(profile: &Profile) -> Result<Self> {
		profile.verify_files()?;
		let parent = profile::open_absolute(&profile.socket_parent, true)?;
		let mut random = [0u8; 16];
		SystemRandom::new()
			.fill(&mut random)
			.map_err(|_| anyhow!("observation socket entropy unavailable"))?;
		let name = format!(
			"hp-o-{}-{}",
			std::process::id(),
			random
				.iter()
				.map(|v| format!("{v:02x}"))
				.collect::<String>()
		);
		let path = profile.socket_parent.join(&name);
		// Reject an unusable parent before creating any private root. Subsequent
		// generations are checked again with their complete sequence number.
		check_control_socket_path(&path.join("m-1"))?;
		let component = std::ffi::CString::new(name)?;
		if unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o700) } != 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		// Until an inode is pinned, failure leaves the unpredictable empty name
		// for explicit reconciliation instead of deleting an uncertain path.
		let directory = profile::open_absolute(&path, true).with_context(|| {
			format!(
				"observation private root identity unavailable at {}; reconciliation required",
				path.display()
			)
		})?;
		let identity = Stamp::of(
			&directory
				.metadata()
				.context("observation private root stamp unavailable; reconciliation required")?,
		);
		let root = Self {
			path,
			directory,
			identity,
			parent: profile.parent_stamp.clone(),
		};
		root.verify(profile)?;
		Ok(root)
	}
	fn verify(&self, profile: &Profile) -> Result<()> {
		if !self
			.identity
			.same_directory(&Stamp::of(&self.directory.metadata()?))
			|| !self
				.identity
				.same_directory(&profile::private_directory(&self.path)?)
			|| !self
				.parent
				.same_directory(&profile::private_directory(&profile.socket_parent)?)
		{
			bail!("observation private socket root changed");
		}
		Ok(())
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessIdentity {
	birth: u64,
	uid: u32,
	dev: u64,
	ino: u64,
	argv: Vec<u8>,
}
fn process_identity(pid: u32) -> Result<ProcessIdentity> {
	let root = PathBuf::from(format!("/proc/{pid}"));
	let status = std::fs::read_to_string(root.join("stat"))?;
	let tail = status
		.rsplit_once(')')
		.context("observation child stat unavailable")?
		.1;
	let birth = tail
		.split_ascii_whitespace()
		.nth(19)
		.context("observation child birth unavailable")?
		.parse()?;
	let exe = std::fs::metadata(root.join("exe"))?;
	Ok(ProcessIdentity {
		birth,
		uid: std::fs::metadata(&root)?.uid(),
		dev: exe.dev(),
		ino: exe.ino(),
		argv: std::fs::read(root.join("cmdline"))?,
	})
}

struct OwnedChild {
	id: u64,
	pid: u32,
	pidfd: Option<OwnedFd>,
	identity: OnceLock<ProcessIdentity>,
	approved: AtomicBool,
	child: AsyncMutex<Child>,
	// Registry ownership keeps capacity charged through timeout/cancellation
	// until wait/reap proves that this exact child has terminated.
	_permits: Vec<Arc<OwnedSemaphorePermit>>,
}
impl OwnedChild {
	fn signal(&self, signal: i32) -> Result<()> {
		let pidfd = self
			.pidfd
			.as_ref()
			.context("observation child pidfd unavailable")?;
		if self
			.identity
			.get()
			.is_none_or(|expected| process_identity(self.pid).ok().as_ref() != Some(expected))
		{
			bail!("observation child identity unavailable; refusing guessed signal");
		}
		if unsafe {
			libc::syscall(
				libc::SYS_pidfd_send_signal,
				pidfd.as_raw_fd(),
				signal,
				std::ptr::null::<libc::siginfo_t>(),
				0,
			)
		} < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
		{
			return Err(std::io::Error::last_os_error().into());
		}
		Ok(())
	}
	async fn wait(&self) -> Result<ExitStatus> {
		Ok(self.child.lock().await.wait().await?)
	}
	async fn terminal(&self) -> Result<bool> {
		Ok(self.child.lock().await.try_wait()?.is_some())
	}
	async fn verify_live(&self) -> Result<()> {
		let mut child = self.child.lock().await;
		if child.try_wait()?.is_some() {
			bail!("observation SSH child exited");
		}
		if self
			.identity
			.get()
			.is_none_or(|v| process_identity(self.pid).ok().as_ref() != Some(v))
		{
			bail!("observation SSH child identity changed");
		}
		Ok(())
	}
	async fn stop(&self, grace: Duration) -> Result<()> {
		let mut child = self.child.lock().await;
		if child.try_wait()?.is_some() {
			return Ok(());
		}
		if !self.approved.load(Ordering::Acquire) {
			// The original unreaped Child is safe to stop even when pidfd or
			// post-exec proof failed. No caller supplies this process handle.
			child.start_kill()?;
			timeout(REAP, child.wait()).await.context(
				"unapproved observation child reap unavailable; reconciliation required",
			)??;
			return Ok(());
		}
		if !grace.is_zero() {
			if let Err(error) = self.signal(libc::SIGTERM) {
				if child.try_wait()?.is_some() {
					return Ok(());
				}
				return Err(error);
			}
			if let Ok(result) = timeout(grace, child.wait()).await {
				result?;
				return Ok(());
			}
		}
		if child.try_wait()?.is_some() {
			return Ok(());
		}
		if let Err(error) = self.signal(libc::SIGKILL) {
			if child.try_wait()?.is_some() {
				return Ok(());
			}
			return Err(error);
		}
		timeout(REAP, child.wait())
			.await
			.context("observation child reap unavailable; reconciliation required")??;
		Ok(())
	}
}

type Ready = Option<std::result::Result<Arc<Master>, String>>;
struct Entry {
	ready: watch::Receiver<Ready>,
	permits: Arc<Semaphore>,
	generation: u64,
	ready_deadline: Instant,
	// Preserve the exact old socket proof outside the fallible renewal task.
	draining: Option<Arc<Master>>,
}
struct Master {
	owned: Arc<OwnedChild>,
	socket: PathBuf,
	stamp: Stamp,
	created: Instant,
	last_use: Mutex<Instant>,
	active: AtomicUsize,
	accepting: AtomicBool,
}
struct ActiveMaster(Arc<Master>);
impl Drop for ActiveMaster {
	fn drop(&mut self) {
		if let Ok(mut last) = self.0.last_use.lock() {
			*last = Instant::now();
		}
		self.0.active.fetch_sub(1, Ordering::AcqRel);
	}
}

struct Core {
	profile: Arc<Profile>,
	root: PrivateRoot,
	stop: CancellationToken,
	agent: OnceLock<AgentIdentity>,
	children: AsyncMutex<BTreeMap<u64, Arc<OwnedChild>>>,
	masters: AsyncMutex<BTreeMap<String, Entry>>,
	background: Mutex<JoinSet<Result<()>>>,
	sequence: AtomicU64,
	owner_tid: libc::c_long,
}

#[derive(Clone, Copy)]
enum Mode {
	Master,
	Slave,
}
impl Core {
	async fn initialize(self: &Arc<Self>) -> Result<()> {
		self.profile.verify_files()?;
		self.root.verify(&self.profile)?;
		let agent =
			profile::agent_snapshot(&self.profile.agent, Instant::now() + Duration::from_secs(5))
				.await?;
		self.agent
			.set(agent)
			.map_err(|_| anyhow!("observation agent already bound"))?;
		let deadline = Instant::now() + Duration::from_secs(30);
		self.verify_profile(deadline).await?;
		let socket = self.root.path.join("effective-check");
		for host in self.profile.hosts.keys() {
			self.effective(host, Mode::Master, &socket, deadline)
				.await?;
			self.effective(host, Mode::Slave, &socket, deadline).await?;
		}
		self.verify_profile(deadline).await
	}
	async fn verify_profile(&self, deadline: Instant) -> Result<()> {
		let checked = async {
			self.profile.verify_files()?;
			self.root.verify(&self.profile)?;
			let agent = tokio::select! {
				value = profile::agent_snapshot(&self.profile.agent, deadline.min(Instant::now() + Duration::from_secs(2))) => value?,
				_ = self.stop.cancelled() => bail!("observation profile check stopped"),
			};
			if self.agent.get() != Some(&agent) {
				bail!("observation SSH credential identity changed");
			}
			self.profile.verify_files()?;
			Ok(())
		}
		.await;
		if checked.is_err() {
			self.stop.cancel();
		}
		checked
	}
	fn arguments(
		&self,
		host: &str,
		mode: Mode,
		socket: &Path,
		effective: bool,
	) -> Result<Vec<String>> {
		let target = self
			.profile
			.hosts
			.get(host)
			.context("host is outside observation profile")?;
		let mut args = vec![
			"/usr/bin/ssh".to_owned(),
			"-F".into(),
			self.profile.config.to_string_lossy().into_owned(),
		];
		if effective {
			args.push("-G".into());
		}
		args.push("-T".into());
		let mut options: Vec<(String, String)> = vec![
			("BatchMode", "yes"),
			("ConnectTimeout", "8"),
			("ConnectionAttempts", "1"),
			("StrictHostKeyChecking", "yes"),
			("ForwardAgent", "no"),
			("ForwardX11", "no"),
			("ClearAllForwardings", "yes"),
			("PermitLocalCommand", "no"),
			("RemoteCommand", "none"),
			("ForkAfterAuthentication", "no"),
			("ControlPersist", "no"),
			("ProxyJump", "none"),
			("ProxyUseFdpass", "no"),
			("IdentityFile", "none"),
			("CertificateFile", "none"),
			("PreferredAuthentications", "publickey"),
			("PubkeyAuthentication", "yes"),
			("PasswordAuthentication", "no"),
			("KbdInteractiveAuthentication", "no"),
			("GSSAPIAuthentication", "no"),
			("HostbasedAuthentication", "no"),
			("PKCS11Provider", "none"),
			("SecurityKeyProvider", "internal"),
			("AddKeysToAgent", "no"),
			("UpdateHostKeys", "no"),
			("KnownHostsCommand", "none"),
			("VerifyHostKeyDNS", "no"),
			("CheckHostIP", "no"),
			("CanonicalizeHostname", "no"),
			("GlobalKnownHostsFile", "/dev/null"),
		]
		.into_iter()
		.map(|(key, value)| (key.to_owned(), value.to_owned()))
		.collect();
		options.extend([
			(
				"IdentityAgent".into(),
				self.profile.agent.to_string_lossy().into_owned(),
			),
			(
				"UserKnownHostsFile".into(),
				self.profile.known_hosts.to_string_lossy().into_owned(),
			),
			("ControlPath".into(), socket.to_string_lossy().into_owned()),
			(
				"ControlMaster".into(),
				if matches!(mode, Mode::Master) {
					"yes"
				} else {
					"no"
				}
				.into(),
			),
			(
				"ProxyCommand".into(),
				if matches!(mode, Mode::Slave) {
					"/usr/bin/false"
				} else {
					"none"
				}
				.into(),
			),
		]);
		for (key, value) in options {
			args.extend(["-o".into(), format!("{key}={value}")]);
		}
		if matches!(mode, Mode::Master) {
			args.extend(["-N".into(), "-n".into()]);
		}
		args.extend(["--".into(), target.clone()]);
		Ok(args)
	}
	fn command(&self, args: &[String]) -> Command {
		let mut command = Command::new("/usr/bin/ssh");
		command
			.args(&args[1..])
			.env_clear()
			.env("PATH", "/usr/bin:/bin")
			.env("LANG", "C")
			.env("SHELL", "/bin/sh")
			.env("SSH_AUTH_SOCK", &self.profile.agent)
			.kill_on_drop(true);
		let controller = unsafe { libc::getpid() };
		// No allocation, formatting, locks, environment lookup or Rust error
		// construction is permitted after fork in this multithreaded process.
		unsafe {
			command.pre_exec(move || {
				if libc::prctl(
					libc::PR_SET_PDEATHSIG,
					libc::SIGKILL as libc::c_ulong,
					0 as libc::c_ulong,
					0 as libc::c_ulong,
					0 as libc::c_ulong,
				) != 0 || libc::getppid() != controller
				{
					libc::_exit(127);
				}
				Ok(())
			});
		}
		command
	}
	async fn spawn(
		&self,
		args: &[String],
		mut command: Command,
		permits: Vec<Arc<OwnedSemaphorePermit>>,
		deadline: Instant,
		cancel: &CancellationToken,
	) -> Result<Arc<OwnedChild>> {
		if unsafe { libc::syscall(libc::SYS_gettid) } != self.owner_tid {
			bail!("observation child spawn attempted outside its lifetime owner thread");
		}
		let expected = args
			.iter()
			.flat_map(|arg| arg.as_bytes().iter().copied().chain([0]))
			.collect::<Vec<_>>();
		let mut children = tokio::select! {
			value = timeout_at(deadline, self.children.lock()) => value.context("observation child admission deadline")?,
			_ = cancel.cancelled() => bail!("observation cancelled before child creation"),
			_ = self.stop.cancelled() => bail!("observation pool stopped before child creation"),
		};
		if cancel.is_cancelled() || self.stop.is_cancelled() || Instant::now() >= deadline {
			bail!("observation cancelled or expired before child creation");
		}
		let child = command
			.spawn()
			.context("observation SSH spawn unavailable")?;
		let pid = child.id().unwrap_or(0);
		let fd = if pid == 0 {
			-1
		} else {
			unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) }
		};
		let pidfd = if fd < 0 {
			None
		} else {
			Some(unsafe { OwnedFd::from_raw_fd(fd as i32) })
		};
		let id = self.sequence.fetch_add(1, Ordering::Relaxed);
		let owned = Arc::new(OwnedChild {
			id,
			pid,
			pidfd,
			identity: OnceLock::new(),
			approved: AtomicBool::new(false),
			child: AsyncMutex::new(child),
			_permits: permits,
		});
		// Register the original Child before fallible post-exec proof or waiting.
		// Failed pidfd/identity checks use the same bounded cleanup ledger.
		children.insert(id, owned.clone());
		drop(children);
		let identity = process_identity(pid).ok();
		let matches = identity.as_ref().is_some_and(|value| {
			value.uid == unsafe { libc::geteuid() }
				&& (value.dev, value.ino) == self.profile.ssh_inode
				&& value.argv == expected
		});
		if let Some(identity) = identity {
			let _ = owned.identity.set(identity);
		}
		let terminal = owned.terminal().await;
		let proof = owned.pidfd.is_some() && terminal.as_ref().is_ok_and(|done| *done || matches);
		if !proof {
			self.stop.cancel();
			self.stop_child(&owned, Duration::ZERO)
				.await
				.context("observation early child proof failed; cleanup uncertain")?;
			self.release(&owned).await?;
			bail!("observation SSH pidfd or post-exec identity refused; no fallback");
		}
		owned.approved.store(matches, Ordering::Release);
		Ok(owned)
	}

	async fn release(&self, child: &Arc<OwnedChild>) -> Result<()> {
		if !matches!(child.terminal().await, Ok(true)) {
			self.stop.cancel();
			bail!("observation child is not reaped; reconciliation required");
		}
		self.children.lock().await.remove(&child.id);
		Ok(())
	}
	async fn stop_child(&self, child: &Arc<OwnedChild>, grace: Duration) -> Result<()> {
		let result = child.stop(grace).await;
		if result.is_err() {
			self.stop.cancel();
		}
		result
	}
	async fn captured(
		&self,
		args: Vec<String>,
		input: &[u8],
		deadline: Instant,
		cancel: &CancellationToken,
		permits: Vec<Arc<OwnedSemaphorePermit>>,
	) -> Result<Output> {
		let mut command = self.command(&args);
		command
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::piped());
		let owned = self
			.spawn(&args, command, permits, deadline, cancel)
			.await?;
		let pipes = {
			let mut child = owned.child.lock().await;
			(child.stdin.take(), child.stdout.take(), child.stderr.take())
		};
		let outcome = async {
			let mut stdin = pipes.0.context("observation SSH stdin unavailable")?;
			let stdout = pipes.1.context("observation SSH stdout unavailable")?;
			let stderr = pipes.2.context("observation SSH stderr unavailable")?;
			let io = async {
				let write = async { stdin.write_all(input).await?; stdin.shutdown().await?; drop(stdin); Ok::<(), anyhow::Error>(()) };
				let (_, stdout, stderr, status) = tokio::try_join!(write, super::read_bounded(stdout), super::read_bounded(stderr), owned.wait())?;
				Ok::<_, anyhow::Error>(Output { status, stdout, stderr })
			};
			tokio::select! {
				value = timeout_at(deadline, io) => value.context("observation SSH deadline; no automatic retry")?,
				_ = cancel.cancelled() => Err(anyhow!("observation SSH cancelled; no automatic retry")),
				_ = self.stop.cancelled() => Err(anyhow!("observation pool stopped; no automatic retry")),
			}
		}.await;
		if outcome.is_err() {
			self.stop_child(&owned, Duration::ZERO).await?;
		}
		self.release(&owned).await?;
		outcome
	}
	async fn effective(
		&self,
		host: &str,
		mode: Mode,
		socket: &Path,
		deadline: Instant,
	) -> Result<()> {
		let args = self.arguments(host, mode, socket, true)?;
		let result = self
			.captured(args, &[], deadline, &self.stop, vec![])
			.await?;
		if !result.status.success()
			|| result.stdout.len() > 256 * 1024
			|| result.stderr.len() > 4096
		{
			bail!("observation SSH effective guards unavailable");
		}
		let mut fields = BTreeMap::new();
		for line in std::str::from_utf8(&result.stdout)?.lines() {
			if let Some((key, value)) = line.split_once(' ') {
				if fields.insert(key, value).is_some()
					&& matches!(key, "identityfile" | "certificatefile")
				{
					bail!("observation SSH default credentials are not closed");
				}
			}
		}
		let value = |key: &str| fields.get(key).copied().unwrap_or_default();
		for key in [
			"forwardagent",
			"forwardx11",
			"permitlocalcommand",
			"forkafterauthentication",
			"controlpersist",
			"proxyusefdpass",
			"passwordauthentication",
			"kbdinteractiveauthentication",
			"gssapiauthentication",
			"hostbasedauthentication",
			"addkeystoagent",
			"updatehostkeys",
			"verifyhostkeydns",
			"checkhostip",
			"canonicalizehostname",
		] {
			if !matches!(value(key), "no" | "false") {
				bail!("observation SSH disabled guard is not effective");
			}
		}
		for key in [
			"batchmode",
			"stricthostkeychecking",
			"clearallforwardings",
			"pubkeyauthentication",
		] {
			if !matches!(value(key), "yes" | "true") {
				bail!("observation SSH required guard is not effective");
			}
		}
		for key in ["identityfile", "certificatefile"] {
			if value(key) != "none" {
				bail!("observation SSH undeclared credential/provider");
			}
		}
		// OpenSSH omits NULL-valued provider/command fields in -G output.
		// The explicit argv options are still required; empty is accepted
		// only for these known none representations, never credential lists.
		for key in ["pkcs11provider", "knownhostscommand"] {
			if !matches!(value(key), "none" | "") {
				bail!("observation SSH undeclared credential/provider");
			}
		}
		if value("preferredauthentications") != "publickey"
			|| value("securitykeyprovider") != "internal"
			|| value("identityagent") != self.profile.agent.to_str().unwrap_or_default()
			|| value("userknownhostsfile") != self.profile.known_hosts.to_str().unwrap_or_default()
			|| value("globalknownhostsfile") != "/dev/null"
			|| value("controlpath") != socket.to_str().unwrap_or_default()
			|| (matches!(mode, Mode::Slave) && value("proxycommand") != "/usr/bin/false")
			|| (matches!(mode, Mode::Master) && !matches!(value("proxycommand"), "none" | ""))
			|| !matches!(
				(mode, value("controlmaster")),
				(Mode::Master, "yes" | "true") | (Mode::Slave, "no" | "false")
			) || !matches!(value("remotecommand"), "none" | "")
		{
			bail!("observation SSH effective profile differs");
		}
		Ok(())
	}
	fn background(
		self: &Arc<Self>,
		work: impl std::future::Future<Output = Result<()>> + Send + 'static,
	) -> Result<()> {
		let mut tasks = self
			.background
			.lock()
			.map_err(|_| anyhow!("observation supervisor unavailable"))?;
		if tasks.len() >= MAX_MASTERS * 4 {
			bail!("observation supervisor bound exceeded");
		}
		tasks.spawn(work);
		Ok(())
	}
	async fn start_master(
		self: &Arc<Self>,
		host: String,
		socket: PathBuf,
		deadline: Instant,
	) -> Result<Arc<Master>> {
		self.verify_profile(deadline).await?;
		self.effective(&host, Mode::Master, &socket, deadline)
			.await?;
		self.effective(&host, Mode::Slave, &socket, deadline)
			.await?;
		if std::fs::symlink_metadata(&socket).is_ok() {
			bail!("observation socket already exists; never adopt");
		}
		let args = self.arguments(&host, Mode::Master, &socket, false)?;
		let mut command = self.command(&args);
		command
			.stdin(Stdio::null())
			.stdout(Stdio::null())
			.stderr(Stdio::piped());
		let created = Instant::now();
		let owned = self
			.spawn(&args, command, vec![], deadline, &self.stop)
			.await?;
		let stderr = owned.child.lock().await.stderr.take();
		let Some(stderr) = stderr else {
			self.stop_child(&owned, Duration::ZERO).await?;
			self.release(&owned).await?;
			bail!("master stderr unavailable");
		};
		let core = self.clone();
		if let Err(error) = self.background(async move { core.drain_master(stderr).await }) {
			self.stop_child(&owned, Duration::ZERO).await?;
			self.release(&owned).await?;
			return Err(error);
		}
		let readiness = async {
			loop {
				owned.verify_live().await?;
				if let Ok(stamp) = profile::socket_stamp(&socket) {
					let stream = UnixStream::connect(&socket).await?;
					let peer = profile::peer(&stream)?;
					if peer.0 != owned.pid as i32
						|| peer.1 != unsafe { libc::geteuid() }
						|| profile::socket_stamp(&socket)? != stamp
					{
						bail!("observation control socket is not the owned master");
					}
					return Ok(stamp);
				}
				tokio::time::sleep(Duration::from_millis(20)).await;
			}
		};
		let result = tokio::select! {
			value = timeout_at(deadline, readiness) => value.unwrap_or_else(|_| Err(anyhow!("observation master startup deadline"))),
			_ = self.stop.cancelled() => Err(anyhow!("observation master startup stopped")),
		};
		match result {
			Ok(stamp) => Ok(Arc::new(Master {
				owned,
				socket,
				stamp,
				created,
				last_use: Mutex::new(Instant::now()),
				active: AtomicUsize::new(0),
				accepting: AtomicBool::new(true),
			})),
			Err(error) => {
				self.stop_child(&owned, Duration::ZERO).await?;
				self.release(&owned).await?;
				Err(error)
			}
		}
	}
	async fn drain_master(&self, mut stderr: ChildStderr) -> Result<()> {
		let mut bytes = 0usize;
		let mut buffer = [0; 4096];
		loop {
			tokio::select! {
				_ = self.stop.cancelled() => return Ok(()),
				value = stderr.read(&mut buffer) => {
					let read = value?;
					if read == 0 { return Ok(()); }
					bytes = bytes.checked_add(read).context("observation master stderr overflow")?;
					if bytes > STDERR_CAP { self.stop.cancel(); bail!("observation master stderr bound exceeded"); }
				}
			}
		}
	}
	async fn entry(
		self: &Arc<Self>,
		host: &str,
		cancel: &CancellationToken,
		deadline: Instant,
	) -> Result<Entry> {
		let mut entries = tokio::select! {
			value = timeout_at(deadline, self.masters.lock()) => value.context("observation master admission deadline")?,
			_ = cancel.cancelled() => bail!("observation cancelled before master admission"),
			_ = self.stop.cancelled() => bail!("observation pool stopped before master admission"),
		};
		if cancel.is_cancelled() || self.stop.is_cancelled() || Instant::now() >= deadline {
			bail!("observation cancelled or expired before master admission");
		}
		if !entries.contains_key(host) {
			if entries.len() >= MAX_MASTERS {
				bail!("observation master capacity unavailable");
			}
			let socket = self.root.path.join(format!(
				"m-{}",
				self.sequence.fetch_add(1, Ordering::Relaxed)
			));
			check_control_socket_path(&socket)?;
			let (send, receive) = watch::channel(None);
			let generation = self.sequence.fetch_add(1, Ordering::Relaxed);
			let ready_deadline = Instant::now() + START + REAP;
			let core = self.clone();
			let name = host.to_owned();
			let start_deadline = deadline.min(Instant::now() + START);
			self.background(async move {
				let value = core
					.start_master(name, socket, start_deadline)
					.await
					.map_err(|error| format!("{error:#}"));
				let _ = send.send(Some(value));
				Ok(())
			})?;
			entries.insert(
				host.to_owned(),
				Entry {
					ready: receive,
					permits: Arc::new(Semaphore::new(HOST_SESSIONS)),
					generation,
					ready_deadline,
					draining: None,
				},
			);
		}
		let entry = entries
			.get(host)
			.context("observation master unavailable")?;
		Ok(Entry {
			ready: entry.ready.clone(),
			permits: entry.permits.clone(),
			generation: entry.generation,
			ready_deadline: entry.ready_deadline,
			draining: entry.draining.clone(),
		})
	}
	async fn renew(
		self: &Arc<Self>,
		host: &str,
		generation: u64,
		old: &Arc<Master>,
		deadline: Instant,
		cancel: &CancellationToken,
	) -> Result<()> {
		let mut entries = tokio::select! {
			value = timeout_at(deadline, self.masters.lock()) => value.context("observation renewal admission deadline")?,
			_ = cancel.cancelled() => bail!("observation cancelled before renewal"),
			_ = self.stop.cancelled() => bail!("observation pool stopped before renewal"),
		};
		if cancel.is_cancelled() || self.stop.is_cancelled() || Instant::now() >= deadline {
			bail!("observation cancelled or expired before renewal");
		}
		let Some(entry) = entries.get_mut(host) else {
			return Ok(());
		};
		let current = { entry.ready.borrow().clone() };
		if entry.generation != generation
			|| !matches!(current, Some(Ok(ref master)) if Arc::ptr_eq(master, old))
		{
			// An old waiter joins the installed generation; it cannot replace it.
			return Ok(());
		}
		old.accepting.store(false, Ordering::Release);
		let (send, receive) = watch::channel(None);
		let next = self.sequence.fetch_add(1, Ordering::Relaxed);
		// Shared lifecycle ownership does not extend any waiter's RPC deadline.
		let ready_deadline = Instant::now().max(old.created + AGE) + REAP + REAP + START;
		entry.ready = receive;
		entry.generation = next;
		entry.ready_deadline = ready_deadline;
		entry.draining = Some(old.clone());
		let core = self.clone();
		let name = host.to_owned();
		let previous = old.clone();
		if let Err(error) = self.background(async move {
			let value = core
				.renew_generation(&name, next, previous, ready_deadline)
				.await
				.map_err(|error| format!("{error:#}"));
			let _ = send.send(Some(value));
			Ok(())
		}) {
			self.stop.cancel();
			return Err(error);
		}
		Ok(())
	}
	async fn renew_generation(
		self: &Arc<Self>,
		host: &str,
		generation: u64,
		old: Arc<Master>,
		deadline: Instant,
	) -> Result<Arc<Master>> {
		let cleanup = async {
			while old.active.load(Ordering::Acquire) != 0 && Instant::now() < old.created + AGE {
				tokio::select! {
					_ = self.stop.cancelled() => break,
					_ = tokio::time::sleep(Duration::from_millis(20)) => {},
				}
			}
			self.stop_child(&old.owned, Duration::from_millis(200))
				.await?;
			self.release(&old.owned).await?;
			self.unlink_socket(&old)?;
			let mut entries = timeout_at(deadline, self.masters.lock())
				.await
				.context("observation renewal cleanup ledger deadline")?;
			let entry = entries
				.get_mut(host)
				.context("observation renewal ledger missing")?;
			if entry.generation != generation
				|| !entry
					.draining
					.as_ref()
					.is_some_and(|value| Arc::ptr_eq(value, &old))
			{
				bail!("observation renewal cleanup generation changed");
			}
			entry.draining = None;
			Ok::<(), anyhow::Error>(())
		}
		.await;
		if let Err(error) = cleanup {
			self.stop.cancel();
			return Err(error);
		}
		if self.stop.is_cancelled() || Instant::now() >= deadline {
			bail!("observation renewal stopped before new master");
		}
		let socket = self.root.path.join(format!(
			"m-{}",
			self.sequence.fetch_add(1, Ordering::Relaxed)
		));
		check_control_socket_path(&socket)?;
		self.start_master(
			host.to_owned(),
			socket,
			deadline.min(Instant::now() + START),
		)
		.await
	}
	async fn execute(self: Arc<Self>, request: Request, global: OwnedSemaphorePermit) {
		let result = self.clone().execute_inner(&request, global).await;
		let _ = request.reply.send(result);
	}
	async fn execute_inner(
		self: Arc<Self>,
		request: &Request,
		global: OwnedSemaphorePermit,
	) -> Result<Captured> {
		let budget = Arc::new(global);
		tokio::select! {
			value = self.verify_profile(request.deadline) => value?,
			_ = request.cancel.cancelled() => bail!("observation cancelled during admission profile check"),
			_ = self.stop.cancelled() => bail!("observation pool stopped during admission profile check"),
		};
		let (master, host, _active) = loop {
			let mut entry = self
				.entry(&request.host, &request.cancel, request.deadline)
				.await?;
			let host = tokio::select! {
				value = timeout_at(request.deadline, entry.permits.clone().acquire_owned()) => value.context("observation host capacity deadline")??,
				_ = request.cancel.cancelled() => bail!("observation request cancelled before submission"),
				_ = self.stop.cancelled() => bail!("observation pool stopped before submission"),
			};
			let ready = async {
				loop {
					let current = { entry.ready.borrow().clone() };
					if let Some(value) = current {
						return value.map_err(|error| anyhow!(error));
					}
					entry
						.ready
						.changed()
						.await
						.context("observation master initializer unavailable")?;
				}
			};
			let master = tokio::select! {
				value = timeout_at(request.deadline, ready) => value.context("observation master admission deadline")??,
				_ = request.cancel.cancelled() => bail!("observation request cancelled before submission"),
				_ = self.stop.cancelled() => bail!("observation pool stopped before submission"),
			};
			// Recheck immutable policy/credentials after queueing, before the lease.
			tokio::select! {
				value = self.verify_profile(request.deadline) => value?,
				_ = request.cancel.cancelled() => bail!("observation cancelled before lease"),
				_ = self.stop.cancelled() => bail!("observation pool stopped before lease"),
			};
			if request.cancel.is_cancelled()
				|| self.stop.is_cancelled()
				|| Instant::now() >= request.deadline
			{
				bail!("observation cancelled or expired before lease");
			}
			master.active.fetch_add(1, Ordering::AcqRel);
			// No await separates the draining/lifetime check from active ownership.
			if master.accepting.load(Ordering::Acquire) && request.deadline <= master.created + AGE
			{
				let active = ActiveMaster(master.clone());
				break (master, host, active);
			}
			master.active.fetch_sub(1, Ordering::AcqRel);
			drop(host);
			// No slave has been created. Join a single bounded admission renewal.
			self.renew(
				&request.host,
				entry.generation,
				&master,
				request.deadline,
				&request.cancel,
			)
			.await?;
		};
		master.owned.verify_live().await?;
		self.root.verify(&self.profile)?;
		if profile::socket_stamp(&master.socket)? != master.stamp {
			self.stop.cancel();
			bail!("observation master socket replaced");
		}
		let stream = timeout_at(request.deadline, UnixStream::connect(&master.socket)).await??;
		let peer = profile::peer(&stream)?;
		if peer.0 != master.owned.pid as i32
			|| peer.1 != unsafe { libc::geteuid() }
			|| profile::socket_stamp(&master.socket)? != master.stamp
		{
			self.stop.cancel();
			bail!("observation master peer changed");
		}
		drop(stream);
		let mut args = self.arguments(&request.host, Mode::Slave, &master.socket, false)?;
		args.push(request.command.clone());
		let output = self
			.captured(
				args,
				&request.input,
				request.deadline,
				&request.cancel,
				vec![budget.clone(), Arc::new(host)],
			)
			.await?;
		tokio::select! {
			value = self.verify_profile(request.deadline) => value?,
			_ = request.cancel.cancelled() => bail!("observation cancelled before response authority check"),
			_ = self.stop.cancelled() => bail!("observation pool stopped before response authority check"),
		};
		if profile::socket_stamp(&master.socket)? != master.stamp {
			self.stop.cancel();
			bail!("observation socket changed during response");
		}
		Ok(Captured {
			output,
			_budget: budget,
		})
	}
	async fn maintain(&self) -> Result<()> {
		{
			let mut tasks = self
				.background
				.lock()
				.map_err(|_| anyhow!("observation supervisor unavailable"))?;
			while let Some(result) = tasks.try_join_next() {
				result.context("observation supervisor panicked")??;
			}
		}
		let mut entries = self.masters.lock().await;
		let mut expired = Vec::new();
		for (host, entry) in entries.iter() {
			match entry.ready.borrow().as_ref() {
				Some(Ok(master)) => {
					let inactive = master.active.load(Ordering::Acquire) == 0;
					let idle = master
						.last_use
						.lock()
						.map_err(|_| anyhow!("observation master clock unavailable"))?
						.elapsed() >= IDLE;
					if master.created.elapsed() >= AGE
						|| (inactive && idle)
						|| master.owned.terminal().await?
					{
						master.accepting.store(false, Ordering::Release);
						self.stop_child(&master.owned, Duration::from_millis(200))
							.await?;
						self.release(&master.owned).await?;
						self.unlink_socket(master)?;
						// Retired masters can still have unreaped slaves or stale
						// waiters charged to this semaphore. Never replace it early.
						if master.active.load(Ordering::Acquire) == 0
							&& entry.permits.available_permits() == HOST_SESSIONS
						{
							expired.push(host.clone());
						}
					}
				}
				Some(Err(_)) => {
					if entry.draining.is_some() {
						bail!("observation renewal cleanup unresolved; reconciliation required");
					}
					if entry.permits.available_permits() == HOST_SESSIONS {
						expired.push(host.clone());
					}
				}
				None if Instant::now() > entry.ready_deadline => {
					bail!("observation master initialization did not finish")
				}
				None => {}
			}
		}
		for host in expired {
			entries.remove(&host);
		}
		Ok(())
	}
	fn unlink_socket(&self, master: &Master) -> Result<()> {
		self.root.verify(&self.profile)?;
		match profile::socket_stamp(&master.socket) {
			Ok(stamp) if stamp == master.stamp => {
				let name = std::ffi::CString::new(
					master
						.socket
						.file_name()
						.context("observation socket name missing")?
						.as_encoded_bytes(),
				)?;
				if unsafe { libc::unlinkat(self.root.directory.as_raw_fd(), name.as_ptr(), 0) } != 0
				{
					return Err(std::io::Error::last_os_error().into());
				}
			}
			Err(_)
				if std::fs::symlink_metadata(&master.socket)
					.is_err_and(|v| v.kind() == std::io::ErrorKind::NotFound) => {}
			_ => bail!("observation socket cleanup identity uncertain; reconciliation required"),
		}
		Ok(())
	}
	fn reap_completed_requests(work: &mut JoinSet<()>) -> Result<()> {
		while let Some(result) = work.try_join_next() {
			result.map_err(|error| anyhow!("observation request supervisor failed: {error}"))?;
		}
		Ok(())
	}
	async fn run(self: Arc<Self>, receiver: mpsc::Receiver<Request>) -> Result<()> {
		self.run_with_capacity(receiver, Arc::new(Semaphore::new(MAX_SESSIONS)))
			.await
	}
	async fn run_with_capacity(
		self: Arc<Self>,
		mut receiver: mpsc::Receiver<Request>,
		global: Arc<Semaphore>,
	) -> Result<()> {
		let mut work = JoinSet::new();
		let mut reservation = None;
		let mut tick = tokio::time::interval(Duration::from_millis(100));
		let outcome = loop {
			tokio::select! {
				_ = self.stop.cancelled() => break Ok(()),
				_ = tick.tick() => { if let Err(error) = self.maintain().await { break Err(error); } },
				Some(result) = work.join_next(), if !work.is_empty() => {
					if let Err(error) = result { break Err(anyhow!("observation request supervisor failed: {error}")); }
				},
				permit = global.clone().acquire_owned(), if reservation.is_none() && work.len() < MAX_SESSIONS => {
					match permit {
						Ok(permit) => reservation = Some(permit),
						Err(_) => break Err(anyhow!("observation global capacity closed")),
					}
				},
				// Leave bounded requests in the channel until both a supervisor
				// slot and the output budget exist. A completed Captured can still
				// own that budget; its drop directly wakes acquire_owned above.
				request = receiver.recv(), if reservation.is_some() && work.len() < MAX_SESSIONS => {
					let Some(request) = request else { break Ok(()); };
					if request.cancel.is_cancelled() || request.reply.is_closed() || Instant::now() >= request.deadline {
						let _ = request.reply.send(Err(anyhow!("observation cancelled before admission")));
						continue;
					}
					// Completed replies may leave unjoined tasks when select chose
					// this receiver. They are not live supervisors or new capacity.
					if let Err(error) = Self::reap_completed_requests(&mut work) {
						break Err(error);
					}
					let Some(permit) = reservation.take() else {
						break Err(anyhow!("observation admission reservation unavailable"));
					};
					work.spawn(self.clone().execute(request, permit));
				}
			}
		};
		self.stop.cancel();
		receiver.close();
		while let Ok(request) = receiver.try_recv() {
			let _ = request
				.reply
				.send(Err(anyhow!("observation pool stopped before admission")));
		}
		while let Some(result) = work.join_next().await {
			result.context("observation request supervisor failed during shutdown")?;
		}
		outcome
	}
	async fn shutdown(&self) -> Result<()> {
		self.stop.cancel();
		let mut uncertain = false;
		let mut background = {
			let mut guard = self
				.background
				.lock()
				.map_err(|_| anyhow!("observation supervisor unavailable"))?;
			std::mem::take(&mut *guard)
		};
		while let Some(result) = background.join_next().await {
			if !matches!(result, Ok(Ok(()))) {
				uncertain = true;
			}
		}
		let children: Vec<_> = self.children.lock().await.values().cloned().collect();
		for child in children {
			if self
				.stop_child(&child, Duration::from_millis(200))
				.await
				.is_err() || self.release(&child).await.is_err()
			{
				uncertain = true;
			}
		}
		if uncertain || !self.children.lock().await.is_empty() {
			bail!("observation child cleanup incomplete; reconciliation required");
		}
		let mut entries = self.masters.lock().await;
		for entry in entries.values() {
			if let Some(master) = &entry.draining {
				self.unlink_socket(master)?;
			}
			if let Some(Ok(master)) = entry.ready.borrow().as_ref() {
				self.unlink_socket(master)?;
			}
		}
		entries.clear();
		self.root.verify(&self.profile)?;
		// Unknown entries are never recursively removed or adopted.
		std::fs::remove_dir(&self.root.path)
			.context("observation private root not empty; reconciliation required")?;
		Ok(())
	}
}

#[cfg(test)]
#[path = "ssh_observation_pool_tests.rs"]
mod tests;
