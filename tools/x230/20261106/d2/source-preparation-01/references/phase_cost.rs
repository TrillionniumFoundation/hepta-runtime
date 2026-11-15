// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Explicit Linux-only diagnostic capture; never an authority or cleanup owner.
//!
//! Synchronous CPU spans cannot be Send and must not contain an await.
//! Async spans are wall time only. Inclusive nesting is preserved in raw rows.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::json;
use std::cell::Cell;
use std::ffi::{CString, OsStr};
use std::future::Future;
use std::io::{self, BufWriter, Read, Write};
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

const EVENT_CAPACITY: usize = 32_768;
const REQUEST_CAPACITY: usize = 2_048;
const NATIVE_ID_BYTES: usize = 128;
const OUTPUT_LIMIT: u64 = 32 * 1024 * 1024;
const MODE_ENV: &str = "HEPTA_RUNTIME_PHASE_COST_MODE";
const OUTPUT_ENV: &str = "HEPTA_RUNTIME_PHASE_COST_OUTPUT";
const ELF_ENV: &str = "HEPTA_RUNTIME_PHASE_COST_ELF_SHA256";

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
	Request,
	RouterBuild,
	NativeAuditBegin,
	NativeAuditFinish,
	CheckJobReference,
	PrepareObservation,
	DecodeObservation,
	EncodeObservation,
	LogicalAdmission,
	QueueReservation,
	QueueSubmitted,
	QueueReceived,
	InitialCapacityGranted,
	OwnerExecute,
	AdmissionProfile,
	HostCapacity,
	GlobalCapacity,
	MasterEntry,
	MasterReady,
	PreCaptureProfile,
	PostCaptureProfile,
	ValidationPermit,
	ValidationBlockingQueue,
	ValidationWorker,
	ValidationOwner,
	AgentSnapshot,
	SocketAndBoundary,
	SocketConnect,
	Arguments,
	ExpectedArgv,
	ChildRegistry,
	Spawn,
	PostExecProof,
	ProcessIdentity,
	Capture,
	StdinWrite,
	StdoutDrain,
	StderrDrain,
	ChildWait,
	AuditPrepare,
	AuditPermit,
	AuditBlockingQueue,
	AuditMutex,
	AuditCritical,
	AuditWrite,
	AuditSync,
	Binding,
}

#[derive(Clone, Copy, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Detail {
	DeadlineBudget {
		remaining_ns: Option<u64>,
		expired: bool,
	},
	MasterLease {
		generation: u64,
		child_id: u64,
		pid: u32,
		birth_ticks: Option<u64>,
	},
	ChildProof {
		child_id: u64,
		pid: u32,
		birth_ticks: Option<u64>,
	},
	ChildReaped {
		child_id: u64,
		pid: u32,
		birth_ticks: Option<u64>,
	},
	CaptureBytes {
		stdin: usize,
		stdout: usize,
		stderr: usize,
	},
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum End {
	BoundaryReached,
	SynchronousScopeExit,
	Abandoned,
}

#[derive(Serialize)]
struct Event {
	span: u64,
	request: usize,
	phase: Phase,
	end: End,
	start_monotonic_ns: u64,
	end_monotonic_ns: u64,
	start_tid: u32,
	end_tid: u32,
	thread_cpu_start_ns: Option<u64>,
	thread_cpu_end_ns: Option<u64>,
	parent_sync_span: u64,
	#[serde(skip_serializing_if = "Option::is_none")]
	detail: Option<Detail>,
}

struct NativeId {
	bytes: [u8; NATIVE_ID_BYTES],
	len: usize,
}

struct RequestMeta {
	operation: &'static str,
	host: Option<usize>,
	native_id: OnceLock<NativeId>,
}

struct Slots<T> {
	rows: Box<[OnceLock<T>]>,
	next: AtomicUsize,
	dropped: AtomicUsize,
}

impl<T> Slots<T> {
	fn new(capacity: usize) -> Self {
		Self {
			rows: std::iter::repeat_with(OnceLock::new)
				.take(capacity)
				.collect(),
			next: AtomicUsize::new(0),
			dropped: AtomicUsize::new(0),
		}
	}

	fn push(&self, value: T) -> Option<usize> {
		let index = match self
			.next
			.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
		{
			Ok(index) => index,
			Err(_) => {
				self.dropped.fetch_add(1, Ordering::SeqCst);
				return None;
			}
		};
		if let Some(slot) = self.rows.get(index) {
			if slot.set(value).is_ok() {
				return Some(index);
			}
		}
		self.dropped.fetch_add(1, Ordering::SeqCst);
		None
	}
}

struct Recorder {
	enabled: bool,
	accepting: AtomicBool,
	active: AtomicUsize,
	sequence: AtomicU64,
	errors: AtomicUsize,
	abandoned: AtomicUsize,
	completed_requests: AtomicUsize,
	events: Slots<Event>,
	requests: Slots<RequestMeta>,
	hosts: Vec<String>,
}

static RECORDER: OnceLock<Recorder> = OnceLock::new();

#[derive(Clone, Copy, Default)]
pub(crate) struct TraceContext(Option<usize>);

tokio::task_local! {
	static CURRENT: TraceContext;
}

thread_local! {
	static SYNC_PARENT: Cell<u64> = const { Cell::new(0) };
}

fn recorder() -> Option<&'static Recorder> {
	RECORDER.get().filter(|recorder| recorder.enabled)
}

fn enter(recorder: &Recorder) -> bool {
	if !recorder.accepting.load(Ordering::SeqCst) {
		return false;
	}
	recorder.active.fetch_add(1, Ordering::SeqCst);
	if !recorder.accepting.load(Ordering::SeqCst) {
		recorder.active.fetch_sub(1, Ordering::SeqCst);
		return false;
	}
	true
}

impl TraceContext {
	pub(crate) fn request(operation: &str, host: Option<&str>) -> Self {
		let operation = match operation {
			"process_status" => "process_status",
			"process_read" => "process_read",
			_ => return Self::default(),
		};
		let Some(recorder) = recorder() else {
			return Self::default();
		};
		if !enter(recorder) {
			return Self::default();
		}
		let host = host.and_then(|name| recorder.hosts.iter().position(|alias| alias == name));
		let index = recorder.requests.push(RequestMeta {
			operation,
			host,
			native_id: OnceLock::new(),
		});
		recorder.active.fetch_sub(1, Ordering::SeqCst);
		Self(index)
	}
}

pub(crate) fn current() -> TraceContext {
	CURRENT.try_with(|value| *value).unwrap_or_default()
}

pub(crate) async fn in_context<F: Future>(context: TraceContext, future: F) -> F::Output {
	CURRENT.scope(context, future).await
}

pub(crate) fn with_context<T>(context: TraceContext, work: impl FnOnce() -> T) -> T {
	CURRENT.sync_scope(context, work)
}

pub(crate) fn bind_native_id(id: &str) {
	let (Some(recorder), Some(request)) = (recorder(), current().0) else {
		return;
	};
	if !enter(recorder) {
		return;
	}
	let ok = if id.is_empty()
		|| id.len() > NATIVE_ID_BYTES
		|| !id.is_ascii()
		|| id.bytes().any(|b| b.is_ascii_control())
	{
		false
	} else if let Some(metadata) = recorder.requests.rows.get(request).and_then(OnceLock::get) {
		let mut bytes = [0; NATIVE_ID_BYTES];
		bytes[..id.len()].copy_from_slice(id.as_bytes());
		metadata
			.native_id
			.set(NativeId {
				bytes,
				len: id.len(),
			})
			.is_ok()
	} else {
		false
	};
	if !ok {
		recorder.errors.fetch_add(1, Ordering::SeqCst);
	}
	recorder.active.fetch_sub(1, Ordering::SeqCst);
}

fn clock_ns(clock: libc::clockid_t) -> Option<u64> {
	let mut stamp = libc::timespec {
		tv_sec: 0,
		tv_nsec: 0,
	};
	if unsafe { libc::clock_gettime(clock, &mut stamp) } != 0
		|| stamp.tv_sec < 0
		|| !(0..1_000_000_000).contains(&stamp.tv_nsec)
	{
		return None;
	}
	u64::try_from(stamp.tv_sec)
		.ok()?
		.checked_mul(1_000_000_000)?
		.checked_add(u64::try_from(stamp.tv_nsec).ok()?)
}

fn tid() -> u32 {
	// Linux exposes the calling thread identity; no new /proc inspection.
	unsafe { libc::syscall(libc::SYS_gettid) as u32 }
}

struct Span {
	recorder: &'static Recorder,
	event: Option<Event>,
}

impl Span {
	fn start(phase: Phase, synchronous: bool) -> Option<Self> {
		let (Some(recorder), Some(request)) = (recorder(), current().0) else {
			return None;
		};
		if !enter(recorder) {
			return None;
		}
		let wall = clock_ns(libc::CLOCK_MONOTONIC);
		let cpu = if synchronous {
			clock_ns(libc::CLOCK_THREAD_CPUTIME_ID)
		} else {
			None
		};
		let sequence =
			recorder
				.sequence
				.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
					value.checked_add(1)
				});
		let (Some(wall), Ok(span)) = (wall, sequence) else {
			recorder.errors.fetch_add(1, Ordering::SeqCst);
			recorder.active.fetch_sub(1, Ordering::SeqCst);
			return None;
		};
		if synchronous && cpu.is_none() {
			recorder.errors.fetch_add(1, Ordering::SeqCst);
			recorder.active.fetch_sub(1, Ordering::SeqCst);
			return None;
		}
		let thread = tid();
		Some(Self {
			recorder,
			event: Some(Event {
				span,
				request,
				phase,
				end: End::Abandoned,
				start_monotonic_ns: wall,
				end_monotonic_ns: wall,
				start_tid: thread,
				end_tid: thread,
				thread_cpu_start_ns: cpu,
				thread_cpu_end_ns: cpu,
				parent_sync_span: if synchronous {
					SYNC_PARENT.with(Cell::get)
				} else {
					0
				},
				detail: None,
			}),
		})
	}

	fn finish(&mut self, end: End) {
		let Some(mut event) = self.event.take() else {
			return;
		};
		event.end = end;
		event.end_tid = tid();
		let wall = clock_ns(libc::CLOCK_MONOTONIC);
		let cpu = if event.thread_cpu_start_ns.is_some() {
			clock_ns(libc::CLOCK_THREAD_CPUTIME_ID)
		} else {
			None
		};
		if wall.is_none_or(|value| value < event.start_monotonic_ns)
			|| (event.thread_cpu_start_ns.is_some()
				&& (cpu.is_none() || event.start_tid != event.end_tid))
			|| cpu
				.zip(event.thread_cpu_start_ns)
				.is_some_and(|(end, start)| end < start)
		{
			self.recorder.errors.fetch_add(1, Ordering::SeqCst);
		}
		event.end_monotonic_ns = wall.unwrap_or(event.start_monotonic_ns);
		event.thread_cpu_end_ns = cpu;
		if end == End::Abandoned {
			self.recorder.abandoned.fetch_add(1, Ordering::SeqCst);
		}
		self.recorder.events.push(event);
		self.recorder.active.fetch_sub(1, Ordering::SeqCst);
	}
}

impl Drop for Span {
	fn drop(&mut self) {
		self.finish(End::Abandoned);
	}
}

pub(crate) struct WallSpan(Span);

pub(crate) fn wall_span(phase: Phase) -> Option<WallSpan> {
	Span::start(phase, false).map(WallSpan)
}

pub(crate) fn finish_span(span: Option<WallSpan>) {
	if let Some(mut span) = span {
		span.0.finish(End::BoundaryReached);
	}
}

pub(crate) async fn wall_future<F: Future>(phase: Phase, future: F) -> F::Output {
	let span = wall_span(phase);
	let value = future.await;
	finish_span(span);
	value
}

pub(crate) async fn request_scope<F: Future>(context: TraceContext, future: F) -> F::Output {
	in_context(context, async move {
		let span = wall_span(Phase::Request);
		let value = future.await;
		if span.is_some() {
			if let Some(recorder) = recorder() {
				recorder.completed_requests.fetch_add(1, Ordering::SeqCst);
			}
		}
		finish_span(span);
		value
	})
	.await
}

pub(crate) struct SyncSpan {
	span: Span,
	previous: u64,
	id: u64,
	_not_send: PhantomData<Rc<()>>,
}

pub(crate) fn sync_span(phase: Phase) -> Option<SyncSpan> {
	let span = Span::start(phase, true)?;
	let event = span.event.as_ref()?;
	let id = event.span;
	let previous = event.parent_sync_span;
	SYNC_PARENT.with(|parent| parent.set(id));
	Some(SyncSpan {
		span,
		previous,
		id,
		_not_send: PhantomData,
	})
}

impl Drop for SyncSpan {
	fn drop(&mut self) {
		SYNC_PARENT.with(|parent| {
			if parent.replace(self.previous) != self.id {
				self.span.recorder.errors.fetch_add(1, Ordering::SeqCst);
			}
		});
		self.span.finish(End::SynchronousScopeExit);
	}
}

pub(crate) fn mark(phase: Phase) {
	finish_span(wall_span(phase));
}

pub(crate) fn annotate(detail: Detail) {
	if let Some(mut span) = wall_span(Phase::Binding) {
		if let Some(event) = span.0.event.as_mut() {
			event.detail = Some(detail);
		}
		finish_span(Some(span));
	}
}

pub(crate) fn deadline_budget(remaining: Option<Duration>) {
	annotate(Detail::DeadlineBudget {
		remaining_ns: remaining.and_then(|value| u64::try_from(value.as_nanos()).ok()),
		expired: remaining.is_none_or(|value| value.is_zero()),
	});
}

struct BoundedFile {
	file: std::fs::File,
	written: u64,
}

impl Write for BoundedFile {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		if u64::try_from(bytes.len())
			.ok()
			.and_then(|count| self.written.checked_add(count))
			.is_none_or(|end| end > OUTPUT_LIMIT)
		{
			return Err(io::Error::other("diagnostic output limit reached"));
		}
		let count = self.file.write(bytes)?;
		self.written += count as u64;
		Ok(count)
	}

	fn flush(&mut self) -> io::Result<()> {
		self.file.flush()
	}
}

struct Output {
	path: PathBuf,
	parent: std::fs::File,
	writer: Option<BufWriter<BoundedFile>>,
}

fn open_at(
	directory: &std::fs::File,
	name: &OsStr,
	flags: i32,
	mode: libc::mode_t,
) -> Result<std::fs::File> {
	let name = CString::new(name.as_bytes())?;
	let fd = unsafe {
		libc::openat(
			directory.as_raw_fd(),
			name.as_ptr(),
			flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
			mode,
		)
	};
	if fd < 0 {
		return Err(io::Error::last_os_error()).context("diagnostic openat failed");
	}
	Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

fn open_parent(path: &Path) -> Result<(std::fs::File, &OsStr)> {
	if !path.is_absolute()
		|| path.as_os_str().as_bytes().len() > 4096
		|| path.as_os_str().as_bytes().ends_with(b"/")
	{
		bail!("diagnostic output must be a bounded absolute file path");
	}
	let mut parts = path.components();
	if parts.next() != Some(Component::RootDir) {
		bail!("diagnostic output must start at the filesystem root");
	}
	let root = CString::new("/")?;
	let fd = unsafe {
		libc::open(
			root.as_ptr(),
			libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
		)
	};
	if fd < 0 {
		return Err(io::Error::last_os_error()).context("diagnostic root open failed");
	}
	let mut parent = unsafe { std::fs::File::from_raw_fd(fd) };
	let mut parts = parts.peekable();
	while let Some(part) = parts.next() {
		let Component::Normal(name) = part else {
			bail!("diagnostic path contains a non-normal component")
		};
		if parts.peek().is_none() {
			let meta = parent.metadata()?;
			if !meta.is_dir()
				|| meta.uid() != unsafe { libc::geteuid() }
				|| meta.mode() & 0o7777 != 0o700
			{
				bail!("diagnostic output parent must be owned mode 0700");
			}
			return Ok((parent, name));
		}
		parent = open_at(
			&parent,
			name,
			libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK,
			0,
		)?;
	}
	bail!("diagnostic output has no filename")
}

fn same_object(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
	left.dev() == right.dev()
		&& left.ino() == right.ino()
		&& left.uid() == right.uid()
		&& left.gid() == right.gid()
		&& left.mode() == right.mode()
}

impl Output {
	fn create(path: &Path) -> Result<Self> {
		let (parent, name) = open_parent(path)?;
		let file = open_at(
			&parent,
			name,
			libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NONBLOCK,
			0o600,
		)?;
		let meta = file.metadata()?;
		if !meta.is_file()
			|| meta.uid() != unsafe { libc::geteuid() }
			|| meta.nlink() != 1
			|| meta.mode() & 0o7777 != 0o600
			|| meta.size() != 0
		{
			bail!("diagnostic output is not an empty owned private regular file");
		}
		Ok(Self {
			path: path.to_owned(),
			parent,
			writer: Some(BufWriter::with_capacity(
				64 * 1024,
				BoundedFile { file, written: 0 },
			)),
		})
	}

	fn line<T: Serialize>(&mut self, value: &T) -> Result<()> {
		let writer = self
			.writer
			.as_mut()
			.context("diagnostic writer already closed")?;
		serde_json::to_writer(&mut *writer, value)?;
		writer.write_all(b"\n")?;
		Ok(())
	}

	fn verify(&self) -> Result<()> {
		let writer = self
			.writer
			.as_ref()
			.context("diagnostic writer already closed")?
			.get_ref();
		let (parent, name) = open_parent(&self.path)?;
		let named = open_at(&parent, name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
		let held = writer.file.metadata()?;
		let current = named.metadata()?;
		if !same_object(&parent.metadata()?, &self.parent.metadata()?)
			|| !same_object(&held, &current)
			|| !held.is_file()
			|| held.nlink() != 1
			|| current.nlink() != 1
			|| held.mode() & 0o7777 != 0o600
			|| held.size() != writer.written
			|| current.size() != writer.written
		{
			bail!("diagnostic output binding changed");
		}
		Ok(())
	}

	fn sync(&mut self) -> Result<()> {
		self.verify()?;
		let writer = self
			.writer
			.as_mut()
			.context("diagnostic writer already closed")?;
		writer.flush()?;
		writer.get_ref().file.sync_all()?;
		self.parent.sync_all()?;
		self.verify()
	}
}

impl Drop for Output {
	fn drop(&mut self) {
		// Never let BufWriter::drop retry a failed or unrequested write.
		// Explicit sync is the only flush boundary; retained partial bytes stay.
		if let Some(writer) = self.writer.take() {
			let (_file, _buffer) = writer.into_parts();
		}
	}
}

fn bounded_text(path: &Path, limit: usize) -> Result<String> {
	let mut file = std::fs::File::open(path)?;
	let mut bytes = Vec::new();
	std::io::Read::by_ref(&mut file)
		.take((limit + 1) as u64)
		.read_to_end(&mut bytes)?;
	if bytes.len() > limit {
		bail!("diagnostic process identity exceeds bound");
	}
	Ok(String::from_utf8(bytes)?)
}

/// Opens the diagnostic sink before child startup. No request can enable it.
pub fn start_from_env(
	runtime_enabled: bool,
	observation_profile: bool,
	stdio: bool,
) -> Result<Option<Guard>> {
	let Some(mode) = std::env::var_os(MODE_ENV) else {
		if std::env::var_os(OUTPUT_ENV).is_some() || std::env::var_os(ELF_ENV).is_some() {
			bail!("diagnostic output or ELF identity requires an explicit diagnostic mode");
		}
		return Ok(None);
	};
	let enabled = match mode.to_str() {
		Some("on") => true,
		Some("off") => false,
		_ => bail!("diagnostic mode must be on or off"),
	};
	if !runtime_enabled || !observation_profile || !stdio {
		bail!("phase diagnostics require explicit runtime, observation pool, and stdio");
	}
	if RECORDER.get().is_some() {
		bail!("phase diagnostic startup may occur only once");
	}
	let path = std::env::var_os(OUTPUT_ENV).context("diagnostic output is required")?;
	let elf = std::env::var(ELF_ENV).context("diagnostic ELF SHA256 is required")?;
	if elf.len() != 64
		|| !elf
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
	{
		bail!("diagnostic ELF SHA256 must be 64 lowercase hexadecimal digits");
	}
	let hosts = super::config::runtime_config()?
		.hosts
		.keys()
		.cloned()
		.collect::<Vec<_>>();
	if hosts.len() > 64 || hosts.iter().any(|name| name.len() > 128) {
		bail!("diagnostic host table exceeds its explicit bound");
	}
	let recorder = Recorder {
		enabled,
		accepting: AtomicBool::new(true),
		active: AtomicUsize::new(0),
		sequence: AtomicU64::new(1),
		errors: AtomicUsize::new(0),
		abandoned: AtomicUsize::new(0),
		completed_requests: AtomicUsize::new(0),
		events: Slots::new(EVENT_CAPACITY),
		requests: Slots::new(REQUEST_CAPACITY),
		hosts,
	};
	let stat = bounded_text(Path::new("/proc/self/stat"), 8192)?;
	let tail = stat
		.rsplit_once(") ")
		.context("diagnostic /proc identity parse failed")?
		.1;
	let start_ticks: u64 = tail
		.split_whitespace()
		.nth(19)
		.context("diagnostic birth identity missing")?
		.parse()?;
	let boot = bounded_text(Path::new("/proc/sys/kernel/random/boot_id"), 128)?;
	let start_ns =
		clock_ns(libc::CLOCK_MONOTONIC).context("diagnostic monotonic clock unavailable")?;
	let mut output = Output::create(Path::new(&path))?;
	output.line(&json!({
		"type": "header", "schema": "hepta-phase-cost-trace/v1",
		"preparation_revision": "recovery-02",
		"mode": if enabled { "on" } else { "off" },
		"pid": std::process::id(), "start_ticks": start_ticks, "boot_id": boot.trim(),
		"start_monotonic_ns": start_ns, "wall_clock": "CLOCK_MONOTONIC",
		"cpu_clock": "CLOCK_THREAD_CPUTIME_ID", "declared_elf_sha256": elf,
		"elf_hash_verified_here": false, "host_aliases": recorder.hosts,
		"event_capacity": EVENT_CAPACITY, "request_capacity": REQUEST_CAPACITY,
		"event_slot_bytes": std::mem::size_of::<OnceLock<Event>>(),
		"request_slot_bytes": std::mem::size_of::<OnceLock<RequestMeta>>(),
		"logical_event_slot_bytes": EVENT_CAPACITY * std::mem::size_of::<OnceLock<Event>>(),
		"logical_request_slot_bytes": REQUEST_CAPACITY * std::mem::size_of::<OnceLock<RequestMeta>>(),
		"memory_accounting": "logical Rust slot sizes, excludes allocator/host table/RSS",
		"output_limit": OUTPUT_LIMIT,
		"operations": ["process_status", "process_read"],
		"cpu_scope": "synchronous lexical spans only; inclusive nesting",
		"wall_scope": "overlapping wall spans; never additive by default",
		"background_unattributed": true, "ssh_child_cpu_measured": false,
		"remote_cpu_measured": false, "pure_network_delay_measured": false,
		"boundary_reached_is_effect_success": false,
		"performance_acceptance_claim": false
	}))?;
	output.sync()?;
	if RECORDER.set(recorder).is_err() {
		bail!("diagnostic recorder publication raced another startup");
	}
	Ok(Some(Guard {
		output: Some(output),
	}))
}

pub struct Guard {
	output: Option<Output>,
}

impl Guard {
	fn close(
		&mut self,
		owners_joined: bool,
		transport_returned_ok: bool,
		early_drop: bool,
	) -> Result<()> {
		let Some(mut output) = self.output.take() else {
			return Ok(());
		};
		let recorder = RECORDER.get().context("diagnostic recorder missing")?;
		recorder.accepting.store(false, Ordering::SeqCst);
		let active = recorder.active.load(Ordering::SeqCst);
		let mut requests = 0usize;
		let mut native_bound = 0usize;
		for (slot, metadata) in recorder.requests.rows.iter().enumerate() {
			if let Some(metadata) = metadata.get() {
				requests += 1;
				let native = metadata
					.native_id
					.get()
					.map(|id| std::str::from_utf8(&id.bytes[..id.len]))
					.transpose()?;
				if native.is_some() {
					native_bound += 1;
				}
				output.line(&json!({
					"type": "request", "slot": slot, "operation": metadata.operation,
					"host_index": metadata.host, "native_request_id": native
				}))?;
			}
		}
		let mut events = 0usize;
		for (slot, event) in recorder.events.rows.iter().enumerate() {
			if let Some(event) = event.get() {
				events += 1;
				output.line(&json!({"type": "event", "slot": slot, "event": event}))?;
			}
		}
		let request_reserved = recorder.requests.next.load(Ordering::SeqCst);
		let event_reserved = recorder.events.next.load(Ordering::SeqCst);
		let request_dropped = recorder.requests.dropped.load(Ordering::SeqCst);
		let event_dropped = recorder.events.dropped.load(Ordering::SeqCst);
		let end_ns = clock_ns(libc::CLOCK_MONOTONIC);
		if end_ns.is_none() {
			recorder.errors.fetch_add(1, Ordering::SeqCst);
		}
		let errors = recorder.errors.load(Ordering::SeqCst);
		let abandoned = recorder.abandoned.load(Ordering::SeqCst);
		let completed = recorder.completed_requests.load(Ordering::SeqCst);
		let complete = active == 0
			&& errors == 0
			&& abandoned == 0
			&& request_dropped == 0
			&& event_dropped == 0
			&& request_reserved == requests
			&& event_reserved == events
			&& native_bound == requests
			&& completed == requests
			&& owners_joined
			&& transport_returned_ok
			&& !early_drop;
		output.line(&json!({
			"type": "footer", "schema": "hepta-phase-cost-trace/v1",
			"end_monotonic_ns": end_ns,
			"active_at_freeze": active, "request_rows": requests, "event_rows": events,
			"request_reserved": request_reserved, "event_reserved": event_reserved,
			"request_dropped": request_dropped, "event_dropped": event_dropped,
			"errors": errors, "abandoned_spans": abandoned,
			"native_ids_bound": native_bound, "completed_request_scopes": completed,
			"owners_joined": owners_joined, "transport_returned_ok": transport_returned_ok,
			"early_drop": early_drop,
			"trace_window_complete": if recorder.enabled { Some(complete) } else { None },
			"native_request_success_asserted": false,
			"external_original_terminal_and_identity_required": true,
			"late_work_after_freeze_is_not_accounted": true,
			"performance_acceptance_claim": false
		}))?;
		output.sync()?;
		if recorder.enabled && !complete {
			bail!("phase diagnostic window incomplete; raw evidence retained");
		}
		Ok(())
	}

	pub fn finish(mut self, owners_joined: bool, transport_returned_ok: bool) -> Result<()> {
		self.close(owners_joined, transport_returned_ok, false)
	}
}

impl Drop for Guard {
	fn drop(&mut self) {
		// Never mask the original startup/transport error or become its cleanup.
		let _ = self.close(false, false, true);
	}
}

#[cfg(test)]
#[path = "phase_cost_tests.rs"]
mod phase_cost_tests;
