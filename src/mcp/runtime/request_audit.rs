// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Private ownership-scoped request metadata. Unknown durable intent precedes dispatch;
//! an audit completion failure never proves that an operation failed or can be retried.
use anyhow::{anyhow, bail, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[cfg(unix)]
use std::collections::HashSet;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use tokio::sync::Semaphore;

use super::config::runtime_config;

#[path = "request_audit_trace.rs"]
pub(super) mod trace;

const MAX_GLOBAL: usize = 512;
const MAX_OWNER: usize = 128;
const MAX_RECORD_BYTES: usize = 2048;
const MAX_PAGE_BYTES: usize = 64 * 1024;
#[cfg(unix)]
const MAX_METADATA_QUERIES: usize = 8;
#[cfg(unix)]
static METADATA_QUERY_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
const STORE_NAME: &str = "request-audit";
const ARCHIVE_NAME: &str = "request-archive-v11";
const ARCHIVE_ANCHOR: &str = ".request-archive-v11-anchor.json";
static STORE_LOCK: OnceLock<AuditStoreLock> = OnceLock::new();
static ACTIVE: OnceLock<Mutex<HashMap<String, Weak<AtomicBool>>>> = OnceLock::new();
static READ_PINS: OnceLock<Mutex<HashMap<String, Vec<Weak<()>>>>> = OnceLock::new();
#[cfg(unix)]
#[path = "request_archive_store.rs"]
mod archive_store;
#[cfg(unix)]
#[path = "request_audit_batch.rs"]
mod batch;
#[cfg(unix)]
#[path = "request_archive_index.rs"]
mod index;
#[cfg(unix)]
#[path = "request_audit_stage.rs"]
mod stage;
#[cfg(unix)]
use archive_store::Archive;
#[cfg(not(unix))]
type Archive = File;
#[cfg(unix)]
static HOT_CACHE: OnceLock<Mutex<VecDeque<HotSnapshot>>> = OnceLock::new();

#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct ArchiveStamp {
	device: u64,
	inode: u64,
	modified: (i64, i64),
	changed: (i64, i64),
	namespace: super::namespace_version::Version,
}
#[cfg(unix)]
struct HotSnapshot {
	stamp: ArchiveStamp,
	records: Vec<Record>,
}
#[cfg(unix)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArchiveAnchor {
	root_device: u64,
	root_inode: u64,
	archive_device: u64,
	archive_inode: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum AuditCompletion {
	/// Successful dispatch response, not confirmed delivery or business success.
	Completed,
	/// Dispatch rejection/failure, never proof that a side effect did not occur.
	Failed,
	/// Completion or possible side effects cannot be reliably classified.
	Unknown,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestHistoryParams {
	/// Last returned request id. Expired and other-owner cursors are refused.
	#[serde(default)]
	pub after_id: Option<String>,
	/// At most 32 metadata records; default 32. No parameters or output are returned.
	#[serde(default)]
	pub limit: Option<u16>,
}

#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UsageStatsParams {}

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DurableState {
	Unknown,
	Completed,
	Failed,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
	request_id: String,
	owner: String,
	tool_name: String,
	state: DurableState,
	accepted_unix_ms: u128,
	elapsed_ms: Option<u64>,
}

/// The private owner and state-directory handle are deliberately not printable.
pub struct RequestTicket {
	directory: File,
	archive: Archive,
	hot_present: bool,
	record: Record,
	started: Instant,
	active: Arc<AtomicBool>,
	_read_pin: Option<Arc<()>>,
}

impl RequestTicket {
	pub fn request_id(&self) -> &str {
		&self.record.request_id
	}
}
#[derive(Clone)]
pub(crate) struct RequestIdentity {
	pub request_id: String,
	pub owner: String,
	pub tool_name: String,
	pub accepted_unix_ms: u128,
}
pub(crate) struct AuditObservation {
	pub identity: RequestIdentity,
	pub state: &'static str,
	pub elapsed_ms: Option<u64>,
}
impl RequestTicket {
	pub(crate) fn identity(&self) -> RequestIdentity {
		RequestIdentity {
			request_id: self.record.request_id.clone(),
			owner: self.record.owner.clone(),
			tool_name: self.record.tool_name.clone(),
			accepted_unix_ms: self.record.accepted_unix_ms,
		}
	}
}
#[cfg(unix)]
pub(crate) fn validate_identity_at(root: &Path, identity: &RequestIdentity) -> Result<()> {
	let observed = optional_observation_at(root, &identity.owner, &identity.request_id)?
		.ok_or_else(|| anyhow!("result admission unavailable"))?;
	if observed.identity.tool_name != identity.tool_name
		|| observed.identity.accepted_unix_ms != identity.accepted_unix_ms
	{
		bail!("result admission unavailable");
	}
	Ok(())
}
#[cfg(unix)]
fn observation_at(root: &Path, owner: &str, id: &str) -> Result<AuditObservation> {
	optional_observation_at(root, owner, id)?
		.ok_or_else(|| anyhow!("request unavailable to this scope"))
}
#[cfg(not(unix))]
pub(crate) fn validate_identity_at(_root: &Path, _identity: &RequestIdentity) -> Result<()> {
	bail!("private request metadata requires Unix");
}
#[cfg(not(unix))]
fn observation_at(_root: &Path, _owner: &str, _id: &str) -> Result<AuditObservation> {
	bail!("private request metadata requires Unix");
}
pub(crate) async fn observation(owner: &str, id: &str) -> Result<AuditObservation> {
	let root = runtime_config()?.state_dir.clone();
	let owner = owner.to_owned();
	let id = id.to_owned();
	tokio::task::spawn_blocking(move || observation_at(&root, &owner, &id))
		.await
		.map_err(|_| anyhow!("request unavailable to this scope"))?
}

/// V9 admission may durably reserve an identity before creating its audit record.
/// Only an absent record is optional; corrupt, unsafe or foreign records refuse.
#[cfg(unix)]
fn optional_observation_at(root: &Path, owner: &str, id: &str) -> Result<Option<AuditObservation>> {
	if !valid_id(owner) || !valid_id(id) {
		bail!("request unavailable to this scope");
	}
	let _guard = store_lock()?;
	let dir = open_store(root)?;
	let archive = open_archive(root).map_err(|_| anyhow!("request unavailable to this scope"))?;
	let Some(r) = retained_record(&dir, &archive, id)
		.map_err(|_| anyhow!("request unavailable to this scope"))?
	else {
		return Ok(None);
	};
	if r.owner != owner {
		bail!("request unavailable to this scope");
	}
	let state = match r.state {
		DurableState::Unknown if is_dispatch_active(id)? => "accepted",
		DurableState::Unknown => "unknown",
		DurableState::Completed => "completed",
		DurableState::Failed => "failed",
	};
	Ok(Some(AuditObservation {
		identity: RequestIdentity {
			request_id: r.request_id,
			owner: r.owner,
			tool_name: r.tool_name,
			accepted_unix_ms: r.accepted_unix_ms,
		},
		state,
		elapsed_ms: r.elapsed_ms,
	}))
}

/// The archive is the durable admission ledger; hot eviction does not revoke it.
/// Only a missing member may fall back. Unsafe metadata never becomes absence.
#[cfg(unix)]
fn retained_record(hot: &File, archive: &Archive, id: &str) -> Result<Option<Record>> {
	fn optional(directory: &File, id: &str) -> Result<Option<Record>> {
		match read_record(directory, &format!("{id}.json")) {
			Ok(record) => Ok(Some(record)),
			Err(error)
				if error
					.downcast_ref::<std::io::Error>()
					.is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
			{
				Ok(None)
			}
			Err(error) => Err(error),
		}
	}
	let hot = optional(hot, id)?;
	let archived = match archive.read_record(&format!("{id}.json")) {
		Ok(record) => Some(record),
		Err(error)
			if error
				.downcast_ref::<std::io::Error>()
				.is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
		{
			None
		}
		Err(error) => return Err(error),
	};
	if let (Some(hot), Some(archived)) = (&hot, &archived) {
		if hot.owner != archived.owner
			|| hot.tool_name != archived.tool_name
			|| hot.accepted_unix_ms != archived.accepted_unix_ms
			|| (hot.state != DurableState::Unknown && hot.state != archived.state)
			|| (hot.elapsed_ms.is_some() && hot.elapsed_ms != archived.elapsed_ms)
		{
			bail!("request archive identity or outcome changed");
		}
	}
	// Completion is published to the archive first. A failed hot-cache update
	// can leave an older unknown receipt, but cannot undo the archived completion.
	Ok(archived.or(hot))
}
#[cfg(not(unix))]
fn optional_observation_at(
	_root: &Path,
	_owner: &str,
	_id: &str,
) -> Result<Option<AuditObservation>> {
	bail!("private request metadata requires Unix");
}
pub(crate) async fn optional_observation(
	owner: &str,
	id: &str,
) -> Result<Option<AuditObservation>> {
	let root = runtime_config()?.state_dir.clone();
	let owner = owner.to_owned();
	let id = id.to_owned();
	tokio::task::spawn_blocking(move || optional_observation_at(&root, &owner, &id))
		.await
		.map_err(|_| anyhow!("request unavailable to this scope"))?
}

fn valid_id(value: &str) -> bool {
	value.len() == 64
		&& value
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_tool(value: &str) -> bool {
	!value.is_empty()
		&& value.len() <= 64
		&& value
			.bytes()
			.all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

fn new_id() -> Result<String> {
	use ring::rand::SecureRandom;
	let mut entropy = [0u8; 32];
	ring::rand::SystemRandom::new()
		.fill(&mut entropy)
		.map_err(|_| anyhow!("request identity entropy unavailable"))?;
	let alphabet = b"0123456789abcdef";
	let mut text = String::with_capacity(64);
	for byte in entropy {
		text.push(alphabet[(byte >> 4) as usize] as char);
		text.push(alphabet[(byte & 15) as usize] as char);
	}
	Ok(text)
}

// Every audit writer and metadata reader reserves a FIFO turn before taking
// the original mutex. A timed reader can cancel its turn without leaving a
// blocked thread behind; later writers cannot repeatedly bypass that reader.
#[derive(Default)]
struct AuditStoreQueue {
	next_ticket: u64,
	active: bool,
	waiting: VecDeque<u64>,
}

#[derive(Default)]
struct AuditStoreLock {
	inner: Mutex<()>,
	queue: Mutex<AuditStoreQueue>,
	changed: std::sync::Condvar,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StoreLockFailure {
	Deadline,
	Unavailable,
}

#[must_use = "the store guard must cover the protected operation"]
struct AuditStoreGuard<'a> {
	lock: &'a AuditStoreLock,
	inner: Option<std::sync::MutexGuard<'a, ()>>,
}

impl AuditStoreLock {
	fn cancel(&self, queue: &mut AuditStoreQueue, ticket: u64) {
		queue.waiting.retain(|queued| *queued != ticket);
		self.changed.notify_all();
	}

	fn release(&self) {
		// Cleanup must still release a reservation during unwinding. Recovering
		// this bookkeeping guard never clears either mutex's poisoned state.
		let mut queue = self.queue.lock().unwrap_or_else(|error| error.into_inner());
		queue.active = false;
		self.changed.notify_all();
	}

	fn acquire(
		&self,
		deadline: Option<Instant>,
	) -> std::result::Result<AuditStoreGuard<'_>, StoreLockFailure> {
		if deadline.is_some_and(|limit| Instant::now() >= limit) {
			return Err(StoreLockFailure::Deadline);
		}
		let mut queue = self
			.queue
			.lock()
			.map_err(|_| StoreLockFailure::Unavailable)?;
		if deadline.is_some_and(|limit| Instant::now() >= limit) {
			return Err(StoreLockFailure::Deadline);
		}
		let ticket = queue.next_ticket;
		queue.next_ticket = ticket.checked_add(1).ok_or(StoreLockFailure::Unavailable)?;
		queue.waiting.push_back(ticket);
		loop {
			if deadline.is_some_and(|limit| Instant::now() >= limit) {
				self.cancel(&mut queue, ticket);
				return Err(StoreLockFailure::Deadline);
			}
			if !queue.active && queue.waiting.front() == Some(&ticket) {
				queue.waiting.pop_front();
				queue.active = true;
				break;
			}
			let waited = match deadline {
				Some(limit) => self
					.changed
					.wait_timeout(queue, limit.saturating_duration_since(Instant::now()))
					.map(|(queue, _)| queue)
					.map_err(|error| error.into_inner().0),
				None => self.changed.wait(queue).map_err(|error| error.into_inner()),
			};
			queue = match waited {
				Ok(queue) => queue,
				Err(mut queue) => {
					self.cancel(&mut queue, ticket);
					return Err(StoreLockFailure::Unavailable);
				}
			};
		}
		drop(queue);
		let mut guard = AuditStoreGuard {
			lock: self,
			inner: None,
		};
		if deadline.is_some_and(|limit| Instant::now() >= limit) {
			return Err(StoreLockFailure::Deadline);
		}
		// All callers use this gate, and the previous owner releases inner
		// before its turn. No second, unbounded mutex wait belongs here.
		match self.inner.try_lock() {
			Ok(inner) => guard.inner = Some(inner),
			Err(std::sync::TryLockError::Poisoned(error)) => {
				drop(error.into_inner());
				return Err(StoreLockFailure::Unavailable);
			}
			Err(std::sync::TryLockError::WouldBlock) => {
				return Err(StoreLockFailure::Unavailable);
			}
		}
		if deadline.is_some_and(|limit| Instant::now() >= limit) {
			return Err(StoreLockFailure::Deadline);
		}
		Ok(guard)
	}
}

impl Drop for AuditStoreGuard<'_> {
	fn drop(&mut self) {
		// Keep standard Mutex poisoning for a panic inside the protected work,
		// and release that mutex before another caller receives the FIFO turn.
		drop(self.inner.take());
		self.lock.release();
	}
}

fn store_lock() -> Result<AuditStoreGuard<'static>> {
	trace::measure("store_lock_wait", 0, None, || {
		STORE_LOCK
			.get_or_init(AuditStoreLock::default)
			.acquire(None)
			.map_err(|_| anyhow!("request audit state lock unavailable"))
	})
}

fn active_registry() -> Result<std::sync::MutexGuard<'static, HashMap<String, Weak<AtomicBool>>>> {
	ACTIVE
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.map_err(|_| anyhow!("request audit active registry unavailable"))
}

fn read_pins() -> Result<std::sync::MutexGuard<'static, HashMap<String, Vec<Weak<()>>>>> {
	READ_PINS
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.map_err(|_| anyhow!("request read pin state unavailable"))
}
fn is_dispatch_active(id: &str) -> Result<bool> {
	let mut registry = active_registry()?;
	registry.retain(|_, marker| marker.strong_count() > 0);
	Ok(registry
		.get(id)
		.and_then(Weak::upgrade)
		.is_some_and(|marker| marker.load(Ordering::Acquire)))
}
fn is_active(id: &str) -> Result<bool> {
	let active = is_dispatch_active(id)?;
	let mut pins = read_pins()?;
	pins.retain(|_, markers| {
		markers.retain(|marker| marker.strong_count() > 0);
		!markers.is_empty()
	});
	Ok(active || pins.contains_key(id))
}

#[cfg(unix)]
fn name(value: &str) -> Result<std::ffi::CString> {
	std::ffi::CString::new(value).map_err(|_| anyhow!("invalid private metadata component"))
}

#[cfg(unix)]
fn open_at(directory: &File, component: &str, flags: i32, mode: u32) -> Result<File> {
	use std::os::fd::{AsRawFd, FromRawFd};
	let component = name(component)?;
	let descriptor = unsafe {
		libc::openat(
			directory.as_raw_fd(),
			component.as_ptr(),
			flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			mode,
		)
	};
	if descriptor < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn private_directory(directory: &File) -> Result<()> {
	private_directory_metadata(directory).map(|_| ())
}

#[cfg(unix)]
fn private_directory_metadata(directory: &File) -> Result<std::fs::Metadata> {
	use std::os::unix::fs::MetadataExt;
	let metadata = directory.metadata()?;
	if !metadata.is_dir()
		|| metadata.uid() != unsafe { libc::geteuid() }
		|| metadata.mode() & 0o7777 != 0o700
	{
		bail!("private request audit directory refused");
	}
	Ok(metadata)
}

#[cfg(unix)]
fn open_store(root: &Path) -> Result<File> {
	open_named_store(root, STORE_NAME)
}

#[cfg(unix)]
fn open_named_store(root: &Path, store_name: &str) -> Result<File> {
	let base = audit_root(root)?;
	open_named_store_at(&base, store_name)
}

#[cfg(unix)]
fn open_named_store_at(base: &File, store_name: &str) -> Result<File> {
	use std::os::fd::AsRawFd;
	let folder = name(store_name)?;
	let made = unsafe { libc::mkdirat(base.as_raw_fd(), folder.as_ptr(), 0o700) };
	if made < 0 {
		let error = std::io::Error::last_os_error();
		if error.kind() != std::io::ErrorKind::AlreadyExists {
			return Err(error.into());
		}
	} else {
		base.sync_all()?;
	}
	let directory = open_at(base, store_name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_directory(&directory)?;
	Ok(directory)
}

#[cfg(unix)]
fn audit_root(root: &Path) -> Result<File> {
	use std::os::fd::FromRawFd;
	use std::os::unix::fs::MetadataExt;
	let raw = root
		.to_str()
		.ok_or_else(|| anyhow!("request audit root is not UTF-8"))?;
	if !root.is_absolute() || raw.split('/').any(|part| part == "." || part == "..") {
		bail!("invalid request audit root");
	}
	let components: Vec<_> = raw.split('/').filter(|part| !part.is_empty()).collect();
	#[cfg(target_os = "linux")]
	let ancestor_access = libc::O_PATH;
	#[cfg(not(target_os = "linux"))]
	let ancestor_access = libc::O_RDONLY;
	let slash = name("/")?;
	let descriptor = unsafe {
		libc::open(
			slash.as_ptr(),
			ancestor_access | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
		)
	};
	if descriptor < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	let mut base = unsafe { File::from_raw_fd(descriptor) };
	for (index, component) in components.iter().enumerate() {
		// Linux O_PATH needs search permission, not directory-listing permission.
		// Keep explicit denial of non-searchable ancestors even for privileged
		// callers, and open the private final directory as a normal fsync-able FD.
		if base.metadata()?.mode() & 0o111 == 0 {
			bail!("request audit ancestor is not searchable");
		}
		let access = if index + 1 == components.len() {
			libc::O_RDONLY
		} else {
			ancestor_access
		};
		base = open_at(&base, component, access | libc::O_DIRECTORY, 0)?;
	}
	private_directory(&base)?;
	Ok(base)
}

#[cfg(not(unix))]
fn open_store(_root: &Path) -> Result<File> {
	bail!("private request auditing requires Unix descriptor support")
}

#[cfg(unix)]
fn validate_file(file: &File) -> Result<()> {
	use std::os::unix::fs::MetadataExt;
	let metadata = file.metadata()?;
	if !metadata.is_file()
		|| metadata.uid() != unsafe { libc::geteuid() }
		|| metadata.mode() & 0o7777 != 0o600
		|| metadata.nlink() != 1
		|| metadata.len() > MAX_RECORD_BYTES as u64
	{
		bail!("private request audit inode refused");
	}
	Ok(())
}

#[cfg(unix)]
fn archive_stamp(directory: &File) -> Result<ArchiveStamp> {
	use std::os::unix::fs::MetadataExt;
	let metadata = private_directory_metadata(directory)?;
	Ok(ArchiveStamp {
		device: metadata.dev(),
		inode: metadata.ino(),
		modified: (metadata.mtime(), metadata.mtime_nsec()),
		changed: (metadata.ctime(), metadata.ctime_nsec()),
		namespace: super::namespace_version::version(directory)?,
	})
}

#[cfg(unix)]
fn read_archive_anchor(root: &File) -> Result<ArchiveAnchor> {
	let mut file = open_at(root, ARCHIVE_ANCHOR, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
	validate_file(&file)?;
	let mut bytes = Vec::new();
	Read::by_ref(&mut file)
		.take((MAX_RECORD_BYTES + 1) as u64)
		.read_to_end(&mut bytes)?;
	if bytes.len() > MAX_RECORD_BYTES {
		bail!("request archive anchor size refused");
	}
	Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(unix)]
fn publish_archive_anchor(root: &File, anchor: &ArchiveAnchor) -> Result<()> {
	use std::os::fd::AsRawFd;
	let temporary = format!(".archive-anchor-{}.tmp", new_id()?);
	let mut file = open_at(
		root,
		&temporary,
		libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
		0o600,
	)?;
	let result = (|| -> Result<()> {
		file.write_all(&serde_json::to_vec(anchor)?)?;
		file.sync_all()?;
		let source = name(&temporary)?;
		let target = name(ARCHIVE_ANCHOR)?;
		if unsafe {
			libc::linkat(
				root.as_raw_fd(),
				source.as_ptr(),
				root.as_raw_fd(),
				target.as_ptr(),
				0,
			)
		} < 0
		{
			return Err(std::io::Error::last_os_error().into());
		}
		if unsafe { libc::unlinkat(root.as_raw_fd(), source.as_ptr(), 0) } < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		root.sync_all()?;
		Ok(())
	})();
	if result.is_err() {
		if let Ok(component) = name(&temporary) {
			unsafe { libc::unlinkat(root.as_raw_fd(), component.as_ptr(), 0) };
		}
	}
	result
}

/// A missing archive after introduction is uncertain history, never an empty archive.
#[cfg(unix)]
fn open_archive(root: &Path) -> Result<Archive> {
	let base = audit_root(root)?;
	open_archive_at(&base)
}

#[cfg(unix)]
fn open_archive_at(base: &File) -> Result<Archive> {
	let (legacy, anchor) = open_legacy_archive_at(base)?;
	Archive::open(base, legacy, anchor)
}

#[cfg(unix)]
fn open_legacy_archive_at(base: &File) -> Result<(File, archive_store::PinnedAnchor)> {
	use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
	let metadata = base.metadata()?;
	match archive_store::PinnedAnchor::open(base) {
		Ok(pinned) => {
			let anchor = pinned.record();
			if anchor.root_device != metadata.dev() || anchor.root_inode != metadata.ino() {
				bail!("request archive root binding changed");
			}
			let archive = open_at(base, ARCHIVE_NAME, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
			let stamp = archive_stamp(&archive)?;
			if (stamp.device, stamp.inode) != (anchor.archive_device, anchor.archive_inode) {
				bail!("request archive identity changed; history never recreated automatically");
			}
			Ok((archive, pinned))
		}
		Err(error)
			if error
				.downcast_ref::<std::io::Error>()
				.is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
		{
			match open_at(base, ARCHIVE_NAME, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
				Err(error)
					if error
						.downcast_ref::<std::io::Error>()
						.is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
				_ => bail!(
					"unanchored request archive refused; history never recreated automatically"
				),
			}
			let component = name(ARCHIVE_NAME)?;
			if unsafe { libc::mkdirat(base.as_raw_fd(), component.as_ptr(), 0o700) } < 0 {
				return Err(std::io::Error::last_os_error().into());
			}
			base.sync_all()?;
			let archive = open_at(base, ARCHIVE_NAME, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
			let stamp = archive_stamp(&archive)?;
			publish_archive_anchor(
				base,
				&ArchiveAnchor {
					root_device: metadata.dev(),
					root_inode: metadata.ino(),
					archive_device: stamp.device,
					archive_inode: stamp.inode,
				},
			)?;
			Ok((archive, archive_store::PinnedAnchor::open(base)?))
		}
		Err(error) => Err(error),
	}
}

#[cfg(unix)]
fn read_record(directory: &File, filename: &str) -> Result<Record> {
	let id = filename
		.strip_suffix(".json")
		.filter(|id| valid_id(id))
		.ok_or_else(|| anyhow!("invalid request metadata filename"))?;
	let staging = format!(".{id}-{id}.tmp");
	match open_at(directory, &staging, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
		Ok(_) => cleanup_staging(directory, &staging)?,
		Err(error)
			if error
				.downcast_ref::<std::io::Error>()
				.is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
		Err(error) => return Err(error),
	}
	let mut file = open_at(directory, filename, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
	{
		use std::os::unix::fs::MetadataExt;
		if file.metadata()?.nlink() == 2 {
			// Old versions used random staging names. Only this exceptional
			// interrupted-publication case scans names, never record history.
			let prefix = format!(".{id}-");
			walk_directory(directory, |entry| {
				if entry.starts_with(&prefix) && entry.ends_with(".tmp") {
					cleanup_staging(directory, entry)?;
				}
				Ok(())
			})?;
		}
	}
	validate_file(&file)?;
	let mut bytes = Vec::new();
	Read::by_ref(&mut file)
		.take((MAX_RECORD_BYTES + 1) as u64)
		.read_to_end(&mut bytes)?;
	if bytes.len() > MAX_RECORD_BYTES {
		bail!("request audit metadata size refused");
	}
	let record: Record = serde_json::from_slice(&bytes)?;
	if !valid_id(&record.request_id)
		|| !valid_id(&record.owner)
		|| !valid_tool(&record.tool_name)
		|| filename != format!("{}.json", record.request_id)
	{
		bail!("request audit metadata identity refused");
	}
	Ok(record)
}

#[cfg(unix)]
fn directory_scan_result(has_entry: bool, error: i32) -> Result<bool> {
	if has_entry {
		return Ok(true);
	}
	if error != 0 {
		return Err(std::io::Error::from_raw_os_error(error).into());
	}
	Ok(false)
}

#[cfg(unix)]
fn scan_errno(reset: bool) -> Result<i32> {
	#[cfg(target_os = "linux")]
	{
		let pointer = unsafe { libc::__errno_location() };
		if reset {
			unsafe { *pointer = 0 };
		}
		Ok(unsafe { *pointer })
	}
	#[cfg(target_os = "macos")]
	{
		let pointer = unsafe { libc::__error() };
		if reset {
			unsafe { *pointer = 0 };
		}
		Ok(unsafe { *pointer })
	}
	#[cfg(not(any(target_os = "linux", target_os = "macos")))]
	{
		let _ = reset;
		bail!("private audit directory scan is unavailable on this platform")
	}
}

#[cfg(unix)]
fn entries(directory: &File) -> Result<Vec<Record>> {
	entries_bounded(directory, MAX_GLOBAL)
}

#[cfg(unix)]
fn walk_directory(directory: &File, mut visit: impl FnMut(&str) -> Result<()>) -> Result<()> {
	walk_directory_with_inode(directory, |filename, _| visit(filename))
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)] // libc inode widths vary across Unix.
fn walk_directory_with_inode(
	directory: &File,
	mut visit: impl FnMut(&str, u64) -> Result<()>,
) -> Result<()> {
	use std::os::fd::AsRawFd;
	// A fresh directory file description avoids a shared seek cursor between snapshots.
	let scan = open_at(directory, ".", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	let duplicate = unsafe { libc::fcntl(scan.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
	if duplicate < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	let pointer = unsafe { libc::fdopendir(duplicate) };
	if pointer.is_null() {
		unsafe { libc::close(duplicate) };
		return Err(std::io::Error::last_os_error().into());
	}
	struct DirectoryStream(*mut libc::DIR);
	impl Drop for DirectoryStream {
		fn drop(&mut self) {
			unsafe { libc::closedir(self.0) };
		}
	}
	let stream = DirectoryStream(pointer);
	loop {
		scan_errno(true)?;
		let item = unsafe { libc::readdir(stream.0) };
		if !directory_scan_result(!item.is_null(), scan_errno(false)?)? {
			break;
		}
		let filename = unsafe { std::ffi::CStr::from_ptr((*item).d_name.as_ptr()) }.to_str()?;
		if filename == "." || filename == ".." {
			continue;
		}
		// This inode is only a scheduling hint. Callers needing metadata still
		// verify the complete named member through the pinned descriptor.
		visit(filename, unsafe { (*item).d_ino } as u64)?;
	}
	Ok(())
}

#[cfg(unix)]
fn directory_members(directory: &File, maximum: usize) -> Result<Vec<String>> {
	let mut names = Vec::new();
	walk_directory(directory, |filename| {
		if names.len() >= maximum + 32 {
			bail!("request audit retention invariant exceeded");
		}
		names.push(filename.to_owned());
		Ok(())
	})?;
	Ok(names)
}

/// Archive read APIs have bounded working memory and release STORE_LOCK after
/// each exact record read, so ordinary admissions can progress during a live scan.
#[cfg(all(test, unix))]
fn scan_archive(archive: &Archive, mut visit: impl FnMut(Record) -> Result<()>) -> Result<()> {
	archive.walk(|directory, filename, _| {
		if filename.starts_with('.') {
			let value = filename
				.strip_prefix('.')
				.and_then(|value| value.strip_suffix(".tmp"))
				.and_then(|value| value.split_once('-'));
			if !value.is_some_and(|(id, nonce)| valid_id(id) && valid_id(nonce)) {
				bail!("unexpected private request audit entry");
			}
			return Ok(());
		}
		let record = {
			let _guard = store_lock()?;
			read_record(directory, filename)?
		};
		visit(record)
	})
}

#[cfg(unix)]
fn entries_bounded(directory: &File, maximum: usize) -> Result<Vec<Record>> {
	let names = directory_members(directory, maximum)?;
	// Remove only verified private staging inodes after an interrupted publication.
	// This cannot remove an active writer because all mutations use STORE_LOCK.
	for filename in names.iter().filter(|value| value.starts_with('.')) {
		cleanup_staging(directory, filename)?;
	}
	let mut result = Vec::new();
	for filename in names.iter().filter(|value| !value.starts_with('.')) {
		if result.len() >= maximum || !filename.ends_with(".json") {
			bail!("unexpected private request audit entry");
		}
		result.push(read_record(directory, filename)?);
	}
	result.sort_by(|left, right| {
		(left.accepted_unix_ms, &left.request_id).cmp(&(right.accepted_unix_ms, &right.request_id))
	});
	Ok(result)
}

#[cfg(unix)]
fn cleanup_staging(directory: &File, filename: &str) -> Result<()> {
	use std::os::fd::AsRawFd;
	use std::os::unix::fs::MetadataExt;
	let value = filename
		.strip_prefix('.')
		.and_then(|value| value.strip_suffix(".tmp"))
		.ok_or_else(|| anyhow!("unexpected private audit staging entry"))?;
	let (id, nonce) = value
		.split_once('-')
		.ok_or_else(|| anyhow!("unexpected private audit staging identity"))?;
	if !valid_id(id) || !valid_id(nonce) {
		bail!("unexpected private audit staging identity");
	}
	let file = open_at(directory, filename, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
	let metadata = file.metadata()?;
	if !metadata.is_file()
		|| metadata.uid() != unsafe { libc::geteuid() }
		|| metadata.mode() & 0o7777 != 0o600
		|| !(1..=2).contains(&metadata.nlink())
		|| metadata.len() > MAX_RECORD_BYTES as u64
	{
		bail!("audit staging inode refused");
	}
	if metadata.nlink() == 2 {
		let published = open_at(
			directory,
			&format!("{id}.json"),
			libc::O_RDONLY | libc::O_NONBLOCK,
			0,
		)?;
		let target = published.metadata()?;
		if target.dev() != metadata.dev() || target.ino() != metadata.ino() {
			bail!("audit staging hard-link binding refused");
		}
	}
	let component = name(filename)?;
	if unsafe { libc::unlinkat(directory.as_raw_fd(), component.as_ptr(), 0) } < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	directory.sync_all()?;
	Ok(())
}

#[cfg(unix)]
fn remove_record(directory: &File, expected: &Record, sync_directory: bool) -> Result<()> {
	use std::os::fd::AsRawFd;
	if read_record(directory, &format!("{}.json", expected.request_id))? != *expected {
		bail!("request hot cache binding changed");
	}
	let filename = name(&format!("{}.json", expected.request_id))?;
	if unsafe { libc::unlinkat(directory.as_raw_fd(), filename.as_ptr(), 0) } < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	if sync_directory {
		directory.sync_all()?;
	}
	Ok(())
}

#[cfg(unix)]
fn archived_copy_matches(archive: &Archive, record: &Record) -> bool {
	let Ok(archived) = archive.read_record(&format!("{}.json", record.request_id)) else {
		return false;
	};
	archived.owner == record.owner
		&& archived.tool_name == record.tool_name
		&& archived.accepted_unix_ms == record.accepted_unix_ms
		&& (record.state == DurableState::Unknown || record.state == archived.state)
		&& (record.elapsed_ms.is_none() || record.elapsed_ms == archived.elapsed_ms)
}

#[cfg(unix)]
fn retain_before_begin(
	directory: &File,
	archive: &Archive,
	owner: &str,
	records: &mut Vec<Record>,
) -> Result<bool> {
	retain_for_batch(directory, archive, owner, records, &HashSet::new(), true)
}

#[cfg(unix)]
fn retain_for_batch(
	directory: &File,
	archive: &Archive,
	owner: &str,
	records: &mut Vec<Record>,
	pending: &HashSet<String>,
	sync_directory: bool,
) -> Result<bool> {
	while records
		.iter()
		.filter(|record| record.owner == owner)
		.count()
		>= MAX_OWNER
	{
		let mut victim = None;
		for (index, record) in records.iter().enumerate() {
			if record.owner == owner
				&& !pending.contains(&record.request_id)
				&& !is_active(&record.request_id)?
				&& archived_copy_matches(archive, record)
			{
				victim = Some(index);
				break;
			}
		}
		let Some(index) = victim else {
			return Ok(false);
		};
		remove_record(directory, &records[index], sync_directory)?;
		records.remove(index);
	}
	while records.len() >= MAX_GLOBAL {
		let mut victim = None;
		for (index, record) in records.iter().enumerate() {
			if !pending.contains(&record.request_id)
				&& !is_active(&record.request_id)?
				&& archived_copy_matches(archive, record)
			{
				victim = Some(index);
				break;
			}
		}
		let Some(index) = victim else {
			return Ok(false);
		};
		remove_record(directory, &records[index], sync_directory)?;
		records.remove(index);
	}
	Ok(true)
}

#[cfg(unix)]
fn save(directory: &File, record: &Record, replacing: bool) -> Result<()> {
	save_with_sync(directory, record, replacing, true)
}

/// File contents always sync before publication. Only the batch worker may
/// defer a directory barrier, and it acknowledges nobody until that barrier.
#[cfg(unix)]
fn save_with_sync(
	directory: &File,
	record: &Record,
	replacing: bool,
	sync_directory: bool,
) -> Result<()> {
	save_raw_with_sync(directory, record, replacing, sync_directory)
}

/// Only authoritative archive writes feed the disposable index. Hot retention
/// copies must not pay for index lookups or create duplicate pending updates.
#[cfg(unix)]
fn save_archive_with_sync(
	archive: &Archive,
	record: &Record,
	replacing: bool,
	sync_directory: bool,
) -> Result<()> {
	archive.fence_at(archive.root())?;
	let filename = format!("{}.json", record.request_id);
	let directory = archive.directory_for_write(&filename, replacing)?;
	index::publication(archive, record, || {
		save_raw_with_sync(directory, record, replacing, sync_directory)
	})?;
	archive.fence_record(&filename, directory)?;
	archive.fence_at(archive.root())
}

#[cfg(unix)]
fn save_raw_with_sync(
	directory: &File,
	record: &Record,
	replacing: bool,
	sync_directory: bool,
) -> Result<()> {
	use std::os::fd::AsRawFd;
	let total = trace::Span::new("serial_record_write", 1, Some(0));
	private_directory(directory)?;
	let filename = format!("{}.json", record.request_id);
	if replacing {
		let existing = read_record(directory, &filename)?;
		if existing.owner != record.owner
			|| existing.tool_name != record.tool_name
			|| existing.accepted_unix_ms != record.accepted_unix_ms
		{
			bail!("request audit receipt binding changed");
		}
	}
	let bytes = serde_json::to_vec(record)?;
	if bytes.len() > MAX_RECORD_BYTES {
		bail!("request audit record size refused");
	}
	let temporary = format!(".{}-{}.tmp", record.request_id, record.request_id);
	let mut file = trace::measure("serial_open_temporary", 1, Some(0), || {
		open_at(
			directory,
			&temporary,
			libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
			0o600,
		)
	})?;
	validate_file(&file)?;
	let persisted = (|| -> Result<()> {
		trace::measure("serial_write_temporary", 1, Some(0), || {
			file.write_all(&bytes)?;
			Ok(())
		})?;
		trace::measure("serial_file_sync", 1, Some(0), || {
			file.sync_all()?;
			Ok(())
		})?;
		drop(file);
		let temp = name(&temporary)?;
		let target = name(&filename)?;
		if replacing {
			if unsafe {
				libc::renameat(
					directory.as_raw_fd(),
					temp.as_ptr(),
					directory.as_raw_fd(),
					target.as_ptr(),
				)
			} < 0
			{
				return Err(std::io::Error::last_os_error().into());
			}
		} else {
			if unsafe {
				libc::linkat(
					directory.as_raw_fd(),
					temp.as_ptr(),
					directory.as_raw_fd(),
					target.as_ptr(),
					0,
				)
			} < 0
			{
				return Err(std::io::Error::last_os_error().into());
			}
			if unsafe { libc::unlinkat(directory.as_raw_fd(), temp.as_ptr(), 0) } < 0 {
				return Err(std::io::Error::last_os_error().into());
			}
		}
		if sync_directory {
			trace::measure("serial_directory_sync", 1, Some(0), || {
				directory.sync_all()?;
				Ok(())
			})?;
		}
		Ok(())
	})();
	if persisted.is_err() {
		if let Ok(temp) = name(&temporary) {
			unsafe { libc::unlinkat(directory.as_raw_fd(), temp.as_ptr(), 0) };
		}
	}
	total.finish(persisted)
}

/// An append-retained metadata archive is independent of the bounded hot cache.
/// Only the exact immutable identity is read; lifetime history is never counted
/// or scanned in the dispatch path, and no history-count admission limit exists.
#[cfg(unix)]
fn archive_record(archive: &Archive, record: &Record) -> Result<()> {
	archive_record_with_sync(archive, record, true)
}

#[cfg(unix)]
fn archive_record_with_sync(
	archive: &Archive,
	record: &Record,
	sync_directory: bool,
) -> Result<()> {
	let Some(replacing) = archive_replacement(archive, record)? else {
		return Ok(());
	};
	save_archive_with_sync(archive, record, replacing, sync_directory)
}

#[cfg(unix)]
fn archive_replacement(archive: &Archive, record: &Record) -> Result<Option<bool>> {
	let replacing = match archive.read_record(&format!("{}.json", record.request_id)) {
		Ok(existing) => {
			if existing.owner != record.owner
				|| existing.tool_name != record.tool_name
				|| existing.accepted_unix_ms != record.accepted_unix_ms
			{
				bail!("request archive identity changed");
			}
			if record.state == DurableState::Unknown && existing.state != DurableState::Unknown {
				return Ok(None);
			}
			if existing.state != DurableState::Unknown && existing.state != record.state {
				bail!("request archive terminal outcome changed");
			}
			if existing.state != DurableState::Unknown && existing.elapsed_ms != record.elapsed_ms {
				bail!("request archive terminal outcome changed");
			}
			if existing.state == record.state && existing.elapsed_ms == record.elapsed_ms {
				return Ok(None);
			}
			true
		}
		Err(error)
			if error
				.downcast_ref::<std::io::Error>()
				.is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
		{
			false
		}
		Err(error) => return Err(error),
	};
	Ok(Some(replacing))
}

#[cfg(unix)]
fn cache_hot(directory: &File, records: &[Record]) -> Result<()> {
	cache_hot_owned(directory, records.to_vec())
}

#[cfg(unix)]
fn cache_hot_owned(directory: &File, records: Vec<Record>) -> Result<()> {
	let stamp = archive_stamp(directory)?;
	let mut cache = HOT_CACHE
		.get_or_init(|| Mutex::new(VecDeque::new()))
		.lock()
		.map_err(|_| anyhow!("request hot cache unavailable"))?;
	cache.retain(|entry| (entry.stamp.device, entry.stamp.inode) != (stamp.device, stamp.inode));
	// This bounds disposable cache memory, never admissions or durable history.
	if cache.len() >= 16 {
		cache.pop_front();
	}
	cache.push_back(HotSnapshot { stamp, records });
	Ok(())
}

#[cfg(unix)]
fn seed_missing_archive_record(archive: &Archive, record: &Record) -> Result<()> {
	if archive
		.existing_directory(&format!("{}.json", record.request_id))?
		.is_some()
	{
		// Existing bytes are never repaired or rebound by an unrelated admission.
		// A bad counterpart prevents eviction of its good hot copy, not new IDs.
		return Ok(());
	}
	save_archive_with_sync(archive, record, false, true)
}

/// Callers hold STORE_LOCK. Cold/external namespace changes are validated once;
/// ordinary writes update the stamp and bounded index after their own fsync.
#[cfg(unix)]
fn hot_snapshot(root: &Path, directory: &File) -> Result<(Vec<Record>, Archive)> {
	let archive = open_archive(root)?;
	let records = hot_snapshot_at(directory, &archive, false)?;
	Ok((records, archive))
}

#[cfg(unix)]
fn hot_snapshot_at(directory: &File, archive: &Archive, consume: bool) -> Result<Vec<Record>> {
	let mut stamp = archive_stamp(directory)?;
	{
		let mut cache = HOT_CACHE
			.get_or_init(|| Mutex::new(VecDeque::new()))
			.lock()
			.map_err(|_| anyhow!("request hot cache unavailable"))?;
		if let Some(position) = cache.iter().position(|entry| entry.stamp == stamp) {
			if consume {
				// A failed cohort leaves a cache miss, so the next caller rereads hot files.
				return cache
					.remove(position)
					.map(|saved| saved.records)
					.ok_or_else(|| anyhow!("request hot snapshot unavailable"));
			}
			return Ok(cache[position].records.clone());
		}
	}
	let mut records = entries(directory)?;
	for attempt in 0..3 {
		let after = archive_stamp(directory)?;
		if after == stamp {
			break;
		}
		if attempt == 2 {
			bail!("request hot namespace changed during validation");
		}
		stamp = after;
		records = entries(directory)?;
	}
	for record in &records {
		seed_missing_archive_record(archive, record)?;
	}
	if !consume {
		cache_hot(directory, &records)?;
	}
	Ok(records)
}

/// Reuse the anchored initialization/validation path without admitting a call.
#[cfg(unix)]
pub(crate) fn prepare_at(root: &Path) -> Result<()> {
	let _guard = store_lock()?;
	let directory = open_store(root)?;
	hot_snapshot(root, &directory)?;
	Ok(())
}
#[cfg(not(unix))]
pub(crate) fn prepare_at(_root: &Path) -> Result<()> {
	bail!("private request auditing requires Unix descriptor support")
}

#[cfg(unix)]
fn update_cached_completion(directory: &File, record: &Record, before: ArchiveStamp) -> Result<()> {
	let after = archive_stamp(directory)?;
	let mut cache = HOT_CACHE
		.get_or_init(|| Mutex::new(VecDeque::new()))
		.lock()
		.map_err(|_| anyhow!("request hot cache unavailable"))?;
	if let Some(saved) = cache.iter_mut().find(|entry| entry.stamp == before) {
		if let Some(original) = saved
			.records
			.iter_mut()
			.find(|item| item.request_id == record.request_id)
		{
			*original = record.clone();
			saved.stamp = after;
		}
	}
	Ok(())
}

#[cfg(unix)]
fn begin_with_read_at(
	root: &Path,
	owner: &str,
	tool_name: &str,
	target: Option<&str>,
) -> Result<RequestTicket> {
	if !valid_id(owner) || !valid_tool(tool_name) {
		bail!("request audit session or canonical tool metadata unavailable");
	}
	let _guard = store_lock()?;
	let directory = open_store(root)?;
	let (mut records, archive) = hot_snapshot(root, &directory)?;
	let read_pin = if let Some(id) = target {
		if !matches!(tool_name, "request_status" | "request_result")
			|| !valid_id(id)
			|| retained_record(&directory, &archive, id)?.is_none_or(|record| record.owner != owner)
		{
			bail!("request unavailable to this scope");
		}
		let pin = Arc::new(());
		read_pins()?
			.entry(id.to_owned())
			.or_default()
			.push(Arc::downgrade(&pin));
		Some(pin)
	} else {
		None
	};
	let hot_present = retain_before_begin(&directory, &archive, owner, &mut records)?;
	let record = Record {
		request_id: new_id()?,
		owner: owner.into(),
		tool_name: tool_name.into(),
		state: DurableState::Unknown,
		accepted_unix_ms: SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_millis(),
		elapsed_ms: None,
	};
	save_archive_with_sync(&archive, &record, false, true)?;
	if hot_present {
		save(&directory, &record, false)?;
		records.push(record.clone());
		records.sort_by(|a, b| {
			(a.accepted_unix_ms, &a.request_id).cmp(&(b.accepted_unix_ms, &b.request_id))
		});
	}
	cache_hot(&directory, &records)?;
	let active = Arc::new(AtomicBool::new(true));
	active_registry()?.insert(record.request_id.clone(), Arc::downgrade(&active));
	Ok(RequestTicket {
		directory,
		archive,
		hot_present,
		record,
		started: Instant::now(),
		active,
		_read_pin: read_pin,
	})
}

#[cfg(unix)]
fn begin_at(root: &Path, owner: &str, tool_name: &str) -> Result<RequestTicket> {
	begin_with_read_at(root, owner, tool_name, None)
}
#[cfg(not(unix))]
fn begin_with_read_at(
	_root: &Path,
	_owner: &str,
	_tool: &str,
	_target: Option<&str>,
) -> Result<RequestTicket> {
	bail!("private request auditing requires Unix descriptor support")
}
/// Protect only an already-owned lookup target until its native read finishes.
pub(crate) async fn begin_with_read(
	owner: &str,
	tool: &str,
	target: Option<String>,
) -> Result<RequestTicket> {
	let total = trace::Span::new("begin_with_read_total", 1, Some(0));
	let root = trace::measure("begin_with_read_config", 1, Some(0), || {
		Ok(runtime_config()?.state_dir.clone())
	})
	.inspect_err(|_| trace::flush())?;
	let owner = owner.to_owned();
	let tool = tool.to_owned();
	let joined = tokio::task::spawn_blocking(move || {
		let span = trace::Span::new("begin_with_read_blocking", 1, Some(0));
		let result = span.finish((|| {
			#[cfg(unix)]
			if let Some(coordinator) = batch::coordinator() {
				return coordinator.begin(root, owner, tool, target);
			}
			begin_with_read_at(&root, &owner, &tool, target.as_deref())
		})());
		trace::flush();
		result
	})
	.await;
	let result = match joined {
		Ok(result) => {
			if let Err(error) = &result {
				trace::Span::new("begin_with_read_inner_failure", 1, Some(0)).record(Some(error));
			}
			result.map_err(|_| {
				anyhow!("request audit intent unavailable; request was not dispatched")
			})
		}
		Err(error) => {
			let stage = if error.is_panic() {
				"begin_with_read_join_panic"
			} else if error.is_cancelled() {
				"begin_with_read_join_cancelled"
			} else {
				"begin_with_read_join_failure"
			};
			let error = anyhow::Error::new(error);
			trace::Span::new(stage, 1, Some(0)).record(Some(&error));
			Err(anyhow!(
				"request audit intent unavailable; request was not dispatched"
			))
		}
	};
	let result = total.finish(result);
	trace::flush();
	result
}

/// Only canonical router names (or `_unknown_tool`) may reach this internal API.
pub async fn begin(owner: &str, canonical_tool_name: &str) -> Result<RequestTicket> {
	let total = trace::Span::new("begin_total", 1, Some(0));
	let root = trace::measure("begin_config", 1, Some(0), || {
		Ok(runtime_config()?.state_dir.clone())
	})
	.inspect_err(|_| trace::flush())?;
	let owner = owner.to_owned();
	let tool = canonical_tool_name.to_owned();
	let joined = tokio::task::spawn_blocking(move || {
		let result = trace::measure("begin_blocking", 1, Some(0), || {
			#[cfg(unix)]
			if let Some(coordinator) = batch::coordinator() {
				return coordinator.begin(root, owner, tool, None);
			}
			begin_at(&root, &owner, &tool)
		});
		trace::flush();
		result
	})
	.await;
	let result = match joined {
		Ok(result) => {
			if let Err(error) = &result {
				trace::Span::new("begin_inner_failure", 1, Some(0)).record(Some(error));
			}
			result.map_err(|_| {
				anyhow!("request audit intent unavailable; request was not dispatched")
			})
		}
		Err(error) => {
			let stage = if error.is_panic() {
				"begin_join_panic"
			} else if error.is_cancelled() {
				"begin_join_cancelled"
			} else {
				"begin_join_failure"
			};
			trace::Span::new(stage, 1, Some(0)).record(Some(&anyhow::Error::new(error)));
			Err(anyhow!(
				"request audit intent unavailable; request was not dispatched"
			))
		}
	};
	let result = total.finish(result);
	trace::flush();
	result
}

#[cfg(not(unix))]
fn begin_at(_root: &Path, _owner: &str, _tool_name: &str) -> Result<RequestTicket> {
	bail!("private request auditing requires Unix descriptor support")
}

#[cfg(unix)]
fn begin_reserved_at(root: &Path, identity: RequestIdentity) -> Result<RequestTicket> {
	if !valid_id(&identity.owner)
		|| !valid_id(&identity.request_id)
		|| !matches!(
			identity.tool_name.as_str(),
			"host_list" | "host_health" | "effective_config"
		) {
		bail!("reserved request identity unavailable");
	}
	begin_reserved_record_at(root, identity)
}
#[cfg(unix)]
fn begin_operation_reserved_at(root: &Path, identity: RequestIdentity) -> Result<RequestTicket> {
	if !valid_id(&identity.owner)
		|| !valid_id(&identity.request_id)
		|| !super::operation_async::eligible(&identity.tool_name)
	{
		bail!("reserved native read identity unavailable");
	}
	begin_reserved_record_at(root, identity)
}
/// Both closed internal families validate their exact capability before opening disk.
#[cfg(unix)]
fn begin_reserved_record_at(root: &Path, identity: RequestIdentity) -> Result<RequestTicket> {
	let _guard = store_lock()?;
	let directory = open_store(root)?;
	match read_record(&directory, &format!("{}.json", identity.request_id)) {
		Ok(_) => bail!("reserved request already exists; never redispatch"),
		Err(error)
			if error
				.downcast_ref::<std::io::Error>()
				.is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
		Err(_) => bail!("reserved request unavailable; never redispatch"),
	}
	let (mut records, archive) = hot_snapshot(root, &directory)?;
	match archive.read_record(&format!("{}.json", identity.request_id)) {
		Ok(_) => bail!("reserved request already archived; never redispatch"),
		Err(error)
			if error
				.downcast_ref::<std::io::Error>()
				.is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
		Err(_) => bail!("reserved request archive unavailable; never redispatch"),
	}
	let hot_present = retain_before_begin(&directory, &archive, &identity.owner, &mut records)?;
	let record = Record {
		request_id: identity.request_id,
		owner: identity.owner,
		tool_name: identity.tool_name,
		state: DurableState::Unknown,
		accepted_unix_ms: identity.accepted_unix_ms,
		elapsed_ms: None,
	};
	save_archive_with_sync(&archive, &record, false, true)?;
	if hot_present {
		save(&directory, &record, false)?;
		records.push(record.clone());
		records.sort_by(|a, b| {
			(a.accepted_unix_ms, &a.request_id).cmp(&(b.accepted_unix_ms, &b.request_id))
		});
	}
	cache_hot(&directory, &records)?;
	let active = Arc::new(AtomicBool::new(true));
	active_registry()?.insert(record.request_id.clone(), Arc::downgrade(&active));
	Ok(RequestTicket {
		directory,
		archive,
		hot_present,
		record,
		started: Instant::now(),
		active,
		_read_pin: None,
	})
}
#[cfg(not(unix))]
fn begin_reserved_at(_root: &Path, _identity: RequestIdentity) -> Result<RequestTicket> {
	bail!("private request auditing requires Unix descriptor support")
}
/// Only a newly published server-generated async reservation may call this.
/// Existing key bindings never rebuild a ticket, even when the audit record is absent.
pub(crate) async fn begin_reserved(identity: RequestIdentity) -> Result<RequestTicket> {
	let root = runtime_config()?.state_dir.clone();
	tokio::task::spawn_blocking(move || begin_reserved_at(&root, identity))
		.await
		.map_err(|_| anyhow!("reserved request admission unavailable; never redispatch"))?
}

#[cfg(not(unix))]
fn begin_operation_reserved_at(_root: &Path, _identity: RequestIdentity) -> Result<RequestTicket> {
	bail!("private request auditing requires Unix descriptor support")
}
/// V10's closed native-read reservation; never widens V9's three-DTO API.
pub(crate) async fn begin_operation_reserved(identity: RequestIdentity) -> Result<RequestTicket> {
	let root = runtime_config()?.state_dir.clone();
	tokio::task::spawn_blocking(move || begin_operation_reserved_at(&root, identity))
		.await
		.map_err(|_| anyhow!("reserved native read admission unavailable; never redispatch"))?
}
#[cfg(unix)]
fn finish_sync(mut ticket: RequestTicket, completion: AuditCompletion) -> Result<()> {
	let _guard = store_lock()?;
	ticket.active.store(false, Ordering::Release);
	ticket.record.state = match completion {
		AuditCompletion::Completed => DurableState::Completed,
		AuditCompletion::Failed => DurableState::Failed,
		AuditCompletion::Unknown => DurableState::Unknown,
	};
	ticket.record.elapsed_ms =
		Some(ticket.started.elapsed().as_millis().min(u64::MAX as u128) as u64);
	archive_record(&ticket.archive, &ticket.record)?;
	if ticket.hot_present {
		let before = archive_stamp(&ticket.directory)?;
		save(&ticket.directory, &ticket.record, true)?;
		update_cached_completion(&ticket.directory, &ticket.record, before)?;
	}
	Ok(())
}

#[cfg(unix)]
#[derive(Debug)]
struct MetadataQueryDeadline;

#[cfg(unix)]
impl std::fmt::Display for MetadataQueryDeadline {
	fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		out.write_str(
			"archive metadata query total deadline exceeded; repeat only the metadata query",
		)
	}
}

#[cfg(unix)]
impl std::error::Error for MetadataQueryDeadline {}

#[cfg(unix)]
fn metadata_query_slots() -> Arc<Semaphore> {
	METADATA_QUERY_SLOTS
		.get_or_init(|| Arc::new(Semaphore::new(MAX_METADATA_QUERIES)))
		.clone()
}

#[cfg(unix)]
fn metadata_query_public_error(error: anyhow::Error) -> anyhow::Error {
	if error.is::<MetadataQueryDeadline>() {
		error
	} else {
		anyhow!(
			"archive index preparing or validation unavailable; repeat only this metadata query"
		)
	}
}

// Admission and blocking-pool queue time consume the original query budget.
// A cancelled caller cannot release a slot while queued or running I/O still
// owns it, and a late blocking worker must not open the archive or start a scan.
#[cfg(unix)]
async fn run_metadata_query<T: Send + 'static>(
	deadline: Instant,
	slots: Arc<Semaphore>,
	query: impl FnOnce(Instant) -> Result<T> + Send + 'static,
) -> Result<T> {
	if Instant::now() >= deadline {
		return Err(MetadataQueryDeadline.into());
	}
	let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async move {
		let permit = slots
			.acquire_owned()
			.await
			.map_err(|_| anyhow!("archive metadata query admission unavailable"))?;
		if Instant::now() >= deadline {
			return Err(MetadataQueryDeadline.into());
		}
		tokio::task::spawn_blocking(move || {
			let _permit = permit;
			if Instant::now() >= deadline {
				return Err(MetadataQueryDeadline.into());
			}
			query(deadline)
		})
		.await
		.map_err(|_| anyhow!("archive metadata query worker unavailable"))?
	})
	.await
	.map_err(|_| anyhow::Error::from(MetadataQueryDeadline))??;
	// A ready worker and an expired timer can be observed together after
	// owner scheduling delay. Never accept that stale successful result.
	if Instant::now() >= deadline {
		return Err(MetadataQueryDeadline.into());
	}
	Ok(result)
}

#[cfg(all(test, unix))]
fn usage_stats_at(root: &Path, owner: &str) -> Result<String> {
	usage_stats_at_until(root, owner, Instant::now() + index::QUERY_BUDGET)
}

#[cfg(unix)]
fn usage_stats_at_until(root: &Path, owner: &str, deadline: Instant) -> Result<String> {
	if !valid_id(owner) {
		bail!("request usage unavailable to this scope");
	}
	let archive = {
		let _guard = index::query_lock(deadline)?;
		let hot = open_store(root)?;
		hot_snapshot(root, &hot)?.1
	};
	Ok(serde_json::to_string(&index::usage(
		root, &archive, owner, deadline,
	)?)?)
}

pub async fn usage_stats(owner: &str, _params: UsageStatsParams) -> Result<String> {
	#[cfg(unix)]
	let deadline = Instant::now() + index::QUERY_BUDGET;
	let root = runtime_config()?.state_dir.clone();
	let owner = owner.to_owned();
	#[cfg(unix)]
	{
		run_metadata_query(deadline, metadata_query_slots(), move |deadline| {
			usage_stats_at_until(&root, &owner, deadline)
		})
		.await
		.map_err(metadata_query_public_error)
	}
	#[cfg(not(unix))]
	{
		let _ = (root, owner);
		bail!("request usage requires Unix descriptor support")
	}
}

#[cfg(all(test, unix))]
fn archive_history_at(root: &Path, owner: &str, params: RequestHistoryParams) -> Result<String> {
	archive_history_at_until(root, owner, params, Instant::now() + index::QUERY_BUDGET)
}

#[cfg(unix)]
fn archive_history_at_until(
	root: &Path,
	owner: &str,
	params: RequestHistoryParams,
	deadline: Instant,
) -> Result<String> {
	if !valid_id(owner) {
		bail!("request archive unavailable to this scope");
	}
	let limit = params.limit.unwrap_or(32) as usize;
	if !(1..=32).contains(&limit) || params.after_id.as_deref().is_some_and(|id| !valid_id(id)) {
		bail!("invalid request archive page");
	}
	let (archive, cursor) = {
		let _guard = index::query_lock(deadline)?;
		let hot = open_store(root)?;
		let archive = hot_snapshot(root, &hot)?.1;
		let cursor = if let Some(id) = params.after_id.as_deref() {
			let record = archive.read_record(&format!("{id}.json"))?;
			if record.owner != owner {
				bail!("request archive cursor unavailable to this scope");
			}
			Some(record)
		} else {
			None
		};
		(archive, cursor)
	};
	let (mut records, total) =
		index::page(root, &archive, owner, cursor.as_ref(), limit, deadline)?;
	let more = records.len() > limit;
	records.truncate(limit);
	let mut page = Vec::new();
	for record in &records {
		let state = match record.state {
			DurableState::Unknown if is_dispatch_active(&record.request_id)? => "accepted",
			DurableState::Unknown => "unknown",
			DurableState::Completed => "completed",
			DurableState::Failed => "failed",
		};
		page.push(
			json!({"request_id":record.request_id,"tool_name":record.tool_name,
			"state":state,"accepted_unix_ms":record.accepted_unix_ms,"elapsed_ms":record.elapsed_ms}),
		);
	}
	let next = if more {
		page.last().map(|row| row["request_id"].clone())
	} else {
		None
	};
	let output = json!({"requests":page,"next_after_id":next,"total":total,
		"archive_retention":"no_automatic_metadata_eviction","history_is_live":true,
		"coverage":"metadata_retained_at_archive_introduction_and_subsequent_admitted_requests",
		"contains_parameters_or_output":false,"automatic_operation_retry":false});
	if wire_size(&output)? > MAX_PAGE_BYTES {
		bail!("request archive wire page limit exceeded");
	}
	Ok(serde_json::to_string(&output)?)
}

pub async fn archive_history(owner: &str, params: RequestHistoryParams) -> Result<String> {
	#[cfg(unix)]
	let deadline = Instant::now() + index::QUERY_BUDGET;
	let root = runtime_config()?.state_dir.clone();
	let owner = owner.to_owned();
	#[cfg(unix)]
	{
		run_metadata_query(deadline, metadata_query_slots(), move |deadline| {
			archive_history_at_until(&root, &owner, params, deadline)
		})
		.await
		.map_err(metadata_query_public_error)
	}
	#[cfg(not(unix))]
	{
		let _ = (root, owner, params);
		bail!("request archive requires Unix descriptor support")
	}
}

#[cfg(not(unix))]
fn finish_sync(_ticket: RequestTicket, _completion: AuditCompletion) -> Result<()> {
	bail!("private request auditing requires Unix descriptor support")
}

/// The caller must preserve its original dispatch result on an error here, and
/// must not retry the operation. The durable unknown intent is the fallback.
pub async fn finish(ticket: RequestTicket, completion: AuditCompletion) -> Result<()> {
	let total = trace::Span::new("finish_total", 1, Some(0));
	let joined = tokio::task::spawn_blocking(move || {
		let result = trace::measure("finish_blocking", 1, Some(0), || {
			#[cfg(unix)]
			if let Some(coordinator) = batch::coordinator() {
				return coordinator.finish(runtime_config()?.state_dir.clone(), ticket, completion);
			}
			finish_sync(ticket, completion)
		});
		trace::flush();
		result
	})
	.await;
	let result = match joined {
		Ok(result) => {
			if let Err(error) = &result {
				trace::Span::new("finish_inner_failure", 1, Some(0)).record(Some(error));
			}
			result.map_err(|_| {
				anyhow!("request audit completion unavailable; operation must not be replayed")
			})
		}
		Err(error) => {
			let stage = if error.is_panic() {
				"finish_join_panic"
			} else if error.is_cancelled() {
				"finish_join_cancelled"
			} else {
				"finish_join_failure"
			};
			trace::Span::new(stage, 1, Some(0)).record(Some(&anyhow::Error::new(error)));
			Err(anyhow!(
				"request audit completion unavailable; operation must not be replayed"
			))
		}
	};
	let result = total.finish(result);
	trace::flush();
	result
}

/// Enable the fixed bounded coordinator only through an administrator CLI flag.
pub fn enable_group_commit() -> Result<()> {
	#[cfg(unix)]
	{
		batch::enable()
	}
	#[cfg(not(unix))]
	{
		bail!("audit group commit requires Unix descriptor support")
	}
}

/// A failed coordinator refuses readiness as well as new admissions.
pub fn group_commit_ready() -> bool {
	#[cfg(unix)]
	{
		batch::coordinator().is_none_or(|worker| worker.is_ready())
	}
	#[cfg(not(unix))]
	{
		true
	}
}

fn wire_size(value: &Value) -> Result<usize> {
	let text = serde_json::to_string(value)?;
	let result = rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(text)]);
	Ok(serde_json::to_vec(&result)?.len())
}

#[cfg(unix)]
fn history_at(root: &Path, owner: &str, params: RequestHistoryParams) -> Result<String> {
	if !valid_id(owner) {
		bail!("request history unavailable to this session");
	}
	let limit = params.limit.unwrap_or(32) as usize;
	if !(1..=32).contains(&limit) || params.after_id.as_deref().is_some_and(|id| !valid_id(id)) {
		bail!("invalid request history page");
	}
	let _guard = store_lock()?;
	let directory = open_store(root)?;
	let retained = entries(&directory)?;
	let records: Vec<_> = retained
		.iter()
		.filter(|record| record.owner == owner)
		.collect();
	let start = match params.after_id {
		Some(id) => {
			records
				.iter()
				.position(|record| record.request_id == id)
				.ok_or_else(|| {
					anyhow!("request history cursor expired or unavailable to this session")
				})? + 1
		}
		None => 0,
	};
	let mut page = Vec::new();
	for record in records.iter().skip(start).take(limit) {
		let state =
			if record.state == DurableState::Unknown && is_dispatch_active(&record.request_id)? {
				"accepted"
			} else {
				match record.state {
					DurableState::Unknown => "unknown",
					DurableState::Completed => "completed",
					DurableState::Failed => "failed",
				}
			};
		page.push(json!({"request_id":record.request_id,"tool_name":record.tool_name,"state":state,"accepted_unix_ms":record.accepted_unix_ms,"elapsed_ms":record.elapsed_ms}));
	}
	let next = if start + page.len() < records.len() {
		page.last().map(|row| row["request_id"].clone())
	} else {
		None
	};
	let output = json!({"requests":page,"next_after_id":next,"retention":{"global":MAX_GLOBAL,"per_session":MAX_OWNER},
		"status_semantics":"native_request_dispatch_observation_not_side_effect_delivery_or_business_success",
		"session_scope":"native_mcp_session_only","cross_session_resume":false,"history_is_live":true,
		"automatic_operation_retry":false});
	if wire_size(&output)? > MAX_PAGE_BYTES {
		bail!("request history wire page limit exceeded");
	}
	Ok(serde_json::to_string(&output)?)
}

#[cfg(not(unix))]
fn history_at(_root: &Path, _owner: &str, _params: RequestHistoryParams) -> Result<String> {
	bail!("private request auditing requires Unix descriptor support")
}

pub async fn history(owner: &str, params: RequestHistoryParams) -> Result<String> {
	let root = runtime_config()?.state_dir.clone();
	let owner = owner.to_owned();
	tokio::task::spawn_blocking(move || history_at(&root, &owner, params))
		.await
		.map_err(|_| anyhow!("request history unavailable to this session"))?
		.map_err(|error| {
			if error.to_string() == "request history cursor expired or unavailable to this session"
			{
				error
			} else {
				anyhow!("request history unavailable to this session or private metadata refused")
			}
		})
}

#[cfg(all(test, unix))]
#[path = "request_audit_tests.rs"]
mod tests;

#[cfg(all(test, unix))]
#[path = "request_audit_lookup_tests.rs"]
mod lookup_tests;

#[cfg(all(test, unix))]
#[path = "request_audit_query_tests.rs"]
mod query_tests;
