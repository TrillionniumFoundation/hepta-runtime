// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Private ownership-scoped request metadata. Unknown durable intent precedes dispatch;
//! an audit completion failure never proves that an operation failed or can be retried.
use anyhow::{anyhow, bail, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use super::config::runtime_config;

const MAX_GLOBAL: usize = 512;
const MAX_OWNER: usize = 128;
const MAX_RECORD_BYTES: usize = 2048;
const MAX_PAGE_BYTES: usize = 64 * 1024;
const STORE_NAME: &str = "request-audit";
static STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static ACTIVE: OnceLock<Mutex<HashMap<String, Weak<AtomicBool>>>> = OnceLock::new();
static READ_PINS: OnceLock<Mutex<HashMap<String, Vec<Weak<()>>>>> = OnceLock::new();

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

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DurableState {
	Unknown,
	Completed,
	Failed,
}

#[derive(Clone, Deserialize, Serialize)]
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
pub(crate) fn retained_ids_at(root: &Path) -> Result<std::collections::HashSet<String>> {
	let _guard = store_lock()?;
	let dir = open_store(root)?;
	Ok(entries(&dir)?.into_iter().map(|r| r.request_id).collect())
}
#[cfg(unix)]
fn observation_at(root: &Path, owner: &str, id: &str) -> Result<AuditObservation> {
	if !valid_id(owner) || !valid_id(id) {
		bail!("request unavailable to this scope");
	}
	let _guard = store_lock()?;
	let dir = open_store(root)?;
	let r = read_record(&dir, &format!("{id}.json"))
		.map_err(|_| anyhow!("request unavailable to this scope"))?;
	if r.owner != owner {
		bail!("request unavailable to this scope");
	}
	let state = match r.state {
		DurableState::Unknown if is_dispatch_active(id)? => "accepted",
		DurableState::Unknown => "unknown",
		DurableState::Completed => "completed",
		DurableState::Failed => "failed",
	};
	Ok(AuditObservation {
		identity: RequestIdentity {
			request_id: r.request_id,
			owner: r.owner,
			tool_name: r.tool_name,
			accepted_unix_ms: r.accepted_unix_ms,
		},
		state,
		elapsed_ms: r.elapsed_ms,
	})
}
#[cfg(not(unix))]
pub(crate) fn retained_ids_at(_root: &Path) -> Result<std::collections::HashSet<String>> {
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
	let r = match read_record(&dir, &format!("{id}.json")) {
		Ok(record) => record,
		Err(error)
			if error
				.downcast_ref::<std::io::Error>()
				.is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
		{
			return Ok(None)
		}
		Err(_) => bail!("request unavailable to this scope"),
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
	let mut entropy = [0u8; 32];
	File::open("/dev/urandom")?.read_exact(&mut entropy)?;
	Ok(entropy.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn store_lock() -> Result<std::sync::MutexGuard<'static, ()>> {
	STORE_LOCK
		.get_or_init(|| Mutex::new(()))
		.lock()
		.map_err(|_| anyhow!("request audit state lock unavailable"))
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
	use std::os::unix::fs::MetadataExt;
	let metadata = directory.metadata()?;
	if !metadata.is_dir()
		|| metadata.uid() != unsafe { libc::geteuid() }
		|| metadata.mode() & 0o7777 != 0o700
	{
		bail!("private request audit directory refused");
	}
	Ok(())
}

#[cfg(unix)]
fn open_store(root: &Path) -> Result<File> {
	use std::os::fd::{AsRawFd, FromRawFd};
	let raw = root
		.to_str()
		.ok_or_else(|| anyhow!("request audit root is not UTF-8"))?;
	if !root.is_absolute() || raw.split('/').any(|part| part == "." || part == "..") {
		bail!("invalid request audit root");
	}
	let slash = name("/")?;
	let descriptor = unsafe {
		libc::open(
			slash.as_ptr(),
			libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
		)
	};
	if descriptor < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	let mut base = unsafe { File::from_raw_fd(descriptor) };
	for component in raw.split('/').filter(|part| !part.is_empty()) {
		base = open_at(&base, component, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	}
	let folder = name(STORE_NAME)?;
	let made = unsafe { libc::mkdirat(base.as_raw_fd(), folder.as_ptr(), 0o700) };
	if made < 0 {
		let error = std::io::Error::last_os_error();
		if error.kind() != std::io::ErrorKind::AlreadyExists {
			return Err(error.into());
		}
	} else {
		base.sync_all()?;
	}
	let directory = open_at(&base, STORE_NAME, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_directory(&directory)?;
	Ok(directory)
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
fn read_record(directory: &File, filename: &str) -> Result<Record> {
	let mut file = open_at(directory, filename, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
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
	use std::os::fd::AsRawFd;
	// A fresh directory file description avoids a shared seek cursor between snapshots.
	let scan = open_at(directory, ".", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	let duplicate = unsafe { libc::dup(scan.as_raw_fd()) };
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
	let mut names = Vec::new();
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
		if names.len() >= MAX_GLOBAL + 32 {
			bail!("request audit retention invariant exceeded");
		}
		names.push(filename.to_owned());
	}
	// Remove only verified private staging inodes after an interrupted publication.
	// This cannot remove an active writer because all mutations use STORE_LOCK.
	for filename in names.iter().filter(|value| value.starts_with('.')) {
		cleanup_staging(directory, filename)?;
	}
	let mut result = Vec::new();
	for filename in names.iter().filter(|value| !value.starts_with('.')) {
		if result.len() >= MAX_GLOBAL || !filename.ends_with(".json") {
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
fn remove_record(directory: &File, id: &str) -> Result<()> {
	use std::os::fd::AsRawFd;
	let filename = name(&format!("{id}.json"))?;
	if unsafe { libc::unlinkat(directory.as_raw_fd(), filename.as_ptr(), 0) } < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	directory.sync_all()?;
	Ok(())
}

#[cfg(unix)]
fn retain_before_begin(directory: &File, owner: &str, records: &mut Vec<Record>) -> Result<()> {
	while records
		.iter()
		.filter(|record| record.owner == owner)
		.count()
		>= MAX_OWNER
	{
		let mut victim = None;
		for (index, record) in records.iter().enumerate() {
			if record.owner == owner && !is_active(&record.request_id)? {
				victim = Some(index);
				break;
			}
		}
		let index = victim.ok_or_else(|| anyhow!("all retained session requests are active"))?;
		remove_record(directory, &records[index].request_id)?;
		records.remove(index);
	}
	while records.len() >= MAX_GLOBAL {
		let mut victim = None;
		for (index, record) in records.iter().enumerate() {
			if !is_active(&record.request_id)? {
				victim = Some(index);
				break;
			}
		}
		let index = victim.ok_or_else(|| anyhow!("all retained requests are active"))?;
		remove_record(directory, &records[index].request_id)?;
		records.remove(index);
	}
	Ok(())
}

#[cfg(unix)]
fn save(directory: &File, record: &Record, replacing: bool) -> Result<()> {
	use std::os::fd::AsRawFd;
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
	let temporary = format!(".{}-{}.tmp", record.request_id, new_id()?);
	let mut file = open_at(
		directory,
		&temporary,
		libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
		0o600,
	)?;
	validate_file(&file)?;
	let persisted = (|| -> Result<()> {
		file.write_all(&bytes)?;
		file.sync_all()?;
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
		directory.sync_all()?;
		Ok(())
	})();
	if persisted.is_err() {
		if let Ok(temp) = name(&temporary) {
			unsafe { libc::unlinkat(directory.as_raw_fd(), temp.as_ptr(), 0) };
		}
	}
	persisted
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
	let mut records = entries(&directory)?;
	let read_pin = if let Some(id) = target {
		if !matches!(tool_name, "request_status" | "request_result")
			|| !valid_id(id)
			|| !records
				.iter()
				.any(|r| r.request_id == id && r.owner == owner)
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
	retain_before_begin(&directory, owner, &mut records)?;
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
	save(&directory, &record, false)?;
	let active = Arc::new(AtomicBool::new(true));
	active_registry()?.insert(record.request_id.clone(), Arc::downgrade(&active));
	Ok(RequestTicket {
		directory,
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
	let root = runtime_config()?.state_dir.clone();
	let owner = owner.to_owned();
	let tool = tool.to_owned();
	tokio::task::spawn_blocking(move || begin_with_read_at(&root, &owner, &tool, target.as_deref()))
		.await
		.map_err(|_| anyhow!("request audit intent unavailable; request was not dispatched"))?
		.map_err(|_| anyhow!("request audit intent unavailable; request was not dispatched"))
}

/// Only canonical router names (or `_unknown_tool`) may reach this internal API.
pub async fn begin(owner: &str, canonical_tool_name: &str) -> Result<RequestTicket> {
	let root = runtime_config()?.state_dir.clone();
	let owner = owner.to_owned();
	let tool = canonical_tool_name.to_owned();
	tokio::task::spawn_blocking(move || begin_at(&root, &owner, &tool))
		.await
		.map_err(|_| anyhow!("request audit intent unavailable; request was not dispatched"))?
		.map_err(|_| anyhow!("request audit intent unavailable; request was not dispatched"))
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
	let mut records = entries(&directory)?;
	retain_before_begin(&directory, &identity.owner, &mut records)?;
	let record = Record {
		request_id: identity.request_id,
		owner: identity.owner,
		tool_name: identity.tool_name,
		state: DurableState::Unknown,
		accepted_unix_ms: identity.accepted_unix_ms,
		elapsed_ms: None,
	};
	save(&directory, &record, false)?;
	let active = Arc::new(AtomicBool::new(true));
	active_registry()?.insert(record.request_id.clone(), Arc::downgrade(&active));
	Ok(RequestTicket {
		directory,
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
	save(&ticket.directory, &ticket.record, true)
}

#[cfg(not(unix))]
fn finish_sync(_ticket: RequestTicket, _completion: AuditCompletion) -> Result<()> {
	bail!("private request auditing requires Unix descriptor support")
}

/// The caller must preserve its original dispatch result on an error here, and
/// must not retry the operation. The durable unknown intent is the fallback.
pub async fn finish(ticket: RequestTicket, completion: AuditCompletion) -> Result<()> {
	tokio::task::spawn_blocking(move || finish_sync(ticket, completion))
		.await
		.map_err(|_| {
			anyhow!("request audit completion unavailable; operation must not be replayed")
		})?
		.map_err(|_| {
			anyhow!("request audit completion unavailable; operation must not be replayed")
		})
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
