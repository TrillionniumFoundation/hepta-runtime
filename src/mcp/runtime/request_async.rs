// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Three typed read-only operations with durable non-replayable key bindings.
//! Cancellation controls an owned Rust future, never a caller-selected process.
use super::{
	config::runtime_config,
	effective_config::EffectiveConfigParams,
	health::HostHealthParams,
	inspect::HostListParams,
	request_audit::{self, AuditCompletion, RequestIdentity},
	request_results,
};
use anyhow::{anyhow, bail, Result};
use rmcp::{
	handler::server::tool::IntoCallToolResult,
	model::{CallToolResponse, CallToolResult},
	schemars,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
	collections::HashMap,
	fs::File,
	io::{Read, Write},
	path::{Path, PathBuf},
	sync::{
		atomic::{AtomicBool, AtomicU8, Ordering},
		Arc, Mutex, OnceLock,
	},
	time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;

const STORE_NAME: &str = "request-async-v9";
const ANCHOR_NAME: &str = ".request-async-v9-anchor.json";
const MAX_RECORD_BYTES: usize = 4096;
const MAX_GLOBAL_KEYS: usize = 512;
const MAX_OWNER_KEYS: usize = 128;
const GLOBAL_ACTIVE: usize = 8;
const OWNER_ACTIVE: usize = 4;
const QUEUED: u8 = 0;
const RUNNING: u8 = 1;
const SETTLING: u8 = 2;
static STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static ROOT_PINS: OnceLock<Mutex<HashMap<PathBuf, (u64, u64)>>> = OnceLock::new();
static ADMISSION: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
static STOPPING: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(
	tag = "tool",
	content = "arguments",
	rename_all = "snake_case",
	deny_unknown_fields
)]
pub enum ReadRequest {
	HostList(HostListParams),
	HostHealth(HostHealthParams),
	EffectiveConfig(EffectiveConfigParams),
}
impl ReadRequest {
	fn tool(&self) -> &'static str {
		match self {
			Self::HostList(_) => "host_list",
			Self::HostHealth(_) => "host_health",
			Self::EffectiveConfig(_) => "effective_config",
		}
	}
	fn validate(&self) -> Result<()> {
		if let Self::HostHealth(p) = self {
			runtime_config()?.host(&p.host)?;
		}
		Ok(())
	}
	async fn dispatch(self) -> Result<CallToolResponse, rmcp::ErrorData> {
		let result = match self {
			Self::HostList(_) => super::inspect::host_list(),
			Self::HostHealth(p) => super::health::host_health(p).await,
			Self::EffectiveConfig(p) => super::effective_config::effective_config(p),
		};
		result
			.map_err(|error| error.to_string())
			.into_call_tool_result()
	}
}
#[derive(Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestStartParams {
	pub operation: ReadRequest,
	/// Required 1..128-byte private key. Reuse only with identical typed arguments.
	pub idempotency_key: String,
}
#[derive(Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestCancelParams {
	/// Opaque server-generated inner request id; never an OS process id.
	pub request_id: String,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Binding {
	request_id: String,
	owner: String,
	tool_name: String,
	accepted_unix_ms: u128,
	key_hash: String,
	request_hash: String,
	policy_binding: String,
}
impl Binding {
	fn identity(&self) -> RequestIdentity {
		RequestIdentity {
			request_id: self.request_id.clone(),
			owner: self.owner.clone(),
			tool_name: self.tool_name.clone(),
			accepted_unix_ms: self.accepted_unix_ms,
		}
	}
}
enum Reservation {
	New(Binding),
	Existing(Binding),
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
	device: u64,
	inode: u64,
	occupancy_device: u64,
	occupancy_inode: u64,
	intents_device: u64,
	intents_inode: u64,
	metadata_lock_device: u64,
	metadata_lock_inode: u64,
	controller_lock_device: u64,
	controller_lock_inode: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Outcome {
	request_id: String,
	owner: String,
	key_hash: String,
	policy_binding: String,
	state: String,
}
fn check_outcome(b: &Binding, o: &Outcome) -> Result<()> {
	if o.request_id != b.request_id
		|| o.owner != b.owner
		|| o.key_hash != b.key_hash
		|| o.policy_binding != b.policy_binding
		|| !matches!(
			o.state.as_str(),
			"completed" | "failed" | "cancelled_before_dispatch" | "cancelled_future" | "unknown"
		) {
		bail!("async outcome unavailable");
	}
	Ok(())
}
struct Active {
	binding: Binding,
	cancel: CancellationToken,
	phase: AtomicU8,
}
#[derive(Default)]
struct Registry {
	reserved: HashMap<String, usize>,
	active: HashMap<String, Arc<Active>>,
	lease: Option<(PathBuf, File)>,
}
fn registry() -> Result<std::sync::MutexGuard<'static, Registry>> {
	REGISTRY
		.get_or_init(|| Mutex::new(Registry::default()))
		.lock()
		.map_err(|_| anyhow!("async request state unavailable"))
}
pub(crate) struct Slot {
	owner: String,
}
impl Slot {
	pub(crate) fn take(owner: &str) -> Result<Self> {
		let mut r = registry()?;
		if STOPPING.load(Ordering::Acquire) {
			bail!("async admission is frozen; existing receipts remain queryable");
		}
		if r.reserved.values().sum::<usize>() >= GLOBAL_ACTIVE
			|| r.reserved.get(owner).copied().unwrap_or(0) >= OWNER_ACTIVE
		{
			bail!("async request concurrency unavailable; existing keys and receipts remain queryable");
		}
		*r.reserved.entry(owner.into()).or_default() += 1;
		Ok(Self {
			owner: owner.into(),
		})
	}
}
impl Drop for Slot {
	fn drop(&mut self) {
		if let Ok(mut r) = registry() {
			if let Some(count) = r.reserved.get_mut(&self.owner) {
				*count = count.saturating_sub(1);
				if *count == 0 {
					r.reserved.remove(&self.owner);
				}
			}
		}
	}
}
struct ActiveGuard {
	id: String,
	_slot: Slot,
}
impl Drop for ActiveGuard {
	fn drop(&mut self) {
		if let Ok(mut r) = registry() {
			r.active.remove(&self.id);
		}
	}
}
fn valid_id(s: &str) -> bool {
	s.len() == 64
		&& s.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_key(s: &str) -> bool {
	!s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control)
}
fn digest(bytes: &[u8]) -> String {
	Sha256::digest(bytes)
		.iter()
		.map(|b| format!("{b:02x}"))
		.collect()
}
fn key_hash(owner: &str, key: &str) -> String {
	let mut hash = Sha256::new();
	hash.update(b"hepta-runtime/async-key/v9\0");
	hash.update(owner.as_bytes());
	hash.update([0]);
	hash.update(key.as_bytes());
	hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}
fn request_hash(operation: &ReadRequest) -> Result<String> {
	let mut bytes = b"hepta-runtime/async-typed-request/v9\0".to_vec();
	bytes.extend(serde_json::to_vec(operation)?);
	Ok(digest(&bytes))
}
fn next_id() -> Result<String> {
	let mut bytes = [0u8; 32];
	File::open("/dev/urandom")?.read_exact(&mut bytes)?;
	Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn valid_binding(r: &Binding) -> bool {
	[
		&r.request_id,
		&r.owner,
		&r.key_hash,
		&r.request_hash,
		&r.policy_binding,
	]
	.iter()
	.all(|v| valid_id(v))
		&& request_results::eligible(&r.tool_name)
}
#[cfg(unix)]
fn open_at(parent: &File, name: &str, flags: i32, mode: u32) -> Result<File> {
	use std::os::fd::{AsRawFd, FromRawFd};
	let name = std::ffi::CString::new(name)?;
	let fd = unsafe {
		libc::openat(
			parent.as_raw_fd(),
			name.as_ptr(),
			flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
			mode,
		)
	};
	if fd < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	Ok(unsafe { File::from_raw_fd(fd) })
}
#[cfg(unix)]
fn private_dir(file: &File) -> Result<()> {
	use std::os::unix::fs::MetadataExt;
	let m = file.metadata()?;
	if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7777 != 0o700 {
		bail!("private async directory unavailable");
	}
	Ok(())
}
#[cfg(unix)]
fn private_file(file: &File) -> Result<()> {
	use std::os::unix::fs::MetadataExt;
	let m = file.metadata()?;
	if !m.is_file()
		|| m.uid() != unsafe { libc::geteuid() }
		|| m.mode() & 0o7777 != 0o600
		|| m.nlink() != 1
		|| m.len() > MAX_RECORD_BYTES as u64
	{
		bail!("private async metadata unavailable");
	}
	Ok(())
}
#[cfg(unix)]
fn root_handle(root: &Path) -> Result<File> {
	let raw = root
		.to_str()
		.ok_or_else(|| anyhow!("private async root unavailable"))?;
	if !root.is_absolute() || raw.split('/').any(|p| p == "." || p == "..") {
		bail!("private async root unavailable");
	}
	let mut base = File::open("/")?;
	for component in raw.split('/').filter(|p| !p.is_empty()) {
		base = open_at(&base, component, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	}
	Ok(base)
}
#[cfg(unix)]
fn root_at(root: &Path) -> Result<File> {
	let base = root_handle(root)?;
	private_dir(&base)?;
	Ok(base)
}
#[cfg(unix)]
fn make_dir(parent: &File, name: &str) -> Result<File> {
	use std::os::fd::AsRawFd;
	let n = std::ffi::CString::new(name)?;
	if unsafe { libc::mkdirat(parent.as_raw_fd(), n.as_ptr(), 0o700) } < 0 {
		let error = std::io::Error::last_os_error();
		if error.kind() != std::io::ErrorKind::AlreadyExists {
			return Err(error.into());
		}
	} else {
		parent.sync_all()?;
	}
	let dir = open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_dir(&dir)?;
	Ok(dir)
}
#[cfg(unix)]
fn read_json<T: serde::de::DeserializeOwned>(dir: &File, name: &str) -> Result<T> {
	let mut f = open_at(dir, name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
	private_file(&f)?;
	let mut bytes = Vec::new();
	Read::by_ref(&mut f)
		.take((MAX_RECORD_BYTES + 1) as u64)
		.read_to_end(&mut bytes)?;
	if bytes.len() > MAX_RECORD_BYTES {
		bail!("private async metadata unavailable");
	}
	Ok(serde_json::from_slice(&bytes)?)
}
#[cfg(unix)]
fn publish<T: Serialize>(dir: &File, name: &str, value: &T) -> Result<()> {
	use std::os::fd::AsRawFd;
	let bytes = serde_json::to_vec(value)?;
	if bytes.len() > MAX_RECORD_BYTES {
		bail!("async metadata bound exceeded");
	}
	let temporary = format!(".publish-{}", next_id()?);
	let mut f = open_at(
		dir,
		&temporary,
		libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
		0o600,
	)?;
	let result = (|| {
		f.write_all(&bytes)?;
		f.sync_all()?;
		let from = std::ffi::CString::new(temporary.as_str())?;
		let to = std::ffi::CString::new(name)?;
		if unsafe {
			libc::linkat(
				dir.as_raw_fd(),
				from.as_ptr(),
				dir.as_raw_fd(),
				to.as_ptr(),
				0,
			)
		} < 0
		{
			return Err(std::io::Error::last_os_error().into());
		}
		if unsafe { libc::unlinkat(dir.as_raw_fd(), from.as_ptr(), 0) } < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		dir.sync_all()?;
		Ok(())
	})();
	// Only staging may be removed on failure. A published key is never erased.
	if result.is_err() {
		if let Ok(n) = std::ffi::CString::new(temporary.as_str()) {
			unsafe {
				libc::unlinkat(dir.as_raw_fd(), n.as_ptr(), 0);
			}
		}
	}
	result
}
#[cfg(unix)]
fn create_lock(dir: &File, name: &str) -> Result<File> {
	let file = open_at(
		dir,
		name,
		libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
		0o600,
	)?;
	private_file(&file)?;
	file.sync_all()?;
	dir.sync_all()?;
	Ok(file)
}
#[cfg(unix)]
fn pinned_lock(dir: &File, name: &str, device: u64, inode: u64) -> Result<File> {
	use std::os::unix::fs::MetadataExt;
	let file = open_at(dir, name, libc::O_RDWR | libc::O_NONBLOCK, 0)?;
	private_file(&file)?;
	let metadata = file.metadata()?;
	if metadata.dev() != device || metadata.ino() != inode || metadata.len() != 0 {
		bail!("async lock identity changed; never create a replacement lock");
	}
	Ok(file)
}
#[cfg(unix)]
fn anchored_lock(root: &Path, dir: &File, name: &str) -> Result<File> {
	use std::os::unix::fs::MetadataExt;
	let base = root_at(root)?;
	let anchor: Anchor =
		read_json(&base, ANCHOR_NAME).map_err(|_| anyhow!("async lock anchor unavailable"))?;
	let metadata = dir.metadata()?;
	if metadata.dev() != anchor.device || metadata.ino() != anchor.inode {
		bail!("async lock namespace changed");
	}
	match name {
		".lock" => pinned_lock(
			dir,
			name,
			anchor.metadata_lock_device,
			anchor.metadata_lock_inode,
		),
		".controller.lock" => pinned_lock(
			dir,
			name,
			anchor.controller_lock_device,
			anchor.controller_lock_inode,
		),
		_ => bail!("async lock identity unavailable"),
	}
}
#[cfg(unix)]
fn store(root: &Path) -> Result<File> {
	use std::os::unix::fs::MetadataExt;
	let base = root_at(root)?;
	let metadata = base.metadata()?;
	let mut pins = ROOT_PINS
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.map_err(|_| anyhow!("async root binding unavailable"))?;
	match pins.get(root) {
		Some(old) if *old != (metadata.dev(), metadata.ino()) => {
			bail!("async root binding changed; keys unavailable")
		}
		Some(_) => {}
		None => {
			if pins.len() >= 128 {
				bail!("async root namespace bound exceeded");
			}
			pins.insert(root.into(), (metadata.dev(), metadata.ino()));
		}
	}
	drop(pins);
	let existing = read_json::<Anchor>(&base, ANCHOR_NAME);
	let dir = match existing {
		Ok(anchor) => {
			let dir = open_at(&base, STORE_NAME, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
			private_dir(&dir)?;
			let m = dir.metadata()?;
			if m.dev() != anchor.device || m.ino() != anchor.inode {
				bail!("async journal binding changed; keys unavailable");
			}
			let occupancy = open_at(&dir, ".occupied", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
			private_dir(&occupancy)?;
			let occupied = occupancy.metadata()?;
			if occupied.dev() != anchor.occupancy_device || occupied.ino() != anchor.occupancy_inode
			{
				bail!("async occupancy binding changed; never replay");
			}
			let intents = open_at(&dir, ".intents", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
			private_dir(&intents)?;
			let intent_metadata = intents.metadata()?;
			if intent_metadata.dev() != anchor.intents_device
				|| intent_metadata.ino() != anchor.intents_inode
			{
				bail!("async intent history binding changed; never replay");
			}
			pinned_lock(
				&dir,
				".lock",
				anchor.metadata_lock_device,
				anchor.metadata_lock_inode,
			)?;
			pinned_lock(
				&dir,
				".controller.lock",
				anchor.controller_lock_device,
				anchor.controller_lock_inode,
			)?;
			dir
		}
		Err(error) if missing(&error) => {
			// An unanchored existing directory is uncertain, never an empty namespace.
			match open_at(&base, STORE_NAME, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
				Ok(_) => bail!("unanchored async journal unavailable"),
				Err(error) if missing(&error) => {}
				Err(error) => return Err(error),
			}
			let dir = make_dir(&base, STORE_NAME)?;
			let occupancy = make_dir(&dir, ".occupied")?;
			let occupied = occupancy.metadata()?;
			let intents = make_dir(&dir, ".intents")?;
			let intent_metadata = intents.metadata()?;
			let metadata_lock = create_lock(&dir, ".lock")?.metadata()?;
			let controller_lock = create_lock(&dir, ".controller.lock")?.metadata()?;
			let m = dir.metadata()?;
			publish(
				&base,
				ANCHOR_NAME,
				&Anchor {
					device: m.dev(),
					inode: m.ino(),
					occupancy_device: occupied.dev(),
					occupancy_inode: occupied.ino(),
					intents_device: intent_metadata.dev(),
					intents_inode: intent_metadata.ino(),
					metadata_lock_device: metadata_lock.dev(),
					metadata_lock_inode: metadata_lock.ino(),
					controller_lock_device: controller_lock.dev(),
					controller_lock_inode: controller_lock.ino(),
				},
			)?;
			dir
		}
		Err(_) => bail!("async journal anchor unavailable"),
	};
	make_dir(&dir, ".outcomes")?;
	Ok(dir)
}
fn missing(error: &anyhow::Error) -> bool {
	error
		.downcast_ref::<std::io::Error>()
		.is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}
#[cfg(unix)]
struct MetadataLock(File);
#[cfg(unix)]
impl Drop for MetadataLock {
	fn drop(&mut self) {
		use std::os::fd::AsRawFd;
		// A forked child shares this open-file description until exec or exit.
		// Closing only the parent's fd would leave its short metadata lock held.
		// The controller's long-lived ownership lease deliberately stays separate.
		unsafe {
			libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
		}
	}
}
#[cfg(unix)]
fn locked_store(root: &Path) -> Result<(File, MetadataLock)> {
	use std::os::fd::AsRawFd;
	let dir = store(root)?;
	let lock = anchored_lock(root, &dir, ".lock")?;
	if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	Ok((dir, MetadataLock(lock)))
}
#[cfg(unix)]
fn names(dir: &File) -> Result<Vec<String>> {
	names_impl(dir, true)
}
#[cfg(unix)]
fn record_names(dir: &File) -> Result<Vec<String>> {
	names_impl(dir, false)
}
#[cfg(unix)]
fn names_impl(dir: &File, root: bool) -> Result<Vec<String>> {
	use std::os::fd::AsRawFd;
	let scan = open_at(dir, ".", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	let fd = unsafe { libc::dup(scan.as_raw_fd()) };
	if fd < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	let stream = unsafe { libc::fdopendir(fd) };
	if stream.is_null() {
		unsafe {
			libc::close(fd);
		}
		return Err(std::io::Error::last_os_error().into());
	}
	struct Stream(*mut libc::DIR);
	impl Drop for Stream {
		fn drop(&mut self) {
			unsafe {
				libc::closedir(self.0);
			}
		}
	}
	let guard = Stream(stream);
	let mut result = Vec::new();
	loop {
		#[cfg(target_os = "linux")]
		let errno = unsafe { libc::__errno_location() };
		#[cfg(target_os = "macos")]
		let errno = unsafe { libc::__error() };
		#[cfg(not(any(target_os = "linux", target_os = "macos")))]
		{
			let _ = &guard;
			bail!("async directory scan unsupported");
		}
		#[cfg(any(target_os = "linux", target_os = "macos"))]
		{
			unsafe {
				*errno = 0;
			}
			let entry = unsafe { libc::readdir(guard.0) };
			if entry.is_null() {
				if unsafe { *errno } != 0 {
					bail!("async directory scan unavailable");
				}
				break;
			}
			let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
				.to_str()?
				.to_owned();
			if matches!(name.as_str(), "." | "..")
				|| (root
					&& matches!(
						name.as_str(),
						".lock" | ".outcomes" | ".occupied" | ".intents" | ".controller.lock"
					)) {
				continue;
			}
			// Incomplete publication is an explicit refusal, never silently treated absent.
			if result.len() >= MAX_GLOBAL_KEYS
				|| !name.ends_with(".json")
				|| !valid_id(&name[..name.len().saturating_sub(5)])
			{
				bail!("async key registry unavailable; administrator review required");
			}
			result.push(name);
		}
	}
	Ok(result)
}
#[cfg(unix)]
fn bindings(dir: &File) -> Result<Vec<Binding>> {
	let occupancy = open_at(dir, ".occupied", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	let intents = open_at(dir, ".intents", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	let outcomes = open_at(dir, ".outcomes", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_dir(&occupancy)?;
	private_dir(&intents)?;
	private_dir(&outcomes)?;
	let mut occupied_names = record_names(&occupancy)?;
	let mut primary_names = names(dir)?;
	occupied_names.sort_unstable();
	primary_names.sort_unstable();
	let mut by_key = HashMap::new();
	let mut by_id = HashMap::new();
	for name in record_names(&intents)? {
		let b: Binding =
			read_json(&intents, &name).map_err(|_| anyhow!("async intent history unavailable"))?;
		if !valid_binding(&b)
			|| name != format!("{}.json", b.request_id)
			|| by_key.insert(b.key_hash.clone(), b.clone()).is_some()
			|| by_id.insert(b.request_id.clone(), b).is_some()
		{
			bail!("async intent history unavailable");
		}
	}
	if occupied_names != primary_names || occupied_names.len() != by_key.len() {
		bail!("async key history incomplete; never replay or repair automatically");
	}
	let mut result = Vec::new();
	for name in occupied_names {
		let b = binding_pair(dir, &name[..name.len() - 5])?
			.ok_or_else(|| anyhow!("async key registry changed"))?;
		if by_key.get(&b.key_hash) != Some(&b) {
			bail!("async key history identity changed");
		}
		result.push(b);
	}
	for name in record_names(&outcomes)? {
		let outcome: Outcome = read_json(&outcomes, &name)
			.map_err(|_| anyhow!("async outcome history unavailable"))?;
		let b = by_id.get(&outcome.request_id).ok_or_else(|| {
			anyhow!("async outcome has no complete historical binding; never replay")
		})?;
		if name != format!("{}.json", outcome.request_id) {
			bail!("async outcome identity changed");
		}
		check_outcome(b, &outcome)?;
	}
	Ok(result)
}
#[cfg(unix)]
fn binding_pair(dir: &File, hash: &str) -> Result<Option<Binding>> {
	let occupancy = open_at(dir, ".occupied", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_dir(&occupancy)?;
	let name = format!("{hash}.json");
	let primary = read_json::<Binding>(dir, &name);
	let occupied = read_json::<Binding>(&occupancy, &name);
	match (primary, occupied) {
		(Ok(primary), Ok(occupied))
			if primary == occupied && valid_binding(&primary) && primary.key_hash == hash =>
		{
			let intents = open_at(dir, ".intents", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
			private_dir(&intents)?;
			let intent: Binding = read_json(&intents, &format!("{}.json", primary.request_id))
				.map_err(|_| anyhow!("async historical intent unavailable; never replay"))?;
			if intent != primary {
				bail!("async historical intent identity changed");
			}
			Ok(Some(primary))
		}
		(Err(primary), Err(occupied)) if missing(&primary) && missing(&occupied) => Ok(None),
		_ => bail!(
			"async key binding or occupancy unavailable; never replay or repair automatically"
		),
	}
}
fn check_binding(b: &Binding, owner: &str, hash: &str, request: &str, policy: &str) -> Result<()> {
	if b.owner != owner
		|| b.key_hash != hash
		|| b.request_hash != request
		|| b.policy_binding != policy
	{
		bail!("async key unavailable to this scope, arguments or current policy");
	}
	Ok(())
}
#[cfg(unix)]
fn lookup_key_at(
	root: &Path,
	owner: &str,
	hash: &str,
	request: &str,
	policy: &str,
) -> Result<Option<Binding>> {
	let _lock = STORE_LOCK
		.get_or_init(|| Mutex::new(()))
		.lock()
		.map_err(|_| anyhow!("async metadata unavailable"))?;
	let (dir, _lease) = locked_store(root)?;
	let Some(b) = binding_pair(&dir, hash)? else {
		// Absence of both key markers is not a fresh permit while any independent
		// historical intent/outcome remains inconsistent with this namespace.
		bindings(&dir)?;
		return Ok(None);
	};
	if !valid_binding(&b) {
		bail!("async key unavailable");
	}
	check_binding(&b, owner, hash, request, policy)?;
	Ok(Some(b))
}
#[cfg(unix)]
fn lookup_id_at(root: &Path, owner: &str, id: &str, policy: &str) -> Result<Option<Binding>> {
	if !valid_id(owner) || !valid_id(id) || !valid_id(policy) {
		bail!("async request unavailable to this scope");
	}
	let _lock = STORE_LOCK
		.get_or_init(|| Mutex::new(()))
		.lock()
		.map_err(|_| anyhow!("async metadata unavailable"))?;
	// A legacy V8 lookup never creates an async namespace or adds a new
	// state-root permission requirement when no async journal exists.
	let base = root_handle(root)?;
	match read_json::<Anchor>(&base, ANCHOR_NAME) {
		Ok(_) => {}
		Err(error) if missing(&error) => {
			match open_at(&base, STORE_NAME, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
				Err(error) if missing(&error) => return Ok(None),
				_ => bail!("unanchored async journal unavailable"),
			}
		}
		Err(_) => bail!("async journal unavailable"),
	}
	let (dir, _lease) = locked_store(root)?;
	for b in bindings(&dir)? {
		if b.request_id == id {
			if b.owner != owner || b.policy_binding != policy {
				bail!("async request unavailable to this scope or current policy");
			}
			let pair = binding_pair(&dir, &b.key_hash)?
				.ok_or_else(|| anyhow!("async occupancy is not a fresh key"))?;
			if pair != b {
				bail!("async key binding changed");
			}
			return Ok(Some(b));
		}
	}
	Ok(None)
}
#[cfg(unix)]
fn reserve_at(root: &Path, candidate: Binding) -> Result<Reservation> {
	if !valid_binding(&candidate) {
		bail!("async admission unavailable");
	}
	let _lock = STORE_LOCK
		.get_or_init(|| Mutex::new(()))
		.lock()
		.map_err(|_| anyhow!("async metadata unavailable"))?;
	let (dir, _lease) = locked_store(root)?;
	let name = format!("{}.json", candidate.key_hash);
	if let Some(old) = binding_pair(&dir, &candidate.key_hash)? {
		if old.tool_name != candidate.tool_name {
			bail!("async key unavailable to this operation");
		}
		if !valid_binding(&old) {
			bail!("async key unavailable");
		}
		check_binding(
			&old,
			&candidate.owner,
			&candidate.key_hash,
			&candidate.request_hash,
			&candidate.policy_binding,
		)?;
		return Ok(Reservation::Existing(old));
	}
	let existing = bindings(&dir)?;
	if existing
		.iter()
		.any(|b| b.request_id == candidate.request_id)
	{
		bail!("generated request identity already bound");
	}
	if existing.len() >= MAX_GLOBAL_KEYS
		|| existing
			.iter()
			.filter(|b| b.owner == candidate.owner)
			.count() >= MAX_OWNER_KEYS
	{
		bail!("async key retention full; new keys refused, existing keys never rebound");
	}
	let occupancy = open_at(&dir, ".occupied", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_dir(&occupancy)?;
	// Burn the identity-indexed historical intent before either key marker.
	// Every incomplete graph refuses: no reconstruction or reissued permit.
	let intents = open_at(&dir, ".intents", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_dir(&intents)?;
	publish(
		&intents,
		&format!("{}.json", candidate.request_id),
		&candidate,
	)?;
	publish(&occupancy, &name, &candidate)?;
	publish(&dir, &name, &candidate)?;
	Ok(Reservation::New(candidate))
}
#[cfg(unix)]
fn acquire_controller(root: &Path) -> Result<()> {
	use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
	let dir = store(root)?;
	let lock = anchored_lock(root, &dir, ".controller.lock")?;
	let mut r = registry()?;
	if let Some((old, held)) = &r.lease {
		private_file(held)?;
		let saved = held.metadata()?;
		let current = lock.metadata()?;
		if old != root
			|| saved.dev() != current.dev()
			|| saved.ino() != current.ino()
			|| saved.len() != 0
		{
			bail!("async controller binding changed");
		}
		return Ok(());
	}
	if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
		bail!("another controller owns async execution; existing receipts remain readable");
	}
	r.lease = Some((root.into(), lock));
	Ok(())
}
#[cfg(unix)]
fn outcome_at(root: &Path, b: &Binding, state: Option<&str>) -> Result<Option<String>> {
	let _lock = STORE_LOCK
		.get_or_init(|| Mutex::new(()))
		.lock()
		.map_err(|_| anyhow!("async metadata unavailable"))?;
	let (dir, _lease) = locked_store(root)?;
	let saved =
		binding_pair(&dir, &b.key_hash)?.ok_or_else(|| anyhow!("async occupancy missing"))?;
	if saved != *b {
		bail!("async outcome binding changed");
	}
	let outcomes = open_at(&dir, ".outcomes", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	private_dir(&outcomes)?;
	let name = format!("{}.json", b.request_id);
	if let Some(state) = state {
		if !matches!(
			state,
			"completed" | "failed" | "cancelled_before_dispatch" | "cancelled_future" | "unknown"
		) {
			bail!("async outcome unavailable");
		}
		publish(
			&outcomes,
			&name,
			&Outcome {
				request_id: b.request_id.clone(),
				owner: b.owner.clone(),
				key_hash: b.key_hash.clone(),
				policy_binding: b.policy_binding.clone(),
				state: state.into(),
			},
		)?;
	}
	let o: Outcome = match read_json(&outcomes, &name) {
		Ok(o) => o,
		Err(error) if missing(&error) => return Ok(None),
		Err(_) => bail!("async outcome unavailable"),
	};
	check_outcome(b, &o)?;
	Ok(Some(o.state))
}
#[cfg(not(unix))]
fn lookup_key_at(
	_root: &Path,
	_owner: &str,
	_hash: &str,
	_request: &str,
	_policy: &str,
) -> Result<Option<Binding>> {
	bail!("async private state requires Unix");
}
#[cfg(not(unix))]
fn lookup_id_at(_root: &Path, _owner: &str, _id: &str, _policy: &str) -> Result<Option<Binding>> {
	bail!("async private state requires Unix");
}
#[cfg(not(unix))]
fn reserve_at(_root: &Path, _candidate: Binding) -> Result<Reservation> {
	bail!("async private state requires Unix");
}
#[cfg(not(unix))]
fn acquire_controller(_root: &Path) -> Result<()> {
	bail!("async private state requires Unix");
}
#[cfg(not(unix))]
fn outcome_at(_root: &Path, _b: &Binding, _state: Option<&str>) -> Result<Option<String>> {
	bail!("async private state requires Unix");
}

fn phase(b: &Binding) -> Result<&'static str> {
	let r = registry()?;
	match r.active.get(&b.request_id) {
		Some(a) if a.binding == *b => Ok(match a.phase.load(Ordering::Acquire) {
			QUEUED => "queued",
			RUNNING => "running",
			_ => "settling",
		}),
		Some(_) => bail!("async live identity changed"),
		None => Ok("unknown"),
	}
}
fn admission_receipt(b: &Binding, reused: bool) -> Result<String> {
	Ok(serde_json::to_string(
		&json!({"request_id":b.request_id,"tool_name":b.tool_name,"reused":reused,
        "async_state":phase(b)?,"idempotency_binding_retained":true,"automatic_retry":false,
        "delivery_proven":false,"execution_resume_after_restart":false,
        "admission_is_not_dispatch_completion":true,"authenticated_chatgpt_caller_isolation":false}),
	)?)
}
pub async fn start(owner: &str, p: RequestStartParams) -> Result<String> {
	if !valid_id(owner) || !valid_key(&p.idempotency_key) {
		bail!("async request parameters unavailable");
	}
	p.operation.validate()?;
	let policy = request_results::policy_binding()?;
	let hash = key_hash(owner, &p.idempotency_key);
	let request = request_hash(&p.operation)?;
	let root = runtime_config()?.state_dir.clone();
	let (read_root, read_owner, read_hash, read_request, read_policy) = (
		root.clone(),
		owner.to_owned(),
		hash.clone(),
		request.clone(),
		policy.clone(),
	);
	if let Some(old) = tokio::task::spawn_blocking(move || {
		lookup_key_at(
			&read_root,
			&read_owner,
			&read_hash,
			&read_request,
			&read_policy,
		)
	})
	.await??
	{
		return checked_receipt(&old, true).await;
	}
	let _admission = ADMISSION
		.get_or_init(|| tokio::sync::Mutex::new(()))
		.lock()
		.await;
	// A duplicate racing admission must be resolved before concurrency admission.
	let (read_root, read_owner, read_hash, read_request, read_policy) = (
		root.clone(),
		owner.to_owned(),
		hash.clone(),
		request.clone(),
		policy.clone(),
	);
	if let Some(old) = tokio::task::spawn_blocking(move || {
		lookup_key_at(
			&read_root,
			&read_owner,
			&read_hash,
			&read_request,
			&read_policy,
		)
	})
	.await??
	{
		return checked_receipt(&old, true).await;
	}
	if STOPPING.load(Ordering::Acquire) {
		bail!("async controller is shutting down");
	}
	let slot = Slot::take(owner)?;
	let lease_root = root.clone();
	tokio::task::spawn_blocking(move || acquire_controller(&lease_root)).await??;
	let candidate = Binding {
		request_id: next_id()?,
		owner: owner.into(),
		tool_name: p.operation.tool().into(),
		accepted_unix_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
		key_hash: hash,
		request_hash: request,
		policy_binding: policy,
	};
	let write_root = root.clone();
	let reservation =
		tokio::task::spawn_blocking(move || reserve_at(&write_root, candidate)).await??;
	let binding = match reservation {
		Reservation::Existing(old) => return checked_receipt(&old, true).await,
		Reservation::New(new) => new,
	};
	// The immutable key is already bound. Any failure below returns this ID,
	// never recreates a permit, resumes a prior admission, or reruns an effect.
	let ticket = match request_audit::begin_reserved(binding.identity()).await {
		Ok(ticket) => ticket,
		Err(_) => return checked_receipt(&binding, false).await,
	};
	let intent = match request_results::admit(ticket.identity()).await {
		Ok(intent) => intent,
		Err(_) => {
			let _ = request_audit::finish(ticket, AuditCompletion::Unknown).await;
			return checked_receipt(&binding, false).await;
		}
	};
	let active = Arc::new(Active {
		binding: binding.clone(),
		cancel: CancellationToken::new(),
		phase: AtomicU8::new(QUEUED),
	});
	registry()?
		.active
		.insert(binding.request_id.clone(), active.clone());
	let guard = ActiveGuard {
		id: binding.request_id.clone(),
		_slot: slot,
	};
	let receipt = checked_receipt(&binding, false).await?;
	let owned_binding = binding.clone();
	tokio::spawn(async move {
		let _guard = guard;
		// Never inherit the outer rmcp request token: its normal reply cancels it.
		// Yield does not claim transport delivery; the durable receipt is recoverable.
		tokio::task::yield_now().await;
		let (result, state) = if active.cancel.is_cancelled() {
			(None, "cancelled_before_dispatch")
		} else {
			active.phase.store(RUNNING, Ordering::Release);
			let operation = tokio::time::timeout(Duration::from_secs(15), p.operation.dispatch());
			tokio::pin!(operation);
			tokio::select! {
				biased;
				_ = active.cancel.cancelled() => (None, "cancelled_future"),
				value = &mut operation => match value {
					Ok(value) => (Some(value), "completed"),
					Err(_) => (None, "unknown"),
				}
			}
		};
		active.phase.store(SETTLING, Ordering::Release);
		// Cancellation cannot abort this settlement; spawn_blocking durability
		// writes are non-abortable once admitted.
		let mut result = result;
		if let Some(ref mut result) = result {
			request_results::attach_identity(result, &owned_binding.request_id);
			request_results::reserve_final_wire(
				result,
				&owned_binding.tool_name,
				&owned_binding.request_id,
			);
		}
		let payload: Option<CallToolResult> = match &result {
			Some(Ok(CallToolResponse::Complete(value))) if !value.is_error.unwrap_or(false) => {
				Some(value.clone())
			}
			_ => None,
		};
		let completion = match &result {
			Some(Ok(CallToolResponse::Complete(value))) if !value.is_error.unwrap_or(false) => {
				AuditCompletion::Completed
			}
			Some(_) => AuditCompletion::Failed,
			None => AuditCompletion::Unknown,
		};
		let retained = request_results::complete(intent, payload).await.is_ok();
		let audited = request_audit::finish(ticket, completion).await.is_ok();
		let terminal = if !retained || !audited {
			"unknown"
		} else if matches!(completion, AuditCompletion::Failed) {
			"failed"
		} else {
			state
		};
		let _ =
			tokio::task::spawn_blocking(move || outcome_at(&root, &owned_binding, Some(terminal)))
				.await;
	});
	Ok(receipt)
}
fn check_audit_identity(b: &Binding, identity: &RequestIdentity) -> Result<()> {
	if identity.request_id != b.request_id
		|| identity.owner != b.owner
		|| identity.tool_name != b.tool_name
		|| identity.accepted_unix_ms != b.accepted_unix_ms
	{
		bail!("async request audit identity unavailable");
	}
	Ok(())
}
async fn audit_present(b: &Binding) -> Result<bool> {
	match request_audit::optional_observation(&b.owner, &b.request_id).await? {
		Some(observation) => {
			check_audit_identity(b, &observation.identity)?;
			Ok(true)
		}
		None => Ok(false),
	}
}
async fn checked_receipt(b: &Binding, reused: bool) -> Result<String> {
	audit_present(b).await?;
	admission_receipt(b, reused)
}
pub(crate) async fn observation(owner: &str, id: &str) -> Result<Option<Value>> {
	let root = runtime_config()?.state_dir.clone();
	let binding = request_results::policy_binding()?;
	let (read_owner, read_id) = (owner.to_owned(), id.to_owned());
	let b =
		tokio::task::spawn_blocking(move || lookup_id_at(&root, &read_owner, &read_id, &binding))
			.await??;
	let Some(b) = b else {
		return Ok(None);
	};
	let audit_metadata_available = audit_present(&b).await?;
	let live = phase(&b)?;
	let root = runtime_config()?.state_dir.clone();
	let copy = b.clone();
	let durable = tokio::task::spawn_blocking(move || outcome_at(&root, &copy, None)).await??;
	let state = if live != "unknown" {
		live.to_owned()
	} else {
		durable.unwrap_or_else(|| "unknown".into())
	};
	Ok(Some(
		json!({"async_state":state,"audit_metadata_available":audit_metadata_available,
        "early_return_async_start_supported":true,
        "owned_future_active":live!="unknown","automatic_retry":false,"execution_resume_after_restart":false,
        "cancellation_does_not_prove_remote_effect_stopped":true,"remote_termination_confirmed":false}),
	))
}
/// Preserve V8's read pin whenever audit metadata exists. A durable async key
/// reserved before audit admission may instead expose only owned unknown state.
pub(crate) async fn audit_read_target(owner: &str, id: &str) -> Result<Option<String>> {
	match observation(owner, id).await? {
		Some(observation)
			if observation.get("audit_metadata_available") == Some(&Value::Bool(false)) =>
		{
			Ok(None)
		}
		_ => Ok(Some(id.to_owned())),
	}
}
pub async fn cancel(owner: &str, p: RequestCancelParams) -> Result<String> {
	let root = runtime_config()?.state_dir.clone();
	let policy = request_results::policy_binding()?;
	let (read_owner, id, binding) = (owner.to_owned(), p.request_id.clone(), policy.clone());
	let b = tokio::task::spawn_blocking(move || lookup_id_at(&root, &read_owner, &id, &binding))
		.await??
		.ok_or_else(|| anyhow!("async request unavailable to this scope"))?;
	audit_present(&b).await?;
	let (requested, observed) = {
		let r = registry()?;
		match r.active.get(&b.request_id) {
			Some(a) if a.binding == b && a.phase.load(Ordering::Acquire) != SETTLING => {
				a.cancel.cancel();
				(true, "owned_future_cancellation_requested")
			}
			Some(a) if a.binding == b => (false, "settlement_is_not_cancellable"),
			Some(_) => bail!("async live identity changed"),
			None => (false, "no_owned_future_present_no_replay"),
		}
	};
	Ok(serde_json::to_string(
		&json!({"request_id":b.request_id,"cancel_requested":requested,"observation":observed,
        "automatic_retry":false,"effect_may_continue":true,"remote_termination_confirmed":false,
        "cancellation_scope":"this_controller_owned_rust_future_only"}),
	)?)
}
pub(crate) fn freeze_admission() {
	STOPPING.store(true, Ordering::Release);
}
pub async fn shutdown() {
	freeze_admission();
	let _admission = ADMISSION
		.get_or_init(|| tokio::sync::Mutex::new(()))
		.lock()
		.await;
	if let Ok(r) = registry() {
		for a in r.active.values() {
			a.cancel.cancel();
		}
	}
	for _ in 0..100 {
		if registry().is_ok_and(|r| r.active.is_empty()) {
			return;
		}
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}
#[cfg(all(test, unix))]
#[path = "request_async_tests.rs"]
mod tests;
