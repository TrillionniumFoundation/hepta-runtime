// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Exact read-only Async closure for public Read qualification.
//! Producer/start/cancel are outside this reference; no fixed-None read substitute.
use super::{config::runtime_config, request_audit::{self, RequestIdentity}, request_results};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::{HashMap, VecDeque}, fs::File, io::{Read, Write},
    path::{Path, PathBuf}, sync::{atomic::{AtomicBool, AtomicU8, Ordering}, Arc, Mutex, OnceLock}};
use tokio_util::sync::CancellationToken;
const STORE_NAME: &str = "request-async-v9";
const ANCHOR_NAME: &str = ".request-async-v9-anchor.json";
const MAX_RECORD_BYTES: usize = 4096;
const QUEUED: u8 = 0;
const RUNNING: u8 = 1;
const SETTLING: u8 = 2;
static STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static ROOT_PINS: OnceLock<Mutex<HashMap<PathBuf, (u64, u64)>>> = OnceLock::new();
static ADMISSION: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
static STOPPING: AtomicBool = AtomicBool::new(false);

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
#[cfg(all(test, unix))]
fn names(dir: &File) -> Result<Vec<String>> {
	names_impl(dir, true)
}
#[cfg(all(test, unix))]
fn record_names(dir: &File) -> Result<Vec<String>> {
	names_impl(dir, false)
}
#[cfg(all(test, unix))]
fn names_impl(dir: &File, root: bool) -> Result<Vec<String>> {
	let mut names = Vec::new();
	for_each_name(dir, root, |name| {
		names.push(name.to_owned());
		Ok(())
	})?;
	Ok(names)
}
#[cfg(unix)]
fn for_each_name(dir: &File, root: bool, mut visit: impl FnMut(&str) -> Result<()>) -> Result<()> {
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
			if !name.ends_with(".json") || !valid_id(&name[..name.len().saturating_sub(5)]) {
				bail!("async key registry unavailable; administrator review required");
			}
			visit(&name)?;
		}
	}
	Ok(())
}
#[cfg(all(test, unix))]
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
#[derive(Clone, PartialEq, Eq)]
struct DirectoryStamp {
	device: u64,
	inode: u64,
	modified: (i64, i64),
	changed: (i64, i64),
	namespace: super::namespace_version::Version,
}
#[cfg(unix)]
#[derive(Clone, PartialEq, Eq)]
struct NamespaceStamp([DirectoryStamp; 4]);
#[cfg(unix)]
static NAMESPACE_CACHE: OnceLock<Mutex<VecDeque<NamespaceStamp>>> = OnceLock::new();

#[cfg(unix)]
fn namespace_stamp(directory: &File) -> Result<NamespaceStamp> {
	use std::os::unix::fs::MetadataExt;
	fn stamp(directory: &File) -> Result<DirectoryStamp> {
		private_dir(directory)?;
		let metadata = directory.metadata()?;
		Ok(DirectoryStamp {
			device: metadata.dev(),
			inode: metadata.ino(),
			modified: (metadata.mtime(), metadata.mtime_nsec()),
			changed: (metadata.ctime(), metadata.ctime_nsec()),
			namespace: super::namespace_version::version(directory)?,
		})
	}
	let occupied = open_at(
		directory,
		".occupied",
		libc::O_RDONLY | libc::O_DIRECTORY,
		0,
	)?;
	let intents = open_at(directory, ".intents", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	let outcomes = open_at(
		directory,
		".outcomes",
		libc::O_RDONLY | libc::O_DIRECTORY,
		0,
	)?;
	Ok(NamespaceStamp([
		stamp(directory)?,
		stamp(&occupied)?,
		stamp(&intents)?,
		stamp(&outcomes)?,
	]))
}
#[cfg(unix)]
fn cache_namespace(directory: &File) -> Result<()> {
	let stamp = namespace_stamp(directory)?;
	let mut cache = NAMESPACE_CACHE
		.get_or_init(|| Mutex::new(VecDeque::new()))
		.lock()
		.map_err(|_| anyhow!("async namespace cache unavailable"))?;
	cache.retain(|old| (old.0[0].device, old.0[0].inode) != (stamp.0[0].device, stamp.0[0].inode));
	// This only bounds disposable validation-cache memory. Durable keys, active
	// futures, and newly eligible requests are never counted against this budget.
	if cache.len() >= 16 {
		cache.pop_front();
	}
	cache.push_back(stamp);
	Ok(())
}
#[cfg(unix)]
fn validate_namespace(directory: &File) -> Result<()> {
	let before = namespace_stamp(directory)?;
	if NAMESPACE_CACHE
		.get_or_init(|| Mutex::new(VecDeque::new()))
		.lock()
		.map_err(|_| anyhow!("async namespace cache unavailable"))?
		.iter()
		.any(|stamp| *stamp == before)
	{
		return Ok(());
	}
	// Only a cold/external namespace change needs a complete inventory. Validate
	// both directions by exact filenames, without collecting lifetime history.
	let intents = open_at(directory, ".intents", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	let occupied = open_at(
		directory,
		".occupied",
		libc::O_RDONLY | libc::O_DIRECTORY,
		0,
	)?;
	let outcomes = open_at(
		directory,
		".outcomes",
		libc::O_RDONLY | libc::O_DIRECTORY,
		0,
	)?;
	for_each_name(directory, true, |name| {
		binding_pair(directory, &name[..name.len() - 5])?
			.ok_or_else(|| anyhow!("async key history incomplete; never replay"))?;
		Ok(())
	})?;
	for_each_name(&occupied, false, |name| {
		binding_pair(directory, &name[..name.len() - 5])?
			.ok_or_else(|| anyhow!("async occupancy history incomplete; never replay"))?;
		Ok(())
	})?;
	for_each_name(&intents, false, |name| {
		let binding: Binding = read_json(&intents, name)?;
		if !valid_binding(&binding)
			|| name != format!("{}.json", binding.request_id)
			|| binding_pair(directory, &binding.key_hash)?.as_ref() != Some(&binding)
		{
			bail!("async intent history incomplete; never replay");
		}
		Ok(())
	})?;
	for_each_name(&outcomes, false, |name| {
		let outcome: Outcome = read_json(&outcomes, name)?;
		if !valid_id(&outcome.request_id) || name != format!("{}.json", outcome.request_id) {
			bail!("async outcome history identity unavailable");
		}
		let binding: Binding = read_json(&intents, &format!("{}.json", outcome.request_id))?;
		if !valid_binding(&binding)
			|| binding.request_id != outcome.request_id
			|| binding_pair(directory, &binding.key_hash)?.as_ref() != Some(&binding)
		{
			bail!("async outcome has no complete historical binding; never replay");
		}
		check_outcome(&binding, &outcome)
	})?;
	if namespace_stamp(directory)? != before {
		bail!("async namespace changed during validation; never replay");
	}
	cache_namespace(directory)
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
	validate_namespace(&dir)?;
	let intents = open_at(&dir, ".intents", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	let binding: Binding = match read_json(&intents, &format!("{id}.json")) {
		Ok(binding) => binding,
		Err(error) if missing(&error) => return Ok(None),
		Err(_) => bail!("async intent unavailable to this scope"),
	};
	if !valid_binding(&binding)
		|| binding.request_id != id
		|| binding.owner != owner
		|| binding.policy_binding != policy
		|| binding_pair(&dir, &binding.key_hash)?.as_ref() != Some(&binding)
	{
		bail!("async request unavailable to this scope or current policy");
	}
	Ok(Some(binding))
}
#[cfg(unix)]
fn outcome_at(root: &Path, b: &Binding, state: Option<&str>) -> Result<Option<String>> {
	let _lock = STORE_LOCK
		.get_or_init(|| Mutex::new(()))
		.lock()
		.map_err(|_| anyhow!("async metadata unavailable"))?;
	let (dir, _lease) = locked_store(root)?;
	validate_namespace(&dir)?;
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
		cache_namespace(&dir)?;
	}
	let o: Outcome = match read_json(&outcomes, &name) {
		Ok(o) => o,
		Err(error) if missing(&error) => return Ok(None),
		Err(_) => bail!("async outcome unavailable"),
	};
	check_outcome(b, &o)?;
	Ok(Some(o.state))
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

enum Reservation {
	New(Binding),
	Existing(Binding),
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
	validate_namespace(&dir)?;
	let Some(b) = binding_pair(&dir, hash)? else {
		// Absence of both key markers is not a fresh permit while any independent
		// historical intent/outcome remains inconsistent with this namespace.
		return Ok(None);
	};
	if !valid_binding(&b) {
		bail!("async key unavailable");
	}
	check_binding(&b, owner, hash, request, policy)?;
	Ok(Some(b))
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
	validate_namespace(&dir)?;
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
	let historical = open_at(&dir, ".intents", libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
	match read_json::<Binding>(&historical, &format!("{}.json", candidate.request_id)) {
		Ok(_) => bail!("generated request identity already bound"),
		Err(error) if missing(&error) => {}
		Err(_) => bail!("generated request identity unavailable"),
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
	cache_namespace(&dir)?;
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


// Qualification-only binary binding transport. Business methods above remain exact.
fn producer_q_u64(raw: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(raw.get(at..at+8).ok_or_else(|| anyhow!("qualification u64 range"))?.try_into()?))
}
fn producer_q_text(raw: &[u8], at: usize, size: usize) -> Result<String> {
    Ok(std::str::from_utf8(raw.get(at..at+size).ok_or_else(|| anyhow!("qualification text range"))?)?.to_owned())
}
fn producer_q_binding(raw: &[u8]) -> Result<Binding> {
    anyhow::ensure!(raw.len() == 352 && &raw[..8] == b"ASYBND01", "qualification binding shape");
    Ok(Binding {
        accepted_unix_ms: u128::from_le_bytes(raw[8..24].try_into()?),
        tool_name: match producer_q_u64(raw,24)? {
            1 => "host_list", 2 => "host_health", 3 => "effective_config", _ => "ineligible"
        }.to_owned(),
        request_id: producer_q_text(raw,32,64)?,
        owner: producer_q_text(raw,96,64)?,
        key_hash: producer_q_text(raw,160,64)?,
        request_hash: producer_q_text(raw,224,64)?,
        policy_binding: producer_q_text(raw,288,64)?,
    })
}
fn producer_q_compact(b: &Binding) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(352);
    out.extend_from_slice(b"ASYBND01");
    out.extend_from_slice(&b.accepted_unix_ms.to_le_bytes());
    let tool: u64 = match b.tool_name.as_str() {
        "host_list" => 1, "host_health" => 2, "effective_config" => 3,
        _ => bail!("qualification output tool"),
    };
    out.extend_from_slice(&tool.to_le_bytes());
    for value in [&b.request_id,&b.owner,&b.key_hash,&b.request_hash,&b.policy_binding] {
        anyhow::ensure!(value.len() == 64, "qualification compact output length");
        out.extend_from_slice(value.as_bytes());
    }
    anyhow::ensure!(out.len() == 352, "qualification compact output");
    Ok(out)
}
fn producer_q_state(state: Option<String>) -> Result<Vec<u8>> {
    let code: u64 = match state.as_deref() {
        None => 0, Some("unknown") => 1, Some("completed") => 5, Some("failed") => 6,
        Some("cancelled_before_dispatch") => 7, Some("cancelled_future") => 8,
        _ => bail!("qualification outcome output"),
    };
    Ok(code.to_le_bytes().to_vec())
}
pub fn qualification_producer_journal(raw: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(raw.len() >= 32 && raw.len() <= 8*1024*1024 && &raw[..8] == b"HRASYCQ1", "qualification journal header");
    let kind = producer_q_u64(raw,8)?;
    let root_len = usize::try_from(producer_q_u64(raw,16)?)?;
    let payload_len = usize::try_from(producer_q_u64(raw,24)?)?;
    anyhow::ensure!(root_len <= raw.len()-32 && payload_len == raw.len()-32-root_len, "qualification journal lengths");
    let root_text = producer_q_text(raw,32,root_len)?;
    let root = Path::new(&root_text);
    let payload = &raw[32+root_len..];
    let result: Result<Vec<u8>> = (|| {
        match kind {
            1 => Ok(super::config::runtime_config()?.state_dir.to_str()
                .ok_or_else(|| anyhow!("qualification UTF-8 config root"))?.as_bytes().to_vec()),
            3 => {
                anyhow::ensure!(payload.len() >= 80, "qualification lookup ID header");
                let owner_len = usize::try_from(producer_q_u64(payload,0)?)?;
                let id_len = usize::try_from(producer_q_u64(payload,8)?)?;
                anyhow::ensure!(owner_len <= payload.len()-80 && id_len == payload.len()-80-owner_len, "qualification lookup ID lengths");
                let policy=producer_q_text(payload,16,64)?;
                let owner=producer_q_text(payload,80,owner_len)?;
                let id=producer_q_text(payload,80+owner_len,id_len)?;
                match lookup_id_at(root,&owner,&id,&policy)? {
                    None => Ok(Vec::new()), Some(b) => producer_q_compact(&b),
                }
            }
            6 => {
                let b=producer_q_binding(payload)?;
                producer_q_state(outcome_at(root,&b,None)?)
            }
            7 => {
                anyhow::ensure!(payload.len()==256, "qualification lookup key shape");
                let owner=producer_q_text(payload,0,64)?;
                let key=producer_q_text(payload,64,64)?;
                let request=producer_q_text(payload,128,64)?;
                let policy=producer_q_text(payload,192,64)?;
                anyhow::ensure!(valid_id(&key),"qualification canonical key hash");
                match lookup_key_at(root,&owner,&key,&request,&policy)? {
                    None=>Ok(Vec::new()), Some(b)=>producer_q_compact(&b),
                }
            }
            8 => {
                let candidate=producer_q_binding(payload)?;
                let (tag,b)=match reserve_at(root,candidate)? {
                    Reservation::New(b)=>(0u64,b), Reservation::Existing(b)=>(1u64,b),
                };
                let mut out=tag.to_le_bytes().to_vec();
                out.extend_from_slice(&producer_q_compact(&b)?);
                Ok(out)
            }
            9 => {
                anyhow::ensure!(payload.len()==360,"qualification outcome write shape");
                let b=producer_q_binding(&payload[..352])?;
                let state=match producer_q_u64(payload,352)? {
                    1=>"unknown",5=>"completed",6=>"failed",7=>"cancelled_before_dispatch",
                    8=>"cancelled_future",_=>"invalid_qualification_state",
                };
                producer_q_state(outcome_at(root,&b,Some(state))?)
            }
            10 => {
                anyhow::ensure!(payload.is_empty(),"qualification lease payload");
                acquire_controller(root)?;
                Ok(Vec::new())
            }
            _ => bail!("qualification journal operation"),
        }
    })();
    let (status,payload)=match result {
        Ok(value)=>(0u64,value),
        Err(error)=>(1u64,error.to_string().into_bytes()),
    };
    let mut out=Vec::with_capacity(32+payload.len());
    out.extend_from_slice(b"HRASYCP1");
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&payload);
    anyhow::ensure!(out.len()<=65536,"qualification response capacity");
    Ok(out)
}

use rmcp::schemars;
use std::time::Duration;

#[derive(Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestCancelParams {
	/// Opaque server-generated inner request id; never an OS process id.
	pub request_id: String,
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


fn observed_admission_receipt(b: &Binding, reused: bool, state: &str) -> Result<String> {
	let mut value = json!({"request_id":b.request_id,"tool_name":b.tool_name,"reused":reused,
        "async_state":state,"idempotency_binding_retained":true,"automatic_retry":false,
        "delivery_proven":false,"execution_resume_after_restart":false,
        "admission_is_not_dispatch_completion":true,"authenticated_chatgpt_caller_isolation":false});
	if reused {
		value["this_call_dispatch_started"] = json!(false);
		value["original_request_replayed"] = json!(false);
	}
	Ok(serde_json::to_string(&value)?)
}


async fn checked_receipt(b: &Binding, reused: bool) -> Result<String> {
	audit_present(b).await?;
	let live = phase(b)?;
	let state = if live == "unknown" {
		let root = runtime_config()?.state_dir.clone();
		let copy = b.clone();
		tokio::task::spawn_blocking(move || outcome_at(&root, &copy, None))
			.await??
			.unwrap_or_else(|| "unknown".into())
	} else {
		live.to_owned()
	};
	// A retained cancelled_future describes uncertain original effects. Reusing
	// its key only proves that this call did not dispatch or replay that request.
	observed_admission_receipt(b, reused, &state)
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


// Qualification controls own real Slot values and actual Registry Active objects.
// Native allocator offsets have no Rust analogue and are never synthesized here.
pub struct ProducerQualification {
    generation: u64,
    active: HashMap<u64,String>,
    slots: HashMap<String,Vec<Slot>>,
}
impl ProducerQualification {
    pub fn new() -> Self {
        Self {generation:0,active:HashMap::new(),slots:HashMap::new()}
    }
    pub fn state(&mut self,raw:&[u8]) -> Result<Vec<u8>> {
        anyhow::ensure!(raw.len()>=64 && &raw[..8]==b"HRASSQ01","qualification state header");
        let op=producer_q_u64(raw,8)?;
        anyhow::ensure!(producer_q_u64(raw,16)?==2 && producer_q_u64(raw,24)? as usize==raw.len()-64,
            "qualification state role/length");
        anyhow::ensure!(producer_q_u64(raw,48)?==0 && producer_q_u64(raw,56)?==0,"qualification state reserved");
        let a=producer_q_u64(raw,32)?;let second=producer_q_u64(raw,40)?;
        let body=&raw[64..];
        let mut diagnostic=0u64;let mut value=0u64;let mut token=0u64;
        match op {
            2|3 => {
                anyhow::ensure!(body.len()==352 && second==0 && a<=255,"qualification Active");
                let b=producer_q_binding(body)?;anyhow::ensure!(valid_binding(&b),"qualification validated binding");
                if op==3 {
                    let active=Arc::new(Active {binding:b.clone(),cancel:CancellationToken::new(),phase:AtomicU8::new(a as u8)});
                    registry()?.active.insert(b.request_id.clone(),active);
                    self.active.retain(|_,id|id!=&b.request_id);
                    self.generation=self.generation.checked_add(1).ok_or_else(||anyhow!("qualification generation"))?;
                    self.active.insert(self.generation,b.request_id.clone());token=self.generation;
                } else {anyhow::ensure!(a==0,"qualification phase argument");}
                match phase(&b) {
                    Ok("unknown")=>{},
                    Ok("queued")=>value=1,
                    Ok("running")=>value=2,
                    Ok("settling")=>value=3,
                    Ok(_)=>bail!("qualification phase output"),
                    Err(e)=>{anyhow::ensure!(e.to_string()=="async live identity changed","qualification phase error");diagnostic=2;}
                }
                if diagnostic==0 && value!=0 {
                    token=*self.active.iter().find(|(_,id)|*id==&b.request_id).ok_or_else(||anyhow!("qualification Active owner"))?.0;
                }
            }
            4|5|12 => {
                anyhow::ensure!(body.is_empty() && a!=0,"qualification Active handle");
                let id=self.active.get(&a).ok_or_else(||anyhow!("qualification stale handle"))?.clone();
                if op==5 {
                    anyhow::ensure!(second==0,"qualification remove argument");
                    registry()?.active.remove(&id);self.active.remove(&a);
                } else {
                    let active=registry()?.active.get(&id).cloned().ok_or_else(||anyhow!("qualification Active absent"))?;
                    if op==4 {
                        anyhow::ensure!(second<=255,"qualification phase range");
                        active.phase.store(second as u8,Ordering::Release);
                        value=match phase(&active.binding)? {"queued"=>1,"running"=>2,_=>3};
                    } else {
                        anyhow::ensure!(second==0,"qualification cancelled argument");
                        value=u64::from(active.cancel.is_cancelled());
                    }
                    token=a;
                }
            }
            8 => {
                anyhow::ensure!(body.is_empty() && a==0 && second==0,"qualification state inspect");
            }
            9|10|15 => {
                anyhow::ensure!(body.len()==64 && a==0 && second==0,"qualification Slot shape");
                let owner=producer_q_text(body,0,64)?;anyhow::ensure!(valid_id(&owner),"qualification Slot owner");
                if op==9 {
                    match Slot::take(&owner) {
                        Ok(slot)=>self.slots.entry(owner.clone()).or_default().push(slot),
                        Err(e)=>{
                            anyhow::ensure!(e.to_string()=="async admission is frozen; existing receipts remain queryable","qualification Slot error");
                            diagnostic=3;
                        }
                    }
                } else if op==10 {
                    if let Some(slot)=self.slots.get_mut(&owner).and_then(Vec::pop) {drop(slot);}
                }
                let r=registry()?;
                if diagnostic==0 {
                    value=r.reserved.get(&owner).copied().unwrap_or(0) as u64;
                    if op==15 {token=u64::from(r.reserved.contains_key(&owner));}
                }
            }
            _=>bail!("qualification Registry control not admitted"),
        }
        let count=registry()?.active.len() as u64;
        let mut out=Vec::with_capacity(64);out.extend_from_slice(b"HRASSR01");
        for word in [diagnostic,value,token,count,0,self.generation,0] {out.extend_from_slice(&word.to_le_bytes());}
        Ok(out)
    }
}
pub async fn qualification_producer_controller(raw:&[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(raw.len()>=48 && &raw[..8]==b"HRASYQ01","qualification controller header");
    let op=producer_q_u64(raw,8)?;
    anyhow::ensure!(producer_q_u64(raw,32)?==0 && producer_q_u64(raw,40)?==0,"qualification controller reserved");
    let mut scalar=0u64;
    let result:Result<Vec<u8>>=async {
        match op {
            3 => {
                let olen=usize::try_from(producer_q_u64(raw,16)?)?;
                let ilen=usize::try_from(producer_q_u64(raw,24)?)?;
                anyhow::ensure!(olen<=raw.len()-48 && ilen==raw.len()-48-olen,"qualification cancel lengths");
                let owner=producer_q_text(raw,48,olen)?;
                let id=producer_q_text(raw,48+olen,ilen)?;
                let text=cancel(&owner,RequestCancelParams{request_id:id}).await?;
                let parsed:Value=serde_json::from_str(&text)?;
                scalar=match parsed["observation"].as_str() {
                    Some("no_owned_future_present_no_replay")=>0,
                    Some("owned_future_cancellation_requested")=>1,
                    Some("settlement_is_not_cancellable")=>2,
                    _=>bail!("qualification cancel output"),
                };
                Ok(text.into_bytes())
            }
            4 => {
                anyhow::ensure!(raw.len()==400 && producer_q_u64(raw,16)?==352,"qualification receipt binding");
                let reused=producer_q_u64(raw,24)?;
                anyhow::ensure!(reused<=1,"qualification reused bit");
                let b=producer_q_binding(&raw[48..])?;anyhow::ensure!(valid_binding(&b),"qualification receipt validated binding");
                let text=checked_receipt(&b,reused!=0).await?;
                let parsed:Value=serde_json::from_str(&text)?;
                scalar=match parsed["async_state"].as_str() {
                    Some("unknown")=>1,Some("queued")=>2,Some("running")=>3,Some("settling")=>4,
                    Some("completed")=>5,Some("failed")=>6,Some("cancelled_before_dispatch")=>7,Some("cancelled_future")=>8,
                    _=>bail!("qualification receipt output"),
                };
                Ok(text.into_bytes())
            }
            5 => {
                anyhow::ensure!(raw.len()==48 && producer_q_u64(raw,16)?==0 && producer_q_u64(raw,24)?==0,"qualification freeze shape");
                freeze_admission();Ok(Vec::new())
            }
            _=>bail!("qualification controller operation"),
        }
    }.await;
    let (tag,body)=match result {Ok(body)=>(1u64,body),Err(error)=>{scalar=0;(2u64,error.to_string().into_bytes())}};
    let mut out=Vec::with_capacity(64+body.len());out.extend_from_slice(b"HRASYR01");
    for word in [op,tag,scalar,0,0,body.len() as u64,0] {out.extend_from_slice(&word.to_le_bytes());}
    out.extend_from_slice(&body);Ok(out)
}

use super::{effective_config::EffectiveConfigParams,health::HostHealthParams,inspect::HostListParams};
use super::request_audit::AuditCompletion;
use rmcp::{handler::server::tool::IntoCallToolResult,model::{CallToolResponse,CallToolResult}};
use std::time::{SystemTime,UNIX_EPOCH};

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


fn request_hash(operation: &ReadRequest) -> Result<String> {
	let mut bytes = b"hepta-runtime/async-typed-request/v9\0".to_vec();
	bytes.extend(serde_json::to_vec(operation)?);
	Ok(digest(&bytes))
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


// Qualification framing only; validation and dispatch use the complete Original functions.
fn qualification_start_params(raw: &[u8]) -> Result<(String,RequestStartParams,u64)> {
    anyhow::ensure!(raw.len()>=64 && &raw[..8]==b"HRASYQ01","qualification start header");
    anyhow::ensure!(producer_q_u64(raw,48)?==0 && producer_q_u64(raw,56)?==0,"qualification start reserved");
    let tool=producer_q_u64(raw,16)?;
    let owner=usize::try_from(producer_q_u64(raw,24)?)?;
    let key=usize::try_from(producer_q_u64(raw,32)?)?;
    let host=usize::try_from(producer_q_u64(raw,40)?)?;
    anyhow::ensure!(owner<=raw.len()-64 && key<=raw.len()-64-owner && host==raw.len()-64-owner-key,
        "qualification start lengths");
    let owner_text=producer_q_text(raw,64,owner)?;
    let key_text=producer_q_text(raw,64+owner,key)?;
    let host_text=producer_q_text(raw,64+owner+key,host)?;
    anyhow::ensure!(tool==2 || host==0,"qualification start host shape");
    let operation=match tool {
        1=>ReadRequest::HostList(HostListParams{}),
        2=>ReadRequest::HostHealth(HostHealthParams{host:host_text}),
        3=>ReadRequest::EffectiveConfig(EffectiveConfigParams{}),
        _=>bail!("qualification start operation"),
    };
    Ok((owner_text,RequestStartParams{operation,idempotency_key:key_text},tool))
}
pub async fn qualification_producer_extended(raw: &[u8]) -> Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    anyhow::ensure!(raw.len()>=48 && &raw[..8]==b"HRASYQ01","qualification extended header");
    let op=producer_q_u64(raw,8)?;
    if op<=5 {return qualification_producer_controller(raw).await;}
    let mut scalar=0u64;
    let result:Result<Vec<u8>>=async {
        match op {
            6=>{
                let (owner,p,tool)=qualification_start_params(raw)?;
                if !valid_id(&owner) || !valid_key(&p.idempotency_key) {
                    bail!("async request parameters unavailable");
                }
                p.operation.validate()?;
                let policy=request_results::policy_binding()?;
                let hash=key_hash(&owner,&p.idempotency_key);
                let request=request_hash(&p.operation)?;
                let root=runtime_config()?.state_dir.clone();
                let root=root.as_os_str().as_bytes();
                let mut body=Vec::with_capacity(288+root.len());
                body.extend_from_slice(b"ASYPRP01");
                for value in [tool,root.len() as u64,0] {body.extend_from_slice(&value.to_le_bytes());}
                body.extend_from_slice(owner.as_bytes());body.extend_from_slice(hash.as_bytes());
                body.extend_from_slice(request.as_bytes());body.extend_from_slice(policy.as_bytes());
                body.extend_from_slice(root);Ok(body)
            }
            7=>{
                let (owner,p,_)=qualification_start_params(raw)?;
                let text=start(&owner,p).await?;
                let value:Value=serde_json::from_str(&text)?;
                scalar=match value["async_state"].as_str() {
                    Some("unknown")=>1,Some("queued")=>2,Some("running")=>3,Some("settling")=>4,
                    Some("completed")=>5,Some("failed")=>6,Some("cancelled_before_dispatch")=>7,Some("cancelled_future")=>8,
                    _=>bail!("qualification start receipt"),
                };
                Ok(text.into_bytes())
            }
            8|9=>{
                anyhow::ensure!(raw.len()==48 && raw[16..48].iter().all(|b|*b==0),"qualification runtime drive shape");
                if op==8 {
                    tokio::task::yield_now().await;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    scalar=registry()?.active.len() as u64;
                } else {
                    shutdown().await;
                }
                Ok(Vec::new())
            }
            _=>bail!("qualification extended operation"),
        }
    }.await;
    let (tag,body)=match result {
        Ok(body)=>(1u64,body),
        Err(error)=>{scalar=0;(2u64,error.to_string().into_bytes())}
    };
    let mut out=Vec::with_capacity(64+body.len());out.extend_from_slice(b"HRASYR01");
    for word in [op,tag,scalar,0,0,body.len() as u64,0] {out.extend_from_slice(&word.to_le_bytes());}
    out.extend_from_slice(&body);Ok(out)
}
