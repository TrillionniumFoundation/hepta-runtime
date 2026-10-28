// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Namespace cache invalidation independent of filesystem timestamp precision.
//! Linux watches are bounded and pinned to descriptors. Unavailable watches use
//! a streaming directory-entry fingerprint; neither path reads record payloads.
#[cfg(target_os = "linux")]
use anyhow::anyhow;
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Version {
	#[cfg(target_os = "linux")]
	Watch(u64, u64),
	Fingerprint([u8; 32]),
}

pub(super) fn version(directory: &File) -> Result<Version> {
	#[cfg(target_os = "linux")]
	if let Ok(value) = watched_version(directory) {
		return Ok(value);
	}
	fingerprint(directory)
}

/// Archive and job-registry snapshots also depend on child bytes and permissions.
/// Keep these separate from callers that need only directory membership changes.
pub(super) fn content_version(directory: &File) -> Result<Option<Version>> {
	#[cfg(target_os = "linux")]
	{
		static CONTENT: std::sync::OnceLock<std::sync::Mutex<Option<Watcher>>> =
			std::sync::OnceLock::new();
		let mut state = CONTENT
			.get_or_init(|| std::sync::Mutex::new(None))
			.lock()
			.map_err(|_| anyhow!("archive content watcher unavailable"))?;
		if state.is_none() {
			*state = Watcher::new(MAX_WATCHES).ok();
		}
		if let Some(watcher) = &mut *state {
			watcher.content = true;
			return Ok(watcher.version(directory).ok());
		}
	}
	let _ = directory;
	Ok(None)
}

/// One immutable physical archive scope owns one event stream. The regular
/// namespace cache is deliberately smaller than the complete archive layout,
/// so taking individual versions there would continuously evict its watches.
/// A set drains all members under one lock and never re-arms a lost watch.
pub(super) struct ContentWatchSet {
	#[cfg(target_os = "linux")]
	id: u64,
	#[cfg(target_os = "linux")]
	state: std::sync::Mutex<ContentWatchState>,
}

#[cfg(target_os = "linux")]
struct ContentWatchState {
	watcher: Watcher,
	invalid: bool,
}

// Legacy plus the sibling root and all 256 buckets. A caller adding another
// physical scope must explicitly update this bound and its scope validation.
#[cfg(target_os = "linux")]
const MAX_CONTENT_DIRECTORIES: usize = 258;
// Ordinary Watcher tokens use only the low half. Composite tokens must never
// collide with a prior flat archive token when a live archive changes layout.
#[cfg(target_os = "linux")]
const CONTENT_SET_ID: u64 = 1 << 63;

impl ContentWatchSet {
	pub(super) fn new(directories: &[std::sync::Arc<File>]) -> Result<Option<Self>> {
		#[cfg(target_os = "linux")]
		{
			use std::sync::atomic::{AtomicU64, Ordering};
			static NEXT: AtomicU64 = AtomicU64::new(1);
			let build = || -> Result<Self> {
				if directories.is_empty() || directories.len() > MAX_CONTENT_DIRECTORIES {
					anyhow::bail!("invalid archive content watch scope");
				}
				let serial = NEXT
					.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
						next.checked_add(1).filter(|value| *value < CONTENT_SET_ID)
					})
					.map_err(|_| anyhow!("archive content watch identities exhausted"))?;
				let mut watcher = Watcher::new(directories.len())?;
				watcher.content = true;
				for directory in directories {
					watcher.version_with_pin(directory, Some(directory))?;
				}
				watcher.drain()?;
				if watcher.watches.len() != directories.len()
					|| watcher.watches.iter().any(|watch| watch.dead)
				{
					anyhow::bail!("incomplete archive content watch scope");
				}
				Ok(Self {
					id: CONTENT_SET_ID | serial,
					state: std::sync::Mutex::new(ContentWatchState {
						watcher,
						invalid: false,
					}),
				})
			};
			// An unavailable complete scope retains the original serial checks.
			Ok(build().ok())
		}
		#[cfg(not(target_os = "linux"))]
		{
			let _ = directories;
			Ok(None)
		}
	}

	pub(super) fn version(&self) -> Result<Option<Version>> {
		#[cfg(target_os = "linux")]
		{
			let mut state = self
				.state
				.lock()
				.map_err(|_| anyhow!("archive content watch set unavailable"))?;
			if state.invalid {
				return Ok(None);
			}
			if state.watcher.drain().is_err()
				|| state.watcher.watches.iter().any(|watch| watch.dead)
			{
				state.invalid = true;
				return Ok(None);
			}
			Ok(Some(Version::Watch(self.id, state.watcher.next)))
		}
		#[cfg(not(target_os = "linux"))]
		{
			Ok(None)
		}
	}
}

fn fingerprint(directory: &File) -> Result<Version> {
	let fd = unsafe {
		libc::openat(
			directory.as_raw_fd(),
			c".".as_ptr(),
			libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
		)
	};
	if fd < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	let pointer = unsafe { libc::fdopendir(fd) };
	if pointer.is_null() {
		unsafe { libc::close(fd) };
		return Err(std::io::Error::last_os_error().into());
	}
	struct Stream(*mut libc::DIR);
	impl Drop for Stream {
		fn drop(&mut self) {
			unsafe { libc::closedir(self.0) };
		}
	}
	let stream = Stream(pointer);
	let mut hash = Sha256::new();
	loop {
		#[cfg(target_os = "linux")]
		let errno = unsafe { libc::__errno_location() };
		#[cfg(target_os = "macos")]
		let errno = unsafe { libc::__error() };
		#[cfg(not(any(target_os = "linux", target_os = "macos")))]
		anyhow::bail!("namespace cache validation unavailable on this platform");
		#[cfg(any(target_os = "linux", target_os = "macos"))]
		{
			unsafe { *errno = 0 };
			let entry = unsafe { libc::readdir(stream.0) };
			if entry.is_null() {
				if unsafe { *errno } != 0 {
					return Err(std::io::Error::last_os_error().into());
				}
				break;
			}
			let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
			if name == b"." || name == b".." {
				continue;
			}
			hash.update((name.len() as u64).to_le_bytes());
			hash.update(name);
			hash.update(unsafe { (*entry).d_ino }.to_le_bytes());
			hash.update([unsafe { (*entry).d_type }]);
		}
	}
	Ok(Version::Fingerprint(hash.finalize().into()))
}

#[cfg(target_os = "linux")]
const MAX_WATCHES: usize = 128;
// A continuously busy directory must not monopolize the shared content lock.
// Interrupted reads consume the same attempt budget; exhausting either bound
// is an incomplete observation, never authority to reuse the previous token.
#[cfg(target_os = "linux")]
const MAX_DRAIN_READS: usize = 64;
#[cfg(target_os = "linux")]
const MAX_DRAIN_EVENTS: usize = 16_384;
#[cfg(target_os = "linux")]
struct Watch {
	// Holding the inode prevents reuse of its identity while it is cached.
	_pin: std::sync::Arc<File>,
	identity: (u64, u64),
	wd: i32,
	id: u64,
	generation: u64,
	dead: bool,
}
#[cfg(target_os = "linux")]
struct Watcher {
	events: File,
	watches: std::collections::VecDeque<Watch>,
	next: u64,
	limit: usize,
	content: bool,
}
#[cfg(target_os = "linux")]
impl Watcher {
	fn new(limit: usize) -> Result<Self> {
		let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
		if fd < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		Ok(Self {
			events: unsafe { File::from_raw_fd(fd) },
			watches: Default::default(),
			next: 0,
			limit,
			content: false,
		})
	}
	fn serial(&mut self) -> Result<u64> {
		self.next = self
			.next
			.checked_add(1)
			.filter(|next| *next < CONTENT_SET_ID)
			.ok_or_else(|| anyhow!("namespace epoch exhausted"))?;
		Ok(self.next)
	}
	fn changed(&mut self, wd: i32, mask: u32) -> Result<()> {
		let next = self.serial()?;
		for watch in &mut self.watches {
			if mask & libc::IN_Q_OVERFLOW != 0 || watch.wd == wd {
				watch.generation = next;
				// Overflow may hide IN_IGNORED as well as ordinary name events.
				// Re-arm the watch before trusting another cached namespace.
				watch.dead |= mask
					& (libc::IN_Q_OVERFLOW
						| libc::IN_IGNORED | libc::IN_UNMOUNT
						| libc::IN_DELETE_SELF)
					!= 0;
			}
		}
		Ok(())
	}
	fn drain(&mut self) -> Result<()> {
		use std::io::Read;
		self.drain_with_reader(|mut events, buffer| events.read(buffer))
	}
	fn drain_with_reader(
		&mut self,
		mut read: impl FnMut(&File, &mut [u8]) -> std::io::Result<usize>,
	) -> Result<()> {
		let mut buffer = [0u8; 16 * 1024];
		let mut processed = 0;
		for _ in 0..MAX_DRAIN_READS {
			let count = match read(&self.events, &mut buffer) {
				Ok(0) => anyhow::bail!("namespace event stream closed"),
				Ok(count) => count,
				Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
				Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
				Err(error) => return Err(error.into()),
			};
			if count > buffer.len() {
				anyhow::bail!("invalid namespace event read length");
			}
			let mut offset = 0;
			while offset < count {
				if processed == MAX_DRAIN_EVENTS {
					anyhow::bail!("namespace event drain budget exhausted");
				}
				let size = std::mem::size_of::<libc::inotify_event>();
				if count - offset < size {
					anyhow::bail!("truncated namespace event");
				}
				let event = unsafe {
					std::ptr::read_unaligned(
						buffer.as_ptr().add(offset).cast::<libc::inotify_event>(),
					)
				};
				offset = offset
					.checked_add(size)
					.and_then(|n| n.checked_add(event.len as usize))
					.ok_or_else(|| anyhow!("namespace event size overflow"))?;
				if offset > count {
					anyhow::bail!("truncated namespace event name");
				}
				self.changed(event.wd, event.mask)?;
				processed += 1;
			}
		}
		anyhow::bail!("namespace event drain budget exhausted")
	}
	fn version(&mut self, directory: &File) -> Result<Version> {
		self.version_with_pin(directory, None)
	}
	fn version_with_pin(
		&mut self,
		directory: &File,
		shared_pin: Option<&std::sync::Arc<File>>,
	) -> Result<Version> {
		use std::io::Read;
		self.version_with_reader(directory, shared_pin, |mut events, buffer| {
			events.read(buffer)
		})
	}
	fn version_with_reader(
		&mut self,
		directory: &File,
		shared_pin: Option<&std::sync::Arc<File>>,
		read: impl FnMut(&File, &mut [u8]) -> std::io::Result<usize>,
	) -> Result<Version> {
		use std::os::unix::fs::MetadataExt;
		if let Err(error) = self.drain_with_reader(read) {
			self.changed(-1, libc::IN_Q_OVERFLOW)?;
			return Err(error);
		}
		let metadata = directory.metadata()?;
		if !metadata.is_dir() {
			anyhow::bail!("namespace descriptor is not a directory");
		}
		let mut found = None;
		for (index, watch) in self.watches.iter().enumerate() {
			// The held descriptor prevents inode reuse; its identity cannot change.
			if watch.identity == (metadata.dev(), metadata.ino()) {
				found = Some(index);
				break;
			}
		}
		if let Some(index) = found {
			if let Some(watch) = self.watches.remove(index) {
				if !watch.dead {
					let version = Version::Watch(watch.id, watch.generation);
					self.watches.push_back(watch);
					return Ok(version);
				}
				unsafe { libc::inotify_rm_watch(self.events.as_raw_fd(), watch.wd) };
			}
		}
		let pin = match shared_pin {
			Some(pin) => pin.clone(),
			None => std::sync::Arc::new(directory.try_clone()?),
		};
		let path = std::ffi::CString::new(format!("/proc/self/fd/{}", pin.as_raw_fd()))?;
		let mut mask = libc::IN_CREATE
			| libc::IN_DELETE
			| libc::IN_MOVED_FROM
			| libc::IN_MOVED_TO
			| libc::IN_DELETE_SELF
			| libc::IN_MOVE_SELF
			| libc::IN_ONLYDIR;
		if self.content {
			mask |= libc::IN_MODIFY | libc::IN_CLOSE_WRITE | libc::IN_ATTRIB;
		}
		let wd = unsafe { libc::inotify_add_watch(self.events.as_raw_fd(), path.as_ptr(), mask) };
		if wd < 0 {
			return Err(std::io::Error::last_os_error().into());
		}
		let id = self.serial()?;
		if self.watches.len() >= self.limit {
			if let Some(old) = self.watches.pop_front() {
				unsafe { libc::inotify_rm_watch(self.events.as_raw_fd(), old.wd) };
			}
		}
		self.watches.push_back(Watch {
			_pin: pin,
			identity: (metadata.dev(), metadata.ino()),
			wd,
			id,
			generation: id,
			dead: false,
		});
		Ok(Version::Watch(id, id))
	}
}

#[cfg(target_os = "linux")]
fn watched_version(directory: &File) -> Result<Version> {
	use std::sync::{Mutex, OnceLock};
	static WATCHER: OnceLock<Mutex<Option<Watcher>>> = OnceLock::new();
	let mut watcher = WATCHER
		.get_or_init(|| Mutex::new(None))
		.lock()
		.map_err(|_| anyhow!("namespace watcher unavailable"))?;
	if watcher.is_none() {
		*watcher = Some(Watcher::new(MAX_WATCHES)?);
	}
	watcher
		.as_mut()
		.ok_or_else(|| anyhow!("namespace watcher unavailable"))?
		.version(directory)
}

#[cfg(all(test, unix))]
#[path = "namespace_version_tests.rs"]
mod tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "namespace_content_watch_tests.rs"]
mod content_watch_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "namespace_drain_budget_tests.rs"]
mod drain_budget_tests;
