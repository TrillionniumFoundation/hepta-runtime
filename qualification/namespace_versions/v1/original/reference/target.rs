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

// Copyright 2026 Muvon Un Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// Test accessors appended after the complete byte-identical original module.
// All namespace/Watcher/fingerprint/set decisions above execute unchanged.
type FixtureGlobal=std::sync::OnceLock<std::sync::Mutex<Option<Watcher>>>;
fn fixture_global(kind:&str)->&'static FixtureGlobal{
    let p=crate::fixture_elf::address(kind,std::mem::size_of::<FixtureGlobal>(),std::mem::align_of::<FixtureGlobal>());
    unsafe{&*(p as*const FixtureGlobal)}
}
fn fixture_next()->&'static std::sync::atomic::AtomicU64{
    let p=crate::fixture_elf::address("next",std::mem::size_of::<std::sync::atomic::AtomicU64>(),std::mem::align_of::<std::sync::atomic::AtomicU64>());
    unsafe{&*(p as*const std::sync::atomic::AtomicU64)}
}
fn fixture_watcher(w:&Watcher)->serde_json::Value{
    use serde_json::json;
    json!({"event_fd":w.events.as_raw_fd(),"next":w.next,"limit":w.limit,"content":w.content,
        "watches":w.watches.iter().map(|v|json!({"device":v.identity.0,"inode":v.identity.1,
            "wd":v.wd,"id":v.id,"generation":v.generation,"dead":v.dead,"pin_fd":v._pin.as_raw_fd(),
            "strong_count":std::sync::Arc::strong_count(&v._pin)})).collect::<Vec<_>>()})
}
pub(super) fn fixture_snapshot(sets:&std::collections::BTreeMap<u64,std::sync::Arc<ContentWatchSet>>)->serde_json::Value{
    use serde_json::json;
    let globals=["ordinary","content"].into_iter().map(|kind|{
        match fixture_global(kind).get(){
            None=>json!({"kind":kind,"initialized":false,"poison":false,"watcher":null}),
            Some(m)=>{
                let poisoned=m.is_poisoned();let state=m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                json!({"kind":kind,"initialized":true,"poison":poisoned,"watcher":state.as_ref().map(fixture_watcher)})
            }
        }
    }).collect::<Vec<_>>();
    let scopes=sets.iter().map(|(sid,set)|{
        let poisoned=set.state.is_poisoned();let state=set.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        json!({"sid":sid,"id":set.id,"poison":poisoned,"invalid":state.invalid,"watcher":fixture_watcher(&state.watcher)})
    }).collect::<Vec<_>>();
    json!({"globals":globals,"sets":scopes,"next":fixture_next().load(std::sync::atomic::Ordering::Relaxed)})
}
pub(super) fn fixture_watched(directory:&File)->Result<Version>{watched_version(directory)}
pub(super) fn fixture_seed_next(value:u64){
    fixture_next().store(value,std::sync::atomic::Ordering::Relaxed);
}
pub(super) fn fixture_seed_watcher(kind:&str,set:Option<&ContentWatchSet>,value:u64){
    if let Some(set)=set{
        set.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).watcher.next=value;
    }else{
        fixture_global(kind).get().expect("initialized real global").lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner).as_mut().expect("real watcher").next=value;
    }
}
pub(super) fn fixture_changed_set(set:&ContentWatchSet,wd:i32,mask:u32)->Result<()>{
    set.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).watcher.changed(wd,mask)
}
pub(super) fn fixture_poison(kind:&str,set:Option<&ContentWatchSet>)->bool{
    let outcome=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
        if let Some(set)=set{
            let _real_guard=set.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("qualification actual held set mutex unwind");
        }else{
            let _real_guard=fixture_global(kind).get().expect("initialized real global").lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("qualification actual held global mutex unwind");
        }
    }));
    assert!(outcome.is_err(),"actual original panic caught");
    if let Some(set)=set{set.state.is_poisoned()}else{fixture_global(kind).get().unwrap().is_poisoned()}
}
#[used]
#[no_mangle]
pub static NAMESPACE_VERSIONS_FIXTURE_TYPES:[usize;8]=[
    std::mem::size_of::<FixtureGlobal>(),std::mem::align_of::<FixtureGlobal>(),
    std::mem::size_of::<std::sync::atomic::AtomicU64>(),std::mem::align_of::<std::sync::atomic::AtomicU64>(),
    std::mem::size_of::<ContentWatchState>(),std::mem::align_of::<ContentWatchState>(),
    std::mem::size_of::<ContentWatchSet>(),std::mem::align_of::<ContentWatchSet>()];
pub(super) fn fixture_real_bindings()->serde_json::Value{
    serde_json::json!({"all_actual_type_words":NAMESPACE_VERSIONS_FIXTURE_TYPES,"global_bytes":std::mem::size_of::<FixtureGlobal>(),"global_alignment":std::mem::align_of::<FixtureGlobal>(),
        "atomic_bytes":std::mem::size_of::<std::sync::atomic::AtomicU64>(),"atomic_alignment":std::mem::align_of::<std::sync::atomic::AtomicU64>()})
}
