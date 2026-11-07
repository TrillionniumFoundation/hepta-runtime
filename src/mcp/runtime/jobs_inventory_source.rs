// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Descriptor-bound original inventory observations and content revalidation.
use super::super::namespace_version;
use super::record_projection::ValidatedJobString;
use super::*;
use std::fs::Metadata;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

type DirectoryIdentity = (u64, u64, u32, u32);
type Stamp = (u64, u64, u32, u32, u64, u64, i64, i64, i64, i64);

struct Directories {
	root: File,
	jobs: File,
	root_identity: DirectoryIdentity,
	jobs_identity: DirectoryIdentity,
}

struct RecordProof {
	stamp: Stamp,
	sha256: [u8; 32],
}

// Pins prevent directory inode reuse while a snapshot is retained. Individual
// receipts are never trusted from timestamps or directory watch state alone.
pub(super) struct SourceProof {
	directories: Directories,
	names: Vec<String>,
	records: Vec<RecordProof>,
}

impl SourceProof {
	pub(super) fn retained_bytes(&self) -> usize {
		self.names.capacity() * std::mem::size_of::<String>()
			+ self.names.iter().map(String::capacity).sum::<usize>()
			+ self.records.capacity() * std::mem::size_of::<RecordProof>()
	}
}

struct Budget {
	started: Instant,
	limits: InventoryLimits,
}

impl Budget {
	fn check(&self) -> Result<()> {
		if self.started.elapsed() >= self.limits.time {
			bail!("durable inventory source time budget exceeded; no partial inventory returned");
		}
		Ok(())
	}
}

fn open_at(base: Option<&File>, component: &str, flags: i32) -> Result<File> {
	let name = std::ffi::CString::new(component)?;
	let fd = unsafe {
		libc::openat(
			base.map_or(libc::AT_FDCWD, AsRawFd::as_raw_fd),
			name.as_ptr(),
			flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
		)
	};
	if fd < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_root(root: &Path) -> Result<File> {
	let raw = root
		.to_str()
		.ok_or_else(|| anyhow::anyhow!("inventory root must be UTF-8"))?;
	if !root.is_absolute() || raw.split('/').any(|part| matches!(part, "." | "..")) {
		bail!("inventory root must be an explicit absolute path");
	}
	let mut base = open_at(None, "/", libc::O_RDONLY | libc::O_DIRECTORY)?;
	for part in raw.split('/').filter(|part| !part.is_empty()) {
		base = open_at(Some(&base), part, libc::O_RDONLY | libc::O_DIRECTORY)?;
	}
	let info = base.metadata()?;
	if info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o077 != 0 {
		bail!("durable inventory root must be private and account-owned");
	}
	Ok(base)
}

fn directory_identity(info: &Metadata) -> DirectoryIdentity {
	(info.dev(), info.ino(), info.uid(), info.mode())
}

impl Directories {
	fn open(root: &Path) -> Result<Self> {
		let root = open_root(root)?;
		let root_identity = directory_identity(&root.metadata()?);
		let jobs = open_at(Some(&root), "jobs", libc::O_RDONLY | libc::O_DIRECTORY)?;
		let info = jobs.metadata()?;
		if info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o022 != 0 {
			bail!("durable inventory directory must be account-owned and non-writable by others");
		}
		Ok(Self {
			root,
			jobs,
			root_identity,
			jobs_identity: directory_identity(&info),
		})
	}

	fn same_scope(&self, other: &Self) -> bool {
		self.root_identity == other.root_identity && self.jobs_identity == other.jobs_identity
	}

	fn finish(&self, root: &Path) -> Result<()> {
		let held = open_at(Some(&self.root), "jobs", libc::O_RDONLY | libc::O_DIRECTORY)?;
		if directory_identity(&held.metadata()?) != self.jobs_identity
			|| directory_identity(&self.jobs.metadata()?) != self.jobs_identity
			|| directory_identity(&self.root.metadata()?) != self.root_identity
			|| directory_identity(&open_root(root)?.metadata()?) != self.root_identity
		{
			bail!("durable inventory root or directory changed");
		}
		Ok(())
	}
}

fn stamp(info: &Metadata) -> Stamp {
	(
		info.dev(),
		info.ino(),
		info.uid(),
		info.mode(),
		info.nlink(),
		info.len(),
		info.mtime(),
		info.mtime_nsec(),
		info.ctime(),
		info.ctime_nsec(),
	)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(clippy::unnecessary_cast)] // libc inode/device widths vary across Unix.
fn named_stamp(base: &File, name: &str) -> Result<Stamp> {
	let name = std::ffi::CString::new(name)?;
	let mut raw = std::mem::MaybeUninit::<libc::stat>::uninit();
	if unsafe {
		libc::fstatat(
			base.as_raw_fd(),
			name.as_ptr(),
			raw.as_mut_ptr(),
			libc::AT_SYMLINK_NOFOLLOW,
		)
	} < 0
	{
		return Err(std::io::Error::last_os_error().into());
	}
	let raw = unsafe { raw.assume_init() };
	if raw.st_size < 0 {
		bail!("durable inventory metadata byte bound refused");
	}
	// Compare every field from the opened original. A replacement symlink, FIFO,
	// directory or hard link cannot match; no second open or FIFO wait is needed.
	Ok((
		raw.st_dev as u64,
		raw.st_ino as u64,
		raw.st_uid,
		raw.st_mode as u32,
		raw.st_nlink as u64,
		raw.st_size as u64,
		raw.st_mtime,
		raw.st_mtime_nsec,
		raw.st_ctime,
		raw.st_ctime_nsec,
	))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn named_stamp(base: &File, name: &str) -> Result<Stamp> {
	Ok(stamp(
		&open_at(Some(base), name, libc::O_RDONLY)?.metadata()?,
	))
}

fn entries(base: &File, budget: &Budget) -> Result<Vec<String>> {
	// A new file description keeps repeated membership scans independent.
	let scan = open_at(Some(base), ".", libc::O_RDONLY | libc::O_DIRECTORY)?;
	let fd = unsafe { libc::dup(scan.as_raw_fd()) };
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
	let mut names = Vec::new();
	loop {
		budget.check()?;
		#[cfg(target_os = "linux")]
		let error = unsafe { libc::__errno_location() };
		#[cfg(target_os = "macos")]
		let error = unsafe { libc::__error() };
		#[cfg(not(any(target_os = "linux", target_os = "macos")))]
		{
			bail!("bounded inventory directory scans require Linux or macOS");
		}
		#[cfg(any(target_os = "linux", target_os = "macos"))]
		{
			unsafe { *error = 0 };
			let item = unsafe { libc::readdir(stream.0) };
			if item.is_null() {
				if unsafe { *error } != 0 {
					return Err(std::io::Error::last_os_error().into());
				}
				break;
			}
			let value = unsafe { std::ffi::CStr::from_ptr((*item).d_name.as_ptr()) }.to_str()?;
			if matches!(value, "." | "..") {
				continue;
			}
			if names.len() >= budget.limits.records.saturating_add(32) {
				bail!("durable inventory source entry bound exceeded");
			}
			names.push(value.to_owned());
		}
	}
	names.sort();
	Ok(names
		.into_iter()
		.filter(|name| name.ends_with(".json"))
		.collect())
}

fn content_watch(base: &File) -> Option<namespace_version::Version> {
	// An unavailable, exhausted or lost watch may only choose the full original
	// read path. The namespace fingerprint alone never authorizes content reuse.
	namespace_version::content_version(base).ok().flatten()
}

fn same_content_watch(
	one: Option<namespace_version::Version>,
	other: Option<namespace_version::Version>,
) -> bool {
	#[cfg(target_os = "linux")]
	{
		matches!(one, Some(namespace_version::Version::Watch(_, _))) && one == other
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = (one, other);
		false
	}
}

fn scan<T>(
	root: &Path,
	budget: &Budget,
	expected: Option<&SourceProof>,
	mut project: impl FnMut(&str, &[u8]) -> Result<T>,
) -> Result<(Vec<T>, SourceProof)> {
	budget.check()?;
	let directories = Directories::open(root)?;
	if expected.is_some_and(|old| !directories.same_scope(&old.directories)) {
		bail!("durable inventory root or directory changed");
	}
	let watch = content_watch(&directories.jobs);
	let names = entries(&directories.jobs, budget)?;
	if names.len() > budget.limits.records {
		bail!("durable inventory source row bound exceeded");
	}
	if expected.is_some_and(|old| old.names != names) {
		bail!("durable inventory membership changed; restart from the first page");
	}
	let mut rows = Vec::with_capacity(names.len());
	let mut records = Vec::with_capacity(names.len());
	let mut bytes = 0u64;
	let mut raw = Vec::new();
	for (index, name) in names.iter().enumerate() {
		budget.check()?;
		let id = name
			.strip_suffix(".json")
			.context("invalid inventory identity")?;
		if !valid_name(id) {
			bail!("invalid durable inventory identity");
		}
		let mut file = open_at(Some(&directories.jobs), name, libc::O_RDONLY)?;
		let before = file.metadata()?;
		if !before.is_file()
			|| before.uid() != unsafe { libc::geteuid() }
			|| before.mode() & 0o7777 != 0o600
			|| before.nlink() != 1
			|| before.len() == 0
			|| before.len() > budget.limits.record_bytes
		{
			bail!("durable inventory metadata inode or byte bound refused");
		}
		bytes = bytes
			.checked_add(before.len())
			.context("durable inventory byte overflow")?;
		if bytes > budget.limits.bytes {
			bail!("durable inventory total source byte bound exceeded");
		}
		raw.clear();
		// One spare byte observes EOF without growing an exactly full input buffer.
		raw.try_reserve_exact(before.len() as usize + 1)
			.context("cannot allocate bounded durable inventory read buffer")?;
		Read::by_ref(&mut file)
			.take(before.len() + 1)
			.read_to_end(&mut raw)?;
		budget.check()?;
		let before = stamp(&before);
		if raw.len() as u64 != before.5 || before != stamp(&file.metadata()?) {
			bail!("durable inventory metadata changed during observation");
		}
		let sha256: [u8; 32] = Sha256::digest(&raw).into();
		if let Some(old) = expected {
			if old.records[index].stamp != before || old.records[index].sha256 != sha256 {
				bail!("durable inventory original content changed; restart from the first page");
			}
		}
		rows.push(project(id, &raw)?);
		records.push(RecordProof {
			stamp: before,
			sha256,
		});
	}
	drop(raw);
	if entries(&directories.jobs, budget)? != names {
		bail!("durable inventory membership changed");
	}
	for (name, before) in names.iter().zip(&records) {
		budget.check()?;
		if named_stamp(&directories.jobs, name)? != before.stamp {
			bail!("durable inventory metadata changed");
		}
	}
	directories.finish(root)?;
	let after = content_watch(&directories.jobs);
	if watch.is_some() && !same_content_watch(watch, after) {
		bail!("durable inventory content watch changed during observation");
	}
	budget.check()?;
	Ok((
		rows,
		SourceProof {
			directories,
			names,
			records,
		},
	))
}

pub(super) fn observe<T>(
	root: &Path,
	limits: InventoryLimits,
	mut project: impl FnMut(JobRecordData<ValidatedJobString>) -> T,
) -> Result<(Vec<T>, SourceProof)> {
	let budget = Budget {
		started: Instant::now(),
		limits,
	};
	scan(root, &budget, None, |id, raw| {
		// The original complete schema validates every field, including escaped
		// private strings and unselected hosts. No private text survives decoding.
		let record: JobRecordData<ValidatedJobString> =
			serde_json::from_slice(raw).context("corrupt durable inventory metadata")?;
		if record.id != id || !valid_name(&record.host) {
			bail!("durable inventory record identity mismatch");
		}
		Ok(project(record))
	})
}

#[cfg(test)]
pub(super) fn observe_owned<T>(
	root: &Path,
	limits: InventoryLimits,
	mut project: impl FnMut(JobRecord) -> T,
) -> Result<(Vec<T>, SourceProof)> {
	let budget = Budget {
		started: Instant::now(),
		limits,
	};
	scan(root, &budget, None, |id, raw| {
		let record: JobRecord =
			serde_json::from_slice(raw).context("corrupt durable inventory metadata")?;
		if record.id != id || !valid_name(&record.host) {
			bail!("durable inventory record identity mismatch");
		}
		Ok(project(record))
	})
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ValidationPath {
	OriginalBytes,
}

pub(super) fn validate(
	root: &Path,
	limits: InventoryLimits,
	proof: &SourceProof,
) -> Result<ValidationPath> {
	let budget = Budget {
		started: Instant::now(),
		limits,
	};
	// A directory content watch cannot prove unchanged receipt bytes: Linux
	// inotify does not report writes through an existing MAP_SHARED mapping.
	// Every continuation therefore rechecks the full originals on every host,
	// including inode safety, byte/record/time limits and final membership and
	// metadata fences. The cache reuses only the previously checked projection.
	scan(root, &budget, Some(proof), |_, _| Ok(()))?;
	Ok(ValidationPath::OriginalBytes)
}

#[cfg(test)]
#[path = "jobs_inventory_source_tests.rs"]
mod tests;
