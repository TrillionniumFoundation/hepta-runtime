// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
// Exact original archive metadata include fragment.
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
	collections::VecDeque,
	fs::File,
	io::Read,
	sync::{Arc, Mutex, OnceLock},
};
const MAX_RECORD_BYTES: usize = 96 * 1024;
const ARCHIVE_ANCHOR: &str = ".request-results-v2-anchor.json";
const ARCHIVE_MARKER: &str = ".request-results-v2.json";
type AnchorCache = VecDeque<(AnchorStamp, Arc<CachedAnchor>)>;
static ANCHOR_CACHE: OnceLock<Mutex<AnchorCache>> = OnceLock::new();
#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DirectoryIdentity {
	device: u64,
	inode: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArchiveAnchor {
	schema: u8,
	root: DirectoryIdentity,
	legacy: DirectoryIdentity,
	store: DirectoryIdentity,
	archive: DirectoryIdentity,
	shards: Vec<DirectoryIdentity>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArchiveMarker {
	schema: u8,
	anchor_sha256: String,
}
struct CachedAnchor {
	anchor: ArchiveAnchor,
	sha256: String,
}
#[derive(PartialEq, Eq)]
struct AnchorStamp {
	device: u64,
	inode: u64,
	length: u64,
	modified: (i64, i64),
	changed: (i64, i64),
}
fn valid_id(value: &str) -> bool {
	value.len() == 64
		&& value
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(data: &[u8]) -> String {
	Sha256::digest(data)
		.iter()
		.map(|b| format!("{b:02x}"))
		.collect()
}
fn name(value: &str) -> Result<std::ffi::CString> {
	std::ffi::CString::new(value).map_err(|_| anyhow!("invalid private metadata component"))
}
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
fn is_not_found(error: &anyhow::Error) -> bool {
	error
		.downcast_ref::<std::io::Error>()
		.is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}
fn read_anchor(root: &File) -> Result<Arc<CachedAnchor>> {
	use std::os::unix::fs::MetadataExt;
	let mut file = open_at(root, ARCHIVE_ANCHOR, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
	validate_file(&file)?;
	let metadata = file.metadata()?;
	let stamp = AnchorStamp {
		device: metadata.dev(),
		inode: metadata.ino(),
		length: metadata.len(),
		modified: (metadata.mtime(), metadata.mtime_nsec()),
		changed: (metadata.ctime(), metadata.ctime_nsec()),
	};
	let cache = ANCHOR_CACHE.get_or_init(|| Mutex::new(VecDeque::new()));
	let mut bytes = Vec::new();
	Read::by_ref(&mut file)
		.take((MAX_RECORD_BYTES + 1) as u64)
		.read_to_end(&mut bytes)?;
	if bytes.len() > MAX_RECORD_BYTES {
		bail!("result archive anchor size refused");
	}
	let after = file.metadata()?;
	if after.dev() != stamp.device
		|| after.ino() != stamp.inode
		|| after.len() != stamp.length
		|| (after.mtime(), after.mtime_nsec()) != stamp.modified
		|| (after.ctime(), after.ctime_nsec()) != stamp.changed
	{
		bail!("result archive anchor changed during read");
	}
	// The file can be edited in place without advancing a coarse filesystem
	// timestamp. Cache parsed identities only after checking the actual bytes.
	let sha256 = digest(&bytes);
	if let Some(anchor) = cache
		.lock()
		.map_err(|_| anyhow!("result anchor cache unavailable"))?
		.iter()
		.find(|(existing, _)| *existing == stamp)
		.map(|(_, anchor)| Arc::clone(anchor))
	{
		if anchor.sha256 != sha256 {
			bail!("result archive anchor bytes changed; history never repaired automatically");
		}
		return Ok(anchor);
	}
	let anchor: ArchiveAnchor = serde_json::from_slice(&bytes)?;
	if anchor.schema != 2 || anchor.shards.len() != 256 {
		bail!("result archive anchor schema refused");
	}
	let anchor = Arc::new(CachedAnchor { sha256, anchor });
	let mut cache = cache
		.lock()
		.map_err(|_| anyhow!("result anchor cache unavailable"))?;
	// This bound limits cache memory only. Eviction never refuses admission,
	// evicts history, changes ownership, or bypasses filesystem validation.
	if cache.len() >= 16 {
		cache.pop_front();
	}
	cache.push_back((stamp, Arc::clone(&anchor)));
	Ok(anchor)
}
fn read_archive_marker(legacy: &File) -> Result<Option<ArchiveMarker>> {
	let mut file = match open_at(legacy, ARCHIVE_MARKER, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
		Ok(file) => file,
		Err(error) if is_not_found(&error) => return Ok(None),
		Err(error) => return Err(error),
	};
	validate_file(&file)?;
	let mut bytes = Vec::new();
	Read::by_ref(&mut file).take(1025).read_to_end(&mut bytes)?;
	if bytes.len() > 1024 {
		bail!("result archive marker size refused");
	}
	let marker: ArchiveMarker = serde_json::from_slice(&bytes)?;
	if marker.schema != 2 || !valid_id(&marker.anchor_sha256) {
		bail!("result archive marker schema refused");
	}
	Ok(Some(marker))
}
