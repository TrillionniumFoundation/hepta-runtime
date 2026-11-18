// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DurableState {
	Unknown,
	Completed,
	Failed,
}
mod record_schema {
	use super::DurableState;
	use serde::{Deserialize, Serialize};

	// Serde derives its default Visitor diagnostic from the Rust identifier,
	// not serde(rename). Keep the original name for both string specializations.
	#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
	#[serde(deny_unknown_fields)]
	pub(super) struct Record<S> {
		pub(super) request_id: S,
		pub(super) owner: S,
		pub(super) tool_name: S,
		pub(super) state: DurableState,
		pub(super) accepted_unix_ms: u128,
		pub(super) elapsed_ms: Option<u64>,
	}
}
type RecordFields<S> = record_schema::Record<S>;
type Record = record_schema::Record<String>;
#[derive(Clone, Copy, PartialEq, Eq)]
struct ArchiveStamp {
	device: u64,
	inode: u64,
	modified: (i64, i64),
	changed: (i64, i64),
	namespace: super::namespace_version::Version,
}
struct HotSnapshot {
	stamp: ArchiveStamp,
	records: Vec<Record>,
}
static HOT_CACHE: OnceLock<Mutex<VecDeque<HotSnapshot>>> = OnceLock::new();
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
fn cache_hot(directory: &File, records: &[Record]) -> Result<()> {
	cache_hot_owned(directory, records.to_vec())
}
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
fn hot_snapshot_cached(directory: &File) -> Result<bool> {
	let stamp = archive_stamp(directory)?;
	let Some(cache) = HOT_CACHE.get() else {
		return Ok(false);
	};
	let cache = cache
		.lock()
		.map_err(|_| anyhow!("request hot cache unavailable"))?;
	Ok(cache.iter().any(|entry| entry.stamp == stamp))
}
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
