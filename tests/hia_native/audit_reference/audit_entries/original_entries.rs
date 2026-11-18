// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
use serde::{Deserialize, Serialize};
use anyhow::{anyhow, bail, Result};
use std::fs::File;
use std::io::{Read, Write};
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
const MAX_RECORD_BYTES: usize = 2048;
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
fn name(value: &str) -> Result<std::ffi::CString> {
	std::ffi::CString::new(value).map_err(|_| anyhow!("invalid private metadata component"))
}
fn open_at(directory: &File, component: &str, flags: i32, mode: u32) -> Result<File> {
	let component = name(component)?;
	open_at_component(directory, &component, flags, mode)
}
fn open_at_component(
	directory: &File,
	component: &std::ffi::CStr,
	flags: i32,
	mode: u32,
) -> Result<File> {
	use std::os::fd::{AsRawFd, FromRawFd};
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
fn directory_scan_result(has_entry: bool, error: i32) -> Result<bool> {
	if has_entry {
		return Ok(true);
	}
	if error != 0 {
		return Err(std::io::Error::from_raw_os_error(error).into());
	}
	Ok(false)
}
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
fn walk_directory(directory: &File, mut visit: impl FnMut(&str) -> Result<()>) -> Result<()> {
	walk_directory_with_inode(directory, |filename, _| visit(filename))
}
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
