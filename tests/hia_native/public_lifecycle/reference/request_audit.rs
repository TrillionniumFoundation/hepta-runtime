// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
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
// SPDX-License-Identifier: Apache-2.0
// Unchanged audit functions used by the complete original Archive module.
use super::*;
use anyhow::{anyhow,bail,Result};
use serde::{Deserialize,Serialize};
use std::collections::HashMap;
use std::sync::{Arc,Mutex,OnceLock,Weak};
const MAX_RECORD_BYTES: usize = 2048;
const ARCHIVE_NAME: &str = "request-archive-v11";
const ARCHIVE_ANCHOR: &str = ".request-archive-v11-anchor.json";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArchiveAnchor {
	root_device: u64,
	root_inode: u64,
	archive_device: u64,
	archive_inode: u64,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct ArchiveStamp {
	device: u64,
	inode: u64,
	modified: (i64, i64),
	changed: (i64, i64),
	namespace: super::namespace_version::Version,
}
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

#[path="original_store.rs"]
mod archive_store;
// Qualification-only framing; all filesystem and lifecycle work calls Archive.
pub(super) struct Observer {
    handles: Vec<(u64, archive_store::Archive)>,
    directories: [u64; 260],
    generation: u64,
    directory_generation: u64,
    pub(super) frames: u64,
    pub(super) calls: [u64; 12],
    pub(super) errors: Vec<String>,
}

fn project_record(value: &Record) -> Vec<u8> {
    let mut out = vec![0; 256];
    out[..8].copy_from_slice(b"HRAJJ001");
    put(&mut out, 8, 1);
    put(&mut out, 16, u64::from(value.elapsed_ms.is_some()));
    put(&mut out, 24, value.accepted_unix_ms as u64);
    put(&mut out, 32, (value.accepted_unix_ms >> 64) as u64);
    put(&mut out, 40, match value.state {
        DurableState::Unknown => 0, DurableState::Completed => 1, DurableState::Failed => 2,
    });
    put(&mut out, 48, value.elapsed_ms.unwrap_or(0));
    for (slot, value) in [&value.request_id, &value.owner, &value.tool_name].into_iter().enumerate() {
        let at = out.len();
        put(&mut out, 64 + slot * 16, at as u64);
        put(&mut out, 72 + slot * 16, value.len() as u64);
        out.extend_from_slice(value.as_bytes());
    }
    out
}

fn project_version(value: Option<super::namespace_version::Version>) -> Vec<u8> {
    let mut out = vec![0; 64];
    out[..8].copy_from_slice(b"HNSVR001");
    match value {
        None => put(&mut out, 8, 3),
        Some(super::namespace_version::Version::Watch(id, generation)) => {
            put(&mut out, 8, 1); put(&mut out, 16, id); put(&mut out, 24, generation);
        }
        Some(super::namespace_version::Version::Fingerprint(digest)) => {
            put(&mut out, 8, 2); out[32..64].copy_from_slice(&digest);
        }
    }
    out
}

impl Observer {
    pub(super) fn new() -> Self {
        Self { handles: Vec::new(), directories: [0; 260], generation: 0,
            directory_generation: 0, frames: 0, calls: [0; 12], errors: Vec::new() }
    }
    pub(super) fn release_all(&mut self) {
        while !self.handles.is_empty() { drop(self.handles.remove(0)); }
        self.directories.fill(0);
    }
    pub(super) fn invoke(&mut self, root: &File, wire: &[u8]) -> (u32, Vec<u8>) {
        self.frames += 1;
        let invalid = (u32::MAX, Vec::new());
        if wire.len() < 64 || wire.len() > 8388608 || &wire[..8] != b"HRAOQ001" { return invalid; }
        let operation = get(wire, 8);
        let lease = get(wire, 16);
        if !(1..=12).contains(&operation) || get(wire, 40) != (wire.len()-64) as u64
            || get(wire, 48) != 0 || get(wire, 56) != 0 || get(wire, 24) > 1
            || (operation != 7 && get(wire, 24) != 0)
            || (operation != 8 && operation != 9 && get(wire, 32) != 0)
            || (![6,7,9,10].contains(&operation) && get(wire, 40) != 0) { return invalid; }
        let filename = match std::str::from_utf8(&wire[64..]) { Ok(value) => value, Err(_) => return invalid };
        let index = self.handles.iter().position(|entry| entry.0 == lease);
        if (operation == 1 && (lease != 0 || !self.handles.is_empty()))
            || (operation != 1 && index.is_none()) { return invalid; }
        let slot = if operation == 8 || operation == 9 {
            if get(wire, 32) == 0 { return invalid; }
            match self.directories.iter().position(|value| *value == get(wire, 32)) {
                Some(slot) if slot == 2 || (4..260).contains(&slot) => slot,
                _ => return invalid,
            }
        } else { 0 };
        if (operation == 1 || operation == 12) && (self.generation == u64::MAX || self.handles.len() == 1024) {
            return (u32::MAX-1, Vec::new());
        }
        self.calls[operation as usize - 1] += 1;
        let mut returned_lease = lease;
        let result = (|| -> Result<(u64, Option<usize>, Vec<u8>)> {
            if operation == 1 {
                let (legacy, anchor) = open_legacy_archive_at(root)?;
                let archive = archive_store::Archive::open(root, legacy, anchor)?;
                self.generation += 1;
                returned_lease = self.generation;
                self.handles.push((returned_lease, archive));
                return Ok((0, None, Vec::new()));
            }
            let index = index.unwrap();
            if operation == 2 {
                drop(self.handles.remove(index)); returned_lease = 0;
                if self.handles.is_empty() { self.directories.fill(0); }
                return Ok((0, None, Vec::new()));
            }
            if operation == 12 {
                let cloned = self.handles[index].1.try_clone()?;
                self.generation += 1;
                returned_lease = self.generation;
                self.handles.push((returned_lease, cloned));
                return Ok((0, None, Vec::new()));
            }
            let archive = &self.handles[index].1;
            match operation {
                3 => archive.fence_at(archive.root())?,
                4 => return Ok((u64::from(archive.needs_exclusive_open()?), None, Vec::new())),
                5 => archive.initialize_shards()?,
                6 => return Ok((0, archive.existing_directory(filename)?.map(|directory| archive.observer_slot(directory).unwrap()), Vec::new())),
                7 => return Ok((0, Some(archive.observer_slot(archive.directory_for_write(filename, get(wire,24)==1)?).unwrap()), Vec::new())),
                8 => archive.fence_target(archive.observer_directory(slot).unwrap())?,
                9 => archive.fence_record(filename, archive.observer_directory(slot).unwrap())?,
                10 => return Ok((0, None, project_record(&archive.read_record(filename)?))),
                11 => return Ok((0, None, project_version(archive.content_version()?))),
                _ => unreachable!(),
            }
            Ok((0, None, Vec::new()))
        })();
        let mut output = vec![0; 64];
        output[..8].copy_from_slice(b"HRAOR001");
        put(&mut output, 24, returned_lease);
        match result {
            Ok((mut answer, directory, payload)) => {
                if let Some(slot) = directory {
                    if self.directories[slot] == 0 { self.directory_generation += 1; self.directories[slot] = self.directory_generation; }
                    answer = self.directories[slot];
                }
                put(&mut output, 32, answer); put(&mut output, 40, payload.len() as u64);
                output.extend(payload);
            }
            Err(error) => {
                let (diagnostic, errno) = diagnostic(&error);
                put(&mut output, 8, diagnostic); put(&mut output, 16, errno);
                self.errors.push(error.to_string());
            }
        }
        (output.len() as u32, output)
    }
}

use archive_store::Archive;
#[path="original_trace.rs"]
pub(super) mod trace;
#[path="original_index.rs"]
mod index;
fn private_directory(directory: &File) -> Result<()> {
	private_directory_metadata(directory).map(|_| ())
}
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
fn decode_save_record(wire: &[u8]) -> Option<Record> {
	let raw = &wire[64..];
	if &raw[..8] != b"HRAJJ001"
		|| get(raw, 8) != 1
		|| get(raw, 16) > 1
		|| get(raw, 40) > 2
		|| get(raw, 56) != 0
		|| (get(raw, 16) == 0 && get(raw, 48) != 0)
		|| raw[112..256].iter().any(|byte| *byte != 0)
	{
		return None;
	}
	let mut at = 256usize;
	let mut strings = Vec::new();
	for slot in 0..3 {
		let start = usize::try_from(get(raw, 64 + slot * 16)).ok()?;
		let length = usize::try_from(get(raw, 72 + slot * 16)).ok()?;
		if start != at || length > raw.len() - at {
			return None;
		}
		strings.push(std::str::from_utf8(&raw[at..at + length]).ok()?.to_owned());
		at += length;
	}
	if at != raw.len() {
		return None;
	}
	Some(Record {
		request_id: strings.remove(0),
		owner: strings.remove(0),
		tool_name: strings.remove(0),
		state: match get(raw, 40) {
			0 => DurableState::Unknown,
			1 => DurableState::Completed,
			2 => DurableState::Failed,
			_ => unreachable!(),
		},
		accepted_unix_ms: u128::from(get(raw, 24)) | (u128::from(get(raw, 32)) << 64),
		elapsed_ms: (get(raw, 16) == 1).then(|| get(raw, 48)),
	})
}
// Qualification-only framing for the complete unchanged save function.
static SAVE_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(super) fn save_calls() -> u64 {
	SAVE_CALLS.load(std::sync::atomic::Ordering::Relaxed)
}

impl Observer {
	pub(super) fn invoke_checked(&mut self, root: &File, wire: &[u8]) -> (u32, Vec<u8>) {
		assert!(index::observer_absent());
		let result = if wire.len() >= 8 && &wire[..8] == b"HRASVQ01" {
			self.invoke_save(wire)
		} else if wire.len() > 4096 {
			self.frames += 1;
			(u32::MAX, Vec::new())
		} else {
			self.invoke(root, wire)
		};
		assert!(index::observer_absent());
		result
	}

	fn invoke_save(&mut self, wire: &[u8]) -> (u32, Vec<u8>) {
		self.frames += 1;
		let invalid = (u32::MAX, Vec::new());
		if !(320..=576).contains(&wire.len())
			|| get(wire, 8) != 1
			|| get(wire, 24) > 1
			|| get(wire, 32) > 1
			|| get(wire, 40) != (wire.len() - 64) as u64
			|| get(wire, 48) != 0
			|| get(wire, 56) != 0
		{
			return invalid;
		}
		let Some(record) = decode_save_record(wire) else {
			return invalid;
		};
		let lease = get(wire, 16);
		let Some((_, archive)) = self.handles.iter().find(|entry| entry.0 == lease) else {
			return invalid;
		};
		SAVE_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
		let result = save_archive_with_sync(archive, &record, get(wire, 24) == 1, get(wire, 32) == 1);
		let mut output = vec![0; 64];
		output[..8].copy_from_slice(b"HRAOR001");
		put(&mut output, 24, lease);
		if let Err(error) = result {
			let (diagnostic, errno) = diagnostic(&error);
			put(&mut output, 8, diagnostic);
			put(&mut output, 16, errno);
			self.errors.push(error.to_string());
		}
		(output.len() as u32, output)
	}
}

use std::collections::VecDeque;
const MAX_GLOBAL: usize = 512;
static HOT_CACHE: OnceLock<Mutex<VecDeque<HotSnapshot>>> = OnceLock::new();
struct HotSnapshot {
	stamp: ArchiveStamp,
	records: Vec<Record>,
}
fn entries(directory: &File) -> Result<Vec<Record>> {
	entries_bounded(directory, MAX_GLOBAL)
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
fn number(raw: &[u8], at: usize) -> u64 {
	u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}
fn word(raw: &mut [u8], at: usize, value: u64) {
	raw[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn projection(value: &Record) -> Vec<u8> {
	let mut out = vec![0; 256];
	out[..8].copy_from_slice(b"HRAJJ001");
	word(&mut out, 8, 1);
	word(&mut out, 16, u64::from(value.elapsed_ms.is_some()));
	word(&mut out, 24, value.accepted_unix_ms as u64);
	word(&mut out, 32, (value.accepted_unix_ms >> 64) as u64);
	word(
		&mut out,
		40,
		match value.state {
			DurableState::Unknown => 0,
			DurableState::Completed => 1,
			DurableState::Failed => 2,
		},
	);
	word(&mut out, 48, value.elapsed_ms.unwrap_or(0));
	for (slot, value) in [&value.request_id, &value.owner, &value.tool_name]
		.into_iter()
		.enumerate()
	{
		let at = out.len();
		word(&mut out, 64 + slot * 16, at as u64);
		word(&mut out, 72 + slot * 16, value.len() as u64);
		out.extend_from_slice(value.as_bytes());
	}
	out
}
fn from_projection(raw: &[u8]) -> Record {
	assert_eq!(&raw[..8], b"HRAJJ001");
	assert_eq!(number(raw, 8), 1);
	let string = |slot: usize| {
		let at = number(raw, 64 + slot * 16) as usize;
		let size = number(raw, 72 + slot * 16) as usize;
		String::from_utf8(raw[at..at + size].to_vec()).unwrap()
	};
	let record = Record {
		request_id: string(0),
		owner: string(1),
		tool_name: string(2),
		accepted_unix_ms: number(raw, 24) as u128 | ((number(raw, 32) as u128) << 64),
		state: match number(raw, 40) {
			0 => DurableState::Unknown,
			1 => DurableState::Completed,
			2 => DurableState::Failed,
			_ => panic!("state"),
		},
		elapsed_ms: if number(raw, 16) == 1 {
			Some(number(raw, 48))
		} else {
			None
		},
	};
	assert_eq!(projection(&record), raw);
	record
}
fn from_stamp(raw: &[u8]) -> ArchiveStamp {
	assert_eq!(raw.len(), 112);
	assert_eq!(&raw[..8], b"HRAST001");
	let namespace = match number(raw, 56) {
		1 => {
			assert_eq!(&raw[80..112], &[0; 32]);
			super::namespace_version::Version::Watch(number(raw, 64), number(raw, 72))
		}
		2 => {
			assert_eq!(number(raw, 64), 0);
			assert_eq!(number(raw, 72), 0);
			super::namespace_version::Version::Fingerprint(raw[80..112].try_into().unwrap())
		}
		_ => panic!("namespace tag"),
	};
	ArchiveStamp {
		device: number(raw, 8),
		inode: number(raw, 16),
		modified: (number(raw, 24) as i64, number(raw, 32) as i64),
		changed: (number(raw, 40) as i64, number(raw, 48) as i64),
		namespace,
	}
}
fn inspect_cache() -> (u64, u64, u64) {
	let Some(cache) = HOT_CACHE.get() else {
		return (0, 0, 0);
	};
	let poison = u64::from(cache.is_poisoned());
	let guard = cache.lock().unwrap_or_else(|p| p.into_inner());
	(guard.len() as u64, 1, poison)
}

fn valid_projection(raw: &[u8]) -> bool {
	if !(256..=512).contains(&raw.len())
		|| &raw[..8] != b"HRAJJ001"
		|| number(raw, 8) != 1
		|| number(raw, 16) > 1
		|| number(raw, 40) > 2
		|| number(raw, 56) != 0
		|| (number(raw, 16) == 0 && number(raw, 48) != 0)
		|| raw[112..256].iter().any(|n| *n != 0)
	{
		return false;
	}
	let mut at = 256_usize;
	for slot in 0..3 {
		let offset = number(raw, 64 + slot * 16);
		let count = number(raw, 72 + slot * 16);
		if offset != at as u64 || count > (raw.len() - at) as u64 {
			return false;
		}
		let end = at + count as usize;
		if std::str::from_utf8(&raw[at..end]).is_err() {
			return false;
		}
		at = end;
	}
	at == raw.len()
}
fn valid_stamp(raw: &[u8]) -> bool {
	if raw.len() != 112 || &raw[..8] != b"HRAST001" {
		return false;
	}
	match number(raw, 56) {
		1 => raw[80..].iter().all(|n| *n == 0),
		2 => number(raw, 64) == 0 && number(raw, 72) == 0,
		_ => false,
	}
}
fn stamp_bytes(stamp: ArchiveStamp) -> Vec<u8> {
	let mut raw = vec![0; 112];
	raw[..8].copy_from_slice(b"HRAST001");
	for (index, value) in [
		stamp.device,
		stamp.inode,
		stamp.modified.0 as u64,
		stamp.modified.1 as u64,
		stamp.changed.0 as u64,
		stamp.changed.1 as u64,
	]
	.into_iter()
	.enumerate()
	{
		word(&mut raw, 8 + index * 8, value);
	}
	match stamp.namespace {
		namespace_version::Version::Watch(first, second) => {
			word(&mut raw, 56, 1);
			word(&mut raw, 64, first);
			word(&mut raw, 72, second);
		}
		namespace_version::Version::Fingerprint(digest) => {
			word(&mut raw, 56, 2);
			raw[80..].copy_from_slice(&digest);
		}
	}
	raw
}
fn inspection(index: usize) -> Vec<u8> {
	let (count, initialized, poison) = inspect_cache();
	let mut out = vec![0; 64];
	out[..8].copy_from_slice(b"HRACR001");
	word(&mut out, 48, count);
	word(&mut out, 56, initialized);
	if poison != 0 {
		word(&mut out, 8, 43);
		return out;
	}
	if index >= count as usize {
		return out;
	}
	let guard = HOT_CACHE.get().unwrap().lock().unwrap();
	let item = &guard[index];
	word(&mut out, 32, 112);
	word(&mut out, 40, item.records.len() as u64);
	out.extend(stamp_bytes(item.stamp));
	for record in &item.records {
		let raw = projection(record);
		out.extend((raw.len() as u64).to_le_bytes());
		out.extend(raw);
	}
	out
}

impl Observer {
pub(super) fn invoke_cache(&mut self, raw: &[u8], directories: &[File], calls: &mut [u64; 7]) -> (u32, Vec<u8>) {
	let invalid = || (u32::MAX, Vec::new());
	if raw.len() < 64 || raw.len() > 1048576 || &raw[..8] != b"HRACQ001" {
		return invalid();
	}
	let op = number(raw, 8);
	let dir = number(raw, 16);
	let count = number(raw, 40);
	let before = number(raw, 48);
	if op > 6
				|| (op != 3 && (number(raw, 24) != 0 || number(raw, 32) != 0))
		|| (op == 3 && (number(raw, 24) == 0 || number(raw, 32) > 1))
		|| number(raw, 56) != 0
		|| count > 512
	{
		return invalid();
	}
	if (op == 0 || op == 5) && dir != 0 {
		return invalid();
	}
	if (1..=4).contains(&op) && !(1..=17).contains(&dir) {
		return invalid();
	}
	if op == 6 {
		if raw.len() != 64 || dir > 15 || count != 0 || before != 0 {
			return invalid();
		}
		calls[6] += 1;
		let out = inspection(dir as usize);
		return (out.len() as u32, out);
	}
	if op != 1 && op != 4 && count != 0 {
		return invalid();
	}
	if op == 4 {
		if count != 1 || before != 112 || raw.len() < 176 || !valid_stamp(&raw[64..176]) {
			return invalid();
		}
	} else if before != 0 {
		return invalid();
	}
	let mut at = 64 + before as usize;
	let mut records = Vec::new();
	for _ in 0..count {
		if raw.len() - at < 8 {
			return invalid();
		}
		let size = number(raw, at);
		at += 8;
		if size > (raw.len() - at) as u64 {
			return invalid();
		}
		let end = at + size as usize;
		if !valid_projection(&raw[at..end]) {
			return invalid();
		}
		records.push(from_projection(&raw[at..end]));
		at = end;
	}
	if at != raw.len() {
		return invalid();
	}
	if op == 3 && !self.handles.iter().any(|entry| entry.0 == number(raw, 24)) {
        return invalid();
    }
    calls[op as usize] += 1;
    let mut returned_records = Vec::new();
	let outcome: Result<u64> = match op {
		0 => Ok(inspect_cache().2),
		1 => cache_hot_owned(&directories[dir as usize - 1], records).map(|_| 0),
		2 => hot_snapshot_cached(&directories[dir as usize - 1]).map(u64::from),
        3 => {
            let archive = &self.handles.iter().find(|entry| entry.0 == number(raw, 24)).unwrap().1;
            hot_snapshot_at(&directories[dir as usize - 1], archive, number(raw, 32) == 1)
                .map(|records| { returned_records = records; 0 })
        }
        4 => update_cached_completion(
			&directories[dir as usize - 1],
			&records[0],
			from_stamp(&raw[64..176]),
		)
		.map(|_| 0),
		5 => {
			let hook = std::panic::take_hook();
			std::panic::set_hook(Box::new(|_| {}));
			let result = std::panic::catch_unwind(|| {
				let _guard = HOT_CACHE
					.get_or_init(|| Mutex::new(VecDeque::new()))
					.lock()
					.unwrap_or_else(|p| p.into_inner());
				panic!("private poison trigger");
			});
			std::panic::set_hook(hook);
			assert!(result.is_err());
			Ok(0)
		}
		_ => unreachable!(),
	};
	let mut out = vec![0; 64];
	out[..8].copy_from_slice(b"HRACR001");
	match outcome {
		Ok(value) => word(&mut out, 32, value),
		Err(error) => {
			let (diagnostic, errno, missing) = cache_error(&error);
			word(&mut out, 8, diagnostic);
			word(&mut out, 16, errno);
			word(&mut out, 24, u64::from(missing));
		}
	}
	let (count, initialized, _) = inspect_cache();
	word(&mut out, 48, count);
	word(&mut out, 56, initialized);
	if number(&out, 8) == 0 && op == 3 {
        word(&mut out, 40, returned_records.len() as u64);
        for record in &returned_records {
            let bytes = projection(record);
            out.extend((bytes.len() as u64).to_le_bytes());
            out.extend(bytes);
        }
    }
    (out.len() as u32, out)
}
}
// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
// Private framing only; all filesystem/cache calls above retain their original bodies.
fn cache_error(error: &anyhow::Error) -> (u64, u64, bool) {
	let text = error.to_string();
	let code = match text.as_str() {
		"request hot cache unavailable" => return (43, 0, false),
		"request hot namespace changed during validation" => return (44, 0, false),
		_ => diagnostic(error),
	};
	let mapped = match code.0 {
		13 => 16,
		15 => 30,
		value if value >= 40 => value + 100,
		value => value,
	};
	(mapped, code.1, mapped == 23 && code.1 == 2)
}

impl Observer {
	pub(super) fn invoke_cold(
		&mut self,
		root: &File,
		wire: &[u8],
		directories: &[File],
		calls: &mut [u64; 7],
		archive_context: &mut bool,
	) -> (u32, Vec<u8>) {
		assert!(index::observer_absent());
		if (64..=1048576).contains(&wire.len()) && &wire[..8] == b"HRACQ001" {
			self.frames += 1;
			if (1..=4).contains(&get(wire, 8)) && !*archive_context {
				return (u32::MAX, Vec::new());
			}
			return self.invoke_cache(wire, directories, calls);
		}
		if (64..=4096).contains(&wire.len()) && &wire[..8] == b"HRAOQ001" {
			*archive_context = true;
		}
		if (320..=576).contains(&wire.len())
			&& &wire[..8] == b"HRASVQ01"
			&& get(wire, 8) == 1
			&& get(wire, 24) <= 1
			&& get(wire, 32) <= 1
			&& get(wire, 40) == (wire.len() - 64) as u64
			&& get(wire, 48) == 0
			&& get(wire, 56) == 0
			&& decode_save_record(wire).is_some()
		{
			*archive_context = true;
		}
		self.invoke_checked(root, wire)
	}
}

use std::collections::HashSet;
const MAX_OWNER: usize = 128;
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
// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Private typed framing. All four retention bodies and actual leaf methods remain unchanged.
#[path = "activity_bridge.rs"]
mod activity;

// Actual shared is_active is included below.

pub(super) struct RetentionState {
    context: Option<(u64, u64)>,
    activity: activity::Bridge,
    pub(super) calls: [u64; 4],
    pub(super) contexts: u64,
}

impl RetentionState {
    pub(super) fn new() -> Self {
        Self { context: None, activity: activity::Bridge::new(), calls: [0; 4], contexts: 0 }
    }
    pub(super) fn finish(&mut self) {
        self.activity.finish();
    }
    pub(super) fn activity_calls(&self) -> &[u64; 17] {
        self.activity.calls()
    }
}

struct RetentionInput {
    operation: u64,
    sync: bool,
    primary: Option<Record>,
    records: Vec<Record>,
    pending: HashSet<String>,
    owner: String,
    id: String,
}

fn retention_input(raw: &[u8]) -> Option<RetentionInput> {
    if !(64..=1048576).contains(&raw.len()) || &raw[..8] != b"HRAKQ001" {
        return None;
    }
    let op = number(raw, 8);
    let sync = number(raw, 16);
    let primary_size = number(raw, 24);
    let record_count = number(raw, 32);
    let pending_count = number(raw, 40);
    let owner_size = number(raw, 48);
    let id_size = number(raw, 56);
    if !(1..=4).contains(&op) || sync > 1 || record_count > 512 || pending_count > 512
        || owner_size > 256 || id_size > 256
        || (op != 4 && (sync != 0 || record_count != 0 || pending_count != 0 || owner_size != 0))
        || (op != 1 && id_size != 0)
        || (!(2..=3).contains(&op) && primary_size != 0)
        || ((2..=3).contains(&op) && !(256..=512).contains(&primary_size))
    {
        return None;
    }
    let mut at = 64_usize;
    let primary = if primary_size != 0 {
        if primary_size > (raw.len() - at) as u64 { return None; }
        let end = at + primary_size as usize;
        if !valid_projection(&raw[at..end]) { return None; }
        let value = from_projection(&raw[at..end]);
        at = end;
        Some(value)
    } else { None };
    let mut records = Vec::new();
    for _ in 0..record_count {
        if raw.len() - at < 8 { return None; }
        let count = number(raw, at);
        at += 8;
        if count > (raw.len() - at) as u64 { return None; }
        let end = at + count as usize;
        if !valid_projection(&raw[at..end]) { return None; }
        records.push(from_projection(&raw[at..end]));
        at = end;
    }
    let mut pending = HashSet::new();
    for _ in 0..pending_count {
        if raw.len() - at < 8 { return None; }
        let count = number(raw, at);
        at += 8;
        if count > 256 || count > (raw.len() - at) as u64 { return None; }
        let end = at + count as usize;
        pending.insert(std::str::from_utf8(&raw[at..end]).ok()?.to_owned());
        at = end;
    }
    if owner_size > (raw.len() - at) as u64 { return None; }
    let owner_end = at + owner_size as usize;
    let owner = std::str::from_utf8(&raw[at..owner_end]).ok()?.to_owned();
    at = owner_end;
    if id_size != (raw.len() - at) as u64 { return None; }
    let id = std::str::from_utf8(&raw[at..]).ok()?.to_owned();
    Some(RetentionInput { operation: op, sync: sync == 1, primary, records, pending, owner, id })
}

fn retention_error(error: &anyhow::Error) -> (u64, u64, bool) {
    let code = match error.to_string().as_str() {
        "request hot cache binding changed" => 31,
        "request archive identity or outcome changed" => 35,
        "request archive identity changed" => 36,
        "request archive terminal outcome changed" => 37,
        "request audit active registry unavailable" => 38,
        "request read pin state unavailable" => 39,
        _ => {
            let (code, errno, _) = cache_error(error);
            let missing = error.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound);
            return (code, errno, missing);
        }
    };
    (code, 0, false)
}

impl Observer {
    pub(super) fn invoke_retention(
        &mut self,
        root: &File,
        raw: &[u8],
        directories: &[File],
        cache_calls: &mut [u64; 7],
        archive_context: &mut bool,
        state: &mut RetentionState,
    ) -> (u32, Vec<u8>) {
        let invalid = || (u32::MAX, Vec::new());
        if raw.starts_with(b"HRAKTQ01") {
            self.frames += 1;
            if raw.len() != 32 || !(1..=17).contains(&number(raw, 8))
                || number(raw, 16) == 0 || number(raw, 24) != 0 {
                return invalid();
            }
            let hot = number(raw, 8);
            let lease = number(raw, 16);
            state.context = Some((hot, lease));
            state.contexts += 1;
            let mut out = raw.to_vec();
            out[..8].copy_from_slice(b"HRAKTR01");
            return (32, out);
        }
        if raw.starts_with(b"HRAAQ001") {
            self.frames += 1;
            return state.activity.invoke(raw);
        }
        if !raw.starts_with(b"HRAKQ001") {
            return self.invoke_cold(root, raw, directories, cache_calls, archive_context);
        }
        self.frames += 1;
        let Some((hot, lease)) = state.context else { return invalid(); };
        if !*archive_context { return invalid(); }
        let Some(archive) = self.handles.iter().find(|entry| entry.0 == lease).map(|entry| &entry.1)
        else { return invalid(); };
        let Some(mut input) = retention_input(raw) else { return invalid(); };
        state.calls[input.operation as usize - 1] += 1;
        let directory = &directories[hot as usize - 1];
        let outcome: Result<(u64, Option<Record>)> = match input.operation {
            1 => retained_record(directory, archive, &input.id)
                .map(|record| (u64::from(record.is_some()), record)),
            2 => Ok((u64::from(archived_copy_matches(archive, input.primary.as_ref().unwrap())), None)),
            3 => archive_replacement(archive, input.primary.as_ref().unwrap())
                .map(|replacement| (replacement.map_or(0, |value| 1 + u64::from(value)), None)),
            4 => retain_for_batch(directory, archive, &input.owner, &mut input.records,
                &input.pending, input.sync).map(|value| (u64::from(value), None)),
            _ => unreachable!(),
        };
        let mut out = vec![0; 64];
        out[..8].copy_from_slice(b"HRAKR001");
        let mut selected = None;
        match outcome {
            Ok((decision, record)) => { word(&mut out, 32, decision); selected = record; }
            Err(error) => {
                let (diagnostic, errno, missing) = retention_error(&error);
                word(&mut out, 8, diagnostic);
                word(&mut out, 16, errno);
                word(&mut out, 24, u64::from(missing));
            }
        }
        if input.operation == 4 {
            word(&mut out, 40, input.records.len() as u64);
            for record in &input.records {
                let bytes = projection(record);
                out.extend((bytes.len() as u64).to_le_bytes());
                out.extend(bytes);
            }
        } else if let Some(record) = selected {
            let bytes = projection(&record);
            word(&mut out, 48, bytes.len() as u64);
            out.extend(bytes);
        }
        (out.len() as u32, out)
    }
}

// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Append in the actual audit module with real std File/Arc and Archive.
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
#[rustfmt::skip]
const STORE_NAME: &str = "request-audit";
#[rustfmt::skip]
static STORE_LOCK: OnceLock<AuditStoreLock> = OnceLock::new();
#[rustfmt::skip]
#[derive(Debug, Clone, Copy)]
pub enum AuditCompletion {
	/// Successful dispatch response, not confirmed delivery or business success.
	Completed,
	/// Dispatch rejection/failure, never proof that a side effect did not occur.
	Failed,
	/// Completion or possible side effects cannot be reliably classified.
	Unknown,
}
#[rustfmt::skip]
pub struct RequestTicket {
	directory: File,
	archive: Archive,
	hot_present: bool,
	record: Record,
	started: Instant,
	active: Arc<AtomicBool>,
	_read_pin: Option<Arc<()>>,
}
#[rustfmt::skip]
#[derive(Clone)]
pub(crate) struct RequestIdentity {
	pub request_id: String,
	pub owner: String,
	pub tool_name: String,
	pub accepted_unix_ms: u128,
}
#[rustfmt::skip]
impl RequestTicket {
	pub fn request_id(&self) -> &str {
		&self.record.request_id
	}
}
#[rustfmt::skip]
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
#[rustfmt::skip]
#[derive(Clone, Copy, PartialEq, Eq)]
enum AuditStoreAccess {
	Exclusive,
	#[cfg(unix)]
	Shared,
}
#[rustfmt::skip]
#[derive(Default)]
struct AuditStoreQueue {
	next_ticket: u64,
	active: bool,
	readers: usize,
	reader_poisoned: bool,
	waiting: VecDeque<(u64, AuditStoreAccess)>,
}
#[rustfmt::skip]
#[derive(Default)]
struct AuditStoreLock {
	inner: Mutex<()>,
	queue: Mutex<AuditStoreQueue>,
	changed: std::sync::Condvar,
}
#[rustfmt::skip]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StoreLockFailure {
	Deadline,
	Unavailable,
}
#[rustfmt::skip]
struct AuditStoreGuard<'a> {
	lock: &'a AuditStoreLock,
	inner: Option<std::sync::MutexGuard<'a, ()>>,
}
#[rustfmt::skip]
struct AuditSharedGuard<'a> {
	lock: &'a AuditStoreLock,
	deadline: Instant,
	active: bool,
	// A panic must publish poison on the same thread that owns this operation.
	_not_send: std::marker::PhantomData<std::sync::MutexGuard<'a, ()>>,
}
#[rustfmt::skip]
impl AuditStoreLock {
	fn cancel(&self, queue: &mut AuditStoreQueue, ticket: u64) {
		queue.waiting.retain(|queued| queued.0 != ticket);
		self.changed.notify_all();
	}

	fn release(&self) {
		// Cleanup releases custody during unwinding without clearing poison.
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
		if queue.reader_poisoned {
			return Err(StoreLockFailure::Unavailable);
		}
		let ticket = queue.next_ticket;
		queue.next_ticket = ticket.checked_add(1).ok_or(StoreLockFailure::Unavailable)?;
		queue
			.waiting
			.push_back((ticket, AuditStoreAccess::Exclusive));
		loop {
			if deadline.is_some_and(|limit| Instant::now() >= limit) {
				self.cancel(&mut queue, ticket);
				return Err(StoreLockFailure::Deadline);
			}
			if queue.reader_poisoned {
				self.cancel(&mut queue, ticket);
				return Err(StoreLockFailure::Unavailable);
			}
			if !queue.active
				&& queue.readers == 0
				&& queue.waiting.front() == Some(&(ticket, AuditStoreAccess::Exclusive))
			{
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
		// The former owner drops inner before releasing its FIFO reservation.
		// No second, unbounded wait is introduced after admission.
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

	#[cfg(unix)]
	fn acquire_shared(
		&self,
		deadline: Instant,
	) -> std::result::Result<AuditSharedGuard<'_>, StoreLockFailure> {
		if Instant::now() >= deadline {
			return Err(StoreLockFailure::Deadline);
		}
		let mut queue = self
			.queue
			.lock()
			.map_err(|_| StoreLockFailure::Unavailable)?;
		if Instant::now() >= deadline {
			return Err(StoreLockFailure::Deadline);
		}
		if queue.reader_poisoned || self.inner.is_poisoned() {
			return Err(StoreLockFailure::Unavailable);
		}
		let ticket = queue.next_ticket;
		queue.next_ticket = ticket.checked_add(1).ok_or(StoreLockFailure::Unavailable)?;
		queue.waiting.push_back((ticket, AuditStoreAccess::Shared));
		loop {
			if Instant::now() >= deadline {
				self.cancel(&mut queue, ticket);
				return Err(StoreLockFailure::Deadline);
			}
			if queue.reader_poisoned || self.inner.is_poisoned() {
				self.cancel(&mut queue, ticket);
				return Err(StoreLockFailure::Unavailable);
			}
			if !queue.active && queue.waiting.front() == Some(&(ticket, AuditStoreAccess::Shared)) {
				queue.waiting.pop_front();
				queue.readers += 1;
				// Let the next adjacent reader observe its own admission condition.
				self.changed.notify_all();
				break;
			}
			queue = match self
				.changed
				.wait_timeout(queue, deadline.saturating_duration_since(Instant::now()))
			{
				Ok((queue, _)) => queue,
				Err(error) => {
					let (mut queue, _) = error.into_inner();
					self.cancel(&mut queue, ticket);
					return Err(StoreLockFailure::Unavailable);
				}
			};
		}
		drop(queue);
		let guard = AuditSharedGuard {
			lock: self,
			deadline,
			active: true,
			_not_send: std::marker::PhantomData,
		};
		if Instant::now() >= deadline {
			return Err(StoreLockFailure::Deadline);
		}
		Ok(guard)
	}
}
#[rustfmt::skip]
impl AuditSharedGuard<'_> {
	fn finish(mut self) -> std::result::Result<(), StoreLockFailure> {
		let mut queue = match self.lock.queue.lock() {
			Ok(queue) => queue,
			Err(error) => {
				drop(error.into_inner());
				return Err(StoreLockFailure::Unavailable);
			}
		};
		// This critical section is the success boundary. A peer that already
		// finished is not retroactively revoked by later poison publication.
		let mut result = if queue.reader_poisoned || self.lock.inner.is_poisoned() {
			Err(StoreLockFailure::Unavailable)
		} else if Instant::now() >= self.deadline {
			Err(StoreLockFailure::Deadline)
		} else {
			Ok(())
		};
		match queue.readers.checked_sub(1) {
			Some(readers) => queue.readers = readers,
			None => {
				queue.reader_poisoned = true;
				result = Err(StoreLockFailure::Unavailable);
			}
		}
		self.active = false;
		self.lock.changed.notify_all();
		result
	}
}
#[rustfmt::skip]
impl Drop for AuditSharedGuard<'_> {
	fn drop(&mut self) {
		if !self.active {
			return;
		}
		let mut queue = self
			.lock
			.queue
			.lock()
			.unwrap_or_else(|error| error.into_inner());
		if std::thread::panicking() {
			queue.reader_poisoned = true;
		}
		match queue.readers.checked_sub(1) {
			Some(readers) => queue.readers = readers,
			None => queue.reader_poisoned = true,
		}
		self.active = false;
		self.lock.changed.notify_all();
	}
}
#[rustfmt::skip]
impl Drop for AuditStoreGuard<'_> {
	fn drop(&mut self) {
		// Keep standard mutex poison and release inner before the FIFO turn.
		drop(self.inner.take());
		self.lock.release();
	}
}
#[rustfmt::skip]
fn store_lock() -> Result<AuditStoreGuard<'static>> {
	trace::measure("store_lock_wait", 0, None, || {
		STORE_LOCK
			.get_or_init(AuditStoreLock::default)
			.acquire(None)
			.map_err(|_| anyhow!("request audit state lock unavailable"))
	})
}
#[rustfmt::skip]
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
#[rustfmt::skip]
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
#[rustfmt::skip]
fn open_named_store(root: &Path, store_name: &str) -> Result<File> {
	let base = audit_root(root)?;
	open_named_store_at(&base, store_name)
}
#[rustfmt::skip]
fn open_store(root: &Path) -> Result<File> {
	open_named_store(root, STORE_NAME)
}
#[rustfmt::skip]
fn open_archive(root: &Path) -> Result<Archive> {
	let base = audit_root(root)?;
	open_archive_at(&base)
}
#[rustfmt::skip]
fn open_archive_at(base: &File) -> Result<Archive> {
	let (legacy, anchor) = open_legacy_archive_at(base)?;
	Archive::open(base, legacy, anchor)
}
#[rustfmt::skip]
fn hot_snapshot(root: &Path, directory: &File) -> Result<(Vec<Record>, Archive)> {
	let archive = open_archive(root)?;
	let records = hot_snapshot_at(directory, &archive, false)?;
	Ok((records, archive))
}
#[rustfmt::skip]
fn retain_before_begin(
	directory: &File,
	archive: &Archive,
	owner: &str,
	records: &mut Vec<Record>,
) -> Result<bool> {
	retain_for_batch(directory, archive, owner, records, &HashSet::new(), true)
}
#[rustfmt::skip]
fn save(directory: &File, record: &Record, replacing: bool) -> Result<()> {
	save_with_sync(directory, record, replacing, true)
}
#[rustfmt::skip]
fn save_with_sync(
	directory: &File,
	record: &Record,
	replacing: bool,
	sync_directory: bool,
) -> Result<()> {
	save_raw_with_sync(directory, record, replacing, sync_directory)
}
#[rustfmt::skip]
fn archive_record(archive: &Archive, record: &Record) -> Result<()> {
	archive_record_with_sync(archive, record, true)
}
#[rustfmt::skip]
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
#[rustfmt::skip]
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
#[rustfmt::skip]
fn begin_at(root: &Path, owner: &str, tool_name: &str) -> Result<RequestTicket> {
	begin_with_read_at(root, owner, tool_name, None)
}
#[rustfmt::skip]
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
#[rustfmt::skip]
fn begin_operation_reserved_at(root: &Path, identity: RequestIdentity) -> Result<RequestTicket> {
	if !valid_id(&identity.owner)
		|| !valid_id(&identity.request_id)
		|| !super::operation_async::eligible(&identity.tool_name)
	{
		bail!("reserved native read identity unavailable");
	}
	begin_reserved_record_at(root, identity)
}
#[rustfmt::skip]
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
#[rustfmt::skip]
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

// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Include in the same audit module as Ticket and Retention.
#[rustfmt::skip]
static ACTIVE: OnceLock<Mutex<HashMap<String, Weak<AtomicBool>>>> = OnceLock::new();
#[rustfmt::skip]
static READ_PINS: OnceLock<Mutex<HashMap<String, Vec<Weak<()>>>>> = OnceLock::new();
#[rustfmt::skip]
fn active_registry() -> Result<std::sync::MutexGuard<'static, HashMap<String, Weak<AtomicBool>>>> {
	ACTIVE
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.map_err(|_| anyhow!("request audit active registry unavailable"))
}
#[rustfmt::skip]
fn read_pins() -> Result<std::sync::MutexGuard<'static, HashMap<String, Vec<Weak<()>>>>> {
	READ_PINS
		.get_or_init(|| Mutex::new(HashMap::new()))
		.lock()
		.map_err(|_| anyhow!("request read pin state unavailable"))
}
#[rustfmt::skip]
fn is_dispatch_active(id: &str) -> Result<bool> {
	let mut registry = active_registry()?;
	registry.retain(|_, marker| marker.strong_count() > 0);
	Ok(registry
		.get(id)
		.and_then(Weak::upgrade)
		.is_some_and(|marker| marker.load(Ordering::Acquire)))
}
#[rustfmt::skip]
fn is_active(id: &str) -> Result<bool> {
	let active = is_dispatch_active(id)?;
	let mut pins = read_pins()?;
	pins.retain(|_, markers| {
		markers.retain(|marker| marker.strong_count() > 0);
		!markers.is_empty()
	});
	Ok(active || pins.contains_key(id))
}

// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Qualification envelope only. Storage, Arc, clocks and entropy are real.

struct TicketInput<'a> {
    op: u64,
    root: u64,
    completion: u64,
    accepted: u128,
    owner: &'a str,
    tool: &'a str,
    id: &'a str,
    target: Option<&'a str>,
}

fn ticket_input(raw: &[u8], live: bool) -> Option<TicketInput<'_>> {
    if !(96..=1120).contains(&raw.len()) || &raw[..8] != b"HRATQ001" {
        return None;
    }
    let op = number(raw, 8);
    if !(1..=7).contains(&op) || (op >= 4) != live || number(raw, 88) != 0 {
        return None;
    }
    let lengths = [number(raw, 48), number(raw, 56), number(raw, 64), number(raw, 80)];
    if lengths.iter().any(|n| *n > 256)
        || lengths.iter().sum::<u64>() != (raw.len() - 96) as u64
        || number(raw, 72) > 1
    {
        return None;
    }
    let root = number(raw, 16);
    let completion = number(raw, 24);
    let accepted = number(raw, 32) as u128 | ((number(raw, 40) as u128) << 64);
    let target_present = number(raw, 72) != 0;
    if op == 1 {
        if completion != 0 || accepted != 0 || lengths[2] != 0
            || (!target_present && lengths[3] != 0) { return None; }
    } else if op <= 3 {
        if completion != 0 || target_present || lengths[3] != 0 { return None; }
    } else if root != 0 || accepted != 0 || lengths.iter().any(|n| *n != 0)
        || target_present || completion > 2 || (op != 4 && completion != 0)
    {
        return None;
    }
    let mut at = 96;
    let mut strings = [""; 4];
    for (index, count) in lengths.into_iter().enumerate() {
        let end = at + count as usize;
        strings[index] = std::str::from_utf8(&raw[at..end]).ok()?;
        at = end;
    }
    Some(TicketInput {
        op, root, completion, accepted, owner: strings[0], tool: strings[1],
        id: strings[2], target: target_present.then_some(strings[3]),
    })
}

fn ticket_error(error: &anyhow::Error) -> (u64, u64, u64) {
    let diagnostic = match error.to_string().as_str() {
        "request audit session or canonical tool metadata unavailable" => 45,
        "request unavailable to this scope" => 46,
        "reserved request identity unavailable" => 47,
        "reserved native read identity unavailable" => 48,
        "reserved request already exists; never redispatch" => 49,
        "reserved request unavailable; never redispatch" => 50,
        "reserved request already archived; never redispatch" => 51,
        "reserved request archive unavailable; never redispatch" => 52,
        "request identity entropy unavailable" => 53,
        "request audit state lock unavailable" => 54,
        "request audit root is not UTF-8" => 1,
        "invalid request audit root" => 2,
        "request audit ancestor is not searchable" => 17,
        _ => {
            let (tag, errno, missing) = retention_error(error);
            return (tag, errno, u64::from(missing));
        }
    };
    (diagnostic, 0, 0)
}

fn outer_reply(handle: u64, code: u32, body: &[u8]) -> (u32, Vec<u8>) {
    assert!(code < 0xfffffff0 || body.is_empty());
    if code < 0xfffffff0 { assert_eq!(code as usize, body.len()); }
    let mut out = vec![0; 32];
    out[..8].copy_from_slice(b"HRATWR01");
    word(&mut out, 8, handle);
    word(&mut out, 16, u64::from(code));
    word(&mut out, 24, body.len() as u64);
    out.extend_from_slice(body);
    (out.len() as u32, out)
}

pub(super) struct TicketService {
    roots: Vec<std::path::PathBuf>,
    tickets: HashMap<u64, RequestTicket>,
    generation: u64,
    activity: activity::Bridge,
    frames: u64,
    outer_refusals: u64,
    inner_refusals: u64,
    calls: [u64; 7],
    consumed: u64,
    eof_drops: u64,
    maximum_live: usize,
    observations: Vec<serde_json::Value>,
}

impl TicketService {
    pub(super) fn new(roots: Vec<std::path::PathBuf>) -> Self {
        assert!((1..=64).contains(&roots.len()));
        // Bind strings only. begin invokes open_store and hot_snapshot separately.
        Self {
            roots, tickets: HashMap::new(), generation: 0, activity: activity::Bridge::new(),
            frames: 0, outer_refusals: 0, inner_refusals: 0, calls: [0; 7],
            consumed: 0, eof_drops: 0, maximum_live: 0, observations: Vec::new(),
        }
    }

    fn activity_strong_handles(&self) -> u64 {
        // An observation of held original fields, never extra Arc clones.
        self.tickets.values().map(|ticket| {
            assert_eq!(Arc::strong_count(&ticket.active), 1);
            if let Some(pin) = &ticket._read_pin { assert_eq!(Arc::strong_count(pin), 1); }
            1 + u64::from(ticket._read_pin.is_some())
        }).sum()
    }

    fn outer_invalid(&mut self) -> (u32, Vec<u8>) {
        self.outer_refusals += 1;
        (u32::MAX, Vec::new())
    }

    pub(super) fn invoke(&mut self, raw: &[u8]) -> (u32, Vec<u8>) {
        self.frames += 1;
        if !(32..=8_388_608).contains(&raw.len()) || &raw[..8] != b"HRATWQ01"
            || number(raw, 24) != (raw.len() - 32) as u64
        { return self.outer_invalid(); }
        let op = number(raw, 8);
        let handle = number(raw, 16);
        let input = &raw[32..];
        if op == 2 {
            if handle != 0 || input.len() < 16 || &input[..8] != b"HRAAQ001"
                || !matches!(number(input, 8), 6 | 7 | 8 | 9 | 10)
            { return self.outer_invalid(); }
            let (code, mut reply) = self.activity.invoke(input);
            if code == 64 {
                assert_eq!(number(&reply, 56), 0, "external observer owns no strong Arc");
                word(&mut reply, 56, self.activity_strong_handles());
            } else { self.inner_refusals += 1; }
            return outer_reply(0, code, &reply);
        }
        if op != 1 || input.len() < 16 || &input[..8] != b"HRATQ001" {
            return self.outer_invalid();
        }
        let method = number(input, 8);
        if handle == 0 {
            if !(1..=3).contains(&method) { return self.outer_invalid(); }
        } else if !(4..=7).contains(&method) || !self.tickets.contains_key(&handle) {
            return self.outer_invalid();
        }
        // This is deliberately before full inner ABI admission: every shallow
        // admitted begin attempt consumes a generation, including INVALID.
        let attempt = if handle == 0 {
            let Some(next) = self.generation.checked_add(1) else {
                return outer_reply(0, u32::MAX - 1, &[]);
            };
            self.generation = next;
            next
        } else { handle };
        let Some(command) = ticket_input(input, handle != 0) else {
            self.inner_refusals += 1;
            self.observations.push(serde_json::json!({"frame":self.frames,
                "attempt":attempt,"method":method,"called_original":false,
                "inner_code":u32::MAX,"handle_before":handle,"handle_after":handle,
                "live":self.tickets.len()}));
            return outer_reply(handle, u32::MAX, &[]);
        };
        if method <= 3 && !(1..=self.roots.len() as u64).contains(&command.root) {
            self.inner_refusals += 1;
            self.observations.push(serde_json::json!({"frame":self.frames,
                "attempt":attempt,"method":method,"called_original":false,
                "inner_code":u32::MAX,"handle_before":handle,"handle_after":handle,
                "live":self.tickets.len(),"unbound_root_refused":true}));
            return outer_reply(handle, u32::MAX, &[]);
        }
        self.calls[method as usize - 1] += 1;
        let mut payload = Vec::new();
        let outcome: Result<()> = match command.op {
            1 => {
                let root = &self.roots[command.root as usize - 1];
                let result = if command.target.is_some() {
                    begin_with_read_at(root, command.owner, command.tool, command.target)
                } else { begin_at(root, command.owner, command.tool) };
                result.map(|ticket| {
                    payload = project_record(&ticket.record);
                    assert!(self.tickets.insert(attempt, ticket).is_none());
                })
            }
            2 | 3 => {
                let root = &self.roots[command.root as usize - 1];
                let identity = RequestIdentity {
                    request_id: command.id.to_owned(), owner: command.owner.to_owned(),
                    tool_name: command.tool.to_owned(), accepted_unix_ms: command.accepted,
                };
                let result = if command.op == 2 { begin_reserved_at(root, identity) }
                    else { begin_operation_reserved_at(root, identity) };
                result.map(|ticket| {
                    payload = project_record(&ticket.record);
                    assert!(self.tickets.insert(attempt, ticket).is_none());
                })
            }
            4 => {
                let ticket = self.tickets.remove(&handle).unwrap();
                self.consumed += 1;
                finish_sync(ticket, match command.completion {
                    0 => AuditCompletion::Unknown, 1 => AuditCompletion::Completed,
                    2 => AuditCompletion::Failed, _ => unreachable!(),
                })
            }
            5 => {
                drop(self.tickets.remove(&handle).unwrap());
                self.consumed += 1;
                Ok(())
            }
            6 => {
                let identity = self.tickets.get(&handle).unwrap().identity();
                payload = project_record(&Record {
                    request_id: identity.request_id, owner: identity.owner,
                    tool_name: identity.tool_name, accepted_unix_ms: identity.accepted_unix_ms,
                    state: DurableState::Unknown, elapsed_ms: None,
                });
                Ok(())
            }
            7 => {
                payload.extend_from_slice(self.tickets.get(&handle).unwrap().request_id().as_bytes());
                Ok(())
            }
            _ => unreachable!(),
        };
        self.maximum_live = self.maximum_live.max(self.tickets.len());
        let live = self.tickets.get(&attempt);
        let returned_handle = live.map_or(0, |_| attempt);
        let (diagnostic, errno, missing) = outcome.as_ref().err().map_or((0,0,0), ticket_error);
        if diagnostic != 0 { assert!(payload.is_empty()); }
        let mut reply = vec![0; 64];
        reply[..8].copy_from_slice(b"HRATR001");
        for (offset, value) in [(8,diagnostic),(16,errno),(24,missing),
            (32,u64::from(live.is_some())),(40,payload.len() as u64),
            (48,live.map_or(0, |ticket| u64::from(ticket.hot_present)))]
        { word(&mut reply, offset, value); }
        reply.extend_from_slice(&payload);
        self.observations.push(serde_json::json!({"frame":self.frames,"attempt":attempt,
            "method":method,"called_original":true,"inner_code":reply.len(),
            "diagnostic":diagnostic,"errno":errno,"not_found":missing,
            "handle_before":handle,"handle_after":returned_handle,"live":self.tickets.len()}));
        outer_reply(returned_handle, reply.len() as u32, &reply)
    }

    pub(super) fn finish(&mut self) -> serde_json::Value {
        let mut handles: Vec<u64> = self.tickets.keys().copied().collect();
        handles.sort_unstable();
        let mut dropped = Vec::new();
        for handle in handles {
            drop(self.tickets.remove(&handle).unwrap());
            dropped.push(handle);
            self.eof_drops += 1;
        }
        assert!(self.tickets.is_empty());
        let active_live = ACTIVE.get().map_or(0, |slot| slot.lock()
            .unwrap_or_else(|error| error.into_inner()).values()
            .filter(|value| value.strong_count() != 0).count());
        let pins_live = READ_PINS.get().map_or(0, |slot| slot.lock()
            .unwrap_or_else(|error| error.into_inner()).values()
            .flat_map(|values| values.iter())
            .filter(|value| value.strong_count() != 0).count());
        assert_eq!((active_live, pins_live), (0,0));
        self.activity.finish();
        assert!(index::observer_absent());
        serde_json::json!({"status":"PASS","frames":self.frames,
            "outer_refusals":self.outer_refusals,"inner_refusals":self.inner_refusals,
            "attempt_generation":self.generation,"original_ticket_calls":self.calls,
            "activity_calls":self.activity.calls(),"consumed":self.consumed,
            "eof_drops":self.eof_drops,"eof_drop_order":dropped,"maximum_live":self.maximum_live,
            "active_strong_after":active_live,"pin_strong_after":pins_live,
            "observations":self.observations,"real_storage_lock":true,
            "real_shared_activity":true,"real_archive_and_retention":true,
            "real_std_clocks":true,"real_system_entropy":true,
            "administrative_root_strings_only":true,"index_registry_absent":true,
            "scripted_storage_children":false,"group_commit_enabled":false,
            "public_admission_closed":false,"whole_runtime_replaced":false})
    }
}

pub(crate) struct AuditObservation {
	pub identity: RequestIdentity,
	pub state: &'static str,
	pub elapsed_ms: Option<u64>,
}

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

fn observation_at(root: &Path, owner: &str, id: &str) -> Result<AuditObservation> {
	optional_observation_at(root, owner, id)?
		.ok_or_else(|| anyhow!("request unavailable to this scope"))
}

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

// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
// Framing only; all storage/lock/Activity work executes unchanged original methods.
impl TicketService {
    pub(super) fn invoke_observation(&mut self, raw: &[u8]) -> (u32, Vec<u8>, u64) {
        let invalid = || (u32::MAX, Vec::new(), 0);
        if !(96..=8_388_608).contains(&raw.len()) || &raw[..8] != b"HRAOVQ01"
            || raw[64..96].iter().any(|v| *v != 0) {
            return invalid();
        }
        let op = number(raw, 8);
        let root = number(raw, 16);
        if !(1..=3).contains(&op) || !(1..=self.roots.len() as u64).contains(&root) {
            return invalid();
        }
        let owner_len = number(raw, 24);
        let id_len = number(raw, 32);
        let tool_len = number(raw, 40);
        let remaining = (raw.len() - 96) as u64;
        if owner_len > remaining || id_len > remaining - owner_len
            || tool_len != remaining - owner_len - id_len {
            return invalid();
        }
        let accepted = u128::from(number(raw, 48)) | (u128::from(number(raw, 56)) << 64);
        if op != 3 && (tool_len != 0 || accepted != 0) { return invalid(); }
        let owner_end = 96 + owner_len as usize;
        let id_end = owner_end + id_len as usize;
        let Ok(owner) = std::str::from_utf8(&raw[96..owner_end]) else { return invalid(); };
        let Ok(id) = std::str::from_utf8(&raw[owner_end..id_end]) else { return invalid(); };
        let Ok(tool) = std::str::from_utf8(&raw[id_end..]) else { return invalid(); };
        let root = &self.roots[root as usize - 1];
        use std::os::unix::ffi::OsStrExt;
        if root.as_os_str().as_bytes().len() > 1_048_528 {
            return (u32::MAX - 1, Vec::new(), 0);
        }
        let result: anyhow::Result<Option<AuditObservation>> = match op {
            1 => optional_observation_at(root, owner, id),
            2 => observation_at(root, owner, id).map(Some),
            3 => validate_identity_at(root, &RequestIdentity {
                request_id: id.to_owned(), owner: owner.to_owned(),
                tool_name: tool.to_owned(), accepted_unix_ms: accepted,
            }).map(|()| None),
            _ => unreachable!(),
        };
        let mut out = vec![0; 128];
        out[..8].copy_from_slice(b"HRAOVR01");
        word(&mut out, 8, op);
        match result {
            Err(error) => {
                let (diagnostic, errno, _) = if error.to_string() == "result admission unavailable" {
                    (55, 0, 0)
                } else { ticket_error(&error) };
                word(&mut out, 16, diagnostic);
                word(&mut out, 24, errno);
            }
            Ok(None) => { if op == 3 { word(&mut out, 32, 2); } }
            Ok(Some(value)) => {
                word(&mut out, 32, 1);
                word(&mut out, 40, match value.state {
                    "unknown" => 1, "accepted" => 2, "completed" => 3, "failed" => 4,
                    _ => unreachable!("original observation state"),
                });
                word(&mut out, 48, value.identity.accepted_unix_ms as u64);
                word(&mut out, 56, (value.identity.accepted_unix_ms >> 64) as u64);
                word(&mut out, 64, u64::from(value.elapsed_ms.is_some()));
                word(&mut out, 72, value.elapsed_ms.unwrap_or(0));
                for (index, text) in [
                    &value.identity.request_id, &value.identity.owner, &value.identity.tool_name,
                ].into_iter().enumerate() {
                    word(&mut out, 80 + index * 8, text.len() as u64);
                    out.extend_from_slice(text.as_bytes());
                }
            }
        }
        assert!((128..=320).contains(&out.len()), "original validated Record bounds");
        (out.len() as u32, out, op)
    }
}

use super::config::runtime_config;
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
#[path = "batch.rs"]
mod batch;
