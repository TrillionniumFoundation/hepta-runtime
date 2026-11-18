// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
const MAX_RESULT_BYTES: usize = 64 * 1024;
const MAX_RECORD_BYTES: usize = 96 * 1024;
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ResultState {
	Unknown,
	Stored,
	Overflow,
	RefusedDto,
	NotCompleted,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
	request_id: String,
	owner: String,
	tool_name: String,
	accepted_unix_ms: u128,
	policy_binding: String,
	state: ResultState,
	payload_base64: Option<String>,
	payload_bytes: Option<usize>,
	payload_sha256: Option<String>,
}
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
fn valid_id(value: &str) -> bool {
	value.len() == 64
		&& value
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_tool(value: &str) -> bool {
	matches!(value, "host_list" | "host_health" | "effective_config")
}
fn digest(data: &[u8]) -> String {
	Sha256::digest(data)
		.iter()
		.map(|b| format!("{b:02x}"))
		.collect()
}
fn base64(data: &[u8]) -> String {
	const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
	for row in data.chunks(3) {
		let n = ((row[0] as u32) << 16)
			| ((row.get(1).copied().unwrap_or(0) as u32) << 8)
			| row.get(2).copied().unwrap_or(0) as u32;
		out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
		out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
		out.push(if row.len() > 1 {
			ALPHABET[((n >> 6) & 63) as usize] as char
		} else {
			'='
		});
		out.push(if row.len() > 2 {
			ALPHABET[(n & 63) as usize] as char
		} else {
			'='
		});
	}
	out
}
fn unbase64(text: &str) -> Result<Vec<u8>> {
	if text.len() > MAX_RESULT_BYTES.div_ceil(3) * 4 || !text.len().is_multiple_of(4) {
		bail!("retained bytes refused");
	}
	fn value(b: u8) -> Option<u32> {
		match b {
			b'A'..=b'Z' => Some((b - b'A') as u32),
			b'a'..=b'z' => Some((b - b'a' + 26) as u32),
			b'0'..=b'9' => Some((b - b'0' + 52) as u32),
			b'+' => Some(62),
			b'/' => Some(63),
			_ => None,
		}
	}
	let mut output = Vec::new();
	for row in text.as_bytes().as_chunks::<4>().0 {
		let a = value(row[0]).ok_or_else(|| anyhow!("retained bytes refused"))?;
		let b = value(row[1]).ok_or_else(|| anyhow!("retained bytes refused"))?;
		let c = if row[2] == b'=' {
			0
		} else {
			value(row[2]).ok_or_else(|| anyhow!("retained bytes refused"))?
		};
		let d = if row[3] == b'=' {
			0
		} else {
			value(row[3]).ok_or_else(|| anyhow!("retained bytes refused"))?
		};
		let n = (a << 18) | (b << 12) | (c << 6) | d;
		output.push((n >> 16) as u8);
		if row[2] != b'=' {
			output.push((n >> 8) as u8);
		}
		if row[3] != b'=' {
			output.push(n as u8);
		}
	}
	if output.len() > MAX_RESULT_BYTES || base64(&output) != text {
		bail!("retained bytes refused");
	}
	Ok(output)
}

// The descriptor, staging and inode checks precede these original byte checks.
fn validate(filename: &str, bytes: &[u8]) -> Result<Record> {
	let id = filename
		.strip_suffix(".json")
		.filter(|id| valid_id(id))
		.ok_or_else(|| anyhow!("invalid retained result filename"))?;
	let _ = id;
	if bytes.len() > MAX_RECORD_BYTES {
		bail!("request audit metadata size refused");
	}
	let record: Record = serde_json::from_slice(&bytes)?;
	if !valid_id(&record.request_id)
		|| !valid_id(&record.owner)
		|| !valid_tool(&record.tool_name)
		|| !valid_id(&record.policy_binding)
		|| filename != format!("{}.json", record.request_id)
	{
		bail!("request audit metadata identity refused");
	}
	match record.state {
		ResultState::Stored => {
			let payload = unbase64(
				record
					.payload_base64
					.as_deref()
					.ok_or_else(|| anyhow!("retained result refused"))?,
			)?;
			if record.payload_bytes != Some(payload.len())
				|| record.payload_sha256.as_deref() != Some(digest(&payload).as_str())
			{
				bail!("retained result integrity refused");
			}
		}
		_ if record.payload_base64.is_some()
			|| record.payload_bytes.is_some()
			|| record.payload_sha256.is_some() =>
		{
			bail!("retained result state refused")
		}
		_ => {}
	}
	Ok(record)
}

use std::fs::File;
use std::io::{Read, Write};
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
fn is_not_found(error: &anyhow::Error) -> bool {
	error
		.downcast_ref::<std::io::Error>()
		.is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}
fn is_absent(directory: &File, component: &str) -> Result<bool> {
	match open_at(directory, component, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
		Ok(_) => Ok(false),
		Err(error) if is_not_found(&error) => Ok(true),
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
fn read_record(directory: &File, filename: &str) -> Result<Record> {
	let id = filename
		.strip_suffix(".json")
		.filter(|id| valid_id(id))
		.ok_or_else(|| anyhow!("invalid retained result filename"))?;
	cleanup_target_staging(directory, id)?;
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
		|| !valid_id(&record.policy_binding)
		|| filename != format!("{}.json", record.request_id)
	{
		bail!("request audit metadata identity refused");
	}
	match record.state {
		ResultState::Stored => {
			let payload = unbase64(
				record
					.payload_base64
					.as_deref()
					.ok_or_else(|| anyhow!("retained result refused"))?,
			)?;
			if record.payload_bytes != Some(payload.len())
				|| record.payload_sha256.as_deref() != Some(digest(&payload).as_str())
			{
				bail!("retained result integrity refused");
			}
		}
		_ if record.payload_base64.is_some()
			|| record.payload_bytes.is_some()
			|| record.payload_sha256.is_some() =>
		{
			bail!("retained result state refused")
		}
		_ => {}
	}
	Ok(record)
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
fn cleanup_target_staging(directory: &File, id: &str) -> Result<()> {
	let filename = format!(".{id}-{id}.tmp");
	if is_absent(directory, &filename)? {
		return Ok(());
	}
	cleanup_staging(directory, &filename)
}
fn save_inner(directory: &File, record: &Record, replacing: bool) -> Result<()> {
	use std::os::fd::AsRawFd;
	private_directory(directory)?;
	cleanup_target_staging(directory, &record.request_id)?;
	let filename = format!("{}.json", record.request_id);
	if replacing {
		let existing = trace::measure("result_read_existing", 1, None, || {
			read_record(directory, &filename)
		})?;
		if existing.owner != record.owner
			|| existing.tool_name != record.tool_name
			|| existing.accepted_unix_ms != record.accepted_unix_ms
			|| existing.policy_binding != record.policy_binding
		{
			bail!("request audit receipt binding changed");
		}
		if existing.state != ResultState::Unknown {
			if existing != *record {
				bail!("completed original result is immutable");
			}
			return Ok(());
		}
	}
	let bytes = serde_json::to_vec(record)?;
	if bytes.len() > MAX_RECORD_BYTES {
		bail!("request audit record size refused");
	}
	let temporary = format!(".{}-{}.tmp", record.request_id, record.request_id);
	let mut file = trace::measure("result_open_temporary", 1, None, || {
		open_at(
			directory,
			&temporary,
			libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
			0o600,
		)
	})?;
	validate_file(&file)?;
	let persisted = (|| -> Result<()> {
		trace::measure("result_file_write", 1, None, || {
			file.write_all(&bytes)?;
			Ok(())
		})?;
		trace::measure("result_file_sync", 1, None, || {
			file.sync_all()?;
			Ok(())
		})?;
		drop(file);
		let temp = name(&temporary)?;
		let target = name(&filename)?;
		let publication = trace::Span::new("result_publish", 1, None);
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
		publication.record(None);
		trace::measure("result_directory_sync", 1, None, || {
			directory.sync_all()?;
			Ok(())
		})?;
		Ok(())
	})();
	if persisted.is_err() {
		if let Ok(temp) = name(&temporary) {
			unsafe { libc::unlinkat(directory.as_raw_fd(), temp.as_ptr(), 0) };
		}
	}
	persisted
}
