// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Qualification framing around unchanged archive reads and the real cache.
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
include!("original_metadata.rs");

fn get(raw: &[u8], at: usize) -> u64 {
	let mut word = [0; 8];
	word.copy_from_slice(&raw[at..at + 8]);
	u64::from_le_bytes(word)
}
fn put(raw: &mut [u8], at: usize, value: u64) {
	raw[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn diagnostic(error: &anyhow::Error) -> (u64, u64) {
	if let Some(error) = error.downcast_ref::<std::io::Error>() {
		return (23, error.raw_os_error().map_or(0, |value| value as u64));
	}
	if error.downcast_ref::<serde_json::Error>().is_some() {
		return (21, 0);
	}
	let code = match error.to_string().as_str() {
		"private request audit inode refused" => 16,
		"result archive anchor size refused" => 17,
		"result archive anchor changed during read" => 18,
		"result anchor cache unavailable" => 19,
		"result archive anchor bytes changed; history never repaired automatically" => 20,
		"result archive anchor schema refused" => 22,
		"result archive marker size refused" => 24,
		"result archive marker schema refused" => 25,
		_ => 255,
	};
	(code, 0)
}
fn project_anchor(anchor: &ArchiveAnchor) -> Vec<u8> {
	let mut out = vec![0; 256];
	out[..8].copy_from_slice(b"HRSTJ001");
	put(&mut out, 8, 2);
	put(&mut out, 24, u64::from(anchor.schema));
	put(&mut out, 56, anchor.shards.len() as u64);
	for (slot, identity) in [&anchor.root, &anchor.legacy, &anchor.store, &anchor.archive]
		.into_iter()
		.enumerate()
	{
		put(&mut out, 64 + slot * 16, identity.device);
		put(&mut out, 72 + slot * 16, identity.inode);
	}
	for identity in &anchor.shards {
		out.extend_from_slice(&identity.device.to_le_bytes());
		out.extend_from_slice(&identity.inode.to_le_bytes());
	}
	out
}
fn project_marker(marker: &ArchiveMarker) -> Vec<u8> {
	let mut out = vec![0; 256];
	out[..8].copy_from_slice(b"HRSTJ001");
	put(&mut out, 8, 3);
	put(&mut out, 24, u64::from(marker.schema));
	put(&mut out, 64, 256);
	put(&mut out, 72, marker.anchor_sha256.len() as u64);
	out.extend_from_slice(marker.anchor_sha256.as_bytes());
	out
}
fn invoke(directory: &File, raw: &[u8]) -> (u32, Vec<u8>) {
	if raw.len() != 24
		|| &raw[..8] != b"HRAMQ001"
		|| get(raw, 16) != 0
		|| !(1..=2).contains(&get(raw, 8))
	{
		return (u32::MAX, Vec::new());
	}
	let operation = get(raw, 8);
	let result = (|| -> Result<Option<(Vec<u8>, Vec<u8>)>> {
		if operation == 1 {
			let cached = read_anchor(directory)?;
			Ok(Some((
				cached.sha256.as_bytes().to_vec(),
				project_anchor(&cached.anchor),
			)))
		} else {
			Ok(read_archive_marker(directory)?.map(|marker| (Vec::new(), project_marker(&marker))))
		}
	})();
	let mut out = vec![0; 64];
	out[..8].copy_from_slice(b"HRAMR001");
	put(&mut out, 24, operation);
	match result {
		Ok(Some((hash, projection))) => {
			put(&mut out, 32, 1);
			put(&mut out, 40, projection.len() as u64);
			put(&mut out, 48, hash.len() as u64);
			out.extend_from_slice(&hash);
			out.extend_from_slice(&projection);
		}
		Ok(None) => {}
		Err(error) => {
			let (code, errno) = diagnostic(&error);
			put(&mut out, 8, code);
			put(&mut out, 16, errno);
		}
	}
	if let Some(cache) = ANCHOR_CACHE.get() {
		if let Ok(cache) = cache.lock() {
			put(&mut out, 56, cache.len() as u64);
		}
	}
	(out.len() as u32, out)
}
fn main() -> Result<()> {
	let path = std::env::args_os()
		.nth(1)
		.ok_or_else(|| anyhow!("private directory argument"))?;
	let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
	let descriptor = unsafe {
		libc::open(
			path.as_ptr(),
			libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
		)
	};
	if descriptor < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	let directory = unsafe { File::from_raw_fd(descriptor) };
	let mut input = std::io::stdin().lock();
	let mut output = std::io::stdout().lock();
	loop {
		let mut length = [0; 8];
		if input.read(&mut length[..1])? == 0 {
			break;
		}
		input.read_exact(&mut length[1..])?;
		let length = u64::from_le_bytes(length);
		if length > 1 << 20 {
			bail!("private frame capacity");
		}
		let mut raw = vec![0; length as usize];
		input.read_exact(&mut raw)?;
		let (code, bytes) = invoke(&directory, &raw);
		output.write_all(&code.to_le_bytes())?;
		output.write_all(&bytes)?;
		output.flush()?;
	}
	Ok(())
}
