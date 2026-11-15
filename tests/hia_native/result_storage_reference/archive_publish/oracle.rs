// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Qualification projection of the original retained-result owner.
include!("original_publish.rs");
use std::os::unix::fs::OpenOptionsExt;

fn word(raw: &[u8], at: usize) -> Option<u64> {
	Some(u64::from_le_bytes(raw.get(at..at + 8)?.try_into().ok()?))
}
fn response(directory: &File, raw: &[u8]) -> Option<Vec<u8>> {
	if raw.len() < 24
		|| raw.len() > 98328
		|| raw.get(..8)? != b"HRAPQ001"
		|| word(raw, 16)? != (raw.len() - 24) as u64
	{
		return None;
	}
	let operation = word(raw, 8)?;
	let result = match operation {
		1 => {
			let anchor: ArchiveAnchor = serde_json::from_slice(&raw[24..]).ok()?;
			publish_anchor(directory, &anchor)
		}
		2 => {
			let expected = std::str::from_utf8(&raw[24..]).ok()?;
			if !valid_id(expected) {
				return None;
			}
			ensure_archive_marker(directory, expected)
		}
		_ => return None,
	};
	let (diagnostic, errno) = match result {
		Ok(()) => (0, 0),
		Err(error) => {
			if let Some(io) = error.downcast_ref::<std::io::Error>() {
				if let Some(errno) = io.raw_os_error() {
					(23, errno as u64)
				} else if io.kind() == std::io::ErrorKind::UnexpectedEof {
					(27, 0)
				} else if io.kind() == std::io::ErrorKind::WriteZero {
					(28, 0)
				} else {
					(255, 0)
				}
			} else if error.downcast_ref::<serde_json::Error>().is_some() {
				(21, 0)
			} else {
				let diagnostic = match error.to_string().as_str() {
					"private request audit inode refused" => 16,
					"result archive anchor size refused" => 22,
					"result archive marker size refused" => 24,
					"result archive marker schema refused" => 25,
					"result archive marker binding changed" => 29,
					"result state unavailable" => 30,
					_ => 255,
				};
				(diagnostic, 0)
			}
		}
	};
	let mut bytes = b"HRAPR001".to_vec();
	for value in [diagnostic, errno, operation, 0, 0] {
		bytes.extend(value.to_le_bytes());
	}
	Some(bytes)
}
fn run() -> Result<()> {
	let root = std::env::args_os()
		.nth(1)
		.ok_or_else(|| anyhow!("directory required"))?;
	let directory = std::fs::OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
		.open(root)?;
	let mut input = std::io::stdin().lock();
	let mut output = std::io::stdout().lock();
	loop {
		let mut header = [0u8; 8];
		loop {
			match input.read(&mut header[..1]) {
				Ok(0) => return Ok(()),
				Ok(_) => break,
				Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
				Err(error) => return Err(error.into()),
			}
		}
		input.read_exact(&mut header[1..])?;
		let length = u64::from_le_bytes(header);
		if length > 1048576 {
			bail!("private frame too large");
		}
		let mut raw = vec![0; length as usize];
		input.read_exact(&mut raw)?;
		if let Some(bytes) = response(&directory, &raw) {
			output.write_all(&(bytes.len() as u32).to_le_bytes())?;
			output.write_all(&bytes)?;
		} else {
			output.write_all(&u32::MAX.to_le_bytes())?;
		}
		output.flush()?;
	}
}
fn main() {
	if run().is_err() {
		std::process::exit(74);
	}
}
