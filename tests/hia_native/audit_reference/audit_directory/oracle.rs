// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Qualification framing around original directory functions and real File leases.
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
include!("original_directory.rs");

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
	let code = match error.to_string().as_str() {
		"request audit root is not UTF-8" => 1,
		"invalid request audit root" => 2,
		"invalid private metadata component" => 3,
		"private request audit directory refused" => 16,
		"request audit ancestor is not searchable" => 17,
		_ => 255,
	};
	(code, 0)
}

struct Owner {
	file: Option<File>,
	generation: u64,
}

impl Owner {
	fn invoke(&mut self, raw: &[u8]) -> (u32, Vec<u8>) {
		let invalid = (u32::MAX, Vec::new());
		if raw.len() < 48 || raw.len() > 1 << 20 || &raw[..8] != b"HRADQ001" {
			return invalid;
		}
		let operation = get(raw, 8);
		let private = get(raw, 16);
		let lease = get(raw, 24);
		if !(1..=4).contains(&operation)
			|| private > 1
			|| (operation == 4 && private != 0)
			|| get(raw, 32) != (raw.len() - 48) as u64
			|| get(raw, 40) != 0
			|| (operation <= 2
				&& (lease != 0 || self.file.is_some() || self.generation == u64::MAX))
			|| (operation >= 3
				&& (raw.len() != 48
					|| self.file.is_none()
					|| lease != self.generation
					|| lease == 0))
		{
			return invalid;
		}
		let mut out = vec![0; 64];
		out[..8].copy_from_slice(b"HRADR001");
		let result = (|| -> Result<Option<DirectoryIdentity>> {
			if operation == 4 {
				drop(self.file.take());
				return Ok(None);
			}
			if operation == 3 {
				let file = self
					.file
					.as_ref()
					.ok_or_else(|| anyhow!("missing private lease"))?;
				return Ok(Some(directory_identity(file, private == 1)?));
			}
			let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(raw[48..].to_vec()));
			let file = if operation == 1 {
				audit_root(&path)?
			} else {
				open_store(&path)?
			};
			let identity = if private == 1 {
				None
			} else {
				Some(directory_identity(&file, false)?)
			};
			self.generation += 1;
			self.file = Some(file);
			Ok(identity)
		})();
		match result {
			Ok(Some(identity)) => {
				put(&mut out, 32, identity.device);
				put(&mut out, 40, identity.inode);
			}
			Ok(None) => {}
			Err(error) => {
				let (code, errno) = diagnostic(&error);
				put(&mut out, 8, code);
				put(&mut out, 16, errno);
			}
		}
		if self.file.is_some() {
			put(&mut out, 24, self.generation);
		}
		(64, out)
	}
}

fn main() -> Result<()> {
	let mut input = std::io::stdin().lock();
	let mut output = std::io::stdout().lock();
	let mut owner = Owner {
		file: None,
		generation: 0,
	};
	loop {
		let mut length = [0; 8];
		let count = input.read(&mut length[..1])?;
		if count == 0 {
			break;
		}
		input.read_exact(&mut length[1..])?;
		let length = u64::from_le_bytes(length);
		if length > 1 << 20 {
			bail!("private frame capacity");
		}
		let mut raw = vec![0; length as usize];
		input.read_exact(&mut raw)?;
		let (code, bytes) = owner.invoke(&raw);
		output.write_all(&code.to_le_bytes())?;
		output.write_all(&bytes)?;
		output.flush()?;
	}
	Ok(())
}
