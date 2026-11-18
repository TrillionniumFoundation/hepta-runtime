// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
//! Qualification framing around unchanged archive_stamp and the full Namespace owner.
use anyhow::{bail, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};

#[path = "original_namespace.rs"]
mod namespace_version;
include!("original_stamp.rs");

fn get(raw: &[u8], at: usize) -> u64 {
	let mut word = [0; 8];
	word.copy_from_slice(&raw[at..at + 8]);
	u64::from_le_bytes(word)
}
fn put(raw: &mut [u8], at: usize, value: u64) {
	raw[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn main() -> Result<()> {
	let args: Vec<_> = std::env::args_os().collect();
	if args.len() != 2 {
		bail!("one administrator-owned descriptor fixture required");
	}
	let name = std::ffi::CString::new(args[1].as_os_str().as_bytes())?;
	let fd = unsafe {
		libc::openat(
			libc::AT_FDCWD,
			name.as_ptr(),
			libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW,
		)
	};
	if fd < 0 {
		return Err(std::io::Error::last_os_error().into());
	}
	let directory = unsafe { File::from_raw_fd(fd) };
	let mut input = std::io::stdin().lock();
	let mut output = std::io::stdout().lock();
	let mut frames = 0_u64;
	let mut calls = 0_u64;
	let mut errors = Vec::new();
	loop {
		let mut header = [0; 8];
		loop {
			match input.read(&mut header[..1]) {
				Ok(0) => {
					drop(directory);
					eprintln!(
						"{}",
						serde_json::json!({"status":"PASS","frames":frames,"original_archive_stamp_calls":calls,
							"errors":errors,"borrowed_file_released":true,"full_original_namespace_module":true,
							"whole_runtime_replaced":false,"production_activated":false})
					);
					return Ok(());
				}
				Ok(1) => break,
				Ok(_) => unreachable!(),
				Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
				Err(error) => return Err(error.into()),
			}
		}
		input.read_exact(&mut header[1..])?;
		let length = u64::from_le_bytes(header);
		if length > 4096 {
			bail!("private frame capacity");
		}
		let mut request = vec![0; length as usize];
		input.read_exact(&mut request)?;
		frames += 1;
		if request.len() != 16 || &request[..8] != b"HRASQ001" || get(&request, 8) != 1 {
			output.write_all(&u32::MAX.to_le_bytes())?;
			output.flush()?;
			continue;
		}
		calls += 1;
		let mut reply = vec![0; 48];
		reply[..8].copy_from_slice(b"HRACC001");
		match audit::observed_stamp(&directory) {
			Ok(stamp) => {
				put(&mut reply, 32, 112);
				reply.extend(stamp);
			}
			Err(error) => {
				let (diagnostic, errno, missing) =
					if let Some(io) = error.downcast_ref::<std::io::Error>() {
						(
							23,
							io.raw_os_error().map_or(0, |n| n as u64),
							io.kind() == std::io::ErrorKind::NotFound,
						)
					} else if error.to_string() == "private request audit directory refused" {
						(16, 0, false)
					} else {
						(255, 0, false)
					};
				put(&mut reply, 8, diagnostic);
				put(&mut reply, 16, errno);
				put(&mut reply, 24, u64::from(missing));
				errors.push(error.to_string());
			}
		}
		output.write_all(&(reply.len() as u32).to_le_bytes())?;
		output.write_all(&reply)?;
		output.flush()?;
	}
}
