// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
//! Real-file qualification framing; the original cache and Namespace methods remain unchanged.
use anyhow::{bail, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};

#[path = "original_namespace.rs"]
mod namespace_version;
mod audit {
	use super::*;
	use anyhow::anyhow;
	use serde::{Deserialize, Serialize};
	use std::collections::VecDeque;
	use std::sync::{Mutex, OnceLock};
	include!("original_policy.rs");

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
	pub(super) fn invoke(raw: &[u8], directories: &[File], calls: &mut [u64; 7]) -> (u32, Vec<u8>) {
		let invalid = || (u32::MAX, Vec::new());
		if raw.len() < 64 || raw.len() > 1048576 || &raw[..8] != b"HRACQ001" {
			return invalid();
		}
		let op = number(raw, 8);
		let dir = number(raw, 16);
		let count = number(raw, 40);
		let before = number(raw, 48);
		if op > 6
			|| op == 3
			|| number(raw, 24) != 0
			|| number(raw, 32) != 0
			|| number(raw, 56) != 0
			|| count > 512
		{
			return invalid();
		}
		if (op == 0 || op == 5) && dir != 0 {
			return invalid();
		}
		if (op == 1 || op == 2 || op == 4) && !(1..=17).contains(&dir) {
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
		calls[op as usize] += 1;
		let outcome: Result<u64> = match op {
			0 => Ok(inspect_cache().2),
			1 => cache_hot_owned(&directories[dir as usize - 1], records).map(|_| 0),
			2 => hot_snapshot_cached(&directories[dir as usize - 1]).map(u64::from),
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
				let (diagnostic, errno, missing) =
					if let Some(io) = error.downcast_ref::<std::io::Error>() {
						(
							23,
							io.raw_os_error().map_or(0, |n| n as u64),
							io.kind() == std::io::ErrorKind::NotFound,
						)
					} else {
						match error.to_string().as_str() {
							"private request audit directory refused" => (16, 0, false),
							"request hot cache unavailable" => (43, 0, false),
							_ => panic!("unclassified original error: {error:#}"),
						}
					};
				word(&mut out, 8, diagnostic);
				word(&mut out, 16, errno);
				word(&mut out, 24, u64::from(missing));
			}
		}
		let (count, initialized, _) = inspect_cache();
		word(&mut out, 48, count);
		word(&mut out, 56, initialized);
		(out.len() as u32, out)
	}
}

fn main() -> Result<()> {
	let args: Vec<_> = std::env::args_os().collect();
	if args.len() != 18 {
		bail!("seventeen administrator-owned descriptor fixtures required");
	}
	let mut directories = Vec::new();
	for name in &args[1..] {
		let name = std::ffi::CString::new(name.as_os_str().as_bytes())?;
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
		directories.push(unsafe { File::from_raw_fd(fd) });
	}
	let mut input = std::io::stdin().lock();
	let mut output = std::io::stdout().lock();
	let mut frames = 0_u64;
	let mut calls = [0_u64; 7];
	loop {
		let mut header = [0; 8];
		loop {
			match input.read(&mut header[..1]) {
				Ok(0) => {
					drop(directories);
					eprintln!(
						"{}",
						serde_json::json!({"status":"PASS","frames":frames,"calls":calls,"borrowed_files_released":true,"real_filesystem_effects":true,"child_contracts_scripted":false,"full_original_namespace_module":true,"whole_runtime_replaced":false})
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
		if length > 1048576 {
			bail!("private frame capacity");
		}
		let mut raw = vec![0; length as usize];
		input.read_exact(&mut raw)?;
		frames += 1;
		let (code, reply) = audit::invoke(&raw, &directories, &mut calls);
		output.write_all(&code.to_le_bytes())?;
		output.write_all(&reply)?;
		output.flush()?;
	}
}
