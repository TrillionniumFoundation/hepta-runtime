// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Qualification framing around unchanged audit record equality, removal and recovery.
use std::io;
use std::os::fd::FromRawFd;
include!("original_remove.rs");

fn word(out: &mut [u8], at: usize, value: u64) {
	out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn number(raw: &[u8], at: usize) -> u64 {
	u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}

fn typed_record(wire: &[u8]) -> Option<Record> {
	let raw = &wire[24..];
	if &raw[..8] != b"HRAJJ001"
		|| number(raw, 8) != 1
		|| number(raw, 16) > 1
		|| number(raw, 40) > 2
		|| number(raw, 56) != 0
		|| (number(raw, 16) == 0 && number(raw, 48) != 0)
		|| raw[112..256].iter().any(|byte| *byte != 0)
	{
		return None;
	}
	let mut at = 256usize;
	let mut strings = Vec::new();
	for slot in 0..3 {
		let start = usize::try_from(number(raw, 64 + slot * 16)).ok()?;
		let length = usize::try_from(number(raw, 72 + slot * 16)).ok()?;
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
		state: match number(raw, 40) {
			0 => DurableState::Unknown,
			1 => DurableState::Completed,
			2 => DurableState::Failed,
			_ => unreachable!(),
		},
		accepted_unix_ms: u128::from(number(raw, 24)) | (u128::from(number(raw, 32)) << 64),
		elapsed_ms: (number(raw, 16) == 1).then(|| number(raw, 48)),
	})
}

fn classify(error: &anyhow::Error) -> (u64, u64) {
	if error.downcast_ref::<serde_json::Error>().is_some() {
		return (24, 0);
	}
	if error.downcast_ref::<std::str::Utf8Error>().is_some() {
		return (28, 0);
	}
	if let Some(error) = error.downcast_ref::<io::Error>() {
		return (23, error.raw_os_error().unwrap() as u64);
	}
	let code = match error.to_string().as_str() {
		"invalid request metadata filename" => 26,
		"request hot cache binding changed" => 31,
		"unexpected private audit staging entry" | "unexpected private audit staging identity" => {
			27
		}
		"private request audit inode refused" => 17,
		"audit staging inode refused" => 18,
		"audit staging hard-link binding refused" => 19,
		"request audit metadata size refused" => 8,
		"request audit metadata identity refused" => 25,
		other => panic!("unclassified original refusal: {other}"),
	};
	(code, 0)
}

fn invoke(directory: &File, wire: &[u8]) -> (u32, Vec<u8>) {
	if wire.len() < 280 || wire.len() > 1 << 20 || &wire[..8] != b"HRAXQ001" {
		return (u32::MAX, vec![]);
	}
	let sync_directory = number(wire, 8);
	if sync_directory > 1 || number(wire, 16) != (wire.len() - 24) as u64 {
		return (u32::MAX, vec![]);
	}
	let Some(record) = typed_record(wire) else {
		return (u32::MAX, vec![]);
	};
	let mut output = vec![0; 32];
	output[..8].copy_from_slice(b"HRAXR001");
	if let Err(error) = remove_record(directory, &record, sync_directory == 1) {
		let (diagnostic, errno) = classify(&error);
		word(&mut output, 8, diagnostic);
		word(&mut output, 16, errno);
	}
	(output.len() as u32, output)
}

fn main() -> io::Result<()> {
	let args: Vec<_> = std::env::args_os().collect();
	assert_eq!(args.len(), 2);
	use std::os::unix::ffi::OsStrExt;
	let path = std::ffi::CString::new(args[1].as_os_str().as_bytes()).unwrap();
	let fd = unsafe {
		libc::open(
			path.as_ptr(),
			libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
		)
	};
	if fd < 0 {
		return Err(io::Error::last_os_error());
	}
	let directory = unsafe { File::from_raw_fd(fd) };
	let mut input = io::stdin().lock();
	let mut stdout = io::BufWriter::new(io::stdout().lock());
	loop {
		let mut header = [0; 8];
		let first = input.read(&mut header[..1])?;
		if first == 0 {
			break;
		}
		input.read_exact(&mut header[1..])?;
		let size = u64::from_le_bytes(header) as usize;
		assert!(size <= 1 << 20);
		let mut wire = vec![0; size];
		input.read_exact(&mut wire)?;
		let (code, bytes) = invoke(&directory, &wire);
		stdout.write_all(&code.to_le_bytes())?;
		stdout.write_all(&bytes)?;
		stdout.flush()?;
	}
	Ok(())
}
