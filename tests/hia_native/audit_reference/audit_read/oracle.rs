// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Qualification framing around unchanged original audit record reads and staging recovery.
use std::io;
use std::os::fd::FromRawFd;
include!("original_read.rs");

fn word(out: &mut [u8], at: usize, value: u64) {
	out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn project(value: &Record) -> Vec<u8> {
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
	if wire.len() < 24 || wire.len() > 1 << 20 || &wire[..8] != b"HRARQ001" {
		return (u32::MAX, vec![]);
	}
	let operation = u64::from_le_bytes(wire[8..16].try_into().unwrap());
	let length = u64::from_le_bytes(wire[16..24].try_into().unwrap());
	if !(1..=2).contains(&operation) || length != (wire.len() - 24) as u64 {
		return (u32::MAX, vec![]);
	}
	let name = match std::str::from_utf8(&wire[24..]) {
		Ok(value) => value,
		Err(_) => return (u32::MAX, vec![]),
	};
	let mut output = vec![0; 32];
	output[..8].copy_from_slice(b"HRARR001");
	let result = if operation == 1 {
		read_record(directory, name).map(Some)
	} else {
		cleanup_staging(directory, name).map(|()| None)
	};
	match result {
		Ok(Some(value)) => {
			let raw = project(&value);
			word(&mut output, 24, raw.len() as u64);
			output.extend(raw);
		}
		Ok(None) => {}
		Err(error) => {
			let (diagnostic, errno) = classify(&error);
			word(&mut output, 8, diagnostic);
			word(&mut output, 16, errno);
		}
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
