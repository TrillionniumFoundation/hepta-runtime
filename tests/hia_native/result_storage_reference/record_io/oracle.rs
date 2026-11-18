// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Qualification framing around unchanged original descriptor-relative storage.
use std::io;
use std::os::fd::FromRawFd;
include!("original_io.rs");

fn word(out: &mut [u8], at: usize, value: u64) {
	out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn string(out: &mut Vec<u8>, slot: usize, value: Option<&str>) {
	if let Some(value) = value {
		let at = out.len();
		word(out, 64 + slot * 16, at as u64);
		word(out, 72 + slot * 16, value.len() as u64);
		out.extend_from_slice(value.as_bytes());
	}
}

fn project(kind: u64, raw: &[u8]) -> Result<Vec<u8>, serde_json::Error> {
	let mut out = vec![0; 256];
	out[..8].copy_from_slice(b"HRSTJ001");
	word(&mut out, 8, kind);
	match kind {
		1 => {
			let value: Record = serde_json::from_slice(raw)?;
			let flags = u64::from(value.payload_base64.is_some())
				| (u64::from(value.payload_bytes.is_some()) << 1)
				| (u64::from(value.payload_sha256.is_some()) << 2);
			word(&mut out, 16, flags);
			word(&mut out, 24, value.accepted_unix_ms as u64);
			word(&mut out, 32, (value.accepted_unix_ms >> 64) as u64);
			word(
				&mut out,
				40,
				match value.state {
					ResultState::Unknown => 0,
					ResultState::Stored => 1,
					ResultState::Overflow => 2,
					ResultState::RefusedDto => 3,
					ResultState::NotCompleted => 4,
				},
			);
			word(&mut out, 48, value.payload_bytes.unwrap_or(0) as u64);
			for (slot, text) in [
				Some(value.request_id.as_str()),
				Some(value.owner.as_str()),
				Some(value.tool_name.as_str()),
				Some(value.policy_binding.as_str()),
				value.payload_base64.as_deref(),
				value.payload_sha256.as_deref(),
			]
			.into_iter()
			.enumerate()
			{
				string(&mut out, slot, text);
			}
		}
		2 => {
			let value: ArchiveAnchor = serde_json::from_slice(raw)?;
			word(&mut out, 24, value.schema as u64);
			word(&mut out, 56, value.shards.len() as u64);
			for (slot, directory) in [&value.root, &value.legacy, &value.store, &value.archive]
				.into_iter()
				.enumerate()
			{
				word(&mut out, 64 + slot * 16, directory.device);
				word(&mut out, 72 + slot * 16, directory.inode);
			}
			for directory in value.shards {
				out.extend_from_slice(&directory.device.to_le_bytes());
				out.extend_from_slice(&directory.inode.to_le_bytes());
			}
		}
		3 => {
			let value: ArchiveMarker = serde_json::from_slice(raw)?;
			word(&mut out, 24, value.schema as u64);
			string(&mut out, 0, Some(&value.anchor_sha256));
		}
		_ => unreachable!(),
	}
	Ok(out)
}

mod trace {
	use anyhow::Result;
	pub struct Span;
	impl Span {
		pub fn new(_: &'static str, _: usize, _: Option<usize>) -> Self {
			Self
		}
		pub fn record(&self, _: Option<&anyhow::Error>) {}
	}
	pub fn measure<T>(
		_: &'static str,
		_: usize,
		_: Option<usize>,
		run: impl FnOnce() -> Result<T>,
	) -> Result<T> {
		run()
	}
}

fn classify(error: &anyhow::Error) -> (u64, u64) {
	if error.downcast_ref::<serde_json::Error>().is_some() {
		return (2, 0);
	}
	if let Some(error) = error.downcast_ref::<io::Error>() {
		if error.kind() == io::ErrorKind::WriteZero {
			return (24, 0);
		}
		return (23, error.raw_os_error().unwrap() as u64);
	}
	let code = match error.to_string().as_str() {
		"invalid retained result filename" => 1,
		"request audit metadata identity refused" => 3,
		"retained result refused" => 4,
		"retained bytes refused" => 5,
		"retained result integrity refused" => 6,
		"retained result state refused" => 7,
		"request audit metadata size refused" => 8,
		"private request audit directory refused" => 16,
		"private request audit inode refused" => 17,
		"audit staging inode refused" => 18,
		"audit staging hard-link binding refused" => 19,
		"request audit receipt binding changed" => 20,
		"completed original result is immutable" => 21,
		"request audit record size refused" => 22,
		other => panic!("unclassified original refusal: {other}"),
	};
	(code, 0)
}

fn record_projection(value: &Record) -> Vec<u8> {
	let bytes = serde_json::to_vec(value).unwrap();
	let projection = project(1, &bytes).unwrap();
	let payload = if matches!(value.state, ResultState::Stored) {
		unbase64(value.payload_base64.as_deref().unwrap()).unwrap()
	} else {
		vec![]
	};
	let mut output = vec![0; 32];
	output[..8].copy_from_slice(b"HRRCV001");
	word(&mut output, 16, projection.len() as u64);
	word(&mut output, 24, payload.len() as u64);
	output.extend(projection);
	output.extend(payload);
	output
}

fn invoke(directory: &File, wire: &[u8]) -> (u32, Vec<u8>) {
	if wire.len() < 117 || wire.len() > 1 << 20 || &wire[..8] != b"HRRFQ001" {
		return (u32::MAX, vec![]);
	}
	let operation = u64::from_le_bytes(wire[8..16].try_into().unwrap());
	let filename = u64::from_le_bytes(wire[16..24].try_into().unwrap());
	let length = u64::from_le_bytes(wire[24..32].try_into().unwrap());
	if !(1..=4).contains(&operation)
		|| filename != 69
		|| length != (wire.len() - 117) as u64
		|| wire[32..48] != [0; 16]
		|| ((operation == 1 || operation == 4) && length != 0)
		|| ((operation == 2 || operation == 3) && (length == 0 || length > 98304))
	{
		return (u32::MAX, vec![]);
	}
	let name = match std::str::from_utf8(&wire[48..117]) {
		Ok(value) if value.ends_with(".json") && valid_id(&value[..64]) => value,
		_ => return (u32::MAX, vec![]),
	};
	let mut output = vec![0; 48];
	output[..8].copy_from_slice(b"HRRFO001");
	let result = match operation {
		1 => read_record(directory, name).map(Some),
		4 => cleanup_target_staging(directory, &name[..64]).map(|()| None),
		_ => {
			let value = match validate(name, &wire[117..]) {
				Ok(record) => record,
				Err(_) => return (u32::MAX, vec![]),
			};
			save_inner(directory, &value, operation == 3).map(|()| None)
		}
	};
	match result {
		Ok(Some(value)) => {
			let raw = record_projection(&value);
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
