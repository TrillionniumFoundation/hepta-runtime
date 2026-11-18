// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
include!("original_prepare.rs");
use std::os::unix::ffi::OsStringExt;
fn word(raw: &[u8], at: usize) -> Option<u64> {
	Some(u64::from_le_bytes(raw.get(at..at + 8)?.try_into().ok()?))
}
fn classify(error: anyhow::Error) -> (u64, u64) {
	if let Some(io) = error.downcast_ref::<std::io::Error>() {
		if let Some(errno) = io.raw_os_error() {
			return (23, errno as u64);
		}
		return match io.kind() {
			std::io::ErrorKind::UnexpectedEof => (27, 0),
			std::io::ErrorKind::WriteZero => (28, 0),
			_ => (255, 0),
		};
	}
	if error.downcast_ref::<serde_json::Error>().is_some() {
		return (21, 0);
	}
	let diagnostic = match error.to_string().as_str() {
		"request audit root is not UTF-8" => 1,
		"invalid request audit root" => 2,
		"invalid private metadata component" => 3,
		"result archive preparation unavailable" => 37,
		"private request audit inode refused" => 16,
		"result archive anchor schema refused" => 17,
		"result archive anchor changed during read" => 18,
		"result anchor cache unavailable" => 19,
		"result archive anchor bytes changed; history never repaired automatically" => 20,
		"result archive anchor size refused" => 22,
		"result archive marker size refused" => 24,
		"result archive marker schema refused" => 25,
		"result archive marker binding changed" => 29,
		"result state unavailable" => 30,
		"result archive anchor missing; history never recreated automatically" => 31,
		"unanchored result archive refused; history never recreated automatically" => 32,
		"result archive directory binding changed; history never recreated automatically" => 33,
		"private request audit directory refused" => 34,
		"invalid result archive identity" => 35,
		"result archive shard binding changed; history never recreated automatically" => 36,
		_ => 255,
	};
	(diagnostic, 0)
}
fn response(raw: &[u8]) -> Option<Vec<u8>> {
	if raw.len() < 24
		|| raw.len() > 1048552
		|| raw.get(..8)? != b"HRSPQ001"
		|| word(raw, 8)? != 1
		|| word(raw, 16)? != (raw.len() - 24) as u64
	{
		return None;
	}
	let root = PathBuf::from(std::ffi::OsString::from_vec(raw[24..].to_vec()));
	let (diagnostic, errno) = match prepare_at(&root) {
		Ok(()) => (0, 0),
		Err(error) => classify(error),
	};
	let mut bytes = b"HRSPR001".to_vec();
	for value in [diagnostic, errno, u64::from(diagnostic == 0)] {
		bytes.extend(value.to_le_bytes());
	}
	Some(bytes)
}
fn run() -> Result<()> {
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
		if let Some(bytes) = response(&raw) {
			output.write_all(&(bytes.len() as u32).to_le_bytes())?;
			output.write_all(&bytes)?;
		} else {
			output.write_all(&u32::MAX.to_le_bytes())?;
		}
		output.flush()?;
	}
}
fn main() {
	if std::env::args_os().len() != 1 {
		std::process::exit(64);
	}
	if run().is_err() {
		std::process::exit(74);
	}
}
