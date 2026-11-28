// Copyright 2026 Muvon Un Limited
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Framed test transport around unchanged, hash-bound original shell owners.
//! This executable is an independent test oracle and is never runtime code.

use std::io::{self, Read, Write};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

mod original {
	#![allow(dead_code)]
	use std::path::Path;
	use std::sync::OnceLock;
	include!("../fixtures/original_shell.rs");

	pub(super) fn terminal(raw: &str) -> Vec<u8> {
		clean_terminal_noise(raw).into_bytes()
	}

	fn word(output: &mut Vec<u8>, value: usize) {
		output.extend_from_slice(&(value as u64).to_le_bytes());
	}

	fn slices(command: &str, values: Vec<&str>) -> Vec<u8> {
		let mut output = Vec::new();
		word(&mut output, values.len());
		for value in values {
			let start = value.as_ptr() as usize - command.as_ptr() as usize;
			word(&mut output, start);
			word(&mut output, start + value.len());
		}
		output
	}

	pub(super) fn gate(op: u64, command: &str, workdir: Option<&Path>) -> io::Result<Vec<u8>> {
		let mut output = Vec::new();
		match op {
			1 => match detect_shell_misuse(command, workdir) {
				None => word(&mut output, 0),
				Some(Misuse::Reject(message)) => {
					word(&mut output, 1);
					output.extend_from_slice(message.as_bytes());
				}
				Some(Misuse::Hint(message)) => {
					word(&mut output, 2);
					output.extend_from_slice(message.as_bytes());
				}
			},
			2 => word(&mut output, usize::from(stashes_changes(command))),
			3 => return Ok(slices(command, split_shell_segments(command))),
			4 => {
				let spans = shell_token_spans(command);
				word(&mut output, spans.len());
				for (start, end) in spans {
					word(&mut output, start);
					word(&mut output, end);
				}
			}
			5 => return Ok(slices(command, redirect_targets(command))),
			6 => match ssh_remote_command(command) {
				None => word(&mut output, 0),
				Some(remote) => {
					word(&mut output, 1);
					let start = remote.as_ptr() as usize - command.as_ptr() as usize;
					word(&mut output, start);
					word(&mut output, start + remote.len());
				}
			},
			_ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown semantic operation")),
		}
		Ok(output)
	}

	use std::io;
	#[cfg(test)]
	mod tests {
		use super::*;
		include!("../fixtures/original_shell_tests.rs");
	}
}

fn invalid(message: &'static str) -> io::Error {
	io::Error::new(io::ErrorKind::InvalidData, message)
}

fn number(raw: &[u8], offset: usize) -> io::Result<u64> {
	let value = raw.get(offset..offset + 8).ok_or_else(|| invalid("missing number"))?;
	let bytes: [u8; 8] = value.try_into().map_err(|_| invalid("bad number"))?;
	Ok(u64::from_le_bytes(bytes))
}

fn semantic(mode: &str, raw: &[u8]) -> io::Result<Vec<u8>> {
	if mode == "terminal" {
		let text = std::str::from_utf8(raw).map_err(|_| invalid("terminal oracle requires original UTF-8 domain"))?;
		return Ok(original::terminal(text));
	}
	if mode != "gate" || raw.get(..8) != Some(b"HSHGATE1") || raw.len() < 40 {
		return Err(invalid("invalid gate semantic frame"));
	}
	let op = number(raw, 8)?;
	let present = number(raw, 16)?;
	let command_len = usize::try_from(number(raw, 24)?).map_err(|_| invalid("command length overflow"))?;
	let workdir_len = usize::try_from(number(raw, 32)?).map_err(|_| invalid("workdir length overflow"))?;
	let command_end = 40usize.checked_add(command_len).ok_or_else(|| invalid("command offset overflow"))?;
	let end = command_end.checked_add(workdir_len).ok_or_else(|| invalid("workdir offset overflow"))?;
	if present > 1 || (present == 0 && workdir_len != 0) || end != raw.len() {
		return Err(invalid("gate semantic envelope differs"));
	}
	let command = std::str::from_utf8(&raw[40..command_end]).map_err(|_| invalid("command is not UTF-8"))?;
	let workdir = OsStr::from_bytes(&raw[command_end..]);
	original::gate(op, command, if present == 1 { Some(Path::new(workdir)) } else { None })
}

fn run() -> io::Result<()> {
	let mut args = std::env::args();
	let _executable = args.next();
	let mode = args.next().ok_or_else(|| invalid("expected terminal or gate mode"))?;
	if !matches!(mode.as_str(), "terminal" | "gate") || args.next().is_some() {
		return Err(invalid("expected only terminal or gate mode"));
	}
	let mut input = io::stdin().lock();
	let mut output = io::BufWriter::new(io::stdout().lock());
	loop {
		let mut header = [0u8; 8];
		match input.read(&mut header[..1])? {
			0 => break,
			1 => input.read_exact(&mut header[1..])?,
			_ => return Err(invalid("invalid frame header read")),
		}
		let length = usize::try_from(u64::from_le_bytes(header)).map_err(|_| invalid("frame length overflow"))?;
		let mut request = Vec::new();
		request.try_reserve_exact(length).map_err(|_| invalid("frame allocation failure"))?;
		request.resize(length, 0);
		input.read_exact(&mut request)?;
		let body = semantic(&mode, &request)?;
		output.write_all(&(body.len() as u64).to_le_bytes())?;
		output.write_all(&body)?;
	}
	output.flush()
}

fn main() {
	if let Err(error) = run() {
		eprintln!("original shell oracle: {error}");
		std::process::exit(2);
	}
}
