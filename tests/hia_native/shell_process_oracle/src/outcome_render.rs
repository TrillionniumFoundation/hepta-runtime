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

//! Binary test transport for unchanged original foreground/promotion statements.
//! Results are typed projections. This adapter performs no capture-file reads,
//! removes, process waits, background registrations or notifications.
use crate::mcp::fs::shell;
use anyhow::{anyhow, bail, Result};
use std::io::{self, Read, Write};
use std::os::unix::process::ExitStatusExt;

fn word(frame: &[u8], offset: usize) -> Result<u64> {
	let bytes: [u8; 8] = frame
		.get(offset..offset + 8)
		.ok_or_else(|| anyhow!("short outcome header"))?
		.try_into()?;
	Ok(u64::from_le_bytes(bytes))
}

fn signed_word(value: u64) -> Result<i32> {
	let result = i32::try_from(value as i64)
		.map_err(|_| anyhow!("outcome value is not sign-extended i32"))?;
	if result as i64 as u64 != value {
		bail!("outcome value is not canonical signed i32");
	}
	Ok(result)
}

fn typed_error(kind: u64, value: u64, bytes: &[u8]) -> Result<io::Error> {
	match kind {
		1 if value == 0 => Ok(io::Error::other(std::str::from_utf8(bytes)?.to_owned())),
		2 if bytes.is_empty() => Ok(io::Error::from_raw_os_error(signed_word(value)?)),
		3 if value == 0 && bytes.is_empty() => Ok(io::ErrorKind::OutOfMemory.into()),
		4 if value == 0 && bytes.is_empty() => Ok(io::Error::other("background task failed")),
		_ => bail!("invalid typed outcome error"),
	}
}

fn read_result(kind: u64, value: u64, bytes: &[u8]) -> Result<io::Result<Vec<u8>>> {
	if kind == 0 {
		if value != 0 {
			bail!("successful read has an error value");
		}
		Ok(Ok(bytes.to_vec()))
	} else {
		Ok(Err(typed_error(kind, value, bytes)?))
	}
}

fn response(kind: u64, text: &[u8], uri: Option<&str>) -> Vec<u8> {
	let uri_bytes = uri.unwrap_or("").as_bytes();
	let mut bytes = Vec::with_capacity(40 + text.len() + uri_bytes.len());
	bytes.extend_from_slice(b"HSHOUR01");
	for value in [kind, text.len() as u64, u64::from(uri.is_some()), uri_bytes.len() as u64] {
		bytes.extend_from_slice(&value.to_le_bytes());
	}
	bytes.extend_from_slice(text);
	bytes.extend_from_slice(uri_bytes);
	bytes
}

fn evaluate(frame: &[u8]) -> Result<Vec<u8>> {
	if frame.len() < 112 || &frame[..8] != b"HSHOUT01" {
		bail!("invalid outcome frame header");
	}
	let op = word(frame, 8)?;
	let wait_kind = word(frame, 16)?;
	let wait_value = word(frame, 24)?;
	let stdout_kind = word(frame, 32)?;
	let stdout_value = word(frame, 40)?;
	let stderr_kind = word(frame, 48)?;
	let stderr_value = word(frame, 56)?;
	let pid = word(frame, 64)?;
	let mut sizes = [0usize; 5];
	let mut end = 112usize;
	for (i, offset) in [72, 80, 88, 96, 104].into_iter().enumerate() {
		sizes[i] = usize::try_from(word(frame, offset)?)
			.map_err(|_| anyhow!("unrepresentable outcome payload length"))?;
		end = end.checked_add(sizes[i]).ok_or_else(|| anyhow!("outcome length overflow"))?;
	}
	if end != frame.len() {
		bail!("outcome frame length differs");
	}
	let mut fields = [&[][..]; 5];
	let mut offset = 112;
	for (i, length) in sizes.into_iter().enumerate() {
		fields[i] = &frame[offset..offset + length];
		offset += length;
	}
	let outcome = match op {
		1 => {
			if pid != 0 || !fields[3].is_empty() || !fields[4].is_empty() {
				bail!("foreground operation has extraneous fields");
			}
			let result = if wait_kind == 0 {
				if !fields[0].is_empty() {
					bail!("successful wait has error text");
				}
				Ok(std::process::ExitStatus::from_raw(signed_word(wait_value)?))
			} else {
				Err(typed_error(wait_kind, wait_value, fields[0])?)
			};
			let stdout = read_result(stdout_kind, stdout_value, fields[1])?;
			let stderr = read_result(stderr_kind, stderr_value, fields[2])?;
			shell::fixture_foreground_result(result, stdout, stderr)
		}
		2 => {
			if [wait_kind, wait_value, stdout_kind, stdout_value, stderr_kind, stderr_value]
				.iter().any(|value| *value != 0)
				|| fields[..3].iter().any(|field| !field.is_empty())
			{
				bail!("promotion operation has extraneous fields");
			}
			let pid = u32::try_from(pid).map_err(|_| anyhow!("promotion PID exceeds u32"))?;
			let command = std::str::from_utf8(fields[3])?.to_owned();
			let id = std::str::from_utf8(fields[4])?.to_owned();
			shell::fixture_promotion_result(id, pid, command)
		}
		3 => {
			if wait_kind != 2
				|| [stdout_kind, stdout_value, stderr_kind, stderr_value, pid]
					.iter().any(|value| *value != 0)
				|| fields.iter().any(|field| !field.is_empty())
			{
				bail!("errno operation has extraneous fields");
			}
			let error = io::Error::from_raw_os_error(signed_word(wait_value)?).to_string();
			return Ok(response(2, error.as_bytes(), None));
		}
		_ => bail!("unknown outcome operation"),
	};
	Ok(match outcome {
		Ok(value) => response(0, value.text.as_bytes(), value.resource_uri.as_deref()),
		Err(error) => response(1, error.to_string().as_bytes(), None),
	})
}

pub(crate) fn run() -> Result<()> {
	let stdin = io::stdin();
	let stdout = io::stdout();
	let mut input = stdin.lock();
	let mut output = stdout.lock();
	loop {
		let mut length = [0u8; 8];
		if input.read(&mut length[..1])? == 0 {
			break;
		}
		input.read_exact(&mut length[1..])?;
		let length = usize::try_from(u64::from_le_bytes(length))
			.map_err(|_| anyhow!("outcome frame length is not representable"))?;
		let mut frame = Vec::new();
		frame.try_reserve_exact(length).map_err(|error| anyhow!("input allocation: {error}"))?;
		frame.resize(length, 0);
		input.read_exact(&mut frame)?;
		let rendered = evaluate(&frame)?;
		// The HIA entry returns the fixed header size. Complete body extent is
		// separately u64 so error/promotion text has no added u32-size ceiling.
		output.write_all(&40u64.to_le_bytes())?;
		output.write_all(&(rendered.len() as u64).to_le_bytes())?;
		output.write_all(&rendered)?;
	}
	output.flush()?;
	Ok(())
}
