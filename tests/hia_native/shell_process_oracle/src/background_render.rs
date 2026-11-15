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

//! Binary transport for original stable-file and observed-tail renderer domains.
//!
//! This is a test adapter. Invalid/capacity transport controls belong to the
//! native transport suite and are never counted as original Rust semantics.
use crate::mcp::fs::background::{self, JobStatus};
use anyhow::{anyhow, bail, Result};
use std::io::{Read, Write};

fn word(bytes: &[u8], offset: usize) -> Result<u64> {
	let slice = bytes
		.get(offset..offset + 8)
		.ok_or_else(|| anyhow!("short background header"))?;
	let array: [u8; 8] = slice.try_into().map_err(|_| anyhow!("short word"))?;
	Ok(u64::from_le_bytes(array))
}

fn response(present: bool, truncated: bool, output: &[u8], text: &[u8], extra: &[u8]) -> Vec<u8> {
	let mut result = Vec::with_capacity(48 + output.len() + text.len() + extra.len());
	result.extend_from_slice(b"HSHBGR01");
	for value in [
		u64::from(present),
		u64::from(truncated),
		output.len() as u64,
		text.len() as u64,
		extra.len() as u64,
	] {
		result.extend_from_slice(&value.to_le_bytes());
	}
	result.extend_from_slice(output);
	result.extend_from_slice(text);
	result.extend_from_slice(extra);
	result
}

fn evaluate(frame: &[u8]) -> Result<Vec<u8>> {
	if frame.len() < 88 || &frame[..8] != b"HSHBGT01" {
		bail!("invalid background frame header");
	}
	let op = word(frame, 8)?;
	let known = word(frame, 16)?;
	let status = word(frame, 24)?;
	let code_word = word(frame, 32)?;
	let out_truncated = word(frame, 40)?;
	let err_truncated = word(frame, 48)?;
	if !(1..=4).contains(&op) || known > 1 || status > 1 || out_truncated > 1 || err_truncated > 1 {
		bail!("invalid typed background fields");
	}
	let code = i32::try_from(code_word as i64)
		.map_err(|_| anyhow!("exit code is not sign-extended i32"))?;
	if code as i64 as u64 != code_word || status == 0 && code_word != 0 {
		bail!("invalid background status code");
	}
	let mut sizes = [0usize; 4];
	let mut end = 88usize;
	for (i, offset) in [56usize, 64, 72, 80].into_iter().enumerate() {
		sizes[i] = usize::try_from(word(frame, offset)?)
			.map_err(|_| anyhow!("unrepresentable frame length"))?;
		end = end
			.checked_add(sizes[i])
			.ok_or_else(|| anyhow!("frame length overflow"))?;
	}
	if end != frame.len() {
		bail!("background frame length differs");
	}
	let mut offset = 88;
	let id = std::str::from_utf8(&frame[offset..offset + sizes[0]])?;
	offset += sizes[0];
	let command = std::str::from_utf8(&frame[offset..offset + sizes[1]])?;
	offset += sizes[1];
	let stdout = &frame[offset..offset + sizes[2]];
	offset += sizes[2];
	let stderr = &frame[offset..];
	if op >= 3 {
		if known != 0
			|| status != 0
			|| code_word != 0
			|| out_truncated != 0
			|| err_truncated != 0
			|| sizes[1] != 0
			|| sizes[2] != 0
			|| sizes[3] != 0
		{
			bail!("URI operation has extraneous fields");
		}
		return match op {
			3 => Ok(response(
				true,
				false,
				&[],
				&[],
				background::resource_uri(id).as_bytes(),
			)),
			4 => match background::job_id_from_uri(id) {
				Some(value) => Ok(response(true, false, &[], &[], value.as_bytes())),
				None => Ok(response(false, false, &[], &[], &[])),
			},
			_ => bail!("unreachable operation"),
		};
	}
	if known == 0 {
		if status != 0
			|| code_word != 0
			|| out_truncated != 0
			|| err_truncated != 0
			|| sizes[1] != 0
			|| sizes[2] != 0
			|| sizes[3] != 0
		{
			bail!("unknown job has extraneous fields");
		}
		background::fixture::absent(id)?;
		return Ok(response(false, false, &[], &[], &[]));
	}
	let status = if status == 0 {
		JobStatus::Running
	} else {
		JobStatus::Exited(code)
	};
	let rendered = if op == 1 {
		if out_truncated != 0 || err_truncated != 0 {
			bail!("stable input cannot predeclare read-tail truncation");
		}
		background::fixture::stable(id, command, status, stdout, stderr)?
	} else {
		background::fixture::observed_tails(
			id,
			command,
			status,
			stdout.to_vec(),
			out_truncated != 0,
			stderr.to_vec(),
			err_truncated != 0,
		)?
	};
	Ok(response(
		true,
		rendered.truncated,
		&rendered.output,
		&rendered.text,
		&rendered.uri,
	))
}

pub(crate) fn run() -> Result<()> {
	let stdin = std::io::stdin();
	let stdout = std::io::stdout();
	let mut input = stdin.lock();
	let mut output = stdout.lock();
	loop {
		let mut length = [0u8; 8];
		if input.read(&mut length[..1])? == 0 {
			break;
		}
		input.read_exact(&mut length[1..])?;
		let length = usize::try_from(u64::from_le_bytes(length))
			.map_err(|_| anyhow!("input frame length is not representable"))?;
		let mut frame = Vec::new();
		frame
			.try_reserve_exact(length)
			.map_err(|error| anyhow!("input allocation: {error}"))?;
		frame.resize(length, 0);
		input.read_exact(&mut frame)?;
		let rendered = evaluate(&frame)?;
		output.write_all(&(rendered.len() as u64).to_le_bytes())?;
		output.write_all(&(rendered.len() as u64).to_le_bytes())?;
		output.write_all(&rendered)?;
	}
	output.flush()?;
	Ok(())
}
