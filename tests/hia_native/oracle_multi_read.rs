// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
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
// SPDX-License-Identifier: Apache-2.0
//! Test-only original multi-file validation after typed parameter admission.
//!
//! The private packet decodes typed fixtures only. It is not a runtime ABI,
//! a replacement for serde admission, or a filesystem/transport reference.
use std::io::{self, BufRead, Write};

type Result<T> = std::result::Result<T, String>;
macro_rules! bail {
	($($arg:tt)*) => {{ return Err(format!($($arg)*)); }};
}
const MAX_FILE_BYTES: u64 = 65_536;
const MAX_RESPONSE_BYTES: u64 = 262_144;
struct MultiReadParams {
	paths: Vec<String>,
	max_file_bytes: Option<u64>,
	max_response_bytes: Option<u64>,
}

// Keep the pinned original function byte-for-byte, including its layout.
#[rustfmt::skip]
fn validate(p: &MultiReadParams) -> Result<(u64, u64)> {
	if !(1..=16).contains(&p.paths.len()) {
		bail!("read_multiple_files requires 1..16 paths");
	}
	let file = p.max_file_bytes.unwrap_or(16_384);
	let response = p.max_response_bytes.unwrap_or(65_536);
	if !(1..=MAX_FILE_BYTES).contains(&file) {
		bail!("max_file_bytes must be 1..65536; larger files require binary_read");
	}
	if !(1024..=MAX_RESPONSE_BYTES).contains(&response) {
		bail!("max_response_bytes must be 1024..262144");
	}
	let mut seen = std::collections::HashSet::new();
	for path in &p.paths {
		// Reject aliases before protected-prefix checks, rather than normalizing after them.
		if path.len() > 4096
			|| !path.starts_with('/')
			|| path.contains('\0')
			|| path[1..]
				.split('/')
				.any(|part| part.is_empty() || part == "." || part == "..")
		{
			bail!("batch paths must be bounded absolute paths without empty, dot or traversal components");
		}
		if !seen.insert(path) {
			bail!("read_multiple_files paths must be distinct");
		}
	}
	Ok((file, response))
}

fn word(bytes: &[u8], at: &mut usize) -> Result<u64> {
	let end = at.checked_add(8).ok_or("packet offset overflow")?;
	let raw: [u8; 8] = bytes
		.get(*at..end)
		.ok_or("truncated packet")?
		.try_into()
		.map_err(|_| "invalid word")?;
	*at = end;
	Ok(u64::from_le_bytes(raw))
}

fn option(present: u64, value: u64) -> Result<Option<u64>> {
	match present {
		0 if value == 0 => Ok(None),
		1 => Ok(Some(value)),
		_ => Err("invalid typed option".to_owned()),
	}
}

fn packet(bytes: &[u8]) -> Result<MultiReadParams> {
	if bytes.get(..8) != Some(b"HMRVAL01") {
		bail!("invalid fixture magic");
	}
	let mut at = 8;
	let max_file_bytes = option(word(bytes, &mut at)?, word(bytes, &mut at)?)?;
	let max_response_bytes = option(word(bytes, &mut at)?, word(bytes, &mut at)?)?;
	let count = usize::try_from(word(bytes, &mut at)?).map_err(|_| "path count overflow")?;
	if count > (bytes.len() - at) / 8 {
		bail!("truncated path list");
	}
	let mut paths = Vec::with_capacity(count);
	for _ in 0..count {
		let size = usize::try_from(word(bytes, &mut at)?).map_err(|_| "path size overflow")?;
		let end = at.checked_add(size).ok_or("path offset overflow")?;
		let raw = bytes.get(at..end).ok_or("truncated path")?;
		paths.push(
			std::str::from_utf8(raw)
				.map_err(|e| e.to_string())?
				.to_owned(),
		);
		at = end;
	}
	if at != bytes.len() {
		bail!("trailing fixture bytes");
	}
	Ok(MultiReadParams {
		paths,
		max_file_bytes,
		max_response_bytes,
	})
}

fn unhex(text: &str) -> Result<Vec<u8>> {
	if text.len() % 2 != 0 {
		bail!("odd hex length");
	}
	text.as_bytes()
		.chunks_exact(2)
		.map(|pair| {
			let nibble = |b: u8| match b {
				b'0'..=b'9' => Ok(b - b'0'),
				b'a'..=b'f' => Ok(b - b'a' + 10),
				_ => Err("invalid lowercase hex".to_owned()),
			};
			Ok(nibble(pair[0])? * 16 + nibble(pair[1])?)
		})
		.collect()
}

fn hex(bytes: &[u8]) -> String {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	let mut out = String::with_capacity(bytes.len() * 2);
	for &byte in bytes {
		out.push(DIGITS[usize::from(byte >> 4)] as char);
		out.push(DIGITS[usize::from(byte & 15)] as char);
	}
	out
}

fn main() -> Result<()> {
	let mut out = io::BufWriter::new(io::stdout().lock());
	for line in io::stdin().lock().lines() {
		let params = packet(&unhex(&line.map_err(|e| e.to_string())?)?)?;
		match validate(&params) {
			Ok((file, response)) => writeln!(out, "OK {file} {response}"),
			Err(error) => writeln!(out, "ERR {}", hex(error.as_bytes())),
		}
		.map_err(|e| e.to_string())?;
	}
	out.flush().map_err(|e| e.to_string())
}
