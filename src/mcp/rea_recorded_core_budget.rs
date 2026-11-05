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

//! Incremental complete-JSON accounting and bounded original-byte encoding.

use super::CoreFailure;
use serde_json::Value;
use std::io::{self, Write};

pub(super) struct Budget {
	limit: usize,
	used: usize,
}

impl Budget {
	pub(super) fn new(limit: usize, empty_report: &Value) -> Result<Self, CoreFailure> {
		Ok(Self {
			limit,
			used: encoded_json_size(empty_report, limit)?,
		})
	}

	pub(super) fn remaining(&self) -> usize {
		self.limit - self.used
	}

	pub(super) fn push(&mut self, array: &mut Vec<Value>, value: Value) -> Result<(), CoreFailure> {
		let comma = usize::from(!array.is_empty());
		let available = self
			.remaining()
			.checked_sub(comma)
			.ok_or_else(CoreFailure::budget)?;
		let size = encoded_json_size(&value, available)?;
		array
			.try_reserve(1)
			.map_err(|_| CoreFailure::allocation())?;
		// The successful count above proves both additions fit the remaining budget.
		self.used += size + comma;
		array.push(value);
		Ok(())
	}

	pub(super) fn finish(&self, value: &Value) -> Result<(), CoreFailure> {
		encoded_json_size(value, self.limit).map(|_| ())
	}
}

struct Counter {
	limit: usize,
	used: usize,
}

impl Write for Counter {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		if bytes.len() > self.limit - self.used {
			return Err(io::Error::other("recorded-core JSON budget exceeded"));
		}
		self.used += bytes.len();
		Ok(bytes.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

fn encoded_json_size(value: &Value, limit: usize) -> Result<usize, CoreFailure> {
	let mut counter = Counter { limit, used: 0 };
	serde_json::to_writer(&mut counter, value).map_err(|_| CoreFailure::budget())?;
	Ok(counter.used)
}

pub(super) fn encoded_size(size: usize) -> Result<usize, CoreFailure> {
	size.div_ceil(3)
		.checked_mul(4)
		.ok_or_else(CoreFailure::budget)
}

pub(super) fn encoded(bytes: &[u8], limit: usize) -> Result<String, CoreFailure> {
	const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	let size = encoded_size(bytes.len())?;
	if size > limit {
		return Err(CoreFailure::budget());
	}
	let mut result = String::new();
	result
		.try_reserve_exact(size)
		.map_err(|_| CoreFailure::allocation())?;
	for chunk in bytes.chunks(3) {
		let first = chunk[0];
		let second = chunk.get(1).copied().unwrap_or(0);
		let third = chunk.get(2).copied().unwrap_or(0);
		result.push(char::from(ALPHABET[usize::from(first >> 2)]));
		result.push(char::from(
			ALPHABET[usize::from(((first & 3) << 4) | (second >> 4))],
		));
		result.push(if chunk.len() > 1 {
			char::from(ALPHABET[usize::from(((second & 15) << 2) | (third >> 6))])
		} else {
			'='
		});
		result.push(if chunk.len() > 2 {
			char::from(ALPHABET[usize::from(third & 63)])
		} else {
			'='
		});
	}
	Ok(result)
}

fn append(result: &mut String, text: &str, limit: usize) -> Result<(), CoreFailure> {
	if text.len() > limit.saturating_sub(result.len()) {
		return Err(CoreFailure::budget());
	}
	result
		.try_reserve(text.len())
		.map_err(|_| CoreFailure::allocation())?;
	result.push_str(text);
	Ok(())
}

pub(super) fn lossy_display(mut bytes: &[u8], limit: usize) -> Result<String, CoreFailure> {
	let mut result = String::new();
	while !bytes.is_empty() {
		match std::str::from_utf8(bytes) {
			Ok(text) => {
				append(&mut result, text, limit)?;
				break;
			}
			Err(error) => {
				let valid = error.valid_up_to();
				// The validator proves the prefix valid without an unsafe conversion.
				let prefix = std::str::from_utf8(&bytes[..valid]).map_err(|_| {
					CoreFailure::format("Recorded note owner UTF-8 validation failed.")
				})?;
				append(&mut result, prefix, limit)?;
				append(&mut result, "\u{fffd}", limit)?;
				match error.error_len() {
					Some(invalid) => bytes = &bytes[valid + invalid..],
					None => break,
				}
			}
		}
	}
	Ok(result)
}
