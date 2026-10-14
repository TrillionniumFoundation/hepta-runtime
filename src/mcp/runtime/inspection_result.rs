// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bound network observations at their actual native SDK envelope, never by dropping fields.
use anyhow::{bail, Result};
use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::Value;
use std::io::{self, Write};

// Keep the original encrypted payload ceiling, not a larger special-case allowance.
const LIMIT: usize = super::super::operation_crypto::MAX_PAYLOAD_BYTES;

struct LimitedWriter {
	bytes: Vec<u8>,
	limit: usize,
}
impl Write for LimitedWriter {
	fn write(&mut self, data: &[u8]) -> io::Result<usize> {
		if data.len() > self.limit.saturating_sub(self.bytes.len()) {
			return Err(io::Error::other("network serialization bound reached"));
		}
		self.bytes.extend_from_slice(data);
		Ok(data.len())
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

fn serialize(value: &Value, pretty: bool, limit: usize) -> Result<String> {
	let mut writer = LimitedWriter {
		bytes: Vec::new(),
		limit,
	};
	if pretty {
		serde_json::to_writer_pretty(&mut writer, value)?;
	} else {
		serde_json::to_writer(&mut writer, value)?;
	}
	Ok(String::from_utf8(writer.bytes)?)
}

fn fits_native_envelope(text: &str, limit: usize) -> bool {
	let sdk = CallToolResult::success(vec![ContentBlock::text(text)]);
	let mut writer = LimitedWriter {
		bytes: Vec::new(),
		limit,
	};
	serde_json::to_writer(&mut writer, &sdk).is_ok()
}

fn network_result_with_limit(value: &Value, limit: usize) -> Result<String> {
	// Ordinary results remain byte-for-byte identical to the earlier pretty JSON.
	// If whitespace/outer escaping alone breaches the envelope, compact the same
	// complete value before the native response is formed and retained.
	for pretty in [true, false] {
		if let Ok(text) = serialize(value, pretty, limit) {
			if fits_native_envelope(&text, limit) {
				return Ok(text);
			}
		}
	}
	// No routes/listeners are cut to make an apparently successful response fit.
	// The native tool error is itself small, so operation_result can retain it.
	bail!("network_inspect result exceeds the native SDK byte limit; no fields were truncated; no automatic retry")
}

pub(super) fn network_result(value: &Value) -> Result<String> {
	network_result_with_limit(value, LIMIT)
}

#[cfg(test)]
#[path = "inspection_result_tests.rs"]
mod tests;
