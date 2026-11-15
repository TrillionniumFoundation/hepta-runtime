// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! ExactElementEdit and unhex copied from the pinned source as a minimal type/hex adapter.
//! No source-file authorization, safetensors parsing or publication is provided here.
use anyhow::{bail, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExactElementEdit {
	/// Flattened element index in the declared tensor's contiguous storage.
	pub index: u64,
	/// Exact existing little-endian element bytes, lowercase hexadecimal.
	pub expected_hex: String,
	/// Exact replacement little-endian element bytes; no rounding is performed.
	pub replacement_hex: String,
}

pub(super) fn unhex(text: &str) -> Result<Vec<u8>> {
	if !text.len().is_multiple_of(2) || text.len() > 8 {
		bail!("element bytes must contain at most four complete bytes");
	}
	text.as_bytes()
		.chunks_exact(2)
		.map(|pair| {
			let digit = |byte| match byte {
				b'0'..=b'9' => Ok(byte - b'0'),
				b'a'..=b'f' => Ok(byte - b'a' + 10),
				_ => bail!("element bytes require lowercase hexadecimal"),
			};
			Ok(digit(pair[0])? * 16 + digit(pair[1])?)
		})
		.collect()
}
