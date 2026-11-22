// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded source and profile authentication. No model execution or effect owner.

pub mod descriptor;
pub mod semantics;
mod unique_json;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;

/// A pin is an input from the reviewing owner, not an owner signature.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourcePin {
	pub source_id: String,
	pub sha256: String,
	pub size_bytes: u64,
}

impl SourcePin {
	pub fn verify(&self, bytes: &[u8], maximum: usize) -> Result<()> {
		validate_sha256(&self.sha256)?;
		if self.source_id.is_empty() || self.source_id.len() > 4096 {
			bail!("source pin requires a bounded, nonempty reviewed identity");
		}
		if bytes.len() > maximum
			|| bytes.len() as u64 != self.size_bytes
			|| digest(bytes) != self.sha256
		{
			bail!("source bytes differ from the pinned size or SHA256, or exceed the limit");
		}
		Ok(())
	}
}

pub fn validate_sha256(value: &str) -> Result<()> {
	if value.len() != 64
		|| !value
			.bytes()
			.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
	{
		bail!("SHA256 must be 64 lowercase hexadecimal characters");
	}
	Ok(())
}

pub fn digest(bytes: &[u8]) -> String {
	let mut text = String::with_capacity(64);
	for byte in Sha256::digest(bytes) {
		let _ = write!(text, "{byte:02x}");
	}
	text
}

pub fn unique_json(bytes: &[u8]) -> Result<serde_json::Value> {
	if bytes.len() > MAX_JSON_BYTES {
		bail!("JSON byte limit exceeded before deserialization");
	}
	unique_json::parse_unique_json(bytes)
}

#[cfg(test)]
#[path = "adapter_tests.rs"]
mod adapter_tests;
