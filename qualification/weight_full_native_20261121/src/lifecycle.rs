// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Isolated callback lifecycle; no production publication or alternative durable owner.

use anyhow::{bail, Result};
use hepta_semantic_source_adapter_study::digest;
use serde::Serialize;

#[derive(Serialize)]
pub struct Restoration {
	pub original_sha256: String,
	pub candidate_sha256: String,
	pub restored_sha256: String,
	pub original_bytes_exact: bool,
	pub production_owner_called: bool,
	pub durable_crash_recovery_exercised: bool,
}

struct Guard<'a> {
	active: &'a mut Vec<u8>,
	original: Vec<u8>,
}
impl Drop for Guard<'_> {
	fn drop(&mut self) {
		self.active.clone_from(&self.original);
	}
}

pub fn run<T>(
	active: &mut Vec<u8>,
	original: &[u8],
	candidate: &[u8],
	evaluate: impl FnOnce(&[u8]) -> Result<T>,
) -> Result<(std::result::Result<T, String>, Restoration)> {
	if active != original {
		bail!("isolated lifecycle old bytes differ from immutable anchor");
	}
	*active = candidate.to_vec();
	let guard = Guard {
		active,
		original: original.to_vec(),
	};
	let result = evaluate(guard.active).map_err(|e| e.to_string());
	let candidate_sha256 = digest(guard.active);
	drop(guard);
	Ok((
		result,
		Restoration {
			original_sha256: digest(original),
			candidate_sha256,
			restored_sha256: digest(active),
			original_bytes_exact: active == original,
			production_owner_called: false,
			durable_crash_recovery_exercised: false,
		},
	))
}
