// Copyright 2026 Muvon Un Limited
// SPDX-License-Identifier: Apache-2.0
use anyhow::{Context, Result};
use std::io::Read;
pub fn new_owner_id() -> Result<String> {
	let mut bytes = [0u8; 32];
	std::fs::File::open("/dev/urandom")
		.context("search identity entropy unavailable")?
		.read_exact(&mut bytes)
		.context("search identity entropy unavailable")?;
	Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
