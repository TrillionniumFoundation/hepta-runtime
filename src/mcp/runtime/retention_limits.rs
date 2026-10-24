// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Immutable administrator-set capacity for durable no-replay key journals.
//! Capacity changes never expire, evict, delete, or rebind an existing key.

use anyhow::{anyhow, bail, Result};
use std::sync::OnceLock;

pub const OWNER_KEYS_ENV: &str = "HEPTA_ASYNC_RETENTION_OWNER_KEYS";
pub const GLOBAL_KEYS_ENV: &str = "HEPTA_ASYNC_RETENTION_GLOBAL_KEYS";
pub const DEFAULT_OWNER_KEYS: usize = 128;
pub const DEFAULT_GLOBAL_KEYS: usize = 512;
pub const MAX_GLOBAL_KEYS: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionLimits {
	pub owner_keys: usize,
	pub global_keys: usize,
}

static LIMITS: OnceLock<std::result::Result<RetentionLimits, String>> = OnceLock::new();

fn parse_capacity(name: &str, value: Option<&str>, default: usize) -> Result<usize> {
	let Some(value) = value else {
		return Ok(default);
	};
	if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
		bail!("{name} must be a positive decimal integer");
	}
	let capacity = value
		.parse::<usize>()
		.map_err(|_| anyhow!("{name} exceeds the supported capacity"))?;
	if !(1..=MAX_GLOBAL_KEYS).contains(&capacity) {
		bail!("{name} must be between 1 and {MAX_GLOBAL_KEYS}");
	}
	Ok(capacity)
}

fn parse_limits(owner: Option<&str>, global: Option<&str>) -> Result<RetentionLimits> {
	let limits = RetentionLimits {
		owner_keys: parse_capacity(OWNER_KEYS_ENV, owner, DEFAULT_OWNER_KEYS)?,
		global_keys: parse_capacity(GLOBAL_KEYS_ENV, global, DEFAULT_GLOBAL_KEYS)?,
	};
	if limits.owner_keys > limits.global_keys {
		bail!("{OWNER_KEYS_ENV} must not exceed {GLOBAL_KEYS_ENV}");
	}
	Ok(limits)
}

fn env_value(name: &str) -> Result<Option<String>> {
	match std::env::var(name) {
		Ok(value) => Ok(Some(value)),
		Err(std::env::VarError::NotPresent) => Ok(None),
		Err(std::env::VarError::NotUnicode(_)) => bail!("{name} must be a decimal integer"),
	}
}

/// Validate once at startup, before opening the runtime or accepting traffic.
pub fn init_retention_limits() -> Result<()> {
	retention_limits().map(|_| ())
}

pub fn retention_limits() -> Result<&'static RetentionLimits> {
	LIMITS
		.get_or_init(|| {
			(|| {
				let owner = env_value(OWNER_KEYS_ENV)?;
				let global = env_value(GLOBAL_KEYS_ENV)?;
				parse_limits(owner.as_deref(), global.as_deref())
			})()
			.map_err(|error: anyhow::Error| error.to_string())
		})
		.as_ref()
		.map_err(|error| anyhow!("invalid immutable retention configuration: {error}"))
}

#[cfg(test)]
#[path = "retention_limits_tests.rs"]
mod tests;
