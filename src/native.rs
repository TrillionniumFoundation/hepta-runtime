// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Trusted in-process access to the existing durable process owner.
//!
//! This facade is not an authorization issuer. The embedding host validates
//! principal, turn, generation, exact payload and FinalUse before invoking it.
//! It retains the configured host policy, owner fence, durable request binding,
//! target supervisor and reconciliation of the existing jobs implementation.
//! A cell proposal, or a successful shadow-intent digest, is not permission.
//!
//! Errors after admission may describe an unknown effect. Keep the original
//! host and idempotency key and reconcile them; do not allocate a replacement.

use crate::mcp::runtime::jobs::{
	self, ProcessCancelParams, ProcessReadParams, ProcessRefParams, ProcessStartParams,
};
use anyhow::{bail, Result};

fn require_key(params: &ProcessStartParams) -> Result<()> {
	match params.idempotency_key.as_deref() {
		Some(key) if !key.trim().is_empty() && key.len() <= 256 => Ok(()),
		_ => bail!("native process execution requires the original nonempty idempotency key"),
	}
}

/// Execute once or observe the same original job through its durable binding.
/// The returned JSON is the existing backend's exact response, not a new receipt.
pub async fn execute_or_observe(params: ProcessStartParams) -> Result<String> {
	require_key(&params)?;
	jobs::start_job(params).await
}

/// Resolve and observe the original request without submitting or relaunching it.
/// A missing local binding is not evidence that an external effect did not occur.
pub async fn observe_request(params: ProcessStartParams) -> Result<Option<String>> {
	require_key(&params)?;
	jobs::observe_request(params).await
}

/// Read the original job. This cannot launch or repair an unknown effect.
pub async fn status(params: ProcessRefParams) -> Result<String> {
	jobs::status_job(params).await
}

/// Read bounded original output with independent byte cursors.
pub async fn read(params: ProcessReadParams) -> Result<String> {
	jobs::read_job(params).await
}

/// Cancel only the stored original job; confirmation still requires status.
pub async fn cancel(params: ProcessCancelParams) -> Result<String> {
	jobs::cancel_job(params).await
}

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;
