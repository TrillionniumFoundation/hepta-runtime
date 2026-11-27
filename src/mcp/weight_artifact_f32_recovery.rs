// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Restore a source-bound, already published F32 candidate without reopening its old source path.
//! The original guard intent and canonical artifact owner remain the only authorities.

#[cfg(not(target_os = "linux"))]
use anyhow::bail;
#[cfg(target_os = "linux")]
use anyhow::Context;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::mcp::rea_model::session::weight::SessionAuthority;
use crate::mcp::runtime::effect_owner_fence::AdmissionPermit;
use crate::mcp::weight_guard::source_bound_f32::BiasBinding;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryParams {
	/// Original native guard intent identity, recorded before the initial evaluation.
	pub journal_id: String,
	pub original_source_sha256: String,
	pub expected_candidate_sha256: String,
	/// May be absent when publication completed but its response and candidate record were lost.
	pub candidate_artifact_id: Option<String>,
	pub bias_binding: BiasBinding,
}

#[cfg(target_os = "linux")]
#[path = "weight_artifact_f32_recovery_linux.rs"]
mod linux;

/// This explicit re-entry performs no parent or candidate forward and creates no new candidate.
/// A response deadline retains the original owner task; it is not a process-crash guarantee.
pub async fn run(params: RecoveryParams) -> Result<Value> {
	run_scoped(params, None, None).await
}

pub(in crate::mcp) async fn run_for_session(
	params: RecoveryParams,
	authority: SessionAuthority,
	owner_admission: AdmissionPermit,
) -> Result<Value> {
	authority.revalidate().await?;
	authority.check_bias_binding(&params.bias_binding)?;
	run_scoped(params, Some(authority), Some(owner_admission)).await
}

async fn run_scoped(
	params: RecoveryParams,
	authority: Option<SessionAuthority>,
	owner_admission: Option<AdmissionPermit>,
) -> Result<Value> {
	#[cfg(target_os = "linux")]
	{
		let config = crate::mcp::runtime::runtime_config()?;
		let roots = config.controller_workspace_roots.clone();
		let state = config.state_dir.clone();
		let guards = match owner_admission {
			Some(admission) => super::owner_guards_from_admission(admission).await?,
			None => super::owner_guards().await?,
		};
		tokio::time::timeout(
			std::time::Duration::from_secs(420),
			super::retained_transaction(guards, async move {
				match authority {
					Some(authority) => linux::run_for_session(params, &roots, &state, authority).await,
					None => linux::run_with_roots(params, &roots, &state).await,
				}
			}),
		)
		.await
		.context("source-bound recovery response deadline exceeded; the admitted owner task may still finish; reconcile the identical request")?
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = (params, authority, owner_admission);
		bail!("source-bound original-intent recovery requires Linux");
	}
}

#[cfg(all(test, target_os = "linux"))]
#[path = "weight_artifact_f32_recovery_tests.rs"]
mod tests;
