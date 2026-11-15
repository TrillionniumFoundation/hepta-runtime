// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0

//! Explicit native Evidence checkpoints. These routes never change the frozen
//! cold-empty session contract or treat a checkpoint locator as authorization.

use super::rea_evidence_session::EvidenceSession;
use super::runtime::{self, caller_scope::OwnerScope, effect_owner_fence::AdmissionPermit};
use anyhow::{ensure, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[cfg(target_os = "linux")]
#[path = "rea_evidence_checkpoint_linux.rs"]
mod platform;

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct CheckpointParams {}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ResumeParams {
	/// Exact immutable checkpoint ID. Current authenticated owner and policy must match.
	pub checkpoint_id: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ListParams {
	#[serde(default)]
	pub offset: usize,
	/// Maximum rows, 1..=32. The first page returns a catalog SHA-256.
	#[serde(default = "default_limit")]
	pub limit: usize,
	/// Required after offset zero. Any catalog or owner/policy change refuses continuation.
	pub expected_catalog_sha256: Option<String>,
}

fn default_limit() -> usize {
	16
}

#[derive(Clone)]
struct Scope {
	state_dir: PathBuf,
	owner: String,
	policy: String,
}

impl Scope {
	fn current(owner: &OwnerScope) -> Result<Self> {
		ensure!(owner.authenticated(), "Evidence checkpoints require a verified HTTP operator credential; stdio has no persistent authority and cannot checkpoint, resume or list checkpoints");
		let config = runtime::runtime_config()?;
		Ok(Self {
			state_dir: config.state_dir.clone(),
			owner: owner.owner().to_owned(),
			policy: runtime::request_results::policy_binding()?,
		})
	}
}

pub(super) async fn checkpoint(
	session: Arc<EvidenceSession>,
	owner: OwnerScope,
	cancellation: CancellationToken,
	admission: Arc<AdmissionPermit>,
) -> Result<String> {
	let scope = Scope::current(&owner)?;
	#[cfg(target_os = "linux")]
	return platform::checkpoint(scope, session, cancellation, admission).await;
	#[cfg(not(target_os = "linux"))]
	{
		let _ = (
			scope.state_dir,
			scope.owner,
			scope.policy,
			session,
			cancellation,
			admission,
		);
		anyhow::bail!("native Evidence checkpoint durability is implemented on Linux only")
	}
}

pub(super) async fn resume(
	params: ResumeParams,
	session: Arc<EvidenceSession>,
	owner: OwnerScope,
	cancellation: CancellationToken,
	admission: Arc<AdmissionPermit>,
) -> Result<String> {
	let scope = Scope::current(&owner)?;
	#[cfg(target_os = "linux")]
	return platform::resume(scope, params, session, cancellation, admission).await;
	#[cfg(not(target_os = "linux"))]
	{
		let _ = (
			scope.state_dir,
			scope.owner,
			scope.policy,
			params,
			session,
			cancellation,
			admission,
		);
		anyhow::bail!("native Evidence checkpoint durability is implemented on Linux only")
	}
}

pub(super) async fn list(
	params: ListParams,
	owner: OwnerScope,
	cancellation: CancellationToken,
	admission: Arc<AdmissionPermit>,
) -> Result<String> {
	let scope = Scope::current(&owner)?;
	#[cfg(target_os = "linux")]
	return platform::list(scope, params, cancellation, admission).await;
	#[cfg(not(target_os = "linux"))]
	{
		let _ = (
			scope.state_dir,
			scope.owner,
			scope.policy,
			params,
			cancellation,
			admission,
		);
		anyhow::bail!("native Evidence checkpoint durability is implemented on Linux only")
	}
}
