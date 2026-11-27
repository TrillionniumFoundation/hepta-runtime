// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Typed F32 research operations admitted by an existing REA model session.
//! Callers select a session and tensor scope, never a path, state directory or executable.

use anyhow::{anyhow, bail, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use crate::mcp::{
	runtime::effect_owner_fence::AdmissionPermit,
	weight_config,
	weight_guard::{Constraint, GuardedPatchParams, Objective},
	weight_tensor::ExactElementEdit,
};

#[path = "rea_model_session_smallhcsn.rs"]
pub(in crate::mcp) mod smallhcsn;
#[path = "rea_model_session_weight_transaction.rs"]
mod transaction;

/// Only this selected F32 matrix may be edited; the separate stored bias is read-only.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadoutScope {
	pub weight_tensor: String,
	pub weight_payload_sha256: String,
	pub bias_tensor: String,
	pub bias_payload_sha256: String,
	pub outputs: usize,
	pub columns: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct F32GuardInput {
	pub edits: Vec<ExactElementEdit>,
	pub inputs: Vec<Vec<f32>>,
	pub bias: Vec<f32>,
	pub objective: Objective,
	pub minimum_gain: f64,
	pub constraints: Vec<Constraint>,
	/// Required exact F32 update radius for this selected matrix only.
	pub maximum_update_l2_norm: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionWeightOperation {
	/// Authenticate the source and return its bound original-intent ID without a forward or write.
	#[serde(rename = "f32_prepare")]
	Prepare { request: Box<F32GuardInput> },
	/// One fixed candidate. Both passing and failing candidates receive a canonical inverse.
	#[serde(rename = "f32_roundtrip")]
	Roundtrip {
		request: Box<F32GuardInput>,
		/// Exact ID returned by f32_prepare; changed bytes, owner, policy or source code fail closed.
		expected_journal_id: String,
	},
	/// Restore the exact original session-bound intent without opening its source path.
	#[serde(rename = "f32_recover")]
	Recover {
		journal_id: String,
		expected_candidate_sha256: String,
		candidate_artifact_id: Option<String>,
	},
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SessionWeightParams {
	/// Existing retained session under the server-resolved owner and exact current policy.
	pub session_id: String,
	pub parent_sha256: String,
	pub readout: ReadoutScope,
	pub operation: SessionWeightOperation,
}

/// The original F32 shape remains byte-for-byte compatible. The hidden profile is
/// a separate closed wire shape and cannot supply a readout scope or an authority.
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(untagged)]
#[schemars(extend("type" = "object"))]
pub enum SessionWeightRequest {
	F32(SessionWeightParams),
	SmallHcsn(smallhcsn::Params),
}

struct Lease {
	owner: String,
}

/// Server-created capability. No Deserialize implementation or public constructor exists.
/// The retained task owns this lease and the existing effect-owner admission together.
#[derive(Clone, Serialize)]
pub(in crate::mcp) struct SessionAuthority {
	schema: &'static str,
	session_id: String,
	owner_sha256: String,
	policy_sha256: String,
	credential_bound: bool,
	parent_sha256: String,
	source_path: String,
	allowed_readout: ReadoutScope,
	#[serde(skip)]
	lease: Arc<Lease>,
}

impl SessionAuthority {
	pub(in crate::mcp) async fn revalidate(&self) -> Result<()> {
		let scope = super::Scope::current(&self.lease.owner)?;
		let (_, manifest) = super::load(&scope, &self.session_id).await?;
		if manifest.owner_sha256 != self.owner_sha256
			|| manifest.policy_sha256 != self.policy_sha256
			|| manifest.source_sha256 != self.parent_sha256
			|| manifest.source_path != self.source_path
		{
			bail!("REA session authority was revoked or its immutable binding changed");
		}
		Ok(())
	}

	pub(in crate::mcp) fn authorize_guard(&self, guard: &GuardedPatchParams) -> Result<()> {
		let selected = &self.allowed_readout;
		let radius = guard.max_update_l2_norm.ok_or_else(|| {
			anyhow!("session-bound F32 research requires an explicit exact update radius")
		})?;
		if guard.patch.path != self.source_path
			|| guard.patch.expected_sha256 != self.parent_sha256
			|| guard.patch.tensor_name != selected.weight_tensor
			|| !(1..=1024).contains(&guard.patch.edits.len())
			|| guard.patch.edits.iter().any(|edit| {
				edit.index >= (selected.outputs * selected.columns) as u64
					|| edit.expected_hex.len() != 8
					|| edit.replacement_hex.len() != 8
			}) || !radius.is_finite()
			|| radius < 0.0
		{
			bail!("guard exceeds the admitted session parent, F32 tensor scope or radius");
		}
		crate::mcp::weight_forward::check_inputs(
			&guard.inputs,
			guard.bias.as_deref(),
			selected.outputs,
			selected.columns,
		)?;
		if guard.bias.as_ref().map(Vec::len) != Some(selected.outputs) {
			bail!("session-bound guard requires the complete selected stored bias");
		}
		Ok(())
	}

	pub(in crate::mcp) fn check_bias_binding(
		&self,
		binding: &crate::mcp::weight_guard::source_bound_f32::BiasBinding,
	) -> Result<()> {
		if binding.tensor_name != self.allowed_readout.bias_tensor
			|| binding.payload_sha256 != self.allowed_readout.bias_payload_sha256
		{
			bail!("recovery bias differs from the original session tensor scope");
		}
		Ok(())
	}
}

fn validate_readout(selected: &ReadoutScope) -> Result<()> {
	if selected.weight_tensor.is_empty()
		|| selected.bias_tensor.is_empty()
		|| selected.weight_tensor == selected.bias_tensor
		|| selected.weight_tensor.len() > 1024
		|| selected.bias_tensor.len() > 1024
		|| !weight_config::valid_sha256(&selected.weight_payload_sha256)
		|| !weight_config::valid_sha256(&selected.bias_payload_sha256)
		|| !(1..=4096).contains(&selected.outputs)
		|| !(1..=4096).contains(&selected.columns)
		|| selected.outputs * selected.columns > 1_048_576
	{
		bail!("session research requires two distinct bounded F32 tensor bindings");
	}
	Ok(())
}

async fn admit(
	params: &SessionWeightParams,
	owner: &str,
	credential_bound: bool,
) -> Result<SessionAuthority> {
	validate_readout(&params.readout)?;
	if !weight_config::valid_sha256(&params.parent_sha256) {
		bail!("session research requires the complete parent SHA-256");
	}
	let scope = super::Scope::current(owner)?;
	let (directory, manifest) = super::load(&scope, &params.session_id).await?;
	if manifest.source_sha256 != params.parent_sha256
		|| manifest.byte_length > 2 * 1024 * 1024 * 1024
	{
		bail!("session parent differs or exceeds the existing 2 GiB F32 owner budget");
	}
	for (name, shape, elements) in [
		(
			&params.readout.weight_tensor,
			vec![
				params.readout.outputs.to_string(),
				params.readout.columns.to_string(),
			],
			params.readout.outputs * params.readout.columns,
		),
		(
			&params.readout.bias_tensor,
			vec![params.readout.outputs.to_string()],
			params.readout.outputs,
		),
	] {
		let row = super::index::tensor(&directory, &manifest, name).await?;
		if row["name"] != *name
			|| row["dtype"] != "F32"
			|| row["shape"] != json!(shape)
			|| row["storage_length_verified"] != true
			|| row["byte_length"].as_u64() != Some((elements * 4) as u64)
		{
			bail!("requested F32 readout scope differs from the authenticated session index");
		}
	}
	Ok(SessionAuthority {
		schema: "hepta.rea.session-weight-authority.v1",
		session_id: params.session_id.clone(),
		owner_sha256: manifest.owner_sha256,
		policy_sha256: manifest.policy_sha256,
		credential_bound,
		parent_sha256: manifest.source_sha256,
		source_path: manifest.source_path,
		allowed_readout: params.readout.clone(),
		lease: Arc::new(Lease {
			owner: owner.into(),
		}),
	})
}

struct BoundedRequest(usize);
impl Write for BoundedRequest {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		if bytes.len() > (1024 * 1024usize).saturating_sub(self.0) {
			return Err(io::Error::other("REA weight request exceeds 1 MiB"));
		}
		self.0 += bytes.len();
		Ok(bytes.len())
	}
	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

/// The MCP server supplies owner from its authenticated session context, never JSON.
/// Research only: this route cannot choose an executable, publish a live pointer or adopt a model.
pub(in crate::mcp) async fn run(
	params: SessionWeightRequest,
	owner: &crate::mcp::runtime::caller_scope::OwnerScope,
	owner_admission: AdmissionPermit,
	deadline: tokio::time::Instant,
) -> Result<String> {
	match params {
		SessionWeightRequest::F32(params) => run_for_owner(
			params, owner.owner(), owner.authenticated(), owner_admission, deadline,
		).await,
		SessionWeightRequest::SmallHcsn(params) => tokio::time::timeout_at(
			deadline,
			smallhcsn::run(params, owner.owner(), owner.authenticated(), owner_admission),
		).await.context("SmallHCSN response deadline exceeded; the admitted original owner task may still finish; recover only its prepared journal identity")?,
	}
}

async fn run_for_owner(
	params: SessionWeightParams,
	owner: &str,
	credential_bound: bool,
	owner_admission: AdmissionPermit,
	deadline: tokio::time::Instant,
) -> Result<String> {
	// The MCP entry creates this cutoff before fence admission. Capacity waiting cannot
	// restart it; after publication the retained owner task still completes compensation.
	tokio::time::timeout_at(
		deadline,
		execute_for_owner(params, owner, credential_bound, owner_admission),
	)
	.await
	.context("session weight response deadline exceeded; an admitted original owner task may still finish; recover only the prepared journal identity")?
}

async fn execute_for_owner(
	params: SessionWeightParams,
	owner: &str,
	credential_bound: bool,
	owner_admission: AdmissionPermit,
) -> Result<String> {
	serde_json::to_writer(&mut BoundedRequest(0), &params)?;
	let authority = tokio::time::timeout(
		Duration::from_secs(60),
		admit(&params, owner, credential_bound),
	)
	.await
	.context("REA weight session admission exceeded 60 seconds; no effect requested")??;
	let authority_sha = super::hash(&serde_json::to_vec(&authority)?);
	let session_id = params.session_id.clone();
	let result = match params.operation {
		SessionWeightOperation::Prepare { request } => {
			let _owner_admission = owner_admission;
			transaction::prepare(*request, authority).await?
		}
		SessionWeightOperation::Roundtrip {
			request,
			expected_journal_id,
		} => {
			transaction::roundtrip(*request, expected_journal_id, authority, owner_admission)
				.await?
		}
		SessionWeightOperation::Recover {
			journal_id,
			expected_candidate_sha256,
			candidate_artifact_id,
		} => {
			crate::mcp::weight_artifact::cohort::f32_recovery::run_for_session(
				crate::mcp::weight_artifact::cohort::f32_recovery::RecoveryParams {
					journal_id,
					original_source_sha256: params.parent_sha256,
					expected_candidate_sha256,
					candidate_artifact_id,
					bias_binding: crate::mcp::weight_guard::source_bound_f32::BiasBinding {
						tensor_name: params.readout.bias_tensor,
						payload_sha256: params.readout.bias_payload_sha256,
					},
				},
				authority,
				owner_admission,
			)
			.await?
		}
	};
	let report = json!({
		"schema":"hepta.rea.session-weight-research.v1","session_id":session_id,
		"session_authority_sha256":authority_sha,"result":result,
		"credential_metadata_resume":credential_bound,"authenticated_chatgpt_caller_isolation":false,
		"authorization":"existing REA session owner and exact current policy; selected F32 matrix only",
		"paths_derived_from_session":true,"accepted_for_activation":false,
		"full_model_executed":false,"feature_provenance_verified":false,
		"production_eligible":false,"automatic_retry":false,
		"reconciliation":"reuse the original session-bound journal identity for explicit restore; do not relaunch an uncertain roundtrip"
	});
	// Preserve actual owner identities even when a declared constraint list makes the detailed
	// report exceed the model-facing wire budget. No result store or replay is introduced.
	let text = serde_json::to_string(&report)?;
	let wire = rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(&text)]);
	if serde_json::to_vec(&wire)?.len() <= 60 * 1024 {
		return Ok(text);
	}
	serde_json::to_string(&json!({
		"schema":"hepta.rea.session-weight-research.v1","session_id":session_id,
		"session_authority_sha256":authority_sha,"detail_omitted_for_wire_budget":true,
		"credential_metadata_resume":credential_bound,"authenticated_chatgpt_caller_isolation":false,
		"journal_id":report["result"]["journal_id"],
		"candidate":report["result"]["candidate"],
		"restoration":report["result"]["restoration"],
		"restoration_verified":report["result"]["restoration_verified"],
		"accepted_for_activation":false,"production_eligible":false,"automatic_retry":false
	}))
	.context("REA research identity receipt serialization failed")
}

#[cfg(all(test, target_os = "linux"))]
#[path = "rea_model_session_weight_tests.rs"]
mod tests;
