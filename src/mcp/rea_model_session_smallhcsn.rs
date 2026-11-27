// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Fixed SmallHCSN sender authority derived from the retained REA session.
//! The serialized binding is evidence, never a deserializable permission token.

use anyhow::{bail, ensure, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

use crate::mcp::{
	runtime::effect_owner_fence::AdmissionPermit, weight_artifact::cohort, weight_config,
	weight_hidden_scope as hidden, weight_smallhcsn_proposal as proposal,
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FixedProfile {
	SmallhcsnCenteredSenderDriveAndBias40V1,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Input {
	/// The single canonical profile JSON; at most 49,152 UTF-8 bytes.
	pub profile_json: String,
	/// Original HCSNIN1 raw input and normalizer bytes, lowercase hex; at most 65,536 decoded bytes.
	pub raw_input_hex: String,
	/// The exact two-tensor F32 plan; target provenance remains a caller declaration.
	pub plan: hidden::PlanParams,
	/// Candidate MSE reduction required on this one fixed raw batch; accuracy may not decrease.
	pub minimum_mse_gain: f64,
	/// Optional native shared proposal. When present, admission recompiles it from actual
	/// parent/raw bytes and requires this plan to match; its declared targets remain unverified.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub proposal: Option<ProposalInput>,
	/// Optional conditional finite policy, bound to this native proposal and full verification budget.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub ndu: Option<crate::mcp::weight_smallhcsn_ndu::Request>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TargetRow {
	pub query: usize,
	pub choice: usize,
	pub tick: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProposalInput {
	/// Each target_delta_z row follows its explicit row_identities entry. The native
	/// adapter reorders these pairs to slow-tick/query/choice before the fixed solver.
	pub parameters: proposal::CompileParams,
	/// Exactly all 480 distinct (query0..79, choice0..1, tick0/2/4) rows.
	pub row_identities: Vec<TargetRow>,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompileInput {
	pub profile_json: String,
	pub raw_input_hex: String,
	pub proposal: ProposalInput,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
	#[serde(rename = "smallhcsn_plan")]
	Plan { request: Box<Input> },
	#[serde(rename = "smallhcsn_compile")]
	Compile { request: Box<CompileInput> },
	#[serde(rename = "smallhcsn_prepare")]
	Prepare { request: Box<Input> },
	#[serde(rename = "smallhcsn_roundtrip")]
	Roundtrip {
		request: Box<Input>,
		/// Exact original request ID returned by preparation, never a fresh retry key.
		expected_journal_id: String,
	},
	#[serde(rename = "smallhcsn_recover")]
	Recover {
		/// Original 64-character intent identity. No replacement profile, inputs or plan is accepted.
		journal_id: String,
		expected_candidate_sha256: String,
	},
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Params {
	pub session_id: String,
	pub parent_sha256: String,
	pub profile: FixedProfile,
	pub operation: Operation,
}

/// No Deserialize implementation and no public constructor. The owner lease remains inside
/// the original retained task until compensation and its durable result have completed.
#[derive(Clone, Serialize)]
pub(in crate::mcp) struct Authority {
	schema: &'static str,
	session_id: String,
	owner_sha256: String,
	policy_sha256: String,
	credential_bound: bool,
	parent_sha256: String,
	source_path: String,
	fixed_profile: FixedProfile,
	#[serde(skip)]
	lease: Arc<super::Lease>,
}

impl Authority {
	pub(in crate::mcp) async fn revalidate(&self) -> Result<()> {
		let scope = super::super::Scope::current(&self.lease.owner)?;
		let (_, manifest) = super::super::load(&scope, &self.session_id).await?;
		ensure!(
			manifest.owner_sha256 == self.owner_sha256
				&& manifest.policy_sha256 == self.policy_sha256
				&& manifest.source_sha256 == self.parent_sha256
				&& manifest.source_path == self.source_path
				&& manifest.tensor_count == 12
				&& manifest.byte_length <= 131072,
			"fixed SmallHCSN session authority was revoked or changed"
		);
		Ok(())
	}

	pub(in crate::mcp) fn parent_sha256(&self) -> &str {
		&self.parent_sha256
	}

	pub(in crate::mcp) fn source_path(&self) -> &str {
		&self.source_path
	}

	pub(in crate::mcp) fn binding(&self) -> Result<Value> {
		Ok(serde_json::to_value(self)?)
	}

	pub(in crate::mcp) fn authorize_data(
		&self,
		profile_json: &str,
		raw_input_hex: &str,
	) -> Result<()> {
		if profile_json.is_empty()
			|| profile_json.len() > 49152
			|| raw_input_hex.len() > 131072
			|| raw_input_hex.is_empty()
			|| !raw_input_hex.len().is_multiple_of(2)
			|| !raw_input_hex
				.bytes()
				.all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
		{
			bail!("fixed SmallHCSN request exceeds its profile or raw byte scope");
		}
		let profile = crate::mcp::rea_evidence::parse_unique_json(profile_json.as_bytes())?;
		ensure!(
			profile["profiles"]
				.as_array()
				.is_some_and(|rows| rows.len() == 1),
			"session SmallHCSN admission requires exactly one canonical profile"
		);
		Ok(())
	}

	pub(in crate::mcp) fn authorize(&self, input: &Input) -> Result<()> {
		ensure!(
			input.plan.parent_sha256 == self.parent_sha256
				&& input.minimum_mse_gain.is_finite()
				&& input.minimum_mse_gain >= 0.0,
			"fixed SmallHCSN request differs from its parent or objective scope"
		);
		self.authorize_data(&input.profile_json, &input.raw_input_hex)?;
		ensure!(
			input.ndu.is_none() || input.proposal.is_some(),
			"finite-policy execution requires a native source-bound proposal"
		);
		if let Some(proposal) = &input.proposal {
			ensure!(
				proposal.parameters.parent_sha256 == self.parent_sha256
					&& proposal.parameters.input_sha256 == input.plan.input_sha256
					&& proposal.parameters.maximum_update_l2_norm.to_bits()
						== input.plan.maximum_update_l2_norm.to_bits(),
				"native proposal differs from the admitted parent, raw input or exact radius"
			);
		}
		Ok(())
	}
}

async fn admit(params: &Params, owner: &str, credential_bound: bool) -> Result<Authority> {
	ensure!(
		weight_config::valid_sha256(&params.parent_sha256),
		"SmallHCSN session requires a complete parent digest"
	);
	let scope = super::super::Scope::current(owner)?;
	let (directory, manifest) = super::super::load(&scope, &params.session_id).await?;
	ensure!(
		manifest.source_sha256 == params.parent_sha256
			&& manifest.tensor_count == 12
			&& (10..=131072).contains(&manifest.byte_length),
		"SmallHCSN session source or fixed twelve-tensor budget differs"
	);
	for (name, shape, length) in [
		(hidden::WEIGHT_NAME, vec!["4", "9"], 144u64),
		(hidden::BIAS_NAME, vec!["4"], 16u64),
	] {
		let row = super::super::index::tensor(&directory, &manifest, name).await?;
		ensure!(
			row["name"] == name
				&& row["dtype"] == "F32"
				&& row["shape"] == json!(shape)
				&& row["byte_length"].as_u64() == Some(length)
				&& row["storage_length_verified"] == true,
			"fixed sender tensor differs from the authenticated REA index"
		);
	}
	Ok(Authority {
		schema: "hepta.rea.smallhcsn-sender-authority.v1",
		session_id: params.session_id.clone(),
		owner_sha256: manifest.owner_sha256,
		policy_sha256: manifest.policy_sha256,
		credential_bound,
		parent_sha256: manifest.source_sha256,
		source_path: manifest.source_path,
		fixed_profile: params.profile,
		lease: Arc::new(super::Lease {
			owner: owner.into(),
		}),
	})
}

pub(super) async fn run(
	params: Params,
	owner: &str,
	credential_bound: bool,
	owner_admission: AdmissionPermit,
) -> Result<String> {
	serde_json::to_writer(&mut super::BoundedRequest(0), &params)?;
	let authority = tokio::time::timeout(
		Duration::from_secs(60),
		admit(&params, owner, credential_bound),
	)
	.await
	.context("fixed SmallHCSN session admission exceeded sixty seconds")??;
	let authority_sha256 = super::super::hash(&serde_json::to_vec(&authority)?);
	let result = match params.operation {
		Operation::Plan { request } => {
			let _owner_admission = owner_admission;
			cohort::smallhcsn::plan(*request, authority).await?
		}
		Operation::Compile { request } => {
			let _owner_admission = owner_admission;
			cohort::smallhcsn::compile(*request, authority).await?
		}
		Operation::Prepare { request } => {
			let _owner_admission = owner_admission;
			cohort::smallhcsn::prepare(*request, authority).await?
		}
		Operation::Roundtrip {
			request,
			expected_journal_id,
		} => {
			cohort::smallhcsn::roundtrip(*request, expected_journal_id, authority, owner_admission)
				.await?
		}
		Operation::Recover {
			journal_id,
			expected_candidate_sha256,
		} => {
			cohort::smallhcsn::recover(
				journal_id,
				expected_candidate_sha256,
				authority,
				owner_admission,
			)
			.await?
		}
	};
	let report = json!({
		"schema":"hepta.rea.session-smallhcsn-research.v1",
		"session_id":params.session_id,"session_authority_sha256":authority_sha256,
		"fixed_scope":"smallhcsn_centered_sender_drive_and_bias40_v1","result":result,
		"credential_metadata_resume":credential_bound,"paths_derived_from_session":true,
		"accepted_for_activation":false,"production_eligible":false,
		"automatic_retry":false,"background_crash_recovery":false,
		"upstream_provenance_verified":false,"global_ndu_optimality_verified":false
	});
	let text = serde_json::to_string(&report)?;
	let wire = rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(&text)]);
	ensure!(
		serde_json::to_vec(&wire)?.len() <= 60 * 1024,
		"bounded SmallHCSN identity receipt exceeded its wire budget; use the original journal ID"
	);
	Ok(text)
}

#[cfg(all(test, target_os = "linux"))]
pub(in crate::mcp) async fn admit_for_test(params: &Params, owner: &str) -> Result<Authority> {
	admit(params, owner, true).await
}
