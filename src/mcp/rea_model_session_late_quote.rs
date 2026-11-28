// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Fixed late-quote task-graph research authority from an existing retained REA session.
//! A serialized binding is evidence only; it cannot recreate the owner lease.

use anyhow::{bail, ensure, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

use crate::mcp::{
	runtime::effect_owner_fence::AdmissionPermit, weight_artifact::cohort, weight_config,
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FixedProfile {
	SmallhcsnLateQuoteMinMark4TaskRouteV1,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Input {
	/// One canonical profile JSON for the late-quote batch; at most 49,152 UTF-8 bytes.
	pub profile_json: String,
	/// HCSNIN1 late-quote input and normalizer bytes, lowercase hex; at most 65,536 decoded bytes.
	pub raw_input_hex: String,
	/// One canonical profile JSON for normal-route retention; at most 49,152 UTF-8 bytes.
	pub retention_profile_json: String,
	/// HCSNIN1 normal-route input and normalizer bytes, lowercase hex; at most 65,536 decoded bytes.
	pub retention_raw_input_hex: String,
	/// Required late-quote accuracy, from 1 through 100 percent. This is not a trading-profit target.
	pub minimum_accuracy_percent: u32,
	/// Finite nonnegative L2 radius for the four original F32 quote-coordinate words only.
	pub maximum_update_l2_norm: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
	/// Compile a source-bound semantic plan without a model forward or an artifact publication.
	#[serde(rename = "late_quote_compile")]
	Compile { request: Box<Input> },
	/// Bind both KEEP and EDIT capsules before any task-dependent selection or publication.
	#[serde(rename = "late_quote_prepare")]
	Prepare { request: Box<Input> },
	/// One bounded research attempt; all outcomes restore the original graph, route and weights.
	#[serde(rename = "late_quote_roundtrip")]
	Roundtrip {
		request: Box<Input>,
		/// The exact original request ID from preparation; never a fresh retry key.
		expected_journal_id: String,
	},
	/// Recover the original prepared plan. No replacement task, candidate or graph is accepted.
	#[serde(rename = "late_quote_recover")]
	Recover {
		journal_id: String,
		/// Digest of the original plan binding both possible capsules, not a selected weight SHA.
		expected_plan_sha256: String,
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

/// Only admission can construct this capability. Its original owner lease remains retained
/// until compensation and durable result publication have completed.
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
				&& (10..=131072).contains(&manifest.byte_length),
			"fixed late-quote session authority was revoked or changed"
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
			|| raw_input_hex.is_empty()
			|| raw_input_hex.len() > 131072
			|| !raw_input_hex.len().is_multiple_of(2)
			|| !raw_input_hex
				.bytes()
				.all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
		{
			bail!("fixed late-quote request exceeds its profile or raw byte scope");
		}
		let profile = crate::mcp::rea_evidence::parse_unique_json(profile_json.as_bytes())?;
		ensure!(
			profile["profiles"]
				.as_array()
				.is_some_and(|rows| rows.len() == 1),
			"late-quote admission requires exactly one canonical profile for each batch"
		);
		Ok(())
	}

	pub(in crate::mcp) fn authorize(&self, input: &Input) -> Result<()> {
		ensure!(
			(1..=100).contains(&input.minimum_accuracy_percent)
				&& input.maximum_update_l2_norm.is_finite()
				&& input.maximum_update_l2_norm >= 0.0,
			"fixed late-quote request differs from its goal or four-word radius scope"
		);
		self.authorize_data(&input.profile_json, &input.raw_input_hex)?;
		self.authorize_data(
			&input.retention_profile_json,
			&input.retention_raw_input_hex,
		)?;
		Ok(())
	}
}

async fn admit(params: &Params, owner: &str, credential_bound: bool) -> Result<Authority> {
	ensure!(
		weight_config::valid_sha256(&params.parent_sha256),
		"late-quote session requires a complete parent digest"
	);
	let scope = super::super::Scope::current(owner)?;
	let (directory, manifest) = super::super::load(&scope, &params.session_id).await?;
	ensure!(
		manifest.source_sha256 == params.parent_sha256
			&& manifest.tensor_count == 12
			&& (10..=131072).contains(&manifest.byte_length),
		"late-quote session source or fixed twelve-tensor budget differs"
	);
	for (name, shape, length) in [
		("body.input_mark.weight", vec!["4", "9"], 144u64),
		("body.readout.weight", vec!["2", "20"], 160u64),
	] {
		let row = super::super::index::tensor(&directory, &manifest, name).await?;
		ensure!(
			row["name"] == name
				&& row["dtype"] == "F32"
				&& row["shape"] == json!(shape)
				&& row["byte_length"].as_u64() == Some(length)
				&& row["storage_length_verified"] == true,
			"fixed mark/readout tensor differs from the authenticated REA index"
		);
	}
	Ok(Authority {
		schema: "hepta.rea.smallhcsn-late-quote-authority.v1",
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
	.context("fixed late-quote session admission exceeded sixty seconds")??;
	let authority_sha256 = super::super::hash(&serde_json::to_vec(&authority)?);
	let result = match params.operation {
		Operation::Compile { request } => {
			let _owner_admission = owner_admission;
			authority.authorize(&request)?;
			cohort::late_quote::compile(*request, authority).await?
		}
		Operation::Prepare { request } => {
			let _owner_admission = owner_admission;
			authority.authorize(&request)?;
			cohort::late_quote::prepare(*request, authority).await?
		}
		Operation::Roundtrip {
			request,
			expected_journal_id,
		} => {
			ensure!(
				weight_config::valid_sha256(&expected_journal_id),
				"late-quote roundtrip requires the original journal digest"
			);
			authority.authorize(&request)?;
			cohort::late_quote::roundtrip(*request, expected_journal_id, authority, owner_admission)
				.await?
		}
		Operation::Recover {
			journal_id,
			expected_plan_sha256,
		} => {
			ensure!(
				weight_config::valid_sha256(&journal_id)
					&& weight_config::valid_sha256(&expected_plan_sha256),
				"late-quote recovery requires the original journal and plan digests"
			);
			cohort::late_quote::recover(
				journal_id,
				expected_plan_sha256,
				authority,
				owner_admission,
			)
			.await?
		}
	};
	let report = json!({
		"schema":"hepta.rea.session-late-quote-research.v1",
		"session_id":params.session_id,"session_authority_sha256":authority_sha256,
		"fixed_scope":"smallhcsn_late_quote_min_mark4_task_route_v1","result":result,
		"credential_metadata_resume":credential_bound,"paths_derived_from_session":true,
		"accepted_for_activation":false,"production_eligible":false,
		"automatic_retry":false,"background_crash_recovery":false,
		"upstream_provenance_verified":false,"global_ndu_optimality_verified":false
	});
	let text = serde_json::to_string(&report)?;
	let wire = rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(&text)]);
	ensure!(
		serde_json::to_vec(&wire)?.len() <= 60 * 1024,
		"bounded late-quote identity receipt exceeded its wire budget; use the original journal ID"
	);
	Ok(text)
}

#[cfg(all(test, target_os = "linux"))]
pub(in crate::mcp) async fn admit_for_test(params: &Params, owner: &str) -> Result<Authority> {
	admit(params, owner, true).await
}
