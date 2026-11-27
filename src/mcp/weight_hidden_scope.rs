// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Bounded sender-drive plans share the existing atomic cohort owner.
//! A caller's target declaration is never evidence of task or NDU optimality.

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
	collections::BTreeSet,
	path::Path,
	time::{Duration, Instant},
};

use super::{weight_artifact::cohort, weight_config, weight_norm, weight_tensor::ExactElementEdit};

#[path = "weight_hidden_scope_drift.rs"]
pub mod drift;
#[path = "weight_hidden_scope_layout.rs"]
mod layout;
#[cfg(test)]
#[path = "weight_hidden_scope_tests.rs"]
mod tests;

pub const WEIGHT_NAME: &str = "body.input_drive.weight";
pub const BIAS_NAME: &str = "body.input_drive.bias";
const MAX_SECONDS: u64 = 5;

fn digest(bytes: &[u8]) -> String {
	super::rea_model::digest_hex(&Sha256::digest(bytes))
}
fn check_deadline(deadline: Instant) -> Result<()> {
	ensure!(Instant::now() < deadline, "hidden-scope deadline exceeded");
	Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetSourceKind {
	CallerSpecified,
	PinnedExternalReference,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetDeclaration {
	pub kind: TargetSourceKind,
	pub source_sha256: String,
	pub description: String,
}
impl TargetDeclaration {
	fn validate(&self) -> Result<()> {
		ensure!(
			weight_config::valid_sha256(&self.source_sha256),
			"target source digest"
		);
		ensure!(
			!self.description.is_empty() && self.description.len() <= 4096,
			"bounded nonempty target declaration required"
		);
		Ok(())
	}
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EditScope {
	SenderDriveAndBias,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "tensor", rename_all = "snake_case", deny_unknown_fields)]
pub enum Coordinate {
	Weight { row: usize, column: usize },
	Bias { row: usize },
}
impl Coordinate {
	fn site(&self) -> Result<(&'static str, usize)> {
		match self {
			Self::Weight { row, column } => {
				ensure!(
					*row < 4 && *column < 9,
					"sender weight coordinate outside 4x9"
				);
				Ok((WEIGHT_NAME, row * 9 + column))
			}
			Self::Bias { row } => {
				ensure!(*row < 4, "sender bias coordinate outside four units");
				Ok((BIAS_NAME, *row))
			}
		}
	}
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Edit {
	pub coordinate: Coordinate,
	pub expected_hex: String,
	pub replacement_hex: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlanParams {
	pub scope: EditScope,
	pub parent_sha256: String,
	pub candidate_sha256: String,
	pub header_sha256: String,
	pub input_sha256: String,
	pub allowed_coordinates: Vec<Coordinate>,
	pub edits: Vec<Edit>,
	pub maximum_update_l2_norm: f64,
	pub target_source: TargetDeclaration,
	pub identity: cohort::Identity,
}

/// Constructible only after complete parent admission and exact F32 budget checks.
pub struct PreparedPlan {
	params: PlanParams,
	expected_candidate: Vec<u8>,
	layout: layout::Layout,
	members: Vec<cohort::Member>,
	budget: Value,
	request_sha256: String,
}

/// Values decoded from the actual admitted candidate, not a floating-point proposal.
pub struct AdmittedHidden {
	pub weight: Vec<f64>,
	pub bias: Vec<f64>,
	pub evidence: Value,
}

pub fn prepare(params: &PlanParams, parent: &[u8]) -> Result<PreparedPlan> {
	prepare_with_deadline(
		params,
		parent,
		Instant::now() + Duration::from_secs(MAX_SECONDS),
	)
}

pub fn prepare_with_deadline(
	params: &PlanParams,
	parent: &[u8],
	deadline: Instant,
) -> Result<PreparedPlan> {
	check_deadline(deadline)?;
	ensure!(
		(10..=131072).contains(&parent.len()),
		"bounded canonical parent required"
	);
	for value in [
		&params.parent_sha256,
		&params.candidate_sha256,
		&params.header_sha256,
		&params.input_sha256,
		&params.identity.code_sha256,
		&params.identity.tensor_map_sha256,
		&params.identity.data_manifest_sha256,
		&params.identity.objective_sha256,
		&params.identity.dependency_manifest_sha256,
	] {
		ensure!(
			weight_config::valid_sha256(value),
			"complete hidden-scope identity required"
		);
	}
	params.target_source.validate()?;
	ensure!(
		digest(parent) == params.parent_sha256,
		"complete parent SHA differs"
	);
	ensure!(
		(1..=40).contains(&params.allowed_coordinates.len())
			&& (2..=40).contains(&params.edits.len()),
		"hidden scope is bounded to 40 F32 coordinates"
	);
	let mut allowed = BTreeSet::new();
	for coordinate in &params.allowed_coordinates {
		coordinate.site()?;
		ensure!(
			allowed.insert(coordinate.clone()),
			"duplicate allowed coordinate"
		);
	}
	let layout = layout::inspect(parent, &params.header_sha256)?;
	let mut expected_candidate = parent.to_vec();
	let mut seen = BTreeSet::new();
	let mut weight_edits = Vec::new();
	let mut bias_edits = Vec::new();
	let mut pairs = Vec::new();
	for edit in &params.edits {
		check_deadline(deadline)?;
		ensure!(
			allowed.contains(&edit.coordinate) && seen.insert(edit.coordinate.clone()),
			"duplicate or undeclared hidden edit coordinate"
		);
		let (name, index) = edit.coordinate.site()?;
		let before = layout::f32_word(&edit.expected_hex)?;
		let after = layout::f32_word(&edit.replacement_hex)?;
		let offset = layout.offset(name, index)?;
		ensure!(
			parent[offset..offset + 4] == before,
			"hidden edit before bytes differ"
		);
		expected_candidate[offset..offset + 4].copy_from_slice(&after);
		pairs.push((f32::from_le_bytes(before), f32::from_le_bytes(after)));
		let exact = ExactElementEdit {
			index: index as u64,
			expected_hex: edit.expected_hex.clone(),
			replacement_hex: edit.replacement_hex.clone(),
		};
		match &edit.coordinate {
			Coordinate::Weight { .. } => weight_edits.push(exact),
			Coordinate::Bias { .. } => bias_edits.push(exact),
		}
	}
	ensure!(!weight_edits.is_empty() && !bias_edits.is_empty(),
        "both sender weight and bias members require explicit edits; exact no-op elements are allowed");
	let budget = weight_norm::check_pairs(pairs, params.maximum_update_l2_norm)?;
	ensure!(
		budget.within_budget,
		"actual F32 hidden update exceeds exact global radius"
	);
	ensure!(
		digest(&expected_candidate) == params.candidate_sha256,
		"candidate commitment differs from exact declared edits"
	);
	let members = vec![
		cohort::Member {
			tensor_name: WEIGHT_NAME.into(),
			edits: weight_edits,
			maximum_update_l2_norm: params.maximum_update_l2_norm,
		},
		cohort::Member {
			tensor_name: BIAS_NAME.into(),
			edits: bias_edits,
			maximum_update_l2_norm: params.maximum_update_l2_norm,
		},
	];
	let request_sha256 = digest(&serde_json::to_vec(params)?);
	check_deadline(deadline)?;
	Ok(PreparedPlan {
		params: params.clone(),
		expected_candidate,
		layout,
		members,
		budget: serde_json::to_value(budget)?,
		request_sha256,
	})
}

impl PreparedPlan {
	/// The existing owner supplies confinement, atomic publication and its immutable inverse.
	/// This builder does not publish, infer authorization or verify declared objective provenance.
	pub fn cohort_request(&self, path: String, request_id: String) -> Result<cohort::PatchParams> {
		ensure!(
			Path::new(&path).is_absolute() && weight_config::valid_sha256(&request_id),
			"explicit parent path and exact owner request key required"
		);
		let mut identity = self.params.identity.clone();
		// The owner identity commits this complete typed plan, including caller declarations.
		identity.dependency_manifest_sha256 = self.request_sha256.clone();
		identity.objective_sha256 = digest(&serde_json::to_vec(&self.params.target_source)?);
		Ok(cohort::PatchParams {
			request_id,
			path,
			expected_sha256: self.params.parent_sha256.clone(),
			identity,
			members: self.members.clone(),
			maximum_update_l2_norm: self.params.maximum_update_l2_norm,
			training: cohort::TrainingContract::InferenceOnly,
		})
	}

	/// Rechecks the actual complete artifact; any extra tensor, metadata or padding change fails.
	pub fn admit(&self, candidate: &[u8]) -> Result<AdmittedHidden> {
		ensure!(
			candidate.len() == self.expected_candidate.len()
				&& digest(candidate) == self.params.candidate_sha256
				&& candidate == self.expected_candidate,
			"actual hidden candidate differs from declared bytes"
		);
		let decode = |name: &str, count: usize| -> Result<Vec<f64>> {
			(0..count)
				.map(|index| {
					let offset = self.layout.offset(name, index)?;
					let word: [u8; 4] = candidate[offset..offset + 4]
						.try_into()
						.context("candidate F32 word")?;
					let value = f32::from_le_bytes(word);
					ensure!(value.is_finite(), "nonfinite admitted hidden value");
					Ok(value as f64)
				})
				.collect()
		};
		let mut evidence = self.evidence();
		evidence["actual_candidate_verified"] = json!(true);
		evidence["all_other_bytes_preserved"] = json!(true);
		Ok(AdmittedHidden {
			weight: decode(WEIGHT_NAME, 36)?,
			bias: decode(BIAS_NAME, 4)?,
			evidence,
		})
	}

	pub fn evidence(&self) -> Value {
		json!({"schema":"hepta.weight.sender-drive-scope.v1","scope":"sender_drive_and_bias",
            "parent_sha256":self.params.parent_sha256,"candidate_sha256":self.params.candidate_sha256,
            "header_sha256":self.params.header_sha256,"input_sha256":self.params.input_sha256,
            "plan_sha256":self.request_sha256,"allowed_coordinates":self.params.allowed_coordinates,
            "edited_elements":self.params.edits.len(),"tensor_members":2,"actual_f32_budget":self.budget,
            "target_source_declared":self.params.target_source,"target_source_independently_verified":false,
            "target_is_proved_ndu_objective":false,"identity_declared":self.params.identity,
            "expected_candidate_other_bytes_preserved":true,"actual_candidate_verified":false,
            "all_other_bytes_preserved":null,"model_forward_executed":false,
            "new_model_owner":false,"production_eligible":false})
	}
}
