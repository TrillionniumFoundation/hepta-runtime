// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Shared 40-coordinate sender proposals from actual parent words and actual normalized input keys.
//! Targets and the parent-correct partition remain explicit caller declarations. A trace hash alone
//! does not authenticate them. The original owner must still admit, evaluate and inverse the edits.

use anyhow::{ensure, Context, Result};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

use super::{
	weight_config,
	weight_hidden_scope::{Coordinate, Edit, TargetDeclaration},
	weight_norm,
	weight_smallhcsn::{self, BoundModel},
};

#[path = "weight_smallhcsn_proposal_math.rs"]
mod math;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Dose {
	Quarter,
	Full,
}

impl Dose {
	fn factor(self) -> f64 {
		match self {
			Self::Quarter => 0.25,
			Self::Full => 1.0,
		}
	}
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompileParams {
	pub parent_sha256: String,
	pub input_sha256: String,
	pub trace_sha256: String,
	pub target_source: TargetDeclaration,
	/// All 80 queries; this is a declared supervision partition, not independently measured truth.
	pub parent_correct: Vec<bool>,
	/// Exactly 480 [sender0..3] rows, ordered slow tick0,2,4 / query0..79 / choice0,1.
	/// Protected query targets must be zero. Failed rows declare desired changes in preactivation.
	pub target_delta_z: Vec<[f64; 4]>,
	pub maximum_update_l2_norm: f64,
	pub dose: Dose,
}

/// No Deserialize: only the checked compiler can construct this in-memory proposal.
pub struct Proposal {
	edits: Vec<Edit>,
	evidence: Value,
}

impl Proposal {
	pub fn into_parts(self) -> (Vec<Edit>, Value) {
		(self.edits, self.evidence)
	}
}

fn flat_matrix(values: &[f64; 40]) -> math::Matrix {
	let mut result = [[0.0; 4]; 10];
	for sender in 0..4 {
		for column in 0..9 {
			result[column][sender] = values[sender * 9 + column];
		}
		result[9][sender] = values[36 + sender];
	}
	result
}

fn flatten(values: &math::Matrix) -> [f64; 40] {
	let mut result = [0.0; 40];
	for sender in 0..4 {
		for column in 0..9 {
			result[sender * 9 + column] = values[column][sender];
		}
		result[36 + sender] = values[9][sender];
	}
	result
}

pub fn compile(params: &CompileParams, model: &BoundModel, raw_input: &[u8]) -> Result<Proposal> {
	compile_with_deadline(
		params,
		model,
		raw_input,
		Instant::now() + Duration::from_secs(5),
	)
}

pub fn compile_with_deadline(
	params: &CompileParams,
	model: &BoundModel,
	raw_input: &[u8],
	deadline: Instant,
) -> Result<Proposal> {
	let started = Instant::now();
	ensure!(started < deadline, "sender proposal deadline exhausted");
	for value in [
		&params.parent_sha256,
		&params.input_sha256,
		&params.trace_sha256,
		&params.target_source.source_sha256,
	] {
		ensure!(
			weight_config::valid_sha256(value),
			"sender proposal commitment required"
		);
	}
	ensure!(
		!params.target_source.description.is_empty()
			&& params.target_source.description.len() <= 4096,
		"bounded nonempty target declaration required"
	);
	ensure!(
		model.canonical_sha256() == params.parent_sha256
			&& model.artifact_sha256() == params.parent_sha256,
		"proposal requires the actual complete canonical parent, not an admitted readout candidate"
	);
	ensure!(
		model.input_sha256() == params.input_sha256
			&& weight_smallhcsn::sha(raw_input) == params.input_sha256,
		"actual raw input identity differs from parent binding"
	);
	let inputs = weight_smallhcsn::inputs(raw_input)?;
	ensure!(
		inputs.queries() == 80
			&& params.parent_correct.len() == 80
			&& params.target_delta_z.len() == 480,
		"fixed 80-query, three-slow-tick shared proposal profile required"
	);
	ensure!(
		params.parent_correct.iter().any(|v| *v) && params.parent_correct.iter().any(|v| !*v),
		"both declared failed and protected queries required"
	);
	let parent = model.sender_drive_f32()?;
	let mut failed = Vec::new();
	let mut protected = Vec::new();
	for (index, target) in params.target_delta_z.iter().enumerate() {
		ensure!(
			Instant::now() < deadline,
			"sender proposal input deadline exhausted"
		);
		let tick = 2 * (index / 160);
		let query = (index % 160) / 2;
		let choice = index % 2;
		let key = inputs
			.normalized_sender_key(query, choice, tick)?
			.map(f64::from);
		if params.parent_correct[query] {
			ensure!(
				target.iter().all(|v| *v == 0.0),
				"protected query residual targets must be zero"
			);
			protected.push(key);
		} else {
			failed.push(math::Observation {
				key,
				residual: *target,
			});
		}
	}
	let solution = math::fit(&failed, &protected, params.maximum_update_l2_norm, deadline)
		.map_err(anyhow::Error::msg)?;
	let flat = flatten(&solution.delta);
	let dose = params.dose.factor();
	let requested_norm = solution.norm * dose;
	let mut scale = if requested_norm == 0.0 {
		1.0
	} else {
		(params.maximum_update_l2_norm * (1.0 - 2.0_f64.powi(-16)) / requested_norm).min(1.0)
	};
	let initial_scale = scale;
	let mut accepted = None;
	for corrections in 0..=16 {
		ensure!(
			Instant::now() < deadline,
			"sender proposal F32 realization deadline exhausted"
		);
		let candidate = std::array::from_fn::<f32, 40, _>(|i| {
			(f64::from(parent[i]) + dose * scale * flat[i]) as f32
		});
		ensure!(
			candidate.iter().all(|v| v.is_finite()),
			"nonfinite F32 sender realization"
		);
		let exact = weight_norm::check_pairs(
			parent.into_iter().zip(candidate),
			params.maximum_update_l2_norm,
		)?;
		if exact.within_budget {
			accepted = Some((candidate, exact, corrections));
			break;
		}
		scale *= 1.0 - 2.0_f64.powi(-16);
	}
	let (candidate, exact, corrections) =
		accepted.context("F32 sender radius failed fixed inward corrections")?;
	let actual_delta =
		std::array::from_fn::<f64, 40, _>(|i| f64::from(candidate[i]) - f64::from(parent[i]));
	let realized_matrix = flat_matrix(&actual_delta);
	let realized_objective = math::objective(&failed, &protected, &realized_matrix);
	ensure!(
		realized_objective.is_finite()
			&& realized_objective
				<= solution.objective_before + 1e-10 * solution.objective_before.max(1.0),
		"represented F32 proposal fails its frozen quadratic objective gate"
	);
	let mut edits = Vec::with_capacity(40);
	for index in 0..40 {
		let coordinate = if index < 36 {
			Coordinate::Weight {
				row: index / 9,
				column: index % 9,
			}
		} else {
			Coordinate::Bias { row: index - 36 }
		};
		edits.push(Edit {
			coordinate,
			expected_hex: super::rea_model::digest_hex(&parent[index].to_le_bytes()),
			replacement_hex: super::rea_model::digest_hex(&candidate[index].to_le_bytes()),
		});
	}
	ensure!(
		Instant::now() < deadline,
		"sender proposal completion deadline exhausted"
	);
	let changed = parent
		.iter()
		.zip(candidate)
		.filter(|(before, after)| before.to_bits() != after.to_bits())
		.count();
	let evidence = json!({
		"schema":"hepta.weight.shared-sender-proposal.v1",
		"status":"PROPOSAL_COMPILED",
		"request_sha256":weight_smallhcsn::sha(&serde_json::to_vec(params)?),
		"actual_parent_sha256":model.artifact_sha256(),
		"actual_input_sha256":params.input_sha256,
		"parent_words_from_opaque_bound_model":true,
		"normalized_keys_from_actual_raw_input":true,
		"trace_sha256_declared":params.trace_sha256,
		"target_source_declared":params.target_source,
		"target_trace_and_parent_correctness_independently_verified":false,
		"target_is_proved_ndu_objective":false,
		"row_layout":"slow ticks 0,2,4; query-major choices 0,1; four sender targets",
		"failed_rows":failed.len(),"protected_rows":protected.len(),
		"supervised_quadratic_fit":true,"parameter_gradients_used":false,
		"objective":"mean_failed ||K D-R||_F^2 + .25 mean_protected ||K D||_F^2 + .02 ||D||_F^2",
		"ridge":math::RIDGE,"protection_weight":math::PROTECT,
		"regularized_width":10,"senders":4,"shared_coordinates":40,
		"unregularized_key_rank_certified":false,
		"solver":"fixed-size F64 Cholesky and at most 128 multiplier bisections",
		"linear_solves":solution.linear_solves,"bisections":solution.bisections,
		"minimum_cholesky_pivot":solution.minimum_cholesky_pivot,
		"multiplier":solution.multiplier,"surrogate_norm":solution.norm,
		"kkt_max_abs":solution.kkt_max_abs,"kkt_tolerance":solution.kkt_tolerance,
		"kkt_is_interval_certificate":false,
		"continuous_full_dose_objective":solution.objective_after,
		"zero_delta_objective":solution.objective_before,
		"represented_f32_objective":realized_objective,
		"dose":params.dose,"initial_rounding_scale":initial_scale,
		"final_rounding_scale":scale,"additional_inward_corrections":corrections,
		"actual_f32_budget":exact,"actual_changed_coordinates":changed,
		"future_recurrent_offsets_held_fixed_only_in_surrogate":true,
		"future_recurrent_offsets_preserved_in_full_model":false,
		"cost_independently_preserved":false,
		"parameter_optimality_for_full_model_proved":false,
		"model_forward_calls":0,"artifact_published":false,
		"original_owner_full_plan_and_evaluation_required":true,
		"production_eligible":false,"wall_seconds":started.elapsed().as_secs_f64()
	});
	Ok(Proposal { edits, evidence })
}
