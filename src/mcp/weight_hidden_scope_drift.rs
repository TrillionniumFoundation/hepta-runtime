// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Closed-form interior drift inversion, with a separate actual-F32 realization report.
//! This does not fit shared weights or hold future recurrent offsets fixed in a real rollout.

use super::{check_deadline, digest, TargetDeclaration, MAX_SECONDS};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
	collections::BTreeSet,
	time::{Duration, Instant},
};

const BASE: f32 = -0.2;
const SCALE: f32 = 0.15;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum F32Realization {
	ReportResidual,
	RequireBitExact,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
	pub query: usize,
	pub choice: usize,
	pub tick: usize,
	pub sender: usize,
	pub desired_drift: f64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompileParams {
	pub parent_sha256: String,
	pub input_sha256: String,
	pub target_source: TargetDeclaration,
	pub f32_realization: F32Realization,
	pub targets: Vec<Target>,
}

pub fn compile(params: &CompileParams) -> Result<Value> {
	compile_with_deadline(params, Instant::now() + Duration::from_secs(MAX_SECONDS))
}
pub fn compile_with_deadline(params: &CompileParams, deadline: Instant) -> Result<Value> {
	check_deadline(deadline)?;
	ensure!(
		super::super::weight_config::valid_sha256(&params.parent_sha256)
			&& super::super::weight_config::valid_sha256(&params.input_sha256),
		"drift source identities"
	);
	params.target_source.validate()?;
	ensure!(
		(1..=1920).contains(&params.targets.len()),
		"bounded explicit slow-tick targets required"
	);
	let mut seen = BTreeSet::new();
	let mut rows = Vec::with_capacity(params.targets.len());
	for target in &params.targets {
		check_deadline(deadline)?;
		ensure!(
			target.query < 80
				&& target.choice < 2
				&& target.sender < 4
				&& matches!(target.tick, 0 | 2 | 4),
			"target outside fixed sender/slow-clock profile"
		);
		ensure!(
			seen.insert((target.query, target.choice, target.tick, target.sender)),
			"duplicate drift target"
		);
		ensure!(target.desired_drift.is_finite(), "nonfinite desired drift");
		let unit = (target.desired_drift - BASE as f64) / SCALE as f64;
		ensure!(unit.is_finite() && unit.abs() < 1.0,
            "target outside strict interior real drift contract; no saturation projection was authorized");
		let preactivation = unit.atanh();
		let pre_f32 = preactivation as f32;
		ensure!(
			preactivation.is_finite() && pre_f32.is_finite(),
			"nonfinite inverse preactivation"
		);
		let realized = BASE + SCALE * pre_f32.tanh();
		let bit_exact = target.desired_drift == (target.desired_drift as f32) as f64
			&& realized.to_bits() == (target.desired_drift as f32).to_bits();
		if matches!(params.f32_realization, F32Realization::RequireBitExact) {
			ensure!(bit_exact, "compiled F32 preactivation does not exactly realize target; no rounding search performed");
		}
		rows.push(json!({"query":target.query,"choice":target.choice,"tick":target.tick,"sender":target.sender,
            "desired_drift_f64":target.desired_drift,"preactivation_f64":preactivation,
            "preactivation_f32_le_hex":super::super::rea_model::digest_hex(&pre_f32.to_le_bytes()),
            "realized_drift_f32_le_hex":super::super::rea_model::digest_hex(&realized.to_le_bytes()),
            "realized_drift_f64":realized as f64,"f32_residual":realized as f64-target.desired_drift,
            "actual_f32_target_bit_exact":bit_exact,
            "real_inverse_reconstruction_residual":BASE as f64+SCALE as f64*preactivation.tanh()-target.desired_drift}));
	}
	check_deadline(deadline)?;
	Ok(
		json!({"schema":"hepta.weight.sender-drift-target-compilation.v1",
        "request_sha256":digest(&serde_json::to_vec(params)?),"parent_sha256_declared":params.parent_sha256,
        "input_sha256_declared":params.input_sha256,"target_source_declared":params.target_source,
        "target_source_independently_verified":false,"target_is_proved_ndu_objective":false,
        "constants":"real inversion of the fixed model's F32 base/scale widened exactly to F64",
        "base_drift_f32_le_hex":super::super::rea_model::digest_hex(&BASE.to_le_bytes()),
        "drift_scale_f32_le_hex":super::super::rea_model::digest_hex(&SCALE.to_le_bytes()),
        "cost_independently_preserved":false,"shared_weight_solution_computed":false,
        "future_recurrent_offset_preservation_proved":false,"model_forward_executed":false,
        "f32_realization_policy":params.f32_realization,"rows":rows,"production_eligible":false}),
	)
}
