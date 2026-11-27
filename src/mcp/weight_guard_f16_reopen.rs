// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Re-read actual F16 coefficient bytes and compare their computed outputs with a typed plan.
//! A borrowed descriptor is not an artifact identity; the canonical owner admits that separately.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::time::{Duration, Instant};

use super::{
	bounded_digest, check_constraints, check_deadline, paired_predictions, prediction_bits_digest,
	score, source, validate, weight_forward, CoupledF16Evaluation, CoupledF16EvaluationParams,
};

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Version {
	Original,
	Candidate,
}

/// New arithmetic from a fully authenticated descriptor. Serialized reports cannot construct it.
#[derive(Debug, Serialize)]
pub struct ReopenedHead {
	schema: &'static str,
	request_sha256: String,
	version: Version,
	source_sha256: String,
	source_size_bytes: u64,
	observed_version: String,
	weight_payload_sha256: String,
	bias_payload_sha256: String,
	outputs: Vec<Vec<f64>>,
	f32_bits_sha256: String,
	score: f64,
	constraint_failures: Vec<usize>,
	gain_against_typed_original: Option<f64>,
	prediction_matches_typed_plan: Option<bool>,
	supplied_row_condition_satisfied: bool,
	complete_source_hash_passes: u8,
	linear_forward_calls: u8,
	wall_seconds: f64,
	full_model_executed: bool,
	feature_provenance_verified: bool,
	production_eligible: bool,
}

impl ReopenedHead {
	pub fn source_sha256(&self) -> &str {
		&self.source_sha256
	}

	pub fn prediction_bits_sha256(&self) -> &str {
		&self.f32_bits_sha256
	}

	pub fn supplied_row_condition_satisfied(&self) -> bool {
		self.supplied_row_condition_satisfied
	}
}

async fn read_inner(
	params: &CoupledF16EvaluationParams,
	file: &mut tokio::fs::File,
	prior: Option<(&CoupledF16Evaluation, Version)>,
	started: Instant,
	deadline: Instant,
) -> Result<ReopenedHead> {
	let shape = validate(params)?;
	let request_sha256 = bounded_digest(params)?;
	let mut capture_params = params.clone();
	let version = prior.map_or(Version::Original, |(_, version)| version);
	if let Some((plan, version)) = prior {
		if request_sha256 != plan.request_sha256 {
			bail!("reopened F16 request differs from its typed source/feature/objective plan");
		}
		if version == Version::Candidate {
			capture_params.proposal.source_sha256 = plan.proposal.candidate_sha256().into();
			capture_params.proposal.members[shape.weight_member]
				.binding
				.payload_sha256 = plan.weight.candidate_sha256.clone();
			capture_params.proposal.members[shape.bias_member]
				.binding
				.payload_sha256 = plan.bias.candidate_sha256.clone();
		}
	}
	// Only capture commitments change locally. The feature source remains the original checkpoint;
	// this does not manufacture a second encoder execution or accept a caller's feature-space swap.
	let captured = source::capture(&capture_params, shape, file, deadline).await?;
	let weights = source::decode(&captured.weight_bytes)?;
	let bias = source::decode(&captured.bias_bytes)?;
	let outputs = weight_forward::calculate(
		&weights,
		&params.features.rows,
		Some(&bias),
		shape.outputs,
		shape.columns,
		deadline,
	)?;
	let f32_bits_sha256 = prediction_bits_digest(&outputs);
	let (outputs, _) = paired_predictions(
		outputs.clone(),
		outputs,
		params.features.rows.len(),
		shape.outputs,
	)?;
	let actual_score = score(&params.objective, &outputs)?;
	let baseline = prior.map_or(outputs.as_slice(), |(plan, _)| {
		plan.baseline_predictions.as_slice()
	});
	let constraint_failures = check_constraints(&params.constraints, &outputs, baseline)?;
	let gain = prior.map(|(plan, _)| actual_score - plan.baseline_score);
	if gain.is_some_and(|value| !value.is_finite()) {
		bail!("reopened F16 supplied-row gain is nonfinite");
	}
	if let Some((plan, version)) = prior {
		let expected_bits = match version {
			Version::Original => &plan.baseline_f32_bits_sha256,
			Version::Candidate => &plan.candidate_f32_bits_sha256,
		};
		if &f32_bits_sha256 != expected_bits {
			bail!("actual reopened F16 outputs differ from the typed byte-plan prediction bits");
		}
	}
	check_deadline(deadline)?;
	Ok(ReopenedHead {
		schema: "hepta.weight.reopened-f16-head.v1",
		request_sha256,
		version,
		source_sha256: capture_params.proposal.source_sha256,
		source_size_bytes: captured.source_size_bytes,
		observed_version: captured.observed_version,
		weight_payload_sha256: super::sha(&captured.weight_bytes),
		bias_payload_sha256: super::sha(&captured.bias_bytes),
		outputs,
		f32_bits_sha256,
		score: actual_score,
		supplied_row_condition_satisfied: version == Version::Candidate
			&& gain.is_some_and(|value| value > params.minimum_gain)
			&& constraint_failures.is_empty(),
		constraint_failures,
		gain_against_typed_original: gain,
		prediction_matches_typed_plan: prior.map(|_| true),
		complete_source_hash_passes: 1,
		linear_forward_calls: 1,
		wall_seconds: started.elapsed().as_secs_f64(),
		full_model_executed: false,
		feature_provenance_verified: false,
		production_eligible: false,
	})
}

async fn read(
	params: &CoupledF16EvaluationParams,
	file: &mut tokio::fs::File,
	prior: Option<(&CoupledF16Evaluation, Version)>,
) -> Result<ReopenedHead> {
	let started = Instant::now();
	let deadline = started + Duration::from_secs(60);
	tokio::time::timeout_at(
		tokio::time::Instant::from_std(deadline),
		read_inner(params, file, prior, started, deadline),
	)
	.await
	.context("reopened F16 head exceeded its 60-second operation budget")?
}

/// The caller must supply a newly admitted descriptor. No serialized plan is accepted.
pub async fn verify_from_admitted(
	plan: &CoupledF16Evaluation,
	params: &CoupledF16EvaluationParams,
	file: &mut tokio::fs::File,
	version: Version,
) -> Result<ReopenedHead> {
	read(params, file, Some((plan, version))).await
}

/// A separate request performs a complete hash and new forward without a cached prediction.
/// Its source hash must be the request's original checkpoint, including after owner restoration.
pub async fn read_original_from_admitted(
	params: &CoupledF16EvaluationParams,
	file: &mut tokio::fs::File,
) -> Result<ReopenedHead> {
	read(params, file, None).await
}
