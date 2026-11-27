// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Compare one authenticated F16 W/b proposal on explicitly committed feature rows.
//! This library interface creates no artifact, invokes no owner and grants no adoption.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use super::super::weight_f16_proposal::{self, F16Proposal, F16ProposalParams, ReadSetRole};
use super::super::{rea_model, weight_config, weight_forward};
use super::{check_constraints, score, BoundedRequest, Constraint, Objective};

#[path = "weight_guard_f16_source.rs"]
mod source;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeadSelection {
	pub weight_name: String,
	pub bias_name: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeatureOrigin {
	SyntheticControl,
	/// A caller claim, not a verified producer execution or encoder output.
	DeclaredEncoderOutput,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureBatch {
	pub origin: FeatureOrigin,
	pub source_checkpoint_sha256: String,
	pub source_domain_sha256: String,
	pub producer_code_sha256: String,
	pub producer_configuration_sha256: String,
	pub declared_producer_receipt_sha256: String,
	pub data_manifest_sha256: String,
	pub sample_ids: Vec<String>,
	/// Domain-separated dimensions, ordered sample IDs and exact F32 row bits.
	pub expected_rows_sha256: String,
	pub rows: Vec<Vec<f32>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoupledF16EvaluationParams {
	pub proposal: F16ProposalParams,
	pub head: HeadSelection,
	pub features: FeatureBatch,
	pub objective: Objective,
	pub constraints: Vec<Constraint>,
	pub minimum_gain: f64,
}

#[derive(Serialize)]
struct FeatureIdentity {
	origin: FeatureOrigin,
	source_checkpoint_sha256: String,
	source_domain_sha256: String,
	producer_code_sha256: String,
	producer_configuration_sha256: String,
	declared_producer_receipt_sha256: String,
	data_manifest_sha256: String,
	sample_ids: Vec<String>,
	rows_sha256: String,
	row_count: usize,
	column_count: usize,
	producer_execution_verified: bool,
	feature_provenance_verified: bool,
}

#[derive(Serialize)]
struct PayloadIdentity {
	name: String,
	shape: Vec<u64>,
	file_offset: u64,
	byte_length: usize,
	original_sha256: String,
	candidate_sha256: String,
}

#[derive(Serialize)]
struct CostObservation {
	operation_limit_seconds: u64,
	complete_source_hash_passes: u8,
	directory_inspections: u8,
	/// Successful passes have the same complete commitment; this is 2 * source size.
	complete_pass_bytes_hashed: u64,
	parser_and_header_extra_io_bytes_known: bool,
	linear_forward_calls: u8,
	combined_multiply_adds: u64,
	combined_output_values: usize,
	proposal_compile_wall_ms: f64,
	second_capture_wall_ms: f64,
	coefficient_preparation_wall_ms: f64,
	baseline_forward_wall_ms: f64,
	candidate_forward_wall_ms: f64,
	comparison_wall_ms: f64,
	operation_wall_ms_before_final_response_check: f64,
	end_to_end_cost_known: bool,
}

/// Constructed only after source, exact-byte, numerical and comparison checks.
/// This is supplied-row evidence, never a receipt authorizing an owner operation.
#[derive(Serialize)]
pub struct CoupledF16Evaluation {
	schema: &'static str,
	request_sha256: String,
	inline_specification_sha256: String,
	evaluator_selected_source_sha256: String,
	proposal_sha256: String,
	proposal: F16Proposal,
	source_sha256: String,
	source_size_bytes: u64,
	observed_version: String,
	raw_prefix_sha256: String,
	json_header_sha256: String,
	head: HeadSelection,
	weight: PayloadIdentity,
	bias: PayloadIdentity,
	features: FeatureIdentity,
	baseline_predictions: Vec<Vec<f64>>,
	candidate_predictions: Vec<Vec<f64>>,
	baseline_f32_bits_sha256: String,
	candidate_f32_bits_sha256: String,
	baseline_score: f64,
	candidate_score: f64,
	gain: f64,
	minimum_gain: f64,
	baseline_constraint_failures: Vec<usize>,
	candidate_constraint_failures: Vec<usize>,
	supplied_row_condition_satisfied: bool,
	cost: CostObservation,
	linear_kernel_evaluated: bool,
	full_model_executed: bool,
	head_semantics_verified: bool,
	independent_holdout_verified: bool,
	owner_invoked: bool,
	artifact_created: bool,
	live_activation: bool,
	rollback_executed: bool,
	production_eligible: bool,
}

#[derive(Clone, Copy)]
struct Shape {
	outputs: usize,
	columns: usize,
	weight_member: usize,
	bias_member: usize,
	macs_per_forward: u64,
}

fn sha(bytes: &[u8]) -> String {
	rea_model::digest_hex(&Sha256::digest(bytes))
}

fn check_deadline(deadline: Instant) -> Result<()> {
	if Instant::now() >= deadline {
		bail!("coupled F16 evaluation exceeded its one operation deadline");
	}
	Ok(())
}

fn bounded_digest(value: &impl Serialize) -> Result<String> {
	let mut encoded = BoundedRequest(Vec::new());
	serde_json::to_writer(&mut encoded, value)?;
	Ok(sha(&encoded.0))
}

fn feature_rows_digest(features: &FeatureBatch, columns: usize) -> Result<String> {
	let mut hash = Sha256::new();
	hash.update(b"hepta.weight.coupled-f16-feature-rows.v1\0");
	hash.update((features.rows.len() as u64).to_le_bytes());
	hash.update((columns as u64).to_le_bytes());
	for (sample, row) in features.sample_ids.iter().zip(&features.rows) {
		if !weight_config::valid_sha256(sample) {
			bail!("coupled F16 feature commitment requires a complete sample digest");
		}
		let mut sample_bytes = [0u8; 32];
		for (index, pair) in sample.as_bytes().as_chunks::<2>().0.iter().enumerate() {
			let digit = |byte: u8| {
				if byte.is_ascii_digit() {
					byte - b'0'
				} else {
					byte - b'a' + 10
				}
			};
			sample_bytes[index] = digit(pair[0]) * 16 + digit(pair[1]);
		}
		hash.update(sample_bytes);
		for value in row {
			hash.update(value.to_bits().to_le_bytes());
		}
	}
	Ok(rea_model::digest_hex(&hash.finalize()))
}

fn validate(params: &CoupledF16EvaluationParams) -> Result<Shape> {
	let head = &params.head;
	if head.weight_name.is_empty()
		|| head.bias_name.is_empty()
		|| head.weight_name.len() > 1024
		|| head.bias_name.len() > 1024
		|| head.weight_name == head.bias_name
		|| !(1..=32).contains(&params.proposal.members.len())
		|| !params.minimum_gain.is_finite()
		|| params.minimum_gain < 0.0
		|| params.constraints.len() > 32
	{
		bail!("coupled F16 evaluation requires distinct bounded W/b, finite gain and bounded constraints");
	}
	let find = |name: &str| {
		params
			.proposal
			.members
			.iter()
			.position(|member| member.binding.name == name)
			.ok_or_else(|| {
				anyhow!("coupled F16 head is absent from the complete proposal read set")
			})
	};
	let weight_member = find(&head.weight_name)?;
	let bias_member = find(&head.bias_name)?;
	let weight = &params.proposal.members[weight_member].binding;
	let bias = &params.proposal.members[bias_member].binding;
	if weight.dtype != "F16"
		|| bias.dtype != "F16"
		|| weight.shape.len() != 2
		|| bias.shape.len() != 1
		|| weight.shape.iter().any(|value| !(1..=4096).contains(value))
		|| bias.shape[0] != weight.shape[0]
		|| params.proposal.members.iter().any(|member| {
			member.role == ReadSetRole::EditTarget
				&& member.binding.name != head.weight_name
				&& member.binding.name != head.bias_name
		}) {
		bail!("coupled F16 evaluation accepts exactly one F16 W[out,in]/b[out] edit pair");
	}
	let outputs = usize::try_from(weight.shape[0])?;
	let columns = usize::try_from(weight.shape[1])?;
	let features = &params.features;
	let macs_per_forward = weight_forward::check_inputs(&features.rows, None, outputs, columns)?;
	if 2 * macs_per_forward > weight_forward::MAX_MACS
		|| 2 * features.rows.len() as u64 * outputs as u64 > weight_forward::MAX_OUTPUT_VALUES
	{
		bail!("coupled F16 baseline and candidate together exceed the original linear budgets");
	}
	if [
		&features.source_checkpoint_sha256,
		&features.source_domain_sha256,
		&features.producer_code_sha256,
		&features.producer_configuration_sha256,
		&features.declared_producer_receipt_sha256,
		&features.data_manifest_sha256,
		&features.expected_rows_sha256,
	]
	.into_iter()
	.any(|digest| !weight_config::valid_sha256(digest))
		|| features.source_checkpoint_sha256 != params.proposal.source_sha256
		|| features.data_manifest_sha256 != params.proposal.data_manifest_sha256
		|| features.sample_ids.len() != features.rows.len()
	{
		bail!("coupled F16 features require explicit source/domain/producer/data/row commitments");
	}
	let mut samples = BTreeSet::new();
	for sample in &features.sample_ids {
		if !weight_config::valid_sha256(sample) || !samples.insert(sample.as_str()) {
			bail!("coupled F16 sample IDs must be distinct complete SHA-256 values");
		}
	}
	if feature_rows_digest(features, columns)? != features.expected_rows_sha256 {
		bail!("coupled F16 ordered sample identities or exact feature bits differ");
	}
	let labels = match &params.objective {
		Objective::SquaredError { targets } => targets,
		Objective::ActionValue {
			action_columns,
			values,
		} => {
			if !(1..=256).contains(&action_columns.len()) {
				bail!("coupled F16 action objective exceeds the existing action-column bound");
			}
			values
		}
	};
	if labels.len() != features.rows.len()
		|| labels.iter().any(|row| {
			row.is_empty() || row.len() > 4096 || row.iter().any(|value| !value.is_finite())
		}) {
		bail!("coupled F16 objective labels must be finite bounded rows");
	}
	Ok(Shape {
		outputs,
		columns,
		weight_member,
		bias_member,
		macs_per_forward,
	})
}

fn prediction_bits_digest(rows: &[Vec<f32>]) -> String {
	let mut hash = Sha256::new();
	hash.update(b"hepta.weight.coupled-f16-predictions.v1\0");
	hash.update((rows.len() as u64).to_le_bytes());
	for row in rows {
		hash.update((row.len() as u64).to_le_bytes());
		for value in row {
			hash.update(value.to_bits().to_le_bytes());
		}
	}
	rea_model::digest_hex(&hash.finalize())
}

type PredictionRows = Vec<Vec<f64>>;

fn paired_predictions(
	baseline: Vec<Vec<f32>>,
	candidate: Vec<Vec<f32>>,
	rows: usize,
	outputs: usize,
) -> Result<(PredictionRows, PredictionRows)> {
	// The reused constraint function zips the two matrices, so prove their full
	// equal shape before either can reach that iterator.
	if rows == 0
		|| outputs == 0
		|| [&baseline, &candidate].into_iter().any(|matrix| {
			matrix.len() != rows
				|| matrix
					.iter()
					.any(|row| row.len() != outputs || row.iter().any(|value| !value.is_finite()))
		}) {
		bail!("coupled F16 predictions must have identical complete finite dimensions");
	}
	let convert = |matrix: Vec<Vec<f32>>| {
		matrix
			.into_iter()
			.map(|row| row.into_iter().map(f64::from).collect())
			.collect()
	};
	Ok((convert(baseline), convert(candidate)))
}

fn implementation_sha256() -> String {
	let mut hash = Sha256::new();
	hash.update(b"hepta.weight.coupled-f16-selected-source.v1\0");
	for (name, bytes) in [
		(
			"evaluator",
			include_bytes!("weight_guard_f16.rs").as_slice(),
		),
		(
			"capture",
			include_bytes!("weight_guard_f16_source.rs").as_slice(),
		),
		("forward", include_bytes!("weight_forward.rs").as_slice()),
		("guard", include_bytes!("weight_guard.rs").as_slice()),
		(
			"proposal",
			include_bytes!("weight_f16_proposal.rs").as_slice(),
		),
		(
			"proposal_capture",
			include_bytes!("weight_f16_source.rs").as_slice(),
		),
		("model", include_bytes!("rea_model.rs").as_slice()),
		("parser", include_bytes!("rea_model_parser.rs").as_slice()),
		("tensor", include_bytes!("weight_tensor.rs").as_slice()),
		("norm", include_bytes!("weight_norm.rs").as_slice()),
		(
			"cohort",
			include_bytes!("weight_artifact_cohort.rs").as_slice(),
		),
		("config", include_bytes!("weight_config.rs").as_slice()),
		("manifest", include_bytes!("../../Cargo.toml").as_slice()),
	] {
		hash.update((name.len() as u64).to_le_bytes());
		hash.update(name.as_bytes());
		hash.update((bytes.len() as u64).to_le_bytes());
		hash.update(bytes);
	}
	rea_model::digest_hex(&hash.finalize())
}

async fn evaluate_inner(
	params: &CoupledF16EvaluationParams,
	file: &mut tokio::fs::File,
	started: Instant,
	deadline: Instant,
) -> Result<CoupledF16Evaluation> {
	let shape = validate(params)?;
	let request_sha256 = bounded_digest(params)?;
	let inline_specification_sha256 = bounded_digest(&(
		&params.head,
		&params.objective,
		&params.constraints,
		params.minimum_gain,
	))?;
	check_deadline(deadline)?;
	let phase = Instant::now();
	let proposal = weight_f16_proposal::compile_from_admitted(&params.proposal, file)
		.await
		.context("coupled F16 exact proposal authentication failed")?;
	let proposal_compile_wall_ms = phase.elapsed().as_secs_f64() * 1000.0;
	check_deadline(deadline)?;
	let phase = Instant::now();
	let mut captured = source::capture(params, shape, file, deadline)
		.await
		.context("coupled F16 second complete-source capture failed")?;
	let second_capture_wall_ms = phase.elapsed().as_secs_f64() * 1000.0;
	let phase = Instant::now();
	let original_weights = source::decode(&captured.weight_bytes)?;
	let original_bias = source::decode(&captured.bias_bytes)?;
	// Keep the compiler's typed result. No serialized receipt is read as authority.
	if let Some(cohort) = proposal.cohort_proposal() {
		for member in &cohort.members {
			let target = if member.tensor_name == params.head.weight_name {
				&mut captured.weight_bytes
			} else if member.tensor_name == params.head.bias_name {
				&mut captured.bias_bytes
			} else {
				bail!("coupled F16 typed proposal contains an edit outside its selected head");
			};
			source::apply(target, &member.edits)?;
		}
	}
	let candidate_weights = source::decode(&captured.weight_bytes)?;
	let candidate_bias = source::decode(&captured.bias_bytes)?;
	let weight_binding = &params.proposal.members[shape.weight_member].binding;
	let bias_binding = &params.proposal.members[shape.bias_member].binding;
	let weight = PayloadIdentity {
		name: weight_binding.name.clone(),
		shape: weight_binding.shape.clone(),
		file_offset: captured.weight_offset,
		byte_length: captured.weight_bytes.len(),
		original_sha256: weight_binding.payload_sha256.clone(),
		candidate_sha256: sha(&captured.weight_bytes),
	};
	let bias = PayloadIdentity {
		name: bias_binding.name.clone(),
		shape: bias_binding.shape.clone(),
		file_offset: captured.bias_offset,
		byte_length: captured.bias_bytes.len(),
		original_sha256: bias_binding.payload_sha256.clone(),
		candidate_sha256: sha(&captured.bias_bytes),
	};
	drop(captured.weight_bytes);
	drop(captured.bias_bytes);
	let coefficient_preparation_wall_ms = phase.elapsed().as_secs_f64() * 1000.0;
	check_deadline(deadline)?;
	let phase = Instant::now();
	let baseline = weight_forward::calculate(
		&original_weights,
		&params.features.rows,
		Some(&original_bias),
		shape.outputs,
		shape.columns,
		deadline,
	)?;
	let baseline_forward_wall_ms = phase.elapsed().as_secs_f64() * 1000.0;
	let phase = Instant::now();
	let candidate = weight_forward::calculate(
		&candidate_weights,
		&params.features.rows,
		Some(&candidate_bias),
		shape.outputs,
		shape.columns,
		deadline,
	)?;
	let candidate_forward_wall_ms = phase.elapsed().as_secs_f64() * 1000.0;
	check_deadline(deadline)?;
	let phase = Instant::now();
	let baseline_f32_bits_sha256 = prediction_bits_digest(&baseline);
	let candidate_f32_bits_sha256 = prediction_bits_digest(&candidate);
	let (baseline_predictions, candidate_predictions) = paired_predictions(
		baseline,
		candidate,
		params.features.rows.len(),
		shape.outputs,
	)?;
	let baseline_score = score(&params.objective, &baseline_predictions)?;
	let candidate_score = score(&params.objective, &candidate_predictions)?;
	let baseline_constraint_failures = check_constraints(
		&params.constraints,
		&baseline_predictions,
		&baseline_predictions,
	)?;
	let candidate_constraint_failures = check_constraints(
		&params.constraints,
		&candidate_predictions,
		&baseline_predictions,
	)?;
	let gain = candidate_score - baseline_score;
	if !gain.is_finite() {
		bail!("coupled F16 supplied-row gain is not finite");
	}
	let supplied_row_condition_satisfied =
		gain > params.minimum_gain && candidate_constraint_failures.is_empty();
	let comparison_wall_ms = phase.elapsed().as_secs_f64() * 1000.0;
	let features = &params.features;
	let result = CoupledF16Evaluation {
		schema: "hepta.weight.coupled-f16-evaluation.v1",
		request_sha256,
		inline_specification_sha256,
		evaluator_selected_source_sha256: implementation_sha256(),
		proposal_sha256: bounded_digest(&proposal)?,
		proposal,
		source_sha256: params.proposal.source_sha256.clone(),
		source_size_bytes: captured.source_size_bytes,
		observed_version: captured.observed_version,
		raw_prefix_sha256: captured.raw_prefix_sha256,
		json_header_sha256: captured.json_header_sha256,
		head: params.head.clone(),
		weight,
		bias,
		features: FeatureIdentity {
			origin: features.origin,
			source_checkpoint_sha256: features.source_checkpoint_sha256.clone(),
			source_domain_sha256: features.source_domain_sha256.clone(),
			producer_code_sha256: features.producer_code_sha256.clone(),
			producer_configuration_sha256: features.producer_configuration_sha256.clone(),
			declared_producer_receipt_sha256: features.declared_producer_receipt_sha256.clone(),
			data_manifest_sha256: features.data_manifest_sha256.clone(),
			sample_ids: features.sample_ids.clone(),
			rows_sha256: features.expected_rows_sha256.clone(),
			row_count: features.rows.len(),
			column_count: shape.columns,
			producer_execution_verified: false,
			feature_provenance_verified: false,
		},
		baseline_predictions,
		candidate_predictions,
		baseline_f32_bits_sha256,
		candidate_f32_bits_sha256,
		baseline_score,
		candidate_score,
		gain,
		minimum_gain: params.minimum_gain,
		baseline_constraint_failures,
		candidate_constraint_failures,
		supplied_row_condition_satisfied,
		cost: CostObservation {
			operation_limit_seconds: 60,
			complete_source_hash_passes: 2,
			directory_inspections: 2,
			complete_pass_bytes_hashed: 2 * captured.source_size_bytes,
			parser_and_header_extra_io_bytes_known: false,
			linear_forward_calls: 2,
			combined_multiply_adds: 2 * shape.macs_per_forward,
			combined_output_values: 2 * features.rows.len() * shape.outputs,
			proposal_compile_wall_ms,
			second_capture_wall_ms,
			coefficient_preparation_wall_ms,
			baseline_forward_wall_ms,
			candidate_forward_wall_ms,
			comparison_wall_ms,
			operation_wall_ms_before_final_response_check: started.elapsed().as_secs_f64() * 1000.0,
			end_to_end_cost_known: false,
		},
		linear_kernel_evaluated: true,
		full_model_executed: false,
		head_semantics_verified: false,
		independent_holdout_verified: false,
		owner_invoked: false,
		artifact_created: false,
		live_activation: false,
		rollback_executed: false,
		production_eligible: false,
	};
	// This checks an extra bounded serialization copy, not transport allocation.
	let mut response = BoundedRequest(Vec::new());
	serde_json::to_writer(&mut response, &result)?;
	check_deadline(deadline)?;
	Ok(result)
}

/// The caller supplies an already-admitted descriptor and all feature/spec data.
/// One deadline covers both complete captures and both sequential F32 forwards.
/// Cooperative checks and timeout do not bound arbitrary OS/worker blocking.
pub async fn evaluate_from_admitted(
	params: &CoupledF16EvaluationParams,
	file: &mut tokio::fs::File,
) -> Result<CoupledF16Evaluation> {
	let started = Instant::now();
	let deadline = started + Duration::from_secs(60);
	tokio::time::timeout_at(
		tokio::time::Instant::from_std(deadline),
		evaluate_inner(params, file, started, deadline),
	)
	.await
	.context("coupled F16 evaluation exceeded its one 60-second operation budget")?
}

#[cfg(all(test, unix))]
#[path = "weight_guard_f16_tests.rs"]
mod tests;
